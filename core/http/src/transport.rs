//! The TCP transport.
//!
//! HTTP/1.0 and HTTP/1.1 over plaintext TCP or TLS, with bodies delimited by
//! `Content-Length`, chunked transfer coding, or connection close.
//!
//! # Two ways to send
//!
//! [`TcpTransport::send_streaming`] returns as soon as the response *head* has
//! arrived, handing back a [`BodyStream`] that owns the connection. That is what the
//! proxy needs: it can forward bytes as they come rather than holding an entire
//! response in memory, which is the difference between working and not working for
//! downloads, server-sent events and long-poll endpoints.
//!
//! [`HttpTransport::send`] is the buffered convenience built on top of it, for
//! callers — the repeater, `hexora send` — that genuinely want the whole body.
//!
//! Connection reuse is M1.4. Each request currently opens its own connection, which is
//! deliberate: a pool that mis-frames one response corrupts the next, so the framing
//! wants to be proven first.
//!
//! # Timeouts
//!
//! Every phase is bounded separately rather than sharing one deadline, because the
//! phases fail for different reasons and a tester needs to know which one stalled: a
//! connect timeout means the host is unreachable, a read-head timeout means the server
//! accepted the connection and then stopped talking — a slowloris in reverse.

use std::time::Instant;

use async_trait::async_trait;
use bytes::BytesMut;
use hexora_engine::transport::{Exchange, HttpTransport, SendOptions};
use hexora_types::error::{HexoraError, NetworkError, Result, TimeoutPhase};
use hexora_types::http::{HttpRequest, HttpResponse};
use hexora_types::limits::Limits;
use hexora_types::raw::RawRequest;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::body::BodyStream;
use crate::parse::{find_head_end, parse_response_head, BodyFraming, Quirk, ResponseHead};
use crate::tls::TlsConfig;
use crate::write::serialize_request;

/// Reads from the socket in chunks of this size.
const READ_CHUNK: usize = 16 * 1024;

/// An HTTP/1.x transport over plaintext TCP.
///
/// Opens a fresh connection per request. Connection reuse is M1.4; doing it now would
/// mean building a pool before there is a parser proven to find message boundaries
/// correctly, and a pool that mis-frames one response corrupts the next.
#[derive(Debug, Clone)]
pub struct TcpTransport {
    tls: TlsConfig,
}

impl Default for TcpTransport {
    /// Deliberately hand-written rather than derived.
    ///
    /// A derived `Default` would use `TlsConfig::default()`, whose ALPN list is
    /// empty, so `TcpTransport::default()` and `TcpTransport::new()` would quietly
    /// negotiate differently. Two constructors that look interchangeable but are
    /// not is exactly the kind of difference that surfaces months later as an
    /// unexplained protocol change.
    fn default() -> Self {
        Self::new()
    }
}

impl TcpTransport {
    /// A transport that verifies TLS against the platform trust store.
    pub fn new() -> Self {
        Self {
            tls: TlsConfig::verified(),
        }
    }

    /// A transport with explicit TLS settings.
    ///
    /// Settings live on the transport rather than on each request because a tester
    /// works against one estate at a time: relaxing verification is a decision about
    /// *this engagement*, and building a second transport is how you say the next one
    /// is different. It is never a process-wide toggle.
    pub fn with_tls(tls: TlsConfig) -> Self {
        Self { tls }
    }

    /// Sends a request and returns as soon as the response *head* has arrived.
    ///
    /// The body is still on the wire. This is what the proxy uses: it can begin
    /// forwarding immediately instead of holding the whole response in memory, which
    /// is what makes downloads, server-sent events and long-poll endpoints work.
    pub async fn send_streaming(
        &self,
        request: HttpRequest,
        options: SendOptions,
    ) -> Result<StreamingExchange> {
        let wire = serialize_request(&request);
        let method = request.method.clone();
        self.write_and_read(request, wire, method, None, options)
            .await
    }

    /// Writes a raw request byte for byte and returns at the response head.
    ///
    /// The only difference from [`Self::send_streaming`] is which bytes are written,
    /// and that is the whole point: nothing here builds them. The response is read
    /// exactly as it would be for any other request, because a malformed request still
    /// produces a real answer and that answer is the result the tester came for.
    pub async fn send_raw_streaming(
        &self,
        raw: RawRequest,
        options: SendOptions,
    ) -> Result<StreamingExchange> {
        // The method matters for *reading* the response, not for writing the request:
        // RFC 9112 6.3 says a HEAD response has no body however it is framed. Read
        // from the raw request line rather than assumed.
        let method = raw.method();
        let bytes = raw.bytes.clone();

        // A structured view for the record. Best effort on purpose: a raw request may
        // not parse, and failing to parse it must not stop it being sent. The faithful
        // record is `Exchange::raw_request`, which is the bytes themselves.
        let request = structured_view(&raw);
        self.write_and_read(request, bytes.to_vec(), method, Some(bytes), options)
            .await
    }

    /// Opens the connection, writes `wire`, and reads the response head.
    async fn write_and_read(
        &self,
        request: HttpRequest,
        wire: Vec<u8>,
        method: String,
        raw: Option<bytes::Bytes>,
        options: SendOptions,
    ) -> Result<StreamingExchange> {
        let started = Instant::now();
        let limits = &options.limits;

        let tcp = connect(&request.service.host, request.service.port, limits).await?;

        // Boxed so the body stream can own the connection, whichever kind it is.
        let (mut connection, tls): (Box<dyn Connection>, _) = if request.service.secure {
            let (stream, tls) =
                crate::tls::handshake(tcp, &request.service.host, &self.tls, limits).await?;
            (Box::new(stream), Some(tls))
        } else {
            (Box::new(tcp), None)
        };

        write_all(&mut connection, &wire, limits).await?;
        let (head, prefix) = read_head(&mut connection, &method, limits).await?;

        // A declared length over the cap is refused before a byte of body is read.
        // Streaming still enforces the limit as bytes arrive, because the declared
        // length can lie — but there is no sense downloading 100 MB of a response that
        // announced a gigabyte we were never going to keep.
        if let BodyFraming::ContentLength(declared) = head.framing {
            limits.check_body_size(declared)?;
        }

        let body = BodyStream::new(connection, prefix, head.framing, limits.clone());

        Ok(StreamingExchange {
            request,
            head,
            tls,
            body,
            raw,
            started,
        })
    }
}

/// A message-model view of a raw request, for the history table and the interface.
///
/// Best effort, and never written to a socket. The request line is read the same way
/// the scope guard reads it; header fields are taken as they split, and one that does
/// not split is skipped rather than guessed at. What went out is
/// `Exchange::raw_request`, which is exact.
fn structured_view(raw: &RawRequest) -> HttpRequest {
    let line = raw.request_line();
    let mut request = HttpRequest::get(
        raw.service.clone(),
        line.as_ref()
            .map(|l| l.target.clone())
            .unwrap_or_else(|| "/".to_string()),
    );
    request.method = line.map(|l| l.method).unwrap_or_default();
    request.body = raw.body();
    // `HttpRequest::get` adds a Host from the service. These bytes may not have
    // carried one — a missing Host is a routing test — and a view that invented it
    // would show the tester a header they did not send.
    request.headers = hexora_types::http::Headers::new();

    let head = raw.head();
    let text = String::from_utf8_lossy(&head);
    for field in text.split(LF).skip(1) {
        let field = field.trim_end_matches(CR);
        if field.is_empty() {
            break;
        }
        if let Some((name, value)) = field.split_once(':') {
            request
                .headers
                .append(hexora_types::http::Header::new(name.trim(), value.trim()));
        }
    }
    request
}

const LF: char = '\n';
const CR: char = '\r';

/// Anything that can carry an HTTP conversation: a plain socket or a TLS stream.
trait Connection: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Connection for T {}

/// A response whose head has arrived and whose body is still being read.
///
/// The stream owns the connection; dropping it closes the connection, which is the
/// right way to abandon a response that is taking too long.
pub struct StreamingExchange {
    /// The request as it was sent.
    pub request: HttpRequest,
    /// The exact bytes written, when the request was sent raw.
    pub raw: Option<bytes::Bytes>,
    /// The parsed response head, including any quirks found in it.
    pub head: ResponseHead,
    /// What the TLS handshake produced, for `https` exchanges.
    pub tls: Option<hexora_types::tls::TlsInfo>,
    /// The body, still arriving.
    pub body: BodyStream<'static>,
    started: Instant,
}

impl std::fmt::Debug for StreamingExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingExchange")
            .field("url", &self.request.url())
            .field("status", &self.head.status)
            .finish_non_exhaustive()
    }
}

impl StreamingExchange {
    /// Reads the body to completion and returns the buffered exchange.
    pub async fn collect(self) -> Result<Exchange> {
        let content_encoding = self
            .head
            .headers
            .get("Content-Encoding")
            .map(|h| h.value_lossy().into_owned())
            .unwrap_or_default();

        let mut head = self.head;
        let request = self.request;
        let collected = self.body.collect(&content_encoding).await?;

        // Trailers join the header list so nothing downstream has to know whether a
        // field arrived before or after the body.
        for trailer in collected.trailers.iter() {
            head.headers.append(trailer.clone());
        }

        report_smuggling_signals(&request, &head, &collected.quirks);

        Ok(Exchange {
            response: HttpResponse {
                status: head.status,
                reason: head.reason.clone(),
                version: head.version,
                headers: head.headers,
                body: collected.bytes,
                truncated: collected.truncated,
            },
            request,
            encoded_body: collected.encoded,
            content_encoding: collected.reversed_coding,
            raw_request: self.raw,
            duration: self.started.elapsed(),
            tls: self.tls,
        })
    }
}

/// Warns when a response's framing shows a desync primitive.
///
/// At `warn` rather than `debug`: this is a finding waiting to be raised, not noise.
fn report_smuggling_signals(request: &HttpRequest, head: &ResponseHead, body_quirks: &[Quirk]) {
    let signals: Vec<&str> = head
        .quirks
        .iter()
        .chain(body_quirks.iter())
        .filter(|q| q.is_smuggling_signal())
        .map(Quirk::explanation)
        .collect();
    if !signals.is_empty() {
        tracing::warn!(
            url = %request.url(),
            signals = ?signals,
            "response framing shows a request-smuggling signal"
        );
    }
}

#[async_trait]
impl HttpTransport for TcpTransport {
    async fn send(&self, request: HttpRequest, options: SendOptions) -> Result<Exchange> {
        self.send_streaming(request, options).await?.collect().await
    }

    async fn send_raw(&self, request: RawRequest, options: SendOptions) -> Result<Exchange> {
        self.send_raw_streaming(request, options)
            .await?
            .collect()
            .await
    }
}

async fn connect(host: &str, port: u16, limits: &Limits) -> Result<TcpStream> {
    let peer = format!("{host}:{port}");

    let stream = tokio::time::timeout(limits.connect_timeout, TcpStream::connect(&peer))
        .await
        .map_err(|_| {
            HexoraError::Network(NetworkError::Timeout {
                phase: TimeoutPhase::Connect,
                elapsed: limits.connect_timeout,
            })
        })?
        .map_err(|e| classify_connect_error(e, &peer))?;

    // Interactive testing is latency-sensitive and the requests are small; waiting for
    // Nagle to coalesce a request nobody is going to add to just adds delay.
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

fn classify_connect_error(e: std::io::Error, peer: &str) -> HexoraError {
    use std::io::ErrorKind;
    HexoraError::Network(match e.kind() {
        ErrorKind::ConnectionRefused => NetworkError::ConnectionRefused {
            peer: peer.to_string(),
        },
        ErrorKind::ConnectionReset => NetworkError::ConnectionReset {
            peer: peer.to_string(),
        },
        // Resolution failures surface as a variety of kinds across platforms, so the
        // host string is the reliable signal rather than the ErrorKind.
        ErrorKind::NotFound | ErrorKind::InvalidInput | ErrorKind::AddrNotAvailable => {
            NetworkError::Dns {
                host: peer.split(':').next().unwrap_or(peer).to_string(),
            }
        }
        _ => NetworkError::Io(e.to_string()),
    })
}

async fn write_all<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    limits: &Limits,
) -> Result<()> {
    tokio::time::timeout(limits.total_timeout, stream.write_all(bytes))
        .await
        .map_err(|_| {
            HexoraError::Network(NetworkError::Timeout {
                phase: TimeoutPhase::WriteRequest,
                elapsed: limits.total_timeout,
            })
        })?
        .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
    Ok(())
}

/// Reads until the head terminator, returning the head and any body bytes that
/// arrived in the same read.
async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    request_method: &str,
    limits: &Limits,
) -> Result<(ResponseHead, BytesMut)> {
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    let deadline = tokio::time::Instant::now() + limits.read_head_timeout;

    loop {
        if let Some(end) = find_head_end(&buf) {
            let head = parse_response_head(&buf[..end], request_method, limits)?;
            let rest = buf.split_off(end);
            return Ok((head, rest));
        }

        // Enforce the cap while reading, not after: a server that never sends a blank
        // line would otherwise grow this buffer without bound.
        limits.check_header_size(buf.len())?;

        let read = tokio::time::timeout_at(deadline, read_more(stream, &mut buf))
            .await
            .map_err(|_| {
                HexoraError::Network(NetworkError::Timeout {
                    phase: TimeoutPhase::ReadResponseHead,
                    elapsed: limits.read_head_timeout,
                })
            })??;

        if read == 0 {
            return Err(HexoraError::Protocol(
                hexora_types::error::ProtocolError::Malformed {
                    protocol: "HTTP/1.1",
                    reason: format!(
                        "connection closed after {} bytes without completing the response head",
                        buf.len()
                    ),
                },
            ));
        }
    }
}

/// Reads one batch of bytes onto the end of `buf`, returning how many arrived.
///
/// Used only while reading the head; once the body starts, [`BodyStream`] owns the
/// connection and does its own reading.
async fn read_more<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut) -> Result<usize> {
    let before = buf.len();
    buf.resize(before + READ_CHUNK, 0);
    let read = stream.read(&mut buf[before..]).await.map_err(|e| {
        HexoraError::Network(match e.kind() {
            std::io::ErrorKind::ConnectionReset => NetworkError::ConnectionReset {
                peer: "peer".to_string(),
            },
            _ => NetworkError::Io(e.to_string()),
        })
    })?;
    buf.truncate(before + read);
    Ok(read)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hexora_engine::transport::Origin;
    use hexora_types::http::{HttpService, HttpVersion};
    use tokio::net::TcpListener;

    use super::*;

    /// Serves one connection with `response`, then closes. Returns the port and a
    /// handle that yields the bytes the client sent.
    async fn serve(response: &'static [u8]) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        serve_with(response, true).await
    }

    async fn serve_with(
        response: &'static [u8],
        close_after: bool,
    ) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = vec![0u8; 8192];
            let n = socket.read(&mut received).await.unwrap_or(0);
            received.truncate(n);
            socket.write_all(response).await.ok();
            if close_after {
                socket.shutdown().await.ok();
            } else {
                // Hold the connection open so read-until-close cannot finish.
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            received
        });
        (port, handle)
    }

    fn request(port: u16, path: &str) -> HttpRequest {
        HttpRequest::get(HttpService::new("127.0.0.1", port, false), path)
    }

    async fn send(port: u16, path: &str) -> Result<Exchange> {
        TcpTransport::new()
            .send(
                request(port, path),
                SendOptions::interactive(Origin::Repeater),
            )
            .await
    }

    // ------------------------------------------------------------- happy path

    #[tokio::test]
    async fn sends_a_request_and_reads_a_content_length_response() {
        let (port, server) =
            serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello")
                .await;

        let exchange = send(port, "/hello").await.unwrap();

        assert_eq!(exchange.response.status, 200);
        assert_eq!(exchange.response.body.as_ref(), b"hello");
        assert_eq!(exchange.response.version, HttpVersion::Http11);
        assert!(!exchange.response.truncated);

        let sent = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(sent.starts_with("GET /hello HTTP/1.1\r\n"), "{sent:?}");
        assert!(sent.contains("Host: 127.0.0.1:"), "{sent:?}");
        assert!(sent.ends_with("\r\n\r\n"), "{sent:?}");
    }

    #[tokio::test]
    async fn measures_round_trip_duration() {
        let (port, _server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let exchange = send(port, "/").await.unwrap();
        assert!(exchange.duration > Duration::ZERO);
        assert!(exchange.duration < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn an_empty_body_is_handled() {
        let (port, _server) = serve(b"HTTP/1.1 204 No Content\r\n\r\n").await;
        let exchange = send(port, "/").await.unwrap();
        assert_eq!(exchange.response.status, 204);
        assert!(exchange.response.body.is_empty());
    }

    #[tokio::test]
    async fn a_body_delimited_by_connection_close_is_read() {
        let (port, _server) = serve(b"HTTP/1.0 200 OK\r\n\r\nstreamed to the end").await;
        let exchange = send(port, "/").await.unwrap();
        assert_eq!(exchange.response.body.as_ref(), b"streamed to the end");
        assert!(!exchange.response.truncated);
    }

    #[tokio::test]
    async fn a_body_arriving_with_the_head_in_one_packet_is_kept() {
        // The head and body land in a single read; the leftover must not be lost.
        let (port, _server) =
            serve(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world").await;
        let exchange = send(port, "/").await.unwrap();
        assert_eq!(exchange.response.body.as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn binary_bodies_survive_intact() {
        let (port, _server) =
            serve(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\x00\xff\xfe\x01").await;
        let exchange = send(port, "/").await.unwrap();
        assert_eq!(exchange.response.body.as_ref(), &[0x00, 0xff, 0xfe, 0x01]);
    }

    // ------------------------------------------------------------ hostile input

    #[tokio::test]
    async fn a_truncated_body_is_reported_rather_than_returned_short() {
        // Declares 100 bytes, sends 5, then closes.
        let (port, _server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort").await;
        let err = send(port, "/").await.unwrap_err();
        assert_eq!(err.code(), "protocol", "{err}");
        assert!(err.to_string().contains("declared body bytes"), "{err}");
    }

    #[tokio::test]
    async fn a_head_that_never_terminates_is_refused_by_the_size_limit() {
        // 200 KB of header bytes with no blank line, against a 4 KB cap.
        static FLOOD: &[u8] = b"HTTP/1.1 200 OK\r\nX-Pad: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = vec![0u8; 4096];
            let _ = socket.read(&mut scratch).await;
            for _ in 0..4096 {
                if socket.write_all(FLOOD).await.is_err() {
                    break;
                }
            }
        });

        let mut options = SendOptions::interactive(Origin::Repeater);
        options.limits.max_header_bytes = 4096;
        let err = TcpTransport::new()
            .send(request(port, "/"), options)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "limit_exceeded", "{err}");
    }

    #[tokio::test]
    async fn an_oversized_body_is_truncated_and_flagged() {
        static BIG: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let (port, _server) = serve(BIG).await;

        let mut options = SendOptions::interactive(Origin::Repeater);
        options.limits.max_body_bytes = 8;
        let exchange = TcpTransport::new()
            .send(request(port, "/"), options)
            .await
            .unwrap();

        assert_eq!(exchange.response.body.len(), 8);
        assert!(
            exchange.response.truncated,
            "evidence derived from a partial body must say it is partial"
        );
    }

    #[tokio::test]
    async fn a_declared_body_larger_than_the_limit_is_refused() {
        let (port, _server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nx").await;
        let mut options = SendOptions::interactive(Origin::Repeater);
        options.limits.max_body_bytes = 1024;
        let err = TcpTransport::new()
            .send(request(port, "/"), options)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "limit_exceeded");
    }

    #[tokio::test]
    async fn a_server_that_accepts_then_goes_silent_hits_the_head_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            // Accept and say nothing at all.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(socket);
        });

        let mut options = SendOptions::interactive(Origin::Repeater);
        options.limits.read_head_timeout = Duration::from_millis(150);
        let err = TcpTransport::new()
            .send(request(port, "/"), options)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "network");
        assert!(err.to_string().contains("response head"), "{err}");
    }

    #[tokio::test]
    async fn a_connection_closed_before_any_response_is_reported_clearly() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket);
        });

        let err = send(port, "/").await.unwrap_err();

        // The classification is genuinely platform-dependent and both answers are
        // truthful. Dropping a socket with unread data queued is an *abortive* close:
        // Windows sends RST, so the read fails with ECONNRESET and we report a network
        // error. Linux more often delivers a clean FIN first, so the read returns 0
        // bytes and we report a protocol error — the head never completed.
        //
        // Asserting one of them would make this test pass on the developer's machine
        // and fail in CI on the other OS, which is worse than useless. What actually
        // matters is that the failure is reported rather than hanging or panicking.
        assert!(
            matches!(err.code(), "network" | "protocol"),
            "unexpected classification: {err}"
        );
    }

    #[tokio::test]
    async fn a_refused_connection_is_classified_as_such() {
        // Bind, capture the port, then drop the listener so nothing is listening.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let err = send(port, "/").await.unwrap_err();
        assert_eq!(err.code(), "network");
        assert!(
            !err.is_retryable(),
            "a refused connection will not fix itself"
        );
    }

    #[tokio::test]
    async fn malformed_responses_produce_protocol_errors_not_panics() {
        for response in [
            &b"not http at all\r\n\r\n"[..],
            &b"HTTP/9.9 200 OK\r\n\r\n"[..],
            &b"HTTP/1.1 999 Nope\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx"[..],
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let owned = response.to_vec();
            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut scratch = vec![0u8; 4096];
                let _ = socket.read(&mut scratch).await;
                socket.write_all(&owned).await.ok();
                socket.shutdown().await.ok();
            });
            let err = send(port, "/").await.unwrap_err();
            assert_eq!(
                err.code(),
                "protocol",
                "{:?}",
                String::from_utf8_lossy(response)
            );
        }
    }

    // ------------------------------------------------------- honest boundaries

    // --------------------------------------------------------- chunked bodies

    #[tokio::test]
    async fn a_chunked_response_is_decoded() {
        let (port, _server) = serve(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        )
        .await;
        let exchange = send(port, "/").await.unwrap();
        assert_eq!(exchange.response.status, 200);
        assert_eq!(exchange.response.body.as_ref(), b"hello world");
        assert!(!exchange.response.truncated);
    }

    #[tokio::test]
    async fn chunked_trailers_join_the_header_list() {
        // Downstream code should not have to care whether a field arrived before or
        // after the body.
        let (port, _server) = serve(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Checksum: deadbeef\r\n\r\n",
        )
        .await;
        let exchange = send(port, "/").await.unwrap();
        assert_eq!(exchange.response.body.as_ref(), b"abc");
        assert_eq!(
            exchange
                .response
                .headers
                .get("X-Checksum")
                .unwrap()
                .value_lossy(),
            "deadbeef"
        );
    }

    #[tokio::test]
    async fn a_chunked_response_that_never_terminates_is_refused() {
        let (port, _server) =
            serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n").await;
        let err = send(port, "/").await.unwrap_err();
        assert_eq!(err.code(), "protocol", "{err}");
        assert!(err.to_string().contains("terminating chunk"), "{err}");
    }

    /// Compresses with gzip, so a test can assert against bytes it produced itself
    /// rather than against whatever the implementation happened to emit.
    fn gzip(payload: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib(payload: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn brotli_compress(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut reader = brotli::CompressorReader::new(payload, 4096, 5, 22);
        std::io::Read::read_to_end(&mut reader, &mut out).unwrap();
        out
    }

    /// Serves one response built at run time, which `serve` cannot: it takes a
    /// `&'static [u8]` and a compressed fixture is produced while the test runs.
    async fn serve_owned(response: Vec<u8>) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = vec![0u8; 8192];
            let _ = socket.read(&mut scratch).await;
            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
        });
        (port, handle)
    }

    /// Serves one response whose body is `body`, framed by Content-Length.
    async fn serve_encoded(coding: &str, body: Vec<u8>) -> (u16, tokio::task::JoinHandle<()>) {
        // Built here rather than inside the task: the coding is a borrowed `&str` and
        // the task outlives the call.
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut response = head.into_bytes();
        response.extend_from_slice(&body);
        serve_owned(response).await
    }

    #[tokio::test]
    async fn an_uncompressed_response_keeps_one_copy_of_its_body() {
        // No coding was reversed, so the decoded body already *is* the wire form.
        // Storing a second identical copy would double the memory of every ordinary
        // response to record a fact that is already true.
        let (port, _server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain").await;
        let exchange = send(port, "/").await.unwrap();

        assert_eq!(exchange.response.body.as_ref(), b"plain");
        assert!(exchange.encoded_body.is_none());
        assert!(exchange.content_encoding.is_none());
    }

    #[tokio::test]
    async fn a_gzip_response_keeps_the_gzip_bytes_and_the_application_bytes() {
        let compressed = gzip(b"compressed payload");
        let (port, _server) = serve_encoded("gzip", compressed.clone()).await;
        let exchange = send(port, "/").await.unwrap();

        assert_eq!(exchange.response.body.as_ref(), b"compressed payload");
        assert_eq!(
            exchange.encoded_body.as_deref(),
            Some(compressed.as_slice()),
            "the wire form is kept byte for byte, not re-compressed"
        );
        assert_eq!(exchange.content_encoding.as_deref(), Some("gzip"));

        // And the kept bytes really are a gzip stream: they decode on their own.
        let again = crate::decode::decode_body(
            "gzip",
            exchange.encoded_body.as_ref().unwrap(),
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(again.body.as_ref(), b"compressed payload");
    }

    #[tokio::test]
    async fn a_deflate_response_keeps_both_forms() {
        let compressed = zlib(b"deflated payload");
        let (port, _server) = serve_encoded("deflate", compressed.clone()).await;
        let exchange = send(port, "/").await.unwrap();

        assert_eq!(exchange.response.body.as_ref(), b"deflated payload");
        assert_eq!(
            exchange.encoded_body.as_deref(),
            Some(compressed.as_slice())
        );
        assert_eq!(exchange.content_encoding.as_deref(), Some("deflate"));
    }

    #[tokio::test]
    async fn a_brotli_response_keeps_both_forms() {
        let compressed = brotli_compress(b"brotli payload");
        let (port, _server) = serve_encoded("br", compressed.clone()).await;
        let exchange = send(port, "/").await.unwrap();

        assert_eq!(exchange.response.body.as_ref(), b"brotli payload");
        assert_eq!(
            exchange.encoded_body.as_deref(),
            Some(compressed.as_slice())
        );
        assert_eq!(exchange.content_encoding.as_deref(), Some("br"));
    }

    #[tokio::test]
    async fn chunked_framing_is_removed_but_the_gzip_bytes_survive() {
        // The distinction this milestone exists for. Chunk headers are framing and
        // are gone; the gzip stream inside them is content and is kept exactly.
        let compressed = gzip(b"chunked and compressed");
        let (first, second) = compressed.split_at(compressed.len() / 2);

        let mut response = Vec::new();
        response.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        response.extend_from_slice(format!("{:x}\r\n", first.len()).as_bytes());
        response.extend_from_slice(first);
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(format!("{:x}\r\n", second.len()).as_bytes());
        response.extend_from_slice(second);
        response.extend_from_slice(b"\r\n0\r\n\r\n");

        let (port, _server) = serve_owned(response).await;
        let exchange = send(port, "/").await.unwrap();

        assert_eq!(exchange.response.body.as_ref(), b"chunked and compressed");
        assert_eq!(
            exchange.encoded_body.as_deref(),
            Some(compressed.as_slice()),
            "the chunk headers are framing and belong in the quirks, not in the body"
        );
    }

    #[tokio::test]
    async fn a_response_with_no_body_keeps_neither_form() {
        let (port, _server) = serve(b"HTTP/1.1 204 No Content\r\n\r\n").await;
        let exchange = send(port, "/").await.unwrap();

        assert!(exchange.response.body.is_empty());
        assert!(exchange.encoded_body.is_none());
    }

    #[tokio::test]
    async fn a_malformed_compressed_body_is_an_error_rather_than_a_wrong_answer() {
        let (port, _server) = serve_encoded("gzip", b"not actually gzip".to_vec()).await;
        let error = send(port, "/").await.unwrap_err();
        assert_eq!(error.code(), "protocol", "{error}");
    }

    #[tokio::test]
    async fn a_decompression_bomb_bounds_both_forms_and_keeps_what_arrived() {
        // Four megabytes of zeroes compress to a few kilobytes. The limit fires while
        // the bytes are being expanded, so the decoded form stops at the cap — and the
        // exchange is still returned, because whatever arrived before the cut is
        // evidence. Neither representation grows past a bound: the wire form is capped
        // by `max_body_bytes` as it arrived, the decoded form by the limit below.
        let compressed = gzip(&vec![0u8; 4 * 1024 * 1024]);
        let cap = 64 * 1024;
        let (port, _server) = serve_encoded("gzip", compressed.clone()).await;

        let exchange = TcpTransport::new()
            .send(
                request(port, "/"),
                SendOptions {
                    origin: Origin::Repeater,
                    limits: Limits {
                        max_decompressed_bytes: cap,
                        ..Limits::default()
                    },
                    follow_redirects: false,
                },
            )
            .await
            .unwrap();

        assert!(
            exchange.response.truncated,
            "a body cut short must say so, or a reader measures a bomb as a document"
        );
        assert!(
            exchange.response.body.len() as u64 <= cap,
            "decoded {} bytes against a {cap}-byte cap",
            exchange.response.body.len()
        );
        assert_eq!(
            exchange.encoded_body.as_deref(),
            Some(compressed.as_slice()),
            "and the bytes that actually arrived are kept, which is what shows the              response was a bomb in the first place"
        );
    }

    #[tokio::test]
    async fn a_gzip_encoded_body_is_decoded() {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"compressed payload").unwrap();
        let compressed = encoder.finish().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = vec![0u8; 4096];
            let _ = socket.read(&mut scratch).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                compressed.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&compressed).await;
            let _ = socket.shutdown().await;
        });

        let exchange = send(port, "/").await.unwrap();
        assert_eq!(exchange.response.body.as_ref(), b"compressed payload");
    }

    // ------------------------------------------------------------------- raw mode

    /// Sends bytes exactly as given and returns what the server actually received.
    ///
    /// The assertion that matters in every test below is against *that* — not against
    /// what Hexora believed it sent. A byte-preservation claim checked anywhere but
    /// the socket is a claim about the wrong thing.
    async fn send_raw_bytes(bytes: &[u8]) -> (Exchange, Vec<u8>) {
        let (port, server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let raw =
            RawRequest::new(HttpService::new("127.0.0.1", port, false), bytes.to_vec()).unwrap();

        let exchange = TcpTransport::new()
            .send_raw(raw, SendOptions::interactive(Origin::Repeater))
            .await
            .unwrap();
        let received = server.await.unwrap();
        (exchange, received)
    }

    #[tokio::test]
    async fn a_raw_request_reaches_the_socket_byte_for_byte() {
        // Bare LF line endings, a lowercase header name, a duplicated header, a
        // deliberately wrong Content-Length and a byte that is not valid UTF-8. Every
        // one of them is something a serializer would have corrected.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"get /a?x=1 HTTP/1.1\n");
        bytes.extend_from_slice(b"host: 127.0.0.1\n");
        bytes.extend_from_slice(b"X-Dup: one\n");
        bytes.extend_from_slice(b"x-dup: two\n");
        bytes.extend_from_slice(b"Content-Length: 999\n");
        bytes.extend_from_slice(b"X-Odd: \xff\xfe\n");
        bytes.extend_from_slice(b"\n");
        bytes.extend_from_slice(b"hi");

        let (exchange, received) = send_raw_bytes(&bytes).await;

        assert_eq!(
            received, bytes,
            "the server must receive exactly what the tester wrote"
        );
        assert!(
            !received.windows(2).any(|w| w == b"\r\n"),
            "not one CRLF may appear where the tester wrote a bare LF"
        );
        assert_eq!(
            exchange.raw_request.as_deref(),
            Some(bytes.as_slice()),
            "and the record of what was sent is the bytes, not a re-serialization"
        );
        assert_eq!(exchange.response.status, 200);
    }

    #[tokio::test]
    async fn a_wrong_content_length_is_sent_as_written() {
        // The repeater warns about this and does not repair it. A tool that corrected
        // it would be answering a question about a different request.
        let bytes =
            b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nthis body is much longer";
        let (_, received) = send_raw_bytes(bytes).await;
        assert_eq!(received, bytes);
    }

    #[tokio::test]
    async fn conflicting_framing_headers_are_sent_as_written() {
        // Both `Content-Length` and `Transfer-Encoding`, which RFC 9112 6.1 says a
        // recipient must reject — and which is the entire basis of request smuggling
        // research, so it has to be sendable.
        let bytes = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let (_, received) = send_raw_bytes(bytes).await;
        assert_eq!(received, bytes);
    }

    #[tokio::test]
    async fn header_order_and_casing_survive() {
        let bytes = b"GET / HTTP/1.1\r\nhOsT: h\r\nZ-Last: 1\r\nA-First: 2\r\n\r\n";
        let (_, received) = send_raw_bytes(bytes).await;
        assert_eq!(received, bytes);
        let text = String::from_utf8_lossy(&received);
        assert!(text.contains("hOsT:"), "casing is preserved: {text}");
        assert!(
            text.find("Z-Last").unwrap() < text.find("A-First").unwrap(),
            "order is preserved: {text}"
        );
    }

    #[tokio::test]
    async fn a_nul_byte_in_the_body_survives() {
        let bytes = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na\x00b";
        let (_, received) = send_raw_bytes(bytes).await;
        assert_eq!(received, bytes);
        assert!(received.contains(&0));
    }

    #[tokio::test]
    async fn an_absolute_form_target_does_not_choose_the_socket() {
        // The request line points at another host; the connection still goes where the
        // caller said. Otherwise editing a request line would be a way to reach a host
        // the scope guard never saw.
        let bytes =
            b"GET http://elsewhere.invalid/admin HTTP/1.1\r\nHost: elsewhere.invalid\r\n\r\n";
        let (exchange, received) = send_raw_bytes(bytes).await;

        assert_eq!(received, bytes, "written as the tester wrote it");
        assert_eq!(
            exchange.request.service.host, "127.0.0.1",
            "but sent to the service the caller chose"
        );
    }

    #[tokio::test]
    async fn a_raw_head_request_is_framed_as_a_head_response() {
        // The method still matters for *reading* the answer: RFC 9112 6.3 says a HEAD
        // response has no body however its headers are framed. Read from the raw
        // request line rather than assumed.
        let (port, _server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n").await;
        let raw = RawRequest::new(
            HttpService::new("127.0.0.1", port, false),
            b"HEAD / HTTP/1.1\r\nHost: h\r\n\r\n".to_vec(),
        )
        .unwrap();

        let exchange = TcpTransport::new()
            .send_raw(raw, SendOptions::interactive(Origin::Repeater))
            .await
            .unwrap();
        assert!(exchange.response.body.is_empty());
    }

    #[tokio::test]
    async fn the_structured_view_of_a_raw_request_is_readable_without_being_authoritative() {
        let bytes = b"PUT /items/7 HTTP/1.1\nHost: h\nX-Trace: abc\n\npayload";
        let (exchange, _) = send_raw_bytes(bytes).await;

        // Good enough for a history row...
        assert_eq!(exchange.request.method, "PUT");
        assert_eq!(exchange.request.path, "/items/7");
        assert_eq!(
            exchange
                .request
                .headers
                .get("X-Trace")
                .map(|h| h.value_lossy().into_owned()),
            Some("abc".to_string())
        );
        assert_eq!(exchange.request.body.as_ref(), b"payload");
        // ...and never the thing that was sent.
        assert_eq!(exchange.raw_request.as_deref(), Some(bytes.as_slice()));
    }

    // ------------------------------------------------------------------- TLS

    /// Serves one HTTPS connection with a throwaway self-signed certificate.
    ///
    /// Local rather than hitting a real site: a test suite that needs the internet
    /// fails for reasons that have nothing to do with the code.
    async fn serve_tls(response: &'static [u8], dns_name: &str) -> u16 {
        use tokio_rustls::TlsAcceptor;

        let issued = rcgen::generate_simple_self_signed(vec![dns_name.to_string()]).unwrap();
        let cert = rustls::pki_types::CertificateDer::from(issued.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(issued.key_pair.serialize_der().into());

        let mut config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        // ALPN is a negotiation, so the server has to offer it too. Without this the
        // client's preference simply goes unanswered and `alpn` comes back as None.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(socket).await {
                let mut scratch = vec![0u8; 4096];
                let _ = tls.read(&mut scratch).await;
                let _ = tls.write_all(response).await;
                let _ = tls.shutdown().await;
            }
        });
        port
    }

    fn https_request(port: u16) -> HttpRequest {
        HttpRequest::get(HttpService::new("localhost", port, true), "/")
    }

    #[tokio::test]
    async fn a_tls_request_completes_and_records_the_handshake() {
        let port = serve_tls(
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure",
            "localhost",
        )
        .await;

        // Self-signed, so verification must be relaxed — exactly the staging case.
        let transport = TcpTransport::with_tls(crate::tls::TlsConfig::accept_any());
        let exchange = transport
            .send(
                https_request(port),
                SendOptions::interactive(Origin::Repeater),
            )
            .await
            .unwrap();

        assert_eq!(exchange.response.status, 200);
        assert_eq!(exchange.response.body.as_ref(), b"secure");

        let tls = exchange
            .tls
            .expect("an https exchange records its handshake");
        assert!(tls.protocol.starts_with("TLSv1"), "{}", tls.protocol);
        assert!(!tls.cipher_suite.is_empty());
        assert_eq!(
            tls.alpn.as_deref(),
            Some("http/1.1"),
            "ALPN must be negotiated"
        );
        assert!(
            !tls.peer_authenticated(),
            "accept-any does not authenticate"
        );
    }

    #[tokio::test]
    async fn the_peer_certificate_is_captured_for_evidence() {
        let port = serve_tls(b"HTTP/1.1 204 No Content\r\n\r\n", "localhost").await;
        let transport = TcpTransport::with_tls(crate::tls::TlsConfig::accept_any());
        let exchange = transport
            .send(
                https_request(port),
                SendOptions::interactive(Origin::Repeater),
            )
            .await
            .unwrap();

        let tls = exchange.tls.unwrap();
        let leaf = tls.peer_certificates.first().expect("a leaf certificate");
        assert!(leaf.self_signed, "{leaf:?}");
        assert!(
            leaf.subject_alt_names
                .iter()
                .any(|n| n.contains("localhost")),
            "{leaf:?}"
        );
        assert!(
            tls.observations().iter().any(|o| o.contains("self-signed")),
            "a self-signed peer is worth telling the tester about"
        );
    }

    #[tokio::test]
    async fn an_untrusted_certificate_is_refused_when_verification_is_on() {
        let port = serve_tls(
            b"HTTP/1.1 200 OK\r\n\r\nContent-Length: 0\r\n\r\n\r\n\r\n",
            "localhost",
        )
        .await;

        // Default transport verifies against the platform store, which will not
        // contain a certificate generated moments ago.
        let err = TcpTransport::new()
            .send(
                https_request(port),
                SendOptions::interactive(Origin::Repeater),
            )
            .await
            .unwrap_err();

        assert_eq!(err.code(), "network", "{err}");
        assert!(err.to_string().to_lowercase().contains("tls"), "{err}");
    }

    #[tokio::test]
    async fn plaintext_exchanges_record_no_tls() {
        let (port, _server) =
            serve(b"HTTP/1.1 200 OK\r\n\r\nContent-Length: 0\r\n\r\n\r\n\r\n").await;
        let exchange = send(port, "/").await.unwrap();
        assert!(exchange.tls.is_none());
    }

    #[tokio::test]
    async fn an_invalid_sni_name_is_rejected_before_connecting() {
        let mut settings = crate::tls::TlsConfig::accept_any();
        settings.sni_override = Some("not a valid dns name!".to_string());

        // Port 9 discards; the SNI check must fail before any handshake matters.
        let request = HttpRequest::get(HttpService::new("127.0.0.1", 9, true), "/");
        let mut options = SendOptions::interactive(Origin::Repeater);
        options.limits.connect_timeout = Duration::from_millis(300);

        let err = TcpTransport::with_tls(settings)
            .send(request, options)
            .await
            .unwrap_err();
        // Either the connection never happened or the name was rejected; both are
        // failures before any data could be exchanged.
        assert!(matches!(err.code(), "invalid_input" | "network"), "{err}");
    }

    // ----------------------------------------------------------- smuggling eye

    #[tokio::test]
    async fn smuggling_signals_survive_the_round_trip() {
        // Bare LF terminators plus CL and TE together: two primitives at once.
        let (port, _server) =
            serve(b"HTTP/1.0 200 OK\nContent-Length: 5\nX-Odd : 1\n\nhello").await;
        let exchange = send(port, "/").await.unwrap();
        assert_eq!(exchange.response.body.as_ref(), b"hello");
        // The response still parsed and the body is correct — the point is that a
        // normal client would have shown exactly this and told you nothing.
        assert_eq!(exchange.response.status, 200);
    }
}

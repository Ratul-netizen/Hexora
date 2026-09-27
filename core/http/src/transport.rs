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
//! callers — the repeater, `hexora send` — that genuinely want the whole body. It is
//! also the only path that speaks **HTTP/2**: with [`TcpTransport::http2`] enabled and a
//! target that offers `h2` at ALPN, `send` hands the connection to [`crate::h2`] and
//! returns the same [`Exchange`]; a server that declines gets the ordinary HTTP/1.x
//! exchange over the same socket. The streaming path stays HTTP/1.x, so the proxy is
//! untouched until M5.1c.
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
    /// Whether the buffered [`HttpTransport::send`] may negotiate HTTP/2.
    ///
    /// Off by default, and only ever consulted by `send` — never by the streaming path
    /// the proxy uses, which stays HTTP/1.x until M5.1c. So a client (the repeater, the
    /// scanner, `hexora send`) turns this on to reach h2-only targets, while the proxy's
    /// own transport is unaffected even though it is the same type.
    http2: bool,
    /// Reusable HTTP/2 connections, one per host, shared across clones of this transport.
    ///
    /// An `Arc` so that a scan or repeater which clones the transport still reuses the one
    /// pool: connection reuse across a whole run is the point of it. Empty and idle until
    /// the first h2 negotiation.
    h2_pool: std::sync::Arc<crate::h2pool::H2Pool>,
}

/// The parts of a request needed to write it and frame the response, kept together so
/// they travel as one argument rather than a handful that are always passed in lockstep.
struct Outgoing {
    request: HttpRequest,
    wire: Vec<u8>,
    method: String,
    raw: Option<bytes::Bytes>,
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
            http2: false,
            h2_pool: std::sync::Arc::new(crate::h2pool::H2Pool::new()),
        }
    }

    /// A transport with explicit TLS settings.
    ///
    /// Settings live on the transport rather than on each request because a tester
    /// works against one estate at a time: relaxing verification is a decision about
    /// *this engagement*, and building a second transport is how you say the next one
    /// is different. It is never a process-wide toggle.
    pub fn with_tls(tls: TlsConfig) -> Self {
        Self {
            tls,
            http2: false,
            h2_pool: std::sync::Arc::new(crate::h2pool::H2Pool::new()),
        }
    }

    /// Enables (or disables) HTTP/2 on the buffered [`HttpTransport::send`] path.
    ///
    /// When on and the target is `https`, `send` offers `h2` with an HTTP/1.1 fallback
    /// (unless the transport's TLS settings already pin an ALPN list naming `h2`) and,
    /// if the server negotiates it, speaks HTTP/2. A server that declines gets the
    /// ordinary HTTP/1.x exchange over the connection already opened — no second
    /// handshake. The streaming path is deliberately untouched, so this cannot change
    /// what the proxy sends.
    pub fn http2(mut self, enabled: bool) -> Self {
        self.http2 = enabled;
        self
    }

    /// The TLS settings this transport uses upstream.
    ///
    /// Exposed so a caller that must open its own connection — the WebSocket relay, which
    /// forwards a raw byte stream the buffered `send` cannot carry — reaches the origin with
    /// the same verification the rest of the proxy uses, rather than inventing its own.
    pub fn tls_config(&self) -> &TlsConfig {
        &self.tls
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
        let (connection, tls) = self.establish(&request.service, &options.limits).await?;
        Self::exchange_over(
            connection,
            tls,
            Outgoing {
                request,
                wire,
                method,
                raw,
            },
            &options.limits,
            started,
        )
        .await
    }

    /// Opens a connection to a service and performs the TLS handshake when it is `https`.
    ///
    /// The HTTP/1.x path this transport was built for; the buffered [`HttpTransport::send`]
    /// does its own connect when it wants to offer HTTP/2, so it can inspect what ALPN
    /// negotiated before committing to a protocol.
    async fn establish(
        &self,
        service: &hexora_types::http::HttpService,
        limits: &Limits,
    ) -> Result<(Box<dyn Connection>, Option<hexora_types::tls::TlsInfo>)> {
        let tcp = connect(&service.host, service.port, limits).await?;

        // Boxed so the body stream can own the connection, whichever kind it is.
        if service.secure {
            let (stream, tls) =
                crate::tls::handshake(tcp, &service.host, &self.tls, limits).await?;
            Ok((Box::new(stream), Some(tls)))
        } else {
            Ok((Box::new(tcp), None))
        }
    }

    /// Writes a request over an already-established connection and reads the head.
    ///
    /// Split out from [`Self::write_and_read`] so the HTTP/2-capable `send` can reuse a
    /// connection it opened itself — when a server declined `h2` at ALPN, the ordinary
    /// HTTP/1.x exchange runs over that same socket rather than opening a second one.
    async fn exchange_over(
        mut connection: Box<dyn Connection>,
        tls: Option<hexora_types::tls::TlsInfo>,
        outgoing: Outgoing,
        limits: &Limits,
        started: Instant,
    ) -> Result<StreamingExchange> {
        let Outgoing {
            request,
            wire,
            method,
            raw,
        } = outgoing;
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
        // HTTP/2 is negotiated here, on the buffered path only, and only for https —
        // browsers reach h2 through ALPN, and h2c (cleartext prior knowledge) is rare
        // enough not to attempt uninvited.
        if self.http2 && request.service.secure {
            let started = Instant::now();
            let limits = options.limits.clone();
            let key = (request.service.host.clone(), request.service.port);

            // Fast path: multiplex a new stream onto a connection already open to this
            // host. No lock is held across this, so concurrent requests to the one host
            // share the connection rather than queueing.
            //
            // A failure on a *reused* connection is retried once on a fresh one: readiness
            // cannot always tell a connection the peer closed between the check and the
            // send, and a pooled connection that refuses a new stream did not process the
            // request, so reconnecting is safe. A fresh connection's failure is returned.
            if let Some((handle, tls)) = self.h2_pool.reuse(&key).await {
                match crate::h2::send_on(handle, tls, request.clone(), &limits, started).await {
                    Ok(exchange) => return Ok(exchange),
                    Err(_) => self.h2_pool.evict(&key),
                }
            }

            // Miss: establish, but serialise it per host so a first-connect race opens one
            // connection, not one per racing request. Different hosts still connect at
            // once, since the gate is per host.
            let gate = self.h2_pool.gate(&key);
            let establishing = gate.lock().await;

            // Another request may have established the connection while we waited.
            if let Some((handle, tls)) = self.h2_pool.reuse(&key).await {
                match crate::h2::send_on(handle, tls, request.clone(), &limits, started).await {
                    Ok(exchange) => return Ok(exchange),
                    Err(_) => self.h2_pool.evict(&key),
                }
            }

            let tcp = connect(&request.service.host, request.service.port, &limits).await?;

            // Offer h2 with an HTTP/1.1 fallback, unless the caller already pinned an
            // ALPN list of their own that names it — a deliberate ALPN is a test in its
            // own right and is not overridden.
            let mut tls_config = self.tls.clone();
            if !tls_config.alpn.iter().any(|p| p == b"h2") {
                tls_config.alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }

            let (stream, info) =
                crate::tls::handshake(tcp, &request.service.host, &tls_config, &limits).await?;

            if info.alpn.as_deref() == Some("h2") {
                let handle = crate::h2::handshake(stream, &limits).await?;
                self.h2_pool.store(key, handle.clone(), info.clone());
                // The gate covers opening the connection, not sending on it: once the
                // connection is pooled, other requests to this host multiplex onto it
                // freely rather than waiting for this request to finish.
                drop(establishing);
                return crate::h2::send_on(handle, info, request, &limits, started).await;
            }

            // The server declined h2; run the ordinary HTTP/1.x exchange over the
            // connection already open rather than reconnecting. Not pooled — HTTP/1.x
            // connection reuse is M1.4, and a mis-framed reuse corrupts the next response.
            // Nothing was stored, so the gate can be released now.
            drop(establishing);
            let wire = serialize_request(&request);
            let method = request.method.clone();
            return Self::exchange_over(
                Box::new(stream),
                Some(info),
                Outgoing {
                    request,
                    wire,
                    method,
                    raw: None,
                },
                &limits,
                started,
            )
            .await?
            .collect()
            .await;
        }

        self.send_streaming(request, options).await?.collect().await
    }

    async fn send_raw(&self, request: RawRequest, options: SendOptions) -> Result<Exchange> {
        self.send_raw_streaming(request, options)
            .await?
            .collect()
            .await
    }

    /// Frame-level HTTP/2 — the h2 analogue of a raw h1 send.
    ///
    /// The request carries the connection target and the header list; both go out exactly as
    /// written, with none of the validation the conforming path applies, which is how a
    /// tester reaches the requests the `h2` crate refuses to emit. A fresh connection is
    /// always opened — a hand-driven raw stream shares no state with the conforming pool, and
    /// a raw send wants to control the whole connection anyway. h2 is required: it is offered
    /// alone at ALPN and a server that declines is an error, because there is no such thing
    /// as a frame-level h2 request over HTTP/1.1.
    async fn send_raw_h2(
        &self,
        request: hexora_types::raw::RawH2Request,
        options: SendOptions,
    ) -> Result<Exchange> {
        let started = Instant::now();
        let limits = &options.limits;

        if !request.service.secure {
            return Err(HexoraError::NotImplemented(
                "frame-level HTTP/2 over cleartext (h2c)",
            ));
        }

        let tcp = connect(&request.service.host, request.service.port, limits).await?;
        let mut tls_config = self.tls.clone();
        tls_config.alpn = vec![b"h2".to_vec()];
        let (stream, info) =
            crate::tls::handshake(tcp, &request.service.host, &tls_config, limits).await?;

        if info.alpn.as_deref() != Some("h2") {
            return Err(HexoraError::Protocol(
                hexora_types::error::ProtocolError::Malformed {
                    protocol: "HTTP/2",
                    reason: "the server did not negotiate h2, so a frame-level h2 request \
                             cannot be sent"
                        .to_string(),
                },
            ));
        }

        crate::h2raw::send(stream, info, &request, limits, started).await
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
            "and the bytes that actually arrived are kept, which is what shows the \
             response was a bomb in the first place"
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

    // ------------------------------------------------------------------- HTTP/2

    /// Serves one HTTP/2 connection over TLS, answering every stream identically.
    ///
    /// Uses the `h2` crate on the server side too, so the test exercises a real HPACK +
    /// framing round trip rather than a mock. `content_encoding` is set on the response
    /// when non-empty, and `body` is sent as-is — a caller that wants a gzip body
    /// compresses it and names the coding.
    async fn serve_h2(
        status: u16,
        extra_headers: &'static [(&'static str, &'static str)],
        content_encoding: &'static str,
        body: &'static [u8],
    ) -> u16 {
        use tokio_rustls::TlsAcceptor;

        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
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
        // Offer only h2, so a client that reaches this server has genuinely negotiated it.
        config.alpn_protocols = vec![b"h2".to_vec()];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(socket).await.unwrap();
            let mut connection = ::h2::server::handshake(tls).await.unwrap();
            while let Some(accepted) = connection.accept().await {
                let (request, mut responder) = accepted.unwrap();
                // Drain the request body so a POST completes cleanly.
                let mut request_body = request.into_body();
                while let Some(chunk) = request_body.data().await {
                    let chunk = chunk.unwrap();
                    let _ = request_body.flow_control().release_capacity(chunk.len());
                }

                let mut builder = http::Response::builder().status(status);
                if !content_encoding.is_empty() {
                    builder = builder.header("content-encoding", content_encoding);
                }
                for (name, value) in extra_headers {
                    builder = builder.header(*name, *value);
                }
                let response = builder.body(()).unwrap();
                let mut send = responder.send_response(response, false).unwrap();
                send.send_data(bytes::Bytes::copy_from_slice(body), true)
                    .unwrap();
            }
        });
        port
    }

    #[tokio::test]
    async fn an_http2_request_round_trips_and_records_the_protocol() {
        let port = serve_h2(200, &[("x-proto", "h2")], "", b"served over h2").await;

        let transport = TcpTransport::with_tls(crate::tls::TlsConfig::accept_any()).http2(true);
        let exchange = transport
            .send(
                https_request(port),
                SendOptions::interactive(Origin::Repeater),
            )
            .await
            .unwrap();

        assert_eq!(exchange.response.status, 200);
        assert_eq!(exchange.response.body.as_ref(), b"served over h2");
        assert_eq!(exchange.response.version, HttpVersion::Http2);
        assert_eq!(
            exchange
                .response
                .headers
                .get("x-proto")
                .map(|h| h.value_lossy().into_owned()),
            Some("h2".to_string())
        );

        let tls = exchange
            .tls
            .expect("an https exchange records its handshake");
        assert_eq!(tls.alpn.as_deref(), Some("h2"), "h2 must have negotiated");
    }

    #[tokio::test]
    async fn an_http2_capable_client_falls_back_to_http1_when_the_server_declines() {
        // The server offers only http/1.1; an h2-enabled client must still get an answer,
        // over the connection it already opened, recorded as HTTP/1.1.
        let port = serve_tls(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfallback",
            "localhost",
        )
        .await;

        let transport = TcpTransport::with_tls(crate::tls::TlsConfig::accept_any()).http2(true);
        let exchange = transport
            .send(
                https_request(port),
                SendOptions::interactive(Origin::Repeater),
            )
            .await
            .unwrap();

        assert_eq!(exchange.response.status, 200);
        assert_eq!(exchange.response.body.as_ref(), b"fallback");
        assert_eq!(exchange.response.version, HttpVersion::Http11);
        assert_eq!(exchange.tls.unwrap().alpn.as_deref(), Some("http/1.1"));
    }

    #[tokio::test]
    async fn an_http2_gzip_body_is_decoded_and_both_forms_are_kept() {
        let compressed: &'static [u8] = Box::leak(gzip(b"the plain body").into_boxed_slice());
        let port = serve_h2(200, &[], "gzip", compressed).await;

        let transport = TcpTransport::with_tls(crate::tls::TlsConfig::accept_any()).http2(true);
        let exchange = transport
            .send(
                https_request(port),
                SendOptions::interactive(Origin::Repeater),
            )
            .await
            .unwrap();

        // The decoded body is what a caller reads, the same as for HTTP/1.x.
        assert_eq!(exchange.response.body.as_ref(), b"the plain body");
        assert_eq!(exchange.content_encoding.as_deref(), Some("gzip"));
        assert_eq!(
            exchange.encoded_body.as_deref(),
            Some(compressed),
            "the gzip bytes are kept alongside the decoded form"
        );
    }

    #[tokio::test]
    async fn the_buffered_send_stays_http1_when_http2_is_not_enabled() {
        // Without .http2(true) an https send must not offer h2, even to a server that
        // would accept it — the proxy relies on this, since it shares the type.
        let port = serve_tls(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
            "localhost",
        )
        .await;
        let transport = TcpTransport::with_tls(crate::tls::TlsConfig::accept_any());
        let exchange = transport
            .send(
                https_request(port),
                SendOptions::interactive(Origin::Repeater),
            )
            .await
            .unwrap();
        assert_eq!(exchange.response.version, HttpVersion::Http11);
        assert_eq!(exchange.tls.unwrap().alpn.as_deref(), Some("http/1.1"));
    }

    /// Serves HTTP/2 over TLS, counting TCP connections and optionally closing a
    /// connection after it has carried `streams_per_conn` streams (0 = never close).
    ///
    /// The connection count is what a reuse test asserts on: many requests that share one
    /// connection increment it once. Closing after N streams is how a re-establish test
    /// forces the client to notice a dead connection and reconnect.
    async fn serve_h2_counting(
        status: u16,
        body: &'static [u8],
        streams_per_conn: usize,
    ) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio_rustls::TlsAcceptor;

        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
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
        config.alpn_protocols = vec![b"h2".to_vec()];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));

        let count = Arc::new(AtomicUsize::new(0));
        let count_task = count.clone();
        tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                count_task.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let tls = match acceptor.accept(socket).await {
                        Ok(tls) => tls,
                        Err(_) => return,
                    };
                    let mut connection = match ::h2::server::handshake(tls).await {
                        Ok(connection) => connection,
                        Err(_) => return,
                    };
                    let mut served = 0usize;
                    while let Some(accepted) = connection.accept().await {
                        let (request, mut responder) = match accepted {
                            Ok(pair) => pair,
                            Err(_) => break,
                        };
                        let mut request_body = request.into_body();
                        while let Some(chunk) = request_body.data().await {
                            if let Ok(chunk) = chunk {
                                let _ = request_body.flow_control().release_capacity(chunk.len());
                            }
                        }
                        let response = http::Response::builder().status(status).body(()).unwrap();
                        if let Ok(mut send) = responder.send_response(response, false) {
                            let _ = send.send_data(bytes::Bytes::copy_from_slice(body), true);
                        }
                        served += 1;
                        if streams_per_conn != 0 && served >= streams_per_conn {
                            // Close the way a real server does — a GOAWAY the client sees,
                            // sent *after* this stream's response — rather than dropping the
                            // socket mid-flight. Draining the accept loop flushes it.
                            connection.graceful_shutdown();
                            while connection.accept().await.is_some() {}
                            break;
                        }
                    }
                });
            }
        });
        (port, count)
    }

    #[tokio::test]
    async fn http2_connections_are_reused_across_requests() {
        use std::sync::atomic::Ordering;
        let (port, count) = serve_h2_counting(200, b"ok", 0).await;

        let transport = TcpTransport::with_tls(crate::tls::TlsConfig::accept_any()).http2(true);
        for _ in 0..3 {
            let exchange = transport
                .send(
                    https_request(port),
                    SendOptions::interactive(Origin::Repeater),
                )
                .await
                .unwrap();
            assert_eq!(exchange.response.status, 200);
        }

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "three sequential requests must share one pooled connection"
        );
    }

    #[tokio::test]
    async fn concurrent_http2_requests_multiplex_over_one_connection() {
        use std::sync::atomic::Ordering;
        let (port, count) = serve_h2_counting(200, b"ok", 0).await;

        // Shared so every task uses the one pool; the gate must collapse the first-connect
        // race to a single connection while the requests themselves multiplex.
        let transport = std::sync::Arc::new(
            TcpTransport::with_tls(crate::tls::TlsConfig::accept_any()).http2(true),
        );

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let transport = transport.clone();
            tasks.push(tokio::spawn(async move {
                transport
                    .send(
                        https_request(port),
                        SendOptions::interactive(Origin::Repeater),
                    )
                    .await
            }));
        }
        for task in tasks {
            let exchange = task.await.unwrap().unwrap();
            assert_eq!(exchange.response.status, 200);
        }

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "eight concurrent requests must share one pooled connection"
        );
    }

    #[tokio::test]
    async fn a_dead_http2_connection_is_evicted_and_replaced() {
        use std::sync::atomic::Ordering;
        // The server closes each connection after one stream, so the second request finds
        // a dead pooled handle and must reconnect rather than fail.
        let (port, count) = serve_h2_counting(200, b"ok", 1).await;

        let transport = TcpTransport::with_tls(crate::tls::TlsConfig::accept_any()).http2(true);

        let first = transport
            .send(
                https_request(port),
                SendOptions::interactive(Origin::Repeater),
            )
            .await
            .unwrap();
        assert_eq!(first.response.status, 200);

        // Let the server's close propagate so the pooled handle is observably dead.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let second = transport
            .send(
                https_request(port),
                SendOptions::interactive(Origin::Repeater),
            )
            .await
            .unwrap();
        assert_eq!(second.response.status, 200);

        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "a closed connection must be replaced, not reused"
        );
    }

    #[tokio::test]
    async fn a_frame_level_h2_request_reads_the_status_and_body() {
        let port = serve_h2(200, &[("x-proto", "h2")], "", b"raw hello").await;

        let transport = TcpTransport::with_tls(crate::tls::TlsConfig::accept_any());
        let service = HttpService::new("localhost", port, true);
        let request = hexora_types::raw::RawH2Request::get(service, "/");

        let exchange = transport
            .send_raw_h2(request, SendOptions::interactive(Origin::Repeater))
            .await
            .unwrap();

        assert_eq!(exchange.response.status, 200);
        assert_eq!(exchange.response.body.as_ref(), b"raw hello");
        assert_eq!(exchange.response.version, HttpVersion::Http2);
    }

    #[tokio::test]
    async fn a_frame_level_send_emits_a_header_the_conforming_client_would_refuse() {
        // An uppercase field name is malformed per RFC 9113 §8.2.1; the `h2` crate would
        // never let a client send it, and a conforming server rejects it with a stream
        // reset. That the request reaches the server at all is the capability M5.1e adds.
        let port = serve_h2(200, &[], "", b"unreachable").await;

        let transport = TcpTransport::with_tls(crate::tls::TlsConfig::accept_any());
        let service = HttpService::new("localhost", port, true);
        let mut request = hexora_types::raw::RawH2Request::get(service, "/");
        request.headers.push((
            bytes::Bytes::from_static(b"X-Uppercase-Name"),
            bytes::Bytes::from_static(b"1"),
        ));

        let error = transport
            .send_raw_h2(request, SendOptions::interactive(Origin::Repeater))
            .await
            .expect_err(
                "the server must refuse a malformed header the conforming client could not send",
            );

        let message = error.to_string();
        assert!(
            message.contains("reset") || message.contains("GOAWAY"),
            "the refusal should be reported as what it was: {message}"
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

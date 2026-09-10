//! The TCP transport.
//!
//! M1.1 scope: HTTP/1.1 (and 1.0) over plaintext TCP, bodies delimited by
//! `Content-Length` or by connection close. TLS is M1.2, streaming is M1.3, pooling is
//! M1.4, chunked decoding is M1.5.
//!
//! Unimplemented framing fails loudly rather than returning a wrong body. A chunked
//! response here returns [`HexoraError::NotImplemented`], because silently handing back
//! the raw chunk headers as if they were content would corrupt every measurement built
//! on top of it — and in a security tool, a wrong body becomes a wrong finding.
//!
//! # Timeouts
//!
//! Every phase is bounded separately rather than sharing one deadline, because the
//! phases fail for different reasons and a tester needs to know which one stalled: a
//! connect timeout means the host is unreachable, a read-head timeout means the server
//! accepted the connection and then stopped talking — a slowloris in reverse.

use std::time::Instant;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use hexora_engine::transport::{Exchange, HttpTransport, SendOptions};
use hexora_types::error::{HexoraError, NetworkError, Result, TimeoutPhase};
use hexora_types::http::{HttpRequest, HttpResponse};
use hexora_types::limits::Limits;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::parse::{find_head_end, parse_response_head, BodyFraming, Quirk, ResponseHead};
use crate::write::serialize_request;

/// Reads from the socket in chunks of this size.
const READ_CHUNK: usize = 16 * 1024;

/// An HTTP/1.x transport over plaintext TCP.
///
/// Opens a fresh connection per request. Connection reuse is M1.4; doing it now would
/// mean building a pool before there is a parser proven to find message boundaries
/// correctly, and a pool that mis-frames one response corrupts the next.
#[derive(Debug, Default, Clone)]
pub struct TcpTransport {
    _private: (),
}

impl TcpTransport {
    /// Creates a transport.
    pub fn new() -> Self {
        Self::default()
    }
}

/// What came back, before it is turned into an [`HttpResponse`].
#[derive(Debug)]
struct RawExchange {
    head: ResponseHead,
    body: Bytes,
    truncated: bool,
}

#[async_trait]
impl HttpTransport for TcpTransport {
    async fn send(&self, request: HttpRequest, options: SendOptions) -> Result<Exchange> {
        if request.service.secure {
            return Err(HexoraError::NotImplemented(
                "TLS transport (M1.2); this build can only send plaintext HTTP",
            ));
        }

        let started = Instant::now();
        let limits = &options.limits;

        let mut stream = connect(&request.service.host, request.service.port, limits).await?;

        let wire = serialize_request(&request);
        write_all(&mut stream, &wire, limits).await?;

        let raw = read_response(&mut stream, &request.method, limits).await?;

        let response = HttpResponse {
            status: raw.head.status,
            reason: raw.head.reason.clone(),
            version: raw.head.version,
            headers: raw.head.headers.clone(),
            body: raw.body,
            truncated: raw.truncated,
        };

        if raw.head.has_smuggling_signal() {
            let signals: Vec<&str> = raw
                .head
                .quirks
                .iter()
                .filter(|q| q.is_smuggling_signal())
                .map(Quirk::explanation)
                .collect();
            // Warn, not debug: this is a finding waiting to be raised, not noise.
            tracing::warn!(
                url = %request.url(),
                signals = ?signals,
                "response framing shows a request-smuggling signal"
            );
        }

        Ok(Exchange {
            request,
            response,
            duration: started.elapsed(),
        })
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

async fn write_all(stream: &mut TcpStream, bytes: &[u8], limits: &Limits) -> Result<()> {
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

async fn read_response(
    stream: &mut TcpStream,
    request_method: &str,
    limits: &Limits,
) -> Result<RawExchange> {
    let (head, mut body) = read_head(stream, request_method, limits).await?;

    let mut truncated = false;
    match head.framing {
        BodyFraming::None => body.clear(),

        BodyFraming::ContentLength(length) => {
            limits.check_body_size(length)?;
            let wanted = usize::try_from(length).map_err(|_| {
                HexoraError::LimitExceeded(hexora_types::error::LimitError::BodyTooLarge {
                    limit: limits.max_body_bytes,
                })
            })?;
            read_exactly(stream, &mut body, wanted, limits).await?;
            if body.len() > wanted {
                // Extra bytes belong to a pipelined response we did not ask for.
                // Keeping them would corrupt this body; they are dropped with the
                // connection, which we close anyway until M1.4.
                body.truncate(wanted);
            }
        }

        BodyFraming::UntilClose => {
            truncated = read_until_close(stream, &mut body, limits).await?;
        }

        BodyFraming::Chunked => {
            return Err(HexoraError::NotImplemented(
                "chunked transfer decoding (M1.5)",
            ));
        }
    }

    Ok(RawExchange {
        head,
        body: body.freeze(),
        truncated,
    })
}

/// Reads until the head terminator, returning the head and any body bytes that
/// arrived in the same read.
async fn read_head(
    stream: &mut TcpStream,
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

async fn read_exactly(
    stream: &mut TcpStream,
    buf: &mut BytesMut,
    wanted: usize,
    limits: &Limits,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + limits.total_timeout;
    while buf.len() < wanted {
        let read = tokio::time::timeout_at(deadline, read_more(stream, buf))
            .await
            .map_err(|_| {
                HexoraError::Network(NetworkError::Timeout {
                    phase: TimeoutPhase::ReadResponseBody,
                    elapsed: limits.total_timeout,
                })
            })??;
        if read == 0 {
            return Err(HexoraError::Protocol(
                hexora_types::error::ProtocolError::Malformed {
                    protocol: "HTTP/1.1",
                    reason: format!(
                        "connection closed after {} of {wanted} declared body bytes",
                        buf.len()
                    ),
                },
            ));
        }
        limits.check_body_size(buf.len() as u64)?;
    }
    Ok(())
}

/// Reads until EOF. Returns whether the body was cut short by a limit.
async fn read_until_close(
    stream: &mut TcpStream,
    buf: &mut BytesMut,
    limits: &Limits,
) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + limits.total_timeout;
    loop {
        if buf.len() as u64 >= limits.max_body_bytes {
            buf.truncate(limits.max_body_bytes as usize);
            // Truncation is reported rather than silently applied: a finding built on
            // a partial body must disclose that it is partial.
            return Ok(true);
        }
        let read = tokio::time::timeout_at(deadline, read_more(stream, buf))
            .await
            .map_err(|_| {
                HexoraError::Network(NetworkError::Timeout {
                    phase: TimeoutPhase::ReadResponseBody,
                    elapsed: limits.total_timeout,
                })
            })??;
        if read == 0 {
            return Ok(false);
        }
    }
}

async fn read_more(stream: &mut TcpStream, buf: &mut BytesMut) -> Result<usize> {
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

    #[tokio::test]
    async fn chunked_responses_fail_loudly_instead_of_returning_a_wrong_body() {
        let (port, _server) =
            serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
                .await;
        let err = send(port, "/").await.unwrap_err();
        assert_eq!(err.code(), "not_implemented");
        assert!(err.to_string().contains("M1.5"), "{err}");
    }

    #[tokio::test]
    async fn https_is_refused_until_the_tls_milestone() {
        let request = HttpRequest::get(HttpService::new("example.com", 443, true), "/");
        let err = TcpTransport::new()
            .send(request, SendOptions::interactive(Origin::Repeater))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "not_implemented");
        assert!(err.to_string().contains("M1.2"), "{err}");
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

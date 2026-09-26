//! # hexora-http
//!
//! Hexora's HTTP/1.x engine.
//!
//! ## What makes this different from an HTTP client
//!
//! A client library exists to make HTTP easy and correct. This exists to make HTTP
//! *observable*, including when it is neither easy nor correct. Three consequences
//! run through the whole crate:
//!
//! * **Nothing is normalized.** Header order, casing, duplicates and non-UTF-8 bytes
//!   all survive in both directions. A request is sent exactly as written, even when
//!   it is self-contradictory.
//! * **Ambiguity is recorded, not resolved.** The parser accepts input a strict
//!   implementation would reject and reports every deviation as a
//!   [`parse::Quirk`]. Bare LF terminators and `Content-Length` beside
//!   `Transfer-Encoding` are not defects to paper over — they are the finding.
//! * **Limits are enforced while bytes arrive**, never afterwards. A hostile server
//!   is assumed, so a response that never ends must be refused before it exhausts
//!   memory rather than after.
//!
//! ## Status
//!
//! Implemented: HTTP/1.0 and HTTP/1.1 over plaintext TCP and TLS; request and
//! response head parsing; `Content-Length`, chunked and connection-close framing;
//! streaming bodies; gzip, deflate and brotli; per-phase timeouts and incrementally
//! enforced limits.
//!
//! The buffered [`transport::TcpTransport::send`] can also negotiate **HTTP/2** when it
//! is turned on with [`transport::TcpTransport::http2`] and the target offers `h2` at
//! ALPN (M5.1a). That path is *conforming* — it wraps the `h2` crate to reach modern
//! targets. HTTP/2 connections are pooled per host and multiplexed, so repeated and
//! concurrent requests to one target share one connection (M5.1b); a hostile peer is
//! bounded by the `h2` handshake's header-list cap, the analogue of the decompression-bomb
//! guard. The streaming path the proxy uses stays HTTP/1.x for now.
//!
//! For the requests a conforming library refuses — an uppercase header name, a duplicate
//! pseudo-header, a value carrying CR/LF — [`transport::TcpTransport::send_raw_h2`] drives a
//! hand-rolled frame-level client ([`h2raw`]) that encodes exactly what the tester wrote and
//! reports what the server did with it (M5.1e). It is the h2 analogue of raw mode.
//!
//! Not implemented, and failing loudly rather than guessing: connection reuse (M1.4)
//! and redirects (M1.6).

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod body;
pub mod chunked;
pub mod decode;
pub mod h2;
pub mod h2pool;
pub mod h2raw;
pub mod parse;
pub mod request;
pub mod tls;
pub mod transport;
pub mod write;

pub use body::{BodyStream, CollectedBody};
pub use parse::{find_head_end, BodyFraming, Quirk, ResponseHead};
pub use request::{parse_request_head, RequestHead, RequestTarget};
pub use tls::{ClientIdentity, TlsConfig};
pub use transport::{StreamingExchange, TcpTransport};
pub use write::serialize_request;

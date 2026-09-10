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
//! Not implemented, and failing loudly rather than guessing: connection reuse (M1.4)
//! and redirects (M1.6).

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod body;
pub mod chunked;
pub mod decode;
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

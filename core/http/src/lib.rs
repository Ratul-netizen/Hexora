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
//! ## Status (M1.1)
//!
//! Implemented: HTTP/1.0 and HTTP/1.1 over plaintext TCP, bodies delimited by
//! `Content-Length` or connection close, per-phase timeouts, incremental limits.
//!
//! Not implemented, and failing loudly rather than guessing: TLS (M1.2), streaming
//! bodies (M1.3), connection reuse (M1.4), chunked decoding and content decoding
//! (M1.5), redirects (M1.6).

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod parse;
pub mod transport;
pub mod write;

pub use parse::{BodyFraming, Quirk, ResponseHead};
pub use transport::TcpTransport;

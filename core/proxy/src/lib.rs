//! # hexora-proxy
//!
//! Hexora's intercepting proxy.
//!
//! ## Status (M2.2)
//!
//! Implemented: the interception certificate authority, and a plain-HTTP proxy that
//! forwards absolute-form requests, strips hop-by-hop headers and reports every
//! exchange to an observer.
//!
//! Not implemented yet: `CONNECT` tunnelling and TLS interception (M2.3),
//! interception hooks (M2.4) and trust installation (M2.5). A `CONNECT` is answered
//! with a clear 501 rather than left to hang.
//!
//! ## The CA is the security-critical part
//!
//! Everything else here is plumbing. The CA private key is the ability to impersonate
//! any site to the machine that trusts it, which makes it the most sensitive thing
//! Hexora will ever hold. See [`ca`] for the rules that follow from that.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod ca;
pub mod intercept;
pub mod server;

pub use ca::{CertificateAuthority, LeafCertificate};
pub use intercept::{InterceptionPolicy, TunnelOutcome};
pub use server::{ExchangeObserver, NoObserver, ProxyConfig, ProxyServer};

//! # hexora-proxy
//!
//! Hexora's intercepting proxy.
//!
//! ## Status (M3)
//!
//! Implemented: the interception certificate authority; a proxy that forwards
//! absolute-form requests and tunnels `CONNECT`, with selective TLS interception;
//! interception hooks that can rewrite, replace, drop or answer a message; and
//! [`ProjectCapture`], which persists every exchange into a project.
//!
//! [`trust`] installs and removes the CA from the platform trust store, and asks the
//! platform whether it is trusted rather than assuming.
//!
//! ## The CA is the security-critical part
//!
//! Everything else here is plumbing. The CA private key is the ability to impersonate
//! any site to the machine that trusts it, which makes it the most sensitive thing
//! Hexora will ever hold. See [`ca`] for the rules that follow from that.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod attach;
pub mod ca;
pub mod capture;
pub mod fanout;
pub mod hook;
pub mod intercept;
pub mod server;
pub mod trust;

pub use ca::{CertificateAuthority, LeafCertificate};
pub use capture::ProjectCapture;
pub use fanout::Fanout;
pub use hook::{
    InterceptDirections, InterceptHandle, Interceptor, ManualInterceptor, PassThrough,
    RequestVerdict, ResponseVerdict,
};
pub use intercept::{InterceptionPolicy, TunnelOutcome};
pub use server::{ExchangeObserver, NoObserver, ProxyConfig, ProxyServer};
pub use trust::{Fingerprints, Installed, ManualStep, Store, TrustState};

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
//! An intercepted tunnel negotiates **HTTP/2** with the browser (M5.1c): when the client
//! selects `h2` at ALPN the proxy is an h2 server, demultiplexing each of the browser's
//! concurrent streams into its own exchange, processed exactly as an HTTP/1.x request is.
//! Upstream, the request is forwarded over the origin's **negotiated** protocol — h2 when
//! offered, HTTP/1.1 otherwise (M5.1d). A browser's h2 request reaching an h1 origin is a
//! **downgrade**, which the proxy records as an explicit event and, because h2→h1 is a
//! request-smuggling class, names the primitives such a downgrade would carry.
//!
//! A `101 Switching Protocols` turns the tunnel into a **WebSocket** relay (WS.a): the
//! upgrade is carried through with `permessage-deflate` stripped so the session stays
//! legible, and from then on the connection is relayed both ways verbatim while every frame
//! is parsed and recorded into `websocket_messages` — masking kept as observed, since a
//! client that does not mask or a server that does is a finding. An interceptor that opts in
//! can forward, replace or drop each message in either direction (WS.c), on the same seam as
//! the HTTP request and response hooks; when none does, the relay stays byte-for-byte.
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
    RequestVerdict, ResponseVerdict, WsVerdict,
};
pub use intercept::{InterceptionPolicy, TunnelOutcome};
pub use server::{ExchangeObserver, NoObserver, ProxyConfig, ProxyServer};
pub use trust::{Fingerprints, Installed, ManualStep, Store, TrustState};

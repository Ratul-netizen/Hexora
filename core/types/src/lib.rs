//! # hexora-types
//!
//! The shared domain model for the Hexora offensive-security platform.
//!
//! Every other crate in the workspace depends on this one and nothing else depends on
//! them, which keeps the dependency graph acyclic and lets the UI, CLI and engine
//! agree on a single vocabulary.
//!
//! ## What lives here
//!
//! | Module | Contents |
//! | ------ | -------- |
//! | [`error`]    | Structured errors and the crate-wide `Result` |
//! | [`ids`]      | Time-ordered, type-distinct entity identifiers |
//! | [`http`]     | The raw-preserving HTTP message model |
//! | [`scope`]    | Authorization boundary for automated traffic |
//! | [`identity`] | Testing principals for authorization work |
//! | [`object`]   | Declared object identifiers, and where they sit in a request |
//! | [`candidate`]| Values that *might* be identifiers, suggested and never assumed |
//! | [`raw`]      | Requests sent as bytes rather than as a model |
//! | [`finding`]  | The evidence-driven vulnerability model |
//! | [`limits`]   | Resource bounds against hostile targets |
//! | [`redact`]   | Secret wrapping and redaction policy |
//! | [`tls`]      | What a TLS handshake produced, as observations |
//!
//! ## Design rules
//!
//! * **Preserve the wire.** Nothing here normalizes away detail that a security
//!   tester might need: duplicate headers, odd casing and non-UTF-8 bytes all
//!   survive a round trip.
//! * **Secrets are typed.** Credentials use [`redact::Secret`], so leaking one into a
//!   log requires an explicit, greppable `.expose()` call.
//! * **Evidence over assertion.** A [`finding::Finding`] cannot claim confidence it
//!   has not earned; see [`finding::Finding::validate`].

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod candidate;
pub mod error;
pub mod finding;
pub mod http;
pub mod identity;
pub mod ids;
pub mod limits;
pub mod object;
pub mod raw;
pub mod redact;
pub mod scope;
pub mod tls;

pub use candidate::{CandidateStatus, IdentifierCandidate, Signal, SignalKind, Strength};
pub use error::{HexoraError, Result};
pub use finding::{Confidence, Evidence, Finding, Hypothesis, Severity};
pub use http::{Header, Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};
pub use identity::{Credential, Identity, PrivilegeLevel};
pub use limits::Limits;
pub use object::{ObjectDeclaration, ObjectLocation};
pub use raw::{RawRequest, RequestMode, RequestSource};
pub use redact::{RedactionPolicy, Secret};
pub use scope::{Scope, ScopeRule};
pub use tls::{CertificateSummary, TlsInfo, Verification};

/// The version of this crate, exposed for the RPC handshake between UI and engine.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The engine RPC contract version.
///
/// Bumped whenever the UI/engine boundary changes shape. The desktop client refuses
/// to talk to an engine reporting a different major value rather than misinterpreting
/// messages.
pub const RPC_CONTRACT_VERSION: u32 = 5;

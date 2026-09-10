//! # hexora-engine
//!
//! The architectural boundaries of the Hexora core, and the places where the security
//! invariants are actually enforced.
//!
//! There is deliberately no interface here for every future subsystem. A trait earns
//! its place when at least two components must agree on it, or when it is the seam an
//! invariant is enforced at. Everything else waits until the milestone that needs it,
//! and gets split into its own crate then; see `docs/architecture.md`.
//!
//! ## What this crate contains
//!
//! | Module | Role | Status |
//! | ------ | ---- | ------ |
//! | [`transport`]  | The single path by which any request reaches the network | Interface + test double |
//! | [`guard`]      | Scope enforcement, wrapping any transport | **Implemented** |
//! | [`permission`] | Extension capabilities and grants | **Implemented** |
//! | [`ai`]         | Tool-call classification for the AI layer | **Implemented** |
//!
//! The real network implementation of [`transport::HttpTransport`] arrives with M1.
//! Until then [`transport::RecordingTransport`] lets the layers above it be tested,
//! and no production path pretends to send traffic.
//!
//! ## Why enforcement lives here and not in each subsystem
//!
//! Scanner, fuzzer, workflows, extensions and the AI layer all need to send requests.
//! If each enforced scope itself, the invariant would hold until the day someone
//! added a sixth subsystem. Instead every one of them is handed a
//! [`guard::ScopeGuard`], and the check happens once, below all of them.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod ai;
pub mod guard;
pub mod permission;
pub mod transport;

pub use ai::{Approval, ToolCall, ToolGate};
pub use guard::{ScopeDecision, ScopeGuard};
pub use permission::{Capability, GrantSet, PermissionRequest};
pub use transport::{Exchange, HttpTransport, Origin, SendOptions};

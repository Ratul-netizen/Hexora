//! The active checks.
//!
//! One, so far, and it was chosen because it is the hypothesis
//! [`nullhawk_scan`](nullhawk_scan) already raises and structurally cannot settle. A
//! scheduler with nothing to schedule proves nothing; this one closes a loop that was
//! left open on purpose in M13.2.

pub mod auth;
pub mod cache;
pub mod crossid;
pub mod echo;
pub mod redirect;
pub mod reflection;
pub mod sqli;
pub mod ssrf;
pub mod ssti;
pub mod traversal;

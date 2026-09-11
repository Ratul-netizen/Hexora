//! The active checks.
//!
//! One, so far, and it was chosen because it is the hypothesis
//! [`hexora_scan`](hexora_scan) already raises and structurally cannot settle. A
//! scheduler with nothing to schedule proves nothing; this one closes a loop that was
//! left open on purpose in M13.2.

pub mod reflection;

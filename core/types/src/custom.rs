//! User-defined scan checks (M15.5) — Hexora's answer to Burp's BChecks.
//!
//! A custom check is a saved query plus a finding template: when the query matches a captured
//! exchange, the passive scanner records an observation with the check's name, severity and
//! message. It is only data here; compiling the query and running it lives in the scanner.
//!
//! # Why it can only ever be a lead
//!
//! A custom check emits an **observation**, which the passive scanner concludes as a lead
//! capped at `Confidence::Reported` — never an actionable, verified finding, and never a
//! hypothesis the active scheduler would try to settle. A user cannot write a check that
//! overclaims, because the evidence model does not let a passive observation say more than
//! "this matched, here is the exchange". That is the same rule the built-in passive checks
//! live under.
//!
//! # What a query may address
//!
//! The passive scanner sees each exchange's metadata and headers, not its bodies, so a custom
//! check's query is restricted to metadata and header fields. A query that reaches for a body
//! is refused when the check is added, rather than silently never matching.

use serde::{Deserialize, Serialize};

use crate::finding::Severity;

/// One user-defined passive check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomCheck {
    /// The detector id, e.g. `custom.exposed-actuator`. Unique within a project.
    pub id: String,
    /// A human name for the finding it raises.
    pub name: String,
    /// The severity the lead is filed at.
    pub severity: Severity,
    /// The query that decides whether an exchange matches (see `hexora-query`).
    pub query: String,
    /// What a match means, shown as the observation's finding text.
    pub message: String,
    /// Whether the check runs. A disabled check is kept but skipped.
    pub enabled: bool,
}

impl CustomCheck {
    /// A check with the given parts, enabled.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        severity: Severity,
        query: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            severity,
            query: query.into(),
            message: message.into(),
            enabled: true,
        }
    }

    /// A one-line description for the CLI and reports.
    pub fn summary(&self) -> String {
        let state = if self.enabled { "" } else { " (disabled)" };
        format!(
            "{}{} [{}]: {} — when `{}`",
            self.id,
            state,
            self.severity.as_str(),
            self.name,
            self.query
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_round_trips_through_json() {
        let check = CustomCheck::new(
            "custom.debug-header",
            "Debug header exposed",
            Severity::Medium,
            "resp.header:x-debug",
            "The application returned an X-Debug header",
        );
        let json = serde_json::to_string(&check).unwrap();
        let back: CustomCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, back);
    }

    #[test]
    fn summary_names_the_id_severity_and_query() {
        let check = CustomCheck::new("custom.x", "X", Severity::High, "status=500", "m");
        let s = check.summary();
        assert!(
            s.contains("custom.x") && s.contains("high") && s.contains("status=500"),
            "{s}"
        );
    }
}

//! The evidence-driven finding model.
//!
//! Hexora's central rule: **a heuristic match is not a finding.** A detector produces
//! a [`Hypothesis`]; the verification engine turns it into a [`Finding`] only after
//! attaching [`Evidence`] that a human — or a reviewer reading the report six months
//! later — can independently re-run.
//!
//! ```text
//! Hypothesis → Test → Evidence → Verification → Finding
//! ```
//!
//! [`Confidence`] is therefore not a model score. It records *how* the claim was
//! established, which is why [`Confidence::Reported`] is the only level an AI or a
//! passive heuristic can produce on its own.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{FindingId, RequestId, ResponseId, TargetId};

/// Impact severity, aligned with common reporting scales.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// A stable sort key, highest severity first.
    pub fn rank(&self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
            Self::Info => 4,
        }
    }
}

/// How firmly a finding is established.
///
/// This ladder is deliberately about *provenance*, not probability. Nothing may be
/// promoted above [`Confidence::Reported`] without evidence attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// A heuristic, a passive check or the AI layer suggested this. Not verified.
    /// Findings at this level must be labelled as unconfirmed in every report.
    Reported,
    /// An active test produced a result consistent with the hypothesis, but the
    /// result could have another cause.
    Tentative,
    /// An active test produced a result that is hard to explain any other way.
    Firm,
    /// The test was replayed and reproduced the same observable effect.
    Confirmed,
}

impl Confidence {
    /// Whether a finding at this level may be presented as a real vulnerability
    /// rather than a lead to investigate.
    pub fn is_actionable(&self) -> bool {
        matches!(self, Self::Firm | Self::Confirmed)
    }
}

/// A single piece of supporting evidence.
///
/// Every variant points at durable project data — request and response IDs, not
/// prose — so the UI can open the exact traffic behind a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// A request/response pair that demonstrates the issue.
    Exchange {
        request: RequestId,
        response: Option<ResponseId>,
        /// What the reader should notice about this exchange.
        note: String,
    },
    /// Two exchanges whose difference is the point, e.g. authorization testing.
    Comparison {
        baseline: RequestId,
        variant: RequestId,
        /// The observable difference, e.g. "identity B received user A's email".
        difference: String,
    },
    /// A byte range within a response body that carries the proof.
    ResponseExcerpt {
        response: ResponseId,
        /// Byte offset into the recorded body.
        offset: usize,
        /// The excerpt itself, redaction already applied.
        excerpt: String,
    },
    /// An out-of-band interaction attributable to a specific request.
    OutOfBand {
        request: RequestId,
        interaction: crate::ids::InteractionId,
        protocol: String,
    },
    /// A measured timing difference, with the samples that produced it.
    Timing {
        request: RequestId,
        baseline_ms: Vec<u64>,
        variant_ms: Vec<u64>,
    },
}

/// A candidate issue, before verification.
///
/// Detectors emit these. They are cheap, may be wrong, and never reach a report
/// directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    /// The detector that raised it, e.g. `passive.missing_hsts`.
    pub detector: String,
    /// Human-readable claim under test.
    pub claim: String,
    /// The request that triggered the hypothesis.
    pub source_request: RequestId,
    /// The parameter or header implicated, if any.
    pub location: Option<Location>,
    /// The severity this would carry if verified.
    pub provisional_severity: Severity,
}

/// Where in a message an issue lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// Which part of the message.
    pub part: MessagePart,
    /// The parameter, header or JSON pointer name.
    pub name: String,
}

/// Which part of an HTTP message a [`Location`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessagePart {
    Path,
    Query,
    Header,
    Cookie,
    Body,
    JsonPointer,
    Multipart,
}

/// A verified issue, ready for the findings list and the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub target: TargetId,
    /// Short title, e.g. "IDOR in GET /api/accounts/{id}".
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Where the issue lives.
    pub location: Option<Location>,
    /// What the issue is.
    pub description: String,
    /// Why it matters for this application specifically.
    pub impact: String,
    /// How to fix it.
    pub remediation: String,
    /// Steps to reproduce, referencing the evidence below.
    pub reproduction: String,
    /// Supporting evidence. Must be non-empty above [`Confidence::Reported`];
    /// enforced by [`Finding::validate`].
    pub evidence: Vec<Evidence>,
    /// CWE identifier, e.g. `CWE-639`.
    pub cwe: Option<String>,
    /// OWASP category, e.g. `API1:2023 Broken Object Level Authorization`.
    pub owasp: Option<String>,
    /// CVSS v3.1 vector string, when one has been assigned.
    pub cvss: Option<String>,
    /// Which detector or human raised it.
    pub source: FindingSource,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Triage state.
    pub status: FindingStatus,
}

/// Who or what produced a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FindingSource {
    /// A passive check over observed traffic.
    PassiveScan { detector: String },
    /// An active check that sent its own traffic.
    ActiveScan { detector: String },
    /// The authorization-testing subsystem.
    AuthorizationTest,
    /// An extension.
    Extension { extension: String },
    /// The AI layer. Always starts at [`Confidence::Reported`].
    Ai { model: String },
    /// A human tester.
    Manual,
}

impl FindingSource {
    /// The highest confidence this source may assert on its own, before the
    /// verification engine has run.
    ///
    /// The AI layer and passive checks can never self-certify a finding: that is the
    /// structural guard against hallucinated vulnerabilities.
    pub fn max_unverified_confidence(&self) -> Confidence {
        match self {
            Self::Ai { .. } | Self::PassiveScan { .. } => Confidence::Reported,
            Self::ActiveScan { .. } | Self::AuthorizationTest | Self::Extension { .. } => {
                Confidence::Tentative
            }
            // A human tester who says they reproduced it is taken at their word.
            Self::Manual => Confidence::Confirmed,
        }
    }
}

/// Triage state of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    #[default]
    New,
    Triaged,
    Confirmed,
    FalsePositive,
    Duplicate,
    Reported,
    Fixed,
    Accepted,
}

impl Finding {
    /// Checks the invariants that keep findings trustworthy.
    ///
    /// Called before a finding is persisted or exported. Violations are programming
    /// errors in a detector, so they are returned as a list rather than logged.
    pub fn validate(&self) -> std::result::Result<(), Vec<&'static str>> {
        let mut problems = Vec::new();
        if self.title.trim().is_empty() {
            problems.push("finding has an empty title");
        }
        if self.confidence > Confidence::Reported && self.evidence.is_empty() {
            problems.push("finding above Reported confidence has no evidence attached");
        }
        if self.confidence > self.source.max_unverified_confidence() && self.evidence.is_empty() {
            problems.push("finding exceeds what its source may assert without verification");
        }
        if self.confidence.is_actionable() && self.reproduction.trim().is_empty() {
            problems.push("actionable finding has no reproduction steps");
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(confidence: Confidence, source: FindingSource, evidence: Vec<Evidence>) -> Finding {
        let now = Utc::now();
        Finding {
            id: FindingId::new(),
            target: TargetId::new(),
            title: "IDOR in GET /api/accounts/{id}".into(),
            severity: Severity::High,
            confidence,
            location: None,
            description: "Object identifiers are not authorized per user.".into(),
            impact: "Any authenticated user can read any account.".into(),
            remediation: "Enforce an ownership check server-side.".into(),
            reproduction: "Send request A as identity B.".into(),
            evidence,
            cwe: Some("CWE-639".into()),
            owasp: Some("API1:2023".into()),
            cvss: None,
            source,
            created_at: now,
            updated_at: now,
            status: FindingStatus::New,
        }
    }

    fn some_evidence() -> Vec<Evidence> {
        vec![Evidence::Comparison {
            baseline: RequestId::new(),
            variant: RequestId::new(),
            difference: "identity B received identity A's email address".into(),
        }]
    }

    #[test]
    fn ai_cannot_self_certify_above_reported() {
        let source = FindingSource::Ai { model: "some-model".into() };
        assert_eq!(source.max_unverified_confidence(), Confidence::Reported);
    }

    #[test]
    fn passive_checks_cannot_self_certify_above_reported() {
        let source = FindingSource::PassiveScan { detector: "missing_hsts".into() };
        assert_eq!(source.max_unverified_confidence(), Confidence::Reported);
    }

    #[test]
    fn a_confident_finding_without_evidence_is_rejected() {
        let f = finding(Confidence::Confirmed, FindingSource::AuthorizationTest, vec![]);
        let problems = f.validate().unwrap_err();
        assert!(problems.iter().any(|p| p.contains("no evidence")), "{problems:?}");
    }

    #[test]
    fn a_confident_finding_with_evidence_is_accepted() {
        let f = finding(Confidence::Confirmed, FindingSource::AuthorizationTest, some_evidence());
        assert!(f.validate().is_ok());
    }

    #[test]
    fn a_reported_finding_may_have_no_evidence() {
        let f = finding(
            Confidence::Reported,
            FindingSource::Ai { model: "some-model".into() },
            vec![],
        );
        assert!(f.validate().is_ok(), "unverified leads are allowed, they are just labelled");
    }

    #[test]
    fn actionable_findings_require_reproduction_steps() {
        let mut f = finding(Confidence::Firm, FindingSource::ActiveScan {
            detector: "sqli.error_based".into(),
        }, some_evidence());
        f.reproduction = "   ".into();
        let problems = f.validate().unwrap_err();
        assert!(problems.iter().any(|p| p.contains("reproduction")), "{problems:?}");
    }

    #[test]
    fn only_firm_and_confirmed_are_actionable() {
        assert!(!Confidence::Reported.is_actionable());
        assert!(!Confidence::Tentative.is_actionable());
        assert!(Confidence::Firm.is_actionable());
        assert!(Confidence::Confirmed.is_actionable());
    }

    #[test]
    fn confidence_and_severity_order_as_expected() {
        assert!(Confidence::Confirmed > Confidence::Reported);
        assert!(Severity::Critical > Severity::Info);
        assert_eq!(Severity::Critical.rank(), 0);
    }
}

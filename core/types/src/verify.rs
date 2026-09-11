//! The gap between "this looks suspicious" and "this is true", made structural.
//!
//! Every scanner Hexora will ever have produces two different things, and the whole
//! question of whether the tool can be trusted is whether they stay different:
//!
//! ```text
//! Detector  →  Hypothesis   "this looks suspicious"      cheap, often wrong
//!                  │
//!              Verifier     a controlled experiment
//!                  ▼
//!             Verification  "it reproduced" / "it did not" / "cannot tell"
//!                  │
//!                  ▼
//!              Verified     the only thing the findings store accepts
//! ```
//!
//! # The rule
//!
//! [`Hypothesis`](crate::finding::Hypothesis) has no path to
//! [`Finding`](crate::finding::Finding). There is no `From`, no `into_finding`, no
//! constructor that takes one. The only way to obtain a [`Verified`] — and
//! `FindingStore` accepts nothing else — is [`Verified::conclude`], which requires a
//! [`Verification`] and refuses one that did not support the hypothesis.
//!
//! This is security invariant 6 moved from a runtime check into the type system. A
//! detector with a bug used to get an error from `Finding::validate`; now it gets a
//! compile error, because the type it produces is not the type that can be stored.
//!
//! # Confidence is derived, never chosen
//!
//! A detector does not get to say how sure it is. [`Verification::confidence`] is a
//! total function from what the experiment showed to what may be claimed:
//!
//! | Verification | Confidence |
//! | ------------ | ---------- |
//! | [`Reproduced`](Verification::Reproduced) — the effect happened again | `Confirmed` |
//! | [`Supported`](Verification::Supported) with [`Support::Distinctive`] | `Firm` |
//! | [`Supported`](Verification::Supported) with [`Support::Consistent`] | `Tentative` |
//! | [`Observed`](Verification::Observed) — nothing to experiment on | `Reported` |
//! | [`Refuted`](Verification::Refuted) | no finding at all |
//! | [`Inconclusive`](Verification::Inconclusive) | no finding at all |
//!
//! `Reported` is the ceiling for anything an experiment did not establish, and
//! [`Confidence::is_actionable`] is false there — so an observation reaches a report
//! as a lead, in the leads section, never as a claimed vulnerability.
//!
//! The ladder used to live as prose in `core/authz/src/analysis.rs`, applied by hand
//! by the one subsystem that produced findings. Written once here, it is the ladder
//! every future check climbs.

use serde::{Deserialize, Serialize};

use crate::finding::{
    Confidence, Evidence, Finding, FindingSource, FindingStatus, Hypothesis, Location, Severity,
};
use crate::ids::{FindingId, RequestId, TargetId};

/// What a check is called, e.g. `authz.bola`.
///
/// Dotted and stable: it goes into a hypothesis, and a retest comparing two
/// engagements needs to recognise the same check across builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DetectorId(pub &'static str);

impl std::fmt::Display for DetectorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Whether running a check puts traffic on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorMode {
    /// Reads traffic that has already been captured. Sends nothing, ever.
    ///
    /// The difference between a check that is safe to run on a production system
    /// during business hours and one that is not, so it is a field rather than
    /// folklore — and, for passive checks, an invariant with a test that fails if a
    /// transport is so much as touched.
    Passive,
    /// Performs its own experiments.
    Active,
}

impl DetectorMode {
    /// The word shown in the registry.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Active => "active",
        }
    }

    /// Whether running this check sends anything.
    pub fn sends(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// What a check is, for a human and for a comparison between two engagements.
///
/// Serialize only: this is a static description compiled into the binary, so it goes
/// out to a listing or an interface and never comes back in. What comes back in is an
/// [`Observation`], which carries the id and version as owned strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DetectorInfo {
    /// Stable identifier, e.g. `headers.security`.
    pub id: DetectorId,
    /// A human name, e.g. "Security header analysis".
    pub name: &'static str,
    /// Bumped whenever what the check looks for changes.
    ///
    /// A finding that stopped appearing because the application was fixed and one
    /// that stopped appearing because the check was changed are different events, and
    /// a retest that cannot tell them apart is worse than none — see invariant 11.
    /// Compared for equality, never ordered: "different" is the only question a
    /// comparison asks of it.
    pub version: &'static str,
    /// One line: what it looks for.
    pub about: &'static str,
    /// Whether it sends.
    pub mode: DetectorMode,
    /// Whether it can state facts about traffic that need no experiment.
    pub observes: bool,
    /// Whether it can raise suspicions that *do* need one.
    ///
    /// Recorded separately from [`Self::observes`] because the two are genuinely
    /// different products, and a check that only ever hypothesises produces no
    /// findings at all until something verifies it.
    pub hypothesizes: bool,
}

impl DetectorInfo {
    /// Whether running this check puts traffic on the wire.
    pub fn sends(&self) -> bool {
        self.mode.sends()
    }
}

/// Whether an observation is worth putting in front of somebody as a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Significance {
    /// True, and useful context, and not an issue.
    ///
    /// `Server: nginx/1.24.0` is a fact about the response; whether it matters
    /// depends on the engagement. It is listed, counted, and never filed as a
    /// finding, because a findings list that fills with facts is one people stop
    /// reading.
    Informational,
    /// True, and worth a tester's attention.
    ///
    /// Reaches a report as a **lead** — [`Verification::Observed`] caps it at
    /// [`Confidence::Reported`], which is not actionable. A passive check cannot
    /// produce anything stronger, by construction rather than by policy.
    Reportable,
}

/// A fact about one captured exchange.
///
/// The other thing a detector may produce, and the one that needs no experiment: a
/// response either carried a `Strict-Transport-Security` header or it did not. Kept
/// apart from [`Hypothesis`] because they have different futures — a hypothesis waits
/// for a verifier, an observation is already as established as it is going to get.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// The check that made it.
    ///
    /// Owned rather than a [`DetectorId`]: an observation is runtime data that gets
    /// written down and read back, and a static string cannot come out of a database.
    pub detector: String,
    /// That check's version at the time.
    pub version: String,
    /// What was seen, in one line.
    pub about: String,
    /// What was expected, and what was there instead.
    ///
    /// The pair rather than a verdict: a reader who disagrees with the expectation
    /// can see it and say so.
    pub expected: String,
    /// What the exchange actually showed.
    pub observed: String,
    /// Why it is worth saying at all.
    pub rationale: String,
    /// The exchange it came from. Never empty — an observation with no exchange is
    /// not evidence of anything.
    pub exchange: RequestId,
    /// Where in the message.
    pub location: Option<Location>,
    /// What it would be worth, if it is worth anything.
    pub severity: Severity,
    /// Whether it should reach a report.
    pub significance: Significance,
}

impl Observation {
    /// Whether this one becomes a finding.
    pub fn is_reportable(&self) -> bool {
        matches!(self.significance, Significance::Reportable)
    }

    /// What makes two observations the same observation.
    ///
    /// Deliberately *not* the URL: five hundred endpoints on one host missing the
    /// same header is one thing to fix, and five hundred findings is a list nobody
    /// reads. The exchange stays attached as evidence; only the grouping is coarse.
    ///
    /// Contains no credential material, because it is built from a detector id, a
    /// host, and the name of a condition — never from a value.
    pub fn fingerprint(&self, host: &str) -> String {
        let place = self
            .location
            .as_ref()
            .map(|location| format!("{:?}:{}", location.part, location.name))
            .unwrap_or_default();
        format!("{}|{}|{}|{}", self.detector, host, self.about, place)
    }
}

/// How strongly an observation points at the hypothesis.
///
/// The distinction that separates `Firm` from `Tentative`, named rather than implied:
/// "a response of the same shape came back" and "the response contained the other
/// person's account number" are not the same kind of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// Consistent with the hypothesis, and with other explanations too.
    Consistent,
    /// Hard to explain any other way.
    Distinctive,
}

/// What an experiment established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verification {
    /// The experiment was performed again and the same observable effect happened.
    ///
    /// The only route to [`Confidence::Confirmed`], and the reason `--verify` exists:
    /// a result that happens once may be a cache, a race or a coincidence.
    Reproduced {
        /// What the reader should notice.
        note: String,
        /// The traffic behind it.
        evidence: Vec<Evidence>,
    },
    /// The experiment supported the hypothesis but was not repeated.
    Supported {
        /// How strongly.
        support: Support,
        /// What the reader should notice.
        note: String,
        /// The traffic behind it.
        evidence: Vec<Evidence>,
    },
    /// No experiment was performed, because there is nothing to experiment on.
    ///
    /// A response either carries a `Strict-Transport-Security` header or it does not;
    /// there is no second send that would establish it more firmly. The honest ceiling
    /// for this is [`Confidence::Reported`], which is not actionable — it reaches a
    /// report as a lead, never as a claimed vulnerability.
    ///
    /// This is the rung a passive check climbs, and deliberately the lowest one that
    /// produces anything at all: a detector that wants more has to run an experiment.
    Observed {
        /// What was seen.
        note: String,
        /// The traffic behind it.
        evidence: Vec<Evidence>,
    },
    /// The experiment ran and did not support the hypothesis.
    ///
    /// Not a finding, and not silence either: a detector whose hypotheses are
    /// routinely refuted is a detector somebody should look at.
    Refuted {
        /// What happened instead.
        note: String,
    },
    /// The experiment could not be performed, or its result cannot be read.
    ///
    /// Out of scope, a transport error, a response that never arrived. Reported as
    /// what it is rather than resolved in either direction.
    Inconclusive {
        /// Why nothing could be established.
        why: String,
    },
}

impl Verification {
    /// What may be claimed on the strength of this, if anything.
    ///
    /// Total, and the only place confidence is decided. `None` means no finding may
    /// be produced at all.
    pub fn confidence(&self) -> Option<Confidence> {
        match self {
            Self::Reproduced { .. } => Some(Confidence::Confirmed),
            Self::Supported {
                support: Support::Distinctive,
                ..
            } => Some(Confidence::Firm),
            Self::Supported {
                support: Support::Consistent,
                ..
            } => Some(Confidence::Tentative),
            Self::Observed { .. } => Some(Confidence::Reported),
            Self::Refuted { .. } | Self::Inconclusive { .. } => None,
        }
    }

    /// The traffic behind it. Empty for the two outcomes that produce no finding.
    pub fn evidence(&self) -> &[Evidence] {
        match self {
            Self::Reproduced { evidence, .. }
            | Self::Supported { evidence, .. }
            | Self::Observed { evidence, .. } => evidence,
            Self::Refuted { .. } | Self::Inconclusive { .. } => &[],
        }
    }

    /// A sentence for a log or a matrix cell.
    pub fn note(&self) -> &str {
        match self {
            Self::Reproduced { note, .. }
            | Self::Supported { note, .. }
            | Self::Observed { note, .. } => note,
            Self::Refuted { note } => note,
            Self::Inconclusive { why } => why,
        }
    }

    /// A one-word label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reproduced { .. } => "reproduced",
            Self::Supported { .. } => "supported",
            Self::Observed { .. } => "observed",
            Self::Refuted { .. } => "refuted",
            Self::Inconclusive { .. } => "inconclusive",
        }
    }
}

/// The prose a finding needs that a hypothesis does not carry.
///
/// A hypothesis is a note to the verifier — "this cell looks like BOLA". A finding is
/// a document a client reads. Splitting them keeps detectors from having to write a
/// report before they know whether they are right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writeup {
    /// The target the claim is about.
    pub target: TargetId,
    /// Short title.
    pub title: String,
    /// What the issue is.
    pub description: String,
    /// Why it matters for this application.
    pub impact: String,
    /// How to fix it.
    pub remediation: String,
    /// Steps to reproduce, referencing the evidence.
    pub reproduction: String,
    /// CWE identifier.
    pub cwe: Option<String>,
    /// OWASP category.
    pub owasp: Option<String>,
    /// What kind of thing raised it.
    pub source: FindingSource,
    /// The severity actually being claimed.
    ///
    /// Usually the hypothesis's provisional severity; a verifier that learned
    /// something may raise or lower it.
    pub severity: Severity,
    /// Where in the message, overriding the hypothesis's location when the experiment
    /// pinned it down more precisely.
    pub location: Option<Location>,
}

/// A finding that came from a verified hypothesis.
///
/// The only type `FindingStore` will write. The inner value is private and there is
/// no public constructor that takes a bare [`Finding`]: everything that reaches a
/// report has been through [`Verified::conclude`] or has a named human behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified(Finding);

impl Verified {
    /// Completes a hypothesis with what verification established.
    ///
    /// `None` when the verification does not support a claim — a refuted or
    /// inconclusive experiment produces no finding, rather than a quiet one. Also
    /// `None` when the assembled finding fails [`Finding::validate`], which is the
    /// backstop for a verifier that returned evidence-free support.
    pub fn conclude(
        hypothesis: &Hypothesis,
        verification: &Verification,
        writeup: Writeup,
    ) -> Option<Self> {
        let confidence = verification.confidence()?;
        let now = chrono::Utc::now();

        let finding = Finding {
            id: FindingId::new(),
            target: writeup.target,
            title: writeup.title,
            severity: writeup.severity,
            confidence,
            location: writeup.location.or_else(|| hypothesis.location.clone()),
            description: writeup.description,
            impact: writeup.impact,
            remediation: writeup.remediation,
            reproduction: writeup.reproduction,
            evidence: verification.evidence().to_vec(),
            cwe: writeup.cwe,
            owasp: writeup.owasp,
            // Left unset. A CVSS vector implies somebody weighed scope, blast radius
            // and the data involved; inventing one would put a number in a report
            // nobody had thought about.
            cvss: None,
            source: writeup.source,
            created_at: now,
            updated_at: now,
            status: FindingStatus::New,
        };

        finding.validate().ok()?;
        Some(Self(finding))
    }

    /// A finding a person is asserting on their own authority.
    ///
    /// The escape hatch, named so it cannot be taken by accident. A human who says
    /// they reproduced something *is* the verifier, which is why
    /// [`FindingSource::Manual`] may already claim `Confirmed`. `Finding::validate`
    /// still applies, so a human cannot record an evidence-free `Confirmed` either.
    pub fn asserted_by_a_human(finding: Finding) -> Result<Self, Vec<&'static str>> {
        if finding.source != FindingSource::Manual {
            return Err(vec![
                "only a Manual finding may be asserted without a verification",
            ]);
        }
        finding.validate()?;
        Ok(Self(finding))
    }

    /// Wraps a finding without a verification. **Tests only.**
    ///
    /// Behind the `test-support` feature, which no production build enables, because
    /// this is precisely the door the rest of this module exists to keep shut. A test
    /// that needs a finding with a particular severity and confidence should not have
    /// to stage an experiment to get one; a detector should not be able to reach this
    /// at all, and cannot — the feature is off in every binary Hexora ships.
    #[cfg(feature = "test-support")]
    pub fn from_trusted_finding(finding: Finding) -> Self {
        Self(finding)
    }

    /// The finding, for reading.
    pub fn finding(&self) -> &Finding {
        &self.0
    }

    /// The finding, for storing.
    pub fn into_finding(self) -> Finding {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::finding::MessagePart;
    use crate::ids::RequestId;

    use super::*;

    fn hypothesis() -> Hypothesis {
        Hypothesis {
            detector: "authz.bola".into(),
            claim: "User B reached User A's object".into(),
            source_request: RequestId::new(),
            location: Some(Location {
                part: MessagePart::Path,
                name: "/accounts/acct-1000".into(),
            }),
            provisional_severity: Severity::High,
        }
    }

    fn writeup() -> Writeup {
        Writeup {
            target: TargetId::new(),
            title: "Broken object-level authorization".into(),
            description: "User B received User A's account.".into(),
            impact: "One user can read another's records.".into(),
            remediation: "Scope the lookup to the session.".into(),
            reproduction: "Send as A, send as B, compare.".into(),
            cwe: Some("CWE-639".into()),
            owasp: None,
            source: FindingSource::AuthorizationTest,
            severity: Severity::High,
            location: None,
        }
    }

    fn evidence() -> Vec<Evidence> {
        vec![Evidence::Comparison {
            baseline: RequestId::new(),
            variant: RequestId::new(),
            difference: "User B received acct-1000".into(),
        }]
    }

    #[test]
    fn the_confidence_ladder_is_a_function_of_the_experiment() {
        let reproduced = Verification::Reproduced {
            note: "happened again".into(),
            evidence: evidence(),
        };
        let distinctive = Verification::Supported {
            support: Support::Distinctive,
            note: "the other identity's account number came back".into(),
            evidence: evidence(),
        };
        let consistent = Verification::Supported {
            support: Support::Consistent,
            note: "a response of the same shape came back".into(),
            evidence: evidence(),
        };

        assert_eq!(reproduced.confidence(), Some(Confidence::Confirmed));
        assert_eq!(distinctive.confidence(), Some(Confidence::Firm));
        assert_eq!(consistent.confidence(), Some(Confidence::Tentative));
    }

    #[test]
    fn an_observation_with_nothing_to_experiment_on_is_a_lead_and_not_more() {
        // The rung a passive check climbs. A missing header is a fact, not a
        // hypothesis — and it is still only worth a lead, because "the header is
        // absent" and "this application has a vulnerability" are different claims.
        let observed = Verification::Observed {
            note: "no Strict-Transport-Security header".into(),
            evidence: evidence(),
        };
        assert_eq!(observed.confidence(), Some(Confidence::Reported));
        assert!(!Confidence::Reported.is_actionable());

        let verified = Verified::conclude(&hypothesis(), &observed, writeup()).unwrap();
        assert_eq!(verified.finding().confidence, Confidence::Reported);
    }

    #[test]
    fn an_experiment_that_did_not_support_the_hypothesis_produces_no_finding() {
        for verification in [
            Verification::Refuted {
                note: "denied on the second replay".into(),
            },
            Verification::Inconclusive {
                why: "the host is out of scope".into(),
            },
        ] {
            assert_eq!(verification.confidence(), None);
            assert!(
                Verified::conclude(&hypothesis(), &verification, writeup()).is_none(),
                "{verification:?} produced a finding"
            );
            assert!(verification.evidence().is_empty());
        }
    }

    #[test]
    fn a_verifier_that_supports_a_claim_with_no_evidence_still_gets_nothing() {
        // The backstop. Invariant 6 says a claim above Reported needs evidence; a
        // verifier returning empty support would otherwise walk straight past it.
        let empty = Verification::Supported {
            support: Support::Distinctive,
            note: "trust me".into(),
            evidence: Vec::new(),
        };
        assert_eq!(empty.confidence(), Some(Confidence::Firm));
        assert!(Verified::conclude(&hypothesis(), &empty, writeup()).is_none());
    }

    #[test]
    fn a_verified_finding_carries_the_experiments_evidence_and_the_writeups_prose() {
        let verification = Verification::Reproduced {
            note: "happened again".into(),
            evidence: evidence(),
        };
        let verified = Verified::conclude(&hypothesis(), &verification, writeup()).unwrap();
        let finding = verified.finding();

        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.evidence.len(), 1);
        assert_eq!(finding.title, "Broken object-level authorization");
        assert_eq!(finding.status, FindingStatus::New);
        // The hypothesis named the place; the writeup did not override it.
        assert_eq!(
            finding.location.as_ref().unwrap().name,
            "/accounts/acct-1000"
        );
    }

    #[test]
    fn a_human_may_assert_a_finding_and_nothing_else_may() {
        let mut manual = Verified::conclude(
            &hypothesis(),
            &Verification::Reproduced {
                note: "n".into(),
                evidence: evidence(),
            },
            writeup(),
        )
        .unwrap()
        .into_finding();

        // A machine-sourced finding cannot take the human escape hatch.
        assert!(Verified::asserted_by_a_human(manual.clone()).is_err());

        manual.source = FindingSource::Manual;
        assert!(Verified::asserted_by_a_human(manual.clone()).is_ok());

        // And a human cannot assert a confident claim with nothing behind it either.
        manual.evidence.clear();
        assert!(Verified::asserted_by_a_human(manual).is_err());
    }

    #[test]
    fn a_detector_id_reads_as_itself() {
        let info = DetectorInfo {
            id: DetectorId("authz.bola"),
            name: "Cross-identity access",
            version: "1.0.0",
            about: "one identity reaching another identity's object",
            mode: DetectorMode::Active,
            observes: false,
            hypothesizes: true,
        };
        assert_eq!(info.id.to_string(), "authz.bola");
        assert!(info.sends(), "an active check sends, by definition");
        assert_eq!(info.mode.as_str(), "active");

        let passive = DetectorInfo {
            mode: DetectorMode::Passive,
            observes: true,
            ..info
        };
        assert!(!passive.sends(), "a passive check never sends");
    }
}

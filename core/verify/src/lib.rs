//! # hexora-verify
//!
//! The shape every check in Hexora has, defined before there are many checks.
//!
//! ```text
//! Detector  →  Hypothesis   "this looks suspicious"        cheap, often wrong
//!                  │
//!              Verifier     a controlled experiment, via a Lab
//!                  ▼
//!             Verification  reproduced / supported / observed / refuted / cannot tell
//!                  │
//!                  ▼
//!              Verified     the only thing the findings store accepts
//! ```
//!
//! The data types live in [`hexora_types::verify`], because `core/storage` has to see
//! [`Verified`](hexora_types::verify::Verified) to refuse everything else. What lives
//! here is the behaviour: the two traits, the one way to perform an experiment, and
//! the registry of what this build can check.
//!
//! ## Why a detector cannot send
//!
//! [`Detector::examine`] is synchronous and takes no [`Lab`]. That is not an
//! oversight: a detector reads evidence that has already been gathered, and a check
//! that wants to put traffic on the wire has to be a [`Verifier`], where the
//! experiment is visible in the signature. It keeps the passive/active distinction
//! from being a comment.
//!
//! ## Why a verifier cannot reach the network except through a Lab
//!
//! [`Verifier::verify`] receives `&dyn Lab` and nothing else that can send. A `Lab` is
//! backed by [`Repeater`](hexora_repeater::Repeater), so every request a verifier
//! makes goes through the same `ScopeGuard`, is attributed to the right origin, and is
//! stored as evidence — which is security invariant 1, kept by construction rather
//! than by each check remembering to.
//!
//! ## What this milestone deliberately does not do
//!
//! There is no scheduler and no `dyn Detector` registry. [`Detector`] and [`Verifier`]
//! carry associated types, so a check is statically paired with what it reads and what
//! it needs to re-run — which is honest about today and costs nothing, because nothing
//! yet dispatches over a heterogeneous set. The queue, the concurrency limits and the
//! object-safe wrapper belong to the active scheduler, where the requirements are
//! real; inventing them here would be inventing them blind.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

use async_trait::async_trait;
use hexora_repeater::{Draft, Repeater, SendAs, Sent};
use hexora_types::finding::Hypothesis;
use hexora_types::identity::Identity;
use hexora_types::verify::{DetectorInfo, Verification, Verified, Writeup};
use hexora_types::Result;

pub use hexora_types::verify::{DetectorId, Support};

/// Something that reads evidence already gathered and says what looks suspicious.
///
/// Cheap, allowed to be wrong, and unable to produce a finding: the only thing it
/// returns is a [`Hypothesis`], and nothing turns one of those into a claim.
pub trait Detector {
    /// What this detector reads — a captured exchange, a completed matrix, a body.
    type Subject;

    /// What it is, for the registry and for a retest comparing two engagements.
    fn about(&self) -> DetectorInfo;

    /// Everything suspicious in the subject.
    ///
    /// Synchronous and without a [`Lab`]: a detector examines, it does not test.
    fn examine(&self, subject: &Self::Subject) -> Vec<Hypothesis>;
}

/// Something that performs a controlled experiment and says whether it held up.
#[async_trait]
pub trait Verifier: Send + Sync {
    /// What this verifier needs in order to re-run the thing under test.
    ///
    /// A hypothesis says *what* is suspected; re-running it needs the request, the
    /// identity and the baseline, which are the subsystem's business and not part of
    /// the universal shape.
    type Case: Sync;

    /// What it is.
    fn about(&self) -> DetectorInfo;

    /// Runs the experiment.
    ///
    /// Returning [`Verification::Inconclusive`] is a legitimate answer and a better
    /// one than a guess: an out-of-scope target, a transport error or an unreadable
    /// response establishes nothing in either direction, and saying so is what keeps
    /// silence from being read as a clean result.
    async fn verify(
        &self,
        hypothesis: &Hypothesis,
        case: &Self::Case,
        lab: &dyn Lab,
    ) -> Result<Verification>;
}

/// The only way a verifier may put traffic on the wire.
///
/// One method, because a verifier needs exactly one capability: send this request as
/// this principal and tell me what came back. Everything that makes that safe —
/// scope, attribution, storage as evidence — is the `Lab`'s business, so a check
/// cannot forget any of it.
#[async_trait]
pub trait Lab: Send + Sync {
    /// Sends a request as a principal and records the exchange.
    ///
    /// Goes through the same `ScopeGuard` as every other automated send. A verifier
    /// has no way to opt out, because there is no other method.
    async fn experiment(&self, draft: &Draft, as_identity: Option<&Identity>) -> Result<Sent>;

    /// Whether sending this would leave the project's scope.
    ///
    /// Asked before a run rather than per request, so an out-of-scope target produces
    /// one sentence instead of one failure per experiment.
    fn would_leave_scope(&self, draft: &Draft, as_identity: Option<&Identity>) -> bool;
}

/// A [`Lab`] backed by the repeater.
///
/// The repeater is already the thing that loads a stored request, applies a
/// credential, sends it through the scope guard and stores the result. A second
/// implementation of any of that would be a second set of bugs.
pub struct RepeaterLab<'a, T: hexora_engine::transport::HttpTransport> {
    repeater: &'a Repeater<T>,
}

impl<'a, T: hexora_engine::transport::HttpTransport> RepeaterLab<'a, T> {
    /// Wraps a repeater as a lab.
    pub fn new(repeater: &'a Repeater<T>) -> Self {
        Self { repeater }
    }

    fn sender<'b>(identity: Option<&'b Identity>) -> SendAs<'b> {
        match identity {
            Some(identity) => SendAs::authz(identity),
            None => SendAs::repeater(),
        }
    }
}

#[async_trait]
impl<T: hexora_engine::transport::HttpTransport> Lab for RepeaterLab<'_, T> {
    async fn experiment(&self, draft: &Draft, as_identity: Option<&Identity>) -> Result<Sent> {
        self.repeater
            .send_as(draft, Self::sender(as_identity))
            .await
    }

    fn would_leave_scope(&self, draft: &Draft, as_identity: Option<&Identity>) -> bool {
        !self
            .repeater
            .decide_as(draft, Self::sender(as_identity))
            .permits_sending()
    }
}

/// Runs one verifier over the hypotheses a detector raised, keeping what survives.
///
/// The step that produces findings, and the only one: a hypothesis the verification
/// did not support yields nothing at all, rather than a quiet low-confidence row.
/// Callers get the verifications back too, because "the detector raised it and the
/// experiment refuted it" is worth showing a tester even though it is not a finding.
pub async fn verify_all<V: Verifier>(
    verifier: &V,
    work: &[(Hypothesis, V::Case)],
    lab: &dyn Lab,
    writeup: impl Fn(&Hypothesis, &Verification) -> Writeup,
) -> Result<Vec<Judged>> {
    let mut judged = Vec::with_capacity(work.len());
    for (hypothesis, case) in work {
        let verification = verifier.verify(hypothesis, case, lab).await?;
        let finding = Verified::conclude(
            hypothesis,
            &verification,
            writeup(hypothesis, &verification),
        );
        judged.push(Judged {
            hypothesis: hypothesis.clone(),
            verification,
            finding,
        });
    }
    Ok(judged)
}

/// What checks a build has.
///
/// Assembled by the application from the crates it links, rather than discovered:
/// there is no plugin mechanism here and pretending otherwise would hide the fact
/// that adding a check means adding a line. What it buys is a straight answer to two
/// questions a tester actually asks — *what does this build look for?* and *which of
/// it puts traffic on the wire?* — and a retest's ability to say that a claim stopped
/// appearing because the check that raised it is no longer here.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    checks: Vec<DetectorInfo>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds every check in a list, keeping the registry sorted by id.
    pub fn with(mut self, checks: impl IntoIterator<Item = DetectorInfo>) -> Self {
        self.checks.extend(checks);
        self.checks.sort_by(|a, b| a.id.0.cmp(b.id.0));
        self.checks.dedup_by(|a, b| a.id == b.id);
        self
    }

    /// Every check, by id.
    pub fn all(&self) -> &[DetectorInfo] {
        &self.checks
    }

    /// One check by id.
    pub fn find(&self, id: &str) -> Option<&DetectorInfo> {
        self.checks.iter().find(|check| check.id.0 == id)
    }

    /// The checks that put traffic on the wire.
    ///
    /// The list a tester wants before pointing this at a production system during
    /// business hours.
    pub fn sending(&self) -> impl Iterator<Item = &DetectorInfo> {
        self.checks.iter().filter(|check| check.sends())
    }
}

/// One hypothesis and what became of it.
#[derive(Debug, Clone)]
pub struct Judged {
    /// What the detector suspected.
    pub hypothesis: Hypothesis,
    /// What the experiment established.
    pub verification: Verification,
    /// The finding, when the verification supported one.
    ///
    /// `None` is the common and welcome case for a refuted hypothesis, and is not an
    /// error: a detector that raises more than it can support is doing its job, as
    /// long as the unsupported ones stop here.
    pub finding: Option<Verified>,
}

impl Judged {
    /// The findings out of a batch, dropping what verification did not support.
    pub fn findings(judged: Vec<Judged>) -> Vec<Verified> {
        judged.into_iter().filter_map(|j| j.finding).collect()
    }
}

#[cfg(test)]
mod tests {
    use hexora_types::finding::{Evidence, FindingSource, Severity};
    use hexora_types::ids::{RequestId, TargetId};
    use hexora_types::verify::{DetectorMode, Support};

    use super::*;

    /// A lab that cannot send anything, for checking that a verifier which does not
    /// need one is not secretly reaching for it.
    struct NoLab;

    #[async_trait]
    impl Lab for NoLab {
        async fn experiment(&self, _: &Draft, _: Option<&Identity>) -> Result<Sent> {
            panic!("this verifier must not send");
        }
        fn would_leave_scope(&self, _: &Draft, _: Option<&Identity>) -> bool {
            false
        }
    }

    struct Fake {
        answer: Verification,
    }

    #[async_trait]
    impl Verifier for Fake {
        type Case = ();

        fn about(&self) -> DetectorInfo {
            DetectorInfo {
                id: DetectorId("test.fake"),
                name: "Fake verifier",
                version: "1.0.0",
                about: "a verifier that answers whatever it was built with",
                mode: DetectorMode::Passive,
                observes: false,
                hypothesizes: true,
            }
        }

        async fn verify(&self, _: &Hypothesis, _: &(), _: &dyn Lab) -> Result<Verification> {
            Ok(self.answer.clone())
        }
    }

    fn hypothesis() -> Hypothesis {
        Hypothesis {
            detector: "test.fake".into(),
            claim: "something is wrong".into(),
            source_request: RequestId::new(),
            location: None,
            provisional_severity: Severity::High,
        }
    }

    fn writeup(_: &Hypothesis, _: &Verification) -> Writeup {
        Writeup {
            target: TargetId::new(),
            title: "A claim".into(),
            description: "Something happened.".into(),
            impact: "It matters.".into(),
            remediation: "Fix it.".into(),
            reproduction: "Send it twice.".into(),
            cwe: None,
            owasp: None,
            source: FindingSource::AuthorizationTest,
            severity: Severity::High,
            location: None,
        }
    }

    fn evidence() -> Vec<Evidence> {
        vec![Evidence::Exchange {
            request: RequestId::new(),
            response: None,
            note: "the response came back".into(),
        }]
    }

    #[tokio::test]
    async fn a_supported_hypothesis_becomes_a_finding() {
        let verifier = Fake {
            answer: Verification::Supported {
                support: Support::Distinctive,
                note: "the other identity's account number came back".into(),
                evidence: evidence(),
            },
        };
        let work = vec![(hypothesis(), ())];
        let judged = verify_all(&verifier, &work, &NoLab, writeup).await.unwrap();

        assert_eq!(judged.len(), 1);
        let finding = judged[0].finding.as_ref().unwrap().finding();
        assert_eq!(finding.confidence, hexora_types::Confidence::Firm);
    }

    #[tokio::test]
    async fn a_refuted_hypothesis_becomes_nothing_and_is_still_reported_back() {
        let verifier = Fake {
            answer: Verification::Refuted {
                note: "denied on the second replay".into(),
            },
        };
        let work = vec![(hypothesis(), ())];
        let judged = verify_all(&verifier, &work, &NoLab, writeup).await.unwrap();

        assert!(
            judged[0].finding.is_none(),
            "a refuted claim is not a finding"
        );
        // But the tester still gets to see that the detector raised it and the
        // experiment knocked it down. Silence here would hide a noisy detector.
        assert_eq!(judged[0].verification.as_str(), "refuted");
        assert!(Judged::findings(judged).is_empty());
    }

    #[tokio::test]
    async fn an_inconclusive_experiment_produces_nothing_in_either_direction() {
        let verifier = Fake {
            answer: Verification::Inconclusive {
                why: "the host is out of scope".into(),
            },
        };
        let work = vec![(hypothesis(), ())];
        let judged = verify_all(&verifier, &work, &NoLab, writeup).await.unwrap();

        assert!(judged[0].finding.is_none());
        assert_eq!(judged[0].verification.as_str(), "inconclusive");
    }

    #[test]
    fn a_registry_is_sorted_by_id_and_says_which_checks_send() {
        let quiet = DetectorInfo {
            id: DetectorId("headers.security"),
            name: "Security header analysis",
            version: "1.0.0",
            about: "a response with no HSTS header",
            mode: DetectorMode::Passive,
            observes: true,
            hypothesizes: false,
        };
        let loud = DetectorInfo {
            id: DetectorId("authz.cross_identity"),
            name: "Cross-identity access",
            version: "3.0.0",
            about: "one identity reaching another identity's object",
            mode: DetectorMode::Active,
            observes: false,
            hypothesizes: true,
        };

        let registry = Registry::new().with([quiet, loud]);
        assert_eq!(registry.all().len(), 2);
        assert_eq!(registry.all()[0].id.0, "authz.cross_identity");
        assert_eq!(registry.find("headers.security").unwrap().version, "1.0.0");
        assert!(registry.find("nothing.here").is_none());

        let sending: Vec<&str> = registry.sending().map(|check| check.id.0).collect();
        assert_eq!(sending, vec!["authz.cross_identity"]);
    }

    #[test]
    fn registering_the_same_check_twice_keeps_one_of_it() {
        let check = DetectorInfo {
            id: DetectorId("authz.cross_identity"),
            name: "Cross-identity access",
            version: "1.0.0",
            about: "x",
            mode: DetectorMode::Active,
            observes: false,
            hypothesizes: true,
        };
        let registry = Registry::new().with([check]).with([check]);
        assert_eq!(registry.all().len(), 1);
    }

    #[test]
    fn a_detector_reports_whether_it_sends() {
        let verifier = Fake {
            answer: Verification::Refuted {
                note: String::new(),
            },
        };
        // The field exists so "is this safe to run against production right now?" has
        // an answer in the registry rather than in somebody's memory.
        assert!(!verifier.about().sends());
    }
}

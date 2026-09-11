//! # hexora-active
//!
//! The part of Hexora that sends traffic a tester did not type by hand.
//!
//! [`hexora_scan`] reads captured traffic and, when one exchange cannot settle a
//! question, raises a [`Hypothesis`] and stops. This is what picks those up:
//!
//! ```text
//! passive pass ──▶ Hypothesis  "this host may reflect any Origin"
//!                      │        a suspicion, filed as nothing
//!                      ▼
//!                   Plan       what would be sent, to whom, how much   ← no traffic
//!                      │
//!                      ▼
//!                    run()     the experiment, paced and bounded
//!                      ▼
//!                 Verification reproduced / supported / refuted / cannot tell
//! ```
//!
//! # Nothing here runs on its own
//!
//! There is no watcher, no daemon and no "scan while you browse". A run happens
//! because somebody invoked one, which is security invariant 8 and the reason this
//! crate has no constructor that starts anything.
//!
//! # The plan is a separate step, and it cannot send
//!
//! ```ignore
//! pub fn Plan::prepare(project, lab, checks, hypotheses, budget) -> Result<Plan>   // reads
//! pub async fn run(plan, lab, checks, cancel) -> Result<Outcome>                   // sends
//! ```
//!
//! [`Plan::prepare`] is synchronous and answers "what would this do?" — which
//! hypotheses have a check that can settle them, which have lost the traffic behind
//! them, which point outside scope, and how many requests each host would receive. A
//! dry run is that function and no more, so `--dry-run` is not a flag the sending path
//! honours, it is the sending path not being called.
//!
//! # What a run promises the target
//!
//! One host is never sent two requests at once, there is a pause between requests to
//! one host, and the whole run has a hard ceiling. See [`Budget`]. A run that hit its
//! ceiling says so, because a truncated run that read as a completed one would turn
//! "unfinished" into "clean".
//!
//! # Stopping
//!
//! [`Cancel`] is checked before every send. Stopping therefore means *no further
//! request is sent* — it cannot mean "requests already on the wire are recalled",
//! because nothing can mean that. The outcome says which it was, so a half-finished
//! run is never mistaken for a quiet one.
//!
//! # Scope is checked twice
//!
//! Once in [`Plan::prepare`], so an out-of-scope target is one line in a dry run
//! instead of a failure per experiment — and again immediately before every send,
//! because scope can be narrowed while a queue is draining and a target authorized ten
//! minutes ago is not thereby authorized now.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use hexora_repeater::Draft;
use hexora_scan::Exchange;
use hexora_types::finding::Hypothesis;
use hexora_types::identity::Identity;
use hexora_types::ids::TargetId;
use hexora_types::verify::{DetectorInfo, Verification, Writeup};
use hexora_types::Result;
use hexora_verify::Lab;

pub mod budget;
pub mod checks;
pub mod schedule;
pub mod standing;

pub use budget::{Budget, MAX_HOSTS_AT_ONCE, MAX_REQUESTS};
pub use schedule::{
    is_state_changing, run, run_into, Outcome, Plan, Skipped, StoppedBecause, REPLAYABLE_METHODS,
};
pub use standing::{standing, Standing};

/// Something that settles a hypothesis by running an experiment.
///
/// Object-safe on purpose, and that is the whole difference from
/// [`Verifier`](hexora_verify::Verifier). A verifier is written by a subsystem that
/// knows its own case type — the authorization matrix re-runs a `CellCase` — and an
/// associated type expresses that exactly. A scheduler holds a `Vec` of checks it
/// knows nothing about, so its trait takes one concrete [`Subject`]: the hypothesis,
/// the exchange it came from, and a draft of the request that produced it.
///
/// The narrower shape is the cost of being schedulable, and it is the right cost: a
/// check that needs more than the traffic behind its own hypothesis is a check that
/// wants to be a subsystem.
#[async_trait]
pub trait ActiveCheck: Send + Sync {
    /// What it is, for the registry and for a retest comparing two engagements.
    fn about(&self) -> DetectorInfo;

    /// Whether this check can settle that hypothesis.
    ///
    /// Asked before anything is sent, so a hypothesis nothing can settle is reported
    /// as unhandled rather than silently dropped. A suspicion with no verifier is a
    /// gap in the tool, and a tester is entitled to see it.
    fn handles(&self, hypothesis: &Hypothesis) -> bool;

    /// Runs the experiment.
    ///
    /// [`Verification::Refuted`] is a first-class and valuable answer here: "the
    /// application does not reflect arbitrary origins" is the result that stops a
    /// passive suspicion from following a tester around for the rest of an engagement.
    ///
    /// [`Verification::Inconclusive`] is the answer whenever the experiment could not
    /// be performed *or interpreted* — a transport error, a target that left scope, or
    /// a captured session that has since expired, which would otherwise look exactly
    /// like a fixed application.
    async fn settle(
        &self,
        subject: &Subject,
        lab: &dyn Lab,
        budget: &Budget,
    ) -> Result<Verification>;

    /// The report entry, for a verification that supported one.
    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup;
}

/// Everything a check is given about one hypothesis.
///
/// Assembled by the scheduler, so a check never touches the project. The exchange
/// arrives through [`hexora_scan::passive::exchange_at`], which means its credential
/// headers are already redacted — an active check sees exactly what the passive check
/// that raised the hypothesis saw.
///
/// The [`Draft`], by contrast, carries the request as it was actually sent, credential
/// included, because re-sending it is the experiment. The two are deliberately
/// different: one is for reading and reporting, the other is for the wire.
#[derive(Debug, Clone)]
pub struct Subject {
    /// What the passive check suspected.
    pub hypothesis: Hypothesis,
    /// The exchange it was raised from, with credentials redacted.
    pub exchange: Exchange,
    /// The request, ready to be varied and re-sent.
    pub draft: Draft,
    /// The target the finding belongs to.
    pub target: TargetId,
    /// The identities the project holds, for a check that replays as somebody else.
    ///
    /// Shared rather than copied per subject: an engagement has a handful of these and
    /// a queue has hundreds of experiments. Most checks ignore it — it is here because
    /// the cross-identity check cannot be written without it and handing that one check
    /// a whole `Project` would give every check the run of the database.
    pub identities: Arc<Vec<Identity>>,
}

impl Subject {
    /// Which identity's credential the captured request actually carried.
    ///
    /// Matched by applying each declared credential to a copy of the request's own
    /// headers and comparing: an exact answer rather than a guess, and the only kind
    /// worth having, because everything a cross-identity test concludes rests on
    /// knowing whose session was captured. Proxy traffic carries no identity id — the
    /// browser did not announce one — so the credential itself is the evidence.
    ///
    /// `None` when nothing matches, which is the common case for an engagement whose
    /// identities were added after the traffic was captured.
    pub fn whose(&self) -> Option<&Identity> {
        let sent = &self.draft.request.headers;
        self.identities.iter().find(|identity| {
            let mut theirs = sent.clone();
            identity.credential.apply(&mut theirs);
            identity.credential.header_names().iter().all(|name| {
                match (sent.get(name), theirs.get(name)) {
                    (Some(a), Some(b)) => a.value == b.value,
                    _ => false,
                }
            })
        })
    }

    /// The host this experiment would be sent to.
    ///
    /// The queue key: everything with the same host shares one sequential queue.
    pub fn host(&self) -> &str {
        &self.exchange.host
    }
}

/// A stop signal a run checks before every send.
///
/// Cheap to clone and safe to share. What it can promise is precise and worth stating
/// exactly: after [`Cancel::stop`], **no further request is sent**. A request already
/// on the wire completes, because there is no way to un-send one, and pretending
/// otherwise in the type would be a lie a tester might rely on during an engagement.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// A signal nobody has pulled yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stops the run before its next request.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether the run has been asked to stop.
    pub fn stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// The checks this crate provides.
///
/// Listed rather than discovered, for the reason
/// [`Registry`](hexora_verify::Registry) gives: adding a check means adding a line,
/// and that is the honest cost of not having a plugin mechanism.
pub fn active_checks() -> Vec<Box<dyn ActiveCheck>> {
    vec![
        Box::new(checks::auth::AuthEnforcement),
        Box::new(checks::crossid::CrossIdentity),
        Box::new(checks::reflection::OriginReflection),
        Box::new(checks::echo::InputReflection),
        Box::new(checks::redirect::RedirectDestination),
    ]
}

/// What every active check in this build is, for `hexora detectors`.
pub fn checks_info() -> Vec<DetectorInfo> {
    active_checks().iter().map(|check| check.about()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_active_check_says_it_sends() {
        // `hexora detectors --sending` is the list a tester reads before pointing this
        // at a production system. A check in this crate that reported itself as
        // passive would keep itself off that list.
        for info in checks_info() {
            assert!(
                info.sends(),
                "{} does not report itself as sending",
                info.id
            );
        }
    }

    #[test]
    fn stopping_is_visible_immediately() {
        let cancel = Cancel::new();
        assert!(!cancel.stopped());
        let clone = cancel.clone();
        clone.stop();
        assert!(cancel.stopped(), "a clone shares the signal");
    }
}

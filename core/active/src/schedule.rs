//! The queue: what would be sent, and then the sending.
//!
//! Two functions, and the split between them is the safety property. [`Plan::prepare`]
//! is synchronous, takes no `async`, and answers every question a tester has before
//! authorizing traffic. [`run`] is the only thing that sends.
//!
//! # One queue per host
//!
//! ```text
//! prepare()  ──▶  host A: 3 experiments  ──┐
//!                 host B: 1 experiment   ──┤── hosts_at_once slots
//!                 host C: 2 experiments  ──┘
//!
//! run()      ──▶  within a host: strictly sequential, with a pause between
//! ```
//!
//! Concurrency without spawning: the host queues are futures driven together on one
//! task by [`futures::stream::buffer_unordered`]. That is what lets the scheduler hold
//! a `&dyn Lab` across the whole run instead of requiring every caller to hand it an
//! `Arc`, and it is why stopping needs no cross-thread handshake — the flag is read
//! between awaits on the same task.
//!
//! # Nothing is retried
//!
//! A transport error produces [`Verification::Inconclusive`] and the experiment is
//! over. Retrying would double the traffic a budget accounted for, and a host that
//! just refused a connection is the last host that should be asked again immediately.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use futures::stream::StreamExt;
use hexora_storage::{DetectorRun, Project};
use hexora_types::finding::Hypothesis;
use hexora_types::verify::{Verification, Verified};
use hexora_types::Result;
use hexora_verify::{Judged, Lab};

use crate::{ActiveCheck, Budget, Cancel, Subject};

/// Why a hypothesis was not going to be tested.
///
/// Reported rather than dropped. A suspicion that nothing can settle is a gap in the
/// tool, and one whose traffic the project has lost is a gap in the evidence; a tester
/// is entitled to know which of the two they are looking at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// What was suspected.
    pub claim: String,
    /// The check that raised it.
    pub detector: String,
    /// Why nothing will be sent for it.
    pub why: String,
}

/// Why a run ended before it had worked through its queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoppedBecause {
    /// Somebody pulled [`Cancel`].
    Cancelled,
    /// The run reached [`Budget::max_requests`].
    CeilingReached,
}

impl StoppedBecause {
    /// The value stored in `scan_runs.stopped_because`.
    pub fn as_column(&self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::CeilingReached => "ceiling",
        }
    }

    /// How it reads, in the sentence that must never be mistaken for "found nothing".
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cancelled => {
                "the run was stopped before it finished, so the experiments it had not \
                 reached were not performed"
            }
            Self::CeilingReached => {
                "the run reached its request ceiling before it finished, so the \
                 experiments it had not reached were not performed"
            }
        }
    }
}

/// What a run would do, worked out without sending anything.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The experiments, in queue order.
    pub work: Vec<Subject>,
    /// The hypotheses that will not be tested, and why.
    pub skipped: Vec<Skipped>,
    /// What the run may do to the systems it tests.
    pub budget: Budget,
}

impl Plan {
    /// Works out what would be sent. Sends nothing.
    ///
    /// Synchronous, and that is the point: there is no `.await` here through which a
    /// request could leave. `--dry-run` is this function without the next one, rather
    /// than a flag the sending path is trusted to honour.
    pub fn prepare(
        project: &Project,
        lab: &dyn Lab,
        checks: &[Box<dyn ActiveCheck>],
        hypotheses: &[Hypothesis],
        budget: &Budget,
    ) -> Result<Self> {
        budget
            .check()
            .map_err(|why| hexora_types::HexoraError::invalid_input("budget", why))?;

        let mut work = Vec::new();
        let mut skipped = Vec::new();

        for hypothesis in hypotheses {
            let Some(check) = checks.iter().find(|check| check.handles(hypothesis)) else {
                skipped.push(Skipped {
                    claim: hypothesis.claim.clone(),
                    detector: hypothesis.detector.clone(),
                    why: "no check in this build can settle it. It stays a suspicion, \
                          which is not the same as it being untrue"
                        .into(),
                });
                continue;
            };
            let _ = check;

            let exchange =
                match hexora_scan::passive::exchange_at(project, hypothesis.source_request) {
                    Ok(Some(exchange)) => exchange,
                    Ok(None) | Err(_) => {
                        skipped.push(Skipped {
                            claim: hypothesis.claim.clone(),
                            detector: hypothesis.detector.clone(),
                            why: format!(
                                "the project no longer holds the exchange it was raised \
                             from ({}), so there is nothing to re-run",
                                hypothesis.source_request
                            ),
                        });
                        continue;
                    }
                };

            let draft = match lab.draft_of(hypothesis.source_request) {
                Ok(draft) => draft,
                Err(e) => {
                    skipped.push(Skipped {
                        claim: hypothesis.claim.clone(),
                        detector: hypothesis.detector.clone(),
                        why: format!("its request could not be loaded to re-send: {e}"),
                    });
                    continue;
                }
            };

            // Asked here so an out-of-scope target is one line in a dry run rather
            // than a failure per experiment. Asked *again* before every send, because
            // scope can be narrowed while a queue is draining.
            if lab.would_leave_scope(&draft, None) {
                skipped.push(Skipped {
                    claim: hypothesis.claim.clone(),
                    detector: hypothesis.detector.clone(),
                    why: format!(
                        "{} is not in the project's scope, so nothing will be sent to it",
                        exchange.host
                    ),
                });
                continue;
            }

            work.push(Subject {
                hypothesis: hypothesis.clone(),
                target: exchange.target,
                exchange,
                draft,
            });
        }

        // Deterministic, so two dry runs of the same project agree and a reader can
        // compare them.
        work.sort_by(|a, b| {
            (a.host(), &a.hypothesis.detector, &a.hypothesis.claim).cmp(&(
                b.host(),
                &b.hypothesis.detector,
                &b.hypothesis.claim,
            ))
        });
        skipped.sort_by(|a, b| (&a.detector, &a.claim).cmp(&(&b.detector, &b.claim)));

        Ok(Self {
            work,
            skipped,
            budget: budget.clone(),
        })
    }

    /// The experiments, grouped into the per-host queues a run will use.
    pub fn by_host(&self) -> Vec<(String, Vec<&Subject>)> {
        let mut queues: BTreeMap<String, Vec<&Subject>> = BTreeMap::new();
        for subject in &self.work {
            queues
                .entry(subject.host().to_string())
                .or_default()
                .push(subject);
        }
        queues.into_iter().collect()
    }

    /// The most requests this run could send, before the ceiling is applied.
    ///
    /// An upper bound, not a prediction: a check that settles a question in one
    /// request sends one. Stated as a ceiling because that is the number somebody
    /// deciding whether to authorize this needs.
    pub fn requests_at_most(&self) -> usize {
        self.work.len() * self.budget.per_hypothesis
    }

    /// Whether the ceiling would cut this run short.
    pub fn exceeds_ceiling(&self) -> bool {
        self.requests_at_most() > self.budget.max_requests
    }

    /// The plan in the sentences a confirmation prompt needs.
    pub fn describe(&self) -> String {
        if self.work.is_empty() {
            return "Nothing to test: no hypothesis in this project has a check that \
                    can settle it and traffic still behind it."
                .into();
        }
        let hosts = self.by_host();
        let mut lines = vec![format!(
            "{} experiment(s) across {} host(s), at most {} request(s):",
            self.work.len(),
            hosts.len(),
            self.requests_at_most(),
        )];
        for (host, queue) in &hosts {
            lines.push(format!(
                "  {host} — {} experiment(s), at most {} request(s)",
                queue.len(),
                queue.len() * self.budget.per_hypothesis,
            ));
        }
        lines.push(format!("Budget: {}", self.budget.describe()));
        if self.exceeds_ceiling() {
            lines.push(format!(
                "This plan can reach the ceiling of {} request(s). A run that stops \
                 there will say so rather than reading as a finished one.",
                self.budget.max_requests
            ));
        }
        lines.join("\n")
    }
}

/// What a run did.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// The run as it was written into the project, when it was.
    pub run: Option<hexora_storage::ScanRun>,
    /// Every experiment and what became of it.
    pub judged: Vec<Judged>,
    /// Hypotheses nothing was sent for.
    pub skipped: Vec<Skipped>,
    /// How many requests actually went out.
    ///
    /// The number a client may ask about afterwards, so it counts sends rather than
    /// intentions.
    pub requests_sent: usize,
    /// Why the run ended early, when it did.
    ///
    /// `None` means the queue was worked through. Anything else means the run is
    /// *unfinished*, and every reader of this struct has to treat it that way.
    pub stopped: Option<StoppedBecause>,
    /// What each check did, including the ones that settled nothing.
    pub detectors: Vec<DetectorRun>,
}

impl Outcome {
    /// The findings, dropping every hypothesis the experiment did not support.
    pub fn findings(&self) -> Vec<&Verified> {
        self.judged
            .iter()
            .filter_map(|judged| judged.finding.as_ref())
            .collect()
    }

    /// The hypotheses an experiment knocked down.
    ///
    /// The most under-valued output here. "This host does not reflect arbitrary
    /// origins" is what stops a passive suspicion from following a tester around for
    /// the rest of an engagement.
    pub fn refuted(&self) -> impl Iterator<Item = &Judged> {
        self.judged
            .iter()
            .filter(|judged| matches!(judged.verification, Verification::Refuted { .. }))
    }

    /// Whether the run worked through everything it planned.
    pub fn complete(&self) -> bool {
        self.stopped.is_none()
    }
}

/// Runs the plan.
///
/// The only function in Hexora that sends traffic nobody typed. Everything that makes
/// that acceptable is above it: the plan was worked out without sending, the budget
/// was checked, scope is re-asked before each request, and [`Cancel`] is read between
/// every one.
pub async fn run(
    plan: &Plan,
    lab: &dyn Lab,
    checks: &[Box<dyn ActiveCheck>],
    cancel: &Cancel,
) -> Result<Outcome> {
    run_recording(plan, lab, checks, cancel, None).await
}

/// The same run, writing a record of itself into a project.
///
/// Separate from [`run`] so the scheduler's own tests can exercise the queue without
/// a project, and so the record is written once at the end from what actually
/// happened rather than accumulated as the run goes. A run that crashes mid-way
/// therefore leaves no row at all, which is the honest outcome: a partial row saying
/// `completed` would be worse than silence, and the CLI reports the crash.
pub async fn run_into(
    plan: &Plan,
    lab: &dyn Lab,
    checks: &[Box<dyn ActiveCheck>],
    cancel: &Cancel,
    project: &Project,
) -> Result<Outcome> {
    run_recording(plan, lab, checks, cancel, Some(project)).await
}

async fn run_recording(
    plan: &Plan,
    lab: &dyn Lab,
    checks: &[Box<dyn ActiveCheck>],
    cancel: &Cancel,
    project: Option<&Project>,
) -> Result<Outcome> {
    let started_at = chrono::Utc::now();
    let mut counts: BTreeMap<String, DetectorRun> = checks
        .iter()
        .map(|check| {
            let info = check.about();
            (
                info.id.to_string(),
                DetectorRun {
                    detector: info.id.to_string(),
                    version: info.version.to_string(),
                    mode: info.mode,
                    observations: 0,
                    hypotheses: 0,
                    reportable: 0,
                },
            )
        })
        .collect();

    let spend = RequestCeiling::new(plan.budget.max_requests);
    let queues = plan.by_host();

    // One future per host, a bounded number driven at a time. Within a future the
    // work is a plain sequential loop, which is what makes "one host is never sent
    // two requests at once" a property of the shape rather than of a lock.
    let worked: Vec<Vec<Worked>> =
        futures::stream::iter(queues.into_iter().map(|(host, queue)| async {
            let _ = host;
            let mut done = Vec::with_capacity(queue.len());
            for subject in queue {
                if cancel.stopped() {
                    break;
                }
                if !spend.has_room(plan.budget.per_hypothesis) {
                    break;
                }
                done.push(one(subject, lab, checks, &plan.budget, &spend, cancel).await);
                // Between experiments as well as within them: two experiments against
                // the same host back to back is the same burst the pause exists to
                // prevent.
                pause(plan.budget.pause).await;
            }
            done
        }))
        .buffer_unordered(plan.budget.hosts_at_once)
        .collect()
        .await;

    let mut judged = Vec::new();
    for result in worked.into_iter().flatten() {
        if let Some(entry) = counts.get_mut(&result.by) {
            entry.hypotheses += 1;
            if result.judged.finding.is_some() {
                entry.reportable += 1;
            }
        }
        judged.push(result.judged);
    }

    // Deterministic output for a deterministic plan: the host queues finish in
    // whatever order the network allows, and a report should not.
    judged.sort_by(|a, b| {
        (&a.hypothesis.detector, &a.hypothesis.claim)
            .cmp(&(&b.hypothesis.detector, &b.hypothesis.claim))
    });

    let stopped = if cancel.stopped() {
        Some(StoppedBecause::Cancelled)
    } else if judged.len() < plan.work.len() {
        // The only other way to leave work undone. Reported even though the run
        // "succeeded", because the difference between a finished run and a truncated
        // one is the difference between "clean" and "unknown".
        Some(StoppedBecause::CeilingReached)
    } else {
        None
    };

    let detectors: Vec<DetectorRun> = counts.into_values().collect();
    let mut record = None;
    if let Some(project) = project {
        let run = hexora_storage::ScanRun {
            id: hexora_types::ids::ScanRunId::new(),
            selection: format!(
                "{} experiment(s) across {} host(s); {}",
                plan.work.len(),
                plan.by_host().len(),
                plan.budget.describe(),
            ),
            started_at,
            completed_at: Some(chrono::Utc::now()),
            // `Completed` says the run reached its end without erroring, which a
            // cancelled run also does. Whether it worked through its queue is
            // `stopped_because`, and the two questions are deliberately separate.
            status: hexora_storage::RunStatus::Completed,
            exchanges_read: plan.work.len() as u64,
            exchanges_skipped: plan.skipped.len() as u64,
            requests_sent: spend.spent() as u64,
            stopped_because: stopped.map(|why| why.as_column().to_string()),
            tool_version: hexora_types::VERSION.to_string(),
            detectors: detectors.clone(),
        };
        project.scans().record(&run)?;
        record = Some(run);
    }

    Ok(Outcome {
        run: record,
        judged,
        skipped: plan.skipped.clone(),
        requests_sent: spend.spent(),
        stopped,
        detectors,
    })
}

struct Worked {
    judged: Judged,
    /// The check that ran the experiment.
    ///
    /// Not the same as `judged.hypothesis.detector`, which names the check that
    /// *raised* the suspicion. Counting an active run against the raiser would leave
    /// every settler's row reading zero — which is exactly the "the check did not run"
    /// reading that `scan_run_detectors` exists to make impossible.
    by: String,
}

/// One experiment.
async fn one(
    subject: &Subject,
    lab: &dyn Lab,
    checks: &[Box<dyn ActiveCheck>],
    budget: &Budget,
    spend: &RequestCeiling,
    cancel: &Cancel,
) -> Worked {
    let check = checks
        .iter()
        .find(|check| check.handles(&subject.hypothesis))
        .expect("prepare() only queues hypotheses a check handles");

    let metered = Metered {
        inner: lab,
        spend,
        cancel,
    };

    let verification = match check.settle(subject, &metered, budget).await {
        Ok(verification) => verification,
        Err(e) => Verification::Inconclusive {
            why: format!("the experiment could not be completed: {e}"),
        },
    };

    let finding = Verified::conclude(
        &subject.hypothesis,
        &verification,
        check.writeup(subject, &verification),
    );

    Worked {
        by: check.about().id.to_string(),
        judged: Judged {
            hypothesis: subject.hypothesis.clone(),
            verification,
            finding,
        },
    }
}

/// A [`Lab`] that counts what goes through it and refuses past the ceiling.
///
/// Wrapped around the real lab rather than trusted to each check, because "send at
/// most four requests" enforced by every author separately is a rule that holds until
/// the first check that forgets. A check that loops is stopped by the wrapper it was
/// handed.
struct Metered<'a> {
    inner: &'a dyn Lab,
    spend: &'a RequestCeiling,
    cancel: &'a Cancel,
}

#[async_trait::async_trait]
impl Lab for Metered<'_> {
    async fn experiment(
        &self,
        draft: &hexora_repeater::Draft,
        as_identity: Option<&hexora_types::identity::Identity>,
    ) -> Result<hexora_repeater::Sent> {
        if self.cancel.stopped() {
            return Err(hexora_types::HexoraError::invalid_input(
                "cancelled",
                "the run was stopped before this request was sent",
            ));
        }
        if !self.spend.take() {
            return Err(hexora_types::HexoraError::invalid_input(
                "budget",
                "the run reached its request ceiling before this request was sent",
            ));
        }
        // Re-asked here and not only in the plan: scope can be narrowed while a queue
        // is draining, and a target authorized ten minutes ago is not thereby
        // authorized now.
        if self.inner.would_leave_scope(draft, as_identity) {
            return Err(hexora_types::HexoraError::invalid_input(
                "scope",
                "the target left the project's scope before this request was sent",
            ));
        }
        self.inner.experiment(draft, as_identity).await
    }

    fn would_leave_scope(
        &self,
        draft: &hexora_repeater::Draft,
        as_identity: Option<&hexora_types::identity::Identity>,
    ) -> bool {
        self.inner.would_leave_scope(draft, as_identity)
    }

    fn draft_of(&self, request: hexora_types::ids::RequestId) -> Result<hexora_repeater::Draft> {
        self.inner.draft_of(request)
    }
}

/// How many requests the run has left.
///
/// Atomic because it is reached through a [`Lab`], which is `Send + Sync` so that a
/// verifier can be held across an await on any runtime. The host queues in this
/// scheduler are futures on one task and could not race — but the ceiling is handed
/// out behind a trait that promises otherwise, and a counter whose safety depended on
/// the current scheduling shape would be a trap for whoever changes it.
struct RequestCeiling {
    spent: std::sync::atomic::AtomicUsize,
    ceiling: usize,
}

impl RequestCeiling {
    fn new(ceiling: usize) -> Self {
        Self {
            spent: std::sync::atomic::AtomicUsize::new(0),
            ceiling,
        }
    }

    /// Claims one request, or refuses because the ceiling is reached.
    ///
    /// A compare-and-swap rather than a fetch-add: overshooting and then apologising
    /// would mean a request already sent, and the count is a promise about traffic
    /// rather than a metric.
    fn take(&self) -> bool {
        let mut seen = self.spent.load(Ordering::SeqCst);
        loop {
            if seen >= self.ceiling {
                return false;
            }
            match self
                .spent
                .compare_exchange(seen, seen + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return true,
                Err(actual) => seen = actual,
            }
        }
    }

    fn has_room(&self, wanted: usize) -> bool {
        // Asked before starting an experiment rather than mid-way: a check that gets
        // two of the four requests it needs produces a worse answer than one that was
        // never started, and "not started" is what the outcome can report honestly.
        self.spent.load(Ordering::SeqCst) + wanted <= self.ceiling
    }

    fn spent(&self) -> usize {
        self.spent.load(Ordering::SeqCst)
    }
}

async fn pause(duration: Duration) {
    if duration.is_zero() {
        return;
    }
    tokio::time::sleep(duration).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ceiling_stops_at_exactly_the_number_it_was_given() {
        let ceiling = RequestCeiling::new(3);
        assert!(ceiling.has_room(3));
        assert!(!ceiling.has_room(4));
        assert!(ceiling.take());
        assert!(ceiling.take());
        assert!(ceiling.take());
        assert!(!ceiling.take(), "the fourth request is refused");
        assert_eq!(ceiling.spent(), 3);
    }

    #[test]
    fn an_experiment_is_not_started_without_room_for_all_of_it() {
        // Half an experiment answers worse than none, and "not started" is the thing
        // the outcome can state honestly.
        let ceiling = RequestCeiling::new(4);
        assert!(ceiling.take());
        assert!(ceiling.take());
        assert!(!ceiling.has_room(4));
        assert!(ceiling.has_room(2));
    }

    #[test]
    fn stopping_early_never_reads_as_finding_nothing() {
        for reason in [StoppedBecause::Cancelled, StoppedBecause::CeilingReached] {
            let said = reason.as_str();
            assert!(said.contains("were not performed"), "{said}");
        }
    }
}

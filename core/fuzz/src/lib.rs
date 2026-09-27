//! # nullhawk-fuzz
//!
//! One request, many values, and a readable account of what came back.
//!
//! ```text
//! GET /login?user=§admin§&pass=x
//!               │
//!               ├─ admin      401  312 bytes   the baseline's answer
//!               ├─ root       401  312 bytes
//!               ├─ test       401  312 bytes
//!               └─ operator   401  489 bytes   ← the one worth looking at
//! ```
//!
//! The whole value is in that last column. A tester sends two hundred values and reads
//! *one* row, and the tool's job is to make that row impossible to miss — which is
//! grouping, not analysis.
//!
//! # It produces observations, never findings
//!
//! Nothing here concludes anything. A response that differs is a response that differs;
//! whether `operator` being a valid username matters is a judgement about the
//! application, and the person who chose the payload list is the one making it. So this
//! crate has no [`Verified`](nullhawk_types::verify::Verified), raises no hypothesis and
//! writes nothing into the findings store. It is a **workbench tool** that happens to
//! reuse the scanner's safety machinery, and keeping it that way is what stops it
//! becoming a second scanner with worse evidence.
//!
//! # What it borrows from the scheduler, and what it does not
//!
//! Borrowed: [`Budget`] — the request ceiling, the pause between requests, and
//! [`Cancel`]. A person iterating a payload list can generate more traffic in a minute
//! than every automated check in this build put together, so the limits that protect a
//! target are not optional here.
//!
//! Not borrowed: the refusal to replay a state-changing request. Invariant 18 is a rule
//! about what a *queue* may decide on its own; a tester who points this at
//! `POST /transfer` has decided, and the CLI tells them exactly what is about to happen
//! and how many times before it does.
//!
//! # Where the payload goes
//!
//! An [`ObjectLocation`] — the same addressing M12.5 uses to substitute an object
//! identifier and M13.4 uses to place a marker. A query parameter, a header, or a byte
//! range in the body; there is one substitution in this codebase and everything goes
//! through it.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

use std::time::{Duration, Instant};

use nullhawk_active::{Budget, Cancel, StoppedBecause};
use nullhawk_types::ids::RequestId;
use nullhawk_types::inject::substitute;
use nullhawk_types::object::ObjectLocation;
use nullhawk_types::structure::{Diff, Policy};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

/// The longest payload echoed back into a table.
const PAYLOAD_LIMIT: usize = 48;

/// What one value produced.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// The value that was placed, truncated for display.
    pub payload: String,
    /// The stored request, so every row can be opened.
    pub request: Option<RequestId>,
    /// What came back.
    pub status: u16,
    /// The decoded body's length.
    pub bytes: usize,
    /// How long it took.
    pub took: Duration,
    /// Why nothing came back, when nothing did.
    ///
    /// A refused connection is a result too — an application that stops answering at
    /// the fortieth payload is telling you something.
    pub error: Option<String>,
}

impl Attempt {
    /// Whether this attempt produced a response at all.
    pub fn answered(&self) -> bool {
        self.error.is_none()
    }
}

/// Attempts that behaved the same way, and how many there were.
///
/// The output that makes a two-hundred-payload run readable: one row per *behaviour*
/// rather than per payload, so the outlier is the short row rather than something to
/// scroll for.
#[derive(Debug, Clone)]
pub struct Group {
    /// The status every attempt in this group answered with.
    pub status: u16,
    /// The body length they shared, or the range when it varied a little.
    pub bytes: usize,
    /// How many attempts behaved this way.
    pub count: usize,
    /// Up to [`EXAMPLES_PER_GROUP`] of the payloads, so a reader can see what they were.
    pub examples: Vec<String>,
    /// One of the attempts, for opening the exchange.
    pub request: Option<RequestId>,
    /// Whether this is how the unchanged request behaved.
    pub is_baseline: bool,
}

/// How many payloads a group names before it stops.
pub const EXAMPLES_PER_GROUP: usize = 5;

/// What a run did.
#[derive(Debug, Clone)]
pub struct Run {
    /// The request sent unchanged, for everything else to be read against.
    pub baseline: Option<Attempt>,
    /// One per payload, in the order they were given.
    pub attempts: Vec<Attempt>,
    /// How many requests actually went out.
    pub requests_sent: usize,
    /// Why the run ended early, when it did.
    ///
    /// `None` means every payload was sent. Anything else means the list was **not
    /// finished**, and a reader who takes "no outlier" from a truncated run has been
    /// misled — see invariant 15.
    pub stopped: Option<StoppedBecause>,
}

impl Run {
    /// Whether every payload was sent.
    pub fn complete(&self) -> bool {
        self.stopped.is_none()
    }

    /// Attempts grouped by how the application behaved, largest group first.
    ///
    /// Grouped on `(status, body length)`. Deliberately exact rather than fuzzy: a
    /// tolerance would hide the one-byte difference between `true` and `false`, which
    /// is the difference a blind test is looking for.
    pub fn grouped(&self) -> Vec<Group> {
        use std::collections::BTreeMap;

        let baseline_key = self
            .baseline
            .as_ref()
            .filter(|attempt| attempt.answered())
            .map(|attempt| (attempt.status, attempt.bytes));

        let mut groups: BTreeMap<(u16, usize), Group> = BTreeMap::new();
        for attempt in self.attempts.iter().filter(|a| a.answered()) {
            let key = (attempt.status, attempt.bytes);
            let group = groups.entry(key).or_insert_with(|| Group {
                status: attempt.status,
                bytes: attempt.bytes,
                count: 0,
                examples: Vec::new(),
                request: attempt.request,
                is_baseline: Some(key) == baseline_key,
            });
            group.count += 1;
            if group.examples.len() < EXAMPLES_PER_GROUP {
                group.examples.push(attempt.payload.clone());
            }
        }

        let mut grouped: Vec<Group> = groups.into_values().collect();
        // Largest first: the crowd is the uninteresting part and belongs at the top
        // where a reader's eye starts, so the short rows stand out below it.
        grouped.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.status.cmp(&b.status))
                .then(a.bytes.cmp(&b.bytes))
        });
        grouped
    }

    /// The attempts that did not behave like the majority.
    ///
    /// "Majority" rather than "baseline": in a list of two hundred usernames the
    /// baseline is one more wrong answer, and the row worth reading is the one that
    /// broke the pattern the other one hundred and ninety-nine made.
    pub fn outliers(&self) -> Vec<&Attempt> {
        let grouped = self.grouped();
        let Some(crowd) = grouped.first() else {
            return Vec::new();
        };
        // Nothing stands out when everything is different, and nothing stands out when
        // everything is the same.
        if grouped.len() < 2 || crowd.count < 2 {
            return Vec::new();
        }
        let majority = (crowd.status, crowd.bytes);
        self.attempts
            .iter()
            .filter(|attempt| attempt.answered() && (attempt.status, attempt.bytes) != majority)
            .collect()
    }

    /// How the run reads in one line.
    pub fn summary(&self) -> String {
        let answered = self.attempts.iter().filter(|a| a.answered()).count();
        let failed = self.attempts.len() - answered;
        let mut line = format!(
            "{} payload(s) sent, {} answered",
            self.attempts.len(),
            answered
        );
        if failed > 0 {
            line.push_str(&format!(", {failed} did not complete"));
        }
        let groups = self.grouped().len();
        line.push_str(&format!(
            ", {groups} distinct behaviour{}",
            if groups == 1 { "" } else { "s" }
        ));
        line
    }
}

/// What to iterate, and where.
pub struct Plan<'a> {
    /// The request to vary.
    pub draft: &'a nullhawk_repeater::Draft,
    /// Where in it the payload goes.
    pub at: ObjectLocation,
    /// The values, in order.
    pub payloads: &'a [String],
    /// What the run may do to the target.
    pub budget: Budget,
}

impl Plan<'_> {
    /// The most requests this would send: one per payload, plus the baseline.
    pub fn requests(&self) -> usize {
        self.payloads.len() + 1
    }

    /// Whether the ceiling would cut the list short.
    pub fn exceeds_ceiling(&self) -> bool {
        self.requests() > self.budget.max_requests
    }

    /// The plan in the sentences a confirmation prompt needs.
    pub fn describe(&self, method: &str, url: &str) -> String {
        let mut lines = vec![format!(
            "{} {} — {} payload(s) into {}, {} request(s) including the baseline",
            method,
            url,
            self.payloads.len(),
            describe(&self.at),
            self.requests(),
        )];
        lines.push(format!("Budget: {}", self.budget.describe()));
        if self.exceeds_ceiling() {
            lines.push(format!(
                "The ceiling of {} request(s) will stop this before the list is \
                 finished, and the result will say so.",
                self.budget.max_requests
            ));
        }
        lines.join("\n")
    }
}

/// How a location reads.
pub fn describe(at: &ObjectLocation) -> String {
    match at {
        ObjectLocation::Query { name, .. } => format!("the `{name}` query parameter"),
        ObjectLocation::Header { name, .. } => format!("the `{name}` header"),
        ObjectLocation::PathSegment { index } => format!("path segment {index}"),
        ObjectLocation::Body { offset } => format!("the body at byte {offset}"),
        other => format!("{other:?}"),
    }
}

/// A short name for a location, for a payload label a reader can attribute to a position.
fn slot_name(at: &ObjectLocation) -> String {
    match at {
        ObjectLocation::Query { name, .. } => name.clone(),
        ObjectLocation::Header { name, .. } => name.clone(),
        ObjectLocation::PathSegment { index } => format!("path[{index}]"),
        ObjectLocation::Body { offset } => format!("body@{offset}"),
        other => format!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Multi-position attacks (Burp Intruder's four modes)
// ---------------------------------------------------------------------------
//
// The single-position `Plan`/`run` above is Sniper with one marker — the case a tester
// reaches for most. The four named modes generalise it over several positions and, for two
// of them, several payload lists. Every mode reduces to the same idea: produce an ordered
// sequence of *placements* — each one a set of (position, value) substitutions plus a label
// for the row — and send the request once per placement, into the same `Run` the
// single-position path produces. The reporting, grouping and safety machinery are unchanged.

/// Which Intruder attack shape to run.
///
/// The names are Burp's, because that is what a tester already knows; the behaviour is the
/// behaviour those names have meant for twenty years.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMode {
    /// One payload list, walked through each position in turn while the others stay at the
    /// request's own value. `positions × payloads` requests.
    Sniper,
    /// One payload list, the same value placed in every position at once. `payloads` requests.
    BatteringRam,
    /// One payload list per position, advanced in lockstep and stopping at the shortest list.
    /// `min(list lengths)` requests.
    Pitchfork,
    /// One payload list per position, every combination — the Cartesian product.
    /// `∏ list lengths` requests.
    ClusterBomb,
}

impl AttackMode {
    /// How the mode reads.
    pub fn label(self) -> &'static str {
        match self {
            AttackMode::Sniper => "sniper",
            AttackMode::BatteringRam => "battering ram",
            AttackMode::Pitchfork => "pitchfork",
            AttackMode::ClusterBomb => "cluster bomb",
        }
    }

    /// Whether the mode uses one shared payload list (Sniper, Battering ram) rather than one
    /// list per position (Pitchfork, Cluster bomb).
    pub fn shares_one_list(self) -> bool {
        matches!(self, AttackMode::Sniper | AttackMode::BatteringRam)
    }

    /// Parses a mode from its CLI spelling (hyphen or underscore, any case).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "sniper" => Some(AttackMode::Sniper),
            "battering-ram" | "batteringram" | "ram" => Some(AttackMode::BatteringRam),
            "pitchfork" => Some(AttackMode::Pitchfork),
            "cluster-bomb" | "clusterbomb" | "cluster" => Some(AttackMode::ClusterBomb),
            _ => None,
        }
    }
}

/// One request's worth of substitutions, with the label its row will carry.
#[derive(Debug, Clone)]
struct Placement {
    label: String,
    /// `(position index into the attack's positions, value to place)`.
    subs: Vec<(usize, String)>,
}

/// A multi-position attack: the request, where the markers are, the lists, and the shape.
pub struct Attack<'a> {
    /// The request to vary.
    pub draft: &'a nullhawk_repeater::Draft,
    /// The marked positions, in order.
    pub positions: Vec<ObjectLocation>,
    /// Sniper and Battering ram take exactly one list; Pitchfork and Cluster bomb take one
    /// per position, in the same order as `positions`.
    pub payload_lists: Vec<&'a [String]>,
    /// Which of the four shapes to run.
    pub mode: AttackMode,
    /// What the run may do to the target.
    pub budget: Budget,
}

impl Attack<'_> {
    /// Checks the positions and lists are consistent with the mode, before anything is sent.
    pub fn validate(&self) -> Result<()> {
        let bad = |why: String| Err(nullhawk_types::NullhawkError::invalid_input("attack", why));
        if self.positions.is_empty() {
            return bad("an attack needs at least one marked position".into());
        }
        if self.payload_lists.is_empty() || self.payload_lists.iter().any(|list| list.is_empty()) {
            return bad("every payload list must have at least one value".into());
        }
        if self.mode.shares_one_list() {
            if self.payload_lists.len() != 1 {
                return bad(format!(
                    "{} uses one payload list for all positions, but {} were given",
                    self.mode.label(),
                    self.payload_lists.len()
                ));
            }
        } else if self.payload_lists.len() != self.positions.len() {
            return bad(format!(
                "{} needs one payload list per position: {} position(s), {} list(s)",
                self.mode.label(),
                self.positions.len(),
                self.payload_lists.len()
            ));
        }
        Ok(())
    }

    /// How many payload placements the full attack is — before the baseline, and before any
    /// ceiling. Saturating, because a Cluster bomb's product can overflow a `usize` long
    /// before it could ever be sent.
    pub fn placements(&self) -> usize {
        match self.mode {
            AttackMode::Sniper => self
                .positions
                .len()
                .saturating_mul(self.payload_lists.first().map_or(0, |l| l.len())),
            AttackMode::BatteringRam => self.payload_lists.first().map_or(0, |l| l.len()),
            AttackMode::Pitchfork => self
                .payload_lists
                .iter()
                .map(|l| l.len())
                .min()
                .unwrap_or(0),
            AttackMode::ClusterBomb => self
                .payload_lists
                .iter()
                .fold(1usize, |acc, l| acc.saturating_mul(l.len())),
        }
    }

    /// The most requests this would send: every placement, plus the baseline.
    pub fn requests(&self) -> usize {
        self.placements().saturating_add(1)
    }

    /// Whether the ceiling would cut the attack short.
    pub fn exceeds_ceiling(&self) -> bool {
        self.requests() > self.budget.max_requests
    }

    /// The attack in the sentences a confirmation prompt needs.
    pub fn describe(&self, method: &str, url: &str) -> String {
        let positions: Vec<String> = self.positions.iter().map(describe).collect();
        let mut lines = vec![
            format!(
                "{} {} — {} attack over {} position(s): {}",
                method,
                url,
                self.mode.label(),
                self.positions.len(),
                positions.join(", "),
            ),
            format!(
                "{} placement(s), {} request(s) including the baseline",
                self.placements(),
                self.requests(),
            ),
            format!("Budget: {}", self.budget.describe()),
        ];
        if self.exceeds_ceiling() {
            lines.push(format!(
                "The ceiling of {} request(s) will stop this before the attack is \
                 finished, and the result will say so.",
                self.budget.max_requests
            ));
        }
        lines.join("\n")
    }

    /// Expands the attack into placements, generating no more than `cap` of them so a large
    /// Cluster bomb cannot exhaust memory building a list the ceiling would never let it send.
    fn expand(&self, cap: usize) -> Vec<Placement> {
        let mut out = Vec::new();
        match self.mode {
            AttackMode::Sniper => {
                let list = self.payload_lists[0];
                let annotate = self.positions.len() > 1;
                for (index, position) in self.positions.iter().enumerate() {
                    for value in list {
                        if out.len() >= cap {
                            return out;
                        }
                        let label = if annotate {
                            format!("{}={value}", slot_name(position))
                        } else {
                            value.clone()
                        };
                        out.push(Placement {
                            label,
                            subs: vec![(index, value.clone())],
                        });
                    }
                }
            }
            AttackMode::BatteringRam => {
                let list = self.payload_lists[0];
                for value in list {
                    if out.len() >= cap {
                        return out;
                    }
                    out.push(Placement {
                        label: value.clone(),
                        subs: (0..self.positions.len())
                            .map(|i| (i, value.clone()))
                            .collect(),
                    });
                }
            }
            AttackMode::Pitchfork => {
                let length = self.placements();
                for k in 0..length {
                    if out.len() >= cap {
                        return out;
                    }
                    let subs: Vec<(usize, String)> = self
                        .payload_lists
                        .iter()
                        .enumerate()
                        .map(|(i, list)| (i, list[k].clone()))
                        .collect();
                    out.push(Placement {
                        label: subs
                            .iter()
                            .map(|(_, v)| v.clone())
                            .collect::<Vec<_>>()
                            .join(" / "),
                        subs,
                    });
                }
            }
            AttackMode::ClusterBomb => {
                // A mixed-radix counter over the lists, least-significant last so the last
                // list varies fastest — the order a tester expects.
                let lengths: Vec<usize> = self.payload_lists.iter().map(|l| l.len()).collect();
                let mut cursor = vec![0usize; lengths.len()];
                loop {
                    if out.len() >= cap {
                        return out;
                    }
                    let subs: Vec<(usize, String)> = cursor
                        .iter()
                        .enumerate()
                        .map(|(i, &k)| (i, self.payload_lists[i][k].clone()))
                        .collect();
                    out.push(Placement {
                        label: subs
                            .iter()
                            .map(|(_, v)| v.clone())
                            .collect::<Vec<_>>()
                            .join(" / "),
                        subs,
                    });
                    // Increment the counter from the last position.
                    let mut carry = lengths.len();
                    loop {
                        if carry == 0 {
                            return out;
                        }
                        carry -= 1;
                        cursor[carry] += 1;
                        if cursor[carry] < lengths[carry] {
                            break;
                        }
                        cursor[carry] = 0;
                    }
                }
            }
        }
        out
    }
}

/// Applies one placement to the draft, substituting each marked position.
///
/// Body-offset positions are applied from the highest offset down, so substituting an earlier
/// one cannot shift the byte offset of a later one. Query and header positions address by name
/// and occurrence, so their order does not matter.
fn apply(
    draft: &nullhawk_repeater::Draft,
    positions: &[ObjectLocation],
    placement: &Placement,
) -> std::result::Result<nullhawk_repeater::Draft, String> {
    let mut ordered: Vec<&(usize, String)> = placement.subs.iter().collect();
    ordered.sort_by_key(|(index, _)| match &positions[*index] {
        ObjectLocation::Body { offset } => usize::MAX - offset,
        _ => 0,
    });
    let mut varied = draft.clone();
    for (index, value) in ordered {
        varied.request =
            substitute(&varied.request, &positions[*index], value).map_err(|e| e.to_string())?;
    }
    Ok(varied)
}

/// Runs a multi-position attack, sending the request once per placement.
///
/// The baseline goes first, unchanged, exactly as [`run`] does — every row is read against it,
/// and a target already failing is visible before the attack piles on. The ceiling and the
/// cancel signal are honoured between placements, and a truncated attack says so.
pub async fn run_attack(attack: &Attack<'_>, lab: &dyn Lab, cancel: &Cancel) -> Result<Run> {
    attack.validate()?;
    attack
        .budget
        .check()
        .map_err(|why| nullhawk_types::NullhawkError::invalid_input("budget", why))?;

    let mut sent = 0usize;
    let baseline = match send(attack.draft, lab, "(unchanged)").await {
        Ok(attempt) => {
            sent += 1;
            Some(attempt)
        }
        Err(e) => Some(failed("(unchanged)", e)),
    };

    // Generate at most a ceiling's worth: anything beyond it could not be sent anyway, and a
    // Cluster bomb's product would otherwise build a list large enough to exhaust memory.
    let placements = attack.expand(attack.budget.max_requests);
    let full = attack.placements();

    let mut attempts = Vec::with_capacity(placements.len());
    let mut stopped = None;

    for placement in &placements {
        if cancel.stopped() {
            stopped = Some(StoppedBecause::Cancelled);
            break;
        }
        if sent >= attack.budget.max_requests {
            stopped = Some(StoppedBecause::CeilingReached);
            break;
        }

        pause(attack.budget.pause).await;

        let varied = match apply(attack.draft, &attack.positions, placement) {
            Ok(varied) => varied,
            Err(e) => {
                attempts.push(failed(&placement.label, e));
                continue;
            }
        };

        match send(&varied, lab, &placement.label).await {
            Ok(attempt) => {
                sent += 1;
                attempts.push(attempt);
            }
            Err(e) => {
                sent += 1;
                attempts.push(failed(&placement.label, e));
            }
        }
    }

    // If generation itself was capped below the full size, the attack was not finished even
    // though the loop ran to the end of what it built.
    if stopped.is_none() && placements.len() < full {
        stopped = Some(StoppedBecause::CeilingReached);
    }

    Ok(Run {
        baseline,
        attempts,
        requests_sent: sent,
        stopped,
    })
}

/// Sends the request once per payload.
///
/// The baseline goes first, unchanged, so every row has something to be read against —
/// and so a target that was already failing is visible before two hundred more requests
/// are aimed at it.
pub async fn run(plan: &Plan<'_>, lab: &dyn Lab, cancel: &Cancel) -> Result<Run> {
    plan.budget
        .check()
        .map_err(|why| nullhawk_types::NullhawkError::invalid_input("budget", why))?;

    let mut sent = 0usize;
    let baseline = match send(plan.draft, lab, "(unchanged)").await {
        Ok(attempt) => {
            sent += 1;
            Some(attempt)
        }
        Err(e) => Some(failed("(unchanged)", e)),
    };

    let mut attempts = Vec::with_capacity(plan.payloads.len());
    let mut stopped = None;

    for payload in plan.payloads {
        if cancel.stopped() {
            stopped = Some(StoppedBecause::Cancelled);
            break;
        }
        if sent >= plan.budget.max_requests {
            stopped = Some(StoppedBecause::CeilingReached);
            break;
        }

        pause(plan.budget.pause).await;

        let mut varied = plan.draft.clone();
        varied.request = match substitute(&varied.request, &plan.at, payload) {
            Ok(request) => request,
            Err(e) => {
                attempts.push(failed(payload, e.to_string()));
                continue;
            }
        };

        match send(&varied, lab, payload).await {
            Ok(attempt) => {
                sent += 1;
                attempts.push(attempt);
            }
            Err(e) => {
                // Counted: the request left, whatever came back.
                sent += 1;
                attempts.push(failed(payload, e));
            }
        }
    }

    Ok(Run {
        baseline,
        attempts,
        requests_sent: sent,
        stopped,
    })
}

/// Compares two of a run's responses, field by field.
///
/// Offered rather than computed for every attempt: a two-hundred-payload run would
/// hold two hundred bodies in memory to answer a question about two of them. A reader
/// picks the outlier and asks.
pub fn compare(baseline: &[u8], variant: &[u8]) -> Diff {
    Diff::of(baseline, variant, &Policy::default())
}

async fn send(
    draft: &nullhawk_repeater::Draft,
    lab: &dyn Lab,
    payload: &str,
) -> std::result::Result<Attempt, String> {
    let started = Instant::now();
    match lab.experiment(draft, None).await {
        Ok(sent) => Ok(Attempt {
            payload: truncate(payload),
            request: Some(sent.id),
            status: sent.exchange.response.status,
            bytes: sent.exchange.response.body.len(),
            took: started.elapsed(),
            error: None,
        }),
        Err(e) => Err(e.to_string()),
    }
}

fn failed(payload: &str, why: impl Into<String>) -> Attempt {
    Attempt {
        payload: truncate(payload),
        request: None,
        status: 0,
        bytes: 0,
        took: Duration::ZERO,
        error: Some(why.into()),
    }
}

fn truncate(value: &str) -> String {
    if value.chars().count() <= PAYLOAD_LIMIT {
        return value.to_string();
    }
    let mut cut: String = value.chars().take(PAYLOAD_LIMIT).collect();
    cut.push('…');
    cut
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

    fn attempt(payload: &str, status: u16, bytes: usize) -> Attempt {
        Attempt {
            payload: payload.into(),
            request: Some(RequestId::new()),
            status,
            bytes,
            took: Duration::from_millis(1),
            error: None,
        }
    }

    fn run_of(baseline: Option<Attempt>, attempts: Vec<Attempt>) -> Run {
        Run {
            baseline,
            requests_sent: attempts.len(),
            attempts,
            stopped: None,
        }
    }

    #[test]
    fn the_crowd_is_one_row_and_the_outlier_is_another() {
        // The whole point. Two hundred payloads, one answer worth reading.
        let mut attempts: Vec<Attempt> = (0..199)
            .map(|i| attempt(&format!("user{i}"), 401, 312))
            .collect();
        attempts.push(attempt("operator", 401, 489));

        let run = run_of(Some(attempt("(unchanged)", 401, 312)), attempts);
        let grouped = run.grouped();

        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].count, 199, "the crowd comes first");
        assert!(grouped[0].is_baseline);
        assert_eq!(grouped[1].count, 1);
        assert_eq!(grouped[1].bytes, 489);

        let outliers = run.outliers();
        assert_eq!(outliers.len(), 1);
        assert_eq!(outliers[0].payload, "operator");
    }

    #[test]
    fn a_one_byte_difference_is_still_a_different_behaviour() {
        // No tolerance on the size: `true` and `false` differ by one byte, and that is
        // exactly the difference a blind test is looking for.
        let run = run_of(None, vec![attempt("a", 200, 100), attempt("b", 200, 101)]);
        assert_eq!(run.grouped().len(), 2);
    }

    #[test]
    fn the_outlier_is_measured_against_the_crowd_not_the_baseline() {
        // In a list of usernames the baseline is one more wrong answer. The row worth
        // reading is the one that broke the pattern the others made.
        let mut attempts: Vec<Attempt> = (0..50)
            .map(|i| attempt(&format!("u{i}"), 404, 20))
            .collect();
        attempts.push(attempt("admin", 200, 5000));

        // The baseline behaved like nothing else in the run.
        let run = run_of(Some(attempt("(unchanged)", 500, 9)), attempts);

        let outliers = run.outliers();
        assert_eq!(outliers.len(), 1, "{outliers:#?}");
        assert_eq!(outliers[0].payload, "admin");
    }

    #[test]
    fn nothing_stands_out_when_everything_is_the_same() {
        let attempts: Vec<Attempt> = (0..20)
            .map(|i| attempt(&format!("u{i}"), 401, 10))
            .collect();
        assert!(run_of(None, attempts).outliers().is_empty());
    }

    #[test]
    fn nothing_stands_out_when_everything_is_different() {
        // Twenty payloads and twenty behaviours is a page that varies, not a signal.
        // Calling all twenty outliers would be worse than calling none.
        let attempts: Vec<Attempt> = (0..20).map(|i| attempt(&format!("u{i}"), 200, i)).collect();
        assert!(run_of(None, attempts).outliers().is_empty());
    }

    #[test]
    fn a_request_that_did_not_complete_is_kept_and_not_grouped() {
        // An application that stops answering at the fortieth payload is telling you
        // something, and it is not "forty identical responses".
        let run = run_of(
            None,
            vec![
                attempt("a", 200, 10),
                failed("b", "connection refused"),
                attempt("c", 200, 10),
            ],
        );
        assert_eq!(run.attempts.len(), 3);
        assert_eq!(run.grouped().iter().map(|g| g.count).sum::<usize>(), 2);
        assert!(
            run.summary().contains("1 did not complete"),
            "{}",
            run.summary()
        );
    }

    #[test]
    fn a_group_names_a_few_of_its_payloads_and_not_all_of_them() {
        let attempts: Vec<Attempt> = (0..100)
            .map(|i| attempt(&format!("u{i}"), 401, 10))
            .collect();
        let grouped = run_of(None, attempts).grouped();
        assert_eq!(grouped[0].count, 100);
        assert_eq!(grouped[0].examples.len(), EXAMPLES_PER_GROUP);
    }

    #[test]
    fn a_truncated_run_says_so() {
        // A reader who takes "no outlier" from a list that was never finished has been
        // misled. Invariant 15, in a tool a person drives.
        let run = Run {
            stopped: Some(StoppedBecause::CeilingReached),
            ..run_of(None, vec![attempt("a", 200, 1)])
        };
        assert!(!run.complete());
        assert!(run.stopped.unwrap().as_str().contains("not performed"));
    }

    #[test]
    fn a_long_payload_is_cut_before_it_reaches_a_table() {
        let long = "A".repeat(500);
        assert!(truncate(&long).chars().count() <= PAYLOAD_LIMIT + 1);
        assert!(truncate(&long).ends_with('…'));
    }

    #[test]
    fn a_plan_says_how_many_requests_it_is() {
        let draft = nullhawk_repeater::Draft::new(nullhawk_types::http::HttpRequest::get(
            nullhawk_types::http::HttpService::new("api.example.com", 443, true),
            "/login?user=admin",
        ));
        let payloads: Vec<String> = (0..50).map(|i| format!("u{i}")).collect();
        let plan = Plan {
            draft: &draft,
            at: ObjectLocation::Query {
                name: "user".into(),
                occurrence: 0,
            },
            payloads: &payloads,
            budget: Budget {
                max_requests: 20,
                ..Budget::default()
            },
        };

        assert_eq!(plan.requests(), 51, "the baseline counts");
        assert!(plan.exceeds_ceiling());
        let described = plan.describe("GET", "https://api.example.com/login?user=admin");
        assert!(described.contains("50 payload(s)"), "{described}");
        assert!(described.contains("`user` query parameter"), "{described}");
        assert!(described.contains("will stop this before"), "{described}");
    }

    // ----- multi-position attack modes -----

    fn draft() -> nullhawk_repeater::Draft {
        nullhawk_repeater::Draft::new(nullhawk_types::http::HttpRequest::get(
            nullhawk_types::http::HttpService::new("api.example.com", 443, true),
            "/login?user=admin&pass=x",
        ))
    }

    fn query(name: &str) -> ObjectLocation {
        ObjectLocation::Query {
            name: name.into(),
            occurrence: 0,
        }
    }

    fn attack<'a>(
        d: &'a nullhawk_repeater::Draft,
        mode: AttackMode,
        positions: Vec<ObjectLocation>,
        lists: Vec<&'a [String]>,
    ) -> Attack<'a> {
        Attack {
            draft: d,
            positions,
            payload_lists: lists,
            mode,
            budget: Budget {
                max_requests: 100_000,
                ..Budget::default()
            },
        }
    }

    #[test]
    fn each_mode_counts_its_placements() {
        let d = draft();
        let one: Vec<String> = vec!["a".into(), "b".into(), "c".into()]; // 3
        let two: Vec<String> = vec!["1".into(), "2".into()]; // 2

        // Sniper: positions × payloads.
        let sniper = attack(
            &d,
            AttackMode::Sniper,
            vec![query("user"), query("pass")],
            vec![&one],
        );
        assert_eq!(sniper.placements(), 6);

        // Battering ram: one request per payload, all positions at once.
        let ram = attack(
            &d,
            AttackMode::BatteringRam,
            vec![query("user"), query("pass")],
            vec![&one],
        );
        assert_eq!(ram.placements(), 3);

        // Pitchfork: lockstep, stops at the shortest list.
        let pitchfork = attack(
            &d,
            AttackMode::Pitchfork,
            vec![query("user"), query("pass")],
            vec![&one, &two],
        );
        assert_eq!(pitchfork.placements(), 2);

        // Cluster bomb: the Cartesian product.
        let cluster = attack(
            &d,
            AttackMode::ClusterBomb,
            vec![query("user"), query("pass")],
            vec![&one, &two],
        );
        assert_eq!(cluster.placements(), 6);
        assert_eq!(cluster.requests(), 7, "the baseline counts");
    }

    #[test]
    fn validate_rejects_a_list_count_that_does_not_fit_the_mode() {
        let d = draft();
        let one: Vec<String> = vec!["a".into()];
        let two: Vec<String> = vec!["a".into()];

        // Pitchfork needs one list per position.
        let bad = attack(
            &d,
            AttackMode::Pitchfork,
            vec![query("user")],
            vec![&one, &two],
        );
        assert!(bad.validate().is_err());

        // Sniper takes exactly one list however many positions there are.
        let bad_sniper = attack(
            &d,
            AttackMode::Sniper,
            vec![query("user"), query("pass")],
            vec![&one, &two],
        );
        assert!(bad_sniper.validate().is_err());

        // A well-formed sniper is accepted.
        let good = attack(&d, AttackMode::Sniper, vec![query("user")], vec![&one]);
        assert!(good.validate().is_ok());
    }

    #[test]
    fn sniper_labels_name_the_position_when_there_is_more_than_one() {
        let d = draft();
        let list: Vec<String> = vec!["x".into()];
        let a = attack(
            &d,
            AttackMode::Sniper,
            vec![query("user"), query("pass")],
            vec![&list],
        );
        let placements = a.expand(100);
        assert_eq!(placements.len(), 2);
        assert_eq!(placements[0].label, "user=x");
        assert_eq!(placements[1].label, "pass=x");
        // Each sniper placement touches exactly one position.
        assert!(placements.iter().all(|p| p.subs.len() == 1));
    }

    #[test]
    fn cluster_bomb_varies_the_last_list_fastest_and_pairs_every_value() {
        let d = draft();
        let users: Vec<String> = vec!["u1".into(), "u2".into()];
        let pins: Vec<String> = vec!["p1".into(), "p2".into()];
        let a = attack(
            &d,
            AttackMode::ClusterBomb,
            vec![query("user"), query("pass")],
            vec![&users, &pins],
        );
        let labels: Vec<String> = a.expand(100).into_iter().map(|p| p.label).collect();
        assert_eq!(labels, vec!["u1 / p1", "u1 / p2", "u2 / p1", "u2 / p2"]);
    }

    #[test]
    fn expand_stops_at_the_cap_so_a_huge_cluster_bomb_cannot_run_away() {
        let d = draft();
        let big: Vec<String> = (0..1000).map(|i| i.to_string()).collect();
        let a = attack(
            &d,
            AttackMode::ClusterBomb,
            vec![query("user"), query("pass")],
            vec![&big, &big],
        );
        assert_eq!(a.placements(), 1_000_000, "the full product");
        assert_eq!(
            a.expand(50).len(),
            50,
            "but only a ceiling's worth is built"
        );
    }

    #[test]
    fn a_cluster_bomb_product_that_overflows_usize_saturates_rather_than_panicking() {
        let d = draft();
        let big: Vec<String> = (0..100).map(|i| i.to_string()).collect();
        // Ten lists of a hundred is 100^10, far past usize.
        let lists: Vec<&[String]> = (0..10).map(|_| big.as_slice()).collect();
        let positions: Vec<ObjectLocation> = (0..10).map(|i| query(&format!("p{i}"))).collect();
        let a = attack(&d, AttackMode::ClusterBomb, positions, lists);
        assert_eq!(a.placements(), usize::MAX, "saturating, not wrapping");
    }
}

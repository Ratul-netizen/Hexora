//! What an engagement looked like at a moment, and what changed since.
//!
//! An engagement is not one sitting. A consultant tests in March, the client fixes
//! through April, the consultant comes back in May — and the only question anybody
//! asks on the second visit is *what changed*. Answering it requires something the
//! project does not otherwise keep: a record of what was true **then**, that a later
//! run cannot rewrite.
//!
//! # Why a snapshot copies rather than references
//!
//! The findings store deliberately mutates in place: re-running a test refreshes the
//! claim it already recorded rather than piling up near-duplicates, and confidence
//! moves with the evidence currently attached. That is right for a live list and
//! fatal for a historical one — a snapshot that merely pointed at finding rows would
//! change its own past every time somebody re-ran a test.
//!
//! So a [`Snapshot`] holds copies: the claims as they stood, their severity,
//! confidence and triage state, the scope, the identities, the declared objects. It
//! does **not** copy traffic. Bodies are the largest thing in a project by orders of
//! magnitude, and a snapshot exists to be diffed, not to be a backup.
//!
//! # What a snapshot deliberately never contains
//!
//! Credentials. An identity is recorded as its label and privilege level, because the
//! question a comparison answers is "were the same principals tested?" and no part of
//! that needs the secret. A snapshot is the most copied, most exported and most
//! long-lived artefact in a project; putting session material in one would be the
//! worst possible place to put it.
//!
//! # The vocabulary of a comparison
//!
//! [`compare`] never says *fixed*. It cannot: the absence of a finding from a later
//! snapshot means one test did not produce one claim, which is a fact about a test
//! run, not about an application. What it can say honestly is *why* a claim is
//! missing, and [`WhyGone`] is that vocabulary — with exactly one variant that is
//! evidence about the application at all, and even that one called
//! [`NotReproduced`](WhyGone::NotReproduced) rather than anything stronger. See
//! security invariant 11.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::finding::{Confidence, FindingSource, FindingStatus, Location, Severity};
use crate::identity::PrivilegeLevel;
use crate::ids::{IdentityId, SnapshotId, TargetId};
use crate::object::ObjectLocation;
use crate::scope::{Scope, ScopeRule};

/// An engagement, as it stood at one moment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Stable identifier.
    pub id: SnapshotId,
    /// What the tester called it — "before the fix", "day 3", "retest".
    pub label: String,
    /// Anything worth saying about the moment that the label could not hold.
    pub note: Option<String>,
    /// When it was taken.
    pub taken_at: DateTime<Utc>,
    /// The Hexora build that took it.
    ///
    /// Recorded because a claim that stopped appearing after an upgrade and a claim
    /// that stopped appearing after a fix are not the same event, and a comparison
    /// that cannot tell them apart is worse than none.
    pub tool_version: String,
    /// The project schema revision at the time.
    pub schema_version: u32,
    /// What was in the project.
    pub contents: Contents,
}

impl Snapshot {
    /// A snapshot of the project as it stands, for comparing against a stored one.
    ///
    /// The id is minted and never written anywhere: this is the *right-hand side* of
    /// "what has changed since the last snapshot?", which is the comparison a tester
    /// asks for most and the one that must not require saving anything first.
    pub fn of_current(contents: Contents, tool_version: impl Into<String>, schema: u32) -> Self {
        Self {
            id: SnapshotId::new(),
            label: "the project as it stands".into(),
            note: None,
            taken_at: Utc::now(),
            tool_version: tool_version.into(),
            schema_version: schema,
            contents,
        }
    }

    /// How this side of a comparison is named in its result.
    pub fn marker(&self) -> Marker {
        Marker {
            id: self.id,
            label: self.label.clone(),
            taken_at: self.taken_at,
            tool_version: self.tool_version.clone(),
        }
    }
}

/// Everything a snapshot records about a project.
///
/// Stored as one JSON document, so it is versioned by nothing but its own shape.
/// `#[serde(default)]` is what keeps a snapshot taken by an older build readable when
/// a later one adds a field: the project schema's migrations move forward and never
/// rewrite history, which means this document must be able to be read as it was
/// written. A field added here must have a default whose meaning is *the cautious
/// answer*, because that is what an old snapshot will silently supply.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Contents {
    /// The scope every automated subsystem was held to.
    pub scope: Scope,
    /// The principals the project tests as — labels and privilege, never credentials.
    pub identities: Vec<IdentityRecord>,
    /// The object identifiers a tester had declared, and who they said owned them.
    pub objects: Vec<ObjectRecord>,
    /// The claims the project held.
    pub findings: Vec<FindingRecord>,
    /// How many exchanges had been captured.
    ///
    /// A count, not the traffic: a snapshot is diffed, not restored.
    pub exchanges: u64,
    /// How many identifier suggestions existed, and how many had been reviewed.
    pub candidates: u64,
    /// Of those, how many a human had accepted or rejected.
    pub candidates_reviewed: u64,
}

/// A principal the project tested as.
///
/// There is no credential field, and nothing that reads a snapshot can ask for one.
/// See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecord {
    /// Stable identifier, so a renamed identity is still recognisably the same one.
    pub id: IdentityId,
    /// Display name at the time.
    pub label: String,
    /// How much authority it was expected to have.
    pub privilege: PrivilegeLevel,
}

/// An object identifier a tester had declared, and who they said owned it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRecord {
    /// What the tester called it.
    pub name: String,
    /// The identifier itself, exactly as declared.
    pub value: String,
    /// The owning identity's label at the time.
    pub owner: String,
    /// Where in a request it sits.
    pub location: ObjectLocation,
}

impl ObjectRecord {
    /// What makes two declarations the same declaration.
    pub fn key(&self) -> String {
        format!("{}|{}", self.value, self.location.key())
    }
}

/// What a finding claimed, at the granularity that makes it the *same* finding.
///
/// The same three fields the findings store uses to decide that a re-run is an update
/// rather than a new row. Using a different key here would let a claim be "the same"
/// to one half of the system and "different" to the other, which is exactly how a
/// regression report starts lying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// The target the claim is about.
    pub target: TargetId,
    /// The claim itself.
    pub title: String,
    /// Where in the message, when the claim is that specific.
    pub location: Option<Location>,
}

impl Claim {
    /// A stable string for joining two snapshots' findings.
    pub fn key(&self) -> String {
        match &self.location {
            Some(location) => format!(
                "{}|{}|{:?}:{}",
                self.target, self.title, location.part, location.name
            ),
            None => format!("{}|{}|", self.target, self.title),
        }
    }
}

/// A claim, as it stood in one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRecord {
    /// What was claimed.
    pub claim: Claim,
    /// How it stood.
    pub state: FindingState,
    /// What raised it.
    pub source: FindingSource,
    /// When the project first recorded this claim.
    pub first_recorded: DateTime<Utc>,
    /// When a run last wrote to it, if the snapshot recorded that.
    ///
    /// The field that separates "still true" from "nobody has looked". A test that
    /// produces no claim does not touch the claim it did not produce, so a finding can
    /// sit unchanged across a retest simply because nothing re-examined it — which
    /// reads identically to a finding that was re-examined and stood up. This
    /// timestamp is what tells them apart.
    ///
    /// `None` in a snapshot taken before the field existed. Unknown is treated as *not
    /// re-tested*, which tells the reader to go and re-run the test — the answer that
    /// is wasteful when wrong rather than misleading when wrong.
    #[serde(default)]
    pub last_updated: Option<DateTime<Utc>>,
}

/// The mutable part of a finding — the part a comparison watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingState {
    /// Impact severity.
    pub severity: Severity,
    /// How firmly it was established.
    pub confidence: Confidence,
    /// Triage state.
    pub status: FindingStatus,
    /// How many pieces of evidence were attached.
    ///
    /// A claim whose evidence count fell is one a later run established less firmly,
    /// which is worth seeing even when severity and confidence did not move.
    pub evidence: u32,
}

/// The identity of what produced a claim, at the granularity a comparison needs.
///
/// Not a display name: two passive checks are different sources even though both
/// would render as "passive scan", and the question
/// [`WhyGone::SourceSilent`] asks is about the specific check.
pub fn source_key(source: &FindingSource) -> String {
    match source {
        FindingSource::PassiveScan { detector } => format!("passive:{detector}"),
        FindingSource::ActiveScan { detector } => format!("active:{detector}"),
        FindingSource::AuthorizationTest => "authorization".into(),
        FindingSource::Extension { extension } => format!("extension:{extension}"),
        FindingSource::Ai { model } => format!("ai:{model}"),
        FindingSource::Manual => "manual".into(),
    }
}

// ---------------------------------------------------------------------------
// Comparing two snapshots
// ---------------------------------------------------------------------------

/// One side of a comparison, named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    /// The snapshot's id.
    pub id: SnapshotId,
    /// What it was called.
    pub label: String,
    /// When it was taken.
    pub taken_at: DateTime<Utc>,
    /// The build that took it.
    pub tool_version: String,
}

/// What changed between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comparison {
    /// The earlier side.
    pub from: Marker,
    /// The later side.
    pub to: Marker,
    /// Whether the two sides were produced by the same build.
    ///
    /// When they were not, every disappearance is inconclusive — see [`WhyGone`].
    pub same_tool: bool,
    /// Every claim either side held, and what became of it.
    pub findings: Vec<ClaimChange>,
    /// Scope rules added and removed.
    pub scope: ScopeChange,
    /// Identities added and removed, by label.
    pub identities: SetChange,
    /// Declared objects added and removed, by value.
    pub objects: SetChange,
    /// How the volumes moved.
    pub counts: CountChange,
}

impl Comparison {
    /// The claims in one state.
    pub fn matching(&self, want: fn(&Change) -> bool) -> Vec<&ClaimChange> {
        self.findings.iter().filter(|c| want(&c.change)).collect()
    }

    /// Whether anything at all differs.
    ///
    /// Used to say "nothing changed" once rather than printing four empty sections.
    pub fn is_empty(&self) -> bool {
        self.findings
            .iter()
            .all(|c| matches!(c.change, Change::Unchanged { .. }))
            && self.scope.is_empty()
            && self.identities.is_empty()
            && self.objects.is_empty()
            && !self.counts.moved()
    }
}

/// One claim, and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimChange {
    /// What was claimed.
    pub claim: Claim,
    /// What raised it, on whichever side had it.
    pub source: FindingSource,
    /// What became of it.
    pub change: Change,
}

/// What became of a claim between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    /// The later snapshot holds a claim the earlier one did not.
    ///
    /// A named field rather than a newtype: an internally tagged newtype variant
    /// flattens its contents into the tag object, so this one alone would have put
    /// `severity` beside `kind` while every other variant nested it. A wire shape
    /// where one case is shaped differently is one every reader gets wrong once.
    Appeared {
        /// How it stands.
        state: FindingState,
    },
    /// Both snapshots hold it, identically.
    Unchanged {
        /// How it stands.
        state: FindingState,
        /// Whether a run wrote to it between the two snapshots.
        ///
        /// False means the claim is standing on evidence gathered before the earlier
        /// snapshot: nothing has re-tested it, and a retest report that presented it
        /// as a current result would be presenting old news as new.
        restated: bool,
    },
    /// Both hold it, but something about it moved.
    Changed {
        /// How it stood in the earlier snapshot.
        before: FindingState,
        /// How it stands in the later one.
        after: FindingState,
    },
    /// The earlier snapshot holds a claim the later one does not.
    ///
    /// Note what this variant is *not* called. See [`WhyGone`].
    Gone {
        /// How it stood when it was last seen.
        before: FindingState,
        /// What can honestly be said about why it is missing.
        because: WhyGone,
    },
}

impl Change {
    /// A one-word label for a table.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Appeared { .. } => "new",
            Self::Unchanged { .. } => "unchanged",
            Self::Changed { .. } => "changed",
            Self::Gone { .. } => "gone",
        }
    }

    /// Whether this is something a reader needs to look at.
    pub fn is_movement(&self) -> bool {
        !matches!(self, Self::Unchanged { .. })
    }

    /// Whether a run wrote to this claim between the two snapshots.
    ///
    /// A claim nobody re-tested is not a claim that survived a retest.
    pub fn was_restated(&self) -> bool {
        match self {
            Self::Appeared { .. } | Self::Changed { .. } => true,
            Self::Unchanged { restated, .. } => *restated,
            Self::Gone { .. } => false,
        }
    }
}

/// Why a claim present in the earlier snapshot is absent from the later one.
///
/// **None of these means "fixed".** A finding is produced by a test; its absence is
/// the absence of a result, and only a test that ran and actively established the
/// negative could say anything stronger. Hexora does not have that yet — the
/// verification framework is M13.1 — so this enum says exactly how much is known,
/// which is sometimes nothing at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WhyGone {
    /// The same build ran, the same source produced other claims, and this one did
    /// not come back.
    ///
    /// The strongest thing this comparison can say, and still only "not reproduced".
    /// The test may not have covered the same request; the application may fail
    /// differently rather than correctly.
    NotReproduced,
    /// Nothing raised by that source appears in the later snapshot.
    ///
    /// Hexora has no registry of which checks ran — that arrives with M13.1 — so
    /// "the check ran and found nothing" and "the check never ran" are the same
    /// picture from here. This says so instead of guessing.
    SourceSilent,
    /// The two snapshots were taken by different builds.
    ///
    /// A disappearance could be the application or the tool, and nothing in the
    /// project distinguishes them. Reported ahead of the other two because it makes
    /// them unsafe to rely on.
    ToolChanged {
        /// The build that took the earlier snapshot.
        from: String,
        /// The build that took the later one.
        to: String,
    },
}

impl WhyGone {
    /// Whether the disappearance says anything about the application at all.
    ///
    /// False for both inconclusive variants. There is deliberately no `is_fixed`.
    pub fn is_about_the_application(&self) -> bool {
        matches!(self, Self::NotReproduced)
    }

    /// A short phrase for a table.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotReproduced => "not reproduced",
            Self::SourceSilent => "source silent",
            Self::ToolChanged { .. } => "tool changed",
        }
    }
}

/// Scope rules added and removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeChange {
    /// Rules the later snapshot has and the earlier one did not.
    pub added: Vec<ScopeLine>,
    /// Rules the earlier snapshot had and the later one does not.
    ///
    /// Worth as much attention as an added rule: a claim that stopped appearing
    /// because its host left scope has not been fixed, it has stopped being tested.
    pub removed: Vec<ScopeLine>,
}

impl ScopeChange {
    /// Whether the scope is the same on both sides.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// One scope rule, and which list it was in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeLine {
    /// The rule.
    pub rule: ScopeRule,
    /// Whether it included or excluded.
    pub excluded: bool,
}

impl std::fmt::Display for ScopeLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.excluded {
            write!(f, "exclude {}", self.rule)
        } else {
            write!(f, "include {}", self.rule)
        }
    }
}

/// Labels added and removed from a set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetChange {
    /// Present in the later snapshot only.
    pub added: Vec<String>,
    /// Present in the earlier snapshot only.
    pub removed: Vec<String>,
}

impl SetChange {
    /// Whether the two sides hold the same set.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// How the project's volumes moved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountChange {
    /// Captured exchanges, before and after.
    pub exchanges: Count,
    /// Identifier suggestions, before and after.
    pub candidates: Count,
    /// Findings held, before and after.
    pub findings: Count,
}

impl CountChange {
    /// Whether any of them moved.
    pub fn moved(&self) -> bool {
        self.exchanges.moved() || self.candidates.moved() || self.findings.moved()
    }
}

/// One number, on both sides.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Count {
    /// In the earlier snapshot.
    pub before: u64,
    /// In the later one.
    pub after: u64,
}

impl Count {
    /// Whether it moved.
    pub fn moved(&self) -> bool {
        self.before != self.after
    }

    /// The signed difference.
    pub fn delta(&self) -> i64 {
        self.after as i64 - self.before as i64
    }
}

/// What changed between two snapshots.
///
/// Pure: two records in, one answer out. Nothing here reads a project, so a
/// comparison can be re-run over exported snapshots years later and produce the same
/// result — which is the point of copying the contents in the first place.
pub fn compare(from: &Snapshot, to: &Snapshot) -> Comparison {
    let same_tool = from.tool_version == to.tool_version;

    let before: BTreeMap<String, &FindingRecord> = from
        .contents
        .findings
        .iter()
        .map(|record| (record.claim.key(), record))
        .collect();
    let after: BTreeMap<String, &FindingRecord> = to
        .contents
        .findings
        .iter()
        .map(|record| (record.claim.key(), record))
        .collect();

    // Which sources produced anything at all on the later side. A source that raised
    // nothing is not a source that found nothing — see `WhyGone::SourceSilent`.
    let sources_after: BTreeSet<String> = to
        .contents
        .findings
        .iter()
        .map(|record| source_key(&record.source))
        .collect();

    let mut findings = Vec::new();

    for (key, old) in &before {
        match after.get(key) {
            Some(new) => {
                let change = if old.state == new.state {
                    Change::Unchanged {
                        state: new.state,
                        // Both sides must know, or the answer is "nobody re-tested it".
                        restated: match (old.last_updated, new.last_updated) {
                            (Some(before), Some(after)) => after > before,
                            _ => false,
                        },
                    }
                } else {
                    Change::Changed {
                        before: old.state,
                        after: new.state,
                    }
                };
                findings.push(ClaimChange {
                    claim: new.claim.clone(),
                    source: new.source.clone(),
                    change,
                });
            }
            None => {
                // Ordered from least to most that can be claimed: a build change
                // makes the other two unsafe to rely on, so it wins.
                let because = if !same_tool {
                    WhyGone::ToolChanged {
                        from: from.tool_version.clone(),
                        to: to.tool_version.clone(),
                    }
                } else if !sources_after.contains(&source_key(&old.source)) {
                    WhyGone::SourceSilent
                } else {
                    WhyGone::NotReproduced
                };
                findings.push(ClaimChange {
                    claim: old.claim.clone(),
                    source: old.source.clone(),
                    change: Change::Gone {
                        before: old.state,
                        because,
                    },
                });
            }
        }
    }

    for (key, new) in &after {
        if !before.contains_key(key) {
            findings.push(ClaimChange {
                claim: new.claim.clone(),
                source: new.source.clone(),
                change: Change::Appeared { state: new.state },
            });
        }
    }

    // Movement first, then by severity: the list is read top-down by somebody asking
    // "what do I need to look at?", and an unchanged claim is never the answer.
    findings.sort_by(|a, b| {
        rank(&a.change)
            .cmp(&rank(&b.change))
            .then_with(|| severity_of(&b.change).cmp(&severity_of(&a.change)))
            .then_with(|| a.claim.title.cmp(&b.claim.title))
    });

    Comparison {
        from: from.marker(),
        to: to.marker(),
        same_tool,
        findings,
        scope: scope_change(&from.contents.scope, &to.contents.scope),
        identities: set_change(
            from.contents.identities.iter().map(|i| i.label.clone()),
            to.contents.identities.iter().map(|i| i.label.clone()),
        ),
        objects: set_change(
            from.contents.objects.iter().map(|o| o.key()),
            to.contents.objects.iter().map(|o| o.key()),
        ),
        counts: CountChange {
            exchanges: Count {
                before: from.contents.exchanges,
                after: to.contents.exchanges,
            },
            candidates: Count {
                before: from.contents.candidates,
                after: to.contents.candidates,
            },
            findings: Count {
                before: from.contents.findings.len() as u64,
                after: to.contents.findings.len() as u64,
            },
        },
    }
}

fn rank(change: &Change) -> u8 {
    match change {
        Change::Appeared { .. } => 0,
        Change::Gone { .. } => 1,
        Change::Changed { .. } => 2,
        // A claim nobody re-tested sorts above one that was re-tested and stood: the
        // first is a gap in the retest, the second is a result.
        Change::Unchanged {
            restated: false, ..
        } => 3,
        Change::Unchanged { restated: true, .. } => 4,
    }
}

fn severity_of(change: &Change) -> Severity {
    match change {
        Change::Appeared { state } => state.severity,
        Change::Unchanged { state, .. } => state.severity,
        Change::Changed { after, .. } => after.severity,
        Change::Gone { before, .. } => before.severity,
    }
}

fn scope_change(from: &Scope, to: &Scope) -> ScopeChange {
    let lines = |scope: &Scope| -> Vec<ScopeLine> {
        scope
            .include
            .iter()
            .map(|rule| ScopeLine {
                rule: rule.clone(),
                excluded: false,
            })
            .chain(scope.exclude.iter().map(|rule| ScopeLine {
                rule: rule.clone(),
                excluded: true,
            }))
            .collect()
    };
    let (before, after) = (lines(from), lines(to));
    ScopeChange {
        added: after
            .iter()
            .filter(|l| !before.contains(l))
            .cloned()
            .collect(),
        removed: before
            .iter()
            .filter(|l| !after.contains(l))
            .cloned()
            .collect(),
    }
}

fn set_change(from: impl Iterator<Item = String>, to: impl Iterator<Item = String>) -> SetChange {
    let before: BTreeSet<String> = from.collect();
    let after: BTreeSet<String> = to.collect();
    SetChange {
        added: after.difference(&before).cloned().collect(),
        removed: before.difference(&after).cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::MessagePart;

    fn state(severity: Severity, confidence: Confidence) -> FindingState {
        FindingState {
            severity,
            confidence,
            status: FindingStatus::New,
            evidence: 2,
        }
    }

    fn record(title: &str, state: FindingState, source: FindingSource) -> FindingRecord {
        let now = Utc::now();
        FindingRecord {
            claim: Claim {
                target: TargetId::from_uuid(uuid::Uuid::from_u128(0x1111)),
                title: title.into(),
                location: None,
            },
            state,
            source,
            first_recorded: now,
            last_updated: Some(now),
        }
    }

    fn snapshot(label: &str, version: &str, findings: Vec<FindingRecord>) -> Snapshot {
        Snapshot {
            id: SnapshotId::new(),
            label: label.into(),
            note: None,
            taken_at: Utc::now(),
            tool_version: version.into(),
            schema_version: 6,
            contents: Contents {
                findings,
                ..Contents::default()
            },
        }
    }

    #[test]
    fn a_claim_present_in_both_is_unchanged() {
        let one = state(Severity::High, Confidence::Confirmed);
        let from = snapshot(
            "before",
            "0.1.0",
            vec![record(
                "IDOR in /accounts",
                one,
                FindingSource::AuthorizationTest,
            )],
        );
        let to = snapshot(
            "after",
            "0.1.0",
            vec![record(
                "IDOR in /accounts",
                one,
                FindingSource::AuthorizationTest,
            )],
        );

        let comparison = compare(&from, &to);
        assert!(matches!(
            comparison.findings[0].change,
            Change::Unchanged { .. }
        ));
        assert!(comparison.is_empty(), "nothing moved");
    }

    #[test]
    fn a_claim_the_later_side_does_not_hold_is_gone_and_never_fixed() {
        let from = snapshot(
            "before",
            "0.1.0",
            vec![record(
                "IDOR in /accounts",
                state(Severity::High, Confidence::Confirmed),
                FindingSource::AuthorizationTest,
            )],
        );
        // The same source still produced something, so the test demonstrably ran.
        let to = snapshot(
            "after",
            "0.1.0",
            vec![record(
                "IDOR in /invoices",
                state(Severity::Medium, Confidence::Firm),
                FindingSource::AuthorizationTest,
            )],
        );

        let comparison = compare(&from, &to);
        let gone = comparison
            .findings
            .iter()
            .find(|c| c.claim.title == "IDOR in /accounts")
            .unwrap();

        match &gone.change {
            Change::Gone { because, .. } => {
                assert_eq!(*because, WhyGone::NotReproduced);
                // The strongest verdict available, and it still is not "fixed".
                assert!(because.is_about_the_application());
                assert_eq!(because.as_str(), "not reproduced");
            }
            other => panic!("expected Gone, got {other:?}"),
        }
    }

    #[test]
    fn a_disappearance_says_nothing_when_the_source_raised_nothing_at_all() {
        let from = snapshot(
            "before",
            "0.1.0",
            vec![record(
                "Missing HSTS",
                state(Severity::Low, Confidence::Reported),
                FindingSource::PassiveScan {
                    detector: "passive.missing_hsts".into(),
                },
            )],
        );
        let to = snapshot("after", "0.1.0", vec![]);

        let comparison = compare(&from, &to);
        match &comparison.findings[0].change {
            Change::Gone { because, .. } => {
                assert_eq!(*because, WhyGone::SourceSilent);
                assert!(
                    !because.is_about_the_application(),
                    "a check that may never have run says nothing about the application"
                );
            }
            other => panic!("expected Gone, got {other:?}"),
        }
    }

    #[test]
    fn two_passive_checks_are_two_different_sources() {
        // Both render as "passive scan", and treating them as one source would let a
        // silent check borrow another check's proof that *something* ran.
        let from = snapshot(
            "before",
            "0.1.0",
            vec![record(
                "Missing HSTS",
                state(Severity::Low, Confidence::Reported),
                FindingSource::PassiveScan {
                    detector: "passive.missing_hsts".into(),
                },
            )],
        );
        let to = snapshot(
            "after",
            "0.1.0",
            vec![record(
                "Cookie without Secure",
                state(Severity::Low, Confidence::Reported),
                FindingSource::PassiveScan {
                    detector: "passive.insecure_cookie".into(),
                },
            )],
        );

        let comparison = compare(&from, &to);
        let gone = comparison
            .findings
            .iter()
            .find(|c| c.claim.title == "Missing HSTS")
            .unwrap();
        assert!(matches!(
            gone.change,
            Change::Gone {
                because: WhyGone::SourceSilent,
                ..
            }
        ));
    }

    #[test]
    fn a_different_build_makes_every_disappearance_inconclusive() {
        let from = snapshot(
            "march",
            "0.1.0",
            vec![record(
                "IDOR in /accounts",
                state(Severity::High, Confidence::Confirmed),
                FindingSource::AuthorizationTest,
            )],
        );
        let to = snapshot(
            "may",
            "0.2.0",
            vec![record(
                "IDOR in /invoices",
                state(Severity::Medium, Confidence::Firm),
                FindingSource::AuthorizationTest,
            )],
        );

        let comparison = compare(&from, &to);
        assert!(!comparison.same_tool);
        let gone = comparison
            .findings
            .iter()
            .find(|c| c.claim.title == "IDOR in /accounts")
            .unwrap();

        match &gone.change {
            // The same source *did* produce a claim, so without the version check
            // this would have read as "not reproduced" — a fix report resting on a
            // detector change nobody was told about.
            Change::Gone {
                because: WhyGone::ToolChanged { from, to },
                ..
            } => {
                assert_eq!(from, "0.1.0");
                assert_eq!(to, "0.2.0");
            }
            other => panic!("expected ToolChanged, got {other:?}"),
        }
    }

    #[test]
    fn a_claim_whose_severity_moved_is_changed_and_carries_both_sides() {
        let from = snapshot(
            "before",
            "0.1.0",
            vec![record(
                "IDOR in /accounts",
                state(Severity::High, Confidence::Confirmed),
                FindingSource::AuthorizationTest,
            )],
        );
        let to = snapshot(
            "after",
            "0.1.0",
            vec![record(
                "IDOR in /accounts",
                state(Severity::Medium, Confidence::Tentative),
                FindingSource::AuthorizationTest,
            )],
        );

        match &compare(&from, &to).findings[0].change {
            Change::Changed { before, after } => {
                assert_eq!(before.severity, Severity::High);
                assert_eq!(after.confidence, Confidence::Tentative);
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn the_same_title_at_a_different_location_is_a_different_claim() {
        // The findings store keys on target, title *and* location; a comparison that
        // keyed on less would report a moved parameter as "unchanged".
        let mut first = record(
            "Reflected input",
            state(Severity::Medium, Confidence::Firm),
            FindingSource::Manual,
        );
        first.claim.location = Some(Location {
            part: MessagePart::Query,
            name: "q".into(),
        });
        let mut second = first.clone();
        second.claim.location = Some(Location {
            part: MessagePart::Query,
            name: "search".into(),
        });

        let comparison = compare(
            &snapshot("before", "0.1.0", vec![first]),
            &snapshot("after", "0.1.0", vec![second]),
        );
        assert_eq!(comparison.findings.len(), 2);
        assert!(comparison
            .findings
            .iter()
            .any(|c| matches!(c.change, Change::Appeared { .. })));
        assert!(comparison
            .findings
            .iter()
            .any(|c| matches!(c.change, Change::Gone { .. })));
    }

    #[test]
    fn what_needs_looking_at_is_listed_before_what_does_not() {
        let unchanged = record(
            "Old news",
            state(Severity::Low, Confidence::Reported),
            FindingSource::Manual,
        );
        let mut appeared = unchanged.clone();
        appeared.claim.title = "Brand new".into();
        appeared.state.severity = Severity::Critical;

        let comparison = compare(
            &snapshot("before", "0.1.0", vec![unchanged.clone()]),
            &snapshot("after", "0.1.0", vec![unchanged, appeared]),
        );
        assert_eq!(comparison.findings[0].claim.title, "Brand new");
        assert!(!comparison.is_empty());
    }

    #[test]
    fn scope_and_identity_movement_is_reported_in_both_directions() {
        let mut from = snapshot("before", "0.1.0", vec![]);
        from.contents.scope = Scope::new().include(ScopeRule::host("api.example.com"));
        from.contents.identities = vec![IdentityRecord {
            id: IdentityId::from_uuid(uuid::Uuid::from_u128(1)),
            label: "User A".into(),
            privilege: PrivilegeLevel::User,
        }];

        let mut to = snapshot("after", "0.1.0", vec![]);
        to.contents.scope = Scope::new().include(ScopeRule::host("staging.example.com"));
        to.contents.identities = vec![IdentityRecord {
            id: IdentityId::from_uuid(uuid::Uuid::from_u128(2)),
            label: "Admin".into(),
            privilege: PrivilegeLevel::Administrator,
        }];

        let comparison = compare(&from, &to);
        assert_eq!(comparison.scope.added.len(), 1);
        // A host that left scope is as important as one that joined: claims about it
        // stopped being tested, which is not the same as being fixed.
        assert_eq!(comparison.scope.removed.len(), 1);
        assert_eq!(comparison.identities.added, vec!["Admin".to_string()]);
        assert_eq!(comparison.identities.removed, vec!["User A".to_string()]);
    }

    #[test]
    fn a_snapshot_serializes_without_anything_resembling_a_credential() {
        let mut snapshot = snapshot("before", "0.1.0", vec![]);
        snapshot.contents.identities = vec![IdentityRecord {
            id: IdentityId::from_uuid(uuid::Uuid::from_u128(1)),
            label: "User A".into(),
            privilege: PrivilegeLevel::User,
        }];

        let json = serde_json::to_string(&snapshot).unwrap();
        for forbidden in ["credential", "token", "cookie", "password", "secret"] {
            assert!(
                !json.contains(forbidden),
                "{forbidden:?} reached a snapshot: {json}"
            );
        }
    }

    #[test]
    fn a_claim_nobody_re_tested_is_not_a_claim_that_survived_a_retest() {
        // The gap this field exists to close, found by running an actual retest: the
        // application was fixed, the matrix re-ran, it reported nothing — and because
        // a run that produces no claim never touches the claim it did not produce, the
        // old finding sat there looking exactly like a current result.
        let one = state(Severity::High, Confidence::Confirmed);
        let mut old = record("IDOR in /accounts", one, FindingSource::AuthorizationTest);
        old.last_updated = Some(old.first_recorded);

        let mut untouched = old.clone();
        let mut retested = old.clone();
        retested.last_updated = Some(old.first_recorded + chrono::Duration::hours(1));

        let from = snapshot("before", "0.1.0", vec![old]);

        let stale = compare(&from, &snapshot("after", "0.1.0", vec![untouched.clone()]));
        assert!(matches!(
            stale.findings[0].change,
            Change::Unchanged {
                restated: false,
                ..
            }
        ));
        assert!(!stale.findings[0].change.was_restated());

        let fresh = compare(&from, &snapshot("after", "0.1.0", vec![retested]));
        assert!(fresh.findings[0].change.was_restated());

        // Neither is "movement": the project holds the same claim either way. The
        // difference is whether anybody checked, which is a different question.
        untouched.state.severity = Severity::High;
        assert!(!stale.findings[0].change.is_movement());
        assert!(!fresh.findings[0].change.is_movement());
    }

    #[test]
    fn a_snapshot_written_before_a_field_existed_still_loads() {
        // Snapshots are stored as JSON inside a schema that only moves forward. A
        // document that could not be read as it was written would make last year's
        // project unopenable, which is the one thing this storage layer must not do.
        let json = r#"{
            "scope": {"include": [], "exclude": []},
            "identities": [],
            "objects": [],
            "findings": [{
                "claim": {"target": "00000000-0000-0000-0000-000000001111",
                          "title": "IDOR", "location": null},
                "state": {"severity": "high", "confidence": "confirmed",
                          "status": "new", "evidence": 1},
                "source": {"kind": "authorization_test"},
                "first_recorded": "2026-01-01T00:00:00Z"
            }]
        }"#;

        let contents: Contents = serde_json::from_str(json).unwrap();
        assert_eq!(contents.findings.len(), 1);
        assert_eq!(contents.findings[0].last_updated, None);
        // And an unknown timestamp reads as "nobody re-tested it" rather than as a
        // result, in both directions.
        let old = snapshot("before", "0.1.0", contents.findings.clone());
        let new = snapshot("after", "0.1.0", contents.findings);
        assert!(!compare(&old, &new).findings[0].change.was_restated());
    }

    #[test]
    fn counts_move_in_both_directions() {
        let mut from = snapshot("before", "0.1.0", vec![]);
        from.contents.exchanges = 900;
        let mut to = snapshot("after", "0.1.0", vec![]);
        to.contents.exchanges = 1200;

        let comparison = compare(&from, &to);
        assert_eq!(comparison.counts.exchanges.delta(), 300);
        assert!(comparison.counts.moved());
    }
}

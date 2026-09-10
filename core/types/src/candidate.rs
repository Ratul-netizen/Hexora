//! Values in captured traffic that *might* be object identifiers.
//!
//! [`ObjectDeclaration`](crate::object::ObjectDeclaration) is a tester's assertion:
//! *this string is an invoice belonging to User A.* Producing one by hand for every
//! identifier in an application is slow, and slowness is why constructed testing ends
//! up narrower than it should be.
//!
//! An [`IdentifierCandidate`] is the other end of that: something Hexora noticed,
//! offered, and will not act on. Three things are kept strictly apart, and the gap
//! between them is the whole design:
//!
//! ```text
//! IdentifierCandidate   "1000 varies where an object id would, in 17 requests"
//!         │  a human decides
//!         ▼
//! ObjectDeclaration     "1000 is an account"
//!         │  a human decides
//!         ▼
//! ownership             "…belonging to User A"
//! ```
//!
//! Hexora produces the first. It never produces the second or third, because it
//! cannot: `/api/users/1000` might be a user id, an account id, a tenant id, a page
//! number or a version, and nothing in the bytes says which. A tool that guessed and
//! then reasoned from the guess would put a fabricated premise underneath every
//! finding downstream.
//!
//! # Why a candidate has signals rather than a score
//!
//! A confidence of `0.87` cannot be argued with. A tester looking at a suggestion
//! needs to answer "why did it suggest this?" — and when the answer is wrong, they
//! need to see *which* signal was wrong. So a candidate carries the reasons and their
//! weights, and the number is derived from them rather than the other way round.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{CandidateId, RequestId};
use crate::object::ObjectLocation;

/// Where a candidate stands with the person reviewing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    /// Suggested by analysis, not yet reviewed.
    #[default]
    Proposed,
    /// A human agreed this is an object identifier.
    ///
    /// Accepting says nothing about *whose* it is. Ownership is a separate act, and
    /// keeping them separate is what stops a suggestion becoming an assertion.
    Accepted,
    /// A human said no. It stays in the project so the same value is not suggested
    /// again on the next analysis.
    Rejected,
    /// Replaced by a later analysis of the same value in the same place.
    Superseded,
}

impl CandidateStatus {
    /// The word stored in the database and shown in the interface.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }

    /// Parses the stored form.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "proposed" => Some(Self::Proposed),
            "accepted" => Some(Self::Accepted),
            "rejected" => Some(Self::Rejected),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }

    /// Whether a re-analysis may replace this candidate's signals.
    ///
    /// A reviewed decision is not overwritten by a later run, for the same reason a
    /// triaged finding is not: a list that undoes human decisions is a list people
    /// stop using.
    pub fn is_reviewed(&self) -> bool {
        matches!(self, Self::Accepted | Self::Rejected)
    }
}

/// One reason a value was suggested, and how much it counted for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// Which observation this is.
    pub kind: SignalKind,
    /// What it contributed. Negative for signals that argue *against*.
    pub weight: i32,
    /// The specific fact, e.g. "seen in 17 requests".
    pub detail: String,
}

/// The kinds of evidence that make a value look like an identifier.
///
/// Every one of these is a fact about observed traffic. None of them is a conclusion,
/// and the strongest of them — a value that a tester has already declared as an object
/// elsewhere — is still only a reason to *ask*.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// The value at this position differs between otherwise identical requests.
    ///
    /// The signal that carries most of the weight, and the reason this is not a
    /// "looks numeric" heuristic: `/api/accounts/{x}/invoices` has one position that
    /// varies and three that do not, and only the first is an identifier.
    VariesInPlace,
    /// The same value was seen in this place more than once.
    Repeated,
    /// The preceding path segment names a collection — `/accounts/1000`.
    ResourceLikePath,
    /// The value came back in a response body, so the application echoes or owns it.
    AppearsInResponse,
    /// A tester has already declared this exact value as an object somewhere.
    MatchesDeclaredObject,
    /// The parameter name is one that usually means paging, not identity.
    ///
    /// Negative. `?page=2` varies between requests and sits in a resource-like path,
    /// and is still not an object.
    CommonPaginationName,
    /// The value is short enough that it is probably an enum or a flag.
    VeryShort,
    /// The value reads like a word rather than an identifier.
    ///
    /// Negative, and never used the other way round: `acct-1000` is not suggested
    /// *because* it has digits in it. But a path segment that is a plain lowercase
    /// word is far more often an endpoint name than an object — `/profile` and
    /// `/status` vary between requests without either being an identifier — and a
    /// reviewer looking at the list will say so, so the list may as well say it first.
    ReadsLikeAWord,
}

impl SignalKind {
    /// A short label for tables and reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VariesInPlace => "varies in place",
            Self::Repeated => "repeated",
            Self::ResourceLikePath => "resource-like path",
            Self::AppearsInResponse => "appears in response",
            Self::MatchesDeclaredObject => "matches a declared object",
            Self::CommonPaginationName => "common paging parameter",
            Self::VeryShort => "very short value",
            Self::ReadsLikeAWord => "reads like a word",
        }
    }
}

/// How much the signals add up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    /// Worth a glance.
    Low,
    /// Worth reviewing.
    Medium,
    /// Very likely an identifier — which still says nothing about whose it is.
    High,
}

impl Strength {
    /// The band a total score falls in.
    ///
    /// Thresholds, like every threshold in this codebase, are a judgement call stated
    /// in one place rather than scattered through the code that uses them.
    pub fn of(score: i32) -> Self {
        match score {
            s if s >= 24 => Self::High,
            s if s >= 12 => Self::Medium,
            _ => Self::Low,
        }
    }

    /// A short label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// A value that might be an object identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentifierCandidate {
    /// Stable identifier.
    pub id: CandidateId,
    /// The value **exactly as observed**.
    ///
    /// Never decoded, never normalized. `%31%30%30%30` and `1000` are different
    /// candidates, because an application may well treat them differently and which
    /// one it accepts can be the finding.
    pub value: String,
    /// Where it sat.
    pub location: ObjectLocation,
    /// A readable description of that place, e.g. `JSON field accountId`.
    ///
    /// The location addresses the bytes; this explains them. A JSON field and a form
    /// field are both byte ranges in a body, and a tester should not have to work out
    /// which one they are looking at.
    pub descriptor: String,
    /// An exchange the value was seen in, kept so the suggestion can be traced back to
    /// traffic. `None` once that exchange is no longer in the project.
    pub source_request: Option<RequestId>,
    /// How many times it was observed in this place.
    pub occurrences: u32,
    /// How many exchanges are still in the project to show for it.
    ///
    /// Recorded separately from [`Self::occurrences`] so a candidate whose traffic has
    /// been pruned says so rather than quietly becoming a claim with nothing behind
    /// it.
    pub live_observations: u32,
    /// Why it was suggested.
    pub signals: Vec<Signal>,
    /// The sum of the signal weights.
    pub score: i32,
    /// Where the reviewer left it.
    pub status: CandidateStatus,
    /// When it was first suggested.
    pub created_at: DateTime<Utc>,
    /// When it was last updated by analysis or a review.
    pub updated_at: DateTime<Utc>,
}

impl IdentifierCandidate {
    /// Builds a candidate from its signals, deriving the score from them.
    pub fn new(
        value: impl Into<String>,
        location: ObjectLocation,
        descriptor: impl Into<String>,
        signals: Vec<Signal>,
    ) -> Self {
        let score = signals.iter().map(|signal| signal.weight).sum();
        let now = Utc::now();
        Self {
            id: CandidateId::new(),
            value: value.into(),
            location,
            descriptor: descriptor.into(),
            source_request: None,
            occurrences: 0,
            live_observations: 0,
            signals,
            score,
            status: CandidateStatus::Proposed,
            created_at: now,
            updated_at: now,
        }
    }

    /// How strong the case is.
    pub fn strength(&self) -> Strength {
        Strength::of(self.score)
    }

    /// A stable key for "the same suggestion".
    ///
    /// The same value in the same place is one candidate however many times analysis
    /// runs. Without this, re-analysing a project would multiply every suggestion by
    /// the number of times somebody pressed the button.
    pub fn key(&self) -> String {
        format!("{}|{}", self.value, self.location.key())
    }

    /// Whether some of the traffic behind this suggestion is gone.
    pub fn has_missing_traffic(&self) -> bool {
        self.live_observations < self.occurrences
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(kind: SignalKind, weight: i32) -> Signal {
        Signal {
            kind,
            weight,
            detail: kind.as_str().to_string(),
        }
    }

    #[test]
    fn the_score_is_the_sum_of_the_reasons() {
        let candidate = IdentifierCandidate::new(
            "1000",
            ObjectLocation::PathSegment { index: 2 },
            "path segment 2",
            vec![
                signal(SignalKind::VariesInPlace, 12),
                signal(SignalKind::ResourceLikePath, 8),
                signal(SignalKind::CommonPaginationName, -5),
            ],
        );
        assert_eq!(candidate.score, 15);
        assert_eq!(candidate.strength(), Strength::Medium);
    }

    #[test]
    fn a_negative_signal_can_talk_a_candidate_down() {
        // `?page=2` varies between requests and sits under a resource-like path. The
        // name is what says it is not an object.
        let candidate = IdentifierCandidate::new(
            "2",
            ObjectLocation::Query {
                name: "page".into(),
                occurrence: 0,
            },
            "query parameter page",
            vec![
                signal(SignalKind::VariesInPlace, 12),
                signal(SignalKind::CommonPaginationName, -14),
                signal(SignalKind::VeryShort, -4),
            ],
        );
        assert!(candidate.score < 12, "{}", candidate.score);
        assert_eq!(candidate.strength(), Strength::Low);
    }

    #[test]
    fn the_same_value_in_the_same_place_is_one_candidate() {
        let here = ObjectLocation::PathSegment { index: 2 };
        let a = IdentifierCandidate::new("1000", here.clone(), "path segment 2", Vec::new());
        let b = IdentifierCandidate::new("1000", here, "path segment 2", Vec::new());
        assert_eq!(a.key(), b.key());
    }

    #[test]
    fn an_encoded_value_is_a_different_candidate_from_its_decoded_form() {
        // The application may accept one and refuse the other, and which it accepts is
        // sometimes the finding. Nothing here decodes anything.
        let here = ObjectLocation::PathSegment { index: 2 };
        let raw = IdentifierCandidate::new("%31%30%30%30", here.clone(), "path segment 2", vec![]);
        let plain = IdentifierCandidate::new("1000", here, "path segment 2", vec![]);
        assert_ne!(raw.key(), plain.key());
        assert_ne!(raw.value, plain.value);
    }

    #[test]
    fn a_reviewed_decision_is_not_something_analysis_may_overwrite() {
        assert!(CandidateStatus::Accepted.is_reviewed());
        assert!(CandidateStatus::Rejected.is_reviewed());
        assert!(!CandidateStatus::Proposed.is_reviewed());
        assert!(!CandidateStatus::Superseded.is_reviewed());
    }

    #[test]
    fn statuses_round_trip_through_their_stored_word() {
        for status in [
            CandidateStatus::Proposed,
            CandidateStatus::Accepted,
            CandidateStatus::Rejected,
            CandidateStatus::Superseded,
        ] {
            assert_eq!(CandidateStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(CandidateStatus::parse("nonsense"), None);
    }

    #[test]
    fn a_candidate_whose_traffic_is_gone_says_so() {
        let mut candidate =
            IdentifierCandidate::new("1000", ObjectLocation::Anywhere, "somewhere", Vec::new());
        candidate.occurrences = 17;
        candidate.live_observations = 17;
        assert!(!candidate.has_missing_traffic());

        candidate.live_observations = 4;
        assert!(candidate.has_missing_traffic());
    }

    #[test]
    fn strength_bands_are_stated_in_one_place() {
        assert_eq!(Strength::of(30), Strength::High);
        assert_eq!(Strength::of(24), Strength::High);
        assert_eq!(Strength::of(23), Strength::Medium);
        assert_eq!(Strength::of(12), Strength::Medium);
        assert_eq!(Strength::of(11), Strength::Low);
        assert_eq!(Strength::of(-40), Strength::Low);
    }

    #[test]
    fn a_candidate_carries_no_owner_field_at_all() {
        // Enforced by the type rather than by review: there is nowhere to put one, so
        // ownership cannot leak into a suggestion by accident.
        let candidate =
            IdentifierCandidate::new("1000", ObjectLocation::Anywhere, "somewhere", Vec::new());
        let json = serde_json::to_value(&candidate).unwrap();
        assert!(json.get("owner").is_none());
        assert!(json.get("owner_id").is_none());
        assert!(json.get("identity").is_none());
    }
}

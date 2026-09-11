//! The terms an engagement is conducted under, beyond what it may touch.
//!
//! [`Scope`](crate::scope::Scope) answers *which systems*. A programme profile answers
//! the other question a bug bounty programme decides for you: **which kinds of finding
//! it will accept**. Those are not the same question, and conflating them loses both.
//!
//! # Why this exists
//!
//! Wolt's HackerOne programme declares these out of scope as finding classes:
//!
//! ```text
//! CORS misconfiguration without proven impact
//! Missing security headers
//! Missing cookie flags
//! Banner grabbing / version disclosure
//! Username / email enumeration
//! Bypassing or non-existence of rate-limits
//! ```
//!
//! That is most of what a passive scanner produces. A run that files forty of them is
//! a run whose output gets skipped, and skipped output is how a real finding gets
//! missed — the same failure as a scanner that cries wolf, arriving by a different
//! road.
//!
//! # What an exclusion does, and what it deliberately does not do
//!
//! An exclusion is about **reporting**, not about looking. What follows from that is
//! not obvious and is the whole design:
//!
//! * A **passive** detector that is excluded still runs. It costs the target nothing —
//!   the passive scanner has no transport — and its observations are still listed,
//!   marked with the programme's reason. What it does not do is produce a finding.
//! * A **hypothesis it raises still flows to the active scheduler.** This is the point.
//!   "CORS misconfiguration *without proven impact*" is out of scope; proven impact is
//!   in scope, and the active check is the thing that proves it. An exclusion that
//!   silenced the lead *and* the experiment would suppress the finding the programme
//!   actually wants.
//! * An **active** detector that is excluded is not scheduled at all. Sending somebody
//!   traffic to produce a finding they have said they will not accept is a cost with
//!   no possible return, and it is their bandwidth.
//!
//! So `cors.configuration` excluded and `cors.reflection` kept is a coherent profile,
//! and it is exactly the profile Wolt's wording describes.
//!
//! # What it is not
//!
//! Not a safety control. Scope is; this is not. An exclusion can only ever *reduce*
//! what gets reported or sent, so a wrong one cannot make Hexora touch something it
//! otherwise would not — which is why it is allowed to be edited casually and scope is
//! not.
//!
//! Not a silence, either. Every exclusion that applied is recorded on the run and
//! printed in the report, with its reason. A reader must be able to tell "nobody
//! looked" from "it was looked at and this programme does not take them", and a
//! reader who cannot is being misled about coverage — see `docs/security-invariants.md`,
//! invariant 15.

use serde::{Deserialize, Serialize};

/// A finding class this programme will not accept, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exclusion {
    /// The detector id, as `hexora detectors` lists it.
    pub detector: String,
    /// Why, in the programme's own words where possible.
    ///
    /// Required rather than optional. An exclusion without a reason is indistinguishable
    /// from a mistake six weeks later, and it is the sentence that goes into the report
    /// where a reader decides whether to trust the coverage.
    pub reason: String,
}

impl Exclusion {
    /// Builds an exclusion.
    pub fn new(detector: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            detector: detector.into(),
            reason: reason.into(),
        }
    }
}

/// An entity a programme says may be targeted, and nothing else.
///
/// Bug bounty programmes hand out test accounts and mean it:
///
/// ```text
/// If you need to test any sort of access to user data, please do it only against
/// this specific consumer test account, whose user_id is 670fa3e9ead6e49d65cc3614.
///
/// ⛔ Don't use or interact with accounts or data you don't own, including but not
/// limited to restaurants/venues and merchant data.
/// ```
///
/// The identifier analyzer, doing its job well, surfaces the ids of **real venues** out
/// of ordinary browsing — a working restaurant's id looks exactly like a test one. A
/// constructed attempt against that identifier is interacting with a business's data,
/// which is the line the programme drew, and a tester reading a list of forty
/// identifiers has no way to tell which is which.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestEntity {
    /// The identifier itself, as the programme wrote it.
    pub id: String,
    /// What it is, in the programme's words: "consumer test account".
    pub what: String,
}

impl TestEntity {
    /// Records a permitted entity.
    pub fn new(id: impl Into<String>, what: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            what: what.into(),
        }
    }
}

/// The terms an engagement is conducted under.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Programme {
    /// What it is called, for the report header.
    #[serde(default)]
    pub name: Option<String>,
    /// Where the terms are published.
    #[serde(default)]
    pub policy_url: Option<String>,
    /// Finding classes this programme will not accept.
    #[serde(default)]
    pub exclusions: Vec<Exclusion>,
    /// The only entities this programme permits being targeted.
    ///
    /// Empty means the programme has not restricted it, and nothing is refused — the
    /// correct reading of silence, and the same one [`Self::exclusions`] takes.
    ///
    /// Non-empty is a **closed list**. An identifier not on it is refused rather than
    /// warned about, because the failure is not recoverable: a request sent at a real
    /// restaurant's id cannot be unsent, and "I did not realise which venue that was"
    /// is the explanation nobody wants to write to a programme.
    #[serde(default)]
    pub test_entities: Vec<TestEntity>,
}

impl Programme {
    /// A profile with no terms recorded, which excludes nothing.
    ///
    /// The correct reading of "nobody has said otherwise": a project with no programme
    /// reports everything it finds.
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether anything at all has been recorded.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.policy_url.is_none()
            && self.exclusions.is_empty()
            && self.test_entities.is_empty()
    }

    /// Whether this programme limits which entities may be targeted at all.
    pub fn restricts_entities(&self) -> bool {
        !self.test_entities.is_empty()
    }

    /// The entity record for an identifier, if the programme named it.
    pub fn entity(&self, id: &str) -> Option<&TestEntity> {
        self.test_entities.iter().find(|entity| entity.id == id)
    }

    /// Why this identifier must not be targeted, or `None` if it may be.
    ///
    /// A sentence rather than a bool, because the caller's job is to tell somebody why
    /// their run did less than they asked, and "refused" on its own invites them to
    /// work around it.
    pub fn refuses(&self, id: &str) -> Option<String> {
        if !self.restricts_entities() || self.entity(id).is_some() {
            return None;
        }
        let permitted: Vec<String> = self
            .test_entities
            .iter()
            .map(|entity| format!("{} ({})", entity.id, entity.what))
            .collect();
        Some(format!(
            "{id} is not one of the entities this programme permits testing against, \
             and interacting with data that is not yours is the line it draws. It \
             permits: {}",
            permitted.join(", ")
        ))
    }

    /// Records a permitted entity, replacing any with the same id.
    pub fn permit(&mut self, entity: TestEntity) {
        self.test_entities
            .retain(|existing| existing.id != entity.id);
        self.test_entities.push(entity);
        self.test_entities.sort_by(|a, b| a.id.cmp(&b.id));
    }

    /// Stops permitting an entity. Returns whether anything was removed.
    pub fn forbid(&mut self, id: &str) -> bool {
        let before = self.test_entities.len();
        self.test_entities.retain(|existing| existing.id != id);
        before != self.test_entities.len()
    }

    /// The exclusion covering this detector, if the programme has one.
    pub fn excluded(&self, detector: &str) -> Option<&Exclusion> {
        self.exclusions
            .iter()
            .find(|exclusion| exclusion.detector == detector)
    }

    /// Adds an exclusion, replacing any for the same detector.
    pub fn exclude(&mut self, exclusion: Exclusion) {
        self.exclusions
            .retain(|existing| existing.detector != exclusion.detector);
        self.exclusions.push(exclusion);
        self.exclusions.sort_by(|a, b| a.detector.cmp(&b.detector));
    }

    /// Stops excluding a detector. Returns whether anything was removed.
    pub fn allow(&mut self, detector: &str) -> bool {
        let before = self.exclusions.len();
        self.exclusions
            .retain(|existing| existing.detector != detector);
        before != self.exclusions.len()
    }

    /// How the programme reads in a run record or a report header.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(name) = &self.name {
            parts.push(name.clone());
        }
        if let Some(url) = &self.policy_url {
            parts.push(url.clone());
        }
        match self.exclusions.len() {
            0 => {}
            1 => parts.push("1 finding class excluded".into()),
            n => parts.push(format!("{n} finding classes excluded")),
        }
        match self.test_entities.len() {
            0 => {}
            1 => parts.push("1 permitted test entity".into()),
            n => parts.push(format!("{n} permitted test entities")),
        }
        if parts.is_empty() {
            "no programme recorded".into()
        } else {
            parts.join(" · ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_project_with_no_programme_excludes_nothing() {
        let programme = Programme::none();
        assert!(programme.is_empty());
        assert!(programme.excluded("headers.security").is_none());
        assert_eq!(programme.describe(), "no programme recorded");
    }

    #[test]
    fn an_exclusion_is_found_by_detector_id() {
        let mut programme = Programme::none();
        programme.exclude(Exclusion::new(
            "headers.security",
            "out of scope: missing security headers",
        ));

        let found = programme.excluded("headers.security").unwrap();
        assert_eq!(found.reason, "out of scope: missing security headers");
        assert!(programme.excluded("headers.securit").is_none());
        assert!(programme.excluded("authz.scheduled").is_none());
    }

    #[test]
    fn excluding_the_same_detector_twice_replaces_the_reason() {
        // Otherwise a report would print two contradictory reasons for one silence.
        let mut programme = Programme::none();
        programme.exclude(Exclusion::new("cookies.security", "first reason"));
        programme.exclude(Exclusion::new("cookies.security", "second reason"));

        assert_eq!(programme.exclusions.len(), 1);
        assert_eq!(
            programme.excluded("cookies.security").unwrap().reason,
            "second reason"
        );
    }

    #[test]
    fn a_detector_can_be_allowed_again() {
        let mut programme = Programme::none();
        programme.exclude(Exclusion::new("cors.configuration", "no proven impact"));

        assert!(programme.allow("cors.configuration"));
        assert!(!programme.allow("cors.configuration"));
        assert!(programme.excluded("cors.configuration").is_none());
    }

    #[test]
    fn excluding_a_lead_does_not_exclude_the_check_that_proves_it() {
        // The distinction the whole design rests on. Wolt's wording — "CORS
        // misconfiguration *without proven impact*" — excludes the observation and
        // wants the experiment.
        let mut programme = Programme::none();
        programme.exclude(Exclusion::new(
            "cors.configuration",
            "out of scope without proven impact",
        ));

        assert!(programme.excluded("cors.configuration").is_some());
        assert!(programme.excluded("cors.reflection").is_none());
    }

    #[test]
    fn a_programme_survives_a_round_trip() {
        let mut programme = Programme {
            name: Some("Wolt".into()),
            policy_url: Some("https://hackerone.com/wolt".into()),
            exclusions: Vec::new(),
            test_entities: Vec::new(),
        };
        programme.exclude(Exclusion::new("headers.security", "out of scope"));

        let json = serde_json::to_string(&programme).unwrap();
        assert_eq!(serde_json::from_str::<Programme>(&json).unwrap(), programme);
    }

    #[test]
    fn a_programme_reads_as_a_line() {
        let mut programme = Programme {
            name: Some("Wolt (HackerOne)".into()),
            policy_url: None,
            exclusions: Vec::new(),
            test_entities: Vec::new(),
        };
        assert_eq!(programme.describe(), "Wolt (HackerOne)");

        programme.exclude(Exclusion::new("a", "r"));
        assert_eq!(
            programme.describe(),
            "Wolt (HackerOne) · 1 finding class excluded"
        );
        programme.exclude(Exclusion::new("b", "r"));
        assert_eq!(
            programme.describe(),
            "Wolt (HackerOne) · 2 finding classes excluded"
        );
    }

    // -----------------------------------------------------------------------
    // The entities a programme permits
    // -----------------------------------------------------------------------

    #[test]
    fn a_programme_that_named_no_entities_refuses_nothing() {
        // Silence is not a restriction. The same reading exclusions take.
        let programme = Programme::none();
        assert!(!programme.restricts_entities());
        assert!(programme.refuses("670e7897e3c56dcc5b5a0989").is_none());
        assert!(programme.refuses("anything-at-all").is_none());
    }

    #[test]
    fn a_named_entity_may_be_targeted_and_nothing_else_may() {
        // Wolt's, verbatim: "do it only against this specific consumer test account,
        // whose user_id is 670fa3e9ead6e49d65cc3614".
        let mut programme = Programme::none();
        programme.permit(TestEntity::new(
            "670fa3e9ead6e49d65cc3614",
            "consumer test account",
        ));
        programme.permit(TestEntity::new(
            "670e7897e3c56dcc5b5a0989",
            "venue test account",
        ));

        assert!(programme.refuses("670fa3e9ead6e49d65cc3614").is_none());
        assert!(programme.refuses("670e7897e3c56dcc5b5a0989").is_none());

        // A real restaurant's id, surfaced by the analyzer out of ordinary browsing.
        // It looks exactly like the permitted ones, which is the whole problem.
        let refusal = programme
            .refuses("681c630060810b6dd12fa130")
            .expect("a venue nobody authorised");
        assert!(refusal.contains("681c630060810b6dd12fa130"), "{refusal}");
        assert!(
            refusal.contains("670fa3e9ead6e49d65cc3614"),
            "it says what is permitted, or the tester has to go and look: {refusal}"
        );
        assert!(
            refusal.contains("consumer test account"),
            "and in the programme's own words: {refusal}"
        );
    }

    #[test]
    fn permitting_the_same_entity_twice_replaces_its_description() {
        let mut programme = Programme::none();
        programme.permit(TestEntity::new("abc", "first"));
        programme.permit(TestEntity::new("abc", "second"));

        assert_eq!(programme.test_entities.len(), 1);
        assert_eq!(programme.entity("abc").unwrap().what, "second");
    }

    #[test]
    fn removing_the_last_entity_stops_refusing_everything() {
        // The failure worth being careful about: a closed list that empties should not
        // quietly become a list that permits nothing. It becomes no list at all.
        let mut programme = Programme::none();
        programme.permit(TestEntity::new("abc", "test account"));
        assert!(programme.refuses("xyz").is_some());

        assert!(programme.forbid("abc"));
        assert!(!programme.restricts_entities());
        assert!(
            programme.refuses("xyz").is_none(),
            "an empty list must mean unrestricted, not forbidden"
        );
        assert!(!programme.forbid("abc"));
    }

    #[test]
    fn entities_travel_with_the_rest_of_the_programme() {
        let mut programme = Programme {
            name: Some("Wolt".into()),
            policy_url: None,
            exclusions: Vec::new(),
            test_entities: Vec::new(),
        };
        programme.permit(TestEntity::new("670fa3e9ead6e49d65cc3614", "consumer"));
        programme.exclude(Exclusion::new("headers.security", "out of scope"));

        let json = serde_json::to_string(&programme).unwrap();
        assert_eq!(serde_json::from_str::<Programme>(&json).unwrap(), programme);
        assert!(programme.describe().contains("1 permitted test entity"));
    }

    #[test]
    fn a_programme_holding_only_entities_is_not_empty() {
        let mut programme = Programme::none();
        programme.permit(TestEntity::new("abc", "test account"));
        assert!(!programme.is_empty(), "it would not be printed in a report");
    }
}

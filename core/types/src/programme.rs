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
        self.name.is_none() && self.policy_url.is_none() && self.exclusions.is_empty()
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
}

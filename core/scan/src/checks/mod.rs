//! The passive checks this build has.
//!
//! Six, grouped by the question they answer rather than one per condition: a tester
//! asks "what does it check about headers?", not "is there a detector for
//! Referrer-Policy?". Each one states several kinds of observation and carries one
//! version, so a retest can tell that the *check* changed.
//!
//! # What is deliberately not here
//!
//! - **Anything that reads a response body.** No check in this milestone needs one,
//!   and loading every body of a large engagement to satisfy a shape nobody uses
//!   would be exactly the premature cost worth avoiding. It is also the safest choice
//!   for credential handling: a body-reading check is the one most likely to quote a
//!   session token back into a report.
//! - **Reflected-input, XSS, injection and traversal candidates.** Those need a
//!   second request with a changed input to mean anything, and a passive scanner that
//!   claimed them would be claiming exactly what it cannot see.
//! - **Version-to-CVE matching.** `Server: nginx/1.24.0` is a fact; deciding it is a
//!   vulnerability needs a vulnerability database, a patch level, and usually the
//!   distribution's backporting policy. Hexora records the fact.

#[cfg(test)]
pub(crate) mod test_support;

pub mod cache;
pub mod cookies;
pub mod cors;
pub mod disclosure;
pub mod headers;
pub mod tls;

use crate::PassiveCheck;

/// Every passive check, in a stable order.
///
/// Listed rather than discovered: adding one means adding a line here, which is the
/// honest cost of not having a plugin mechanism.
pub fn all() -> Vec<Box<dyn PassiveCheck>> {
    vec![
        Box::new(headers::SecurityHeaders),
        Box::new(cookies::CookieAttributes),
        Box::new(cors::CorsConfiguration),
        Box::new(disclosure::DisclosureHeaders),
        Box::new(cache::CacheBehaviour),
        Box::new(tls::TlsObservations),
    ]
}

/// The information every check needs to describe itself.
pub(crate) mod prelude {
    pub(crate) use hexora_types::finding::{FindingSource, Location, MessagePart, Severity};
    pub(crate) use hexora_types::ids::TargetId;
    pub(crate) use hexora_types::verify::{
        DetectorId, DetectorInfo, DetectorMode, Observation, Significance, Writeup,
    };

    pub(crate) use crate::{Exchange, PassiveCheck};

    /// Builds an observation, filling in the parts every check repeats.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observation(
        info: &DetectorInfo,
        exchange: &Exchange,
        about: impl Into<String>,
        expected: impl Into<String>,
        observed: impl Into<String>,
        rationale: impl Into<String>,
        severity: Severity,
        significance: Significance,
        location: Option<Location>,
    ) -> Observation {
        Observation {
            detector: info.id.to_string(),
            version: info.version.to_string(),
            about: about.into(),
            expected: expected.into(),
            observed: observed.into(),
            rationale: rationale.into(),
            exchange: exchange.id,
            location,
            severity,
            significance,
        }
    }

    /// A response header, as a location.
    pub(crate) fn header_at(name: &str) -> Option<Location> {
        Some(Location {
            part: MessagePart::Header,
            name: name.to_string(),
        })
    }

    /// The source a passive finding records, carrying the check and its version.
    ///
    /// The provenance a retest needs: a claim that stopped appearing because the
    /// check was rewritten is not a claim that was fixed.
    pub(crate) fn source(info: &DetectorInfo) -> FindingSource {
        FindingSource::PassiveScan {
            detector: info.id.to_string(),
            version: info.version.to_string(),
        }
    }
}

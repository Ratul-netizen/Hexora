//! `input.reflected` — every request carrying a query input, marked for the reflection check.
//!
//! The bridge between what a crawl (or the proxy) captures and what the active
//! `input.reflection` check tests. That check settles whether an input's characters come back
//! unencoded — but it only runs against inputs *something raised a hypothesis about*, and
//! nothing did, so a captured `?q=…` was never tested and a reflected XSS went unfound.
//!
//! This raises one suspicion per distinct query parameter; the active check answers it. It
//! sends nothing — a suspicion is a lead until an experiment settles it, exactly like every
//! other passive hypothesis. Reflection alone is not XSS, so the provisional severity is low;
//! the active check reports what actually came back and where.
//!
//! Only query parameters, for now: the active check tests query parameters and headers (not
//! bodies yet), and a hypothesis about an input it cannot place a marker in would only ever
//! settle as inconclusive.

use hexora_types::finding::Hypothesis;

use super::prelude::*;

/// The check.
pub struct InputCandidates;

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.reflected"),
    name: "Reflected-input candidate",
    version: "1.0.0",
    about: "query inputs worth testing for reflection, so the active check has something to settle",
    mode: DetectorMode::Passive,
    observes: false,
    hypothesizes: true,
    settles: None,
};

impl PassiveCheck for InputCandidates {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn suspect(&self, exchange: &Exchange) -> Vec<Hypothesis> {
        let query = exchange.path.split_once('?').map(|(_, q)| q);
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for (name, _value) in hexora_types::inject::query_pairs(query) {
            if name.is_empty() || !seen.insert(name.to_string()) {
                continue;
            }
            out.push(Hypothesis {
                // What the active `input.reflection` check handles (its SETTLES key), which is
                // this detector's own id — the cors.configuration → cors.reflection pattern.
                detector: INFO.id.to_string(),
                claim: format!(
                    "the {name:?} parameter on {} {} may reflect input",
                    exchange.method,
                    endpoint(&exchange.url),
                ),
                source_request: exchange.id,
                location: Some(Location {
                    part: MessagePart::Query,
                    name: name.to_string(),
                }),
                provisional_severity: Severity::Low,
            });
        }
        out
    }

    fn writeup(&self, observation: &Observation, exchange: &Exchange, target: TargetId) -> Writeup {
        // Never called: this check produces suspicions, not reportable observations. Written
        // honestly rather than with a panic, so a later change of significance is not a trap.
        Writeup {
            target,
            title: observation.about.clone(),
            description: observation.rationale.clone(),
            impact: "Context for a tester, not an issue in itself.".into(),
            remediation: "Test the input for reflection with the active scanner.".into(),
            reproduction: format!("Request {} {}.", exchange.method, exchange.url),
            cwe: None,
            owasp: None,
            source: source(&INFO),
            severity: Severity::Info,
            location: observation.location.clone(),
        }
    }
}

/// The URL without its query string, so a claim names the endpoint, not the values seen on it.
fn endpoint(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::exchange_get;

    #[test]
    fn a_parameterized_request_raises_one_hypothesis_per_query_parameter() {
        let ex = exchange_get("https://acme.test/search?q=laptop&sort=price");
        let raised = InputCandidates.suspect(&ex);
        assert_eq!(raised.len(), 2);
        // Every one is addressed to the active reflection check and names its query slot.
        for h in &raised {
            assert_eq!(h.detector, "input.reflected");
            let loc = h.location.as_ref().unwrap();
            assert_eq!(loc.part, MessagePart::Query);
        }
        assert!(raised.iter().any(|h| h.location.as_ref().unwrap().name == "q"));
        assert!(raised.iter().any(|h| h.location.as_ref().unwrap().name == "sort"));
    }

    #[test]
    fn a_request_with_no_query_raises_nothing() {
        let ex = exchange_get("https://acme.test/about");
        assert!(InputCandidates.suspect(&ex).is_empty());
    }

    #[test]
    fn a_repeated_parameter_is_raised_once() {
        let ex = exchange_get("https://acme.test/s?q=a&q=b");
        assert_eq!(InputCandidates.suspect(&ex).len(), 1);
    }
}

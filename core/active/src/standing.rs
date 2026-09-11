//! Everything an active run could settle, from one place.
//!
//! Two sources, and they are genuinely different:
//!
//! ```text
//! a passive check saw something   →  "this host may reflect any Origin"
//!                                     a suspicion about the application
//!
//! a request has an input          →  "this endpoint takes `q`"
//!                                     a work item; nothing is suspected yet
//! ```
//!
//! The second kind does not belong in a passive pass. `hexora scan passive` reports
//! what the checks *saw*, and an endpoint having a query parameter is not something
//! anybody saw — it is a list of places nobody has looked. Putting five hundred of
//! those into a passive summary would bury the two lines that came from evidence.
//!
//! So they are enumerated here, at the moment an active run is being planned, which is
//! the only moment they mean anything. The plan then shows the total and its request
//! ceiling before a single request goes out.
//!
//! # One function, two front ends
//!
//! The CLI and the window both call [`standing`]. They used to each have their own,
//! which is how two surfaces of one tool come to disagree about what is testable.

use hexora_scan::passive::Selection;
use hexora_storage::Project;
use hexora_types::finding::Hypothesis;
use hexora_types::Result;

/// What could be settled, and what is out of reach.
#[derive(Debug, Clone, Default)]
pub struct Standing {
    /// Everything an active run could test.
    pub hypotheses: Vec<Hypothesis>,
    /// How many stand on traffic that is no longer in scope.
    ///
    /// Counted so an empty list can say *why* it is empty. "Nothing to test" and
    /// "everything that could be tested is out of bounds" are different sentences, and
    /// only one of them is about the application.
    pub out_of_scope: usize,
}

/// Everything an active run could settle over this project's traffic.
///
/// Reads. Sends nothing — it has no transport and no [`Lab`](hexora_verify::Lab), the
/// same property [`hexora_scan::passive::scan`] has and for the same reason.
pub fn standing(project: &Project, selection: &Selection) -> Result<Standing> {
    let mut hypotheses = observed(project, selection)?;
    hypotheses.extend(work_items(project, selection)?);

    let out_of_scope = if hypotheses.is_empty() {
        let wider = Selection {
            everything: true,
            ..selection.clone()
        };
        let mut all = observed(project, &wider)?;
        all.extend(work_items(project, &wider)?);
        all.len()
    } else {
        0
    };

    Ok(Standing {
        hypotheses,
        out_of_scope,
    })
}

/// Suspicions a passive check raised from something it actually saw.
fn observed(project: &Project, selection: &Selection) -> Result<Vec<Hypothesis>> {
    Ok(hexora_scan::passive::scan(project, selection)?.hypotheses)
}

/// One work item per input of each distinct endpoint.
///
/// Deduplicated on `(method, path-without-query, input)`, so a search page loaded
/// forty times is one experiment and two endpoints that both take `q` are two.
fn work_items(project: &Project, selection: &Selection) -> Result<Vec<Hypothesis>> {
    use std::collections::BTreeSet;

    let summary = hexora_scan::passive::scan(project, selection)?;
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut raised = Vec::new();

    // The passive pass already read and filtered the traffic — by scope, by host, by
    // detector. Reusing what it examined means an active run tests exactly the
    // exchanges a passive one reported on, rather than a second, differently-filtered
    // set that nobody chose.
    for exchange in &summary.endpoints {
        let target = &exchange.path;
        let endpoint = target.split('?').next().unwrap_or(target).to_string();

        // Every check that can raise a work item from a captured exchange. Listed
        // rather than discovered, for the reason the registry gives.
        let raised_here = crate::checks::echo::suspect(exchange)
            .into_iter()
            .chain(crate::checks::redirect::suspect(exchange));

        for hypothesis in raised_here {
            let name = hypothesis
                .location
                .as_ref()
                .map(|location| format!("{:?}/{}", location.part, location.name))
                .unwrap_or_default();
            // Keyed by the check as well as the input: two checks asking different
            // questions about one parameter are two experiments, not a duplicate.
            let key = format!("{} {name}", hypothesis.detector);
            if seen.insert((exchange.method.clone(), endpoint.clone(), key)) {
                raised.push(hypothesis);
            }
        }
    }

    Ok(raised)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexora_storage::{CapturedExchange, Project};
    use hexora_types::http::{Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};

    fn capture(project: &Project, target: &str) {
        capture_as(project, target, "proxy")
    }

    fn capture_as(project: &Project, target: &str, origin: &'static str) {
        let service = HttpService::new("api.example.com", 443, true);
        let mut headers = Headers::new();
        headers.set("Content-Type", "text/html");
        project
            .traffic()
            .record(&CapturedExchange {
                request: HttpRequest::get(service, target),
                response: HttpResponse {
                    status: 200,
                    reason: None,
                    version: HttpVersion::Http11,
                    headers,
                    body: bytes::Bytes::from("<html></html>"),
                    truncated: false,
                },
                encoded_body: None,
                raw_request: None,
                content_encoding: None,
                origin,
                identity: None,
                parent: None,
                quirks: Vec::new(),
                tls: None,
                duration_ms: 1,
            })
            .unwrap();
    }

    fn everything() -> Selection {
        Selection {
            everything: true,
            ..Default::default()
        }
    }

    #[test]
    fn each_input_of_each_endpoint_becomes_one_work_item() {
        let project = Project::in_memory().unwrap();
        capture(&project, "/search?q=shoes&page=2");
        capture(&project, "/other?q=hats");

        let standing = standing(&project, &everything()).unwrap();
        let claims: Vec<&str> = standing
            .hypotheses
            .iter()
            .map(|h| h.claim.as_str())
            .collect();

        assert_eq!(claims.len(), 3, "{claims:#?}");
    }

    #[test]
    fn the_same_endpoint_seen_many_times_is_one_work_item_per_input() {
        // A search page loaded forty times is one experiment, not forty.
        let project = Project::in_memory().unwrap();
        for _ in 0..40 {
            capture(&project, "/search?q=shoes");
        }

        let standing = standing(&project, &everything()).unwrap();
        assert_eq!(standing.hypotheses.len(), 1, "{:#?}", standing.hypotheses);
    }

    #[test]
    fn the_same_endpoint_with_different_values_is_still_one_work_item() {
        // The value is not the input. `?q=shoes` and `?q=hats` are one place to probe.
        let project = Project::in_memory().unwrap();
        capture(&project, "/search?q=shoes");
        capture(&project, "/search?q=hats");

        let standing = standing(&project, &everything()).unwrap();
        assert_eq!(standing.hypotheses.len(), 1, "{:#?}", standing.hypotheses);
    }

    #[test]
    fn the_scanners_own_requests_are_never_read_back_as_the_applications_traffic() {
        // A project accumulates Hexora's own probes. An endpoint described by one of
        // them would be reported to a tester as `?q=hxa3f9<>"';()hxb1k2` — a URL
        // nobody's application has, named in a finding about that application.
        let project = Project::in_memory().unwrap();
        capture_as(&project, "/search?q=hxa3f9probe", "scanner");

        let standing = standing(&project, &everything()).unwrap();
        assert!(
            standing.hypotheses.is_empty(),
            "the scanner enumerated its own traffic: {:#?}",
            standing.hypotheses
        );
    }

    #[test]
    fn an_endpoint_is_described_by_real_traffic_even_after_the_scanner_has_run() {
        // The same endpoint, captured once by the proxy and once by a probe. The
        // finding has to name the request a person made.
        let project = Project::in_memory().unwrap();
        capture(&project, "/search?q=shoes");
        capture_as(&project, "/search?q=hxa3f9probe", "scanner");

        let standing = standing(&project, &everything()).unwrap();
        assert_eq!(standing.hypotheses.len(), 1, "{:#?}", standing.hypotheses);
        assert!(
            standing.hypotheses[0].claim.contains("/search"),
            "{}",
            standing.hypotheses[0].claim
        );
        assert!(
            !standing.hypotheses[0].claim.contains("hxa3f9probe"),
            "a probe value reached a claim about somebody's application: {}",
            standing.hypotheses[0].claim
        );
    }

    #[test]
    fn a_project_with_nothing_to_probe_says_so_without_blaming_scope() {
        let project = Project::in_memory().unwrap();
        capture(&project, "/health");

        let standing = standing(&project, &everything()).unwrap();
        assert!(standing.hypotheses.is_empty());
        assert_eq!(
            standing.out_of_scope, 0,
            "there is nothing out of scope here — the project simply has no inputs"
        );
    }

    #[test]
    fn work_that_is_out_of_scope_is_counted_rather_than_silently_dropped() {
        // The difference between "nothing to test" and "everything that could be
        // tested is out of bounds". Only one of them is about the application.
        let project = Project::in_memory().unwrap();
        capture(&project, "/search?q=shoes");

        // The default selection reads in-scope traffic only, and nothing is in scope.
        let standing = standing(&project, &Selection::default()).unwrap();
        assert!(standing.hypotheses.is_empty());
        assert_eq!(standing.out_of_scope, 1);
    }
}

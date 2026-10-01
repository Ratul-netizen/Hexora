//! `input.domxss` — does a URL source flow into a dangerous sink in the page's own script?
//!
//! Reflected and stored XSS are about what the *server* puts in the page. DOM XSS is the
//! server's blind spot: the page's own JavaScript reads a value from the URL — the
//! fragment (`location.hash`), the query (`location.search`) — and hands it to a sink that
//! turns a string into markup or code, `innerHTML`, `document.write`, `eval`. The payload
//! may never reach the server at all (everything after `#` stays in the browser), so
//! nothing an HTTP check sees can find it.
//!
//! This drives a real browser with the sinks instrumented, plants a canary in each source,
//! and reports a finding only when the canary is seen *arriving at a sink* — the flow
//! itself, proven in the page, not inferred. The heavy lifting is
//! [`nullhawk_browser::domxss`], the same engine behind `nullhawk domxss`; this settles it
//! as part of an active run, per page.
//!
//! # A browser per page, so only where a page has script to run
//!
//! Driving a browser costs seconds, and DOM XSS lives in client-side script, so this is
//! raised only for HTML responses — a JSON endpoint has no DOM to poison. The one
//! navigation is scope-checked before the browser is pointed at it.

use async_trait::async_trait;
use std::time::Duration;

use nullhawk_browser::DomXssReport;
use nullhawk_types::finding::{
    Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity,
};
use nullhawk_types::verify::{DetectorId, DetectorInfo, DetectorMode, Verification, Writeup};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct DomXss;

const SETTLES: &str = "input.domxss";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.domxss"),
    name: "DOM-based cross-site scripting",
    version: "1.0.0",
    about: "whether a URL source (the fragment or query) flows into a dangerous sink in \
            the page's own script — proven in a real browser",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Loud,
};

/// How long the page is given to load and run its script before the sinks are read.
const TEST_TIMEOUT: Duration = Duration::from_secs(12);

#[async_trait]
impl ActiveCheck for DomXss {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn handles(&self, hypothesis: &Hypothesis) -> bool {
        hypothesis.detector == SETTLES
    }

    async fn settle(
        &self,
        subject: &Subject,
        lab: &dyn Lab,
        _budget: &Budget,
    ) -> Result<Verification> {
        let where_ = where_(subject);

        // The one navigation this check drives, scope-checked like any automated send
        // before the browser is pointed at it.
        if lab.would_leave_scope(&subject.draft, None) {
            return Ok(Verification::Inconclusive {
                why: format!("{where_} is out of scope now, so the page was not loaded"),
            });
        }

        if nullhawk_browser::find_browser().is_none() {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "no Chrome/Edge/Chromium was found to trace {where_}'s script — install \
                     one or set NULLHAWK_BROWSER, and run again"
                ),
            });
        }

        let report =
            match nullhawk_browser::domxss::test(&subject.exchange.url, true, TEST_TIMEOUT).await {
                Ok(report) => report,
                Err(e) => {
                    return Ok(Verification::Inconclusive {
                        why: format!("the browser could not trace {where_}'s script: {e}"),
                    })
                }
            };

        match report.hits.first() {
            Some(hit) => Ok(Verification::Reproduced {
                note: format!(
                    "{where_} flows a URL source into a sink in its own script: a value \
                     planted in the {} reached `{}` in the page. A source the browser hands \
                     the page becoming markup or code there is DOM-based cross-site \
                     scripting, found without the server seeing the payload",
                    hit.source, hit.sink,
                ),
                evidence: evidence(subject, &report),
            }),
            None => Ok(Verification::Refuted {
                note: format!(
                    "no URL source reached a dangerous sink in {where_}'s script — the \
                     fragment and query were traced through the page and neither became \
                     markup or code",
                ),
            }),
        }
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        Writeup {
            target: subject.target,
            title: format!("DOM-based cross-site scripting in {}", where_(subject)),
            description: format!(
                "The script on {} reads a value from the URL and passes it to a sink that \
                 turns a string into markup or code. {}\n\nThe flow was traced in a real \
                 browser with the sinks instrumented; the evidence records which source \
                 reached which sink.",
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "The payload runs in the visitor's browser as that visitor, and where \
                     the source is the URL fragment it never reaches the server — so no \
                     server-side log or filter sees it, and a WAF cannot catch what it \
                     never receives. Delivered through a link, it reaches anyone who \
                     follows one."
                .into(),
            remediation: "Do not pass values read from `location` to a sink that interprets \
                          them — assign text with `textContent`, not `innerHTML`; never \
                          `eval` or `document.write` a URL-derived string. Where markup is \
                          unavoidable, sanitise with a vetted library (such as DOMPurify) \
                          before it reaches the sink."
                .into(),
            reproduction: format!(
                "Load {} in a browser with a payload in the URL fragment or query and \
                 observe it reach the sink. `nullhawk domxss {}` drives the same trace \
                 outside a scan.",
                subject.exchange.url, subject.exchange.url,
            ),
            cwe: Some("CWE-79".into()),
            owasp: Some("A03:2021 Injection".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: severity_for(verification),
            location: Some(Location {
                part: MessagePart::Query,
                name: "location".into(),
            }),
        }
    }
}

fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Reproduced { .. } => Severity::High,
        _ => Severity::Low,
    }
}

/// The traced flows, one evidence line each — the source, the sink, and what the sink
/// received (already truncated by the tracer).
fn evidence(subject: &Subject, report: &DomXssReport) -> Vec<Evidence> {
    let mut evidence = vec![Evidence::Exchange {
        request: subject.exchange.id,
        response: None,
        note: format!(
            "the captured page this was raised from: {} {}",
            subject.exchange.method, subject.exchange.url
        ),
    }];
    for hit in &report.hits {
        evidence.push(Evidence::Exchange {
            request: subject.exchange.id,
            response: None,
            note: format!(
                "traced in the browser: the {} reached `{}` carrying `{}`",
                hit.source, hit.sink, hit.sample
            ),
        });
    }
    evidence
}

fn where_(subject: &Subject) -> String {
    format!(
        "{} {}",
        subject.exchange.method,
        path_of(&subject.exchange.url)
    )
}

fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("/")
}

fn sentence(note: &str) -> String {
    let mut chars = note.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Whether a response has a DOM to poison — HTML the browser runs script in.
fn is_html(exchange: &nullhawk_scan::Exchange) -> bool {
    exchange
        .response_headers
        .get("content-type")
        .map(|h| h.value_lossy().to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

/// Raises one suspicion per HTML page. Per page, not per input: the sources it plants in
/// (the fragment and the query) are the browser's, traced through the page's own script.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    if crate::schedule::is_state_changing(&exchange.method) {
        return Vec::new();
    }
    if !(200..400).contains(&exchange.status) {
        return Vec::new();
    }
    if !is_html(exchange) {
        return Vec::new();
    }

    vec![Hypothesis {
        detector: SETTLES.to_string(),
        claim: format!(
            "{} {} returns a page with script — whether a URL source flows into a sink in \
             it needs a browser",
            exchange.method,
            path_of(&exchange.url),
        ),
        source_request: exchange.id,
        location: Some(Location {
            part: MessagePart::Query,
            name: "location".into(),
        }),
        provisional_severity: Severity::Info,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullhawk_types::http::Headers;

    fn raised(detector: &str) -> Hypothesis {
        Hypothesis {
            detector: detector.into(),
            claim: "something".into(),
            source_request: nullhawk_types::ids::RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        }
    }

    fn exchange(content_type: Option<&str>, status: u16, method: &str) -> nullhawk_scan::Exchange {
        let mut headers = Headers::new();
        if let Some(ct) = content_type {
            headers.set("Content-Type", ct);
        }
        nullhawk_scan::Exchange {
            id: nullhawk_types::ids::RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "app.example".into(),
            port: 443,
            secure: true,
            method: method.into(),
            url: "https://app.example/page".into(),
            path: "/page".into(),
            status,
            request_headers: Headers::new(),
            response_headers: headers,
            response_bytes: 100,
            authenticated: false,
            tls: None,
            sent_at: "2026-10-01T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    #[test]
    fn it_settles_only_its_own_suspicion() {
        assert!(DomXss.handles(&raised(SETTLES)));
        assert!(!DomXss.handles(&raised("input.xss")));
        assert!(!DomXss.handles(&raised("input.stored")));
    }

    #[test]
    fn it_is_active_and_a_settler() {
        let info = DomXss.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn only_html_pages_are_probed() {
        assert_eq!(
            suspect(&exchange(Some("text/html; charset=utf-8"), 200, "GET")).len(),
            1
        );
        assert!(suspect(&exchange(Some("application/json"), 200, "GET")).is_empty());
        assert!(suspect(&exchange(None, 200, "GET")).is_empty());
        assert!(suspect(&exchange(Some("text/html"), 200, "POST")).is_empty());
        assert!(suspect(&exchange(Some("text/html"), 500, "GET")).is_empty());
    }

    #[test]
    fn a_traced_flow_is_high_and_nothing_is_low() {
        assert_eq!(
            severity_for(&Verification::Reproduced {
                note: String::new(),
                evidence: Vec::new()
            }),
            Severity::High
        );
        assert_eq!(
            severity_for(&Verification::Refuted {
                note: String::new()
            }),
            Severity::Low
        );
    }
}

//! `http.smuggling` — do a front-end and a back-end disagree about where one request
//! ends and the next begins?
//!
//! When a reverse proxy and the server behind it frame a request differently — one by
//! `Content-Length`, the other by `Transfer-Encoding` — part of one request can be made
//! to hang off the front of the next. That is request smuggling, and it is among the most
//! serious things a web stack can get wrong.
//!
//! # Detected by timing, on a connection of its own
//!
//! This check uses the safe, timing-based detection: a deliberately ambiguous request
//! whose two framings disagree about how many body bytes follow. If the two ends of the
//! chain disagree, one of them waits for bytes that never arrive, and the response is
//! delayed by its read timeout. A stack that is *not* vulnerable frames the request one
//! way, answers (usually with an error) straight away, and there is no delay.
//!
//! ```text
//! baseline   GET /                         → 200 in 40 ms
//! CL.TE      POST / (CL:4, TE:chunked, …)  → (no answer for 30 s) ← the back-end waits
//! ```
//!
//! The one property that makes this safe to run is already guaranteed by the transport:
//! **every HTTP/1.1 request opens its own connection, used for nothing else, and closed
//! afterwards** (`nullhawk_http`'s transport does not pool). A probe that leaves a
//! connection in a confused state therefore cannot corrupt anybody else's request — the
//! connection is torn down the moment this one finishes. Nothing is pipelined onto a
//! shared socket, which is the thing that makes smuggling tests dangerous elsewhere.
//!
//! # Timing is a lead, confirmed by hand
//!
//! A reproduced, framing-specific delay against a fast baseline is a strong signal, but a
//! delay is not the smuggled request itself. The finding says *confirm by hand* and points
//! at the exact bytes, because turning a timing difference into a demonstrated desync is a
//! judgement a person makes, not a number a scanner reads.
//!
//! # One probe per host, at its root
//!
//! Smuggling is a property of the chain in front of the application, not of any one
//! endpoint, so the suspicion is raised once — on a captured `GET /` — and not repeated
//! for every path below it, which would re-test the same front-end many times over. A host
//! whose root was never captured is not tested, and that is written down rather than hidden.

use std::time::Instant;

use async_trait::async_trait;
use nullhawk_repeater::Draft;
use nullhawk_types::finding::{Evidence, FindingSource, Hypothesis, Severity};
use nullhawk_types::ids::RequestId;
use nullhawk_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct RequestSmuggling;

/// The hypothesis this check raises and settles itself: no passive signal exists for a
/// framing disagreement, which only shows under a crafted request.
const SETTLES: &str = "http.desync";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("http.smuggling"),
    name: "HTTP request smuggling",
    version: "1.0.0",
    about: "whether a front-end and back-end disagree about request framing, by the delay an ambiguous CL/TE request causes",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: true,
    settles: Some(SETTLES),
    // Loud: it sends malformed framing and waits out a read timeout, so it is slow and
    // conspicuous — exactly what `scan active --quiet` leaves out.
    intrusiveness: nullhawk_types::verify::Intrusiveness::Loud,
};

/// A probe response delayed by at least this much over the baseline is read as a wait for
/// bytes that never came. Generous on purpose: network jitter is milliseconds, and the
/// delay a desync causes is a whole read timeout — seconds.
const DELAY_THRESHOLD_MS: u64 = 5_000;

/// A baseline slower than this means the endpoint is slow to *everything*, so a timing
/// test cannot tell a desync from ordinary latency. Reported as inconclusive, not refuted.
const SLOW_BASELINE_MS: u64 = 3_000;

#[async_trait]
impl ActiveCheck for RequestSmuggling {
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
        budget: &Budget,
    ) -> Result<Verification> {
        let host = host_header(subject);
        let path = request_path(subject);
        let service = subject.draft.request.service.clone();

        // The baseline: a normal, well-framed GET to the same endpoint, on its own
        // connection. It measures how long an untroubled request takes here, which is what
        // a probe's delay is judged against.
        let baseline = timed(lab, &service, baseline_bytes(&host, &path)).await;
        let Some(baseline_id) = baseline.request else {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "a normal request to {path} did not complete, so there was no baseline \
                     latency to measure a desync against"
                ),
            });
        };
        if baseline.elapsed_ms >= SLOW_BASELINE_MS {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "a normal request to {path} already took {}ms, so this endpoint is slow \
                     to everything and a timing test cannot separate a desync from ordinary \
                     latency",
                    baseline.elapsed_ms,
                ),
            });
        }

        let mut spent = 1usize;
        let mut results: Vec<(&str, u64)> = Vec::new();

        for (class, bytes) in [
            ("CL.TE", clte_bytes(&host, &path)),
            ("TE.CL", tecl_bytes(&host, &path)),
        ] {
            if spent >= budget.per_hypothesis.max(1) {
                break;
            }
            spent += 1;
            let probe = timed(lab, &service, bytes.clone()).await;
            results.push((class, probe.elapsed_ms));

            if delayed(probe.elapsed_ms, baseline.elapsed_ms) {
                // A delay once can be a slow moment on the network. Reproduce it before
                // calling it a desync — the same ambiguous request, a second isolated
                // connection.
                // The confirming send is the last request this hypothesis makes, so the
                // budget is only read, not tracked past here.
                let confirmed = if spent < budget.per_hypothesis.max(1) {
                    let again = timed(lab, &service, bytes).await;
                    delayed(again.elapsed_ms, baseline.elapsed_ms).then_some(again.elapsed_ms)
                } else {
                    None
                };

                let variant_ms: Vec<u64> =
                    std::iter::once(probe.elapsed_ms).chain(confirmed).collect();
                let timed_request = probe.request.unwrap_or(baseline_id);
                let evidence = vec![
                    Evidence::Exchange {
                        request: baseline_id,
                        response: None,
                        note: format!(
                            "a normal GET {path} answered in {}ms — the baseline",
                            baseline.elapsed_ms
                        ),
                    },
                    Evidence::Timing {
                        request: timed_request,
                        baseline_ms: vec![baseline.elapsed_ms],
                        variant_ms: variant_ms.clone(),
                    },
                ];

                return Ok(if confirmed.is_some() {
                    Verification::Supported {
                        support: Support::Distinctive,
                        note: format!(
                            "a {class} probe to {path} — an ambiguous Content-Length / \
                             Transfer-Encoding request — took {} against a {}ms baseline, and \
                             the same probe delayed again on a second connection ({}). The \
                             delay is specific to the ambiguous framing and reproduced: the \
                             front-end and back-end disagree on where the body ends. Confirm \
                             by hand — the delay is the sign, not the smuggled request itself",
                            ms_list(&variant_ms),
                            baseline.elapsed_ms,
                            ms_list(&variant_ms[1..]),
                        ),
                        evidence,
                    }
                } else {
                    Verification::Supported {
                        support: Support::Consistent,
                        note: format!(
                            "a {class} probe to {path} took {}ms against a {}ms baseline, but \
                             a second identical probe did not delay — one slow response is not \
                             a pattern two experiments agree on, so this is a lead to check by \
                             hand rather than a confirmed desync",
                            probe.elapsed_ms, baseline.elapsed_ms,
                        ),
                        evidence,
                    }
                });
            }
        }

        Ok(Verification::Refuted {
            note: format!(
                "neither an ambiguous-framing probe delayed beyond the {}ms baseline for \
                 {path} ({}); no timing sign of a front-end/back-end desync here",
                baseline.elapsed_ms,
                results
                    .iter()
                    .map(|(class, ms)| format!("{class} {ms}ms"))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        let path = request_path(subject);
        Writeup {
            target: subject.target,
            title: format!(
                "Possible HTTP request smuggling at {}",
                subject.exchange.host
            ),
            description: format!(
                "An ambiguous request to {path} on {} — one that frames its body by \
                 Content-Length and Transfer-Encoding at once, so a front-end and a \
                 back-end that trust different headers disagree about where it ends — was \
                 answered far more slowly than a normal request, on a connection used for \
                 nothing else. {}",
                subject.exchange.host,
                sentence(verification.note()),
            ),
            impact: "If a front-end proxy and the server behind it disagree about request \
                     framing, an attacker can prepend bytes to the next visitor's request: \
                     poisoning the shared cache, capturing other users' requests, bypassing \
                     front-end access controls, and turning a self-only issue into one that \
                     hits every user behind the same proxy. The timing here is a strong \
                     sign, not a demonstration — what it is worth depends on what the \
                     smuggled prefix can reach."
                .into(),
            remediation: "Make the front-end and back-end agree on one framing. Prefer \
                          HTTP/2 end to end (its framing is unambiguous), or configure the \
                          front-end to reject any request that carries both Content-Length \
                          and Transfer-Encoding, and to normalise Transfer-Encoding before \
                          forwarding. Do not forward a request the front-end could not \
                          unambiguously frame."
                .into(),
            reproduction: format!(
                "Send a normal GET {path} and note the round-trip, then send the ambiguous \
                 Content-Length/Transfer-Encoding request named above on a fresh connection \
                 and compare. A delay of several seconds is the back-end waiting for body \
                 bytes the front-end did not forward. `nullhawk poc <project> <finding>` \
                 compiles the exact bytes; confirm the desync by smuggling a benign prefix \
                 by hand before reporting it as exploitable.",
            ),
            cwe: Some("CWE-444".into()),
            owasp: Some("A05:2021 Security Misconfiguration".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: severity_for(verification),
            location: None,
        }
    }
}

/// One timed send: how long it took wall-clock, and the request id when it completed.
///
/// The elapsed time is measured around the call, so a probe that hangs until the read
/// timeout and then *errors* still reports the time it spent waiting — which is the whole
/// signal. An error with a small elapsed (a refused connection) is simply not a delay.
struct Timed {
    elapsed_ms: u64,
    request: Option<RequestId>,
}

async fn timed(
    lab: &dyn Lab,
    service: &nullhawk_types::http::HttpService,
    bytes: Vec<u8>,
) -> Timed {
    let draft = match Draft::raw(service.clone(), bytes) {
        Ok(draft) => draft,
        Err(_) => {
            return Timed {
                elapsed_ms: 0,
                request: None,
            }
        }
    };
    let start = Instant::now();
    let result = lab.experiment(&draft, None).await;
    let elapsed_ms = start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    Timed {
        elapsed_ms,
        request: result.ok().map(|sent| sent.id),
    }
}

/// Whether a probe's time is a desync-sized delay over the baseline.
fn delayed(probe_ms: u64, baseline_ms: u64) -> bool {
    probe_ms >= baseline_ms.saturating_add(DELAY_THRESHOLD_MS)
}

/// The `Host` header value for a probe: bare host, or host:port when the port is not the
/// scheme's default.
fn host_header(subject: &Subject) -> String {
    let (host, port, secure) = (
        &subject.exchange.host,
        subject.exchange.port,
        subject.exchange.secure,
    );
    let default = (secure && port == 443) || (!secure && port == 80);
    if default {
        host.clone()
    } else {
        format!("{host}:{port}")
    }
}

/// The request path to aim the probes at.
fn request_path(subject: &Subject) -> String {
    let path = &subject.draft.request.path;
    if path.is_empty() {
        "/".to_string()
    } else {
        path.clone()
    }
}

/// A normal, well-framed request. The baseline the probes are judged against.
fn baseline_bytes(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes()
}

/// CL.TE: the front-end honours Content-Length (4 bytes), the back-end honours chunked and
/// waits for a chunk that the front-end did not forward.
fn clte_bytes(host: &str, path: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nA\r\nX"
    )
    .into_bytes()
}

/// TE.CL: the front-end honours chunked (the `0` chunk ends the body), the back-end
/// honours Content-Length (6) and waits for the byte the front-end held back.
fn tecl_bytes(host: &str, path: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\nX"
    )
    .into_bytes()
}

fn ms_list(samples: &[u64]) -> String {
    samples
        .iter()
        .map(|ms| format!("{ms}ms"))
        .collect::<Vec<_>>()
        .join(" and ")
}

/// Severity, from what the experiment established. A reproduced delay is a strong lead for
/// a serious class, but timing is not proof, so it stays below a demonstrated desync.
fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Supported {
            support: Support::Distinctive,
            ..
        } => Severity::High,
        Verification::Supported { .. } => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Raises one suspicion per host, on a captured `GET /`.
///
/// Root only: smuggling is a property of the front-end, so one probe at the root settles
/// it for the host, and probing every endpoint below would re-test the same chain. A GET,
/// so the suspicion's source request is one the scheduler would replay; the probes
/// themselves are crafted fresh.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    let path = exchange.path.split('?').next().unwrap_or(&exchange.path);
    if !exchange.method.eq_ignore_ascii_case("GET") || path != "/" {
        return Vec::new();
    }
    vec![Hypothesis {
        detector: SETTLES.to_string(),
        claim: format!(
            "{} has a GET / — whether its front-end and back-end frame requests the same \
             way needs a crafted request",
            exchange.host,
        ),
        source_request: exchange.id,
        location: None,
        provisional_severity: Severity::Info,
    }]
}

fn sentence(note: &str) -> String {
    let mut chars = note.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(method: &str, url: &str) -> nullhawk_scan::Exchange {
        let path = url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|at| rest[at..].to_string()))
            .unwrap_or_else(|| "/".into());
        nullhawk_scan::Exchange {
            id: RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "app.example.com".into(),
            port: 443,
            secure: true,
            method: method.into(),
            url: url.into(),
            path,
            status: 200,
            request_headers: nullhawk_types::http::Headers::new(),
            response_headers: nullhawk_types::http::Headers::new(),
            response_bytes: 10,
            authenticated: false,
            tls: None,
            sent_at: "2026-10-01T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    #[test]
    fn it_raises_and_settles_its_own_suspicion() {
        let info = RequestSmuggling.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert!(info.hypothesizes);
        assert_eq!(info.settles, Some(SETTLES));
        let raised = suspect(&exchange("GET", "https://app.example.com/"));
        assert_eq!(raised.len(), 1);
        assert!(RequestSmuggling.handles(&raised[0]));
    }

    #[test]
    fn only_a_root_get_raises_a_suspicion() {
        // One per host, at the root — not once per endpoint.
        assert_eq!(
            suspect(&exchange("GET", "https://app.example.com/")).len(),
            1
        );
        assert_eq!(
            suspect(&exchange("GET", "https://app.example.com/?x=1")).len(),
            1
        );
        assert!(suspect(&exchange("GET", "https://app.example.com/admin")).is_empty());
        assert!(suspect(&exchange("POST", "https://app.example.com/")).is_empty());
    }

    #[test]
    fn a_raised_suspicion_claims_nothing_and_names_no_input() {
        let raised = suspect(&exchange("GET", "https://app.example.com/"));
        assert_eq!(raised[0].provisional_severity, Severity::Info);
        assert!(raised[0].claim.contains("needs a crafted request"));
        assert!(raised[0].location.is_none());
    }

    #[test]
    fn the_probes_carry_both_framings_and_disagree_on_the_body() {
        // The whole point: each probe declares Content-Length AND Transfer-Encoding, and
        // the two framings imply different body lengths.
        let clte = String::from_utf8(clte_bytes("h", "/")).unwrap();
        assert!(clte.contains("Content-Length: 4"));
        assert!(clte.contains("Transfer-Encoding: chunked"));
        assert!(clte.ends_with("\r\n\r\n1\r\nA\r\nX"));

        let tecl = String::from_utf8(tecl_bytes("h", "/")).unwrap();
        assert!(tecl.contains("Content-Length: 6"));
        assert!(tecl.contains("Transfer-Encoding: chunked"));
        assert!(tecl.ends_with("\r\n\r\n0\r\n\r\nX"));
    }

    #[test]
    fn the_baseline_is_well_formed_and_sends_nothing_ambiguous() {
        let base = String::from_utf8(baseline_bytes("h", "/")).unwrap();
        assert!(!base.contains("Transfer-Encoding"));
        assert!(!base.contains("Content-Length"));
        assert!(base.starts_with("GET / HTTP/1.1"));
    }

    #[test]
    fn a_delay_is_a_whole_threshold_over_baseline_not_jitter() {
        assert!(!delayed(90, 40), "50ms of jitter is not a desync");
        assert!(!delayed(40 + DELAY_THRESHOLD_MS - 1, 40));
        assert!(delayed(40 + DELAY_THRESHOLD_MS, 40));
        assert!(delayed(30_000, 40), "a read-timeout-sized hang is a delay");
    }

    #[test]
    fn host_header_adds_a_nonstandard_port_only() {
        let mut ex = exchange("GET", "https://app.example.com/");
        let subject = subject_from(&ex);
        assert_eq!(host_header(&subject), "app.example.com");
        ex.port = 8443;
        let subject = subject_from(&ex);
        assert_eq!(host_header(&subject), "app.example.com:8443");
    }

    #[test]
    fn severity_stays_below_a_demonstrated_desync() {
        let distinctive = Verification::Supported {
            support: Support::Distinctive,
            note: String::new(),
            evidence: Vec::new(),
        };
        assert_eq!(severity_for(&distinctive), Severity::High);
        let consistent = Verification::Supported {
            support: Support::Consistent,
            note: String::new(),
            evidence: Vec::new(),
        };
        assert_eq!(severity_for(&consistent), Severity::Medium);
    }

    fn subject_from(ex: &nullhawk_scan::Exchange) -> Subject {
        Subject {
            hypothesis: Hypothesis {
                detector: SETTLES.into(),
                claim: String::new(),
                source_request: ex.id,
                location: None,
                provisional_severity: Severity::Info,
            },
            draft: nullhawk_repeater::Draft::new(nullhawk_types::http::HttpRequest::get(
                nullhawk_types::http::HttpService::new(&ex.host, ex.port, ex.secure),
                "/",
            )),
            target: ex.target,
            exchange: ex.clone(),
            identities: std::sync::Arc::new(Vec::new()),
        }
    }
}

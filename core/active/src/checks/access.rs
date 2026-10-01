//! `access.bypass` — a 403 that one small change to the request walks straight past.
//!
//! ```text
//! captured:  GET /admin                       →  403
//! control:   GET /admin                       →  403   (re-sent now: the restriction is live)
//! probed:    GET /admin   X-Forwarded-For: 127.0.0.1  →  200, 8 KB unlike the 403
//! ```
//!
//! # What counts as a bypass, and what does not
//!
//! A forbidden URL is rarely forbidden every way you can ask for it. But a scanner that
//! called every `200` a bypass would be wrong most of the time, so this one is narrow on
//! purpose:
//!
//! * Every mutation **keeps the target resource and the GET method**. A `2xx` with a body
//!   therefore means *this* resource was served — not a different public page, and not a
//!   side effect. Method changes and path-rewrite headers (`X-Original-URL`) are left to
//!   the manual 403-bypass tool (`frontend/src/lib/bypass.ts`): the first because an
//!   automated run must never send a state-changing verb, the second because rewriting the
//!   path to `/` makes a `200` impossible to tell from the homepage.
//! * The 403 is **re-established in this run** before anything is called a bypass of it.
//!   A capture can be stale — a session expired, the restriction lifted — and a bypass of
//!   a 403 that is no longer there is not a finding.
//! * The bypassing response's body must **differ from the 403's**. A deny page served with
//!   a `200` status is not access to anything; only a different body is the resource.
//!
//! The request is replayed with its **own captured credentials** (the draft carries them),
//! so a flip from 403 to 200 is a bypass *for the same caller* — the thing that matters.
//!
//! # Which endpoints
//!
//! A captured `GET` that answered `403`. One suspicion per forbidden endpoint: the bypass
//! is a property of the request, not of any one input. A 403 on a `POST` is skipped — the
//! scheduler cannot replay it without its body, and guessing one would be worse than the
//! gap.

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
pub struct AccessBypass;

/// The hypothesis this check exists to answer.
const SETTLES: &str = "access.restricted";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("access.bypass"),
    name: "Access-control bypass",
    version: "1.0.0",
    about:
        "whether a 403 is lifted by a path or header mutation that still reaches the same resource",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Moderate,
};

#[async_trait]
impl ActiveCheck for AccessBypass {
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
        // The request exactly as captured, sent again now. If it no longer forbids, there
        // is nothing live to bypass and saying so is better than testing a ghost.
        let control = match send(lab, &subject.draft).await {
            Ok(answer) => answer,
            Err(why) => {
                return Ok(Verification::Inconclusive {
                    why: format!("the forbidden request could not be re-sent: {why}"),
                })
            }
        };
        if control.status != 403 {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "{} {} answered {} now, not 403, so there is no live restriction to \
                     bypass",
                    subject.exchange.method,
                    path_of(&subject.exchange.url),
                    control.status,
                ),
            });
        }

        // Control has already spent one request; the rest of the budget is for mutations,
        // highest-signal first, stopping the moment one lands.
        let allowed = budget.per_hypothesis.max(1).saturating_sub(1);
        let mut tried: Vec<String> = Vec::new();
        for mutation in mutations(&subject.draft.request.path)
            .into_iter()
            .take(allowed)
        {
            let mut draft = subject.draft.clone();
            draft.request.path = mutation.path.clone();
            if let Some((name, value)) = mutation.header {
                draft.request.headers.set(name, value);
            }

            let answer = match send(lab, &draft).await {
                Ok(answer) => answer,
                // A mutation that would not send is not evidence either way; try the next.
                Err(_) => continue,
            };
            // Only a mutation that actually went out and did not bypass counts as one the
            // 403 held against.
            tried.push(mutation.technique.clone());

            if is_bypass(&control, &answer) {
                return Ok(Verification::Supported {
                    support: Support::Distinctive,
                    note: format!(
                        "the request returned 403; the same request with {} ({}) returned \
                         {} and a {}-byte body unlike the 403 — the restriction on {} is \
                         reachable past it",
                        mutation.technique,
                        mutation.note,
                        answer.status,
                        answer.body.len(),
                        path_of(&subject.exchange.url),
                    ),
                    evidence: evidence(subject, &control, &answer, &mutation),
                });
            }
        }

        Ok(Verification::Refuted {
            note: format!(
                "the 403 on {} held against {} mutation(s): {}",
                path_of(&subject.exchange.url),
                tried.len(),
                tried.join(", "),
            ),
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        Writeup {
            target: subject.target,
            title: format!("A 403 on {} is bypassable", path_of(&subject.exchange.url),),
            description: format!(
                "{} {} answered 403, and answered 403 again when re-sent. {}\n\nThe request \
                 carried its own captured credentials throughout, so this is a bypass for \
                 the same caller, not the result of dropping a session.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "A control that was meant to forbid this request did not. What that is \
                     worth depends on what the 403 was protecting — an admin page, an \
                     internal API, a WAF rule — so confirm what the bypassing response \
                     actually contains. When it is the protected resource, this is broken \
                     access control: the restriction can be skipped by anyone who knows the \
                     trick."
                .into(),
            remediation: "Enforce the access decision at the point the resource is served, \
                          not at a proxy or a route pattern in front of it, so that a path \
                          the front-end and the origin normalise differently cannot reach \
                          it past the check. Do not trust client-supplied forwarding headers \
                          (`X-Forwarded-For`, `X-Real-IP`, `X-Custom-IP-Authorization`) for \
                          an IP allow-list. Match routes after normalisation, not before."
                .into(),
            reproduction: format!(
                "Send {} {} and confirm the 403, then re-send it with the mutation named \
                 above and compare the body. `nullhawk poc <project> <finding>` compiles \
                 the exact requests; the full mutation set is in the manual 403-bypass tool.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-284".into()),
            owasp: Some("A01:2021 Broken Access Control".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: severity_for(verification),
            location: subject.hypothesis.location.clone(),
        }
    }
}

/// One mutation of the forbidden request.
struct Mutation {
    /// `path` or `header`, for the report.
    #[allow(dead_code)]
    group: &'static str,
    /// The human label, e.g. "trailing slash".
    technique: String,
    /// Why it sometimes works.
    note: &'static str,
    /// The request path to send — the original, unless this is a path mutation.
    path: String,
    /// A header to add, when this is a header mutation.
    header: Option<(&'static str, &'static str)>,
}

/// The mutations tried, highest-signal first.
///
/// All keep the target resource and the GET method — see the module documentation for why
/// method changes and path-rewrite headers are not here. A budget usually sends only the
/// first few, which is why order is by how often each one is the one that works.
fn mutations(full_path: &str) -> Vec<Mutation> {
    let (path, query) = match full_path.find('?') {
        Some(at) => (&full_path[..at], &full_path[at..]),
        None => (full_path, ""),
    };
    let trimmed = path.trim_end_matches('/');
    let seg = if trimmed.is_empty() { "/" } else { trimmed };
    let rest = seg.strip_prefix('/').unwrap_or(seg);
    let with_query = |p: String| format!("{p}{query}");
    let original = full_path.to_string();

    let header = |group, technique: &str, note, name, value| Mutation {
        group,
        technique: technique.to_string(),
        note,
        path: original.clone(),
        header: Some((name, value)),
    };
    let path_mut = |technique: &str, note, new_path: String| Mutation {
        group: "path",
        technique: technique.to_string(),
        note,
        path: with_query(new_path),
        header: None,
    };

    let mut out = vec![
        path_mut(
            "Tomcat `..;/` prefix",
            "a `/..;/` segment some proxies normalise away only after the ACL check",
            format!("/..;/{rest}"),
        ),
        path_mut(
            "trailing slash",
            "a router that matched the exact path may not match it with a trailing slash",
            format!("{seg}/"),
        ),
        header(
            "header",
            "X-Forwarded-For 127.0.0.1",
            "an IP allow-list that trusts a client-supplied forwarding header",
            "X-Forwarded-For",
            "127.0.0.1",
        ),
        header(
            "header",
            "X-Custom-IP-Authorization 127.0.0.1",
            "a header seen guarding internal admin routes",
            "X-Custom-IP-Authorization",
            "127.0.0.1",
        ),
        path_mut(
            "dot-segment `/./` prefix",
            "a `/./` the proxy keeps but the origin strips",
            format!("/./{rest}"),
        ),
        header(
            "header",
            "X-Real-IP 127.0.0.1",
            "an alternative client-IP header",
            "X-Real-IP",
            "127.0.0.1",
        ),
        path_mut(
            "uppercase path",
            "a case-sensitive ACL over a case-insensitive route",
            seg.to_uppercase(),
        ),
        path_mut(
            "encoded first character",
            "the first path character percent-encoded, decoded after the ACL check",
            encode_first(rest),
        ),
        header(
            "header",
            "X-Forwarded-Host localhost",
            "spoofing the host a control keys on",
            "X-Forwarded-Host",
            "localhost",
        ),
        path_mut(
            "semicolon suffix",
            "a matrix parameter the ACL may not account for",
            format!("{seg};"),
        ),
        header(
            "header",
            "X-Originating-IP 127.0.0.1",
            "an older allow-list header",
            "X-Originating-IP",
            "127.0.0.1",
        ),
        path_mut(
            "double-encoded first character",
            "double URL-encoding to survive one decode pass",
            double_encode_first(rest),
        ),
        header(
            "header",
            "X-Client-IP 127.0.0.1",
            "another client-IP variant",
            "X-Client-IP",
            "127.0.0.1",
        ),
    ];
    // A path mutation that changed nothing (an already-uppercase path, a root `/`) would
    // just re-send the control. Drop it; header mutations always add something.
    out.retain(|mutation| mutation.header.is_some() || mutation.path != original);
    out
}

/// `/admin` → `/%61dmin`. ASCII only; a non-ASCII first byte is left alone.
fn encode_first(rest: &str) -> String {
    match rest.chars().next() {
        Some(c) if c.is_ascii() => format!("/%{:02x}{}", c as u8, &rest[1..]),
        _ => format!("/{rest}"),
    }
}

/// `/admin` → `/%2561dmin`: a second encoding to survive one decode pass.
fn double_encode_first(rest: &str) -> String {
    match rest.chars().next() {
        Some(c) if c.is_ascii() => format!("/%25{:02x}{}", c as u8, &rest[1..]),
        _ => format!("/{rest}"),
    }
}

/// One send and what came back.
struct Answer {
    request: RequestId,
    status: u16,
    body: Vec<u8>,
}

/// Sends a draft and reads the status and body. No identity is substituted: the draft
/// carries the captured request's own credentials, which is exactly who the bypass must
/// be tested as.
async fn send(lab: &dyn Lab, draft: &Draft) -> std::result::Result<Answer, String> {
    let sent = lab
        .experiment(draft, None)
        .await
        .map_err(|e| e.to_string())?;
    let response = &sent.exchange.response;
    Ok(Answer {
        request: sent.id,
        status: response.status,
        body: response.body.to_vec(),
    })
}

/// A bypass is a success status, a non-empty body, and a body unlike the deny page. All
/// three: a `200` with the 403's own body is a deny page with the wrong status line, not
/// access to anything.
fn is_bypass(control: &Answer, answer: &Answer) -> bool {
    (200..300).contains(&answer.status) && !answer.body.is_empty() && answer.body != control.body
}

/// Severity, from what the experiment established. A confirmed content bypass of an access
/// control is broken access control; a weaker signal is not asserted as one.
fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Reproduced { .. } => Severity::High,
        Verification::Supported {
            support: Support::Distinctive,
            ..
        } => Severity::High,
        Verification::Supported { .. } => Severity::Medium,
        _ => Severity::Low,
    }
}

fn evidence(
    subject: &Subject,
    control: &Answer,
    answer: &Answer,
    mutation: &Mutation,
) -> Vec<Evidence> {
    vec![
        Evidence::Exchange {
            request: subject.exchange.id,
            response: None,
            note: format!(
                "the captured 403: {} {}",
                subject.exchange.method, subject.exchange.url
            ),
        },
        Evidence::Exchange {
            request: control.request,
            response: None,
            note: "the same request sent again now — 403, so the restriction is live".into(),
        },
        Evidence::Exchange {
            request: answer.request,
            response: None,
            note: format!(
                "with {} — {} and a {}-byte body unlike the 403",
                mutation.technique,
                answer.status,
                answer.body.len(),
            ),
        },
    ]
}

/// Raises one suspicion per forbidden GET endpoint.
///
/// A GET so the scheduler can replay it; 403 because that is the status a bypass is of.
/// One per endpoint, not per input — the bypass is a property of the request.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    if exchange.status != 403 || !exchange.method.eq_ignore_ascii_case("GET") {
        return Vec::new();
    }
    vec![Hypothesis {
        detector: SETTLES.to_string(),
        claim: format!(
            "{} {} returned 403 — whether a mutation reaches it anyway needs a request",
            exchange.method,
            path_of(&exchange.url),
        ),
        source_request: exchange.id,
        location: None,
        // A work item. Anything above Info would be claiming an experiment's result.
        provisional_severity: Severity::Info,
    }]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn raised(detector: &str) -> Hypothesis {
        Hypothesis {
            detector: detector.into(),
            claim: "something".into(),
            source_request: RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        }
    }

    fn exchange(status: u16, method: &str, url: &str) -> nullhawk_scan::Exchange {
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
            status,
            request_headers: nullhawk_types::http::Headers::new(),
            response_headers: nullhawk_types::http::Headers::new(),
            response_bytes: 0,
            authenticated: false,
            tls: None,
            sent_at: "2026-10-01T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    #[test]
    fn it_settles_its_own_suspicions_and_no_others() {
        assert!(AccessBypass.handles(&raised(SETTLES)));
        assert!(!AccessBypass.handles(&raised("redirect.controllable")));
        assert!(!AccessBypass.handles(&raised("input.reflected")));
    }

    #[test]
    fn it_reports_itself_as_active_and_as_a_settler() {
        let info = AccessBypass.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
        assert!(info.produces_something());
    }

    #[test]
    fn only_a_forbidden_get_is_worth_probing() {
        assert_eq!(
            suspect(&exchange(403, "GET", "https://app.example.com/admin")).len(),
            1
        );
        // Not forbidden, and forbidden-but-not-GET: neither is a target.
        assert!(suspect(&exchange(200, "GET", "https://app.example.com/admin")).is_empty());
        assert!(suspect(&exchange(401, "GET", "https://app.example.com/admin")).is_empty());
        assert!(suspect(&exchange(403, "POST", "https://app.example.com/admin")).is_empty());
    }

    #[test]
    fn a_raised_suspicion_claims_nothing_about_the_application() {
        let raised = suspect(&exchange(403, "GET", "https://app.example.com/admin"));
        assert_eq!(raised.len(), 1);
        assert_eq!(raised[0].provisional_severity, Severity::Info);
        assert!(
            raised[0].claim.contains("needs a request"),
            "{}",
            raised[0].claim
        );
        assert!(
            raised[0].location.is_none(),
            "a request-level suspicion names no input"
        );
    }

    #[test]
    fn mutations_keep_the_target_and_preserve_the_query() {
        let out = mutations("/admin?tab=users");
        assert!(!out.is_empty());
        for mutation in &out {
            // The query survives every path mutation, so the same resource is addressed.
            if mutation.header.is_none() {
                assert!(
                    mutation.path.ends_with("?tab=users"),
                    "{} dropped the query: {}",
                    mutation.technique,
                    mutation.path
                );
            } else {
                // A header mutation leaves the path exactly as it was.
                assert_eq!(mutation.path, "/admin?tab=users", "{}", mutation.technique);
            }
        }
    }

    #[test]
    fn a_two_hundred_with_the_deny_page_body_is_not_a_bypass() {
        // The failure mode this check exists to avoid: a server that answers 200 with the
        // very same forbidden body. Same bytes, different status line, no access gained.
        let control = Answer {
            request: RequestId::new(),
            status: 403,
            body: b"Forbidden".to_vec(),
        };
        let same = Answer {
            request: RequestId::new(),
            status: 200,
            body: b"Forbidden".to_vec(),
        };
        assert!(!is_bypass(&control, &same));

        let empty = Answer {
            request: RequestId::new(),
            status: 200,
            body: Vec::new(),
        };
        assert!(!is_bypass(&control, &empty));

        let real = Answer {
            request: RequestId::new(),
            status: 200,
            body: b"<admin dashboard>".to_vec(),
        };
        assert!(is_bypass(&control, &real));

        // A redirect to a login page is not a bypass, however different the body.
        let redirected = Answer {
            request: RequestId::new(),
            status: 302,
            body: b"<login>".to_vec(),
        };
        assert!(!is_bypass(&control, &redirected));
    }

    #[test]
    fn a_confirmed_bypass_is_high_and_a_weaker_signal_is_not() {
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

    #[test]
    fn encoding_the_first_character_is_the_first_character_only() {
        assert_eq!(encode_first("admin"), "/%61dmin");
        assert_eq!(double_encode_first("admin"), "/%2561dmin");
    }
}

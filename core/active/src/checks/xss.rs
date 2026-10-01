//! `input.xss` — whether a reflected input actually *executes* as script in a browser.
//!
//! Reflection is a lead, not a finding: `echo.rs` reports that an input comes back and in
//! which context, because a value in the page is not yet a value that runs. This settles
//! the question reflection leaves open — does a payload placed in that input execute — and
//! it answers it the only way that is not a guess: by loading the page in a real browser
//! and asking whether the script ran.
//!
//! ```text
//! ?q=<img src=x onerror=window.__nh_xss='<token>'>
//!   → the page renders, the image fails, the handler runs
//!   → window.__nh_xss === '<token>'   read back over the DevTools protocol
//! ```
//!
//! The marker is a fresh token set by the payload itself, so a global carrying it back
//! can only mean the injected script executed — not that it was reflected, encoded or
//! sanitised into inertness. A second token in a second load confirms it. Where the value
//! reflects but no payload runs — output encoding, a Content-Security-Policy, a framework
//! that escapes — the browser proves *that*, and the result is a refutation, which is a
//! stronger statement than reflection alone could make in either direction.
//!
//! # A browser is expensive, so it is earned
//!
//! Driving a browser costs seconds; an HTTP probe costs milliseconds. So the browser is
//! launched only after a cheap HTTP check shows the input reflects at all — an input that
//! never comes back cannot execute, and is refuted without a browser ever starting.
//!
//! # What it drives, and its one rough edge
//!
//! The browser navigates straight to the in-scope endpoint under test (the scope guard's
//! verdict on that request is checked first). Unlike a proxied capture session it has no
//! chokepoint for the *subresources* the page then pulls — a rendered page fetches its own
//! scripts and, sometimes, third-party ones. Those are read-only page loads, not tests;
//! the deliberate testing is the one navigation, and it is scope-checked.

use async_trait::async_trait;
use std::time::Duration;

use nullhawk_browser::{Browser, LaunchOptions};
use nullhawk_types::finding::{
    Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity,
};
use nullhawk_types::inject::{inputs, inputs_in, substitute};
use nullhawk_types::object::ObjectLocation;
use nullhawk_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct ReflectedXss;

const SETTLES: &str = "input.xss";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.xss"),
    name: "Reflected cross-site scripting",
    version: "1.1.0",
    about: "whether a reflected input executes as script — proven by loading the page in a \
            real browser and reading back a marker the payload set",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Loud,
};

/// The global the payload sets, and reads back to prove it ran.
const MARKER: &str = "__nh_xss";

/// How long to wait for a navigation's load event.
const NAV_TIMEOUT: Duration = Duration::from_secs(10);

/// Breakout payloads, each of which sets `window.__nh_xss` to the token when it executes.
/// `{t}` is the token. Ordered from the contexts that need the least breakout to the most;
/// `onerror` on a broken image fires immediately and without interaction, so it leads.
fn payloads(token: &str) -> Vec<String> {
    vec![
        format!("<img src=x onerror=window.{MARKER}='{token}'>"),
        format!("\"><img src=x onerror=window.{MARKER}='{token}'>"),
        format!("'><img src=x onerror=window.{MARKER}='{token}'>"),
        format!("<svg onload=window.{MARKER}='{token}'>"),
        format!("</script><img src=x onerror=window.{MARKER}='{token}'>"),
        format!("<script>window.{MARKER}='{token}'</script>"),
    ]
}

#[async_trait]
impl ActiveCheck for ReflectedXss {
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
        let Some(slot) = slot_named(subject) else {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "the input this was raised about is no longer in {} {}, so there was \
                     nothing to reflect",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };

        // Cheap gate: an input that does not come back in the page cannot execute in it.
        // One HTTP probe rules that out before a browser is ever launched.
        let canary = format!("nhxss{}", fresh_token());
        match reflects(subject, lab, &slot, &canary).await {
            Some(true) => {}
            Some(false) => {
                return Ok(Verification::Refuted {
                    note: format!(
                        "{} is not reflected in the response, so it cannot execute as \
                         script there",
                        describe(&slot)
                    ),
                })
            }
            None => {
                return Ok(Verification::Inconclusive {
                    why: format!(
                        "the reflection probe for {} did not complete",
                        describe(&slot)
                    ),
                })
            }
        }

        // It reflects. Only a browser can say whether it *runs*, so one is earned now.
        if nullhawk_browser::find_browser().is_none() {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "{} is reflected, but no Chrome/Edge/Chromium was found to confirm \
                     whether it executes — install one or set NULLHAWK_BROWSER, and run \
                     again",
                    describe(&slot)
                ),
            });
        }

        let browser = match Browser::launch_with(&LaunchOptions {
            headless: true,
            proxy: None,
            ignore_certificate_errors: true,
        }) {
            Ok(browser) => browser,
            Err(e) => {
                return Ok(Verification::Inconclusive {
                    why: format!("a browser to confirm execution could not be launched: {e}"),
                })
            }
        };
        let mut cdp = match browser.connect().await {
            Ok(cdp) => cdp,
            Err(e) => {
                return Ok(Verification::Inconclusive {
                    why: format!("the browser started but could not be driven: {e}"),
                })
            }
        };

        // Each payload is tried on its own fresh navigation, so a marker can only be set by
        // the load it belongs to. The first that runs is confirmed with a second token.
        let mut reflected_inertly = false;
        for payload in payloads(&fresh_token()) {
            let token = extract_token(&payload);
            match executed(subject, lab, &mut cdp, &slot, &payload, &token).await {
                Executed::Yes => {
                    // Confirm: a different token through the same breakout. A page that set
                    // the first global for any other reason will not set the second too.
                    let token2 = fresh_token();
                    let payload2 = payload.replace(&token, &token2);
                    if let Executed::Yes =
                        executed(subject, lab, &mut cdp, &slot, &payload2, &token2).await
                    {
                        return Ok(Verification::Reproduced {
                            note: format!(
                                "{} executes as script: a payload placed in it ran in the \
                                 browser and set a value only that request supplied, and a \
                                 second payload with a different value did the same. This \
                                 is reflected cross-site scripting",
                                describe(&slot)
                            ),
                            evidence: vec![from_exchange(subject), ran(subject, &payload)],
                        });
                    }
                    return Ok(Verification::Supported {
                        support: Support::Distinctive,
                        note: format!(
                            "{} executed a script payload in the browser once; the \
                             confirming second payload did not run",
                            describe(&slot)
                        ),
                        evidence: vec![from_exchange(subject), ran(subject, &payload)],
                    });
                }
                Executed::ReflectedNotRun => reflected_inertly = true,
                Executed::Error => {}
            }
        }

        Ok(if reflected_inertly {
            Verification::Refuted {
                note: format!(
                    "{} is reflected but no payload executed in the browser — the value is \
                     encoded on output, or a Content-Security-Policy stops it running. It \
                     is reflected, not scriptable",
                    describe(&slot)
                ),
            }
        } else {
            Verification::Refuted {
                note: format!(
                    "no script payload placed in {} executed in the browser",
                    describe(&slot)
                ),
            }
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        let slot = slot_named(subject);
        let where_ = slot
            .as_ref()
            .map(describe)
            .unwrap_or_else(|| "an input".into());

        Writeup {
            target: subject.target,
            title: format!(
                "Reflected cross-site scripting in {} of {} {}",
                where_,
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "A value placed in {where_} of {} {} is reflected into the page and runs as \
                 script in the browser. {}\n\nExecution was confirmed by loading the page in \
                 a real browser and reading back a value the payload set — not inferred \
                 from the reflection.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "Script that runs in a visitor's browser runs as that visitor: it reads \
                     the page and the session it is served with, acts with the user's \
                     privileges, and can rewrite what they see. Delivered through a link, \
                     it reaches anyone who follows one."
                .into(),
            remediation: "Encode output for the context it lands in — HTML-encode for body \
                          text, attribute-encode inside attributes — at the point the page \
                          is built, and prefer a template engine that does it by default. A \
                          Content-Security-Policy that forbids inline script is defence in \
                          depth, not a substitute for encoding."
                .into(),
            reproduction: format!(
                "Load {} {} in a browser with {where_} carrying an `<img src=x onerror=…>` \
                 payload and observe the handler run. `nullhawk poc <project> <finding>` \
                 compiles the exact request.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-79".into()),
            owasp: Some("A03:2021 Injection".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: severity_for(verification),
            location: slot
                .as_ref()
                .map(|slot| Location {
                    part: part_of(slot),
                    name: name_of(slot),
                })
                .or(subject.hypothesis.location.clone()),
        }
    }
}

fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Reproduced { .. } => Severity::High,
        Verification::Supported {
            support: Support::Distinctive,
            ..
        } => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Whether a canary placed in the input comes back anywhere in the response body. `None`
/// when the probe could not be sent.
async fn reflects(
    subject: &Subject,
    lab: &dyn Lab,
    slot: &ObjectLocation,
    canary: &str,
) -> Option<bool> {
    let mut draft = subject.draft.clone();
    draft.request = substitute(&draft.request, slot, canary).ok()?;
    let sent = lab.experiment(&draft, None).await.ok()?;
    let body = String::from_utf8_lossy(&sent.exchange.response.body);
    Some(body.contains(canary))
}

/// The outcome of loading one payload in the browser.
enum Executed {
    /// The payload ran: the marker global came back carrying its token.
    Yes,
    /// The page loaded, the marker did not appear — reflected but inert.
    ReflectedNotRun,
    /// The navigation or read failed; nothing was established.
    Error,
}

/// Navigates the browser to the endpoint with `payload` in the input, and reads the marker.
async fn executed(
    subject: &Subject,
    lab: &dyn Lab,
    cdp: &mut nullhawk_browser::Cdp,
    slot: &ObjectLocation,
    payload: &str,
    token: &str,
) -> Executed {
    let mut draft = subject.draft.clone();
    draft.request = match substitute(&draft.request, slot, payload) {
        Ok(request) => request,
        Err(_) => return Executed::Error,
    };
    // The one deliberate request, scope-checked like any other automated send.
    if lab.would_leave_scope(&draft, None) {
        return Executed::Error;
    }
    let Some(url) = url_of(subject, &draft.request.path) else {
        return Executed::Error;
    };

    // For a header input the payload rides a request header on the navigation, not the
    // URL (substitute left the path unchanged). User-Agent has its own override; every
    // other header goes through the extra-headers channel.
    if let ObjectLocation::Header { name, .. } = slot {
        if cdp
            .call("Network.enable", serde_json::json!({}))
            .await
            .is_err()
        {
            return Executed::Error;
        }
        let set = if name.eq_ignore_ascii_case("user-agent") {
            cdp.call(
                "Network.setUserAgentOverride",
                serde_json::json!({ "userAgent": payload }),
            )
            .await
        } else {
            cdp.call(
                "Network.setExtraHTTPHeaders",
                serde_json::json!({ "headers": { name: payload } }),
            )
            .await
        };
        if set.is_err() {
            return Executed::Error;
        }
    }

    if cdp.navigate(&url, NAV_TIMEOUT).await.is_err() {
        return Executed::Error;
    }
    // A short settle for a handler that runs just after load.
    tokio::time::sleep(Duration::from_millis(300)).await;

    match cdp.eval(&format!("window.{MARKER} || ''")).await {
        Ok(value) if value.as_str() == Some(token) => Executed::Yes,
        Ok(_) => Executed::ReflectedNotRun,
        Err(_) => Executed::Error,
    }
}

/// The full URL to drive the browser to: the subject's own origin, with the substituted
/// path (which carries the payload in its query).
fn url_of(subject: &Subject, path: &str) -> Option<String> {
    let scheme = if subject.exchange.secure {
        "https"
    } else {
        "http"
    };
    let host = &subject.exchange.host;
    let port = subject.exchange.port;
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}:{port}{path}"))
}

/// The token a payload carries, read back out of it — the text inside the quotes of the
/// `window.__nh_xss='…'` assignment, anchored on the assignment rather than the first
/// quote (a breakout payload can open with a quote of its own).
fn extract_token(payload: &str) -> String {
    let needle = format!("window.{MARKER}='");
    payload
        .split_once(&needle)
        .and_then(|(_, rest)| rest.split_once('\'').map(|(token, _)| token.to_string()))
        .unwrap_or_default()
}

fn fresh_token() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

fn ran(subject: &Subject, payload: &str) -> Evidence {
    Evidence::Exchange {
        request: subject.exchange.id,
        response: None,
        note: format!(
            "loaded in a browser with the payload `{payload}` in the input — the marker \
             global carried back the token it set, so the script executed"
        ),
    }
}

fn from_exchange(subject: &Subject) -> Evidence {
    Evidence::Exchange {
        request: subject.exchange.id,
        response: None,
        note: format!(
            "the captured exchange this was raised from: {} {}",
            subject.exchange.method, subject.exchange.url
        ),
    }
}

fn slot_named(subject: &Subject) -> Option<ObjectLocation> {
    let wanted = subject.hypothesis.location.as_ref()?;
    inputs(&subject.draft.request).into_iter().find(|slot| {
        name_of(slot).eq_ignore_ascii_case(&wanted.name) && part_of(slot) == wanted.part
    })
}

fn describe(slot: &ObjectLocation) -> String {
    match slot {
        ObjectLocation::Query { name, .. } => format!("the `{name}` query parameter"),
        ObjectLocation::Header { name, .. } => format!("the `{name}` header"),
        other => format!("{other:?}"),
    }
}

fn name_of(slot: &ObjectLocation) -> String {
    match slot {
        ObjectLocation::Query { name, .. } | ObjectLocation::Header { name, .. } => name.clone(),
        other => format!("{other:?}"),
    }
}

fn part_of(slot: &ObjectLocation) -> MessagePart {
    match slot {
        ObjectLocation::Query { .. } => MessagePart::Query,
        ObjectLocation::Header { .. } => MessagePart::Header,
        _ => MessagePart::Body,
    }
}

fn sentence(note: &str) -> String {
    let mut chars = note.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("/")
}

/// Raises one suspicion per input — a work item at `Info`, settled by an experiment.
///
/// Query parameters and request headers both: a header a page reflects (a `User-Agent` an
/// error page echoes, a `Referer` a "you came from" line shows) is as much a reflected-XSS
/// sink as a query parameter, and the browser confirms it by carrying the payload on the
/// navigation's header rather than in its URL.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    inputs_in(&exchange.path, &exchange.request_headers)
        .into_iter()
        .map(|slot| Hypothesis {
            detector: SETTLES.to_string(),
            claim: format!(
                "{} {} — {}",
                exchange.method,
                path_of(&exchange.url),
                describe(&slot),
            ),
            source_request: exchange.id,
            location: Some(Location {
                part: part_of(&slot),
                name: name_of(&slot),
            }),
            provisional_severity: Severity::Info,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raised(detector: &str) -> Hypothesis {
        Hypothesis {
            detector: detector.into(),
            claim: "something".into(),
            source_request: nullhawk_types::ids::RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        }
    }

    #[test]
    fn it_settles_only_xss_suspicions() {
        assert!(ReflectedXss.handles(&raised(SETTLES)));
        assert!(!ReflectedXss.handles(&raised("input.reflected")));
        assert!(!ReflectedXss.handles(&raised("input.crlf")));
    }

    #[test]
    fn it_is_active_and_a_settler() {
        let info = ReflectedXss.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn it_raises_for_a_reflectable_request_header_not_only_query() {
        // A header a page echoes is a reflected-XSS sink too; the browser carries the
        // payload on the navigation's header rather than in its URL.
        let mut headers = nullhawk_types::http::Headers::new();
        headers.set("User-Agent", "Mozilla/5.0");
        let exchange = nullhawk_scan::Exchange {
            id: nullhawk_types::ids::RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "shop.example".into(),
            port: 443,
            secure: true,
            method: "GET".into(),
            url: "https://shop.example/page?q=1".into(),
            path: "/page?q=1".into(),
            status: 200,
            request_headers: headers,
            response_headers: nullhawk_types::http::Headers::new(),
            response_bytes: 0,
            authenticated: false,
            tls: None,
            sent_at: "2026-10-01T00:00:00Z".into(),
            origin: "proxy".into(),
        };
        let kinds: Vec<MessagePart> = suspect(&exchange)
            .iter()
            .filter_map(|h| h.location.as_ref().map(|l| l.part))
            .collect();
        assert!(
            kinds.contains(&MessagePart::Query),
            "the query input still raises"
        );
        assert!(
            kinds.contains(&MessagePart::Header),
            "a reflectable request header now raises too: {kinds:?}"
        );
    }

    #[test]
    fn every_payload_sets_and_carries_the_token() {
        let payloads = payloads("tok123");
        for p in &payloads {
            assert!(p.contains("window.__nh_xss='tok123'"), "{p}");
            assert_eq!(extract_token(p), "tok123", "{p}");
        }
        // The leading payload is the no-interaction image handler.
        assert!(payloads[0].starts_with("<img src=x onerror="));
    }

    #[test]
    fn a_url_is_built_from_the_subjects_own_origin() {
        let subject = subject_for("shop.example", 443, true, "/search?q=hi");
        assert_eq!(
            url_of(&subject, "/search?q=PAYLOAD").as_deref(),
            Some("https://shop.example:443/search?q=PAYLOAD")
        );
    }

    #[test]
    fn severity_follows_what_the_experiment_showed() {
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

    fn subject_for(host: &str, port: u16, secure: bool, target: &str) -> Subject {
        let exchange = nullhawk_scan::Exchange {
            id: nullhawk_types::ids::RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: host.into(),
            port,
            secure,
            method: "GET".into(),
            url: format!(
                "{}://{host}:{port}{target}",
                if secure { "https" } else { "http" }
            ),
            path: target.into(),
            status: 200,
            request_headers: nullhawk_types::http::Headers::new(),
            response_headers: nullhawk_types::http::Headers::new(),
            response_bytes: 0,
            authenticated: false,
            tls: None,
            sent_at: "2026-09-30T00:00:00Z".into(),
            origin: "proxy".into(),
        };
        Subject {
            hypothesis: raised(SETTLES),
            exchange,
            draft: nullhawk_repeater::Draft::new(nullhawk_types::http::HttpRequest::get(
                nullhawk_types::http::HttpService::new(host, port, secure),
                target,
            )),
            target: nullhawk_types::ids::TargetId::new(),
            identities: std::sync::Arc::new(Vec::new()),
        }
    }
}

//! `input.stored` — whether an input is stored and later executes for someone who never
//! sent it.
//!
//! Reflected XSS runs only while the payload is in the request. Stored XSS is worse: the
//! payload is kept, and runs for the next visitor to a page that never carried it. This
//! proves that difference the only way that is not a guess — inject a payload on one
//! request, then load a **clean** request that does not carry it, in a real browser, and
//! see whether the payload runs anyway.
//!
//! ```text
//! store:   GET /guestbook?msg=<img src=x onerror=window.__nh_stored='<token>'>
//! verify:  GET /guestbook?msg=nothing        (no payload of its own)
//!            → window.__nh_stored === '<token>'   the stored entry ran
//! ```
//!
//! Execution on a request that did not carry the payload is what makes it *stored* rather
//! than reflected. A payload-free load that still runs it can only be serving something
//! kept from the earlier request.
//!
//! # What it can reach, and what it cannot
//!
//! The scheduler replays only safe methods, so the store has to be reachable by a `GET` —
//! a guestbook, a profile field, a search term logged to a page. A store that needs a
//! `POST` body is out of reach here, because replaying `POST` bodies is not something an
//! automated run does, by the same design that keeps it from resending `POST /transfers`.
//! Query inputs only, for the same reason.
//!
//! # A browser is earned
//!
//! Launching one costs seconds. So a cheap HTTP pair — store a plain marker, then fetch a
//! clean request and look for the marker — gates it: an input whose value does not persist
//! to a later clean response cannot be a stored sink, and is refuted with no browser.

use async_trait::async_trait;
use std::time::Duration;

use nullhawk_browser::{Browser, LaunchOptions};
use nullhawk_types::finding::{
    Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity,
};
use nullhawk_types::inject::{inputs, inputs_in, substitute};
use nullhawk_types::object::ObjectLocation;
use nullhawk_types::verify::{DetectorId, DetectorInfo, DetectorMode, Verification, Writeup};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct StoredXss;

const SETTLES: &str = "input.stored";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.stored"),
    name: "Stored cross-site scripting",
    version: "1.0.0",
    about: "whether an input is stored and later executes for a request that did not carry \
            it — proven in a real browser against a clean, payload-free load",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
};

/// The global a stored payload sets, and that a clean load reads back.
const MARKER: &str = "__nh_stored";

/// A benign value for the clean, verifying request — carries no payload of its own, so a
/// marker seen on the response to it was served from storage, not from this request.
const BENIGN: &str = "nhclean";

const NAV_TIMEOUT: Duration = Duration::from_secs(10);

/// Breakout payloads, each of which sets `window.__nh_stored` to the token when it runs.
fn payloads(token: &str) -> Vec<String> {
    vec![
        format!("<img src=x onerror=window.{MARKER}='{token}'>"),
        format!("\"><img src=x onerror=window.{MARKER}='{token}'>"),
        format!("'><img src=x onerror=window.{MARKER}='{token}'>"),
        format!("<svg onload=window.{MARKER}='{token}'>"),
        format!("<script>window.{MARKER}='{token}'</script>"),
    ]
}

#[async_trait]
impl ActiveCheck for StoredXss {
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
                     nothing to store",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };

        // Cheap gate: does a value stored through this input survive to a later, clean
        // request? A plain marker, then a benign fetch that should not carry it.
        let marker = format!("nhs{}", fresh_token());
        match persists(subject, lab, &slot, &marker).await {
            Some(true) => {}
            Some(false) => {
                return Ok(Verification::Refuted {
                    note: format!(
                        "a value placed in {} did not survive to a later request that did \
                         not carry it — this input is not stored and shown back",
                        describe(&slot)
                    ),
                })
            }
            None => {
                return Ok(Verification::Inconclusive {
                    why: format!(
                        "the persistence probe for {} did not complete",
                        describe(&slot)
                    ),
                })
            }
        }

        // It persists. Only a browser can say whether the stored value *runs*.
        if nullhawk_browser::find_browser().is_none() {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "a value placed in {} persists to a later request, but no \
                     Chrome/Edge/Chromium was found to confirm whether it executes — \
                     install one or set NULLHAWK_BROWSER, and run again",
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

        let mut persisted_inertly = false;
        for payload in payloads(&fresh_token()) {
            let token = extract_token(&payload);
            match stored_and_ran(subject, lab, &mut cdp, &slot, &payload, &token).await {
                Ran::OnCleanLoad => {
                    return Ok(Verification::Reproduced {
                        note: format!(
                            "{} is stored and runs for a request that did not carry it: a \
                             payload placed in it executed on a later, clean load in the \
                             browser, setting a value only the storing request supplied. \
                             This is stored cross-site scripting",
                            describe(&slot)
                        ),
                        evidence: vec![from_exchange(subject), ran(subject, &payload)],
                    });
                }
                Ran::PersistedNotRun => persisted_inertly = true,
                Ran::No => {}
            }
        }

        Ok(if persisted_inertly {
            Verification::Refuted {
                note: format!(
                    "a payload placed in {} is stored and shown back, but did not execute \
                     on a clean load — the stored value is encoded on output. It is a \
                     stored input, not a stored script",
                    describe(&slot)
                ),
            }
        } else {
            Verification::Refuted {
                note: format!(
                    "no payload placed in {} both persisted and executed on a clean load",
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
                "Stored cross-site scripting in {} of {} {}",
                where_,
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "A value placed in {where_} of {} {} is stored and runs as script for a \
                 later request that did not carry it. {}\n\nExecution was confirmed by \
                 loading a clean, payload-free request in a real browser and reading back a \
                 value only the storing request set.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "A stored script runs for everyone who reaches the page that shows it, \
                     with no link to follow and nothing for the victim to do. It runs as \
                     each of them: reading their session, acting with their privileges, and \
                     spreading where the stored content is shown."
                .into(),
            remediation: "Encode stored values for the context they are shown in, at the \
                          point the page is built — not only when they are received. A value \
                          that was safe to store is not thereby safe to render; the encoding \
                          belongs at output. A Content-Security-Policy forbidding inline \
                          script is defence in depth."
                .into(),
            reproduction: format!(
                "Send {} {} once with {where_} carrying an `<img src=x onerror=…>` payload, \
                 then load the page again with a benign value and watch the stored payload \
                 run. `nullhawk poc <project> <finding>` compiles the requests.",
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
        // Stored XSS is the higher-consequence of the two — it needs no link and reaches
        // every viewer — so a confirmed one is High, as reflected is.
        Verification::Reproduced { .. } => Severity::High,
        _ => Severity::Low,
    }
}

/// Whether a value placed in the input survives to a later request that carries a
/// different, benign value there. `None` when a probe could not be sent.
async fn persists(
    subject: &Subject,
    lab: &dyn Lab,
    slot: &ObjectLocation,
    marker: &str,
) -> Option<bool> {
    // Store the marker.
    let mut store = subject.draft.clone();
    store.request = substitute(&store.request, slot, marker).ok()?;
    lab.experiment(&store, None).await.ok()?;

    // Fetch again with a benign value in the same input. A marker here was not sent now.
    let mut clean = subject.draft.clone();
    clean.request = substitute(&clean.request, slot, BENIGN).ok()?;
    let sent = lab.experiment(&clean, None).await.ok()?;
    let body = String::from_utf8_lossy(&sent.exchange.response.body);
    Some(body.contains(marker))
}

/// The outcome of storing a payload and loading a clean request in the browser.
enum Ran {
    /// The stored payload ran on the clean, payload-free load — stored XSS.
    OnCleanLoad,
    /// It persisted (was shown back) but did not execute — encoded on output.
    PersistedNotRun,
    /// Neither; nothing established for this payload.
    No,
}

/// Stores a payload through the input, then loads a clean request and reads the marker.
async fn stored_and_ran(
    subject: &Subject,
    lab: &dyn Lab,
    cdp: &mut nullhawk_browser::Cdp,
    slot: &ObjectLocation,
    payload: &str,
    token: &str,
) -> Ran {
    // Store: navigate with the payload in the input. Scope-checked like any send.
    let mut store = subject.draft.clone();
    store.request = match substitute(&store.request, slot, payload) {
        Ok(request) => request,
        Err(_) => return Ran::No,
    };
    if lab.would_leave_scope(&store, None) {
        return Ran::No;
    }
    let Some(store_url) = url_of(subject, &store.request.path) else {
        return Ran::No;
    };
    if cdp.navigate(&store_url, NAV_TIMEOUT).await.is_err() {
        return Ran::No;
    }

    // Verify: a clean load with a benign value. The marker here can only be stored.
    let mut clean = subject.draft.clone();
    clean.request = match substitute(&clean.request, slot, BENIGN) {
        Ok(request) => request,
        Err(_) => return Ran::No,
    };
    let Some(clean_url) = url_of(subject, &clean.request.path) else {
        return Ran::No;
    };
    if cdp.navigate(&clean_url, NAV_TIMEOUT).await.is_err() {
        return Ran::No;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let ran = matches!(
        cdp.eval(&format!("window.{MARKER} || ''")).await,
        Ok(value) if value.as_str() == Some(token)
    );
    if ran {
        return Ran::OnCleanLoad;
    }

    // Did the clean page at least show the payload text (persisted but inert)?
    let shown = matches!(
        cdp.eval("document.documentElement.outerHTML").await,
        Ok(value) if value.as_str().map(|h| h.contains(token)).unwrap_or(false)
    );
    if shown {
        Ran::PersistedNotRun
    } else {
        Ran::No
    }
}

/// The full URL to drive the browser to: the subject's own origin with the substituted
/// path (which carries the value in its query).
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

/// The token a payload carries, inside its `window.__nh_stored='…'` assignment.
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
            "stored `{payload}` through the input, then loaded a clean request in a browser \
             — the marker global carried back the token, so the stored value executed"
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

/// Raises one suspicion per query input — a work item at `Info`, settled by an experiment.
///
/// Query parameters only: the store has to be reachable by a safe (`GET`) request, which
/// the scheduler is willing to replay; a store behind a `POST` body is out of reach.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    inputs_in(&exchange.path, &exchange.request_headers)
        .into_iter()
        .filter(|slot| matches!(slot, ObjectLocation::Query { .. }))
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
    fn it_settles_only_stored_xss_suspicions() {
        assert!(StoredXss.handles(&raised(SETTLES)));
        assert!(!StoredXss.handles(&raised("input.xss")));
        assert!(!StoredXss.handles(&raised("input.reflected")));
    }

    #[test]
    fn it_is_active_and_a_settler() {
        let info = StoredXss.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn every_payload_sets_and_carries_its_token() {
        for p in payloads("tok42") {
            assert!(p.contains("window.__nh_stored='tok42'"), "{p}");
            assert_eq!(extract_token(&p), "tok42", "{p}");
        }
    }

    #[test]
    fn the_benign_verify_value_is_not_itself_a_payload() {
        // The clean, verifying request must carry something inert, so a marker on its
        // response can only have come from storage.
        assert!(!BENIGN.contains('<'));
        assert!(!BENIGN.contains(MARKER));
    }

    #[test]
    fn severity_is_high_for_a_confirmed_store_and_low_otherwise() {
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

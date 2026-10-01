//! `input.ssrf` — whether an input makes the server fetch a URL of the caller's choosing.
//!
//! The high-confidence, no-collaborator half of SSRF detection: point the input at a
//! resource only the server can reach — the cloud instance metadata service at
//! `169.254.169.254`, off-limits from the internet — and see its contents come back.
//!
//! ```text
//! url=http://169.254.169.254/latest/meta-data/   → ami-id  instance-id  iam/  …
//! url=<original>                                  → the ordinary page, no metadata.
//! ```
//!
//! The metadata index is a list of tokens (`ami-id`, `instance-id`,
//! `block-device-mapping/`, `security-credentials`) that a normal application response
//! has no reason to contain, so their appearance *from a request the caller aimed at an
//! internal address* is the proof. A control request to a benign external URL that does
//! not return them rules out a page that happened to mention one.
//!
//! It only reads, and only the metadata index — not the credential path beneath it. A
//! confirmed hit means the credential path is reachable; retrieving it is the tester's
//! call, not an automated scan's.
//!
//! # Blind SSRF, when a collaborator is configured
//!
//! Where the metadata trick reflects nothing, a *blind* fetch — one that makes the
//! request but reveals nothing in the response — is still caught if the run was given an
//! out-of-band collaborator ([`Lab::canary`]). The input is set to a collaborator URL
//! carrying an unguessable token; a callback bearing that token is proof the server made
//! the request, whatever its response said. Without a collaborator this case is honestly
//! reported as refuted rather than silently skipped.

use async_trait::async_trait;
use nullhawk_types::finding::{
    Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity,
};
use nullhawk_types::ids::InteractionId;
use nullhawk_types::inject::{inputs, inputs_in, substitute, value_at};
use nullhawk_types::object::ObjectLocation;
use nullhawk_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use nullhawk_types::Result;
use nullhawk_verify::{Canary, Lab};

use crate::{ActiveCheck, Budget, Subject};

/// How long to wait for a callback, and how often to check. A blind fetch is not
/// instantaneous — the target has to make its own request to the collaborator — so the
/// token is polled a handful of times before the sink is called quiet.
const CALLBACK_POLLS: usize = 6;
const CALLBACK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(750);

/// The check.
pub struct ServerSideRequestForgery;

const SETTLES: &str = "input.ssrf";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.ssrf"),
    name: "Server-side request forgery",
    version: "1.1.0",
    about: "whether an input makes the server fetch a caller-chosen URL — proven by the \
            contents of the cloud metadata endpoint coming back from an internal address",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Moderate,
};

const METADATA_URL: &str = "http://169.254.169.254/latest/meta-data/";
const CONTROL_URL: &str = "http://example.com/";

/// Tokens the EC2 metadata index lists that an ordinary page does not. Hyphenated and
/// specific on purpose, so a match is the metadata service and not prose.
const SIGNATURES: &[&str] = &[
    "ami-id",
    "instance-id",
    "instance-type",
    "block-device-mapping",
    "reservation-id",
    "security-credentials",
    "public-ipv4",
    "local-ipv4",
];

/// Parameter names that commonly name a resource the server will fetch. Used only to
/// decide whether an SSRF probe is worth a request — a match is not required to report.
const SINK_NAMES: &[&str] = &[
    "url",
    "uri",
    "link",
    "src",
    "href",
    "dest",
    "destination",
    "redirect",
    "redir",
    "return",
    "returnto",
    "next",
    "continue",
    "callback",
    "cb",
    "feed",
    "rss",
    "image",
    "img",
    "file",
    "path",
    "page",
    "domain",
    "host",
    "site",
    "target",
    "out",
    "load",
    "resource",
    "fetch",
    "proxy",
    "remote",
    "webhook",
    "source",
    "avatar",
    "preview",
];

#[async_trait]
impl ActiveCheck for ServerSideRequestForgery {
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
        let Some(slot) = slot_named(subject) else {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "the input this was raised about is no longer in {} {}, so there was \
                     nothing to point at a URL",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };
        let base = value_at(&subject.draft.request, &slot).unwrap_or_default();

        // Worth a request only if the parameter plausibly names something fetched: a
        // sink-like name, or a value that already looks like a URL or path. Spraying a
        // metadata URL at every numeric id would be requests spent to learn nothing.
        if !worth_probing(&slot, &base) {
            return Ok(Verification::Refuted {
                note: format!(
                    "{} is not a plausible request-forgery sink: its name is not one that \
                     names a fetched resource and its value is not URL-shaped",
                    describe(&slot)
                ),
            });
        }

        // A control: the untouched request must not already carry metadata tokens.
        let baseline = match probe(subject, lab, &slot, &base).await {
            Attempt::Answered(a) => a,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };
        if first_signature(&baseline.body).is_some() {
            return Ok(Verification::Inconclusive {
                why: "the untouched response already contains cloud-metadata tokens, so a \
                      probe match here would not be attributable to the input"
                    .into(),
            });
        }

        if budget.per_hypothesis < 2 {
            return Ok(Verification::Inconclusive {
                why: "the budget allowed no probe request".into(),
            });
        }

        let metadata = match probe(subject, lab, &slot, METADATA_URL).await {
            Attempt::Answered(a) => a,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };
        let Some(hit) = first_signature(&metadata.body) else {
            // The metadata trick reflects nothing here. A *blind* fetch — one that makes
            // the request but reveals nothing in its response — is invisible to every
            // in-band check, and is exactly what a collaborator exists to catch. Only
            // when the run has one: without a collaborator this is honestly Refuted, not
            // silently skipped.
            if let Some(canary) = lab.canary() {
                if let Some(verdict) = blind_ssrf(subject, lab, &slot, canary).await {
                    return Ok(verdict);
                }
            }
            return Ok(Verification::Refuted {
                note: format!(
                    "{} pointed at the cloud metadata address did not return its contents, \
                     and no out-of-band interaction arrived — this input does not fetch a \
                     caller-chosen URL, or the host is not on a metadata-bearing cloud",
                    describe(&slot),
                ),
            });
        };

        // Confirm the content came from the fetch, not the page: a benign external URL
        // returns no metadata tokens.
        if budget.per_hypothesis >= 3 {
            if let Attempt::Answered(control) = probe(subject, lab, &slot, CONTROL_URL).await {
                if first_signature(&control.body).is_none() {
                    return Ok(Verification::Reproduced {
                        note: format!(
                            "{} fetched the cloud metadata endpoint and returned its \
                             contents ({}); a benign external URL did not — the server \
                             requests a URL the input controls",
                            describe(&slot),
                            hit,
                        ),
                        evidence: vec![
                            from_exchange(subject),
                            Evidence::Comparison {
                                baseline: control.request,
                                variant: metadata.request,
                                difference: format!(
                                    "the metadata URL returned `{hit}`; an external URL did not"
                                ),
                            },
                        ],
                    });
                }
            }
        }

        Ok(Verification::Supported {
            support: Support::Distinctive,
            note: format!(
                "{} returned cloud-metadata contents ({}) when pointed at the internal \
                 metadata address; the confirming control was not sent",
                describe(&slot),
                hit,
            ),
            evidence: vec![
                from_exchange(subject),
                Evidence::Exchange {
                    request: metadata.request,
                    response: None,
                    note: format!("answered {} carrying `{hit}`", metadata.status),
                },
            ],
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
                "Server-side request forgery in {} of {} {}",
                where_,
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "A value placed in {where_} of {} {} makes the server issue a request to a \
                 URL the caller chooses, reaching an internal address the caller cannot. {}\
                 \n\nThe evidence records the internal URL and the metadata it returned.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "A server that fetches a caller-chosen URL can be turned against its own \
                     network: cloud instance metadata (and the credentials under it), \
                     internal services with no external authentication, and link-local \
                     addresses. Reaching the metadata endpoint, as here, is often a direct \
                     path to the host's cloud role."
                .into(),
            remediation: "Do not fetch caller-supplied URLs. Where a fetch is required, \
                          resolve the URL and allowlist the destination host, reject \
                          link-local and private ranges (including via DNS rebinding), and \
                          disable redirects. On AWS, require IMDSv2 so a bare GET cannot \
                          read metadata."
                .into(),
            reproduction: format!(
                "Send {} {} with {where_} set to the internal URL the evidence records and \
                 read the response. `nullhawk poc <project> <finding>` compiles the exact \
                 request.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-918".into()),
            owasp: Some("A10:2021 Server-Side Request Forgery".into()),
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
        // Reaching the metadata endpoint is a path to the host's cloud credentials.
        Verification::Reproduced { .. } => Severity::Critical,
        Verification::Supported {
            support: Support::Distinctive,
            ..
        } => Severity::High,
        _ => Severity::Low,
    }
}

/// Whether this input is worth an SSRF probe: a sink-like name, or a URL/path-shaped value.
fn worth_probing(slot: &ObjectLocation, base: &str) -> bool {
    let name = name_of(slot).to_ascii_lowercase();
    if SINK_NAMES.iter().any(|n| name == *n) {
        return true;
    }
    let v = base.trim();
    v.starts_with("http://")
        || v.starts_with("https://")
        || v.starts_with("//")
        || v.starts_with('/')
        || v.contains("://")
        || (v.contains('.') && !v.contains(' ') && v.len() >= 4)
}

fn first_signature(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    SIGNATURES
        .iter()
        .find(|needle| text.contains(**needle))
        .map(|needle| needle.to_string())
}

struct Answer {
    request: nullhawk_types::ids::RequestId,
    status: u16,
    body: Vec<u8>,
}

enum Attempt {
    Answered(Answer),
    Failed(String),
}

async fn probe(subject: &Subject, lab: &dyn Lab, slot: &ObjectLocation, value: &str) -> Attempt {
    let mut draft = subject.draft.clone();
    draft.request = match substitute(&draft.request, slot, value) {
        Ok(request) => request,
        Err(e) => return Attempt::Failed(format!("the payload could not be placed: {e}")),
    };
    match lab.experiment(&draft, None).await {
        Ok(sent) => Attempt::Answered(Answer {
            request: sent.id,
            status: sent.exchange.response.status,
            body: sent.exchange.response.body.to_vec(),
        }),
        Err(e) => Attempt::Failed(e.to_string()),
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

/// Plants a collaborator canary in the input and waits for a callback.
///
/// This is the blind case: the response may reveal nothing, so the proof is not in it.
/// The URL carries a token only this request minted, so an interaction bearing it is one
/// this request provoked — an unguessable token is what lets a self-hosted collaborator
/// on a public host tell a real hit from background noise.
///
/// Returns `None` — not a refutation — when the probe could not be sent or nothing had
/// called back within the polling window: a later, slower callback is possible, and
/// "nothing yet" is not "nothing ever". The caller turns that into the honest Refuted.
async fn blind_ssrf(
    subject: &Subject,
    lab: &dyn Lab,
    slot: &ObjectLocation,
    canary: Canary,
) -> Option<Verification> {
    let request = match probe(subject, lab, slot, &canary.url).await {
        Attempt::Answered(answer) => answer.request,
        Attempt::Failed(_) => return None,
    };

    for _ in 0..CALLBACK_POLLS {
        tokio::time::sleep(CALLBACK_INTERVAL).await;
        let Ok(interactions) = lab.interactions(&canary.token).await else {
            continue;
        };
        if let Some(hit) = interactions.into_iter().next() {
            return Some(Verification::Reproduced {
                note: format!(
                    "{} made the server fetch a URL the input controls: a {} interaction \
                     reached the collaborator from {}, carrying the token planted only in \
                     this request. The response revealed nothing — this is a blind \
                     server-side request forgery, proven by the callback rather than the \
                     page",
                    describe(slot),
                    hit.protocol,
                    hit.source,
                ),
                evidence: vec![
                    from_exchange(subject),
                    Evidence::Exchange {
                        request,
                        response: None,
                        note: format!("the input was set to the collaborator URL {}", canary.url),
                    },
                    Evidence::OutOfBand {
                        request,
                        interaction: InteractionId::new(),
                        protocol: hit.protocol,
                    },
                ],
            });
        }
    }
    None
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

    fn query(name: &str) -> ObjectLocation {
        ObjectLocation::Query {
            name: name.into(),
            occurrence: 0,
        }
    }

    #[test]
    fn it_settles_only_ssrf_suspicions() {
        assert!(ServerSideRequestForgery.handles(&raised(SETTLES)));
        assert!(!ServerSideRequestForgery.handles(&raised("input.sqli")));
        assert!(!ServerSideRequestForgery.handles(&raised("input.reflected")));
    }

    #[test]
    fn it_is_active_and_a_settler() {
        let info = ServerSideRequestForgery.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn sink_names_and_url_values_are_worth_probing() {
        assert!(worth_probing(&query("url"), "1"));
        assert!(worth_probing(&query("redirect"), "x"));
        assert!(worth_probing(&query("q"), "https://example.com/x"));
        assert!(worth_probing(&query("q"), "/some/path"));
        assert!(!worth_probing(&query("id"), "1000"));
        assert!(worth_probing(&query("page"), "1000")); // "page" is a sink name
    }

    #[test]
    fn metadata_tokens_are_recognised_but_prose_is_not() {
        let index = b"ami-id\nami-launch-index\nblock-device-mapping/\ninstance-id\niam/\n";
        assert_eq!(first_signature(index).as_deref(), Some("ami-id"));
        assert!(first_signature(b"<html>Welcome to our instance of the app</html>").is_none());
    }

    #[test]
    fn reproduced_ssrf_to_metadata_is_critical() {
        assert_eq!(
            severity_for(&Verification::Reproduced {
                note: String::new(),
                evidence: Vec::new()
            }),
            Severity::Critical
        );
        assert_eq!(
            severity_for(&Verification::Supported {
                support: Support::Distinctive,
                note: String::new(),
                evidence: Vec::new()
            }),
            Severity::High
        );
    }
}

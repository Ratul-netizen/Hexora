//! `cors.reflection` — does the application allow *any* origin, or one origin?
//!
//! M13.2's `cors.configuration` sees a response whose `Access-Control-Allow-Origin`
//! equals the `Origin` the request sent, with credentials allowed. That is consistent
//! with two applications:
//!
//! ```text
//! reflecting   Origin: https://evil.example  →  Allow-Origin: https://evil.example
//! allowlisted  Origin: https://evil.example  →  Allow-Origin: https://app.example
//! ```
//!
//! The first is a serious finding. The second is correct behaviour. One captured
//! exchange cannot tell them apart, because in the captured exchange the origin *was*
//! the allowed one — so the passive check raises a hypothesis and files nothing.
//!
//! This settles it with the one thing that can: a request carrying an origin that
//! cannot be on anybody's allowlist.
//!
//! # The probe origin
//!
//! `https://nullhawk-probe.invalid`. `.invalid` is reserved by RFC 2606 and is
//! guaranteed never to resolve, so the value cannot name a real site, cannot be
//! mistaken for one in a log, and cannot cause a browser anywhere to treat some real
//! domain as trusted. Nothing is sent *to* it — an `Origin` is a header on a request
//! that still goes to the target host.
//!
//! # Twice, with different origins
//!
//! A server that echoes one arbitrary origin is very likely to echo any. "Very likely"
//! is a lead, and this is an active check with a budget, so it asks again with a
//! second unrelated origin. Two reflections of two different arbitrary values is the
//! same experiment repeated with a different input, which is what
//! [`Verification::Reproduced`] means — not the same request sent twice.
//!
//! # The answer that is not a refutation
//!
//! A captured request carries the session it was captured with, and sessions expire.
//! If the probe comes back without the CORS headers the capture had, the application
//! has not been shown to be safe — the *experiment* failed. That is
//! [`Verification::Inconclusive`], and keeping it apart from [`Verification::Refuted`]
//! is the whole difference between "this was fixed" and "my token ran out", which is
//! the mistake M12.8 exists to prevent at the engagement level and this prevents at
//! the request level.

use async_trait::async_trait;
use nullhawk_types::finding::{
    Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity,
};
use nullhawk_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct OriginReflection;

/// The check whose hypotheses this one exists to answer.
const SETTLES: &str = "cors.configuration";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("cors.reflection"),
    name: "Origin reflection",
    version: "1.1.0",
    about: "whether an application reflects any Origin it is sent — outright, or past a broken matcher via a null origin or a prefix trick — with credentials allowed",
    mode: DetectorMode::Active,
    observes: false,
    // It settles other checks' suspicions and raises none of its own.
    hypothesizes: false,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Moderate,
};

/// Origins that cannot be on anybody's allowlist.
///
/// `.invalid` is reserved by RFC 2606: it never resolves, so neither value can name a
/// real site or be mistaken for one by somebody reading a server log afterwards.
const PROBES: [&str; 2] = [
    "https://nullhawk-probe.invalid",
    "https://nullhawk-second-probe.invalid",
];

/// The attacker-controlled domain the prefix-match probe is built under. An attacker who
/// owned it could create the subdomain `<trusted-origin>.evil-nullhawk.invalid`, which is
/// exactly what a matcher comparing the start of the Origin string would wrongly accept —
/// but `.invalid` cannot actually be registered, so the probe names nothing real.
const EVIL: &str = "evil-nullhawk.invalid";

#[async_trait]
impl ActiveCheck for OriginReflection {
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
        let host = subject.exchange.host.clone();

        let first = match probe(subject, lab, PROBES[0]).await {
            Probe::Answered(answer) => answer,
            Probe::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };

        // The application no longer answers the way it did when this was captured.
        // Not a refutation: an expired session looks exactly like a fixed application
        // from here, and reporting one as the other is the failure this check is most
        // likely to commit.
        let Some(allowed) = first.allow_origin.clone() else {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "{host} answered without an Access-Control-Allow-Origin header this \
                     time, though the captured exchange had one (status {}). The \
                     experiment did not run — the credential the request was captured \
                     with may no longer be valid — so nothing is established either way",
                    first.status
                ),
            });
        };

        if allowed == "*" {
            return Ok(Verification::Refuted {
                note: format!(
                    "{host} answered a probe origin with Access-Control-Allow-Origin: * \
                     rather than echoing it, so it does not reflect. A wildcard with \
                     credentials is its own issue and is what cors.configuration \
                     reports; it is not this one"
                ),
            });
        }

        if allowed != PROBES[0] {
            // An allowlist is present — it answered with an origin of its own choosing
            // rather than the arbitrary one. But a matcher can be present and broken: the
            // common mistakes are trusting a null origin and comparing only the *start* of
            // the Origin string. Try the origins those two let through before concluding
            // the allowlist holds, because an allowlist that can be walked past is a worse
            // finding than plain reflection, not a safe result.
            // probe1 has already spent one request; the rest of the budget is for edges.
            // Named so it does not shadow `allowed`, the Allow-Origin value the notes cite.
            let edge_budget = budget.per_hypothesis.max(1).saturating_sub(1);
            for (class, origin) in edge_origins(subject.exchange.secure, &host)
                .into_iter()
                .take(edge_budget)
            {
                let edge = match probe(subject, lab, &origin).await {
                    Probe::Answered(answer) => answer,
                    Probe::Failed(_) => continue,
                };
                if edge.allow_origin.as_deref() == Some(origin.as_str()) && edge.credentialed {
                    return Ok(Verification::Supported {
                        support: Support::Distinctive,
                        note: format!(
                            "{host} answered an arbitrary origin with {allowed} of its own \
                             choosing, but echoed {origin} — {class} — with \
                             Access-Control-Allow-Credentials: true. A matcher is present \
                             and lets through an origin an attacker controls"
                        ),
                        evidence: evidence(subject, &first, Some(&edge)),
                    });
                }
            }
            return Ok(Verification::Refuted {
                note: format!(
                    "{host} was sent Origin: {} and answered \
                     Access-Control-Allow-Origin: {allowed}; a null origin and a \
                     prefix-match origin were refused too. An allowlist is present and was \
                     not bypassed by the tricks tried",
                    PROBES[0]
                ),
            });
        }

        if !first.credentialed {
            // Reflection without credentials is a much weaker thing: a cross-origin
            // read of an unauthenticated response is what a public API is.
            return Ok(Verification::Supported {
                support: Support::Consistent,
                note: format!(
                    "{host} echoed the probe origin, but did not allow credentials on \
                     that response. A reflected origin without credentials does not \
                     give another site a way to read this one using a visitor's session"
                ),
                evidence: evidence(subject, &first, None),
            });
        }

        // One arbitrary origin echoed is already strong. A second, unrelated one is
        // the same experiment with a different input — which is what makes it
        // reproduced rather than repeated.
        if budget.per_hypothesis < 2 {
            return Ok(Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "{host} echoed {} with credentials allowed. The budget allowed one \
                     request, so it was not asked a second time with a different origin",
                    PROBES[0]
                ),
                evidence: evidence(subject, &first, None),
            });
        }

        let second = match probe(subject, lab, PROBES[1]).await {
            Probe::Answered(answer) => answer,
            Probe::Failed(why) => {
                return Ok(Verification::Supported {
                    support: Support::Distinctive,
                    note: format!(
                        "{host} echoed {} with credentials allowed. The confirming \
                         request with a second origin did not complete ({why}), so this \
                         rests on one experiment",
                        PROBES[0]
                    ),
                    evidence: evidence(subject, &first, None),
                })
            }
        };

        if second.allow_origin.as_deref() == Some(PROBES[1]) && second.credentialed {
            return Ok(Verification::Reproduced {
                note: format!(
                    "{host} echoed two unrelated origins that cannot be on any \
                     allowlist — {} and {} — each with Access-Control-Allow-Credentials: \
                     true. It reflects whatever Origin it is sent",
                    PROBES[0], PROBES[1]
                ),
                evidence: evidence(subject, &first, Some(&second)),
            });
        }

        Ok(Verification::Supported {
            support: Support::Distinctive,
            note: format!(
                "{host} echoed {} with credentials allowed, but answered {} differently \
                 ({}). One of the two arbitrary origins was reflected, which is not a \
                 pattern two experiments agree on",
                PROBES[0],
                PROBES[1],
                second
                    .allow_origin
                    .clone()
                    .unwrap_or_else(|| "with no Access-Control-Allow-Origin".into()),
            ),
            evidence: evidence(subject, &first, Some(&second)),
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        Writeup {
            target: subject.target,
            // Names the endpoint. Two findings on one host that read identically are
            // two a triager has to open to tell apart.
            title: format!(
                "Any origin can read {} {} with a visitor's session",
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "{} was sent an Origin header naming a domain that cannot belong to any \
                 legitimate site, and reflected it into Access-Control-Allow-Origin with \
                 Access-Control-Allow-Credentials: true. {}",
                subject.exchange.url,
                verification.note(),
            ),
            impact: "Any website a logged-in user visits can make requests to this \
                     application with that user's cookies attached and read the \
                     responses. What that is worth is whatever these endpoints return \
                     and whatever they accept — a reflected origin turns every \
                     same-origin protection on this host into no protection at all for \
                     anybody who has visited another site."
                .into(),
            remediation: "Compare the request's Origin against a fixed list of allowed \
                          origins on the server and answer with the matched entry, \
                          never with the value that was sent. If the list is empty, do \
                          not send the header. Send Vary: Origin whenever the answer \
                          depends on the request, and allow credentials only for \
                          origins that genuinely need them."
                .into(),
            reproduction: format!(
                "Send {} {} with an Origin header naming a domain outside any allowlist — \
                 `{}`, or `Origin: null`, or `https://<this-host>.{}` — and read \
                 Access-Control-Allow-Origin and Access-Control-Allow-Credentials on the \
                 response. `nullhawk poc <project> <finding>` compiles the exact requests \
                 that were made.",
                subject.exchange.method, subject.exchange.url, PROBES[0], EVIL,
            ),
            cwe: Some("CWE-942".into()),
            owasp: Some("A05:2021 Security Misconfiguration".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: Severity::High,
            location: Some(Location {
                part: MessagePart::Header,
                name: "Access-Control-Allow-Origin".into(),
            }),
        }
    }
}

/// The path part of a URL, for a title that names an endpoint rather than a host.
fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("/")
}

/// Origins a broken matcher lets through, built from the request's own scheme and host.
///
/// * `null` — the value a sandboxed iframe or a redirected request sends; an application
///   that trusts it hands every such context a credentialed cross-origin read.
/// * `<scheme>://<host>.evil-nullhawk.invalid` — the trusted origin with an attacker
///   suffix. A matcher that checks only that the Origin *starts with* the trusted value
///   accepts it, and an attacker who owned the suffix domain could serve from exactly
///   there.
fn edge_origins(secure: bool, host: &str) -> Vec<(&'static str, String)> {
    let scheme = if secure { "https" } else { "http" };
    vec![
        ("a null origin", "null".to_string()),
        ("a prefix-match bypass", format!("{scheme}://{host}.{EVIL}")),
    ]
}

/// What one probe established.
struct Answer {
    request: nullhawk_types::ids::RequestId,
    status: u16,
    allow_origin: Option<String>,
    credentialed: bool,
    sent: String,
}

enum Probe {
    Answered(Answer),
    Failed(String),
}

/// Sends the captured request again with a different `Origin`.
///
/// Everything else about the request is left exactly as it was captured, including its
/// credential: whether a *credentialed* cross-origin read is allowed is the question,
/// and stripping the session would answer a different one.
async fn probe(subject: &Subject, lab: &dyn Lab, origin: &str) -> Probe {
    let mut draft = subject.draft.clone();
    draft.request.headers.set("Origin", origin);

    let sent = match lab.experiment(&draft, None).await {
        Ok(sent) => sent,
        Err(e) => return Probe::Failed(e.to_string()),
    };

    let headers = &sent.exchange.response.headers;
    let allow_origin = headers
        .get("access-control-allow-origin")
        .map(|header| header.value_lossy().trim().to_string());
    let credentialed = headers
        .get("access-control-allow-credentials")
        .map(|header| header.value_lossy().trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    Probe::Answered(Answer {
        request: sent.id,
        status: sent.exchange.response.status,
        allow_origin,
        credentialed,
        sent: origin.to_string(),
    })
}

/// The traffic behind the claim: the capture, and each probe.
///
/// The captured exchange is cited as well as the probes, because "here is what you
/// were already serving" and "here is what it did when I asked rudely" are different
/// halves of the argument and a reader will want both.
fn evidence(subject: &Subject, first: &Answer, second: Option<&Answer>) -> Vec<Evidence> {
    let mut evidence = vec![Evidence::Exchange {
        request: subject.exchange.id,
        response: None,
        note: format!(
            "the captured exchange this was raised from: {} {}",
            subject.exchange.method, subject.exchange.url
        ),
    }];

    for answer in [Some(first), second].into_iter().flatten() {
        evidence.push(Evidence::Exchange {
            request: answer.request,
            response: None,
            note: format!(
                "sent with Origin: {} — answered {} with Access-Control-Allow-Origin: {}{}",
                answer.sent,
                answer.status,
                answer
                    .allow_origin
                    .clone()
                    .unwrap_or_else(|| "(absent)".into()),
                if answer.credentialed {
                    " and credentials allowed"
                } else {
                    ""
                },
            ),
        });
    }
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_settles_the_passive_checks_hypothesis_and_no_others() {
        let raised = |detector: &str| Hypothesis {
            detector: detector.into(),
            claim: "something".into(),
            source_request: nullhawk_types::ids::RequestId::new(),
            location: None,
            provisional_severity: Severity::High,
        };
        assert!(OriginReflection.handles(&raised("cors.configuration")));
        assert!(!OriginReflection.handles(&raised("headers.security")));
        assert!(!OriginReflection.handles(&raised("authz.cross_identity")));
    }

    #[test]
    fn the_probe_origins_can_never_name_a_real_site() {
        // RFC 2606 reserves `.invalid`. A probe that named a domain somebody could
        // register would eventually hand that registrant a trusted origin somewhere.
        for probe in PROBES {
            assert!(probe.ends_with(".invalid"), "{probe}");
        }
        assert_ne!(
            PROBES[0], PROBES[1],
            "two probes must differ to be a retest"
        );
    }

    #[test]
    fn the_edge_origins_are_a_null_and_a_prefix_trick_that_name_nothing_real() {
        let edges = edge_origins(true, "app.example.com");
        let origins: Vec<&str> = edges.iter().map(|(_, o)| o.as_str()).collect();
        assert!(origins.contains(&"null"), "{origins:?}");
        // The prefix-match probe is the trusted origin with an attacker suffix, so a
        // startsWith matcher accepts it — but it is under `.invalid`, so it is not real.
        assert!(
            origins.contains(&"https://app.example.com.evil-nullhawk.invalid"),
            "{origins:?}"
        );
        for (_, origin) in &edges {
            assert!(
                origin == "null" || origin.ends_with(".invalid"),
                "{origin} could name a registrable domain"
            );
        }
    }

    #[test]
    fn a_cleartext_host_builds_a_cleartext_prefix_probe() {
        // The probe mirrors the request's scheme, so it tests the matcher as it is reached.
        let edges = edge_origins(false, "intranet.local");
        assert!(edges
            .iter()
            .any(|(_, o)| o == "http://intranet.local.evil-nullhawk.invalid"));
    }

    #[test]
    fn it_reports_itself_as_active_and_as_a_settler() {
        let info = OriginReflection.about();
        assert_eq!(info.version, "1.1.0");
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(
            info.sends(),
            "it must appear in `nullhawk detectors --sending`"
        );
        assert!(
            !info.hypothesizes,
            "it settles suspicions, it does not raise them"
        );
        assert_eq!(
            info.settles,
            Some(SETTLES),
            "the registry has to be able to say this suspicion has somebody to answer it"
        );
        assert!(info.produces_something());
    }
}

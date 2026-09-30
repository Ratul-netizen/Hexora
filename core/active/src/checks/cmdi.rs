//! `input.cmdi` — whether an input is run as part of a shell command.
//!
//! Command injection has the same clean tell template injection does, and this check is
//! built the same way: it does not look for a marker coming back — a marker coming back
//! is reflection — it looks for the *shell* having computed something the input asked
//! for, and confirms with a second, different sum.
//!
//! ```text
//! x; echo $((9973*8009))   → 79873157   the shell did the arithmetic. One coincidence, maybe.
//! x; echo $((9973*8011))   → 79893103   it did the second one too, tracking the expression.
//! ```
//!
//! `$((…))` is POSIX shell arithmetic: only a shell evaluates it. If the literal
//! `$((9973*8009))` comes back unchanged, the input was reflected, not run — echo.rs's
//! territory, not this one. If the product `79873157` comes back and the literal does
//! not, a shell expanded it, which it does only for a string it is executing. Requiring
//! a *second* product rules out a page that merely happened to contain the first.
//!
//! # Nothing here has a side effect
//!
//! Every payload is `echo` of an arithmetic expansion. It writes nothing, deletes
//! nothing and reaches no network — the proof is that the shell did a multiplication,
//! which is as harmless as a computation gets. The scheduler already replays only the
//! safe methods, so this never rides on a request that changes data.
//!
//! # Reflected output only
//!
//! This settles the cases where the command's output reaches the response. A sink whose
//! output goes nowhere is *blind*, and blind command injection needs an out-of-band
//! channel to confirm — which this build does not yet wire into the lab. Until it does,
//! a blind sink here reads as [`Verification::Refuted`]: the experiment ran and the
//! product did not come back. That is honest about what was tested, not a claim the sink
//! is safe.

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
pub struct OsCommandInjection;

const SETTLES: &str = "input.cmdi";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.cmdi"),
    name: "OS command injection",
    version: "1.0.0",
    about: "whether an input is run by a shell — proven by the shell evaluating an \
            arithmetic expansion the input carries, confirmed by a second sum",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
};

/// Two large factors and two multipliers, so the products are eight-digit numbers a page
/// has no ordinary reason to hold, and the two differ. Distinct from the SSTI check's
/// factors so a marker in a log names which check put it there.
const A: u64 = 9973;
const B1: u64 = 8009;
const B2: u64 = 8011;

/// How an injected value might break out of the command it landed in, and what to call
/// it. Each wraps the payload command; the base value is kept in front so a sink that
/// uses it (a filename, a host) still parses up to the breakout.
///
/// `prefix` opens the breakout, `suffix` closes it — empty for the separators that run
/// what follows to end of line, paired for the substitutions.
const CONTEXTS: &[(&str, &str, &str)] = &[
    ("a `;` command separator", "; ", ""),
    ("a `|` pipe", "| ", ""),
    ("an `&` operator", "& ", ""),
    ("`$( )` command substitution", "$(", ")"),
    ("a backtick substitution", "`", "`"),
    ("a newline", "\n", ""),
];

#[async_trait]
impl ActiveCheck for OsCommandInjection {
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
                     nothing to run",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };
        let base = value_at(&subject.draft.request, &slot).unwrap_or_default();
        let product1 = (A * B1).to_string();
        let product2 = (A * B2).to_string();
        let arith1 = format!("$(({A}*{B1}))");
        let arith2 = format!("$(({A}*{B2}))");

        let mut sent = 0usize;
        for (context, prefix, suffix) in CONTEXTS {
            if sent + 2 > budget.per_hypothesis.max(1) {
                break;
            }
            let first_payload = format!("{base}{prefix}echo {arith1}{suffix}");
            let Some(first) = probe(subject, lab, &slot, &first_payload).await else {
                continue;
            };
            sent += 1;

            // The shell evaluated the expansion only if its *result* is present and the
            // expansion itself is not — the latter would mean it came back as text.
            let ran = first.body_has(&product1) && !first.body_has(&arith1);
            if !ran {
                continue;
            }

            // Confirm: a different sum. A page that happened to contain the first product
            // will not contain the second one too.
            let second_payload = format!("{base}{prefix}echo {arith2}{suffix}");
            let Some(second) = probe(subject, lab, &slot, &second_payload).await else {
                return Ok(Verification::Supported {
                    support: Support::Distinctive,
                    note: format!(
                        "{} is run by a shell through {context}: `echo {arith1}` came back \
                         as {product1}. The confirming sum could not be sent",
                        describe(&slot),
                    ),
                    evidence: vec![from_exchange(subject), answered(&first, &first_payload)],
                });
            };

            if second.body_has(&product2) && !second.body_has(&arith2) {
                return Ok(Verification::Reproduced {
                    note: format!(
                        "{} is run by a shell through {context}: `echo {arith1}` came back \
                         as {product1} and `echo {arith2}` as {product2}, so the response \
                         evaluates the expansion the input carries",
                        describe(&slot),
                    ),
                    evidence: vec![
                        from_exchange(subject),
                        Evidence::Comparison {
                            baseline: first.request,
                            variant: second.request,
                            difference: format!(
                                "`echo {arith1}` ran as {product1}; `echo {arith2}` ran as \
                                 {product2}"
                            ),
                        },
                    ],
                });
            }

            return Ok(Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "{} ran `echo {arith1}` as {product1} through {context}, but a second \
                     sum did not — one experiment, not two agreeing ones",
                    describe(&slot),
                ),
                evidence: vec![from_exchange(subject), answered(&first, &first_payload)],
            });
        }

        Ok(Verification::Refuted {
            note: format!(
                "no shell evaluated an arithmetic payload in {}: it came back unchanged or \
                 absent, so either the input is not run by a shell, or it is run but its \
                 output does not reach the response — a blind sink this in-band check \
                 cannot settle",
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
                "OS command injection in {} of {} {}",
                where_,
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "A value placed in {where_} of {} {} is run by a server-side shell, which \
                 evaluated an arithmetic expansion the input carried. {}\n\nThe evidence \
                 records the two sums and their computed results.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "An input a shell evaluates is arbitrary command execution on the \
                     server as the account the application runs as: reading and writing \
                     files it can reach, making outbound connections, and moving laterally \
                     from there. The arithmetic is only the proof; the same channel runs \
                     any command."
                .into(),
            remediation: "Do not build shell command lines from input. Call the program \
                          directly with an argument vector (execve-style) so nothing is \
                          parsed by a shell, and pass the value as one argument. Where a \
                          shell is unavoidable, an allowlist of exact permitted values is \
                          the only reliable defence; escaping is not."
                .into(),
            reproduction: format!(
                "Send {} {} with {where_} carrying the `echo $((a*b))` payloads the \
                 evidence records and read the computed products back. `nullhawk poc \
                 <project> <finding>` compiles the exact requests.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-78".into()),
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
        // Reproduced command execution is the top of the ladder: it is arbitrary code on
        // the server, so Critical is exactly right.
        Verification::Reproduced { .. } => Severity::Critical,
        Verification::Supported {
            support: Support::Distinctive,
            ..
        } => Severity::High,
        _ => Severity::Low,
    }
}

struct Answer {
    request: nullhawk_types::ids::RequestId,
    status: u16,
    body: Vec<u8>,
}

impl Answer {
    fn body_has(&self, needle: &str) -> bool {
        String::from_utf8_lossy(&self.body).contains(needle)
    }
}

/// Places a payload and returns what came back, or nothing if it could not be sent — a
/// failed probe just moves on to the next breakout rather than settling anything.
async fn probe(
    subject: &Subject,
    lab: &dyn Lab,
    slot: &ObjectLocation,
    value: &str,
) -> Option<Answer> {
    let mut draft = subject.draft.clone();
    draft.request = substitute(&draft.request, slot, value).ok()?;
    let sent = lab.experiment(&draft, None).await.ok()?;
    Some(Answer {
        request: sent.id,
        status: sent.exchange.response.status,
        body: sent.exchange.response.body.to_vec(),
    })
}

fn answered(answer: &Answer, payload: &str) -> Evidence {
    Evidence::Exchange {
        request: answer.request,
        response: None,
        note: format!("payload `{payload}` — answered {}", answer.status),
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
    fn it_settles_only_command_injection_suspicions() {
        assert!(OsCommandInjection.handles(&raised(SETTLES)));
        assert!(!OsCommandInjection.handles(&raised("input.ssti")));
        assert!(!OsCommandInjection.handles(&raised("input.sqli")));
    }

    #[test]
    fn it_is_active_and_a_settler() {
        let info = OsCommandInjection.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn the_products_are_distinctive_eight_digit_and_differ() {
        // Eight-digit products a page has no ordinary reason to contain, and two that
        // differ so a second sum confirms the first was not a coincidence.
        assert_eq!(A * B1, 79_873_757);
        assert_eq!(A * B2, 79_893_703);
        assert_ne!(A * B1, A * B2);
        // Distinct from the SSTI check's factors, so a marker in a log names which check
        // put it there and the two never collide.
        assert_ne!(A, 7919);
    }

    #[test]
    fn reproduced_command_injection_is_critical() {
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
        assert_eq!(
            severity_for(&Verification::Refuted {
                note: String::new()
            }),
            Severity::Low
        );
    }

    #[test]
    fn the_computed_product_is_the_tell_not_the_expansion() {
        // The whole distinction from reflection: the shell's result present, the
        // expansion text absent, is execution; the expansion coming back is reflection.
        let ran = Answer {
            request: nullhawk_types::ids::RequestId::new(),
            status: 200,
            body: format!("<p>ping x: {}</p>", A * B1).into_bytes(),
        };
        assert!(ran.body_has(&(A * B1).to_string()));
        assert!(!ran.body_has(&format!("$(({A}*{B1}))")));

        let reflected = Answer {
            request: nullhawk_types::ids::RequestId::new(),
            status: 200,
            body: format!("<p>ping x; echo $(({A}*{B1}))</p>").into_bytes(),
        };
        // The reflected expansion is present, so `ran` would be false for it.
        assert!(reflected.body_has(&format!("$(({A}*{B1}))")));
        assert!(!reflected.body_has(&(A * B1).to_string()));
    }
}

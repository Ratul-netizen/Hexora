//! `input.ssti` — whether an input is evaluated as a server-side template.
//!
//! Template injection has a clean tell that reflection does not: the server does
//! arithmetic the input asked for. So this does not look for the payload coming back —
//! it looks for the payload's *result*, and confirms with a second, different sum:
//!
//! ```text
//! {{7919*8443}}   → 66860117   evaluated. But so might one coincidence.
//! {{7919*8447}}   → 66891793   evaluated too, tracking the expression. Now it is proven.
//! ```
//!
//! The factors are large and fixed, so the products are eight-digit numbers a page has
//! no ordinary reason to contain, and requiring *two* different products to appear rules
//! out a coincidental match. When the literal `{{7919*8443}}` comes back unchanged
//! instead, the input is reflected, not evaluated — a different check's territory.
//!
//! It reads only: multiplication has no side effect. Which delimiters evaluated names the
//! family of engine (Jinja/Twig, Freemarker/EL, ERB, …), which is where exploitation
//! starts, but this reports the fact, not the exploit.

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
pub struct TemplateInjection;

const SETTLES: &str = "input.ssti";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("input.ssti"),
    name: "Server-side template injection",
    version: "1.0.0",
    about: "whether an input is evaluated as a template — proven by the server computing \
            an arithmetic result the input asked for, confirmed by a second sum",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
};

/// Two large factors and two multipliers, so the products are distinctive and differ.
const A: u64 = 7919;
const B1: u64 = 8443;
const B2: u64 = 8447;

/// Delimiter families, and the engines they point at. `{{…}}` is Jinja2, Twig,
/// Nunjucks, Angular; `${…}` is Freemarker, JSP EL, Thymeleaf; and so on.
const SYNTAXES: &[(&str, &str, &str)] = &[
    ("Jinja2 / Twig / Nunjucks", "{{", "}}"),
    ("Freemarker / EL / Thymeleaf", "${", "}"),
    ("Ruby ERB / EJS", "<%= ", " %>"),
    ("Smarty / Mako", "{", "}"),
];

#[async_trait]
impl ActiveCheck for TemplateInjection {
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
                     nothing to evaluate",
                    subject.exchange.method, subject.exchange.url
                ),
            });
        };
        let base = value_at(&subject.draft.request, &slot).unwrap_or_default();
        let product1 = (A * B1).to_string();
        let product2 = (A * B2).to_string();

        let mut sent = 0usize;
        for (engine, open, close) in SYNTAXES {
            if sent + 2 > budget.per_hypothesis.max(1) {
                break;
            }
            let first_payload = format!("{base}{open}{A}*{B1}{close}");
            let Some(first) = probe(subject, lab, &slot, &first_payload).await else {
                continue;
            };
            sent += 1;
            let literal = format!("{open}{A}*{B1}{close}");
            let evaluated = first.body_has(&product1) && !first.body_has(&literal);
            if !evaluated {
                continue;
            }

            // Confirm: a different sum. A page that happened to contain the first product
            // will not contain the second one too.
            let second_payload = format!("{base}{open}{A}*{B2}{close}");
            let Some(second) = probe(subject, lab, &slot, &second_payload).await else {
                return Ok(Verification::Supported {
                    support: Support::Distinctive,
                    note: format!(
                        "{} was evaluated as a {} template ({A}*{B1} came back as \
                         {product1}); the confirming sum could not be sent",
                        describe(&slot),
                        engine
                    ),
                    evidence: vec![from_exchange(subject), answered(&first, &first_payload)],
                });
            };

            if second.body_has(&product2) {
                return Ok(Verification::Reproduced {
                    note: format!(
                        "{} is evaluated as a {} template: {A}*{B1} came back as {product1} \
                         and {A}*{B2} came back as {product2}, so the response computes the \
                         expression the input carries",
                        describe(&slot),
                        engine
                    ),
                    evidence: vec![
                        from_exchange(subject),
                        Evidence::Comparison {
                            baseline: first.request,
                            variant: second.request,
                            difference: format!(
                                "{A}*{B1} rendered as {product1}; {A}*{B2} rendered as \
                                 {product2}"
                            ),
                        },
                    ],
                });
            }

            return Ok(Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "{} rendered {A}*{B1} as {product1} in a {} template, but a second sum \
                     did not render — one experiment, not two agreeing ones",
                    describe(&slot),
                    engine
                ),
                evidence: vec![from_exchange(subject), answered(&first, &first_payload)],
            });
        }

        Ok(Verification::Refuted {
            note: format!(
                "no template delimiters evaluated in {}: an arithmetic payload came back \
                 unchanged or absent, so the input is not rendered as a template",
                describe(&slot),
            ),
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        let slot = slot_named(subject);
        let where_ = slot.as_ref().map(describe).unwrap_or_else(|| "an input".into());

        Writeup {
            target: subject.target,
            title: format!(
                "Server-side template injection in {} of {} {}",
                where_,
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "A value placed in {where_} of {} {} is rendered by a server-side template \
                 engine, which evaluated arithmetic the input carried. {}\n\nThe evidence \
                 records the two sums and their computed results.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "An input evaluated by a template engine is a step from arithmetic to \
                     the engine's object graph, and on most engines from there to reading \
                     files, environment and — through a reachable method — command \
                     execution on the server. How far depends on the engine and its \
                     sandbox; the evaluation is the foothold."
                .into(),
            remediation: "Never render user input as a template. Pass it as data to a fixed \
                          template (context variables), not concatenated into the template \
                          source. Where a templating feature is intentional, use a sandboxed \
                          engine and a strict allowlist of accessible attributes."
                .into(),
            reproduction: format!(
                "Send {} {} with {where_} carrying the template payloads the evidence \
                 records and read the computed results. `nullhawk poc <project> <finding>` \
                 compiles the exact requests.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-1336".into()),
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
        // Reproduced SSTI is the highest-consequence input finding here: it is usually a
        // path to code execution, so it is the one place a Critical is defensible.
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
        // A number match tolerates a comma-grouped or entity-split render only loosely;
        // exact substring is enough for these distinctive eight-digit products.
        String::from_utf8_lossy(&self.body).contains(needle)
    }
}

/// Places a payload and returns what came back, or nothing if it could not be sent —
/// the reason is not needed here, because a failed probe just moves on to the next
/// delimiter family rather than settling anything.
async fn probe(subject: &Subject, lab: &dyn Lab, slot: &ObjectLocation, value: &str) -> Option<Answer> {
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
    fn it_settles_only_ssti_suspicions() {
        assert!(TemplateInjection.handles(&raised(SETTLES)));
        assert!(!TemplateInjection.handles(&raised("input.sqli")));
        assert!(!TemplateInjection.handles(&raised("input.traversal")));
    }

    #[test]
    fn it_is_active_and_a_settler() {
        let info = TemplateInjection.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn the_products_are_distinctive_and_differ() {
        assert_ne!(A * B1, A * B2);
        assert_eq!(A * B1, 66_860_117);
        assert_eq!(A * B2, 66_891_793);
    }

    #[test]
    fn reproduced_ssti_is_critical() {
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

    #[test]
    fn body_match_finds_the_product() {
        let a = Answer {
            request: nullhawk_types::ids::RequestId::new(),
            status: 200,
            body: b"<p>result: 66860117</p>".to_vec(),
        };
        assert!(a.body_has("66860117"));
        assert!(!a.body_has("66891793"));
    }
}

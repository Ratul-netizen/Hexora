//! `authz.reachable` — the same endpoint, as everybody else.
//!
//! M12.1 replays one captured request as every identity, when a tester names it. This
//! is that across an engagement's traffic, which is the difference between a tool that
//! answers a question and one that asks it of everything:
//!
//! ```text
//! captured:  GET /accounts/acct-1000   as User A   →  200  the owner's record
//! replayed:  the same request          as User B   →  200  the *same document*
//!                                      anonymous   →  401
//! ```
//!
//! # Whose session was it?
//!
//! Everything a cross-identity test concludes rests on knowing whose session was
//! captured, and proxy traffic does not say — a browser announces no identity id. So
//! the credential is the evidence: each declared credential is applied to a copy of the
//! request's own headers and compared byte for byte. An exact answer or none at all.
//!
//! An endpoint whose captured credential matches nothing the project declares is
//! reported as untested with that reason, never guessed at. Hexora will not decide that
//! a session belongs to somebody.
//!
//! # What it does not invent
//!
//! Ownership. If the tester has declared which object identifiers belong to whom, a
//! leaked one is a fact about the bytes and the claim is firm; if not, the claim rests
//! on the response being the *same document*, which M12.10 can establish without a
//! declaration — behind an anonymous control that was refused. See invariant 10: a
//! suggestion is not an object and an object is not an ownership claim.
//!
//! # What it costs
//!
//! One request per identity per endpoint, plus the owner's own baseline. A project with
//! three identities is four requests, which needs a budget of at least four per
//! experiment; a run with less says so rather than testing a subset and reporting it as
//! the whole.

use async_trait::async_trait;
use hexora_authz::compare::Baseline;
use hexora_authz::{analysis, Cell, Matrix, Outcome, Verdict};
use hexora_types::finding::{Hypothesis, Location, MessagePart, Severity};
use hexora_types::identity::{Identity, PrivilegeLevel};
use hexora_types::verify::{DetectorId, DetectorInfo, DetectorMode, Verification, Writeup};
use hexora_types::Result;
use hexora_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct CrossIdentity;

/// The hypothesis this check exists to answer.
const SETTLES: &str = "authz.reachable";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("authz.scheduled"),
    name: "Cross-identity access, scheduled",
    version: "1.0.0",
    about: "an endpoint captured as one identity, replayed as every other one",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
};

#[async_trait]
impl ActiveCheck for CrossIdentity {
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
        let Some(owner) = subject.whose() else {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "the credential {} {} was captured with does not match any identity \
                     this project declares, so there is nobody to say whose session it \
                     was.{}",
                    subject.exchange.method,
                    path_of(&subject.exchange.url),
                    how_to_fix(subject),
                ),
            });
        };

        // Everybody else, anonymous included. The anonymous principal comes from the
        // project rather than being minted here: a request attributed to one the
        // project does not hold cannot be stored, and a fresh id every run would leave
        // a trail of principals nobody declared.
        let others: Vec<&Identity> = subject
            .identities
            .iter()
            .filter(|identity| identity.id != owner.id)
            .collect();

        if others.is_empty() {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "{} is the only identity this project holds, and a cross-identity \
                     test needs somebody to compare against",
                    owner.label
                ),
            });
        }

        // The owner's own fresh reply, plus one per other identity.
        let wanted = others.len() + 1;
        if budget.per_hypothesis < wanted {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "testing {} {} against {} other identit{} needs {wanted} requests \
                     and the budget allows {}. Nothing was sent: a subset of the \
                     identities would be reported as though it were all of them",
                    subject.exchange.method,
                    path_of(&subject.exchange.url),
                    others.len(),
                    if others.len() == 1 { "y" } else { "ies" },
                    budget.per_hypothesis,
                ),
            });
        }

        // The baseline is a fresh send, never the capture. Comparing against a stored
        // response produces differences that belong to time rather than to
        // authorization — M12.1's rule, and it matters more here because a scheduled
        // run meets traffic captured hours ago.
        let owner_sent = match lab.experiment(&subject.draft, Some(owner)).await {
            Ok(sent) => sent,
            Err(e) => {
                return Ok(Verification::Inconclusive {
                    why: format!("the owner's own request could not be replayed: {e}"),
                })
            }
        };

        if !(200..300).contains(&owner_sent.exchange.response.status) {
            return Ok(Verification::Inconclusive {
                why: format!(
                    "replaying {} {} as {} answered {}, so that session no longer \
                     reaches the resource and nothing said about anybody else's access \
                     would have meant anything",
                    subject.exchange.method,
                    path_of(&subject.exchange.url),
                    owner.label,
                    owner_sent.exchange.response.status,
                ),
            });
        }

        let baseline = Baseline::of(&owner_sent.exchange.response);
        let owner_cell = Cell {
            identity: owner.id,
            label: owner.label.clone(),
            privilege: owner.privilege,
            request: Some(owner_sent.id),
            status: Some(owner_sent.exchange.response.status),
            similarity: 1.0,
            structure: None,
            outcome: Outcome::Allowed,
            verdict: Verdict::Expected,
            leaked_object_ids: Vec::new(),
            own_object_ids: Vec::new(),
            verification: None,
            error: None,
            note: None,
        };

        // One send per identity, through the same `replay_once` the on-demand matrix
        // uses. Not a second implementation: a scheduled run that classified responses
        // differently from `hexora authz` would be a second set of verdicts for one
        // question.
        let mut cells = Vec::with_capacity(others.len());
        for identity in &others {
            cells.push(
                hexora_authz::replay_once(lab, &subject.draft, identity, owner, &baseline).await,
            );
        }

        let appears_public = cells.iter().any(|cell| {
            cell.privilege == PrivilegeLevel::Anonymous && cell.outcome == Outcome::Allowed
        }) && owner.privilege != PrivilegeLevel::Anonymous;

        if appears_public {
            for cell in &mut cells {
                if cell.verdict == Verdict::Violation && cell.privilege != PrivilegeLevel::Anonymous
                {
                    cell.verdict = Verdict::Inconclusive;
                    cell.note = Some(
                        "an unauthenticated request received the same resource, so this \
                         identity's access proves nothing about authorization"
                            .into(),
                    );
                }
            }
        }

        let matrix = Matrix {
            base: subject.hypothesis.source_request,
            method: subject.exchange.method.clone(),
            url: subject.exchange.url.clone(),
            owner: owner_cell,
            cells,
            appears_public,
        };

        Ok(conclude(&matrix, owner))
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        // Built from the matrix where there is one, so a scheduled finding reads
        // exactly like an on-demand one. The fallback is only reached for a
        // verification that produced no finding, where the writeup is never used.
        let owner = subject
            .whose()
            .map(|identity| identity.label.clone())
            .unwrap_or_else(|| "the captured identity".into());

        Writeup {
            target: subject.target,
            title: format!(
                "Cross-identity access to {} {}",
                subject.exchange.method,
                path_of(&subject.exchange.url),
            ),
            description: format!(
                "{} {} was captured as {} and replayed as every other identity this \
                 project holds. {}",
                subject.exchange.method,
                subject.exchange.url,
                owner,
                verification.note(),
            ),
            impact: "An identity reached a resource that belongs to somebody else. What \
                     that is worth is whatever the resource is, and whether the \
                     identifier can be enumerated — both of which need a look at the \
                     endpoint rather than at one response."
                .into(),
            remediation: "Enforce the authorization check on the server for every \
                          request, deriving the acting principal from the session \
                          rather than from a parameter the client controls. Scope the \
                          lookup itself to that principal, so an object belonging to \
                          somebody else is never loaded to be checked afterwards."
                .into(),
            reproduction: format!(
                "Send {} {} as each identity and compare the responses. `hexora authz \
                 <project> <request> --as-identity <owner>` runs exactly this one \
                 matrix on demand, and `hexora poc <project> <finding>` compiles the \
                 requests.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-639".into()),
            owasp: Some("API1:2023 Broken Object Level Authorization".into()),
            source: hexora_types::finding::FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: Severity::Medium,
            location: Some(Location {
                part: MessagePart::Path,
                name: path_of(&subject.exchange.url).to_string(),
            }),
        }
    }
}

/// What the matrix established, through the same ladder the on-demand run uses.
///
/// [`analysis::judge`] is the shared piece: the confidence a cross-identity result
/// earns is decided in one place, so a scheduled finding and an on-demand one about
/// the same endpoint cannot disagree.
fn conclude(matrix: &Matrix, owner: &Identity) -> Verification {
    let control = matrix.anonymous_control();

    let worst = matrix
        .cells
        .iter()
        .filter(|cell| cell.verdict == Verdict::Violation && cell.request.is_some())
        // Not the anonymous cell. *Does this endpoint need a session* is
        // `auth.enforcement`'s question, and it answers it with a better experiment —
        // a baseline replay and a comparison rather than one cell of a matrix. Two
        // checks reporting the same public endpoint in different words is the kind of
        // duplication that makes a scanner's output feel like filler.
        .filter(|cell| cell.privilege != PrivilegeLevel::Anonymous)
        .max_by_key(|cell| {
            // The strongest evidence first: a declared identifier beats a shape match.
            (
                !cell.leaked_object_ids.is_empty(),
                cell.structure
                    .as_ref()
                    .map(|s| s.same_document())
                    .unwrap_or(false),
            )
        });

    let Some(cell) = worst else {
        return Verification::Refuted {
            note: refutation(matrix, owner),
        };
    };

    analysis::judge(cell, &owner.label, matrix.owner.request, control)
}

/// The sentence for a matrix in which nobody reached anything they should not have.
///
/// Says what was tried. "No violations" over an unstated number of identities is the
/// kind of silence a retest cannot read.
fn refutation(matrix: &Matrix, owner: &Identity) -> String {
    let tried: Vec<String> = matrix
        .cells
        .iter()
        .map(|cell| format!("{} ({})", cell.label, cell.outcome.as_str()))
        .collect();

    if matrix.appears_public {
        return format!(
            "{} {} served the same resource to an unauthenticated request, so what the \
             other identities received proves nothing about authorization. Tried: {}",
            matrix.method,
            path_of(&matrix.url),
            tried.join(", "),
        );
    }

    if matrix
        .cells
        .iter()
        .any(|cell| cell.privilege == PrivilegeLevel::Anonymous && cell.outcome == Outcome::Allowed)
    {
        return format!(
            "{} {} served the same resource to an unauthenticated request. No other \
             identity reached anything {} did not, and whether this endpoint needs a \
             session at all is what auth.enforcement answers. Tried: {}",
            matrix.method,
            path_of(&matrix.url),
            owner.label,
            tried.join(", "),
        );
    }

    format!(
        "{} {} was replayed as {} identit{} and none of them received {}'s resource. \
         Tried: {}",
        matrix.method,
        path_of(&matrix.url),
        matrix.cells.len(),
        if matrix.cells.len() == 1 { "y" } else { "ies" },
        owner.label,
        tried.join(", "),
    )
}

/// What to do about an unattributable request, in the terms of this request.
///
/// A cookie jar is the common case and the one where the old message helped least: the
/// tester is told nothing matched, while the header holds a dozen names of which
/// exactly one means anything. So the names are listed.
///
/// Names only. A `Cookie` header's values *are* the session.
fn how_to_fix(subject: &Subject) -> String {
    let header = subject
        .draft
        .request
        .headers
        .get("cookie")
        .map(|header| header.value_lossy().into_owned());

    let Some(header) = header else {
        return " Add it with `hexora identity add` and run again".to_string();
    };
    let names: Vec<&str> = header
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, _)| name.trim())
        .filter(|name| !name.is_empty())
        .collect();

    if names.is_empty() {
        return " Add it with `hexora identity add` and run again".to_string();
    }
    format!(
        " It was sent with cookies, and a jar is compared whole unless you say which of \
         them identifies you — several change on every request, so comparing them all \
         matches nothing. These were sent: {}. Declare the one that is your session with \
         `hexora identity add --session-cookie <name>`",
        names.join(", ")
    )
}

fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("/")
}

/// Raises one suspicion per authenticated endpoint worth replaying as somebody else.
///
/// The same two filters the authentication check uses, for the same reasons: an
/// endpoint nobody authenticated to has no owner to compare against, and the scheduler
/// refuses anything that might change data (invariant 18).
pub fn suspect(exchange: &hexora_scan::Exchange) -> Vec<Hypothesis> {
    if !exchange.authenticated {
        return Vec::new();
    }
    if crate::schedule::is_state_changing(&exchange.method) {
        return Vec::new();
    }
    if !(200..300).contains(&exchange.status) {
        return Vec::new();
    }

    vec![Hypothesis {
        detector: SETTLES.to_string(),
        claim: format!(
            "{} {} was reached with one identity's session — whether another identity \
             reaches the same thing needs a request",
            exchange.method,
            path_of(&exchange.url),
        ),
        source_request: exchange.id,
        location: Some(Location {
            part: MessagePart::Path,
            name: path_of(&exchange.url).to_string(),
        }),
        provisional_severity: Severity::Info,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexora_types::http::{Header, Headers, HttpRequest, HttpService};

    fn exchange(method: &str, status: u16, authenticated: bool) -> hexora_scan::Exchange {
        hexora_scan::Exchange {
            id: hexora_types::ids::RequestId::new(),
            target: hexora_types::ids::TargetId::new(),
            host: "api.example.com".into(),
            port: 443,
            secure: true,
            method: method.into(),
            url: "https://api.example.com/accounts/acct-1000".into(),
            path: "/accounts/acct-1000".into(),
            status,
            request_headers: Headers::new(),
            response_headers: Headers::new(),
            response_bytes: 0,
            authenticated,
            tls: None,
            sent_at: "2026-09-11T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    /// A subject whose captured request carries `sent` as its `Authorization`.
    fn subject_carrying(sent: &str, identities: Vec<Identity>) -> Subject {
        let exchange = exchange("GET", 200, true);
        let mut request = HttpRequest::get(
            HttpService::new("api.example.com", 443, true),
            "/accounts/acct-1000",
        );
        request.headers.append(Header::new("Authorization", sent));

        Subject {
            hypothesis: Hypothesis {
                detector: SETTLES.into(),
                claim: String::new(),
                source_request: exchange.id,
                location: None,
                provisional_severity: Severity::Info,
            },
            draft: hexora_repeater::Draft::new(request),
            target: exchange.target,
            exchange,
            identities: std::sync::Arc::new(identities),
        }
    }

    #[test]
    fn it_settles_its_own_suspicions_and_no_others() {
        let raised = |detector: &str| Hypothesis {
            detector: detector.into(),
            claim: String::new(),
            source_request: hexora_types::ids::RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        };
        assert!(CrossIdentity.handles(&raised(SETTLES)));
        assert!(!CrossIdentity.handles(&raised("auth.unverified")));
        assert!(!CrossIdentity.handles(&raised("input.reflected")));
    }

    #[test]
    fn the_owner_is_recognised_from_the_credential_that_was_captured() {
        // Proxy traffic announces no identity id. The credential is the evidence, and
        // everything this check concludes rests on getting it right.
        let alice = Identity::bearer("User A", "TOKEN_A");
        let bob = Identity::bearer("User B", "TOKEN_B");
        let subject = subject_carrying("Bearer TOKEN_B", vec![alice, bob]);

        assert_eq!(subject.whose().map(|i| i.label.as_str()), Some("User B"));
    }

    #[test]
    fn a_credential_nobody_declared_is_never_attributed_to_anybody() {
        // Hexora will not decide whose session this was. The check reports it as
        // untested with that reason.
        let alice = Identity::bearer("User A", "TOKEN_A");
        let subject = subject_carrying("Bearer SOMEBODY_ELSES_TOKEN", vec![alice]);

        assert!(subject.whose().is_none());
    }

    #[test]
    fn a_near_miss_is_not_a_match() {
        let alice = Identity::bearer("User A", "TOKEN_A");
        let subject = subject_carrying("Bearer TOKEN_A_BUT_LONGER", vec![alice]);
        assert!(subject.whose().is_none());
    }

    #[test]
    fn nothing_that_changes_data_is_ever_queued() {
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(
                suspect(&exchange(method, 200, true)).is_empty(),
                "{method} was queued for replay"
            );
        }
        assert_eq!(suspect(&exchange("GET", 200, true)).len(), 1);
    }

    #[test]
    fn an_endpoint_nobody_authenticated_to_has_no_owner_to_compare_against() {
        assert!(suspect(&exchange("GET", 200, false)).is_empty());
    }

    #[test]
    fn an_endpoint_that_already_refuses_establishes_nothing() {
        for status in [401, 403, 404, 302] {
            assert!(
                suspect(&exchange("GET", status, true)).is_empty(),
                "{status}"
            );
        }
    }

    #[test]
    fn a_raised_suspicion_claims_nothing_about_the_application() {
        let raised = suspect(&exchange("GET", 200, true));
        assert_eq!(raised[0].provisional_severity, Severity::Info);
        assert!(raised[0].claim.contains("needs a request"));
    }

    #[test]
    fn it_reports_itself_as_active_and_as_a_settler() {
        let info = CrossIdentity.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[tokio::test]
    async fn a_budget_too_small_for_every_identity_sends_nothing_at_all() {
        // A subset of the identities reported as though it were all of them would be
        // the worst possible output: an endpoint marked tested that nobody tested
        // properly.
        struct NoLab;
        #[async_trait]
        impl Lab for NoLab {
            async fn experiment(
                &self,
                _: &hexora_repeater::Draft,
                _: Option<&Identity>,
            ) -> Result<hexora_repeater::Sent> {
                panic!("nothing may be sent when the budget cannot cover the run");
            }
            fn would_leave_scope(&self, _: &hexora_repeater::Draft, _: Option<&Identity>) -> bool {
                false
            }
            fn draft_of(&self, _: hexora_types::ids::RequestId) -> Result<hexora_repeater::Draft> {
                panic!("not used")
            }
        }

        let identities = vec![
            Identity::bearer("User A", "TOKEN_A"),
            Identity::bearer("User B", "TOKEN_B"),
            Identity::bearer("User C", "TOKEN_C"),
        ];
        let subject = subject_carrying("Bearer TOKEN_A", identities);
        let budget = Budget {
            per_hypothesis: 2,
            ..Budget::default()
        };

        let verification = CrossIdentity
            .settle(&subject, &NoLab, &budget)
            .await
            .unwrap();
        match verification {
            Verification::Inconclusive { why } => {
                assert!(why.contains("needs 3 requests"), "{why}");
                assert!(why.contains("Nothing was sent"), "{why}");
            }
            other => panic!("expected Inconclusive, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unrecognised_credential_sends_nothing_and_says_why() {
        struct NoLab;
        #[async_trait]
        impl Lab for NoLab {
            async fn experiment(
                &self,
                _: &hexora_repeater::Draft,
                _: Option<&Identity>,
            ) -> Result<hexora_repeater::Sent> {
                panic!("nothing may be sent without knowing whose session it was");
            }
            fn would_leave_scope(&self, _: &hexora_repeater::Draft, _: Option<&Identity>) -> bool {
                false
            }
            fn draft_of(&self, _: hexora_types::ids::RequestId) -> Result<hexora_repeater::Draft> {
                panic!("not used")
            }
        }

        let subject = subject_carrying(
            "Bearer NOBODY_DECLARED_THIS",
            vec![Identity::bearer("User A", "TOKEN_A")],
        );
        let verification = CrossIdentity
            .settle(&subject, &NoLab, &Budget::default())
            .await
            .unwrap();

        match verification {
            Verification::Inconclusive { why } => {
                assert!(why.contains("does not match any identity"), "{why}");
                assert!(
                    !why.contains("NOBODY_DECLARED_THIS"),
                    "credential leaked: {why}"
                );
            }
            other => panic!("expected Inconclusive, got {other:?}"),
        }
    }
}

//! Turning a finding into something a triager can run.
//!
//! The highest-friction moment in a security engagement is not finding the bug — it
//! is convincing somebody else that it is real. A report that says *User B received
//! User A's invoice* invites an argument; a report that hands over the two requests
//! that showed it, in a form the reader can paste into a terminal, ends one.
//!
//! # Compiled from evidence, never invented
//!
//! Every step points at a [`RequestId`] the project holds, and the bytes come from
//! that stored request. Nothing here composes a request that was not sent: if the
//! project can no longer resolve a citation, the step says so and stops, because a
//! reproduction built from a guess is worse than no reproduction at all — it fails,
//! and the reader concludes the finding was wrong rather than that the evidence was
//! missing.
//!
//! # Credentials are placeholders, always
//!
//! A proof of concept is the single most-forwarded artefact an engagement produces:
//! it goes into a ticket, an email, a chat channel, and eventually a screenshot. So
//! it never carries a session.
//!
//! ```text
//! sent:        Authorization: Bearer eyJhbGciOi...
//! reproduced:  Authorization: Bearer <USER_A_TOKEN>
//! ```
//!
//! The token is named after the identity the request was sent as, and the same
//! identity gets the same placeholder in every step — so a reader sets two values and
//! runs the whole thing, and can see at a glance that step 1 and step 2 were sent as
//! different people, which is usually the entire point.
//!
//! # curl is offered only when curl can do it
//!
//! A `curl` command is a convenience, and it is not a faithful representation of
//! every request. curl recomputes `Content-Length`, normalises line endings, and
//! cannot express a header block containing a bare LF. Those are precisely the
//! requests a smuggling or parser-differential finding is *about*.
//!
//! So [`Curl::Inexpressible`] is a first-class outcome with a reason attached, and the
//! raw form is always present. A tool that silently emitted a curl command which sent
//! something else would be undoing the work of `RequestSource::Raw` at the last step.

use std::collections::BTreeMap;

use hexora_storage::{Project, StoredRequest};
use hexora_types::finding::{Confidence, Evidence, Finding};
use hexora_types::ids::{FindingId, RequestId};
use hexora_types::redact::is_sensitive_header;
use hexora_types::Result;
use serde::Serialize;

/// A reproduction, compiled from a finding's evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reproduction {
    /// The finding it reproduces.
    pub finding: FindingId,
    /// Its title.
    pub title: String,
    /// How firmly the finding is established.
    ///
    /// Carried so a reader is never handed a runnable script without being told
    /// whether anything verified the claim behind it.
    pub confidence: Confidence,
    /// The prose the finding already carried, unchanged.
    pub summary: String,
    /// What to do, in order.
    pub steps: Vec<Step>,
    /// The values the reader has to supply.
    pub placeholders: Vec<Placeholder>,
    /// What this reproduction cannot do, stated rather than discovered.
    pub caveats: Vec<String>,
}

impl Reproduction {
    /// Whether any step can actually be run.
    pub fn is_runnable(&self) -> bool {
        self.steps.iter().any(|step| step.raw.is_some())
    }
}

/// One request to send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    /// Its position, from 1.
    pub number: usize,
    /// What this step is for, in a sentence.
    pub what: String,
    /// The exchange it was taken from, so a reader can open the original.
    pub request: RequestId,
    /// The identity it was sent as, when it was sent as one.
    pub identity: Option<String>,
    /// The request as bytes, with credentials replaced by placeholders.
    ///
    /// `None` when the project no longer holds the exchange — the step is still
    /// listed, because a missing citation is a fact about the project worth printing.
    pub raw: Option<String>,
    /// The same request as a shell command, when one can express it.
    pub curl: Curl,
    /// What the reader should see, when the evidence said.
    pub expect: Option<String>,
}

impl Step {
    /// The step as one line: what to do, and who to do it as.
    ///
    /// Composed here rather than in each renderer, because three copies of
    /// "join these two strings" is three places for "Send the control request. as
    /// User A" to survive.
    pub fn heading(&self) -> String {
        let what = self.what.trim_end_matches('.');
        match &self.identity {
            Some(identity) => format!("{what}, as {identity}."),
            None => format!("{what}."),
        }
    }
}

/// Whether a request can be reproduced with `curl`, and if not, why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Curl {
    /// A command that sends this request.
    ///
    /// A named field rather than a newtype: an internally tagged newtype variant over
    /// a string does not serialize, and this type goes into the report's JSON.
    Command {
        /// The command.
        command: String,
    },
    /// curl cannot send this request as it was sent.
    ///
    /// Carries the reason, because "no curl command" with no explanation reads as a
    /// missing feature rather than as the point.
    Inexpressible {
        /// Why not.
        reason: String,
    },
    /// The exchange could not be read back, so there was nothing to convert.
    Unavailable,
}

impl Curl {
    /// The command, when there is one.
    pub fn command(&self) -> Option<&str> {
        match self {
            Self::Command { command } => Some(command),
            _ => None,
        }
    }
}

/// A value the reader supplies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Placeholder {
    /// The token as it appears in the steps, e.g. `<USER_A_AUTHORIZATION>`.
    pub token: String,
    /// The header it belongs in.
    pub header: String,
    /// The authentication scheme in front of it, when there was one.
    ///
    /// `Bearer` is kept in the reproduction and only the credential after it is
    /// replaced, so a reader can see what kind of value the header wants.
    pub scheme: Option<String>,
    /// The identity it authenticates as, when the exchange recorded one.
    pub identity: Option<String>,
    /// How many bytes the part this token stands for was.
    ///
    /// The credential itself, not the whole header value: a reader who pastes a
    /// 40-byte token where a 200-byte one belongs should be able to notice, and a
    /// count that included `Bearer ` would be measuring the wrong thing.
    pub bytes: usize,
}

/// Compiles a finding's evidence into a reproduction.
///
/// Reads the project. Sends nothing — the same shape as every other read in this
/// crate, and the reason `hexora report` and `hexora poc` are safe to run against a
/// finished engagement.
pub fn reproduce(project: &Project, finding: &Finding) -> Result<Reproduction> {
    let traffic = project.traffic();
    let identities = project.identities();
    let labels: BTreeMap<_, _> = identities
        .list()?
        .into_iter()
        .map(|identity| (identity.id, identity.label))
        .collect();

    let mut caveats = Vec::new();
    let mut tokens = Tokens::default();
    let mut ordered: Vec<(RequestId, String, Option<String>)> = Vec::new();

    for evidence in &finding.evidence {
        match evidence {
            Evidence::Comparison {
                baseline,
                variant,
                difference,
            } => {
                // The control first: a reader who runs only the second request has
                // nothing to compare it against, and the comparison is the finding.
                push(&mut ordered, *baseline, "Send the control request.", None);
                push(
                    &mut ordered,
                    *variant,
                    "Send the same request as the other identity.",
                    Some(difference.clone()),
                );
            }
            Evidence::Exchange { request, note, .. } => {
                push(
                    &mut ordered,
                    *request,
                    "Send this request.",
                    Some(note.clone()),
                );
            }
            Evidence::ResponseExcerpt { .. } => {
                caveats.push(
                    "One piece of evidence is an excerpt of a response body rather than \
                     a request, so it is quoted in the report and has no step here."
                        .into(),
                );
            }
            Evidence::OutOfBand { .. } => caveats.push(
                "One piece of evidence is an out-of-band interaction, which a reader \
                 cannot reproduce without the same listener."
                    .into(),
            ),
            Evidence::Timing { .. } => caveats.push(
                "One piece of evidence is a timing comparison. Re-running the requests \
                 below shows the behaviour; whether the timing difference survives the \
                 reader's own network is a separate question."
                    .into(),
            ),
        }
    }

    let mut steps = Vec::with_capacity(ordered.len());
    for (position, (request, what, expect)) in ordered.into_iter().enumerate() {
        let number = position + 1;
        let stored = match traffic.request(request) {
            Ok(stored) => stored,
            Err(e) => {
                caveats.push(format!(
                    "Step {number} cites {request}, which the project no longer holds \
                     ({e}). The finding's evidence is incomplete."
                ));
                steps.push(Step {
                    number,
                    what,
                    request,
                    identity: None,
                    raw: None,
                    curl: Curl::Unavailable,
                    expect,
                });
                continue;
            }
        };

        let identity = stored
            .identity
            .map(|id| labels.get(&id).cloned().unwrap_or_else(|| id.to_string()));
        let raw = render(&stored, identity.as_deref(), &mut tokens);
        let curl = to_curl(&stored, identity.as_deref(), &mut tokens);

        steps.push(Step {
            number,
            what,
            request,
            identity,
            raw: Some(raw),
            curl,
            expect,
        });
    }

    if steps.is_empty() {
        caveats.push(
            "This finding cites no exchange that can be re-sent, so there is nothing \
             to run. The claim rests on what is quoted in the report."
                .into(),
        );
    }
    if !finding.confidence.is_actionable() {
        // Printed on the artefact itself, because a runnable script is exactly the
        // thing somebody forwards without the paragraph that qualified it.
        caveats.push(
            "This finding is a lead rather than an established issue: running the \
             steps below shows what Hexora saw, not that the application is \
             exploitable."
                .into(),
        );
    }

    Ok(Reproduction {
        finding: finding.id,
        title: finding.title.clone(),
        confidence: finding.confidence,
        summary: finding.reproduction.clone(),
        steps,
        placeholders: tokens.into_placeholders(),
        caveats,
    })
}

/// Adds a step, merging a repeat of the same request rather than listing it twice.
fn push(
    ordered: &mut Vec<(RequestId, String, Option<String>)>,
    request: RequestId,
    what: &str,
    expect: Option<String>,
) {
    if let Some(existing) = ordered.iter_mut().find(|(id, _, _)| *id == request) {
        // A finding often cites the same exchange twice — once for the comparison and
        // once for what was in the body. One request, two things to notice.
        if let Some(expect) = expect {
            match &mut existing.2 {
                Some(already) if already.contains(&expect) => {}
                Some(already) => {
                    already.push(' ');
                    already.push_str(&expect);
                }
                slot @ None => *slot = Some(expect),
            }
        }
        return;
    }
    ordered.push((request, what.to_string(), expect));
}

/// The placeholders minted so far, so one identity gets one token everywhere.
#[derive(Debug, Default)]
struct Tokens {
    by_key: BTreeMap<String, Placeholder>,
}

impl Tokens {
    /// The header value with its credential replaced by a placeholder.
    ///
    /// Splits the scheme off first, so `Bearer eyJ…` becomes `Bearer <USER_A_…>` and
    /// the recorded length is the credential's rather than the whole value's.
    fn substitute(&mut self, header: &str, value: &str, identity: Option<&str>) -> String {
        let (scheme, credential) = split_scheme(value);
        let token = self.placeholder(header, identity, scheme, credential.len());
        match scheme {
            Some(scheme) => format!("{scheme} {token}"),
            None => token,
        }
    }

    /// The placeholder for a credential header on a request sent as `identity`.
    fn placeholder(
        &mut self,
        header: &str,
        identity: Option<&str>,
        scheme: Option<&str>,
        bytes: usize,
    ) -> String {
        let key = format!("{}|{}", header.to_ascii_lowercase(), identity.unwrap_or(""));
        if let Some(existing) = self.by_key.get(&key) {
            return existing.token.clone();
        }

        let token = match identity {
            Some(identity) => format!("<{}_{}>", shout(identity), shout(header)),
            None => format!("<{}>", shout(header)),
        };
        self.by_key.insert(
            key,
            Placeholder {
                token: token.clone(),
                header: header.to_string(),
                scheme: scheme.map(str::to_string),
                identity: identity.map(str::to_string),
                bytes,
            },
        );
        token
    }

    fn into_placeholders(self) -> Vec<Placeholder> {
        self.by_key.into_values().collect()
    }
}

/// Splits an authentication scheme off a header value.
///
/// `Bearer eyJ…` is a scheme and a credential; `sessionid=abc` is all credential.
fn split_scheme(value: &str) -> (Option<&str>, &str) {
    for scheme in ["Bearer", "Basic", "Digest", "Negotiate", "Token"] {
        if let Some(rest) = value.strip_prefix(scheme) {
            if let Some(credential) = rest.strip_prefix(' ') {
                return (Some(scheme), credential);
            }
        }
    }
    (None, value)
}

/// `User A` → `USER_A`, so a placeholder reads as one.
fn shout(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .replace("__", "_")
}

/// The request as bytes, with credentials replaced.
///
/// Built from the stored header block rather than from a re-serialization, so a
/// duplicated header, an unusual casing or a deliberately wrong `Content-Length`
/// survives into the reproduction — those are often what the finding is about.
fn render(stored: &StoredRequest, identity: Option<&str>, tokens: &mut Tokens) -> String {
    let mut out = format!(
        "{} {} {}\r\n",
        stored.method, stored.path, stored.http_version
    );

    for (name, value) in header_lines(stored) {
        if is_sensitive_header(&name) {
            let replaced = tokens.substitute(&name, &value, identity);
            out.push_str(&format!("{name}: {replaced}\r\n"));
        } else {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
    }

    out.push_str("\r\n");
    match std::str::from_utf8(&stored.body) {
        Ok(body) => out.push_str(body),
        Err(_) => out.push_str(&format!(
            "[{} bytes of non-UTF-8 body — see the stored exchange]",
            stored.body.len()
        )),
    }
    out
}

/// Header name/value pairs, exactly as stored.
fn header_lines(stored: &StoredRequest) -> Vec<(String, String)> {
    String::from_utf8_lossy(&stored.headers_raw)
        .split("\r\n")
        .flat_map(|line| line.split('\n'))
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

/// The request as a `curl` command, when curl can send it.
fn to_curl(stored: &StoredRequest, identity: Option<&str>, tokens: &mut Tokens) -> Curl {
    let headers = header_lines(stored);

    // The four ways a stored request outruns what curl can express. Each one is a
    // thing a real finding is sometimes *about*, so none of them is papered over.
    if let Some(reason) = inexpressible(stored, &headers) {
        return Curl::Inexpressible { reason };
    }

    let mut command = String::from("curl -i");
    if stored.method != "GET" {
        command.push_str(&format!(" -X {}", stored.method));
    }

    for (name, value) in &headers {
        // curl sets Host from the URL, and sending both produces two.
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let value = if is_sensitive_header(name) {
            tokens.substitute(name, value, identity)
        } else {
            value.clone()
        };
        command.push_str(&format!(" \\\n  -H {}", quote(&format!("{name}: {value}"))));
    }

    if !stored.body.is_empty() {
        // Checked above, so this cannot fail — but expressed as a match rather than
        // an unwrap, because a panic in a report generator is a bad way to find out.
        if let Ok(body) = std::str::from_utf8(&stored.body) {
            command.push_str(&format!(" \\\n  --data-raw {}", quote(body)));
        }
    }

    command.push_str(&format!(" \\\n  {}", quote(&url_of(stored))));
    Curl::Command { command }
}

/// Why curl cannot send this request as it was sent, if it cannot.
fn inexpressible(stored: &StoredRequest, headers: &[(String, String)]) -> Option<String> {
    if std::str::from_utf8(&stored.body).is_err() {
        return Some(
            "the request body is not valid UTF-8, so it cannot be written into a shell \
             command — send the raw form above instead"
                .into(),
        );
    }

    let declared: Vec<usize> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .filter_map(|(_, value)| value.trim().parse().ok())
        .collect();
    if declared.len() > 1 {
        return Some(
            "the request carries more than one Content-Length, which curl will not \
             send — and which is usually the point of the request"
                .into(),
        );
    }
    if let Some(declared) = declared.first() {
        if *declared != stored.body.len() {
            return Some(format!(
                "the request declares Content-Length: {declared} for a {}-byte body. \
                 curl recomputes the length, so it would send something else",
                stored.body.len()
            ));
        }
    }

    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        && !declared.is_empty()
    {
        return Some(
            "the request carries both Transfer-Encoding and Content-Length. curl will \
             not send that combination, and it is usually the subject of the finding"
                .into(),
        );
    }

    // A header block with a bare LF is a parser-differential test case, and writing
    // it as `-H` would send a well-formed one. Counted rather than pattern-matched:
    // every LF that is not part of a CRLF is a bare one, and that is the question.
    let raw = String::from_utf8_lossy(&stored.headers_raw);
    let lf = raw.matches('\n').count();
    let crlf = raw.matches("\r\n").count();
    if lf > crlf {
        return Some(
            "the header block is separated by bare LF rather than CRLF. curl sends \
             CRLF, so it would send a different request"
                .into(),
        );
    }

    None
}

/// Single-quotes a value for a POSIX shell.
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn url_of(stored: &StoredRequest) -> String {
    if stored.path.starts_with("http://") || stored.path.starts_with("https://") {
        stored.path.clone()
    } else {
        format!("{}{}", stored.service.origin(), stored.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hexora_storage::{CapturedExchange, TrafficStore};
    use hexora_types::finding::{
        FindingSource, FindingStatus, Hypothesis, Location, MessagePart, Severity,
    };
    use hexora_types::http::{
        Header, Headers, HttpRequest, HttpResponse, HttpService, HttpVersion,
    };
    use hexora_types::identity::Identity;
    use hexora_types::ids::TargetId;
    use hexora_types::verify::{Verification, Verified, Writeup};

    struct Fixture {
        project: Project,
        traffic: TrafficStore,
    }

    fn fixture() -> Fixture {
        // The project's own traffic store, not a second one over the same database:
        // a separate `MemoryBlobStore` would hold the bodies somewhere `reproduce`
        // cannot see them, and every request with a body would read back as missing.
        let project = Project::in_memory().unwrap();
        let traffic = project.traffic();
        Fixture { project, traffic }
    }

    impl Fixture {
        fn capture(
            &self,
            method: &str,
            path: &str,
            headers: &[(&str, &str)],
            body: &str,
            identity: Option<&Identity>,
        ) -> RequestId {
            let service = HttpService::new("api.example.com", 443, true);
            let mut request = HttpRequest::get(service, path);
            request.method = method.to_string();
            request.headers = Headers::new();
            for (name, value) in headers {
                request
                    .headers
                    .append(Header::new((*name).to_string(), *value));
            }
            request.body = Bytes::copy_from_slice(body.as_bytes());

            if let Some(identity) = identity {
                self.project.identities().put(identity).unwrap();
            }

            self.traffic
                .record(&CapturedExchange {
                    request,
                    raw_request: None,
                    response: HttpResponse {
                        status: 200,
                        reason: None,
                        version: HttpVersion::Http11,
                        headers: Headers::new(),
                        body: Bytes::from_static(b"{}"),
                        truncated: false,
                    },
                    encoded_body: None,
                    content_encoding: None,
                    origin: "authz",
                    identity: identity.map(|i| i.id),
                    parent: None,
                    quirks: Vec::new(),
                    tls: None,
                    duration_ms: 1,
                })
                .unwrap()
        }
    }

    fn finding(target: TargetId, evidence: Vec<Evidence>, confidence: Confidence) -> Finding {
        let hypothesis = Hypothesis {
            detector: "authz.cross_identity".into(),
            claim: "User B reached User A's object".into(),
            source_request: RequestId::new(),
            location: Some(Location {
                part: MessagePart::Path,
                name: "/accounts/acct-1000".into(),
            }),
            provisional_severity: Severity::High,
        };
        let verification = match confidence {
            Confidence::Confirmed => Verification::Reproduced {
                note: "it happened again".into(),
                evidence,
            },
            _ => Verification::Observed {
                note: "seen once".into(),
                evidence,
            },
        };
        let writeup = Writeup {
            target,
            title: "Broken object-level authorization".into(),
            description: "User B received User A's account.".into(),
            impact: "One user can read another's records.".into(),
            remediation: "Scope the lookup to the session.".into(),
            reproduction: "Send as A, send as B, compare.".into(),
            cwe: None,
            owasp: None,
            source: FindingSource::AuthorizationTest,
            severity: Severity::High,
            location: None,
        };
        let mut finding = Verified::conclude(&hypothesis, &verification, writeup)
            .unwrap()
            .into_finding();
        finding.status = FindingStatus::New;
        finding
    }

    #[test]
    fn a_comparison_becomes_the_control_first_and_then_the_variant() {
        let fixture = fixture();
        let target = fixture
            .traffic
            .upsert_target("api.example.com", 443, true)
            .unwrap();
        let user_a = Identity::bearer("User A", "token-for-user-a");
        let user_b = Identity::bearer("User B", "token-for-user-b");

        let baseline = fixture.capture(
            "GET",
            "/accounts/acct-1000",
            &[
                ("Host", "api.example.com"),
                ("Authorization", "Bearer token-for-user-a"),
            ],
            "",
            Some(&user_a),
        );
        let variant = fixture.capture(
            "GET",
            "/accounts/acct-1000",
            &[
                ("Host", "api.example.com"),
                ("Authorization", "Bearer token-for-user-b"),
            ],
            "",
            Some(&user_b),
        );

        let finding = finding(
            target,
            vec![Evidence::Comparison {
                baseline,
                variant,
                difference: "User B received acct-1000".into(),
            }],
            Confidence::Confirmed,
        );

        let poc = reproduce(&fixture.project, &finding).unwrap();
        assert_eq!(poc.steps.len(), 2);
        assert_eq!(poc.steps[0].request, baseline);
        assert_eq!(poc.steps[0].identity.as_deref(), Some("User A"));
        assert_eq!(poc.steps[1].identity.as_deref(), Some("User B"));
        // The difference the comparison established is what the reader is told to
        // look for, on the step that produced it.
        assert_eq!(
            poc.steps[1].expect.as_deref(),
            Some("User B received acct-1000")
        );
        assert!(poc.is_runnable());
    }

    #[test]
    fn no_credential_survives_into_a_reproduction() {
        // The property this module is shaped around: a PoC is the most-forwarded
        // thing an engagement produces.
        let fixture = fixture();
        let target = fixture
            .traffic
            .upsert_target("api.example.com", 443, true)
            .unwrap();
        let user_a = Identity::bearer("User A", "token-for-user-a");

        let request = fixture.capture(
            "GET",
            "/accounts/acct-1000",
            &[
                ("Host", "api.example.com"),
                ("Authorization", "Bearer token-for-user-a"),
                ("Cookie", "sessionid=do-not-leak-me"),
            ],
            "",
            Some(&user_a),
        );

        let finding = finding(
            target,
            vec![Evidence::Exchange {
                request,
                response: None,
                note: "served the object".into(),
            }],
            Confidence::Confirmed,
        );

        let poc = reproduce(&fixture.project, &finding).unwrap();
        let rendered = format!("{poc:?}");
        assert!(!rendered.contains("token-for-user-a"), "{rendered}");
        assert!(!rendered.contains("do-not-leak-me"), "{rendered}");

        // And what replaced them says whose credential goes there.
        let raw = poc.steps[0].raw.as_ref().unwrap();
        assert!(raw.contains("Bearer <USER_A_AUTHORIZATION>"), "{raw}");
        assert!(poc
            .placeholders
            .iter()
            .any(|p| p.identity.as_deref() == Some("User A")));
    }

    #[test]
    fn one_identity_gets_one_placeholder_across_every_step() {
        // So a reader sets two values and runs the whole thing — and can see that
        // step 1 and step 2 were sent as different people, which is the finding.
        let fixture = fixture();
        let target = fixture
            .traffic
            .upsert_target("api.example.com", 443, true)
            .unwrap();
        let user_a = Identity::bearer("User A", "token-a");
        let user_b = Identity::bearer("User B", "token-b");

        let first = fixture.capture(
            "GET",
            "/a",
            &[("Authorization", "Bearer token-a")],
            "",
            Some(&user_a),
        );
        let second = fixture.capture(
            "GET",
            "/b",
            &[("Authorization", "Bearer token-a")],
            "",
            Some(&user_a),
        );
        let third = fixture.capture(
            "GET",
            "/c",
            &[("Authorization", "Bearer token-b")],
            "",
            Some(&user_b),
        );

        let finding = finding(
            target,
            vec![
                Evidence::Exchange {
                    request: first,
                    response: None,
                    note: "one".into(),
                },
                Evidence::Exchange {
                    request: second,
                    response: None,
                    note: "two".into(),
                },
                Evidence::Exchange {
                    request: third,
                    response: None,
                    note: "three".into(),
                },
            ],
            Confidence::Confirmed,
        );

        let poc = reproduce(&fixture.project, &finding).unwrap();
        assert_eq!(poc.placeholders.len(), 2, "{:#?}", poc.placeholders);
        assert!(poc.steps[0]
            .raw
            .as_ref()
            .unwrap()
            .contains("<USER_A_AUTHORIZATION>"));
        assert!(poc.steps[1]
            .raw
            .as_ref()
            .unwrap()
            .contains("<USER_A_AUTHORIZATION>"));
        assert!(poc.steps[2]
            .raw
            .as_ref()
            .unwrap()
            .contains("<USER_B_AUTHORIZATION>"));
    }

    #[test]
    fn the_same_exchange_cited_twice_is_one_step() {
        let fixture = fixture();
        let target = fixture
            .traffic
            .upsert_target("api.example.com", 443, true)
            .unwrap();
        let request = fixture.capture("GET", "/a", &[], "", None);

        let finding = finding(
            target,
            vec![
                Evidence::Exchange {
                    request,
                    response: None,
                    note: "the response was served".into(),
                },
                Evidence::Exchange {
                    request,
                    response: None,
                    note: "and it contained acct-1000".into(),
                },
            ],
            Confidence::Confirmed,
        );

        let poc = reproduce(&fixture.project, &finding).unwrap();
        assert_eq!(poc.steps.len(), 1, "one request, two things to notice");
        let expect = poc.steps[0].expect.as_ref().unwrap();
        assert!(expect.contains("the response was served"), "{expect}");
        assert!(expect.contains("acct-1000"), "{expect}");
    }

    #[test]
    fn a_curl_command_is_offered_for_an_ordinary_request() {
        let fixture = fixture();
        let target = fixture
            .traffic
            .upsert_target("api.example.com", 443, true)
            .unwrap();
        let request = fixture.capture(
            "POST",
            "/accounts",
            &[
                ("Host", "api.example.com"),
                ("Content-Type", "application/json"),
                ("Content-Length", "13"),
            ],
            r#"{"id":"1000"}"#,
            None,
        );

        let finding = finding(
            target,
            vec![Evidence::Exchange {
                request,
                response: None,
                note: "it worked".into(),
            }],
            Confidence::Confirmed,
        );

        let poc = reproduce(&fixture.project, &finding).unwrap();
        let command = poc.steps[0].curl.command().expect("a command");

        assert!(command.starts_with("curl -i -X POST"), "{command}");
        assert!(command.contains("--data-raw"), "{command}");
        assert!(
            command.contains("https://api.example.com/accounts"),
            "{command}"
        );
        // Host and Content-Length are curl's to set; sending both produces two.
        assert!(!command.contains("-H 'Host:"), "{command}");
        assert!(!command.contains("Content-Length"), "{command}");
    }

    #[test]
    fn curl_is_refused_with_a_reason_when_it_would_send_something_else() {
        // The four cases where a curl command would quietly undo the work raw mode
        // exists to do. Each says why rather than simply being absent.
        let fixture = fixture();
        let target = fixture
            .traffic
            .upsert_target("api.example.com", 443, true)
            .unwrap();

        let wrong_length =
            fixture.capture("POST", "/a", &[("Content-Length", "999")], "short", None);
        let two_lengths = fixture.capture(
            "POST",
            "/b",
            &[("Content-Length", "5"), ("Content-Length", "6")],
            "short",
            None,
        );
        let both_framings = fixture.capture(
            "POST",
            "/c",
            &[("Content-Length", "5"), ("Transfer-Encoding", "chunked")],
            "short",
            None,
        );

        for (request, expected) in [
            (wrong_length, "recomputes the length"),
            (two_lengths, "more than one Content-Length"),
            (both_framings, "both Transfer-Encoding and Content-Length"),
        ] {
            let finding = finding(
                target,
                vec![Evidence::Exchange {
                    request,
                    response: None,
                    note: "n".into(),
                }],
                Confidence::Confirmed,
            );
            let poc = reproduce(&fixture.project, &finding).unwrap();
            match &poc.steps[0].curl {
                Curl::Inexpressible { reason } => {
                    assert!(reason.contains(expected), "{reason}")
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
            // And the raw form is still there, which is the whole point.
            assert!(poc.steps[0].raw.is_some());
        }
    }

    #[test]
    fn a_request_the_project_no_longer_holds_is_stated_rather_than_invented() {
        let fixture = fixture();
        let target = fixture
            .traffic
            .upsert_target("api.example.com", 443, true)
            .unwrap();
        let gone = RequestId::new();

        let finding = finding(
            target,
            vec![Evidence::Exchange {
                request: gone,
                response: None,
                note: "n".into(),
            }],
            Confidence::Confirmed,
        );

        let poc = reproduce(&fixture.project, &finding).unwrap();
        assert_eq!(poc.steps.len(), 1);
        assert!(poc.steps[0].raw.is_none());
        assert_eq!(poc.steps[0].curl, Curl::Unavailable);
        assert!(!poc.is_runnable());
        assert!(
            poc.caveats.iter().any(|c| c.contains("no longer holds")),
            "{:#?}",
            poc.caveats
        );
    }

    #[test]
    fn a_lead_says_on_the_artefact_that_it_is_a_lead() {
        // A runnable script is exactly the thing somebody forwards without the
        // paragraph that qualified it.
        let fixture = fixture();
        let target = fixture
            .traffic
            .upsert_target("api.example.com", 443, true)
            .unwrap();
        let request = fixture.capture("GET", "/a", &[], "", None);

        let finding = finding(
            target,
            vec![Evidence::Exchange {
                request,
                response: None,
                note: "n".into(),
            }],
            Confidence::Reported,
        );

        let poc = reproduce(&fixture.project, &finding).unwrap();
        assert!(
            poc.caveats.iter().any(|c| c.contains("lead rather than")),
            "{:#?}",
            poc.caveats
        );
    }

    #[test]
    fn a_non_utf8_body_is_described_rather_than_mangled() {
        let fixture = fixture();
        let target = fixture
            .traffic
            .upsert_target("api.example.com", 443, true)
            .unwrap();

        let service = HttpService::new("api.example.com", 443, true);
        let mut request = HttpRequest::get(service, "/upload");
        request.method = "POST".into();
        request.body = Bytes::from_static(&[0xff, 0xfe, 0x00, 0x01]);
        let id = fixture
            .traffic
            .record(&CapturedExchange {
                request,
                raw_request: None,
                response: HttpResponse {
                    status: 200,
                    reason: None,
                    version: HttpVersion::Http11,
                    headers: Headers::new(),
                    body: Bytes::new(),
                    truncated: false,
                },
                encoded_body: None,
                content_encoding: None,
                origin: "proxy",
                identity: None,
                parent: None,
                quirks: Vec::new(),
                tls: None,
                duration_ms: 1,
            })
            .unwrap();

        let finding = finding(
            target,
            vec![Evidence::Exchange {
                request: id,
                response: None,
                note: "n".into(),
            }],
            Confidence::Confirmed,
        );

        let poc = reproduce(&fixture.project, &finding).unwrap();
        let raw = poc.steps[0].raw.as_ref().unwrap();
        assert!(raw.contains("non-UTF-8 body"), "{raw}");
        assert!(matches!(poc.steps[0].curl, Curl::Inexpressible { .. }));
    }

    #[test]
    fn a_shell_quoted_value_cannot_escape_its_quotes() {
        assert_eq!(quote("plain"), "'plain'");
        // The one character that ends a single-quoted string.
        assert_eq!(quote("it's"), r#"'it'\''s'"#);
        assert_eq!(quote("a; rm -rf /"), "'a; rm -rf /'");
    }

    #[test]
    fn a_placeholder_measures_the_credential_and_not_the_scheme() {
        // A reader who pastes a 40-byte token where a 200-byte one belongs should be
        // able to notice. `Bearer ` is not part of what they are pasting.
        let fixture = fixture();
        let target = fixture
            .traffic
            .upsert_target("api.example.com", 443, true)
            .unwrap();
        let user_a = Identity::bearer("User A", "abcdefg");

        let request = fixture.capture(
            "GET",
            "/a",
            &[("Authorization", "Bearer abcdefg")],
            "",
            Some(&user_a),
        );
        let finding = finding(
            target,
            vec![Evidence::Exchange {
                request,
                response: None,
                note: "n".into(),
            }],
            Confidence::Confirmed,
        );

        let poc = reproduce(&fixture.project, &finding).unwrap();
        let placeholder = &poc.placeholders[0];
        assert_eq!(placeholder.scheme.as_deref(), Some("Bearer"));
        assert_eq!(placeholder.bytes, 7, "the credential, not `Bearer abcdefg`");
        // And the scheme survives into the reproduction, so the reader can see what
        // kind of value the header wants.
        assert!(poc.steps[0]
            .raw
            .as_ref()
            .unwrap()
            .contains("Authorization: Bearer <USER_A_AUTHORIZATION>"));
    }

    #[test]
    fn a_credential_with_no_scheme_is_replaced_whole() {
        assert_eq!(split_scheme("Bearer abc"), (Some("Bearer"), "abc"));
        assert_eq!(split_scheme("sessionid=abc"), (None, "sessionid=abc"));
        // `Bearer` with no space after it is not a scheme, it is the whole value.
        assert_eq!(split_scheme("Bearerabc"), (None, "Bearerabc"));
    }

    #[test]
    fn a_step_heading_reads_as_a_sentence() {
        let step = Step {
            number: 1,
            what: "Send the control request.".into(),
            request: RequestId::new(),
            identity: Some("User A".into()),
            raw: None,
            curl: Curl::Unavailable,
            expect: None,
        };
        assert_eq!(step.heading(), "Send the control request, as User A.");

        let anonymous = Step {
            identity: None,
            ..step
        };
        assert_eq!(anonymous.heading(), "Send the control request.");
    }

    #[test]
    fn a_placeholder_reads_as_one() {
        assert_eq!(shout("User A"), "USER_A");
        assert_eq!(shout("Authorization"), "AUTHORIZATION");
        assert_eq!(shout("admin@example.com"), "ADMIN_EXAMPLE_COM");
    }
}

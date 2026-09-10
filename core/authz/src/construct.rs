//! Constructing cross-identity requests, rather than only replaying captured ones.
//!
//! A matrix replays a request as written. That answers "can User B reach this URL?"
//! and it cannot answer "can User B reach **User A's** invoice?", because the tester
//! may only ever have captured User B asking for their own. The request that would
//! answer it has never existed, so it has to be built:
//!
//! ```text
//! captured:     GET /api/invoices/invoice-2001     as User B   (their own)
//! declared:     invoice-1001 belongs to User A
//! constructed:  GET /api/invoices/invoice-1001     as User B
//! ```
//!
//! # Nothing is guessed
//!
//! Both facts that make this possible — *which value is an object* and *who it
//! belongs to* — are declared by a human ([`hexora_types::object`]). A tool that
//! guessed would send traffic at an endpoint on the strength of a value that looked
//! like an id, and then reason about the answer as though the guess had been true.
//!
//! # A 200 is not a finding
//!
//! The interesting failure mode here is not missing a bug; it is reporting one that
//! is not there. An application can return 200 to a request for somebody else's
//! object for at least four innocent reasons: it served the *caller's* object and
//! ignored the identifier, it returned an error page that echoed the input, it
//! returned an empty collection, or the object is genuinely public. So the verdict
//! rests on what came back rather than on the status line:
//!
//! | What the response contained | Verdict |
//! | --- | --- |
//! | The owner's other declared identifiers | violation — the strongest evidence there is |
//! | The substituted identifier, in a document shaped like the caller's own | violation |
//! | The substituted identifier, in a document shaped like nothing | inconclusive: probably an echo |
//! | The caller's own identifiers | expected — the application scoped the lookup to the session |
//! | Neither | inconclusive |
//!
//! The middle row is why every sender sends one unmodified request first: without the
//! caller's own object document to compare against, "shaped like the object" has no
//! meaning.

use std::collections::HashMap;

use hexora_engine::transport::HttpTransport;
use hexora_repeater::{Draft, SendAs};
use hexora_storage::ConstructedAttempt;
use hexora_types::http::HttpRequest;
use hexora_types::identity::Identity;
use hexora_types::ids::{IdentityId, ObjectId, RequestId};
use hexora_types::object::{ObjectDeclaration, ObjectLocation};
use hexora_types::redact::is_sensitive_header;
use hexora_types::Result;

use crate::compare::{contains_any, Fingerprint, SAME_RESOURCE};
use crate::{AuthzTester, Outcome, Verdict};

/// How many constructed requests one run may send unless told otherwise.
///
/// Deliberately small. Every attempt is a real request at a real application, and a
/// tester who wants a hundred of them should have to say so.
pub const DEFAULT_MAX_ATTEMPTS: usize = 12;

/// The most a run may send however it is configured.
///
/// A ceiling rather than a preference: this crate exists to produce evidence, not
/// volume, and an authorization run that turns into a crawl is one that will get an
/// engagement stopped.
pub const HARD_MAX_ATTEMPTS: usize = 100;

/// One constructed request and what it established.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// Who sent it.
    pub sender: IdentityId,
    /// Their label, carried so a rendered result does not need the identity store.
    pub sender_label: String,
    /// The declaration whose value was substituted in.
    pub declaration: ObjectId,
    /// What kind of object it is.
    pub object_name: String,
    /// The identifier that was asked for.
    pub object_value: String,
    /// Who the tester says owns it.
    pub owner: IdentityId,
    /// Their label.
    pub owner_label: String,
    /// Where the substitution happened.
    pub location: ObjectLocation,
    /// What was in that place before.
    pub original_value: String,
    /// The stored constructed request, and half the evidence behind any finding.
    pub request: Option<RequestId>,
    /// The sender's own unmodified send, which this is compared against.
    pub control: Option<RequestId>,
    /// The status that came back.
    pub status: Option<u16>,
    /// How alike this response and the sender's own were.
    pub similarity: f32,
    /// What happened.
    pub outcome: Outcome,
    /// What it means.
    pub verdict: Verdict,
    /// Owner identifiers in the response *other than* the one that was asked for.
    ///
    /// The strongest evidence a constructed attempt can produce: an identifier the
    /// caller never sent, belonging to somebody else, in a response to the caller.
    pub disclosed_object_ids: Vec<String>,
    /// Whether the substituted identifier itself came back.
    ///
    /// On its own this proves little — an error page quoting its input echoes it too
    /// — which is why it is recorded separately from [`Self::disclosed_object_ids`].
    pub echoed: bool,
    /// The sender's own identifiers in the response, which exonerate the endpoint.
    pub own_object_ids: Vec<String>,
    /// Whether a second attempt reproduced the result.
    pub reproduced: bool,
    /// Why there is no request, when it failed.
    pub error: Option<String>,
    /// What the reader should know about this row.
    pub note: Option<String>,
}

impl Attempt {
    /// Whether this attempt shows an identity reaching somebody else's object.
    pub fn is_violation(&self) -> bool {
        self.verdict == Verdict::Violation
    }

    /// How the substitution reads in one line.
    pub fn describe_substitution(&self) -> String {
        format!(
            "{} → {} in {}",
            self.original_value,
            self.object_value,
            self.location.describe()
        )
    }
}

/// A finished construction run.
#[derive(Debug, Clone)]
pub struct Construction {
    /// The request every attempt was built from.
    pub base: RequestId,
    /// Its method.
    pub method: String,
    /// Its URL.
    pub url: String,
    /// Every attempt that was sent, in the order it was sent.
    pub attempts: Vec<Attempt>,
    /// Combinations that produced no request, and why.
    ///
    /// Reported rather than dropped: "nothing happened" and "there was nowhere to put
    /// the identifier" look identical otherwise, and only one of them is something
    /// the tester can fix.
    pub skipped: Vec<String>,
    /// The cap this run was held to.
    pub limit: usize,
}

impl Construction {
    /// Every attempt that reached somebody else's object.
    pub fn violations(&self) -> impl Iterator<Item = &Attempt> {
        self.attempts.iter().filter(|a| a.is_violation())
    }
}

/// What to construct, and as whom.
#[derive(Debug, Clone)]
pub struct ConstructionPlan {
    /// The captured request to build from.
    pub base: RequestId,
    /// The identities that will send the constructed requests.
    pub senders: Vec<Identity>,
    /// The objects to reach for. Each is attempted by every sender that does not own
    /// it.
    pub declarations: Vec<ObjectDeclaration>,
    /// Whether to send each violation a second time before reporting it.
    pub verify: bool,
    /// The most requests this run may send.
    pub limit: usize,
}

impl ConstructionPlan {
    /// A plan with the default attempt cap and verification off.
    pub fn new(
        base: RequestId,
        senders: Vec<Identity>,
        declarations: Vec<ObjectDeclaration>,
    ) -> Self {
        Self {
            base,
            senders,
            declarations,
            verify: false,
            limit: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Caps how many requests the run may send, within [`HARD_MAX_ATTEMPTS`].
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.clamp(1, HARD_MAX_ATTEMPTS);
        self
    }

    /// Whether each violation is attempted a second time before being reported.
    pub fn verifying(mut self, verify: bool) -> Self {
        self.verify = verify;
        self
    }
}

impl<T: HttpTransport> AuthzTester<T> {
    /// Builds cross-identity requests from a captured one and sends them.
    ///
    /// Every attempt goes out through the same repeater — and therefore the same
    /// [`ScopeGuard`](hexora_engine::guard::ScopeGuard) — as every other automated
    /// request in Hexora. There is no second send path here, which is the only way to
    /// promise that scope holds for constructed traffic too.
    pub async fn construct(&self, plan: &ConstructionPlan) -> Result<Construction> {
        let draft = self.repeater.draft_from(plan.base)?;
        let url = draft.request.url();
        let method = draft.request.method.clone();

        // Asked once, before anything is built. Constructed traffic is automated
        // traffic, and finding out per attempt would produce one identical failure
        // per attempt instead of one sentence about the project's scope.
        if let Some(first) = plan.senders.first() {
            if !self
                .repeater
                .decide_as(&draft, SendAs::authz(first))
                .permits_sending()
            {
                return Err(hexora_types::HexoraError::OutOfScope(url));
            }
        }

        // Persisted before anything is sent, so every generated row can name the
        // credential it was sent with for as long as the project exists.
        for sender in &plan.senders {
            self.identities.put(sender)?;
        }
        // And the declarations. A constructed request records which declaration it
        // came from; a row pointing at a declaration the project never held would be
        // a row nobody can explain, which is the one thing provenance exists to
        // prevent.
        for declaration in &plan.declarations {
            self.objects.put(declaration).map_err(|e| {
                hexora_types::HexoraError::invalid_input(
                    "declaration",
                    format!(
                        "{} could not be recorded ({e}). A declaration names the                          identity that owns the object, and that identity has to be one                          the project already holds",
                        declaration.describe()
                    ),
                )
            })?;
        }

        // Owner identifiers, per identity: what the identity itself declares plus
        // every object declared as theirs. Both are the tester's assertions, and a
        // response is searched for all of them.
        let owned = owned_identifiers(&plan.declarations, &plan.senders);
        let labels: HashMap<IdentityId, String> = plan
            .senders
            .iter()
            .map(|identity| (identity.id, identity.label.clone()))
            .collect();

        let mut construction = Construction {
            base: plan.base,
            method,
            url,
            attempts: Vec::new(),
            skipped: Vec::new(),
            limit: plan.limit,
        };

        // One unmodified send per sender, kept for the whole run. It is what "the
        // document this identity gets for its own object" means, and without it a
        // response can only be judged on its status line.
        let mut controls: HashMap<IdentityId, (RequestId, Fingerprint)> = HashMap::new();
        let mut stop = false;

        for sender in &plan.senders {
            if stop {
                break;
            }
            for declaration in &plan.declarations {
                if declaration.owner == sender.id {
                    continue;
                }
                if construction.attempts.len() >= plan.limit {
                    construction.skipped.push(format!(
                        "stopped at the {}-attempt limit; raise it to go further",
                        plan.limit
                    ));
                    stop = true;
                    break;
                }

                let Some((location, original)) = slot_for(
                    &draft.request,
                    plan.base,
                    declaration,
                    sender,
                    &plan.declarations,
                    &plan.senders,
                    &owned,
                ) else {
                    construction.skipped.push(format!(
                        "{}: nowhere to put {} — this request carries no value that has \
                         been declared as anybody's object, so there is no slot to \
                         substitute into. Declare the identifier that *is* in this \
                         request first",
                        sender.label, declaration.value,
                    ));
                    continue;
                };

                if original == declaration.value {
                    construction.skipped.push(format!(
                        "{}: the request already asks for {} — replaying it as another \
                         identity is what the matrix does, so nothing was constructed",
                        sender.label, declaration.value,
                    ));
                    continue;
                }

                // One unmodified send per sender, reused for every attempt they make.
                // `entry` is not usable here: producing the value is an await, and an
                // occupied entry held across it borrows the map for the whole send.
                let control = match controls.get(&sender.id) {
                    Some(control) => control.clone(),
                    None => match self.control_for(&draft, sender).await {
                        Ok(control) => {
                            controls.insert(sender.id, control.clone());
                            control
                        }
                        Err(e) => {
                            construction.skipped.push(format!(
                                "{}: could not establish a control response ({e}), so \
                                 nothing it received could be compared against its own",
                                sender.label
                            ));
                            break;
                        }
                    },
                };

                let attempt = self
                    .attempt(
                        &draft,
                        sender,
                        declaration,
                        &location,
                        &original,
                        &control,
                        &owned,
                        &labels,
                    )
                    .await;
                construction.attempts.push(attempt);
            }
        }

        if plan.verify {
            self.reproduce_attempts(&draft, plan, &controls, &owned, &labels, &mut construction)
                .await;
        }
        Ok(construction)
    }

    /// Sends every violation a second time and records whether it happened again.
    ///
    /// Reproduction is the difference between [`Confidence::Firm`] and
    /// [`Confidence::Confirmed`](hexora_types::Confidence::Confirmed): a one-off that
    /// does not repeat was a cache, a race, or a session that had not expired yet.
    #[allow(clippy::too_many_arguments)]
    async fn reproduce_attempts(
        &self,
        draft: &Draft,
        plan: &ConstructionPlan,
        controls: &HashMap<IdentityId, (RequestId, Fingerprint)>,
        owned: &HashMap<IdentityId, Vec<String>>,
        labels: &HashMap<IdentityId, String>,
        construction: &mut Construction,
    ) {
        for index in 0..construction.attempts.len() {
            if !construction.attempts[index].is_violation() {
                continue;
            }
            let sender_id = construction.attempts[index].sender;
            let declaration_id = construction.attempts[index].declaration;

            let (Some(sender), Some(declaration), Some(control)) = (
                plan.senders.iter().find(|s| s.id == sender_id),
                plan.declarations.iter().find(|d| d.id == declaration_id),
                controls.get(&sender_id),
            ) else {
                continue;
            };

            let location = construction.attempts[index].location.clone();
            let original = construction.attempts[index].original_value.clone();
            let again = self
                .attempt(
                    draft,
                    sender,
                    declaration,
                    &location,
                    &original,
                    control,
                    owned,
                    labels,
                )
                .await;

            construction.attempts[index].reproduced = again.is_violation();
            if !again.is_violation() {
                construction.attempts[index].note = Some(format!(
                    "did not reproduce on a second attempt ({} the second time)",
                    again.outcome.as_str()
                ));
            }
        }
    }

    /// Sends the request unmodified as one identity, to have their own object
    /// document to compare against.
    async fn control_for(
        &self,
        draft: &Draft,
        sender: &Identity,
    ) -> Result<(RequestId, Fingerprint)> {
        let sent = self.repeater.send_as(draft, SendAs::authz(sender)).await?;
        let fingerprint = Fingerprint::of(&sent.exchange.response);
        Ok((sent.id, fingerprint))
    }

    /// Builds one constructed request, sends it, and decides what it showed.
    #[allow(clippy::too_many_arguments)]
    async fn attempt(
        &self,
        draft: &Draft,
        sender: &Identity,
        declaration: &ObjectDeclaration,
        location: &ObjectLocation,
        original: &str,
        control: &(RequestId, Fingerprint),
        owned: &HashMap<IdentityId, Vec<String>>,
        labels: &HashMap<IdentityId, String>,
    ) -> Attempt {
        let mut attempt = Attempt {
            sender: sender.id,
            sender_label: sender.label.clone(),
            declaration: declaration.id,
            object_name: declaration.name.clone(),
            object_value: declaration.value.clone(),
            owner: declaration.owner,
            owner_label: labels
                .get(&declaration.owner)
                .cloned()
                .unwrap_or_else(|| declaration.owner.to_string()),
            location: location.clone(),
            original_value: original.to_string(),
            request: None,
            control: Some(control.0),
            status: None,
            similarity: 0.0,
            outcome: Outcome::Failed,
            verdict: Verdict::Inconclusive,
            disclosed_object_ids: Vec::new(),
            echoed: false,
            own_object_ids: Vec::new(),
            reproduced: false,
            error: None,
            note: None,
        };

        // The captured request is never touched: the substitution is applied to a
        // clone. What was captured must not depend on what was tested afterwards.
        let built = match location {
            ObjectLocation::Body { offset } => {
                substitute_in_body(&draft.request, *offset, original, &declaration.value)
            }
            other => substitute(&draft.request, other, &declaration.value),
        };
        let request = match built {
            Ok(request) => request,
            Err(e) => {
                attempt.error = Some(e.to_string());
                return attempt;
            }
        };

        // The parent is the request this was built from, so `hexora repeat --tree`
        // and the desktop history both answer "where did this come from?" without
        // knowing anything about object declarations.
        let constructed = Draft::derived_from(request, draft.parent);

        let sent = match self
            .repeater
            .send_as(&constructed, SendAs::authz(sender))
            .await
        {
            Ok(sent) => sent,
            Err(e) => {
                attempt.error = Some(e.to_string());
                return attempt;
            }
        };

        // Recorded before anything is concluded. A request that was sent and whose
        // reason was not written down is a row nobody can explain later.
        if let Some(source) = draft.parent {
            if let Err(e) = self.objects.record_attempt(&ConstructedAttempt {
                request: sent.id,
                source_request: source,
                declaration: Some(declaration.id),
                sender: Some(sender.id),
                location: location.clone(),
                original_value: original.to_string(),
                replacement_value: declaration.value.clone(),
            }) {
                tracing::warn!("could not record the provenance of a constructed attempt: {e}");
            }
        }

        let response = &sent.exchange.response;
        let empty = Vec::new();
        let owner_ids = owned.get(&declaration.owner).unwrap_or(&empty);
        let sender_ids = owned.get(&sender.id).unwrap_or(&empty);

        let found_for_owner = contains_any(&response.body, owner_ids);
        attempt.echoed = found_for_owner.contains(&declaration.value);
        attempt.disclosed_object_ids = found_for_owner
            .into_iter()
            .filter(|id| *id != declaration.value)
            .collect();
        attempt.own_object_ids = contains_any(&response.body, sender_ids);

        attempt.request = Some(sent.id);
        attempt.status = Some(response.status);
        attempt.similarity = control.1.similarity(&Fingerprint::of(response));

        judge(&mut attempt, sender, declaration);
        attempt
    }
}

/// Decides what one constructed response established.
///
/// A free function so the rules can be exercised without a transport: every
/// interesting case here is "what did the bytes contain", and none of them need a
/// socket.
fn judge(attempt: &mut Attempt, sender: &Identity, declaration: &ObjectDeclaration) {
    let status = attempt.status.unwrap_or(0);
    let looks_like_the_document = attempt.similarity >= SAME_RESOURCE;

    match status {
        401 | 403 | 407 => {
            attempt.outcome = Outcome::Denied;
            attempt.verdict = Verdict::Expected;
            return;
        }
        404 | 410 => {
            attempt.outcome = Outcome::NotFound;
            attempt.verdict = Verdict::Expected;
            attempt.note = Some(
                "the application said the object does not exist. That is what a \
                 well-built application returns to hide one, and also what a broken one \
                 returns when a lookup scoped to the wrong tenant comes back empty"
                    .into(),
            );
            return;
        }
        300..=399 => {
            attempt.outcome = Outcome::Redirected;
            attempt.verdict = Verdict::Expected;
            return;
        }
        500..=599 => {
            attempt.outcome = Outcome::ServerError;
            attempt.verdict = Verdict::Inconclusive;
            return;
        }
        _ => {}
    }

    // The application served the caller their own object and ignored the identifier
    // that was substituted in. That is the endpoint working.
    if !attempt.own_object_ids.is_empty() && attempt.disclosed_object_ids.is_empty() {
        attempt.outcome = Outcome::Different;
        attempt.verdict = Verdict::Expected;
        attempt.note = Some(format!(
            "served {}'s own data ({}) rather than the object that was asked for",
            sender.label,
            attempt.own_object_ids.join(", ")
        ));
        return;
    }

    // An identifier the caller never sent, belonging to somebody else, in a response
    // to the caller. The strongest thing a constructed attempt can produce.
    if !attempt.disclosed_object_ids.is_empty() {
        attempt.outcome = Outcome::Allowed;
        attempt.verdict = cross_identity(sender, declaration);
        return;
    }

    if attempt.echoed && looks_like_the_document {
        attempt.outcome = Outcome::Allowed;
        attempt.verdict = cross_identity(sender, declaration);
        return;
    }

    if attempt.echoed {
        attempt.outcome = Outcome::Different;
        attempt.verdict = Verdict::Inconclusive;
        attempt.note = Some(format!(
            "the response quotes {} but does not look like the document {} receives for \
             its own object ({:.0}% alike), so this may be an error page echoing its \
             input rather than a disclosure",
            declaration.value,
            sender.label,
            attempt.similarity * 100.0
        ));
        return;
    }

    if looks_like_the_document {
        // Same shape, nothing identifiable in it. Worth a tester's attention and not
        // worth a claim: a document of the right shape with no identifier in it cannot
        // be shown to be anybody's in particular.
        attempt.outcome = Outcome::Allowed;
        attempt.verdict = Verdict::Inconclusive;
        attempt.note = Some(format!(
            "{:.0}% alike the document {} receives for its own object, but it carries no \
             identifier that establishes whose object it is. Declare more of {}'s \
             objects to settle it",
            attempt.similarity * 100.0,
            sender.label,
            attempt.owner_label
        ));
        return;
    }

    attempt.outcome = Outcome::Different;
    attempt.verdict = Verdict::Inconclusive;
    attempt.note = Some(
        "the response carries neither the object that was asked for nor anything \
         belonging to the caller, so it establishes nothing either way"
            .into(),
    );
}

/// An identity reaching an object it does not own is the finding.
///
/// The owner's privilege level is deliberately not consulted. In a replay matrix the
/// direction matters — an administrator reading a user's record is what administration
/// means — but a *constructed* request is one nobody made in the ordinary course of
/// using the application, so "this principal could fetch that object by asking for it"
/// is worth reporting whichever way the privileges run, and the tester triages it.
fn cross_identity(sender: &Identity, declaration: &ObjectDeclaration) -> Verdict {
    if sender.id == declaration.owner {
        Verdict::Expected
    } else {
        Verdict::Violation
    }
}

/// Every identifier each identity is said to own: their own declarations plus the
/// object declarations naming them.
fn owned_identifiers(
    declarations: &[ObjectDeclaration],
    identities: &[Identity],
) -> HashMap<IdentityId, Vec<String>> {
    let mut owned: HashMap<IdentityId, Vec<String>> = HashMap::new();
    for identity in identities {
        owned
            .entry(identity.id)
            .or_default()
            .extend(identity.owned_object_ids.iter().cloned());
    }
    for declaration in declarations {
        let ids = owned.entry(declaration.owner).or_default();
        if !ids.contains(&declaration.value) {
            ids.push(declaration.value.clone());
        }
    }
    owned
}

/// Decides where in a request an object identifier should go.
///
/// The slot is a property of the **request**, not of who is sending it: whatever
/// place holds an object in `GET /accounts/acct-2000` holds one whoever asks. So it
/// is resolved once and every sender substitutes into the same place, which is also
/// what makes the attempts comparable to each other.
///
/// Two rules, in this order:
///
/// 1. **Where a declared value already sits.** Any value the tester has declared as
///    somebody's, appearing in this request, marks an object slot — that is what a
///    declaration means. The sender's own object is preferred, because "as User B,
///    ask for User A's invoice" built out of "User B asking for their own" is the
///    construction with the cleanest control.
/// 2. **Where *this* declaration was found**, if it was found in this very request.
///
/// A location recorded on a *different* endpoint is deliberately not reused. Path
/// segment 1 of `/accounts/{id}` is an identifier; path segment 1 of
/// `/secure/accounts/{id}` is the word "accounts", and substituting there produces a
/// request to an endpoint nobody chose and an answer that means nothing.
///
/// `None` is reported to the tester rather than silently producing no attempt.
fn slot_for(
    request: &HttpRequest,
    base: RequestId,
    declaration: &ObjectDeclaration,
    sender: &Identity,
    declarations: &[ObjectDeclaration],
    others: &[Identity],
    owned: &HashMap<IdentityId, Vec<String>>,
) -> Option<(ObjectLocation, String)> {
    // A stable order, so two runs of the same project construct the same requests:
    // the sender's own identifiers first, then every declared value in the order the
    // project holds them, then everybody else's. The last group matters for an
    // identity that owns nothing — the anonymous control owns nothing by definition,
    // and the slot is a property of the request rather than of who is sending.
    let mut candidates: Vec<&String> = Vec::new();
    if let Some(ids) = owned.get(&sender.id) {
        candidates.extend(ids.iter());
    }
    // Including the target's own value looks pointless and is not: a request that
    // already asks for it resolves the slot here, and the caller then reports "the
    // matrix covers that" instead of "there is nowhere to put it", which is the
    // difference between a useful message and a confusing one.
    candidates.extend(declarations.iter().map(|other| &other.value));
    for identity in others {
        if identity.id == sender.id {
            continue;
        }
        if let Some(ids) = owned.get(&identity.id) {
            candidates.extend(ids.iter());
        }
    }

    for candidate in candidates {
        if let Some(location) = locate(request, candidate).into_iter().next() {
            return Some((location, candidate.clone()));
        }
    }

    if declaration.source_request == Some(base) {
        let current = value_at(request, &declaration.location)?;
        return Some((declaration.location.clone(), current));
    }
    None
}

/// Every place a value appears in a request.
///
/// Sensitive headers are skipped without exception. An `Authorization` value is a
/// credential, not an object identifier, and a substitution that rewrote one would
/// change *who is asking* in the middle of a test about what they may ask for.
pub fn locate(request: &HttpRequest, value: &str) -> Vec<ObjectLocation> {
    let mut found = Vec::new();
    if value.is_empty() {
        return found;
    }

    let (path, query) = split_target(&request.path);
    for (index, segment) in path_segments(path).enumerate() {
        if segment == value || percent_decode(segment) == value {
            found.push(ObjectLocation::PathSegment { index });
        }
    }

    let mut seen: HashMap<String, usize> = HashMap::new();
    for (name, parameter) in query_pairs(query) {
        let occurrence = seen.entry(name.to_string()).or_insert(0);
        if parameter == value || percent_decode(parameter) == value {
            found.push(ObjectLocation::Query {
                name: name.to_string(),
                occurrence: *occurrence,
            });
        }
        *occurrence += 1;
    }

    let mut header_seen: HashMap<String, usize> = HashMap::new();
    for header in request.headers.iter() {
        let lower = header.name.to_ascii_lowercase();
        let occurrence = header_seen.entry(lower.clone()).or_insert(0);
        if !is_sensitive_header(&header.name) && header.value_lossy() == value {
            found.push(ObjectLocation::Header {
                name: header.name.clone(),
                occurrence: *occurrence,
            });
        }
        *occurrence += 1;
    }

    if let Some(offset) = find_bytes(&request.body, value.as_bytes()) {
        found.push(ObjectLocation::Body { offset });
    }

    found
}

/// What is currently at a location, if it resolves in this request.
pub fn value_at(request: &HttpRequest, location: &ObjectLocation) -> Option<String> {
    let (path, query) = split_target(&request.path);
    match location {
        ObjectLocation::PathSegment { index } => {
            path_segments(path).nth(*index).map(str::to_string)
        }
        ObjectLocation::Query { name, occurrence } => query_pairs(query)
            .filter(|(key, _)| key == name)
            .nth(*occurrence)
            .map(|(_, value)| value.to_string()),
        ObjectLocation::Header { name, occurrence } => request
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name) && !is_sensitive_header(&h.name))
            .nth(*occurrence)
            .map(|h| h.value_lossy().into_owned()),
        // A body offset alone cannot say how long the value is, so it only resolves
        // together with the declaration that produced it. Callers that need the
        // current value use rule 1 in `slot_for`, which knows what it matched — and
        // `Anywhere` is that rule by definition.
        ObjectLocation::Body { .. } | ObjectLocation::Anywhere => None,
    }
}

/// Returns a copy of the request with one location's value replaced.
///
/// The input is never modified. The tester's captured request is evidence; a function
/// that edited it in place would make the record of what was captured depend on what
/// was tested afterwards.
pub fn substitute(
    request: &HttpRequest,
    location: &ObjectLocation,
    replacement: &str,
) -> Result<HttpRequest> {
    hexora_types::object::validate_identifier(replacement)?;
    let mut built = request.clone();

    match location {
        ObjectLocation::PathSegment { index } => {
            let (path, query) = split_target(&request.path);
            let mut segments: Vec<String> = path_segments(path).map(str::to_string).collect();
            let slot = segments.get_mut(*index).ok_or_else(|| {
                hexora_types::HexoraError::invalid_input(
                    "location",
                    format!("this request has no path segment {index}"),
                )
            })?;
            *slot = encode_path_segment(replacement);

            let leading = if path.starts_with('/') { "/" } else { "" };
            let trailing = if path.len() > 1 && path.ends_with('/') {
                "/"
            } else {
                ""
            };
            built.path = format!(
                "{leading}{}{trailing}{}",
                segments.join("/"),
                query.map(|q| format!("?{q}")).unwrap_or_default()
            );
        }
        ObjectLocation::Query { name, occurrence } => {
            let (path, query) = split_target(&request.path);
            let query = query.ok_or_else(|| {
                hexora_types::HexoraError::invalid_input(
                    "location",
                    "this request has no query string",
                )
            })?;

            let mut matched = 0usize;
            let mut replaced = false;
            let rebuilt: Vec<String> = query
                .split('&')
                .map(|pair| {
                    let (key, value) = match pair.split_once('=') {
                        Some((key, value)) => (key, Some(value)),
                        None => (pair, None),
                    };
                    if key != name {
                        return pair.to_string();
                    }
                    let this = matched;
                    matched += 1;
                    if this != *occurrence {
                        return pair.to_string();
                    }
                    replaced = true;
                    match value {
                        Some(_) => format!("{key}={}", encode_query_value(replacement)),
                        None => format!("{key}={}", encode_query_value(replacement)),
                    }
                })
                .collect();

            if !replaced {
                return Err(hexora_types::HexoraError::invalid_input(
                    "location",
                    format!("this request has no {name} parameter at occurrence {occurrence}"),
                ));
            }
            built.path = format!("{path}?{}", rebuilt.join("&"));
        }
        ObjectLocation::Header { name, occurrence } => {
            if is_sensitive_header(name) {
                return Err(hexora_types::HexoraError::invalid_input(
                    "location",
                    format!(
                        "{name} carries a credential, not an object identifier, and is \
                         never substituted"
                    ),
                ));
            }
            let mut matched = 0usize;
            let mut replaced = false;
            let mut headers = hexora_types::http::Headers::new();
            for header in request.headers.iter() {
                if header.name.eq_ignore_ascii_case(name) {
                    let this = matched;
                    matched += 1;
                    if this == *occurrence {
                        replaced = true;
                        headers.append(hexora_types::http::Header::new(
                            header.name.clone(),
                            replacement,
                        ));
                        continue;
                    }
                }
                headers.append(header.clone());
            }
            if !replaced {
                return Err(hexora_types::HexoraError::invalid_input(
                    "location",
                    format!("this request has no {name} header at occurrence {occurrence}"),
                ));
            }
            built.headers = headers;
        }
        ObjectLocation::Body { offset } => {
            // A byte offset alone does not say how long the value is. The caller that
            // knows — because it matched the value in the first place — calls
            // `substitute_in_body`, and arriving here means somebody lost that.
            return Err(hexora_types::HexoraError::invalid_input(
                "location",
                format!(
                    "a body substitution needs the value it is replacing, not only \
                     byte {offset}; call substitute_in_body"
                ),
            ));
        }
        ObjectLocation::Anywhere => {
            return Err(hexora_types::HexoraError::invalid_input(
                "location",
                "this declaration records no place, so there is nothing to substitute \
                 into. A run resolves it against the sender's own object instead",
            ));
        }
    }

    Ok(built)
}

/// Replaces one occurrence of a value in the body, leaving every other byte alone.
///
/// Byte-level on purpose. Parsing the body to JSON and re-serializing it would
/// reorder keys, drop duplicates and rewrite whitespace — a request the tester never
/// wrote, sent under their name, in a tool whose entire premise is that it does not
/// rewrite what you asked it to send.
pub fn substitute_in_body(
    request: &HttpRequest,
    offset: usize,
    original: &str,
    replacement: &str,
) -> Result<HttpRequest> {
    hexora_types::object::validate_identifier(replacement)?;
    let end = offset + original.len();
    if end > request.body.len() || &request.body[offset..end] != original.as_bytes() {
        return Err(hexora_types::HexoraError::invalid_input(
            "location",
            format!("the body no longer holds {original:?} at byte {offset}"),
        ));
    }

    let mut body = Vec::with_capacity(request.body.len() + replacement.len());
    body.extend_from_slice(&request.body[..offset]);
    body.extend_from_slice(replacement.as_bytes());
    body.extend_from_slice(&request.body[end..]);

    let mut built = request.clone();
    built.body = bytes::Bytes::from(body);
    // Content-Length is left exactly as the tester had it. Correcting it silently is
    // what a client library does; a security tool that framed a body differently from
    // the header would hide the very thing somebody might be testing for.
    Ok(built)
}

// ---------------------------------------------------------------------------
// Target parsing
// ---------------------------------------------------------------------------

fn split_target(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

fn path_segments(path: &str) -> impl Iterator<Item = &str> {
    path.strip_prefix('/').unwrap_or(path).split('/')
}

fn query_pairs(query: Option<&str>) -> impl Iterator<Item = (&str, &str)> {
    query
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Percent-decodes, leaving invalid escapes as written.
///
/// Used only for *matching* a declared value against what is in a request, never for
/// building one. A tester who declared `acct 1` should still match `acct%201`.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Encodes a value so it stays inside one path segment.
///
/// An identifier containing `/` would otherwise become two segments and the request
/// would be asking a different endpoint — a test whose result means nothing, run
/// against a URL nobody chose. `..` is encoded for the same reason: a substitution is
/// meant to change which object is asked for, not which path is walked.
fn encode_path_segment(value: &str) -> String {
    encode(value, |byte| matches!(byte, b'/' | b'?' | b'#' | b' '))
}

/// Encodes a value so it stays inside one query parameter.
fn encode_query_value(value: &str) -> String {
    encode(value, |byte| {
        matches!(byte, b'&' | b'#' | b'?' | b' ' | b'+')
    })
}

/// Percent-encodes the bytes a predicate selects, plus any stray `%`.
///
/// A `%` that already begins a valid escape is left alone, so a tester who declared
/// `acct%2F1` gets that value on the wire rather than `acct%252F1`.
fn encode(value: &str, needs_encoding: impl Fn(u8) -> bool) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'%' {
            let valid_escape =
                i + 2 < bytes.len() && hex(bytes[i + 1]).is_some() && hex(bytes[i + 2]).is_some();
            if valid_escape {
                out.push('%');
            } else {
                out.push_str("%25");
            }
            i += 1;
            continue;
        }
        if needs_encoding(byte) {
            out.push_str(&format!("%{byte:02X}"));
        } else {
            out.push(byte as char);
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hexora_engine::guard::ScopeGuard;
    use hexora_engine::transport::{Exchange, SendOptions};
    use hexora_repeater::Repeater;
    use hexora_storage::{
        FindingStore, IdentityStore, MemoryBlobStore, MetadataDb, ObjectStore, TrafficStore,
    };
    use hexora_types::finding::{Confidence, Evidence, FindingStatus, Severity};
    use hexora_types::http::{Headers, HttpResponse, HttpService, HttpVersion};
    use hexora_types::scope::{Scope, ScopeRule};

    use super::*;

    const HOST: &str = "api.example.com";

    /// How an application answers a request for an object it was not asked to protect.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Behaviour {
        /// Authenticated is treated as authorized: the classic IDOR.
        Vulnerable,
        /// Ownership is checked: anybody else gets a 403.
        Secure,
        /// The lookup is scoped to the session, so the caller gets their own object
        /// whatever identifier they send.
        IgnoresTheIdentifier,
        /// 200, with a document that says nothing about whose it is.
        AnonymousDocument,
        /// 200, with something unrelated to the object.
        Unrelated,
        /// 200, quoting the identifier inside an error page.
        EchoesInAnErrorPage,
    }

    /// A tiny account application, answering on the object that was asked for.
    ///
    /// Keyed on the `Authorization` header because that is what an identity actually
    /// puts on the wire, and on the path because that is what a constructed attempt
    /// changes. A fake keyed on anything else would be testing the test.
    #[derive(Debug)]
    struct Accounts {
        behaviour: Behaviour,
        sent: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl Accounts {
        fn new(behaviour: Behaviour) -> Arc<Self> {
            Arc::new(Self {
                behaviour,
                sent: std::sync::Mutex::new(Vec::new()),
            })
        }

        /// Every (credential, target) pair the application was asked for.
        fn requests(&self) -> Vec<(String, String)> {
            self.sent.lock().unwrap().clone()
        }

        fn owner_of(account: &str) -> Option<&'static str> {
            match account {
                "acct-1000" => Some("TOKEN_A"),
                "acct-2000" => Some("TOKEN_B"),
                _ => None,
            }
        }

        fn document(account: &str) -> String {
            match account {
                "acct-1000" => {
                    r#"{"id":"acct-1000","owner":"User A","email":"alice@example.com"}"#.into()
                }
                _ => r#"{"id":"acct-2000","owner":"User B","email":"bob@example.com"}"#.into(),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct Shared(Arc<Accounts>);

    #[async_trait::async_trait]
    impl HttpTransport for Shared {
        async fn send(&self, request: HttpRequest, _options: SendOptions) -> Result<Exchange> {
            let auth = request
                .headers
                .get("Authorization")
                .map(|h| h.value_lossy().into_owned())
                .unwrap_or_default();
            self.0
                .sent
                .lock()
                .unwrap()
                .push((auth.clone(), request.path.clone()));

            // Whatever the request asks for: the last path segment, or the `id`
            // parameter, or the id in the body — the three places a test substitutes.
            let asked_for = asked_for(&request);
            let caller = auth.trim_start_matches("Bearer ").to_string();

            // Every behaviour serves a caller their *own* object normally. Only what
            // happens when they ask for somebody else's is the variable — which is
            // also what makes the control response mean something: it is the document
            // this identity gets when the application is working.
            let owns = Accounts::owner_of(&asked_for) == Some(caller.as_str());
            let (status, body) = if caller.is_empty() {
                (401, r#"{"error":"authentication required"}"#.to_string())
            } else if owns {
                (200, Accounts::document(&asked_for))
            } else {
                match self.0.behaviour {
                    Behaviour::Vulnerable => (200, Accounts::document(&asked_for)),
                    Behaviour::Secure => (403, r#"{"error":"forbidden"}"#.to_string()),
                    Behaviour::IgnoresTheIdentifier => {
                        let own = if caller == "TOKEN_A" {
                            "acct-1000"
                        } else {
                            "acct-2000"
                        };
                        (200, Accounts::document(own))
                    }
                    Behaviour::AnonymousDocument => (
                        200,
                        r#"{"id":"redacted","owner":"redacted","email":"redacted"}"#.to_string(),
                    ),
                    Behaviour::Unrelated => (200, r#"{"items":[],"page":1,"total":0}"#.to_string()),
                    Behaviour::EchoesInAnErrorPage => (
                        200,
                        format!(r#"{{"error":"no such account: {asked_for}"}}"#),
                    ),
                }
            };

            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json");
            Ok(Exchange {
                request,
                encoded_body: None,
                content_encoding: None,
                raw_request: None,
                response: HttpResponse {
                    status,
                    reason: None,
                    version: HttpVersion::Http11,
                    headers,
                    body: bytes::Bytes::from(body),
                    truncated: false,
                },
                duration: std::time::Duration::from_millis(1),
                tls: None,
            })
        }
    }

    fn asked_for(request: &HttpRequest) -> String {
        let body = String::from_utf8_lossy(&request.body);
        if let Some(at) = body.find("\"account\":\"") {
            let rest = &body[at + 11..];
            if let Some(end) = rest.find('"') {
                return rest[..end].to_string();
            }
        }
        let (path, query) = super::split_target(&request.path);
        if let Some(query) = query {
            for (name, value) in super::query_pairs(Some(query)) {
                if name == "id" {
                    return value.to_string();
                }
            }
        }
        path.rsplit('/').next().unwrap_or_default().to_string()
    }

    /// A project, its stores, and the database behind them.
    struct Fixture {
        db: MetadataDb,
        traffic: Arc<TrafficStore>,
        identities: IdentityStore,
    }

    fn fixture() -> Fixture {
        let db = MetadataDb::in_memory().unwrap();
        let identities = IdentityStore::new(db.clone());
        // Both principals exist in the project before anything runs, as they do in
        // real use: an object is declared as belonging to an identity somebody added.
        identities.put(&user_a()).unwrap();
        identities.put(&user_b()).unwrap();
        Fixture {
            traffic: Arc::new(TrafficStore::new(
                db.clone(),
                Arc::new(MemoryBlobStore::new()),
            )),
            identities,
            db,
        }
    }

    fn tester(fixture: &Fixture, app: Arc<Accounts>, scope: Scope) -> AuthzTester<Shared> {
        let guard = ScopeGuard::new(Shared(app), Arc::new(scope));
        AuthzTester::new(
            Repeater::new(guard, fixture.traffic.clone()),
            fixture.traffic.clone(),
            fixture.identities.clone(),
        )
    }

    fn in_scope() -> Scope {
        Scope::new().include(ScopeRule::host(HOST))
    }

    /// Captures User B asking for their *own* account — the case a replay cannot test.
    fn capture(fixture: &Fixture, target: &str) -> RequestId {
        capture_request(fixture, HttpRequest::get(service(), target))
    }

    fn capture_request(fixture: &Fixture, request: HttpRequest) -> RequestId {
        let mut headers = Headers::new();
        headers.set("Content-Type", "application/json");
        fixture
            .traffic
            .record(&hexora_storage::CapturedExchange {
                request,
                response: HttpResponse {
                    status: 200,
                    reason: None,
                    version: HttpVersion::Http11,
                    headers,
                    body: bytes::Bytes::from(Accounts::document("acct-2000")),
                    truncated: false,
                },
                encoded_body: None,
                raw_request: None,
                content_encoding: None,
                origin: "proxy",
                identity: None,
                parent: None,
                quirks: Vec::new(),
                tls: None,
                duration_ms: 1,
            })
            .unwrap()
    }

    fn service() -> HttpService {
        HttpService::new(HOST, 443, true)
    }

    /// The fixture identities have fixed ids, so calling `user_a()` twice names the
    /// same principal. Ownership is by id, and two identities with the same label are
    /// two different people as far as a declaration is concerned.
    fn user_a() -> Identity {
        let mut identity = Identity::bearer("User A", "TOKEN_A");
        identity.id = "00000000000000000000000000000a01".parse().unwrap();
        identity.owned_object_ids = vec!["acct-1000".into()];
        identity
    }

    fn user_b() -> Identity {
        let mut identity = Identity::bearer("User B", "TOKEN_B");
        identity.id = "00000000000000000000000000000b02".parse().unwrap();
        identity.owned_object_ids = vec!["acct-2000".into()];
        identity
    }

    fn declaration(owner: &Identity, value: &str, location: ObjectLocation) -> ObjectDeclaration {
        ObjectDeclaration::new("account", value, owner.id, location).unwrap()
    }

    // -----------------------------------------------------------------------
    // Substitution
    // -----------------------------------------------------------------------

    #[test]
    fn a_path_identifier_is_located_and_replaced() {
        let request = HttpRequest::get(service(), "/accounts/acct-2000");
        let found = locate(&request, "acct-2000");
        assert_eq!(found, vec![ObjectLocation::PathSegment { index: 1 }]);

        let built = substitute(&request, &found[0], "acct-1000").unwrap();
        assert_eq!(built.path, "/accounts/acct-1000");
        assert_eq!(
            request.path, "/accounts/acct-2000",
            "the request a substitution was built from is never modified"
        );
    }

    #[test]
    fn a_query_identifier_is_located_and_replaced() {
        let request = HttpRequest::get(service(), "/accounts?id=acct-2000&view=full");
        let found = locate(&request, "acct-2000");
        assert_eq!(
            found,
            vec![ObjectLocation::Query {
                name: "id".into(),
                occurrence: 0
            }]
        );

        let built = substitute(&request, &found[0], "acct-1000").unwrap();
        assert_eq!(built.path, "/accounts?id=acct-1000&view=full");
    }

    #[test]
    fn a_json_body_identifier_is_replaced_byte_for_byte() {
        // No JSON parsing: the bytes around the identifier survive exactly, including
        // the duplicate key and the odd spacing, because a request the tester did not
        // write is a request they cannot reason about.
        let mut request = HttpRequest::get(service(), "/accounts/lookup");
        request.method = "POST".into();
        request.body = bytes::Bytes::from(
            r#"{"account":"acct-2000",  "account":"acct-2000", "note":"keep\tme"}"#,
        );

        let found = locate(&request, "acct-2000");
        let ObjectLocation::Body { offset } = found[0] else {
            panic!("expected a body location, got {found:?}");
        };

        let built = substitute_in_body(&request, offset, "acct-2000", "acct-1000").unwrap();
        assert_eq!(
            String::from_utf8_lossy(&built.body),
            r#"{"account":"acct-1000",  "account":"acct-2000", "note":"keep\tme"}"#,
            "only the matched occurrence changes"
        );
    }

    #[test]
    fn a_duplicated_query_parameter_is_addressed_by_occurrence() {
        let request = HttpRequest::get(service(), "/a?id=one&id=two");
        let built = substitute(
            &request,
            &ObjectLocation::Query {
                name: "id".into(),
                occurrence: 1,
            },
            "three",
        )
        .unwrap();
        assert_eq!(built.path, "/a?id=one&id=three");
    }

    #[test]
    fn a_duplicated_header_is_addressed_by_occurrence() {
        let mut request = HttpRequest::get(service(), "/a");
        request
            .headers
            .append(hexora_types::http::Header::new("X-Account", "one"));
        request
            .headers
            .append(hexora_types::http::Header::new("X-Account", "two"));

        let built = substitute(
            &request,
            &ObjectLocation::Header {
                name: "X-Account".into(),
                occurrence: 1,
            },
            "three",
        )
        .unwrap();
        let values: Vec<String> = built
            .headers
            .iter()
            .filter(|h| h.name == "X-Account")
            .map(|h| h.value_lossy().into_owned())
            .collect();
        assert_eq!(values, vec!["one", "three"]);
    }

    #[test]
    fn a_credential_header_is_never_an_object_location() {
        // Substituting into `Authorization` would change *who is asking* in the middle
        // of a test about what they may ask for.
        let mut request = HttpRequest::get(service(), "/a");
        request.headers.set("Authorization", "Bearer acct-2000");

        assert!(
            locate(&request, "acct-2000").is_empty(),
            "a credential is not an object identifier"
        );
        let refused = substitute(
            &request,
            &ObjectLocation::Header {
                name: "Authorization".into(),
                occurrence: 0,
            },
            "acct-1000",
        );
        assert!(refused.is_err());
    }

    #[test]
    fn a_path_traversal_payload_stays_inside_its_segment() {
        // A substitution changes which object is asked for. It must not change which
        // path is walked, or the answer is about an endpoint nobody chose.
        let request = HttpRequest::get(service(), "/accounts/acct-2000");
        let built = substitute(
            &request,
            &ObjectLocation::PathSegment { index: 1 },
            "../../admin",
        )
        .unwrap();
        assert_eq!(built.path, "/accounts/..%2F..%2Fadmin");
    }

    #[test]
    fn a_query_payload_cannot_add_a_parameter() {
        let request = HttpRequest::get(service(), "/a?id=one");
        let built = substitute(
            &request,
            &ObjectLocation::Query {
                name: "id".into(),
                occurrence: 0,
            },
            "two&admin=1",
        )
        .unwrap();
        assert_eq!(built.path, "/a?id=two%26admin=1");
    }

    #[test]
    fn an_identifier_that_is_already_encoded_is_not_encoded_twice() {
        let request = HttpRequest::get(service(), "/accounts/acct-2000");
        let built = substitute(
            &request,
            &ObjectLocation::PathSegment { index: 1 },
            "acct%2F1",
        )
        .unwrap();
        assert_eq!(built.path, "/accounts/acct%2F1");
    }

    #[test]
    fn a_stray_percent_is_encoded() {
        let request = HttpRequest::get(service(), "/accounts/acct-2000");
        let built =
            substitute(&request, &ObjectLocation::PathSegment { index: 1 }, "100%").unwrap();
        assert_eq!(built.path, "/accounts/100%25");
    }

    #[test]
    fn a_value_with_control_characters_is_refused_at_substitution_too() {
        // Declaration validates, and so does substitution: the two are separate entry
        // points and a check on only one of them is a check nobody can rely on.
        let request = HttpRequest::get(service(), "/accounts/acct-2000");
        let refused = substitute(
            &request,
            &ObjectLocation::PathSegment { index: 1 },
            "acct\r\nX-Injected: 1",
        );
        assert!(refused.is_err());
    }

    #[test]
    fn a_percent_encoded_value_in_a_request_still_matches_what_was_declared() {
        let request = HttpRequest::get(service(), "/accounts/acct%201");
        assert_eq!(
            locate(&request, "acct 1"),
            vec![ObjectLocation::PathSegment { index: 1 }]
        );
    }

    #[test]
    fn matching_is_byte_exact_and_does_not_normalize_unicode() {
        // Two spellings of the same character are two different identifiers as far as
        // an application is concerned, and which one it accepts may be the finding.
        // Normalizing here would hide that, so a declaration that does not match is
        // reported as not found rather than quietly matching something else.
        let composed = "caf\u{e9}-1"; // é as one code point
        let decomposed = "cafe\u{301}-1"; // e followed by a combining acute
        let request = HttpRequest::get(service(), format!("/accounts/{composed}"));

        assert_eq!(
            locate(&request, composed),
            vec![ObjectLocation::PathSegment { index: 1 }]
        );
        assert!(
            locate(&request, decomposed).is_empty(),
            "a different byte sequence is a different identifier"
        );
    }

    #[test]
    fn a_double_encoded_value_is_not_decoded_twice_when_matching() {
        // `%2561` decodes once to `%61`, not to `a`. Decoding to a fixed point here
        // would match a value the application will never see — the same mistake scope
        // normalization exists to avoid, in the other direction.
        let request = HttpRequest::get(service(), "/accounts/%2561");
        assert_eq!(
            locate(&request, "%61"),
            vec![ObjectLocation::PathSegment { index: 1 }]
        );
        assert!(locate(&request, "a").is_empty());
    }

    #[test]
    fn substituting_never_touches_anything_but_the_slot() {
        let mut request = HttpRequest::get(service(), "/accounts/acct-2000?view=full&x=1");
        request.headers.set("Authorization", "Bearer TOKEN_B");
        request.headers.set("X-Trace", "keep-me");
        request.body = bytes::Bytes::from("untouched");

        let built = substitute(
            &request,
            &ObjectLocation::PathSegment { index: 1 },
            "acct-1000",
        )
        .unwrap();

        assert_eq!(built.path, "/accounts/acct-1000?view=full&x=1");
        assert_eq!(built.body, request.body, "the body is not rewritten");
        assert_eq!(
            built
                .headers
                .get("Authorization")
                .map(|h| h.value_lossy().into_owned()),
            Some("Bearer TOKEN_B".to_string()),
            "the credential is not touched"
        );
        assert_eq!(
            built
                .headers
                .get("X-Trace")
                .map(|h| h.value_lossy().into_owned()),
            Some("keep-me".to_string())
        );
        assert_eq!(built.method, request.method);
    }

    #[test]
    fn an_oversized_identifier_never_reaches_a_request() {
        let request = HttpRequest::get(service(), "/accounts/acct-2000");
        let long = "a".repeat(hexora_types::object::MAX_IDENTIFIER_LEN + 1);
        assert!(substitute(&request, &ObjectLocation::PathSegment { index: 1 }, &long).is_err());
    }

    #[test]
    fn a_location_that_does_not_resolve_is_an_error_rather_than_a_silent_no_op() {
        let request = HttpRequest::get(service(), "/accounts");
        assert!(substitute(&request, &ObjectLocation::PathSegment { index: 9 }, "x").is_err());
        assert!(substitute(
            &request,
            &ObjectLocation::Query {
                name: "id".into(),
                occurrence: 0
            },
            "x"
        )
        .is_err());
    }

    // -----------------------------------------------------------------------
    // Running attempts
    // -----------------------------------------------------------------------

    async fn run(
        behaviour: Behaviour,
        target: &str,
        declarations: Vec<ObjectDeclaration>,
        senders: Vec<Identity>,
    ) -> (Fixture, Arc<Accounts>, RequestId, Construction) {
        let fixture = fixture();
        let app = Accounts::new(behaviour);
        let tester = tester(&fixture, app.clone(), in_scope());
        let base = capture(&fixture, target);

        let plan = ConstructionPlan::new(base, senders, declarations);
        let construction = tester.construct(&plan).await.unwrap();
        (fixture, app, base, construction)
    }

    #[tokio::test]
    async fn user_b_reaching_user_a_object_is_a_violation_with_evidence() {
        let (fixture, app, base, construction) = run(
            Behaviour::Vulnerable,
            "/accounts/acct-2000",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
            vec![user_b()],
        )
        .await;

        assert_eq!(construction.attempts.len(), 1, "{:?}", construction.skipped);
        let attempt = &construction.attempts[0];
        assert!(attempt.is_violation(), "{attempt:?}");
        assert_eq!(attempt.original_value, "acct-2000");
        assert_eq!(attempt.object_value, "acct-1000");
        assert_eq!(attempt.status, Some(200));
        assert!(attempt.echoed, "the object that was asked for came back");

        // The application really was asked for the other account, as User B.
        let asked = app.requests();
        assert!(
            asked.contains(&(
                "Bearer TOKEN_B".to_string(),
                "/accounts/acct-1000".to_string()
            )),
            "{asked:?}"
        );

        // And the capture the tester chose is untouched.
        let stored = fixture.traffic.request(base).unwrap();
        assert_eq!(stored.path, "/accounts/acct-2000");

        let target_id = fixture.traffic.target_of(base).unwrap();
        let findings = crate::analysis::construction_findings(&construction, target_id);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].confidence,
            Confidence::Firm,
            "an identity received a document of the object's shape carrying the              identifier it asked for: that is a fact about the bytes, not a guess"
        );
        assert!(findings[0].confidence.is_actionable());
        assert!(
            findings[0].title.contains("User B can reach"),
            "{}",
            findings[0].title
        );
        assert!(matches!(
            findings[0].evidence[0],
            Evidence::Comparison { .. }
        ));
        assert!(findings[0].validate().is_ok());
    }

    #[tokio::test]
    async fn a_secure_application_produces_no_finding_at_all() {
        let (fixture, _, base, construction) = run(
            Behaviour::Secure,
            "/accounts/acct-2000",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
            vec![user_b()],
        )
        .await;

        let attempt = &construction.attempts[0];
        assert_eq!(attempt.status, Some(403));
        assert_eq!(attempt.outcome, Outcome::Denied);
        assert!(!attempt.is_violation());

        let target_id = fixture.traffic.target_of(base).unwrap();
        assert!(crate::analysis::construction_findings(&construction, target_id).is_empty());
    }

    #[tokio::test]
    async fn an_endpoint_that_ignores_the_identifier_is_cleared_rather_than_reported() {
        // The lookup is scoped to the session, so the caller gets their own object
        // whatever they ask for. The response is a perfect shape match, which is why
        // the identifiers inside are what decides it.
        let (fixture, _, base, construction) = run(
            Behaviour::IgnoresTheIdentifier,
            "/accounts/acct-2000",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
            vec![user_b()],
        )
        .await;

        let attempt = &construction.attempts[0];
        assert_eq!(attempt.status, Some(200));
        assert!(!attempt.is_violation(), "{attempt:?}");
        assert_eq!(attempt.own_object_ids, vec!["acct-2000"]);
        assert!(attempt.note.as_deref().unwrap().contains("own data"));

        let target_id = fixture.traffic.target_of(base).unwrap();
        assert!(crate::analysis::construction_findings(&construction, target_id).is_empty());
    }

    #[tokio::test]
    async fn a_200_with_nothing_identifiable_in_it_is_not_a_finding() {
        let (fixture, _, base, construction) = run(
            Behaviour::Unrelated,
            "/accounts/acct-2000",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
            vec![user_b()],
        )
        .await;

        let attempt = &construction.attempts[0];
        assert_eq!(attempt.status, Some(200));
        assert!(!attempt.is_violation());
        assert!(!attempt.echoed);

        let target_id = fixture.traffic.target_of(base).unwrap();
        assert!(
            crate::analysis::construction_findings(&construction, target_id).is_empty(),
            "a 200 is not evidence of anything on its own"
        );
    }

    #[tokio::test]
    async fn an_error_page_that_quotes_the_identifier_is_not_a_disclosure() {
        let (fixture, _, base, construction) = run(
            Behaviour::EchoesInAnErrorPage,
            "/accounts/acct-2000",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
            vec![user_b()],
        )
        .await;

        let attempt = &construction.attempts[0];
        assert!(attempt.echoed, "the identifier is in the body");
        assert!(
            !attempt.is_violation(),
            "but the document is nothing like the caller's own object: {attempt:?}"
        );
        assert!(attempt.note.as_deref().unwrap().contains("echoing"));

        let target_id = fixture.traffic.target_of(base).unwrap();
        assert!(crate::analysis::construction_findings(&construction, target_id).is_empty());
    }

    #[tokio::test]
    async fn a_document_nobody_can_be_shown_to_own_produces_a_lead_not_a_finding() {
        let (fixture, _, base, construction) = run(
            Behaviour::AnonymousDocument,
            "/accounts/acct-2000",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
            vec![user_b()],
        )
        .await;

        let attempt = &construction.attempts[0];
        assert_eq!(attempt.verdict, Verdict::Inconclusive);
        assert!(attempt.similarity >= SAME_RESOURCE, "{attempt:?}");

        let target_id = fixture.traffic.target_of(base).unwrap();
        let findings = crate::analysis::construction_findings(&construction, target_id);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].confidence,
            Confidence::Tentative,
            "ownership could not be established, so this is a lead"
        );
        assert!(!findings[0].confidence.is_actionable());
        assert!(
            findings[0].title.starts_with("Unproven"),
            "{}",
            findings[0].title
        );
    }

    #[tokio::test]
    async fn a_query_parameter_object_is_constructed_too() {
        let (_, app, _, construction) = run(
            Behaviour::Vulnerable,
            "/accounts?id=acct-2000",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::Query {
                    name: "id".into(),
                    occurrence: 0,
                },
            )],
            vec![user_b()],
        )
        .await;

        assert!(construction.attempts[0].is_violation());
        assert!(app.requests().contains(&(
            "Bearer TOKEN_B".to_string(),
            "/accounts?id=acct-1000".to_string()
        )));
    }

    #[tokio::test]
    async fn a_body_object_is_constructed_too() {
        let fixture = fixture();
        let app = Accounts::new(Behaviour::Vulnerable);
        let tester = tester(&fixture, app.clone(), in_scope());

        let mut request = HttpRequest::get(service(), "/accounts/lookup");
        request.method = "POST".into();
        request.body = bytes::Bytes::from(r#"{"account":"acct-2000"}"#);
        let base = capture_request(&fixture, request);

        let plan = ConstructionPlan::new(
            base,
            vec![user_b()],
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::Body { offset: 12 },
            )],
        );
        let construction = tester.construct(&plan).await.unwrap();

        assert_eq!(construction.attempts.len(), 1, "{:?}", construction.skipped);
        assert!(construction.attempts[0].is_violation());
        assert!(matches!(
            construction.attempts[0].location,
            ObjectLocation::Body { .. }
        ));
    }

    #[tokio::test]
    async fn an_out_of_scope_target_is_refused_before_anything_is_sent() {
        let fixture = fixture();
        let app = Accounts::new(Behaviour::Vulnerable);
        // A project whose scope does not cover the fixture host.
        let tester = tester(&fixture, app.clone(), Scope::new());
        let base = capture(&fixture, "/accounts/acct-2000");

        let plan = ConstructionPlan::new(
            base,
            vec![user_b()],
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
        );
        let error = tester.construct(&plan).await.unwrap_err();

        assert_eq!(error.code(), "out_of_scope", "{error}");
        assert!(
            app.requests().is_empty(),
            "not one request may leave for a host nobody declared"
        );
    }

    #[tokio::test]
    async fn the_provenance_of_every_constructed_request_is_recorded() {
        let (fixture, _, base, construction) = run(
            Behaviour::Vulnerable,
            "/accounts/acct-2000",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
            vec![user_b()],
        )
        .await;

        let generated = construction.attempts[0].request.unwrap();
        let objects = ObjectStore::new(fixture.db.clone());
        let attempt = objects.attempt(generated).unwrap().expect("recorded");

        assert_eq!(attempt.source_request, base);
        assert_eq!(attempt.original_value, "acct-2000");
        assert_eq!(attempt.replacement_value, "acct-1000");
        assert_eq!(attempt.sender, Some(construction.attempts[0].sender));
        assert_eq!(attempt.location, ObjectLocation::PathSegment { index: 1 });

        // And the traffic itself knows where it came from, so `--tree` answers the
        // same question without knowing anything about declarations.
        let stored = fixture.traffic.request(generated).unwrap();
        assert_eq!(stored.parent, Some(base));
        assert_eq!(stored.origin, "authz");
        assert!(stored.identity.is_some());
        assert_eq!(objects.attempts_from(base).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_attempt_limit_is_enforced_and_reported() {
        let fixture = fixture();
        let app = Accounts::new(Behaviour::Vulnerable);
        let tester = tester(&fixture, app.clone(), in_scope());
        let base = capture(&fixture, "/accounts/acct-2000");

        let alice = user_a();
        let plan = ConstructionPlan::new(
            base,
            vec![user_b()],
            vec![
                declaration(
                    &alice,
                    "acct-1000",
                    ObjectLocation::PathSegment { index: 1 },
                ),
                declaration(
                    &alice,
                    "acct-1001",
                    ObjectLocation::PathSegment { index: 1 },
                ),
                declaration(
                    &alice,
                    "acct-1002",
                    ObjectLocation::PathSegment { index: 1 },
                ),
            ],
        )
        .with_limit(1);

        let construction = tester.construct(&plan).await.unwrap();
        assert_eq!(construction.attempts.len(), 1);
        assert!(
            construction.skipped.iter().any(|s| s.contains("limit")),
            "{:?}",
            construction.skipped
        );
    }

    #[test]
    fn the_attempt_limit_cannot_be_raised_past_the_ceiling() {
        let plan =
            ConstructionPlan::new(RequestId::new(), Vec::new(), Vec::new()).with_limit(usize::MAX);
        assert_eq!(plan.limit, HARD_MAX_ATTEMPTS);
        assert_eq!(
            ConstructionPlan::new(RequestId::new(), Vec::new(), Vec::new())
                .with_limit(0)
                .limit,
            1
        );
    }

    #[tokio::test]
    async fn an_identity_is_never_asked_to_attempt_its_own_object() {
        // The same instance on both sides: two `user_b()` calls are two identities
        // with the same label, and ownership is by id.
        let bob = user_b();
        let (_, _, _, construction) = run(
            Behaviour::Vulnerable,
            "/accounts/acct-2000",
            vec![declaration(
                &bob,
                "acct-2000",
                ObjectLocation::PathSegment { index: 1 },
            )],
            vec![bob.clone()],
        )
        .await;
        assert!(construction.attempts.is_empty());
        assert!(construction.skipped.is_empty());
    }

    #[tokio::test]
    async fn a_request_that_already_asks_for_the_object_is_left_to_the_matrix() {
        // Substituting acct-1000 for acct-1000 is a replay, and the matrix does
        // replays. Saying so beats sending a duplicate request.
        let (_, _, _, construction) = run(
            Behaviour::Vulnerable,
            "/accounts/acct-1000",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
            vec![user_b()],
        )
        .await;

        assert!(construction.attempts.is_empty());
        assert!(
            construction.skipped[0].contains("already asks for"),
            "{:?}",
            construction.skipped
        );
    }

    #[tokio::test]
    async fn nowhere_to_put_the_identifier_is_reported_rather_than_silently_skipped() {
        let (_, _, _, construction) = run(
            Behaviour::Vulnerable,
            "/health",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::Query {
                    name: "id".into(),
                    occurrence: 0,
                },
            )],
            vec![user_b()],
        )
        .await;

        assert!(construction.attempts.is_empty());
        assert!(
            construction.skipped[0].contains("nowhere to put"),
            "{:?}",
            construction.skipped
        );
    }

    #[tokio::test]
    async fn verification_promotes_a_reproduced_violation_to_confirmed() {
        let fixture = fixture();
        let app = Accounts::new(Behaviour::Vulnerable);
        let tester = tester(&fixture, app.clone(), in_scope());
        let base = capture(&fixture, "/accounts/acct-2000");

        let mut plan = ConstructionPlan::new(
            base,
            vec![user_b()],
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
        );
        plan.verify = true;

        let construction = tester.construct(&plan).await.unwrap();
        assert!(construction.attempts[0].reproduced);

        let target_id = fixture.traffic.target_of(base).unwrap();
        let findings = crate::analysis::construction_findings(&construction, target_id);
        assert_eq!(findings[0].confidence, Confidence::Confirmed);
    }

    #[tokio::test]
    async fn a_credential_never_appears_in_a_construction_result() {
        // The result crosses into the CLI, the IPC boundary and the report. None of
        // them may carry a session.
        let (_, _, _, construction) = run(
            Behaviour::Vulnerable,
            "/accounts/acct-2000",
            vec![declaration(
                &user_a(),
                "acct-1000",
                ObjectLocation::PathSegment { index: 1 },
            )],
            vec![user_b()],
        )
        .await;

        let rendered = format!("{construction:?}");
        assert!(!rendered.contains("TOKEN_A"), "{rendered}");
        assert!(!rendered.contains("TOKEN_B"), "{rendered}");
    }

    #[tokio::test]
    async fn re_running_updates_the_claim_and_keeps_the_triage_decision() {
        let fixture = fixture();
        let app = Accounts::new(Behaviour::Vulnerable);
        let tester = tester(&fixture, app.clone(), in_scope());
        let base = capture(&fixture, "/accounts/acct-2000");
        let target_id = fixture.traffic.target_of(base).unwrap();
        let findings_store = FindingStore::new(fixture.db.clone());

        let alice = user_a();
        let declared = declaration(
            &alice,
            "acct-1000",
            ObjectLocation::PathSegment { index: 1 },
        );

        let first = tester
            .construct(&ConstructionPlan::new(
                base,
                vec![user_b()],
                vec![declared.clone()],
            ))
            .await
            .unwrap();
        let finding = &crate::analysis::construction_findings(&first, target_id)[0];
        let recorded = findings_store.record(finding).unwrap();
        assert!(recorded.is_new());

        findings_store
            .set_status(recorded.id(), FindingStatus::FalsePositive)
            .unwrap();

        let second = tester
            .construct(&ConstructionPlan::new(base, vec![user_b()], vec![declared]))
            .await
            .unwrap();
        let again = &crate::analysis::construction_findings(&second, target_id)[0];
        let recorded_again = findings_store.record(again).unwrap();

        assert!(!recorded_again.is_new(), "the same claim, refreshed");
        assert_eq!(recorded_again.id(), recorded.id());
        assert_eq!(findings_store.count().unwrap(), 1);
        assert_eq!(
            findings_store.get(recorded.id()).unwrap().status,
            FindingStatus::FalsePositive,
            "a dismissed finding stays dismissed, or the list becomes one nobody reads"
        );
    }

    #[tokio::test]
    async fn every_sender_attempts_every_object_it_does_not_own() {
        let fixture = fixture();
        let app = Accounts::new(Behaviour::Vulnerable);
        let tester = tester(&fixture, app.clone(), in_scope());
        let base = capture(&fixture, "/accounts/acct-2000");

        let alice = user_a();
        let bob = user_b();
        let plan = ConstructionPlan::new(
            base,
            vec![alice.clone(), bob.clone()],
            vec![
                declaration(
                    &alice,
                    "acct-1000",
                    ObjectLocation::PathSegment { index: 1 },
                ),
                declaration(&bob, "acct-2000", ObjectLocation::PathSegment { index: 1 }),
            ],
        );
        let construction = tester.construct(&plan).await.unwrap();

        // User A attempts acct-1000? No — they own it. User A attempts acct-2000: the
        // request already asks for it, so the matrix covers that. User B attempts
        // acct-1000: constructed.
        let attempted: Vec<&str> = construction
            .attempts
            .iter()
            .map(|a| a.object_value.as_str())
            .collect();
        assert_eq!(attempted, vec!["acct-1000"]);
        assert_eq!(construction.attempts[0].sender_label, "User B");
    }
}

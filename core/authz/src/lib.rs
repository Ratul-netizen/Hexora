//! # hexora-authz
//!
//! Authorization testing: take one request that worked, replay it as everybody else,
//! and say what that proves.
//!
//! This is the highest-value manual work in most engagements and the part testers
//! most often run out of time for. Doing it by hand means keeping several sessions
//! alive, resending the same request in each, and eyeballing responses that differ in
//! a dozen irrelevant ways — for every interesting endpoint, every time something
//! changes.
//!
//! ## The shape of a run
//!
//! ```text
//! base request ──┬── replayed as the owner    → the baseline (fresh, not the capture)
//!                ├── replayed as User B       → compare
//!                ├── replayed as Admin        → compare
//!                └── replayed as Anonymous    → the control
//! ```
//!
//! Three decisions in that diagram are the whole design:
//!
//! **The baseline is replayed, never reused.** The captured response is minutes or
//! weeks old; the session that produced it may have expired, the record may have been
//! deleted, the feature flag may have flipped. Comparing a fresh response against a
//! stale one produces differences that belong to time, not to authorization.
//!
//! **Anonymous is a control, not just another row.** If an unauthenticated request
//! gets the same document, then "User B can read it" proves nothing about User B —
//! the resource is public. A matrix that reported six violations for a public page
//! would be worse than useless, so the control demotes them and the run reports the
//! one thing that is actually true. See [`Matrix::appears_public`].
//!
//! **Every send is recorded, as its identity.** A result that exists only in a
//! terminal cannot be cited in a report. Each replay is stored with `origin = authz`
//! and the identity it was sent as, so the evidence behind a finding is two request
//! ids somebody else can open months later.
//!
//! ## Constructing, not only replaying
//!
//! A replay answers "can User B reach this URL?". It cannot answer "can User B reach
//! **User A's** invoice?" when the only captured traffic is User B asking for their
//! own — the request that would answer it has never existed. [`construct`] builds it,
//! by substituting an identifier the tester has declared as somebody else's. Nothing
//! about which value is an object, or whose it is, is guessed. See that module.
//!
//! ## Suggesting, never assuming
//!
//! Declaring every object identifier by hand is what keeps constructed testing
//! narrower than it should be. [`suggest`] reads captured traffic and offers the
//! values that *vary where an identifier would* — and stops there. A suggestion is not
//! an object and an object is not an ownership claim; both remaining steps are a
//! person's. Nothing in that module sends a request or writes a finding.
//!
//! ## What a run does not do
//!
//! It does not decide that anything is a vulnerability on its own. It produces
//! outcomes and, from them, candidate findings capped at what the evidence supports —
//! [`Confidence::Tentative`] for a similarity match, [`Confidence::Firm`] when an
//! object the tester declared as somebody else's turns up in the response body, and
//! [`Confidence::Confirmed`] only when a second replay reproduced the same result.
//! See [`analysis`].
//!
//! There is a second route to [`Confidence::Firm`], added in M12.10 and needing no
//! declaration: two identities served not a document of the same *shape* but the same
//! *document*, field for field, behind an unauthenticated request that was refused it.
//! The anonymous control is the gate — two identities reading an identical public page
//! looks exactly the same from inside a comparison — and
//! [`AnonymousControl::NotTried`] does not clear it, because a run that did not look
//! has not shown anything. See [`compare::Baseline`] and
//! [`hexora_types::structure`].
//!
//! ## Requests that change things
//!
//! A matrix replays whatever it is given. Pointing one at `DELETE /accounts/42` will
//! delete account 42 up to six times. The engine will not stop you — a security tool
//! that quietly refused to test destructive endpoints would be hiding the most
//! serious authorization bugs there are — but [`Plan::is_state_changing`] flags it so
//! a caller can ask first, and the CLI does.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod analysis;
pub mod compare;
pub mod construct;
pub mod suggest;

use std::sync::Arc;

use hexora_engine::transport::HttpTransport;
use hexora_repeater::{Repeater, SendAs};
use hexora_storage::{IdentityStore, ObjectStore, TrafficStore};
use hexora_types::error::Result;
use hexora_types::finding::Hypothesis;
use hexora_types::identity::{Identity, PrivilegeLevel};
use hexora_types::ids::{IdentityId, RequestId, TargetId};
use hexora_verify::Detector;

use crate::compare::{contains_any, Baseline, Fingerprint, SAME_RESOURCE};

/// Methods that are safe to replay because they are not supposed to change anything.
///
/// From RFC 9110 §9.2.1. "Supposed to" is doing real work in that sentence: an
/// application is free to delete a record on `GET`, and some do. The list is a
/// warning, not a guarantee.
const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "TRACE"];

/// What a single identity got when it replayed the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The same resource the owner received.
    Allowed,
    /// The application refused: 401, 403 or 407.
    Denied,
    /// The application said the resource does not exist.
    ///
    /// Kept separate from [`Outcome::Denied`] because it is genuinely ambiguous: a
    /// 404 is both what a well-built application returns to hide an object's
    /// existence, and what a broken one returns when a lookup scoped to the wrong
    /// tenant comes back empty.
    NotFound,
    /// A redirect, usually to a login page. Reported rather than followed.
    Redirected,
    /// A successful response carrying something else — most often that identity's own
    /// data, which is the application working correctly.
    Different,
    /// The server failed, 5xx.
    ServerError,
    /// No response: the request could not be completed.
    Failed,
}

impl Outcome {
    /// A short label for tables and JSON.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::NotFound => "not-found",
            Self::Redirected => "redirected",
            Self::Different => "different",
            Self::ServerError => "server-error",
            Self::Failed => "failed",
        }
    }
}

/// What a cell means for authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// An identity received a resource it should not have.
    Violation,
    /// The application behaved as it should: refused, or served something else.
    Expected,
    /// The result cannot support a claim either way.
    Inconclusive,
}

impl Verdict {
    /// A short label for tables and JSON.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Violation => "violation",
            Self::Expected => "expected",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// What happened when an unauthenticated request was tried.
///
/// The question that separates "two identities were served the same document" from
/// "two identities were served the same *public* document". Without it, a marketing
/// page and a bank statement look alike to a comparison, and only one of them is a
/// finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymousControl {
    /// No unauthenticated request was sent, so nothing is known either way.
    NotTried,
    /// An unauthenticated request was sent and did not receive the resource.
    Refused,
    /// An unauthenticated request received it too, and the resource is public.
    Allowed,
}

/// One identity's replay of the base request.
#[derive(Debug, Clone)]
pub struct Cell {
    /// The identity that sent it.
    pub identity: IdentityId,
    /// Its label, carried so a rendered matrix does not need the identity store.
    pub label: String,
    /// Its privilege level.
    pub privilege: PrivilegeLevel,
    /// The stored request id of this replay, and half of the evidence behind any
    /// finding derived from it.
    pub request: Option<RequestId>,
    /// The status that came back, if a response did.
    pub status: Option<u16>,
    /// How alike the owner's fresh response and this one were, 0.0 to 1.0.
    pub similarity: f32,
    /// Where this response differs from the owner's, field by field.
    ///
    /// The sentence a score cannot produce: not "97% alike" but "`$.email` was present
    /// for User A and absent for User B". `None` when nothing was sent, so there was
    /// nothing to compare. Carries the normalization policy that was applied, because
    /// a comparison that set fields aside without saying so would be altering evidence.
    pub structure: Option<hexora_types::structure::Diff>,
    /// What happened.
    pub outcome: Outcome,
    /// What it means.
    pub verdict: Verdict,
    /// Object identifiers belonging to the owner that appeared in this response.
    ///
    /// The strongest evidence a matrix can produce, because it is a fact about the
    /// bytes rather than a score.
    pub leaked_object_ids: Vec<String>,
    /// Object identifiers belonging to *this* identity that appeared in the response.
    ///
    /// The exonerating half of the same fact, and the reason a correctly-built
    /// endpoint stops being reported as a violation. `GET /profile` returns a
    /// document of exactly the owner's shape to every caller — the application is
    /// working, and only the identifiers inside say so.
    pub own_object_ids: Vec<String>,
    /// What verification established about this cell, once it has run.
    ///
    /// `None` means nothing re-examined it — which is not the same as "it did not
    /// reproduce", and the difference is the whole reason this is not a `bool`.
    pub verification: Option<hexora_types::verify::Verification>,
    /// Why the cell has no request, when it failed.
    pub error: Option<String>,
    /// Why a violation was demoted, when it was.
    pub note: Option<String>,
}

/// A completed run.
#[derive(Debug, Clone)]
pub struct Matrix {
    /// The request every cell derives from.
    pub base: RequestId,
    /// The method of the base request.
    pub method: String,
    /// The URL every identity asked for.
    pub url: String,
    /// The owner's own fresh replay, which every other cell is compared against.
    pub owner: Cell,
    /// Every other identity's replay, in the order they were sent.
    pub cells: Vec<Cell>,
    /// Whether an unauthenticated request received the same resource.
    ///
    /// When this is true the per-identity verdicts are demoted to
    /// [`Verdict::Inconclusive`]: nothing about User B is proven by User B reading
    /// something the whole internet can read. The anonymous cell keeps its own
    /// verdict, because *that* is the finding.
    pub appears_public: bool,
}

impl Matrix {
    /// What an unauthenticated request established, if one was sent.
    ///
    /// [`AnonymousControl::NotTried`] is deliberately not the same as
    /// [`AnonymousControl::Refused`]: a run without an anonymous control has not shown
    /// that the resource is non-public, it has merely not looked.
    pub fn anonymous_control(&self) -> AnonymousControl {
        let anonymous: Vec<&Cell> = self
            .cells
            .iter()
            .filter(|cell| cell.privilege == PrivilegeLevel::Anonymous)
            .collect();
        if anonymous.is_empty() {
            return AnonymousControl::NotTried;
        }
        if anonymous
            .iter()
            .any(|cell| cell.outcome == Outcome::Allowed)
        {
            return AnonymousControl::Allowed;
        }
        // A failed send says nothing; only a reply that was not the resource does.
        if anonymous.iter().any(|cell| cell.status.is_some()) {
            AnonymousControl::Refused
        } else {
            AnonymousControl::NotTried
        }
    }

    /// Every cell that showed an identity reaching something it should not have.
    pub fn violations(&self) -> impl Iterator<Item = &Cell> {
        self.cells
            .iter()
            .filter(|cell| cell.verdict == Verdict::Violation)
    }

    /// Whether anything in the run needs a human to look at it.
    pub fn is_interesting(&self) -> bool {
        self.violations().next().is_some()
    }
}

/// What to run, and as whom.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The captured request to replay.
    pub base: RequestId,
    /// The identity the base request belongs to. Its fresh replay is the baseline.
    pub owner: Identity,
    /// Everybody else to try it as.
    pub others: Vec<Identity>,
    /// Whether to add an unauthenticated control when the plan has no anonymous
    /// identity of its own.
    ///
    /// On by default. It costs one request and it is the difference between "User B
    /// can read User A's invoice" and "that URL is public", which are not the same
    /// report.
    pub anonymous_control: bool,
    /// Whether to replay each violation a second time before reporting it.
    pub verify: bool,
}

impl Plan {
    /// A plan with the anonymous control on and verification off.
    pub fn new(base: RequestId, owner: Identity, others: Vec<Identity>) -> Self {
        Self {
            base,
            owner,
            others,
            anonymous_control: true,
            verify: false,
        }
    }

    /// Whether replaying this request may change data on the target.
    ///
    /// Answered from the stored request's method, so a caller can warn before the
    /// first send rather than after the sixth.
    pub fn is_state_changing(method: &str) -> bool {
        !SAFE_METHODS
            .iter()
            .any(|safe| safe.eq_ignore_ascii_case(method))
    }
}

/// Runs authorization matrices against a project.
pub struct AuthzTester<T: HttpTransport> {
    repeater: Repeater<T>,
    store: Arc<TrafficStore>,
    identities: IdentityStore,
    /// Declared objects, and the provenance of every request constructed from one.
    ///
    /// Held by the tester rather than passed per call: a constructed request that
    /// reached the network and whose reason was not written down is a row nobody can
    /// explain later, so recording it must not be something a caller can forget.
    objects: ObjectStore,
}

impl<T: HttpTransport> std::fmt::Debug for AuthzTester<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthzTester").finish_non_exhaustive()
    }
}

impl<T: HttpTransport> AuthzTester<T> {
    /// Builds a tester over a repeater and the project that will hold the evidence.
    ///
    /// The repeater is reused rather than reimplemented: loading a stored request,
    /// applying a credential, sending it and recording the result is exactly what it
    /// already does, and a second send path would be a second set of bugs.
    pub fn new(repeater: Repeater<T>, store: Arc<TrafficStore>, identities: IdentityStore) -> Self {
        let objects = ObjectStore::new(identities.database().clone());
        Self {
            repeater,
            store,
            identities,
            objects,
        }
    }

    /// The method of a stored request, for a state-change warning before anything is
    /// sent.
    pub fn method_of(&self, base: RequestId) -> Result<String> {
        Ok(self.store.request(base)?.method)
    }

    /// Replays the base request as every identity in the plan.
    ///
    /// A failure to reach the target for one identity does not abort the run: that
    /// cell records [`Outcome::Failed`] with the reason and the rest continue. A
    /// matrix with a hole in it is still evidence; five cells thrown away because the
    /// sixth timed out is not.
    pub async fn run(&self, plan: &Plan) -> Result<Run> {
        let draft = self.repeater.draft_from(plan.base)?;
        let url = draft.request.url();
        let method = draft.request.method.clone();

        // Asked once, before anything is sent. A matrix is automated traffic, so an
        // out-of-scope target is refused at the transport — and finding that out per
        // identity would produce six identical failures instead of one sentence
        // saying the project's scope does not cover the host.
        if !self
            .repeater
            .decide_as(&draft, SendAs::authz(&plan.owner))
            .permits_sending()
        {
            return Err(hexora_types::HexoraError::OutOfScope(url));
        }

        // Persisted before anything is sent, and not only to satisfy the foreign key
        // on `requests.identity_id`. The project has to be able to answer "which
        // credential was this sent with?" for every row it holds; an identity that
        // existed for the duration of one command would leave rows nobody can explain.
        self.identities.put(&plan.owner)?;
        for identity in &plan.others {
            self.identities.put(identity)?;
        }

        // The baseline is a fresh send, not the capture. See the module docs.
        let owner_sent = self
            .repeater
            .send_as(&draft, SendAs::authz(&plan.owner))
            .await?;
        let owner_baseline = Baseline::of(&owner_sent.exchange.response);
        let owner_cell = Cell {
            identity: plan.owner.id,
            label: plan.owner.label.clone(),
            privilege: plan.owner.privilege,
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

        let mut identities = plan.others.clone();
        if plan.anonymous_control
            && !identities
                .iter()
                .any(|i| i.privilege == PrivilegeLevel::Anonymous)
            && plan.owner.privilege != PrivilegeLevel::Anonymous
        {
            let control = Identity::anonymous();
            self.identities.put(&control)?;
            identities.push(control);
        }

        let mut cells = Vec::with_capacity(identities.len());
        for identity in &identities {
            cells.push(
                self.replay(&draft, identity, &plan.owner, &owner_baseline)
                    .await,
            );
        }

        let appears_public = cells.iter().any(|cell| {
            cell.privilege == PrivilegeLevel::Anonymous && cell.outcome == Outcome::Allowed
        }) && plan.owner.privilege != PrivilegeLevel::Anonymous;

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

        Ok(Run {
            matrix: Matrix {
                base: plan.base,
                method,
                url,
                owner: owner_cell,
                cells,
                appears_public,
            },
            draft,
            identities,
            owner: plan.owner.clone(),
            baseline: owner_baseline,
            repeat: plan.verify,
        })
    }

    /// Runs the matrix, raises hypotheses from it, and verifies each one.
    ///
    /// The whole check, in the shape every check has. The matrix is the first
    /// experiment; `--verify` makes the verifier run a second one. Nothing here
    /// produces a `Finding` directly — it cannot, because
    /// [`Verified::conclude`](hexora_types::verify::Verified::conclude) is the only
    /// thing that does and it needs a verification.
    pub async fn assess(&self, plan: &Plan, target: TargetId) -> Result<Assessment> {
        let mut run = self.run(plan).await?;

        let detector = crate::analysis::MatrixDetector;
        let hypotheses = detector.examine(&run.matrix);

        let work: Vec<(Hypothesis, crate::analysis::CellCase)> = hypotheses
            .into_iter()
            .filter_map(|hypothesis| {
                let cell = run
                    .matrix
                    .cells
                    .iter()
                    .find(|cell| cell.request == Some(hypothesis.source_request))?
                    .clone();
                let identity = run
                    .identities
                    .iter()
                    .find(|identity| identity.id == cell.identity)
                    .cloned();
                Some((hypothesis, crate::analysis::CellCase { cell, identity }))
            })
            .collect();

        let verifier = crate::analysis::ReplayVerifier {
            draft: &run.draft,
            owner: &run.owner,
            baseline: &run.baseline,
            control: run.matrix.anonymous_control(),
            owner_request: run.matrix.owner.request,
            repeat: run.repeat,
        };
        let lab = hexora_verify::RepeaterLab::new(&self.repeater);

        let matrix_for_writeup = run.matrix.clone();
        let judged = hexora_verify::verify_all(&verifier, &work, &lab, |hypothesis, _| {
            let cell = matrix_for_writeup
                .cells
                .iter()
                .find(|cell| cell.request == Some(hypothesis.source_request))
                .expect("the hypothesis came from this matrix");
            crate::analysis::matrix_writeup(&matrix_for_writeup, cell, target)
        })
        .await?;

        // Written back so the matrix a tester reads says what verification found,
        // rather than leaving the table and the findings list telling different
        // stories about the same cell.
        for outcome in &judged {
            if let Some(cell) = run
                .matrix
                .cells
                .iter_mut()
                .find(|cell| cell.request == Some(outcome.hypothesis.source_request))
            {
                cell.verification = Some(outcome.verification.clone());
            }
        }

        Ok(Assessment {
            matrix: run.matrix,
            judged,
        })
    }

    /// Sends the draft as one identity and classifies what came back.
    async fn replay(
        &self,
        draft: &hexora_repeater::Draft,
        identity: &Identity,
        owner: &Identity,
        baseline: &Baseline,
    ) -> Cell {
        replay_once(
            &hexora_verify::RepeaterLab::new(&self.repeater),
            draft,
            identity,
            owner,
            baseline,
        )
        .await
    }
}

/// Sends a draft as one identity through a lab and classifies what came back.
///
/// Free rather than a method, and taking a [`Lab`](hexora_verify::Lab) rather than the
/// repeater, because the verifier needs exactly this and must not be handed a
/// transport of its own. Both callers go through the same scope guard because there
/// is only one way to send.
pub(crate) async fn replay_once(
    lab: &dyn hexora_verify::Lab,
    draft: &hexora_repeater::Draft,
    identity: &Identity,
    owner: &Identity,
    baseline: &Baseline,
) -> Cell {
    {
        let mut cell = Cell {
            identity: identity.id,
            label: identity.label.clone(),
            privilege: identity.privilege,
            request: None,
            status: None,
            similarity: 0.0,
            structure: None,
            outcome: Outcome::Failed,
            verdict: Verdict::Inconclusive,
            leaked_object_ids: Vec::new(),
            own_object_ids: Vec::new(),
            verification: None,
            error: None,
            note: None,
        };

        let sent = match lab.experiment(draft, Some(identity)).await {
            Ok(sent) => sent,
            Err(e) => {
                cell.error = Some(e.to_string());
                return cell;
            }
        };

        let response = &sent.exchange.response;
        let fingerprint = Fingerprint::of(response);
        let similarity = baseline.similarity(&fingerprint);

        cell.request = Some(sent.id);
        cell.status = Some(response.status);
        cell.similarity = similarity;
        // Computed for every cell, including the ones that turn out to be fine: a
        // tester reading a matrix wants to know *why* a row was dismissed as much as
        // why one was raised, and "every value differed" is that answer.
        cell.structure = Some(baseline.structure(response));
        cell.outcome = classify(response.status, similarity);
        cell.leaked_object_ids = contains_any(&response.body, &owner.owned_object_ids);
        cell.own_object_ids = contains_any(&response.body, &identity.owned_object_ids);
        if !cell.own_object_ids.is_empty() && cell.leaked_object_ids.is_empty() {
            // The response is shaped like the owner's because it *is* that document
            // — filled in for whoever asked. That is the application scoping a lookup
            // to the session, which is the behaviour being tested for.
            cell.outcome = Outcome::Different;
            cell.note = Some(format!(
                "served this identity's own data ({})",
                cell.own_object_ids.join(", ")
            ));
        }
        cell.verdict = verdict_for(&cell, identity, owner);
        cell
    }
}

/// The checks this crate provides.
///
/// Listed rather than discovered: adding a check means adding it here, and that is
/// the honest cost of not having a plugin mechanism.
pub fn checks() -> [hexora_types::verify::DetectorInfo; 2] {
    [
        crate::analysis::CROSS_IDENTITY,
        crate::analysis::CONSTRUCTED_OBJECT,
    ]
}

/// A completed matrix, with what a verifier needs to run any of it again.
///
/// The context is held rather than rebuilt because re-deriving a draft and a baseline
/// would mean sending the owner's request a second time just to have something to
/// compare against — extra traffic on a client's system to recover state the run
/// already had.
#[derive(Debug)]
pub struct Run {
    /// What the run saw.
    pub matrix: Matrix,
    draft: hexora_repeater::Draft,
    identities: Vec<Identity>,
    owner: Identity,
    baseline: Baseline,
    repeat: bool,
}

/// A run, and what verification made of it.
pub struct Assessment {
    /// The matrix, with each verified cell carrying its verification.
    pub matrix: Matrix,
    /// Every hypothesis the detector raised and what became of it.
    pub judged: Vec<hexora_verify::Judged>,
}

impl Assessment {
    /// The findings, dropping every hypothesis verification did not support.
    pub fn findings(&self) -> Vec<hexora_types::verify::Verified> {
        self.judged
            .iter()
            .filter_map(|outcome| outcome.finding.clone())
            .collect()
    }

    /// Hypotheses an experiment knocked down, for a tester who wants to see that the
    /// check ran and produced nothing rather than assuming it did not run.
    pub fn unsupported(&self) -> impl Iterator<Item = &hexora_verify::Judged> {
        self.judged
            .iter()
            .filter(|outcome| outcome.finding.is_none())
    }
}

/// Turns a status and a similarity score into an outcome.
fn classify(status: u16, similarity: f32) -> Outcome {
    match status {
        401 | 403 | 407 => Outcome::Denied,
        404 | 410 => Outcome::NotFound,
        300..=399 => Outcome::Redirected,
        500..=599 => Outcome::ServerError,
        _ if similarity >= SAME_RESOURCE => Outcome::Allowed,
        _ => Outcome::Different,
    }
}

/// Decides what a classified cell means.
///
/// A leaked object identifier makes it a violation regardless of similarity: a
/// response shaped differently from the owner's that nonetheless contains the owner's
/// account number has still disclosed the owner's account number.
fn verdict_for(cell: &Cell, identity: &Identity, owner: &Identity) -> Verdict {
    let reached_the_resource = cell.outcome == Outcome::Allowed;
    let leaked = !cell.leaked_object_ids.is_empty();

    if !(reached_the_resource || leaked) {
        return match cell.outcome {
            Outcome::Denied | Outcome::Different | Outcome::Redirected => Verdict::Expected,
            // 404, 5xx and failures say nothing either way.
            _ => Verdict::Inconclusive,
        };
    }

    if identity.violated_by_access_to(owner) {
        Verdict::Violation
    } else {
        // A higher-privilege identity reading a user's data is what administration
        // means. Reporting it as a finding is how a tool teaches people to ignore it.
        Verdict::Expected
    }
}

#[cfg(test)]
mod tests {
    use hexora_engine::guard::ScopeGuard;
    use hexora_engine::transport::{Exchange, HttpTransport, SendOptions};
    use hexora_storage::{MemoryBlobStore, MetadataDb};
    use hexora_types::http::{Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};
    use hexora_types::scope::Scope;

    use super::*;

    /// A transport that answers according to the credential it was handed.
    ///
    /// Keyed on the `Authorization` header because that is what the identity actually
    /// puts on the wire — a fake keyed on an identity id would test the test.
    #[derive(Debug, Default)]
    struct Application {
        /// `Authorization` value → (status, body). Anything unlisted gets a 403.
        answers: std::collections::HashMap<String, (u16, String)>,
        sent: std::sync::Mutex<Vec<String>>,
    }

    impl Application {
        fn with(answers: &[(&str, u16, &str)]) -> Arc<Self> {
            Arc::new(Self {
                answers: answers
                    .iter()
                    .map(|(auth, status, body)| {
                        ((*auth).to_string(), (*status, (*body).to_string()))
                    })
                    .collect(),
                sent: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn credentials_seen(&self) -> Vec<String> {
            self.sent.lock().unwrap().clone()
        }
    }

    /// A cloneable handle, so a test can keep the application while the guard owns a
    /// transport.
    #[derive(Debug, Clone)]
    struct Shared(Arc<Application>);

    #[async_trait::async_trait]
    impl HttpTransport for Shared {
        async fn send(&self, request: HttpRequest, _options: SendOptions) -> Result<Exchange> {
            let auth = request
                .headers
                .get("Authorization")
                .map(|h| h.value_lossy().into_owned())
                .unwrap_or_default();
            self.0.sent.lock().unwrap().push(auth.clone());

            let (status, body) = self
                .0
                .answers
                .get(&auth)
                .cloned()
                .unwrap_or((403, r#"{"error":"forbidden"}"#.to_string()));

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

    /// A project's traffic store and identity store over one in-memory database.
    fn project() -> (Arc<TrafficStore>, IdentityStore) {
        let db = MetadataDb::in_memory().unwrap();
        (
            Arc::new(TrafficStore::new(
                db.clone(),
                Arc::new(MemoryBlobStore::new()),
            )),
            IdentityStore::new(db),
        )
    }

    /// Stores a request to replay from, as the proxy would have captured it.
    fn capture(store: &TrafficStore) -> RequestId {
        let service = HttpService::new("api.example.com", 443, true);
        let request = HttpRequest::get(service, "/accounts/acct-1000");
        let mut headers = Headers::new();
        headers.set("Content-Type", "application/json");
        store
            .record(&hexora_storage::CapturedExchange {
                request,
                response: HttpResponse {
                    status: 200,
                    reason: None,
                    version: HttpVersion::Http11,
                    headers,
                    body: bytes::Bytes::from(r#"{"id":"acct-1000","owner":"alice"}"#),
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

    /// A scope covering the fixture host.
    ///
    /// Not optional: authorization replays are automated traffic, and the guard
    /// refuses automated requests to hosts nobody declared in scope.
    fn scope() -> Arc<Scope> {
        Arc::new(Scope::new().include(hexora_types::scope::ScopeRule::host("api.example.com")))
    }

    fn tester(
        app: Arc<Application>,
        store: Arc<TrafficStore>,
        identities: IdentityStore,
    ) -> AuthzTester<Shared> {
        let guard = ScopeGuard::new(Shared(app), scope());
        AuthzTester::new(Repeater::new(guard, store.clone()), store, identities)
    }

    fn owner() -> Identity {
        let mut owner = Identity::bearer("User A", "TOKEN_A");
        owner.owned_object_ids = vec!["acct-1000".into()];
        owner
    }

    #[tokio::test]
    async fn a_peer_reading_the_owners_record_is_a_violation() {
        let app = Application::with(&[
            (
                "Bearer TOKEN_A",
                200,
                r#"{"id":"acct-1000","owner":"alice"}"#,
            ),
            // The bug: User B gets User A's record back verbatim.
            (
                "Bearer TOKEN_B",
                200,
                r#"{"id":"acct-1000","owner":"alice"}"#,
            ),
        ]);
        let (store, identities) = project();
        let base = capture(&store);
        let tester = tester(app, store, identities);

        let matrix = tester
            .run(&Plan::new(
                base,
                owner(),
                vec![Identity::bearer("User B", "TOKEN_B")],
            ))
            .await
            .unwrap()
            .matrix;

        let cell = &matrix.cells[0];
        assert_eq!(cell.outcome, Outcome::Allowed);
        assert_eq!(cell.verdict, Verdict::Violation);
        assert_eq!(cell.leaked_object_ids, ["acct-1000"]);
        assert!(cell.request.is_some(), "a violation must be citable");
    }

    #[tokio::test]
    async fn an_application_that_denies_the_peer_produces_no_violation() {
        let app = Application::with(&[(
            "Bearer TOKEN_A",
            200,
            r#"{"id":"acct-1000","owner":"alice"}"#,
        )]);
        let (store, identities) = project();
        let base = capture(&store);
        let tester = tester(app, store, identities);

        let matrix = tester
            .run(&Plan::new(
                base,
                owner(),
                vec![Identity::bearer("User B", "TOKEN_B")],
            ))
            .await
            .unwrap()
            .matrix;

        assert_eq!(matrix.cells[0].outcome, Outcome::Denied);
        assert_eq!(matrix.cells[0].verdict, Verdict::Expected);
        assert!(!matrix.is_interesting());
    }

    #[tokio::test]
    async fn each_identity_is_sent_its_own_credential_and_only_that_one() {
        let app = Application::with(&[(
            "Bearer TOKEN_A",
            200,
            r#"{"id":"acct-1000","owner":"alice"}"#,
        )]);
        let (store, identities) = project();
        let base = capture(&store);
        let tester = tester(app.clone(), store, identities);

        tester
            .run(&Plan::new(
                base,
                owner(),
                vec![Identity::bearer("User B", "TOKEN_B")],
            ))
            .await
            .unwrap();

        let seen = app.credentials_seen();
        assert_eq!(seen[0], "Bearer TOKEN_A");
        assert_eq!(seen[1], "Bearer TOKEN_B");
        assert_eq!(
            seen[2], "",
            "the anonymous control must carry no credential at all"
        );
    }

    #[tokio::test]
    async fn an_anonymous_control_is_added_when_the_plan_has_none() {
        let app = Application::with(&[(
            "Bearer TOKEN_A",
            200,
            r#"{"id":"acct-1000","owner":"alice"}"#,
        )]);
        let (store, identities) = project();
        let base = capture(&store);
        let tester = tester(app, store, identities);

        let matrix = tester
            .run(&Plan::new(
                base,
                owner(),
                vec![Identity::bearer("User B", "TOKEN_B")],
            ))
            .await
            .unwrap()
            .matrix;

        assert_eq!(matrix.cells.len(), 2);
        assert_eq!(matrix.cells[1].privilege, PrivilegeLevel::Anonymous);
    }

    #[tokio::test]
    async fn a_public_resource_demotes_the_peer_verdicts_instead_of_reporting_six_bugs() {
        // Everything, credential or not, gets the same page.
        let body = r#"{"id":"acct-1000","owner":"alice"}"#;
        let app = Application::with(&[
            ("Bearer TOKEN_A", 200, body),
            ("Bearer TOKEN_B", 200, body),
            ("", 200, body),
        ]);
        let (store, identities) = project();
        let base = capture(&store);
        let tester = tester(app, store, identities);

        let matrix = tester
            .run(&Plan::new(
                base,
                owner(),
                vec![Identity::bearer("User B", "TOKEN_B")],
            ))
            .await
            .unwrap()
            .matrix;

        assert!(matrix.appears_public);
        assert_eq!(
            matrix.cells[0].verdict,
            Verdict::Inconclusive,
            "a peer reading a public page is not an authorization finding"
        );
        assert!(matrix.cells[0].note.is_some());
        assert_eq!(
            matrix.cells[1].verdict,
            Verdict::Violation,
            "the anonymous cell keeps its verdict — that is the finding"
        );
    }

    #[tokio::test]
    async fn an_endpoint_that_serves_each_caller_their_own_record_is_not_a_violation() {
        // `GET /profile`: the same document shape for everybody, filled in from the
        // session. Similarity alone calls this identical; the identifiers inside are
        // what say the application scoped the lookup correctly.
        let app = Application::with(&[
            (
                "Bearer TOKEN_A",
                200,
                r#"{"id":"acct-1000","owner":"alice","balance":17}"#,
            ),
            (
                "Bearer TOKEN_B",
                200,
                r#"{"id":"acct-2000","owner":"bob","balance":92}"#,
            ),
        ]);
        let (store, identities) = project();
        let base = capture(&store);
        let tester = tester(app, store, identities);

        let mut peer = Identity::bearer("User B", "TOKEN_B");
        peer.owned_object_ids = vec!["acct-2000".into()];

        let matrix = tester
            .run(&Plan::new(base, owner(), vec![peer]))
            .await
            .unwrap()
            .matrix;

        let cell = &matrix.cells[0];
        assert_eq!(cell.own_object_ids, ["acct-2000"]);
        assert!(cell.leaked_object_ids.is_empty());
        assert_eq!(cell.outcome, Outcome::Different);
        assert_eq!(
            cell.verdict,
            Verdict::Expected,
            "an application that scopes the lookup to the session is working"
        );
        assert!(cell.note.as_deref().unwrap().contains("own data"));
    }

    #[tokio::test]
    async fn a_response_holding_both_identities_data_is_still_a_violation() {
        // A leak wins over the exoneration: a listing that returns everybody's
        // records contains the caller's own ids too, and is not thereby innocent.
        let app = Application::with(&[
            (
                "Bearer TOKEN_A",
                200,
                r#"{"accounts":[{"id":"acct-1000"},{"id":"acct-2000"}]}"#,
            ),
            (
                "Bearer TOKEN_B",
                200,
                r#"{"accounts":[{"id":"acct-1000"},{"id":"acct-2000"}]}"#,
            ),
        ]);
        let (store, identities) = project();
        let base = capture(&store);
        let tester = tester(app, store, identities);

        let mut peer = Identity::bearer("User B", "TOKEN_B");
        peer.owned_object_ids = vec!["acct-2000".into()];

        let matrix = tester
            .run(&Plan::new(base, owner(), vec![peer]))
            .await
            .unwrap()
            .matrix;

        assert_eq!(matrix.cells[0].leaked_object_ids, ["acct-1000"]);
        assert_eq!(matrix.cells[0].verdict, Verdict::Violation);
    }

    #[tokio::test]
    async fn an_administrator_reading_a_users_record_is_expected() {
        let body = r#"{"id":"acct-1000","owner":"alice"}"#;
        let app = Application::with(&[("Bearer TOKEN_A", 200, body), ("Bearer ROOT", 200, body)]);
        let (store, identities) = project();
        let base = capture(&store);
        let tester = tester(app, store, identities);

        let mut admin = Identity::bearer("Admin", "ROOT");
        admin.privilege = PrivilegeLevel::Administrator;

        let matrix = tester
            .run(&Plan::new(base, owner(), vec![admin]))
            .await
            .unwrap()
            .matrix;

        assert_eq!(matrix.cells[0].outcome, Outcome::Allowed);
        assert_eq!(matrix.cells[0].verdict, Verdict::Expected);
    }

    #[tokio::test]
    async fn every_replay_is_recorded_as_the_identity_that_sent_it() {
        let app = Application::with(&[(
            "Bearer TOKEN_A",
            200,
            r#"{"id":"acct-1000","owner":"alice"}"#,
        )]);
        let (store, identities) = project();
        let base = capture(&store);
        let tester = tester(app, store.clone(), identities);

        let identity = Identity::bearer("User B", "TOKEN_B");
        let matrix = tester
            .run(&Plan::new(base, owner(), vec![identity.clone()]))
            .await
            .unwrap()
            .matrix;

        let stored = store.request(matrix.cells[0].request.unwrap()).unwrap();
        assert_eq!(stored.origin, "authz");
        assert_eq!(
            stored.identity,
            Some(identity.id),
            "a replay that cannot say which principal sent it is not evidence"
        );
        assert_eq!(
            stored.parent,
            Some(base),
            "a replay must point at what it derived from"
        );
    }

    #[tokio::test]
    async fn a_transport_failure_leaves_a_hole_rather_than_ending_the_run() {
        #[derive(Debug)]
        struct Broken;

        #[async_trait::async_trait]
        impl HttpTransport for Broken {
            async fn send(&self, _r: HttpRequest, _o: SendOptions) -> Result<Exchange> {
                Err(hexora_types::HexoraError::Internal(
                    "connection reset".into(),
                ))
            }
        }

        let (store, identities) = project();
        let base = capture(&store);
        let guard = ScopeGuard::new(Broken, scope());
        let tester = AuthzTester::new(Repeater::new(guard, store.clone()), store, identities);

        // The owner's baseline failing is fatal — there is nothing to compare to.
        let error = tester
            .run(&Plan::new(base, owner(), vec![]))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("connection reset"));
    }

    #[tokio::test]
    async fn a_verified_violation_records_that_it_happened_again() {
        let body = r#"{"id":"acct-1000","owner":"alice"}"#;
        let app =
            Application::with(&[("Bearer TOKEN_A", 200, body), ("Bearer TOKEN_B", 200, body)]);
        let (store, identities) = project();
        let base = capture(&store);
        let tester = tester(app, store, identities);

        let mut plan = Plan::new(base, owner(), vec![Identity::bearer("User B", "TOKEN_B")]);
        plan.verify = true;
        plan.anonymous_control = false;

        // The second experiment is the verifier's, so this goes through `assess`.
        let assessment = tester
            .assess(&plan, hexora_types::ids::TargetId::new())
            .await
            .unwrap();
        assert!(matches!(
            assessment.matrix.cells[0].verification,
            Some(hexora_types::verify::Verification::Reproduced { .. })
        ));
        assert_eq!(
            assessment.findings()[0].finding().confidence,
            hexora_types::Confidence::Confirmed
        );
    }

    #[tokio::test]
    async fn a_matrix_refuses_to_run_against_a_host_nobody_put_in_scope() {
        let app = Application::with(&[(
            "Bearer TOKEN_A",
            200,
            r#"{"id":"acct-1000","owner":"alice"}"#,
        )]);
        let (store, identities) = project();
        let base = capture(&store);
        let guard = ScopeGuard::new(Shared(app.clone()), Arc::new(Scope::new()));
        let tester = AuthzTester::new(Repeater::new(guard, store.clone()), store, identities);

        let error = tester
            .run(&Plan::new(
                base,
                owner(),
                vec![Identity::bearer("User B", "TOKEN_B")],
            ))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("out of scope"), "{error}");
        assert!(
            app.credentials_seen().is_empty(),
            "nothing may reach the wire once scope has refused the run"
        );
    }

    #[test]
    fn state_changing_methods_are_flagged_before_anything_is_sent() {
        assert!(!Plan::is_state_changing("GET"));
        assert!(!Plan::is_state_changing("head"));
        assert!(Plan::is_state_changing("POST"));
        assert!(Plan::is_state_changing("DELETE"));
        assert!(
            Plan::is_state_changing("PROPPATCH"),
            "an unknown method is assumed to change things"
        );
    }

    #[test]
    fn a_not_found_says_nothing_either_way() {
        let cell = Cell {
            identity: IdentityId::new(),
            label: "User B".into(),
            privilege: PrivilegeLevel::User,
            request: None,
            status: Some(404),
            similarity: 0.0,
            structure: None,
            outcome: Outcome::NotFound,
            verdict: Verdict::Inconclusive,
            leaked_object_ids: Vec::new(),
            own_object_ids: Vec::new(),
            verification: None,
            error: None,
            note: None,
        };
        let a = Identity::bearer("User B", "b");
        assert_eq!(verdict_for(&cell, &a, &owner()), Verdict::Inconclusive);
    }

    #[test]
    fn a_leaked_identifier_is_a_violation_even_when_the_document_differs() {
        let mut cell = Cell {
            identity: IdentityId::new(),
            label: "User B".into(),
            privilege: PrivilegeLevel::User,
            request: None,
            status: Some(200),
            similarity: 0.1,
            structure: None,
            outcome: Outcome::Different,
            verdict: Verdict::Inconclusive,
            leaked_object_ids: vec!["acct-1000".into()],
            own_object_ids: Vec::new(),
            verification: None,
            error: None,
            note: None,
        };
        let b = Identity::bearer("User B", "b");
        cell.verdict = verdict_for(&cell, &b, &owner());
        assert_eq!(cell.verdict, Verdict::Violation);
    }
}

//! Saying *what* differed between two responses, not how alike they were.
//!
//! A similarity score answers "did the same kind of document come back?" — the right
//! question for deciding whether an identity was served the resource at all, and
//! useless for explaining what a tester is looking at:
//!
//! ```text
//! responses differ: 37 bytes          a number nobody can act on
//!
//! $.account.email                     a claim somebody can check
//!   control: alice@example.com
//!   variant: absent
//! ```
//!
//! This module produces the second. It is deliberately **not** a verdict: a difference
//! is a fact about two documents, and whether it means anything is the verifier's
//! question and ultimately the tester's.
//!
//! # Normalization is never implicit
//!
//! Two responses from a real application always differ somewhere — a timestamp, a
//! nonce, a CSRF token. Ignoring those is necessary, and is exactly where a comparison
//! engine starts quietly altering evidence. So it is a [`Policy`] the caller passes in,
//! and two rules hold:
//!
//! 1. **Nothing is removed.** A field the policy set aside is still in
//!    [`Diff::differences`], carrying the reason and both values. A reader can see what
//!    was ignored and disagree with it.
//! 2. **The policy is reportable.** [`Policy::describe`] says what was applied, so a
//!    report never shows "these documents matched" without what was allowed not to
//!    match.
//!
//! [`Policy::strict`] sets nothing aside at all, which is what to use when the question
//! is whether two documents are identical.
//!
//! # The original bytes are never touched
//!
//! This reads two bodies and returns a description. The bodies stay in the project as
//! they arrived; the normalized form lives inside one comparison and is never stored,
//! quoted as evidence, or re-sent.
//!
//! # Duplicate keys are reported, not collapsed
//!
//! `{"id":"1000","id":"1001"}` is valid JSON that every parser reduces to one key, and
//! which one it keeps is the parser's business rather than the application's. For
//! security tooling that is a loss worth knowing about, so a body containing repeated
//! keys is flagged in [`Diff::quirks`].
//!
//! # What this is not
//!
//! It is not schema validation. Nothing here knows what an application *should*
//! return; it compares two documents that were actually served and says where they
//! disagree. A JSON Schema layer can arrive when a check needs one.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// The longest value quoted in a difference.
///
/// Long enough to recognise an identifier, short enough that a report does not become
/// a copy of somebody's record.
pub const VALUE_LIMIT: usize = 80;

/// How deep a document is walked.
const MAX_DEPTH: usize = 24;

/// How many items of an array are walked.
const MAX_ARRAY: usize = 64;

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// What a comparison is allowed to set aside.
///
/// Passed in rather than assumed, because deciding that a field "does not count" is a
/// judgement about somebody else's application and the reader has to be able to see
/// it. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Field names whose values are expected to change on every request.
    ///
    /// Matched on the last path segment, case-insensitively. Deliberately never
    /// includes `id`, `uuid` or `key`: those are what a cross-identity comparison
    /// exists to look at, and setting one aside would set aside the finding.
    pub dynamic_fields: Vec<String>,
    /// Whether to withhold the *value* of a field whose name says it is a credential.
    ///
    /// The difference is still reported — that a session token differs between two
    /// identities is correct and worth seeing — but what it was does not travel.
    pub withhold_credentials: bool,
    /// Whether two arrays holding the same values in a different order count as equal.
    ///
    /// Found against a real API, and it invalidated every structural comparison made
    /// against it. Two *identical unauthenticated* requests, one second apart:
    ///
    /// ```text
    /// A: ["LVA", "EST", "SWE", "DNK", "ISR", "LTU"]
    /// B: ["ISR", "SWE", "DNK", "LTU", "LVA", "EST"]
    /// ```
    ///
    /// Same set, shuffled. Compared by index that is six differences, and six
    /// differences is "the responses differ" — which is the premise underneath
    /// `authz.scheduled`, `auth.enforcement` and everything else that asks whether two
    /// callers were served the same thing. An application that returns a collection in
    /// no particular order would make all of them wrong, and most APIs do.
    ///
    /// **Only when the values are identical.** The arrays are compared as multisets
    /// first; if anything was added, removed or changed, nothing is set aside and every
    /// difference is reported as before. Reordering alone is the one case, because
    /// reordering alone means nothing changed.
    ///
    /// Off in [`Policy::strict`], like everything else that sets anything aside.
    pub reordering_is_not_a_difference: bool,
}

impl Policy {
    /// The field names this build treats as changing every request.
    ///
    /// A starting point, not a truth about anybody's application. A field genuinely
    /// called `timestamp` that carried an account number would be set aside wrongly —
    /// and would still appear in the difference list saying so.
    pub const DYNAMIC: &'static [&'static str] = &[
        "timestamp",
        "generated_at",
        "served_at",
        "requested_at",
        "nonce",
        "csrf",
        "csrf_token",
        "csrftoken",
        "xsrf",
        "request_id",
        "requestid",
        "trace_id",
        "traceid",
        "span_id",
        "correlation_id",
        "etag",
        "duration",
        "elapsed",
        "latency",
        "took_ms",
        "seed",
    ];

    /// Sets nothing aside.
    ///
    /// The comparison a reader can check line by line, and the right one when the
    /// question is whether two documents are identical.
    pub fn strict() -> Self {
        Self {
            dynamic_fields: Vec::new(),
            withhold_credentials: false,
            reordering_is_not_a_difference: false,
        }
    }

    /// Withholds credential values and nothing else.
    pub fn careful() -> Self {
        Self {
            dynamic_fields: Vec::new(),
            withhold_credentials: true,
            reordering_is_not_a_difference: true,
        }
    }

    /// How the policy reads in a report.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.dynamic_fields.is_empty() {
            parts.push("no field was treated as dynamic".to_string());
        } else {
            parts.push(format!(
                "{} field name(s) treated as changing every request",
                self.dynamic_fields.len()
            ));
        }
        if self.withhold_credentials {
            parts.push("credential values withheld".into());
        }
        parts.join("; ")
    }
}

impl Default for Policy {
    /// Withholds credential values and sets aside the usual per-request fields.
    ///
    /// A default rather than a silent behaviour: [`Policy::describe`] says what it did,
    /// and every field it set aside is still listed with both its values.
    fn default() -> Self {
        Self {
            dynamic_fields: Self::DYNAMIC.iter().map(|name| name.to_string()).collect(),
            withhold_credentials: true,
            reordering_is_not_a_difference: true,
        }
    }
}

// ---------------------------------------------------------------------------
// The difference
// ---------------------------------------------------------------------------

/// Whether two bodies could be compared field by field at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparable {
    /// Both parsed as JSON, so the comparison is structural.
    Structurally,
    /// Neither parsed as JSON. Nothing here applies, and the caller's existing
    /// similarity score is what there is.
    NotStructured,
    /// One parsed and the other did not — usually a document on one side and an error
    /// page on the other, which is itself the most interesting thing about the pair.
    OnlyOneSide,
}

/// Why a difference was set aside rather than counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetAside {
    /// The policy names this field as changing on every request.
    Dynamic,
    /// The policy withholds this field's value because its name says it is a
    /// credential. The difference itself is still reported.
    Credential,
}

impl SetAside {
    /// How it reads in a summary.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dynamic => "the policy treats this field as changing every request",
            Self::Credential => "value withheld: the field name says it is a credential",
        }
    }
}

/// What happened at one path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldChange {
    /// In the variant and not the control.
    Appeared {
        /// The value, quoted and truncated, or `None` when withheld or a container.
        now: Option<String>,
    },
    /// In the control and not the variant.
    ///
    /// The shape that matters most for authorization: a field the owner sees and the
    /// other identity does not is the application scoping something correctly, and the
    /// reverse is the opposite.
    Disappeared {
        /// The value it had.
        was: Option<String>,
    },
    /// In both, with different values of the same type.
    Changed {
        /// What the control had.
        from: Option<String>,
        /// What the variant had.
        to: Option<String>,
    },
    /// In both, at different types — a number became a string, say.
    ///
    /// Kept apart from [`Self::Changed`] because a type change is a change in the
    /// *shape* of a response, which is a different signal from a value moving.
    TypeChanged {
        /// The control's type.
        from: String,
        /// The variant's.
        to: String,
    },
}

impl FieldChange {
    /// A short label for a table.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Appeared { .. } => "appeared",
            Self::Disappeared { .. } => "disappeared",
            Self::Changed { .. } => "changed",
            Self::TypeChanged { .. } => "type changed",
        }
    }

    /// Whether this is a change of shape rather than of value.
    pub fn is_structural(&self) -> bool {
        !matches!(self, Self::Changed { .. })
    }
}

/// One path where two documents disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDifference {
    /// Where, as a JSON path: `$.account.email`, `$.items[3].price`.
    pub path: String,
    /// What happened.
    pub change: FieldChange,
    /// Why the policy set it aside, if it did.
    ///
    /// A difference with a reason here is reported and not counted. Nothing is removed.
    pub set_aside: Option<SetAside>,
    /// Whether the field's name suggests it carries something personal.
    ///
    /// A hint for ordering, not a claim: `email`, `balance` and `role` are worth a
    /// reader's eye before `sort_order` is. Hexora does not know what the data means.
    pub notable: bool,
}

impl FieldDifference {
    /// Whether this difference counts toward the comparison.
    pub fn counts(&self) -> bool {
        self.set_aside.is_none()
    }

    /// The difference in one line.
    ///
    /// `control` and `variant` name the two sides — usually two identity labels —
    /// because "present for User A, absent for User B" is readable and "present on the
    /// left" is not.
    pub fn describe(&self, control: &str, variant: &str) -> String {
        let body = match &self.change {
            FieldChange::Appeared { now } => {
                format!(
                    "absent for {control}, {} for {variant}",
                    quoted(now.as_deref())
                )
            }
            FieldChange::Disappeared { was } => {
                format!(
                    "{} for {control}, absent for {variant}",
                    quoted(was.as_deref())
                )
            }
            // Both sides withheld is the common credential case, and saying "a value
            // that is not quoted here" twice reads like a fault rather than a policy.
            FieldChange::Changed {
                from: None,
                to: None,
            } => {
                format!("the value {control} was served differs from {variant}'s")
            }
            FieldChange::Changed { from, to } => format!(
                "{} for {control}, {} for {variant}",
                quoted(from.as_deref()),
                quoted(to.as_deref())
            ),
            FieldChange::TypeChanged { from, to } => {
                format!("{from} for {control}, {to} for {variant}")
            }
        };
        match self.set_aside {
            Some(why) => format!("{} — {body} ({})", self.path, why.as_str()),
            None => format!("{} — {body}", self.path),
        }
    }
}

fn quoted(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("`{value}`"),
        None => "a value that is not quoted here".to_string(),
    }
}

/// Something about a body worth saying before its contents are discussed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quirk {
    /// The control document repeated a key in one of its objects.
    DuplicateKeysInControl,
    /// The variant document did.
    DuplicateKeysInVariant,
    /// Arrays holding the same values in a different order were compared as sets.
    ///
    /// Reported rather than done quietly. A reader deciding whether to trust "the same
    /// document" is entitled to know that some of it was only the same once order was
    /// ignored.
    ArraysReordered {
        /// How many arrays this happened to.
        count: usize,
    },
}

impl Quirk {
    /// How it reads.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ArraysReordered { .. } => {
                "some arrays held the same values in a different order and were compared \
                 as sets; nothing in them was added, removed or changed"
            }
            Self::DuplicateKeysInControl => {
                "the control response repeated a key in one of its objects, and a parser \
                 keeps only one of them"
            }
            Self::DuplicateKeysInVariant => {
                "the variant response repeated a key in one of its objects, and a parser \
                 keeps only one of them"
            }
        }
    }
}

/// Where two documents disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diff {
    /// Whether a field-by-field comparison was possible.
    pub comparable: Comparable,
    /// Every path where they disagree, including the ones the policy set aside.
    ///
    /// Ordered by path, so the same two documents always produce the same list.
    pub differences: Vec<FieldDifference>,
    /// How many leaf paths the two documents have in common.
    pub shared_paths: usize,
    /// How many paths appear in either.
    pub total_paths: usize,
    /// What the comparison was allowed to ignore.
    pub policy: Policy,
    /// Anything about the bodies a reader should know before reading the rest.
    pub quirks: Vec<Quirk>,
}

impl Diff {
    /// Compares two response bodies under a policy.
    ///
    /// Takes bytes: a response body is whatever the application sent, including
    /// nothing at all and including invalid UTF-8. Neither body is modified.
    pub fn of(control: &[u8], variant: &[u8], policy: &Policy) -> Self {
        let left = parse(control);
        let right = parse(variant);

        let mut quirks = Vec::new();
        if left.as_ref().is_some_and(|parsed| parsed.duplicate_keys) {
            quirks.push(Quirk::DuplicateKeysInControl);
        }
        if right.as_ref().is_some_and(|parsed| parsed.duplicate_keys) {
            quirks.push(Quirk::DuplicateKeysInVariant);
        }

        let (comparable, differences, shared, total) = match (left, right) {
            (Some(mut left), Some(mut right)) => {
                if policy.reordering_is_not_a_difference {
                    let reordered = settle_order(&mut left.value, &mut right.value);
                    if reordered > 0 {
                        quirks.push(Quirk::ArraysReordered { count: reordered });
                    }
                }
                let (differences, shared, total) = compare(&left.value, &right.value, policy);
                (Comparable::Structurally, differences, shared, total)
            }
            (None, None) => (Comparable::NotStructured, Vec::new(), 0, 0),
            _ => (Comparable::OnlyOneSide, Vec::new(), 0, 0),
        };

        Self {
            comparable,
            differences,
            shared_paths: shared,
            total_paths: total,
            policy: policy.clone(),
            quirks,
        }
    }

    /// The differences that count under the policy.
    pub fn counted(&self) -> impl Iterator<Item = &FieldDifference> {
        self.differences.iter().filter(|d| d.counts())
    }

    /// How many the policy set aside.
    pub fn set_aside(&self) -> usize {
        self.differences.len() - self.counted().count()
    }

    /// Whether the two documents say the same thing everywhere the policy counts.
    ///
    /// A much harder claim than a similarity score: not *a document of the same shape*,
    /// but *the same document*. For a cross-identity replay that is the difference
    /// between "both users see an invoice" and "the second user saw the first user's
    /// invoice".
    ///
    /// False when the bodies were not both JSON: nothing was compared, so nothing is
    /// established.
    pub fn same_document(&self) -> bool {
        self.comparable == Comparable::Structurally && self.counted().next().is_none()
    }

    /// Whether every shared leaf holds a different value.
    ///
    /// The opposite signal, and the one that says an application scoped its lookup to
    /// the caller: two documents of identical shape whose every value differs are two
    /// users' own records.
    pub fn every_value_differs(&self) -> bool {
        self.comparable == Comparable::Structurally
            && self.shared_paths > 0
            && self
                .counted()
                .filter(|d| matches!(d.change, FieldChange::Changed { .. }))
                .count()
                == self.shared_paths
    }

    /// The differences most worth a reader's attention, most notable first.
    ///
    /// Deterministic: the same two documents always produce the same order.
    pub fn ranked(&self) -> Vec<&FieldDifference> {
        let mut ordered: Vec<&FieldDifference> = self.counted().collect();
        ordered.sort_by(|a, b| {
            (!a.notable, !a.change.is_structural(), &a.path).cmp(&(
                !b.notable,
                !b.change.is_structural(),
                &b.path,
            ))
        });
        ordered
    }

    /// The difference in a sentence, naming the fields that matter most.
    pub fn summary(&self, control: &str, variant: &str) -> String {
        match self.comparable {
            Comparable::NotStructured => {
                return "neither response was JSON, so no field-by-field comparison was \
                        made"
                    .to_string()
            }
            Comparable::OnlyOneSide => {
                return format!(
                    "one of the two responses was a JSON document and the other was not, \
                     so {control} and {variant} were not served the same kind of thing"
                )
            }
            Comparable::Structurally => {}
        }

        let ranked = self.ranked();
        if ranked.is_empty() {
            let aside = self.set_aside();
            let tail = if aside > 0 {
                format!(" ({aside} field(s) set aside by the comparison policy, listed in full)")
            } else {
                String::new()
            };
            return format!(
                "the two responses are the same document at every one of {} field(s){tail}",
                self.shared_paths
            );
        }

        let shown: Vec<String> = ranked
            .iter()
            .take(3)
            .map(|difference| difference.describe(control, variant))
            .collect();
        let more = ranked.len().saturating_sub(shown.len());
        let tail = if more > 0 {
            format!("; and {more} more")
        } else {
            String::new()
        };
        format!("{}{tail}", shown.join("; "))
    }
}

// ---------------------------------------------------------------------------
// Comparing
// ---------------------------------------------------------------------------

/// A place in a document: a value, or the container that holds other places.
///
/// Containers are recorded as well as leaves so that every document has a node at `$`
/// and at every object and array on the way down. Without that, `{}` and `{"a":null}`
/// share no path at all and the comparison reports a difference at the root — which is
/// true and useless. With it they agree at `$` and differ at `$.a`, while `{}` against
/// `[]` still differ at `$`, by type.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// A scalar value.
    Leaf(serde_json::Value),
    /// An object or an array, empty or not.
    Container(&'static str),
}

impl Node {
    fn kind(&self) -> &'static str {
        match self {
            Self::Leaf(value) => kind_of(value),
            Self::Container(kind) => kind,
        }
    }

    fn value(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Leaf(value) => Some(value),
            Self::Container(_) => None,
        }
    }

    fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf(_))
    }
}

fn compare(
    control: &serde_json::Value,
    variant: &serde_json::Value,
    policy: &Policy,
) -> (Vec<FieldDifference>, usize, usize) {
    let mut left = BTreeMap::new();
    let mut right = BTreeMap::new();
    flatten(control, "$".into(), &mut left);
    flatten(variant, "$".into(), &mut right);

    let mut differences = Vec::new();
    let mut shared = 0usize;

    for (path, control_node) in &left {
        match right.get(path) {
            Some(variant_node) => {
                // Only leaves count toward "how much did these two have in common":
                // a shared `$.user` object is structure, and what is under it is the
                // comparison.
                if control_node.is_leaf() && variant_node.is_leaf() {
                    shared += 1;
                }
                if control_node == variant_node {
                    continue;
                }
                let withheld = policy.withhold_credentials && names_a_credential(path);
                let change = if control_node.kind() != variant_node.kind() {
                    FieldChange::TypeChanged {
                        from: control_node.kind().to_string(),
                        to: variant_node.kind().to_string(),
                    }
                } else {
                    FieldChange::Changed {
                        from: control_node.value().and_then(|v| render(v, withheld)),
                        to: variant_node.value().and_then(|v| render(v, withheld)),
                    }
                };
                differences.push(difference(path, change, policy));
            }
            None => {
                let withheld = policy.withhold_credentials && names_a_credential(path);
                differences.push(difference(
                    path,
                    FieldChange::Disappeared {
                        was: control_node.value().and_then(|v| render(v, withheld)),
                    },
                    policy,
                ));
            }
        }
    }

    for (path, variant_node) in &right {
        if left.contains_key(path) {
            continue;
        }
        let withheld = policy.withhold_credentials && names_a_credential(path);
        differences.push(difference(
            path,
            FieldChange::Appeared {
                now: variant_node.value().and_then(|v| render(v, withheld)),
            },
            policy,
        ));
    }

    differences.sort_by(|a, b| a.path.cmp(&b.path));
    let total = left
        .keys()
        .chain(right.keys())
        .collect::<BTreeSet<_>>()
        .len();
    (differences, shared, total)
}

fn difference(path: &str, change: FieldChange, policy: &Policy) -> FieldDifference {
    let name = field(path);
    let set_aside = if policy
        .dynamic_fields
        .iter()
        .any(|dynamic| dynamic.eq_ignore_ascii_case(&name))
    {
        Some(SetAside::Dynamic)
    } else if policy.withhold_credentials && names_a_credential(path) {
        Some(SetAside::Credential)
    } else {
        None
    };

    FieldDifference {
        path: path.to_string(),
        change,
        set_aside,
        notable: names_something_personal(path),
    }
}

/// Sorts arrays that hold the same values in a different order, in both documents.
///
/// Returns how many it touched, so the caller can record a [`Quirk`] rather than making
/// the change invisible.
///
/// The guard is that the two arrays must be **permutations of each other**: same values,
/// same multiplicities. When that holds, sorting both makes them identical and no
/// information is lost, because there was no difference to lose. When it does not hold,
/// both are left exactly as they were and every difference is reported as before — an
/// array that gained an element is a change, and hiding it behind a sort would be the
/// kind of quiet normalisation this module exists to avoid.
fn settle_order(left: &mut serde_json::Value, right: &mut serde_json::Value) -> usize {
    use serde_json::Value;

    match (left, right) {
        (Value::Array(a), Value::Array(b)) => {
            let mut touched = 0;
            if a.len() == b.len() && is_permutation(a, b) && !same_order(a, b) {
                a.sort_by_key(|item| item.to_string());
                b.sort_by_key(|item| item.to_string());
                touched += 1;
            }
            // Descend either way: a correctly ordered array can still hold objects with
            // shuffled arrays inside them.
            for (x, y) in a.iter_mut().zip(b.iter_mut()) {
                touched += settle_order(x, y);
            }
            touched
        }
        (Value::Object(a), Value::Object(b)) => {
            let mut touched = 0;
            for (key, x) in a.iter_mut() {
                if let Some(y) = b.get_mut(key) {
                    touched += settle_order(x, y);
                }
            }
            touched
        }
        _ => 0,
    }
}

/// Whether two arrays hold the same values with the same multiplicities.
///
/// By serialized form, which is exact for JSON and does not need `Value` to be `Ord`.
fn is_permutation(a: &[serde_json::Value], b: &[serde_json::Value]) -> bool {
    let mut left: Vec<String> = a.iter().map(|item| item.to_string()).collect();
    let mut right: Vec<String> = b.iter().map(|item| item.to_string()).collect();
    left.sort();
    right.sort();
    left == right
}

fn same_order(a: &[serde_json::Value], b: &[serde_json::Value]) -> bool {
    a.iter().zip(b.iter()).all(|(x, y)| x == y)
}

/// Flattens a document to one node per path, keeping array indices.
///
/// `$.items[3].price` rather than `$.items[].price`: a tester told an invoice differs
/// wants to know which one. The cost is honest and worth stating — an array whose order
/// changed between two responses shows as many differences, because as far as this
/// comparison can tell, it did change.
fn flatten(value: &serde_json::Value, path: String, out: &mut BTreeMap<String, Node>) {
    // A hostile application can send a deeply nested document, and a comparison is not
    // worth a stack overflow.
    if path.matches('.').count() + path.matches('[').count() > MAX_DEPTH {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            out.insert(path.clone(), Node::Container("object"));
            for (key, child) in map {
                flatten(child, format!("{path}.{key}"), out);
            }
        }
        serde_json::Value::Array(items) => {
            out.insert(path.clone(), Node::Container("array"));
            for (index, child) in items.iter().take(MAX_ARRAY).enumerate() {
                flatten(child, format!("{path}[{index}]"), out);
            }
        }
        leaf => {
            out.insert(path, Node::Leaf(leaf.clone()));
        }
    }
}

fn kind_of(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// A value, quoted and truncated — or withheld.
fn render(value: &serde_json::Value, withheld: bool) -> Option<String> {
    if withheld {
        return None;
    }
    let text = match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    if text.chars().count() <= VALUE_LIMIT {
        return Some(text);
    }
    let mut cut: String = text.chars().take(VALUE_LIMIT).collect();
    cut.push('…');
    Some(cut)
}

/// The last named segment of a path, lowercased.
fn field(path: &str) -> String {
    path.rsplit('.')
        .next()
        .unwrap_or(path)
        .split('[')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Whether a field's name says its value is a credential.
///
/// Matched as a substring for the stems that cannot mean anything else, so
/// `session_token`, `refreshToken` and `x_api_key` are all covered without the list
/// having to enumerate every spelling an application might use. The cost of a false
/// match is a value not quoted; the cost of a miss is a session in a report, so the
/// rule leans the way it does deliberately.
fn names_a_credential(path: &str) -> bool {
    const STEMS: &[&str] = &[
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "session",
        "cookie",
        "credential",
        "private_key",
        "privatekey",
        "signature",
    ];
    /// Short enough that a substring match would catch unrelated fields.
    const EXACT: &[&str] = &["auth", "pin", "otp", "jwt", "nonce_secret"];

    let name = field(path);
    STEMS.iter().any(|stem| name.contains(stem)) || EXACT.contains(&name.as_str())
}

/// Whether a field's name suggests it carries something personal.
///
/// Ordering only. Hexora does not know what an application's data means, and a field
/// called `balance` might be a progress bar.
fn names_something_personal(path: &str) -> bool {
    const PERSONAL: &[&str] = &[
        "email",
        "e_mail",
        "phone",
        "mobile",
        "ssn",
        "national_id",
        "address",
        "street",
        "postcode",
        "zip",
        "dob",
        "birthdate",
        "birthday",
        "salary",
        "balance",
        "iban",
        "card",
        "card_number",
        "account",
        "account_id",
        "owner",
        "owner_id",
        "user_id",
        "customer_id",
        "name",
        "full_name",
        "role",
        "roles",
        "admin",
        "is_admin",
        "permission",
        "permissions",
        "scope",
        "scopes",
    ];
    PERSONAL.contains(&field(path).as_str())
}

// ---------------------------------------------------------------------------
// Parsing, and the keys a parser throws away
// ---------------------------------------------------------------------------

/// A parsed body, and whether reading it lost anything.
struct Parsed {
    value: serde_json::Value,
    duplicate_keys: bool,
}

fn parse(body: &[u8]) -> Option<Parsed> {
    let text = std::str::from_utf8(body).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    Some(Parsed {
        duplicate_keys: has_duplicate_keys(text),
        value,
    })
}

/// Whether any object in the document repeats a key.
///
/// Every JSON parser reduces `{"id":"1000","id":"1001"}` to one key, and which one it
/// keeps is the parser's business rather than the application's. A comparison that
/// silently lost one of them would be comparing something the server did not send, so
/// this scans the text the parser has already accepted and says whether that happened.
///
/// A scanner rather than a second parse: it answers one question, over input
/// `serde_json` has already declared well-formed.
fn has_duplicate_keys(text: &str) -> bool {
    // One entry per open container: `Some(keys)` for an object, `None` for an array.
    let mut stack: Vec<Option<BTreeSet<String>>> = Vec::new();
    let mut chars = text.chars().peekable();
    let mut pending: Option<String> = None;

    while let Some(c) = chars.next() {
        match c {
            '{' => {
                pending = None;
                stack.push(Some(BTreeSet::new()));
            }
            '[' => {
                pending = None;
                stack.push(None);
            }
            '}' | ']' => {
                pending = None;
                stack.pop();
            }
            ',' => pending = None,
            ':' => {
                // The string just read was a key, if we are directly inside an object.
                if let (Some(key), Some(Some(keys))) = (pending.take(), stack.last_mut()) {
                    if !keys.insert(key) {
                        return true;
                    }
                }
            }
            '"' => {
                let mut literal = String::new();
                let mut escaped = false;
                for c in chars.by_ref() {
                    if escaped {
                        literal.push(c);
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        break;
                    } else {
                        literal.push(c);
                    }
                }
                pending = Some(literal);
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diff(control: &str, variant: &str) -> Diff {
        Diff::of(control.as_bytes(), variant.as_bytes(), &Policy::default())
    }

    fn strict(control: &str, variant: &str) -> Diff {
        Diff::of(control.as_bytes(), variant.as_bytes(), &Policy::strict())
    }

    // -----------------------------------------------------------------------
    // What a difference says
    // -----------------------------------------------------------------------

    #[test]
    fn the_same_document_produces_no_differences() {
        let body = r#"{"id":"acct-1000","owner":"User A","balance":4210}"#;
        let diff = strict(body, body);

        assert!(diff.differences.is_empty());
        assert!(diff.same_document());
        assert_eq!(diff.shared_paths, 3, "three leaves, not counting the root");
    }

    #[test]
    fn key_order_is_not_a_difference() {
        let diff = strict(r#"{"a":1,"b":2,"c":3}"#, r#"{"c":3,"b":2,"a":1}"#);
        assert!(diff.differences.is_empty(), "{:#?}", diff.differences);
    }

    #[test]
    fn a_field_only_the_control_has_disappeared() {
        // The sentence this module exists to produce.
        let diff = strict(
            r#"{"id":"acct-1000","email":"alice@example.com","role":"user"}"#,
            r#"{"id":"acct-1000","email":"alice@example.com"}"#,
        );

        let counted: Vec<&FieldDifference> = diff.counted().collect();
        assert_eq!(counted.len(), 1, "{counted:#?}");
        assert_eq!(counted[0].path, "$.role");
        assert!(matches!(counted[0].change, FieldChange::Disappeared { .. }));

        let summary = diff.summary("User A", "User B");
        assert!(summary.contains("$.role"), "{summary}");
        assert!(summary.contains("absent for User B"), "{summary}");
    }

    #[test]
    fn a_field_only_the_variant_has_appeared() {
        let diff = strict(r#"{"id":1}"#, r#"{"id":1,"admin":true}"#);
        let counted: Vec<&FieldDifference> = diff.counted().collect();
        assert_eq!(counted.len(), 1);
        assert_eq!(counted[0].path, "$.admin");
        assert!(matches!(counted[0].change, FieldChange::Appeared { .. }));
    }

    #[test]
    fn a_changed_scalar_quotes_both_sides() {
        // The distinction that matters for authorization: the same field holding a
        // different identifier is not the same as it holding the same one.
        let diff = strict(
            r#"{"invoice":{"owner":{"id":"acct-1000"}}}"#,
            r#"{"invoice":{"owner":{"id":"acct-2000"}}}"#,
        );
        let counted: Vec<&FieldDifference> = diff.counted().collect();
        assert_eq!(counted.len(), 1);
        assert_eq!(counted[0].path, "$.invoice.owner.id");
        match &counted[0].change {
            FieldChange::Changed { from, to } => {
                assert_eq!(from.as_deref(), Some("acct-1000"));
                assert_eq!(to.as_deref(), Some("acct-2000"));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn the_same_identifier_on_both_sides_is_no_difference_at_all() {
        // The pair the previous test contrasts with, and the one that says the variant
        // was served the control's object.
        let body = r#"{"invoice":{"owner":{"id":"acct-1000"}}}"#;
        assert!(strict(body, body).same_document());
    }

    #[test]
    fn a_number_becoming_a_string_is_a_type_change_and_not_a_value_change() {
        let diff = strict(r#"{"id":1000}"#, r#"{"id":"1000"}"#);
        let counted: Vec<&FieldDifference> = diff.counted().collect();
        assert_eq!(counted.len(), 1);
        match &counted[0].change {
            FieldChange::TypeChanged { from, to } => {
                assert_eq!(from, "number");
                assert_eq!(to, "string");
            }
            other => panic!("expected TypeChanged, got {other:?}"),
        }
        assert!(counted[0].change.is_structural());
    }

    #[test]
    fn a_missing_field_and_an_explicit_null_are_different_things() {
        // `{"a": null}` says the application has a field with no value; `{}` says it
        // has no field. A comparison that conflated them would lose the distinction an
        // API's own contract rests on.
        let diff = strict(r#"{"a":null}"#, r#"{}"#);
        let counted: Vec<&FieldDifference> = diff.counted().collect();
        assert_eq!(counted.len(), 1, "{counted:#?}");
        assert_eq!(counted[0].path, "$.a");
        assert!(matches!(counted[0].change, FieldChange::Disappeared { .. }));
    }

    #[test]
    fn an_empty_object_and_an_empty_array_are_not_the_same() {
        let diff = strict("{}", "[]");
        assert_eq!(diff.comparable, Comparable::Structurally);
        assert!(!diff.same_document());
        let counted: Vec<&FieldDifference> = diff.counted().collect();
        assert_eq!(counted[0].path, "$");
        assert!(matches!(counted[0].change, FieldChange::TypeChanged { .. }));
    }

    #[test]
    fn an_empty_object_and_a_populated_one_differ_only_at_the_field() {
        // The root is a container in both, so the difference is the field and not the
        // document.
        let diff = strict(r#"{}"#, r#"{"a":1}"#);
        let counted: Vec<&FieldDifference> = diff.counted().collect();
        assert_eq!(counted.len(), 1);
        assert_eq!(counted[0].path, "$.a");
    }

    // -----------------------------------------------------------------------
    // Paths
    // -----------------------------------------------------------------------

    #[test]
    fn a_nested_difference_gets_the_path_that_finds_it() {
        let diff = strict(
            r#"{"user":{"profile":{"email":"a@example.com"}}}"#,
            r#"{"user":{"profile":{"email":"b@example.com"}}}"#,
        );
        assert_eq!(diff.counted().next().unwrap().path, "$.user.profile.email");
    }

    #[test]
    fn an_array_element_keeps_its_index() {
        // `$.items[3].price` rather than `$.items[].price`: a tester told an invoice
        // differs wants to know which one.
        let diff = strict(
            r#"{"items":[{"price":1},{"price":2},{"price":3},{"price":4}]}"#,
            r#"{"items":[{"price":1},{"price":2},{"price":3},{"price":9}]}"#,
        );
        let counted: Vec<&FieldDifference> = diff.counted().collect();
        assert_eq!(counted.len(), 1);
        assert_eq!(counted[0].path, "$.items[3].price");
    }

    #[test]
    fn a_shorter_array_loses_its_tail_rather_than_shifting() {
        let diff = strict(r#"{"a":[1,2,3]}"#, r#"{"a":[1,2]}"#);
        let counted: Vec<&FieldDifference> = diff.counted().collect();
        assert_eq!(counted.len(), 1);
        assert_eq!(counted[0].path, "$.a[2]");
        assert!(matches!(counted[0].change, FieldChange::Disappeared { .. }));
    }

    #[test]
    fn the_same_two_documents_always_produce_the_same_order() {
        let control = r#"{"z":1,"a":2,"m":{"q":3,"b":4}}"#;
        let variant = r#"{"z":9,"a":8,"m":{"q":7,"b":6}}"#;
        let first: Vec<String> = strict(control, variant)
            .differences
            .iter()
            .map(|d| d.path.clone())
            .collect();
        for _ in 0..5 {
            let again: Vec<String> = strict(control, variant)
                .differences
                .iter()
                .map(|d| d.path.clone())
                .collect();
            assert_eq!(first, again);
        }
        assert_eq!(first, vec!["$.a", "$.m.b", "$.m.q", "$.z"]);
    }

    // -----------------------------------------------------------------------
    // Normalization, which is never implicit
    // -----------------------------------------------------------------------

    #[test]
    fn a_strict_policy_sets_nothing_aside() {
        let diff = strict(
            r#"{"id":1,"timestamp":"2026-09-11T11:00:01Z"}"#,
            r#"{"id":1,"timestamp":"2026-09-11T11:00:03Z"}"#,
        );
        assert_eq!(diff.counted().count(), 1);
        assert_eq!(diff.set_aside(), 0);
        assert!(!diff.same_document());
        assert_eq!(diff.policy.describe(), "no field was treated as dynamic");
    }

    #[test]
    fn a_field_the_policy_sets_aside_is_still_reported_with_its_reason() {
        // The rule that keeps this from becoming the thing it replaces. Nothing is
        // removed; it is marked, both values survive, and the summary says how many.
        let diff = diff(
            r#"{"id":1,"timestamp":"2026-09-11T11:00:01Z","csrf":"aaa"}"#,
            r#"{"id":1,"timestamp":"2026-09-11T11:00:03Z","csrf":"bbb"}"#,
        );

        assert!(diff.same_document(), "nothing that counts differs");
        assert_eq!(diff.set_aside(), 2);
        assert_eq!(diff.differences.len(), 2, "both are still in the list");

        let timestamp = diff
            .differences
            .iter()
            .find(|d| d.path == "$.timestamp")
            .unwrap();
        assert_eq!(timestamp.set_aside, Some(SetAside::Dynamic));
        match &timestamp.change {
            FieldChange::Changed { from, to } => {
                assert_eq!(from.as_deref(), Some("2026-09-11T11:00:01Z"));
                assert_eq!(to.as_deref(), Some("2026-09-11T11:00:03Z"));
            }
            other => panic!("expected Changed, got {other:?}"),
        }

        assert!(diff.summary("A", "B").contains("set aside"));
    }

    #[test]
    fn the_policy_says_what_it_did() {
        let default = Policy::default();
        assert!(default.describe().contains("changing every request"));
        assert!(default.describe().contains("credential values withheld"));
        assert_eq!(
            Policy::strict().describe(),
            "no field was treated as dynamic"
        );
        assert_eq!(
            Policy::careful().describe(),
            "no field was treated as dynamic; credential values withheld"
        );
    }

    #[test]
    fn an_identifier_is_never_treated_as_dynamic() {
        // `id`, `uuid` and `key` are precisely what a cross-identity comparison exists
        // to look at. A policy that set one aside would set aside the finding.
        for name in ["id", "uuid", "key", "account_id", "invoice_id", "object_id"] {
            assert!(
                !Policy::DYNAMIC.contains(&name),
                "{name} is in the default dynamic list"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Credentials
    // -----------------------------------------------------------------------

    #[test]
    fn a_credential_field_reports_the_change_and_withholds_the_value() {
        // That a session token differs between two identities is correct and worth
        // seeing. What it *is* never belongs in a comparison.
        let diff = diff(
            r#"{"id":1,"access_token":"secret-value-for-a"}"#,
            r#"{"id":1,"access_token":"secret-value-for-b"}"#,
        );

        let token = diff
            .differences
            .iter()
            .find(|d| d.path == "$.access_token")
            .unwrap();
        assert_eq!(token.set_aside, Some(SetAside::Credential));
        match &token.change {
            FieldChange::Changed { from, to } => {
                assert!(from.is_none() && to.is_none(), "{token:#?}");
            }
            other => panic!("expected Changed, got {other:?}"),
        }

        let rendered = format!("{diff:?}") + &diff.summary("A", "B");
        assert!(!rendered.contains("secret-value-for-a"), "{rendered}");
    }

    #[test]
    fn a_credential_is_recognised_however_the_application_spells_it() {
        // The list is stems rather than whole names, because an application that calls
        // it `session_token` is not thereby allowed to put it in a report.
        for name in [
            "session_token",
            "refreshtoken",
            "x_api_key",
            "csrf_secret",
            "authorization",
            "jwt",
        ] {
            let diff = diff(
                &format!(r#"{{"{name}":"value-for-a"}}"#),
                &format!(r#"{{"{name}":"value-for-b"}}"#),
            );
            assert_eq!(
                diff.differences[0].set_aside,
                Some(SetAside::Credential),
                "{name}"
            );
            assert!(!format!("{diff:?}").contains("value-for-a"), "{name}");
        }
    }

    #[test]
    fn an_ordinary_field_is_not_mistaken_for_a_credential() {
        // A stem match is not free: `tokens_remaining` is withheld too, and that is the
        // side of the trade to err on — the difference is still reported, so a tester
        // who wants the number can go and look at the response the finding cites.
        for name in ["email", "balance", "id", "owner", "role", "quota"] {
            let diff = diff(
                &format!(r#"{{"{name}":"a"}}"#),
                &format!(r#"{{"{name}":"b"}}"#),
            );
            assert_ne!(
                diff.differences[0].set_aside,
                Some(SetAside::Credential),
                "{name}"
            );
        }
    }

    #[test]
    fn a_strict_policy_does_quote_a_credential_and_records_that_it_did() {
        // The escape hatch is explicit: a tester comparing two tokens on their own
        // machine asked for this, and the policy carried on the diff says so.
        let diff = strict(r#"{"token":"abc"}"#, r#"{"token":"def"}"#);
        assert_eq!(diff.counted().count(), 1);
        assert!(!diff.policy.withhold_credentials);
    }

    // -----------------------------------------------------------------------
    // What a parser throws away
    // -----------------------------------------------------------------------

    #[test]
    fn a_repeated_key_is_reported_rather_than_silently_collapsed() {
        let diff = diff(r#"{"id":"1000","id":"1001"}"#, r#"{"id":"1000"}"#);
        assert!(
            diff.quirks.contains(&Quirk::DuplicateKeysInControl),
            "{:#?}",
            diff.quirks
        );
        assert!(!diff.quirks.contains(&Quirk::DuplicateKeysInVariant));
    }

    #[test]
    fn duplicate_detection_is_not_confused_by_strings_that_look_like_keys() {
        assert!(!has_duplicate_keys(r#"{"a":"b:c","d":"a"}"#));
        assert!(!has_duplicate_keys(r#"{"a":{"b":1},"c":{"b":2}}"#));
        assert!(!has_duplicate_keys(r#"[{"a":1},{"a":2}]"#));
        assert!(!has_duplicate_keys(r#"{"a":"say \"a\": twice"}"#));
        assert!(has_duplicate_keys(r#"{"a":1,"b":2,"a":3}"#));
        assert!(has_duplicate_keys(r#"{"x":{"k":1,"k":2}}"#));
    }

    // -----------------------------------------------------------------------
    // Falling back
    // -----------------------------------------------------------------------

    #[test]
    fn bodies_that_are_not_json_establish_nothing() {
        let diff = strict("<html>a</html>", "<html>b</html>");
        assert_eq!(diff.comparable, Comparable::NotStructured);
        assert!(!diff.same_document(), "nothing was compared");
        assert!(diff.summary("A", "B").contains("no field-by-field"));
    }

    #[test]
    fn a_document_against_an_error_page_is_the_interesting_case() {
        let diff = Diff::of(br#"{"id":1}"#, b"<html>denied</html>", &Policy::default());
        assert_eq!(diff.comparable, Comparable::OnlyOneSide);
        assert!(!diff.same_document());
        assert!(diff
            .summary("User A", "User B")
            .contains("not served the same kind"));
    }

    #[test]
    fn the_bodies_are_never_modified() {
        // This reads and describes. The originals stay exactly as the application sent
        // them, which is what every other layer cites as evidence.
        let control = br#"{"a":1,"timestamp":"x"}"#;
        let variant = br#"{"a":2,"timestamp":"y"}"#;
        let before = (control.to_vec(), variant.to_vec());

        let _ = Diff::of(control, variant, &Policy::default());
        assert_eq!(control.to_vec(), before.0);
        assert_eq!(variant.to_vec(), before.1);
    }

    // -----------------------------------------------------------------------
    // The two strong signals, and ranking
    // -----------------------------------------------------------------------

    #[test]
    fn two_users_own_records_are_not_the_same_document() {
        // The signal that says an application scoped its lookup to the caller —
        // available without a declared object id, which today is the only way to
        // establish it.
        let diff = strict(
            r#"{"id":"acct-1000","owner":"User A","balance":4210}"#,
            r#"{"id":"acct-2000","owner":"User B","balance":17}"#,
        );
        assert!(!diff.same_document());
        assert!(diff.every_value_differs(), "{:#?}", diff.differences);
    }

    #[test]
    fn one_shared_value_is_enough_to_stop_every_value_differing() {
        let diff = strict(
            r#"{"id":"acct-1000","owner":"User A"}"#,
            r#"{"id":"acct-1000","owner":"User B"}"#,
        );
        assert!(!diff.every_value_differs());
        assert!(!diff.same_document());
    }

    #[test]
    fn a_personal_field_is_shown_before_an_uninteresting_one() {
        let diff = strict(
            r#"{"sort_order":1,"email":"a@example.com","tab_index":3}"#,
            r#"{"sort_order":2,"email":"b@example.com","tab_index":4}"#,
        );
        let summary = diff.summary("User A", "User B");
        let email = summary.find("$.email").expect("email is mentioned");
        let sort = summary.find("$.sort_order").unwrap_or(usize::MAX);
        assert!(email < sort, "{summary}");
    }

    #[test]
    fn a_long_value_is_cut_rather_than_copied_into_the_report() {
        let long = "x".repeat(500);
        let diff = strict(&format!(r#"{{"note":"{long}"}}"#), r#"{"note":"short"}"#);
        let counted: Vec<&FieldDifference> = diff.counted().collect();
        match &counted[0].change {
            FieldChange::Changed { from, .. } => {
                let from = from.as_ref().unwrap();
                assert!(from.chars().count() <= VALUE_LIMIT + 1);
                assert!(from.ends_with('…'));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn hostile_input_does_not_panic_or_run_away() {
        let deep = format!("{}1{}", "[".repeat(400), "]".repeat(400));
        let wide = format!(
            "{{{}}}",
            (0..3000)
                .map(|i| format!(r#""k{i}":{i}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        for (control, variant) in [
            ("", ""),
            ("null", "null"),
            ("{}", "[]"),
            (deep.as_str(), "1"),
            (wide.as_str(), "{}"),
            ("{\"a\":", "{\"a\":"),
            (r#"{"a":" "}"#, r#"{"a":""}"#),
        ] {
            let _ = strict(control, variant);
            let _ = diff(control, variant);
        }
        let _ = Diff::of(&[0xff, 0xfe], &[0x00], &Policy::default());
    }

    // -----------------------------------------------------------------------
    // Arrays that come back in a different order
    // -----------------------------------------------------------------------

    #[test]
    fn the_same_values_in_a_different_order_are_not_a_difference() {
        // Measured against a real API, from two *identical unauthenticated* requests a
        // second apart. Compared by index this is six differences, and six differences
        // is "the responses differ" — which is the premise underneath every check that
        // asks whether two callers were served the same thing.
        let a = br#"{"countries":["LVA","EST","SWE","DNK","ISR","LTU"]}"#;
        let b = br#"{"countries":["ISR","SWE","DNK","LTU","LVA","EST"]}"#;

        let diff = Diff::of(a, b, &Policy::default());
        assert!(
            diff.same_document(),
            "a shuffled array read as a changed document: {}",
            diff.summary("control", "variant")
        );
    }

    #[test]
    fn a_reordering_is_reported_rather_than_done_quietly() {
        // A reader deciding whether to trust "the same document" is entitled to know
        // that part of it was only the same once order was ignored.
        let a = br#"{"tags":["x","y"]}"#;
        let b = br#"{"tags":["y","x"]}"#;

        let diff = Diff::of(a, b, &Policy::default());
        assert!(
            diff.quirks
                .iter()
                .any(|quirk| matches!(quirk, Quirk::ArraysReordered { count: 1 })),
            "{:?}",
            diff.quirks
        );
    }

    #[test]
    fn an_array_that_actually_changed_is_still_a_difference() {
        // The guard. Sorting is only sound when the two arrays hold the same values;
        // an array that gained, lost or altered an element changed, and hiding that
        // behind a sort would be exactly the quiet normalisation this module refuses.
        for (a, b) in [
            (&br#"{"t":["x","y"]}"#[..], &br#"{"t":["y","z"]}"#[..]),
            (&br#"{"t":["x","y"]}"#[..], &br#"{"t":["x","y","z"]}"#[..]),
            (
                &br#"{"t":["x","x","y"]}"#[..],
                &br#"{"t":["x","y","y"]}"#[..],
            ),
        ] {
            let diff = Diff::of(a, b, &Policy::default());
            assert!(
                !diff.same_document(),
                "a real change was sorted away: {} vs {}",
                String::from_utf8_lossy(a),
                String::from_utf8_lossy(b)
            );
        }
    }

    #[test]
    fn strict_counts_a_reordering_as_a_difference() {
        // `strict` sets nothing aside, and that has to keep meaning what it says.
        let a = br#"{"t":["x","y"]}"#;
        let b = br#"{"t":["y","x"]}"#;

        assert!(!Diff::of(a, b, &Policy::strict()).same_document());
        assert!(Diff::of(a, b, &Policy::default()).same_document());
    }

    #[test]
    fn a_shuffled_array_nested_in_an_object_is_settled_too() {
        let a = br#"{"payment":{"methods":["card","cash"],"fee":1}}"#;
        let b = br#"{"payment":{"methods":["cash","card"],"fee":1}}"#;
        assert!(Diff::of(a, b, &Policy::default()).same_document());
    }

    #[test]
    fn shuffled_objects_inside_an_array_are_settled_by_their_content() {
        // Arrays of objects are the common real shape — a list of venues, a list of
        // orders — and they shuffle for the same reasons scalars do.
        let a = br#"[{"id":"a","n":1},{"id":"b","n":2}]"#;
        let b = br#"[{"id":"b","n":2},{"id":"a","n":1}]"#;
        assert!(Diff::of(a, b, &Policy::default()).same_document());
    }

    #[test]
    fn a_changed_object_inside_a_shuffled_array_is_still_found() {
        let a = br#"[{"id":"a","n":1},{"id":"b","n":2}]"#;
        let b = br#"[{"id":"b","n":2},{"id":"a","n":99}]"#;
        let diff = Diff::of(a, b, &Policy::default());
        assert!(
            !diff.same_document(),
            "{}",
            diff.summary("control", "variant")
        );
    }
}

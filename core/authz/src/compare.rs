//! Deciding whether two identities were served the same thing.
//!
//! The whole authorization question reduces to one comparison: the owner asked for a
//! resource and got it; somebody else asked for the same resource — did they get it
//! too? Answering that with `a.body == b.body` does not survive contact with a real
//! application. The same page rendered for two users differs by a CSRF token, a
//! greeting, a session id, a timestamp and a nonce, and none of that means the second
//! user was denied anything.
//!
//! So responses are reduced to a [`Fingerprint`] before they are compared:
//!
//! * **Status** and **content type** are kept exactly — a 403 is never "nearly" a 200.
//! * **JSON bodies** are reduced to their *shape*: the set of key paths, with array
//!   indices collapsed. Two invoices for two customers have identical shapes and
//!   different values, which is precisely the signal — the second user was served the
//!   invoice document, whoever's it was.
//! * **Everything else** is reduced to a token multiset with volatile runs (digits,
//!   long hex strings) masked, so a token that changes every request stops dominating
//!   the comparison.
//!
//! # The one thing similarity cannot tell you
//!
//! A high score means "the same kind of document came back", never "the tester's data
//! leaked". A public marketing page scores 1.00 for every identity including
//! anonymous, and nothing is wrong. That is why [`Fingerprint`] is only half of the
//! evidence and [`contains_any`] is the other half: an object id known to belong to
//! *someone else* appearing in the body is a fact, not a score. The analysis layer
//! weighs them differently on purpose.

use std::collections::BTreeSet;

use hexora_types::http::HttpResponse;

/// A response reduced to the parts a cross-identity comparison can use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// The status code, verbatim.
    pub status: u16,
    /// The media type, without parameters and lowercased.
    pub content_type: Option<String>,
    /// For a JSON body, the set of key paths with array indices collapsed to `[]`.
    pub json_shape: Option<BTreeSet<String>>,
    /// Normalized tokens, for bodies that are not JSON.
    pub tokens: BTreeSet<String>,
    /// The decoded body length in bytes.
    pub body_len: usize,
}

/// A similarity at or above this is treated as "the same resource came back".
///
/// A judgement call, like every threshold. It sits high because the *cost* of the two
/// mistakes is not symmetric: a missed authorization bug is one more finding a tester
/// would have found by hand, while a false one sends them to re-test something the
/// application got right, and a tool that does that twice stops being believed. Cells
/// below the threshold are still reported as `Different`, with their score, so a
/// near-miss is visible rather than silently dropped.
pub const SAME_RESOURCE: f32 = 0.90;

impl Fingerprint {
    /// Reduces a response to its comparable form.
    pub fn of(response: &HttpResponse) -> Self {
        let content_type = response
            .headers
            .get("Content-Type")
            .map(|h| media_type(&h.value_lossy()));

        let body = String::from_utf8_lossy(&response.body);
        let json_shape = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .map(|value| {
                let mut shape = BTreeSet::new();
                collect_shape(&value, String::new(), &mut shape);
                shape
            });

        Self {
            status: response.status,
            content_type,
            // Tokens are collected even for JSON: a shape comparison alone cannot
            // separate two documents whose keys match but whose *structure* is a
            // single error string, and the token set is what catches that.
            tokens: tokenize(&body),
            json_shape,
            body_len: response.body.len(),
        }
    }

    /// How alike two responses are, from 0.0 to 1.0.
    ///
    /// A different status code is scored as nothing alike regardless of body, because
    /// a 200 and a 403 carrying the same template are the opposite of the same result.
    pub fn similarity(&self, other: &Self) -> f32 {
        if self.status != other.status {
            return 0.0;
        }
        if self.content_type != other.content_type {
            return 0.0;
        }

        match (&self.json_shape, &other.json_shape) {
            (Some(a), Some(b)) => jaccard(a, b),
            // One side parsed as JSON and the other did not: whatever came back, it
            // was not the same document.
            (Some(_), None) | (None, Some(_)) => 0.0,
            (None, None) => {
                if self.tokens.is_empty() && other.tokens.is_empty() {
                    // Two empty bodies with the same status really are the same
                    // result — a pair of empty 204s, say.
                    1.0
                } else {
                    jaccard(&self.tokens, &other.tokens)
                }
            }
        }
    }
}

/// Which of `needles` appear literally in `haystack`.
///
/// Used for the strong signal: an object identifier the tester declared as belonging
/// to one identity, turning up in a body served to another. Case-sensitive and
/// substring-based, because an opaque id is opaque — normalizing it would risk
/// matching something that merely looks similar, and a false claim of a data leak is
/// the worst output this subsystem could produce.
///
/// Needles shorter than [`MIN_OBJECT_ID_LEN`] are ignored: `1` appears in almost every
/// response ever served, and reporting that as a leak would bury the real ones.
pub fn contains_any(haystack: &[u8], needles: &[String]) -> Vec<String> {
    let body = String::from_utf8_lossy(haystack);
    needles
        .iter()
        .filter(|needle| needle.len() >= MIN_OBJECT_ID_LEN && body.contains(needle.as_str()))
        .cloned()
        .collect()
}

/// The shortest object identifier that may be reported as leaked.
pub const MIN_OBJECT_ID_LEN: usize = 4;

/// The media type from a `Content-Type` value, lowercased, parameters dropped.
fn media_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count() as f32;
    let union = a.union(b).count() as f32;
    intersection / union
}

/// Collects the key paths of a JSON document, with array indices collapsed.
///
/// `{"users":[{"id":1,"name":"a"}]}` becomes `{"/users", "/users[]", "/users[]/id",
/// "/users[]/name"}` — a shape that is identical for one user or a thousand, and for
/// any values inside.
fn collect_shape(value: &serde_json::Value, path: String, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}/{key}");
                out.insert(child_path.clone());
                collect_shape(child, child_path, out);
            }
        }
        serde_json::Value::Array(items) => {
            let child_path = format!("{path}[]");
            out.insert(child_path.clone());
            for item in items {
                collect_shape(item, child_path.clone(), out);
            }
        }
        // Leaves contribute their path, which the parent already inserted. Their
        // *values* are deliberately not part of the shape.
        _ => {}
    }
}

/// Splits a body into comparable tokens, masking the parts that change every request.
fn tokenize(body: &str) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    for raw in body.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-') {
        if raw.is_empty() {
            continue;
        }
        tokens.insert(mask(raw));
    }
    tokens
}

/// Replaces a token that looks like a number, a hash or an opaque id with a
/// placeholder for its class.
///
/// Session ids, CSRF tokens, request ids and timestamps differ on every response and
/// between every identity. Left alone they make two renderings of the same page look
/// only half alike; masked, what remains is the page.
fn mask(token: &str) -> String {
    let is_digits = token.chars().all(|c| c.is_ascii_digit());
    if is_digits {
        return "<num>".into();
    }
    let is_hex = token.len() >= 8 && token.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex {
        return "<hex>".into();
    }
    // Long mixed-case-and-digit runs are the shape of a session cookie or a JWT
    // segment. The length floor keeps ordinary words out.
    if token.len() >= 20
        && token.chars().any(|c| c.is_ascii_digit())
        && token.chars().any(|c| c.is_ascii_alphabetic())
    {
        return "<opaque>".into();
    }
    token.to_string()
}

#[cfg(test)]
mod tests {
    use hexora_types::http::{Headers, HttpVersion};

    use super::*;

    fn response(status: u16, content_type: &str, body: &str) -> HttpResponse {
        let mut headers = Headers::new();
        headers.set("Content-Type", content_type);
        HttpResponse {
            status,
            reason: None,
            version: HttpVersion::Http11,
            headers,
            body: bytes::Bytes::from(body.to_owned()),
            truncated: false,
        }
    }

    fn similarity(a: &HttpResponse, b: &HttpResponse) -> f32 {
        Fingerprint::of(a).similarity(&Fingerprint::of(b))
    }

    #[test]
    fn the_same_json_document_for_two_customers_is_the_same_resource() {
        let a = response(
            200,
            "application/json",
            r#"{"id":"acct-1","owner":"alice","balance":100,"lines":[{"sku":"x","qty":1}]}"#,
        );
        let b = response(
            200,
            "application/json",
            r#"{"id":"acct-2","owner":"bob","balance":755,"lines":[{"sku":"y","qty":9},{"sku":"z","qty":2}]}"#,
        );
        assert!(
            similarity(&a, &b) >= SAME_RESOURCE,
            "two invoices are the same *resource*: {}",
            similarity(&a, &b)
        );
    }

    #[test]
    fn a_denial_is_never_similar_to_the_resource_it_denied() {
        let allowed = response(200, "application/json", r#"{"id":"acct-1"}"#);
        let denied = response(403, "application/json", r#"{"error":"forbidden"}"#);
        assert_eq!(similarity(&allowed, &denied), 0.0);
    }

    #[test]
    fn a_denial_dressed_as_two_hundred_is_still_not_the_resource() {
        // Applications that answer every request with 200 are common, and the status
        // check cannot save us there. The body shape has to.
        let allowed = response(
            200,
            "application/json",
            r#"{"invoice":{"id":"1","total":10,"lines":[]}}"#,
        );
        let denied = response(200, "application/json", r#"{"error":"not authorised"}"#);
        assert!(
            similarity(&allowed, &denied) < SAME_RESOURCE,
            "{}",
            similarity(&allowed, &denied)
        );
    }

    #[test]
    fn a_changed_media_type_is_not_the_same_resource() {
        let json = response(200, "application/json", r#"{"a":1}"#);
        let html = response(200, "text/html", "<html><body>a</body></html>");
        assert_eq!(similarity(&json, &html), 0.0);
    }

    #[test]
    fn content_type_parameters_do_not_split_a_media_type() {
        let a = response(200, "text/html; charset=utf-8", "<p>hello</p>");
        let b = response(200, "TEXT/HTML", "<p>hello</p>");
        assert_eq!(similarity(&a, &b), 1.0);
    }

    #[test]
    fn per_request_tokens_do_not_make_the_same_page_look_different() {
        let a = response(
            200,
            "text/html",
            "<html><input name=csrf value=8f3a91bd0c4e77aa><p>Welcome back</p></html>",
        );
        let b = response(
            200,
            "text/html",
            "<html><input name=csrf value=11de99cc07b34412><p>Welcome back</p></html>",
        );
        assert!(
            similarity(&a, &b) >= SAME_RESOURCE,
            "a rotating CSRF token is not a different page: {}",
            similarity(&a, &b)
        );
    }

    #[test]
    fn a_different_page_is_not_the_same_resource() {
        let account = response(
            200,
            "text/html",
            "<html><h1>Account statement</h1><table><tr><td>Balance</td></tr></table></html>",
        );
        let login = response(
            200,
            "text/html",
            "<html><h1>Sign in</h1><form><input name=password></form></html>",
        );
        assert!(similarity(&account, &login) < SAME_RESOURCE);
    }

    #[test]
    fn two_empty_bodies_with_the_same_status_are_the_same_result() {
        let a = response(204, "text/plain", "");
        let b = response(204, "text/plain", "");
        assert_eq!(similarity(&a, &b), 1.0);
    }

    #[test]
    fn json_shape_ignores_how_many_items_an_array_holds() {
        let one = response(200, "application/json", r#"{"items":[{"id":1}]}"#);
        let many = response(
            200,
            "application/json",
            r#"{"items":[{"id":1},{"id":2},{"id":3}]}"#,
        );
        assert_eq!(similarity(&one, &many), 1.0);
    }

    #[test]
    fn a_body_that_stopped_being_json_is_not_the_same_resource() {
        let json = response(200, "application/json", r#"{"a":1}"#);
        let broken = response(200, "application/json", "upstream connect error");
        assert_eq!(similarity(&json, &broken), 0.0);
    }

    #[test]
    fn an_owned_object_id_is_found_in_a_body_that_should_not_hold_it() {
        let body = br#"{"account":"acct-9f2b","owner":"alice"}"#;
        assert_eq!(
            contains_any(body, &["acct-9f2b".into(), "acct-0000".into()]),
            ["acct-9f2b"]
        );
    }

    #[test]
    fn short_identifiers_are_never_reported_as_leaked() {
        // "1" appears in nearly every response ever served. Reporting it would bury
        // the leaks that are real.
        let body = br#"{"page":1,"total":42}"#;
        assert!(contains_any(body, &["1".into(), "42".into()]).is_empty());
    }

    #[test]
    fn a_similarity_score_never_leaves_the_unit_interval() {
        let pairs = [
            (
                response(200, "text/html", "<p>a</p>"),
                response(200, "text/html", "<p>b</p>"),
            ),
            (
                response(200, "application/json", "{}"),
                response(200, "application/json", r#"{"a":{"b":[1,2]}}"#),
            ),
            (
                response(500, "text/plain", ""),
                response(500, "text/plain", "x"),
            ),
        ];
        for (a, b) in pairs {
            let score = similarity(&a, &b);
            assert!((0.0..=1.0).contains(&score), "{score}");
        }
    }

    #[test]
    fn similarity_is_symmetric_and_reflexive() {
        let a = response(200, "application/json", r#"{"a":1,"b":[{"c":2}]}"#);
        let b = response(200, "application/json", r#"{"a":9,"b":[]}"#);
        assert_eq!(similarity(&a, &b), similarity(&b, &a));
        assert_eq!(similarity(&a, &a), 1.0);
    }
}

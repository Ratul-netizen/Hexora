//! Where a value sits in a request, and how to put a different one there.
//!
//! Two subsystems need this and neither owns it. M12.5 builds the request nobody
//! captured by replacing a declared object identifier; M13.4 places a marker in an
//! input to see where it comes back. Both are asking the same two questions about an
//! [`ObjectLocation`], so the answers live here rather than in whichever crate needed
//! them first.
//!
//! ```text
//! locate(request, "acct-1000")  ->  [PathSegment { index: 2 }, Query { name: "ref" }]
//! value_at(request, location)   ->  "acct-1000"
//! substitute(request, location, "acct-2000")
//! ```
//!
//! # Nothing else about the request changes
//!
//! A substitution touches exactly the bytes at the location it was given. Header order,
//! casing, duplicates and the body all survive, because a generated request that
//! quietly differed from its original in a second place would make every conclusion
//! drawn from it unfalsifiable.
//!
//! # Sensitive headers are never a location
//!
//! [`locate`] skips them without exception. An `Authorization` value is a credential,
//! not an input: rewriting one changes *who is asking* in the middle of a test about
//! what they may ask for, and no caller has a legitimate reason to want that.
//!
//! # One way to substitute, and it always validates
//!
//! [`substitute`] refuses a replacement containing control characters, whatever the
//! caller is. A value carrying CR or LF would split the request it is spliced into,
//! and that is true of a marker a check generated exactly as much as of a value a
//! person typed — so there is no unvalidated variant to reach for. A future check that
//! genuinely needs to place a CR has to add that path deliberately, and say why.

use std::collections::HashMap;

use crate::http::HttpRequest;
use crate::object::ObjectLocation;
use crate::redact::is_sensitive_header;
use crate::Result;

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
    crate::object::validate_identifier(replacement)?;
    let mut built = request.clone();

    match location {
        ObjectLocation::PathSegment { index } => {
            let (path, query) = split_target(&request.path);
            let mut segments: Vec<String> = path_segments(path).map(str::to_string).collect();
            let slot = segments.get_mut(*index).ok_or_else(|| {
                crate::HexoraError::invalid_input(
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
                crate::HexoraError::invalid_input("location", "this request has no query string")
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
                return Err(crate::HexoraError::invalid_input(
                    "location",
                    format!("this request has no {name} parameter at occurrence {occurrence}"),
                ));
            }
            built.path = format!("{path}?{}", rebuilt.join("&"));
        }
        ObjectLocation::Header { name, occurrence } => {
            if is_sensitive_header(name) {
                return Err(crate::HexoraError::invalid_input(
                    "location",
                    format!(
                        "{name} carries a credential, not an object identifier, and is \
                         never substituted"
                    ),
                ));
            }
            let mut matched = 0usize;
            let mut replaced = false;
            let mut headers = crate::http::Headers::new();
            for header in request.headers.iter() {
                if header.name.eq_ignore_ascii_case(name) {
                    let this = matched;
                    matched += 1;
                    if this == *occurrence {
                        replaced = true;
                        headers.append(crate::http::Header::new(header.name.clone(), replacement));
                        continue;
                    }
                }
                headers.append(header.clone());
            }
            if !replaced {
                return Err(crate::HexoraError::invalid_input(
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
            return Err(crate::HexoraError::invalid_input(
                "location",
                format!(
                    "a body substitution needs the value it is replacing, not only \
                     byte {offset}; call substitute_in_body"
                ),
            ));
        }
        ObjectLocation::Anywhere => {
            return Err(crate::HexoraError::invalid_input(
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
    crate::object::validate_identifier(replacement)?;
    let end = offset + original.len();
    if end > request.body.len() || &request.body[offset..end] != original.as_bytes() {
        return Err(crate::HexoraError::invalid_input(
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

/// Every place in a request that a caller supplied a value.
///
/// The question [`locate`] does not answer: not *where is this value* but *what does
/// this request take*. An active check needs it to know what there is to probe.
///
/// ```text
/// GET /search?q=shoes&page=2   ->  Query { name: "q" }, Query { name: "page" }
/// ```
///
/// # What is left out, and why
///
/// **Path segments.** A segment is as often structure as data — `/api/v2/users/1000`
/// has one input and three parts of a route — and putting a marker into the wrong one
/// produces a 404 and a wasted request. `hexora identifiers` exists to tell those
/// apart with evidence; guessing here would undo it.
///
/// **Sensitive headers**, without exception, for the reason [`locate`] skips them.
///
/// **Headers a client controls rather than the application** — `Host` decides where
/// the request goes, `Content-Length` decides how it is framed, and a marker in either
/// tests the transport rather than the application.
///
/// **Body fields**, for now. A body is `Content-Type`-shaped: JSON wants a field path,
/// a form wants a parameter name, multipart wants a part, and
/// [`ObjectLocation::Body`] addresses a byte offset — which is the right handle for
/// replacing a known value and the wrong one for enumerating unknown fields. That
/// wants a body model rather than an offset, and inventing one here would be inventing
/// it blind.
pub fn inputs(request: &HttpRequest) -> Vec<ObjectLocation> {
    inputs_in(&request.path, &request.headers)
}

/// The same, from a request target and header block rather than a whole request.
///
/// For callers holding a stored exchange rather than a live [`HttpRequest`] — the
/// scanner reads a redacted view of captured traffic, and a redacted `Cookie` is
/// skipped by exactly the same rule as an unredacted one.
pub fn inputs_in(target: &str, headers: &crate::http::Headers) -> Vec<ObjectLocation> {
    let mut found = Vec::new();

    let (_, query) = split_target(target);
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (name, _) in query_pairs(query) {
        let occurrence = seen.entry(name.to_string()).or_insert(0);
        found.push(ObjectLocation::Query {
            name: name.to_string(),
            occurrence: *occurrence,
        });
        *occurrence += 1;
    }

    let mut header_seen: HashMap<String, usize> = HashMap::new();
    for header in headers.iter() {
        let lower = header.name.to_ascii_lowercase();
        let occurrence = header_seen.entry(lower.clone()).or_insert(0);
        if !is_sensitive_header(&header.name) && !is_transport_header(&lower) {
            found.push(ObjectLocation::Header {
                name: header.name.clone(),
                occurrence: *occurrence,
            });
        }
        *occurrence += 1;
    }

    found
}

/// Headers that decide how a request is delivered rather than what it asks for.
///
/// A marker in one of these tests the transport, not the application — and two of them
/// would send the request somewhere else entirely.
fn is_transport_header(lower: &str) -> bool {
    matches!(
        lower,
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "upgrade"
            | "expect"
            | "te"
            | "trailer"
            | "content-type"
    ) || is_browser_metadata(lower)
}

/// Headers the *browser* writes about itself, which no application treats as input.
///
/// Found against a real target, and it is a cost paid in somebody else's bandwidth:
/// 86 captured exchanges produced **940** experiments, because every header on every
/// request became something to probe — including `Sec-Fetch-Dest`, `sec-ch-ua-mobile`
/// and `Accept-Encoding`. A plan that large cannot finish inside a sane budget, so what
/// ran was an arbitrary five per cent of it, which is worse than testing nothing:
/// it *looks* like coverage.
///
/// The line is who writes the header and why. Client hints and fetch metadata are the
/// user agent describing itself under a spec that says servers may vary on them and
/// nothing more. They are not a place an application puts data it later prints.
///
/// **`User-Agent`, `Referer` and `Origin` stay probeable** — deliberately. Those three
/// really do reach error pages, admin panels and log viewers, and they are the classic
/// stored-reflection vectors. Narrowing the list to what is genuinely inert is the
/// point; narrowing it until nothing is left would be a scanner that finds nothing and
/// says so quickly.
fn is_browser_metadata(lower: &str) -> bool {
    matches!(
        lower,
        "accept"
            | "accept-encoding"
            | "accept-language"
            | "accept-charset"
            | "dnt"
            | "priority"
            | "upgrade-insecure-requests"
    ) || lower.starts_with("sec-ch-")
        || lower.starts_with("sec-fetch-")
}

// ---------------------------------------------------------------------------
// Target parsing
// ---------------------------------------------------------------------------

/// Splits a request target into its path and its query string.
///
/// `/a/b?c=1` becomes `("/a/b", Some("c=1"))`. No decoding: the target is what was
/// sent, and a caller that wants the decoded form asks for it.
pub fn split_target(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

/// The `/`-separated segments of a path, without the leading empty one.
pub fn path_segments(path: &str) -> impl Iterator<Item = &str> {
    path.strip_prefix('/').unwrap_or(path).split('/')
}

/// The `name=value` pairs of a query string, in order and without collapsing
/// duplicates.
///
/// Duplicate parameter names are frequently the point of a test, so a repeated name
/// appears once per occurrence rather than being reduced to one.
pub fn query_pairs(query: Option<&str>) -> impl Iterator<Item = (&str, &str)> {
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
    use super::*;
    use crate::http::{Header, HttpRequest, HttpService};

    fn request(target: &str, headers: &[(&str, &str)]) -> HttpRequest {
        let mut request = HttpRequest::get(HttpService::new("api.example.com", 443, true), target);
        for (name, value) in headers {
            request.headers.append(Header::new(*name, *value));
        }
        request
    }

    // -----------------------------------------------------------------------
    // What a request takes
    // -----------------------------------------------------------------------

    #[test]
    fn every_query_parameter_is_an_input() {
        let found = inputs(&request("/search?q=shoes&page=2", &[]));
        assert_eq!(
            found,
            vec![
                ObjectLocation::Query {
                    name: "q".into(),
                    occurrence: 0
                },
                ObjectLocation::Query {
                    name: "page".into(),
                    occurrence: 0
                },
            ]
        );
    }

    #[test]
    fn a_repeated_parameter_is_addressed_once_per_occurrence() {
        // Duplicate parameters are frequently the point of a test. Collapsing them
        // would make the second one unreachable.
        let found = inputs(&request("/s?tag=a&tag=b", &[]));
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[1],
            ObjectLocation::Query {
                name: "tag".into(),
                occurrence: 1
            }
        );
    }

    #[test]
    fn a_credential_header_is_never_an_input() {
        // Rewriting one changes *who is asking* in the middle of a test about what
        // they may ask for.
        let found = inputs(&request(
            "/me",
            &[
                ("Authorization", "Bearer abc"),
                ("Cookie", "sessionid=abc"),
                ("X-Api-Key", "abc"),
                ("Referer", "https://app.example.com/"),
            ],
        ));
        let names: Vec<String> = found
            .iter()
            .filter_map(|location| match location {
                ObjectLocation::Header { name, .. } => Some(name.to_ascii_lowercase()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["referer".to_string()], "{names:?}");
    }

    #[test]
    fn a_header_that_decides_delivery_is_never_an_input() {
        // A marker in `Host` sends the request somewhere else; one in `Content-Length`
        // tests the framing. Neither asks the application anything.
        let found = inputs(&request(
            "/",
            &[
                ("Host", "api.example.com"),
                ("Content-Length", "0"),
                ("Transfer-Encoding", "chunked"),
                ("Connection", "keep-alive"),
                ("Content-Type", "application/json"),
                ("User-Agent", "curl/8"),
            ],
        ));
        let names: Vec<String> = found
            .iter()
            .filter_map(|location| match location {
                ObjectLocation::Header { name, .. } => Some(name.to_ascii_lowercase()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["user-agent".to_string()], "{names:?}");
    }

    #[test]
    fn a_path_segment_is_never_offered_as_an_input() {
        // `/api/v2/users/1000` has one input and three parts of a route, and nothing
        // about the characters says which. `hexora identifiers` answers that with
        // evidence; guessing here would undo it.
        let found = inputs(&request("/api/v2/users/1000", &[]));
        assert!(
            !found
                .iter()
                .any(|l| matches!(l, ObjectLocation::PathSegment { .. })),
            "{found:?}"
        );
    }

    #[test]
    fn a_request_with_nothing_to_probe_offers_nothing() {
        assert!(inputs(&request("/health", &[("Host", "api.example.com")])).is_empty());
    }

    // -----------------------------------------------------------------------
    // Placing a value a check generated
    // -----------------------------------------------------------------------

    #[test]
    fn a_probe_marker_goes_in_and_a_request_splitter_does_not() {
        // There is one substitution and it always validates. A marker carrying the
        // characters a reflection check needs passes; one carrying CR or LF does not,
        // because that value would split the request it is spliced into rather than
        // being carried by it.
        let request = request("/search?q=shoes", &[]);
        let location = ObjectLocation::Query {
            name: "q".into(),
            occurrence: 0,
        };

        let built = substitute(&request, &location, "hxa<\">hxb").unwrap();
        assert!(built.path.starts_with("/search?q="), "{}", built.path);
        // Sent as itself rather than percent-encoded. A query value may legally carry
        // these bytes, and encoding them would test the server's decoder instead of
        // what it does with the value once it has one.
        assert!(
            built.path.contains("hxa<\">hxb"),
            "the marker did not survive into the request: {}",
            built.path
        );

        for splitter in ["a\r\nX-Injected: 1", "a\nb", "a\0b"] {
            assert!(
                substitute(&request, &location, splitter).is_err(),
                "{splitter:?} was allowed into a request"
            );
        }
    }

    #[test]
    fn a_payload_substitution_changes_nothing_else_about_the_request() {
        let mut original = request("/search?q=shoes&page=2", &[("X-Trace", "abc")]);
        original.headers.append(Header::new("x-trace", "second"));
        let location = ObjectLocation::Query {
            name: "q".into(),
            occurrence: 0,
        };

        let built = substitute(&original, &location, "marker").unwrap();

        assert_eq!(built.path, "/search?q=marker&page=2");
        assert_eq!(built.headers.len(), original.headers.len());
        assert_eq!(built.headers.count("x-trace"), 2, "duplicates survive");
        assert_eq!(built.body, original.body);
        assert_eq!(built.method, original.method);
    }

    #[test]
    fn every_input_a_request_offers_can_actually_be_substituted() {
        // The two functions have to agree: an input nothing can be placed into would
        // be a slot a scheduler queues an experiment for and then fails on.
        let request = request(
            "/search?q=shoes&tag=a&tag=b",
            &[("User-Agent", "curl/8"), ("Referer", "https://x.example/")],
        );
        for location in inputs(&request) {
            let built = substitute(&request, &location, "marker")
                .unwrap_or_else(|e| panic!("{location:?} could not be substituted: {e}"));
            assert_eq!(
                value_at(&built, &location).as_deref(),
                Some("marker"),
                "{location:?} did not read back"
            );
        }
    }
}

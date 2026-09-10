//! Suggesting which values in captured traffic might be object identifiers.
//!
//! Declaring every identifier by hand is what keeps constructed testing narrower than
//! it should be, and the obvious shortcut — "it looks like a number, call it an id" —
//! is worse than the problem. `/api/v2/users/1000?page=3` has three numbers in it and
//! one identifier.
//!
//! # What actually distinguishes an identifier
//!
//! Not its shape. Its **variation in a fixed place**:
//!
//! ```text
//! GET /api/accounts/1000/invoices
//! GET /api/accounts/2000/invoices
//! GET /api/accounts/1000/profile
//!      ────┬──── ──┬─ ───┬───
//!       constant  varies  constant
//! ```
//!
//! Three segments are structure and one is data, and nothing about the characters says
//! which. So requests are grouped by *shape* — same method, same segments apart from
//! one — and the position that differs across an otherwise identical group is the
//! position worth asking about. Everything else in this module is a signal that raises
//! or lowers that suspicion.
//!
//! # Nothing here concludes anything
//!
//! This module reads. It never sends a request, never edits stored traffic, never
//! writes a finding, and above all never decides who owns anything. A suggestion says
//! *"this varies where an identifier would"*; whether it is an object, and whose, are
//! two further questions only a person can answer. See security invariant 10.
//!
//! # Known limitation
//!
//! A value found in a request body is offered as one suggestion for the whole body
//! rather than one per field, because a byte offset is a property of a single request
//! and cannot be the identity of a suggestion that spans many. The descriptor names
//! the field it was first seen in; two different fields carrying the same value are
//! offered once. Path and query candidates do not have this limitation.

use std::collections::{BTreeMap, BTreeSet};

use hexora_storage::repository::Limit;
use hexora_storage::{CandidateStore, ObjectStore, Suggested, TrafficStore};
use hexora_types::candidate::{IdentifierCandidate, Signal, SignalKind};
use hexora_types::ids::RequestId;
use hexora_types::object::ObjectLocation;
use hexora_types::redact::is_sensitive_header;
use hexora_types::Result;

/// Parameter names that usually mean paging rather than identity.
///
/// A page number varies between otherwise identical requests and sits under a
/// resource-like path — it earns every positive signal an identifier does. Only the
/// name gives it away, so the name is what counts against it.
const PAGING_NAMES: &[&str] = &[
    "page",
    "per_page",
    "perpage",
    "limit",
    "offset",
    "size",
    "count",
    "start",
    "skip",
    "take",
    "cursor",
    "sort",
    "order",
    "order_by",
    "direction",
    "format",
    "version",
    "v",
    "lang",
    "locale",
    "timestamp",
    "ts",
    "_",
];

/// The most suggestions one analysis will offer.
///
/// A review queue nobody can finish is one nobody starts. Traffic beyond this produces
/// the strongest candidates, and the caller is told the rest were not offered.
pub const MAX_SUGGESTIONS: usize = 200;

/// How many exchanges one analysis reads.
const MAX_EXCHANGES: u32 = 2_000;

/// What an analysis produced.
#[derive(Debug, Clone, Default)]
pub struct Suggestions {
    /// Suggestions the project had not seen before.
    pub created: usize,
    /// Suggestions whose signals were refreshed.
    pub refreshed: usize,
    /// Suggestions left alone because a human had already decided about them.
    pub reviewed: usize,
    /// How many exchanges were read.
    pub exchanges: usize,
    /// Candidates that scored but were dropped at [`MAX_SUGGESTIONS`].
    pub not_offered: usize,
}

impl Suggestions {
    /// How many suggestions reached the project.
    pub fn total(&self) -> usize {
        self.created + self.refreshed
    }
}

/// One sighting of a value in a particular place.
#[derive(Debug, Clone)]
struct Observation {
    /// Which comparable place this is — the key requests are grouped by.
    place: String,
    /// The value, exactly as it appeared. Never decoded.
    value: String,
    /// Where to address it in a request.
    location: ObjectLocation,
    /// How to describe that place to a person.
    descriptor: String,
    /// The exchange it came from.
    request: RequestId,
    /// The path segment before it, for the resource-like-path signal.
    preceding: Option<String>,
    /// The parameter or field name, where the place has one.
    name: Option<String>,
}

/// Reads a project's traffic and offers values that might be identifiers.
///
/// Sends nothing. Reads the traffic store, the declared objects and the existing
/// suggestions, and writes only suggestions.
pub fn analyze(
    traffic: &TrafficStore,
    objects: &ObjectStore,
    candidates: &CandidateStore,
) -> Result<Suggestions> {
    let mut result = Suggestions::default();

    let page = traffic.history(None, Limit::new(MAX_EXCHANGES))?;
    result.exchanges = page.items.len();

    let declared: BTreeSet<String> = objects
        .list()?
        .into_iter()
        .map(|declaration| declaration.value)
        .collect();

    let mut requests = Vec::with_capacity(page.items.len());
    let mut response_text: Vec<String> = Vec::new();
    for row in &page.items {
        requests.push(traffic.request(row.id)?);
        // Read once and kept as text: a value coming back in a response is a signal,
        // and re-reading every body per candidate would be quadratic.
        if let Ok(body) = traffic.response_body(row.id, false) {
            response_text.push(String::from_utf8_lossy(&body).into_owned());
        }
    }

    // Pass one: the path. Which position in which shape of request varies is the
    // question everything else depends on, including what a *query* place means —
    // `?page=` under `/accounts/1000/` and under `/accounts/2000/` is the same place,
    // and treating the literal path as the key would make every one of them unique
    // and therefore constant.
    let mut path_observations = Vec::new();
    for request in &requests {
        path_observations.extend(observe_path(request));
    }
    let varying = varying_places(&path_observations);

    // Pass two: everything addressed relative to a path, keyed on the template rather
    // than on the literal path.
    let mut observations = path_observations;
    for request in &requests {
        let template = template_for(request, &varying);
        observations.extend(observe_query(request, &template));
        observations.extend(observe_headers(request));
        observations.extend(observe_body(request, &template));
    }

    // Group by place to decide what varies...
    let mut places: BTreeMap<&str, Vec<&Observation>> = BTreeMap::new();
    for observation in &observations {
        places
            .entry(observation.place.as_str())
            .or_default()
            .push(observation);
    }

    let mut distinct_in_place: BTreeMap<&str, usize> = BTreeMap::new();
    let mut worth_offering: BTreeSet<String> = BTreeSet::new();
    for (place, seen) in &places {
        let distinct: BTreeSet<&str> = seen.iter().map(|o| o.value.as_str()).collect();
        // One value in a place is structure, not data: `/api/accounts` never varies,
        // and a position that never varies is part of the endpoint.
        if distinct.len() < 2 {
            continue;
        }
        // Variation only means something *relative to something constant*. A place
        // whose shape is nothing but the wildcard — `/status` against `/profile` —
        // has no endpoint holding still around it, so what varies is the endpoint
        // itself. Structural rather than a guess about the characters.
        if !holds_something_constant(place) {
            continue;
        }
        distinct_in_place.insert(place, distinct.len());
        worth_offering.extend(seen.iter().map(|o| candidate_key(o)));
    }

    // Group by *suggestion* — the value and where it sits, not which endpoint it sat
    // under — over every sighting rather than only the qualifying ones. Once a
    // position has been shown to carry data, the same value at the same position in
    // another endpoint is another sighting of the same thing, and "seen in 17
    // requests" is a fact about the project rather than about one shape of request.
    let mut by_candidate: BTreeMap<String, Vec<&Observation>> = BTreeMap::new();
    for observation in &observations {
        let key = candidate_key(observation);
        if worth_offering.contains(&key) {
            by_candidate.entry(key).or_default().push(observation);
        }
    }

    let mut scored: Vec<(IdentifierCandidate, Vec<RequestId>)> = Vec::new();
    for sightings in by_candidate.into_values() {
        let first = sightings[0];
        let distinct = sightings
            .iter()
            .filter_map(|o| distinct_in_place.get(o.place.as_str()))
            .copied()
            .max()
            .unwrap_or(2);

        let signals = signals_for(
            &first.value,
            first,
            sightings.len(),
            distinct,
            &declared,
            &response_text,
        );
        let mut candidate = IdentifierCandidate::new(
            first.value.clone(),
            first.location.clone(),
            first.descriptor.clone(),
            signals,
        );
        candidate.source_request = Some(first.request);
        candidate.occurrences = sightings.len() as u32;

        let seen_in: BTreeSet<RequestId> = sightings.iter().map(|o| o.request).collect();
        scored.push((candidate, seen_in.into_iter().collect()));
    }

    // Strongest first, so a truncated run offers the ones worth reviewing.
    scored.sort_by(|a, b| b.0.score.cmp(&a.0.score).then(a.0.value.cmp(&b.0.value)));
    if scored.len() > MAX_SUGGESTIONS {
        result.not_offered = scored.len() - MAX_SUGGESTIONS;
        scored.truncate(MAX_SUGGESTIONS);
    }

    for (candidate, requests) in scored {
        match candidates.record(&candidate, &requests)? {
            Suggested::Created(_) => result.created += 1,
            Suggested::Refreshed(_) => result.refreshed += 1,
            Suggested::Reviewed(_) => result.reviewed += 1,
        }
    }

    Ok(result)
}

/// Whether a place has anything constant in it for a value to vary against.
///
/// A path place is `path|METHOD|/a/{}/c`: at least one segment must be something
/// other than the wildcard. Query, header and body places are always anchored to a
/// name, so they qualify by construction.
fn holds_something_constant(place: &str) -> bool {
    let Some(shape) = place.strip_prefix("path|") else {
        return true;
    };
    let Some((_, path)) = shape.split_once('|') else {
        return true;
    };
    path.split('/')
        .any(|segment| !segment.is_empty() && segment != "{}")
}

/// What makes two sightings the same suggestion: the value, and where it sits.
fn candidate_key(observation: &Observation) -> String {
    format!("{}|{}", observation.value, observation.location.key())
}

/// The places where more than one value was seen.
fn varying_places(observations: &[Observation]) -> BTreeSet<String> {
    let mut seen: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for observation in observations {
        seen.entry(observation.place.as_str())
            .or_default()
            .insert(observation.value.as_str());
    }
    seen.into_iter()
        .filter(|(_, values)| values.len() > 1)
        .map(|(place, _)| place.to_string())
        .collect()
}

/// A request's path with its varying segments replaced by `{}`.
///
/// `/accounts/1000/invoices` and `/accounts/2000/invoices` both become
/// `/accounts/{}/invoices`, which is what makes a query parameter under them one place
/// rather than two.
fn template_for(request: &hexora_storage::StoredRequest, varying: &BTreeSet<String>) -> String {
    let path = path_of(request);
    let segments: Vec<&str> = path.strip_prefix('/').unwrap_or(path).split('/').collect();
    let rendered: Vec<&str> = segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            if varying.contains(&path_place(request, &segments, index)) {
                "{}"
            } else {
                *segment
            }
        })
        .collect();
    format!("/{}", rendered.join("/"))
}

/// A path with one position blanked out: `/accounts/{}`.
fn shape_of(segments: &[&str], index: usize) -> String {
    let rendered: Vec<&str> = segments
        .iter()
        .enumerate()
        .map(|(i, s)| if i == index { "{}" } else { *s })
        .collect();
    format!("/{}", rendered.join("/"))
}

/// The key that groups "this position, in this shape of request".
fn path_place(request: &hexora_storage::StoredRequest, segments: &[&str], index: usize) -> String {
    format!("path|{}|{}", request.method, shape_of(segments, index))
}

fn path_of(request: &hexora_storage::StoredRequest) -> &str {
    match request.path.split_once('?') {
        Some((path, _)) => path,
        None => request.path.as_str(),
    }
}

fn query_of(request: &hexora_storage::StoredRequest) -> Option<&str> {
    request.path.split_once('?').map(|(_, query)| query)
}

/// Every path segment of one request, with the place that groups it.
fn observe_path(request: &hexora_storage::StoredRequest) -> Vec<Observation> {
    let path = path_of(request);
    let segments: Vec<&str> = path.strip_prefix('/').unwrap_or(path).split('/').collect();

    segments
        .iter()
        .enumerate()
        .filter(|(_, segment)| !segment.is_empty())
        .map(|(index, segment)| Observation {
            place: path_place(request, &segments, index),
            value: (*segment).to_string(),
            location: ObjectLocation::PathSegment { index },
            // The index alone is not enough to tell two rows apart. `acct-1000` at
            // segment 1 of `/accounts/{}` and at segment 2 of `/secure/accounts/{}`
            // are two different things to test, and a list that shows both as
            // "path segment 1" and "path segment 2" makes the reader go and look.
            descriptor: format!("path segment {index} of {}", shape_of(&segments, index)),
            request: request.id,
            preceding: index
                .checked_sub(1)
                .and_then(|i| segments.get(i))
                .map(|s| (*s).to_string()),
            name: None,
        })
        .collect()
}

/// Query parameter values, keyed on the path *template* rather than the literal path.
fn observe_query(request: &hexora_storage::StoredRequest, template: &str) -> Vec<Observation> {
    let mut found = Vec::new();
    let mut seen_names: BTreeMap<String, usize> = BTreeMap::new();

    for (name, value) in query_pairs(query_of(request)) {
        let occurrence = seen_names.entry(name.to_string()).or_insert(0);
        if !value.is_empty() {
            found.push(Observation {
                place: format!("query|{}|{template}|{name}", request.method),
                value: value.to_string(),
                location: ObjectLocation::Query {
                    name: name.to_string(),
                    occurrence: *occurrence,
                },
                descriptor: format!("query parameter {name}"),
                request: request.id,
                preceding: None,
                name: Some(name.to_string()),
            });
        }
        *occurrence += 1;
    }
    found
}

/// Header values, narrowly.
///
/// Most headers carry no identifiers, and a credential is never one — it varies
/// between requests more reliably than anything else in them, which is exactly why the
/// filter is on the field name rather than on the behaviour.
fn observe_headers(request: &hexora_storage::StoredRequest) -> Vec<Observation> {
    let mut found = Vec::new();
    let mut header_names: BTreeMap<String, usize> = BTreeMap::new();

    for line in String::from_utf8_lossy(&request.headers_raw)
        .split("\r\n")
        .flat_map(|l| l.split(LF))
    {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        let occurrence = header_names.entry(name.to_ascii_lowercase()).or_insert(0);
        if !is_sensitive_header(name) && names_an_identifier(name) && !value.is_empty() {
            found.push(Observation {
                place: format!("header|{}", name.to_ascii_lowercase()),
                value: value.to_string(),
                location: ObjectLocation::Header {
                    name: name.to_string(),
                    occurrence: *occurrence,
                },
                descriptor: format!("header {name}"),
                request: request.id,
                preceding: None,
                name: Some(name.to_string()),
            });
        }
        *occurrence += 1;
    }
    found
}

const LF: char = '\n';

/// Values in a request body: JSON leaves and form fields.
///
/// The body is *read*, never rewritten. Values are taken as they appear in the bytes,
/// so a form field that is percent-encoded stays percent-encoded — a suggestion that
/// silently decoded it would propose a value the application never saw.
fn observe_body(request: &hexora_storage::StoredRequest, template: &str) -> Vec<Observation> {
    let mut found = Vec::new();
    if request.body.is_empty() {
        return found;
    }
    let Ok(text) = std::str::from_utf8(&request.body) else {
        // Not text. A binary body may well contain identifiers, and guessing where
        // they start and end is not something to do without a format to go on.
        return found;
    };

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        let mut leaves = Vec::new();
        collect_json(&value, String::new(), &mut leaves);
        for (pointer, leaf) in leaves {
            if leaf.is_empty() {
                continue;
            }
            let offset = text.find(&leaf).unwrap_or(0);
            found.push(Observation {
                place: format!("json|{}|{template}|{pointer}", request.method),
                value: leaf,
                // Addressed as a body range rather than a field: `ObjectLocation` has
                // no field variant, and inventing one would mean teaching the M12.5
                // substitution path to rewrite structured bodies — which is exactly
                // the JSON round trip that milestone refused to do.
                location: ObjectLocation::Anywhere,
                descriptor: format!("JSON field {pointer}"),
                request: request.id,
                preceding: None,
                name: Some(pointer),
            });
            let _ = offset;
        }
        return found;
    }

    // Form-encoded, judged by shape rather than by a Content-Type that may be absent.
    if text.contains('=') && !text.contains('\n') {
        for (name, value) in query_pairs(Some(text)) {
            if value.is_empty() {
                continue;
            }
            found.push(Observation {
                place: format!("form|{}|{template}|{name}", request.method),
                value: value.to_string(),
                location: ObjectLocation::Anywhere,
                descriptor: format!("form field {name}"),
                request: request.id,
                preceding: None,
                name: Some(name.to_string()),
            });
        }
    }
    found
}

/// The reasons a value was offered, and what each one counted for.
fn signals_for(
    value: &str,
    first: &Observation,
    sightings: usize,
    distinct: usize,
    declared: &BTreeSet<String>,
    responses: &[String],
) -> Vec<Signal> {
    let mut signals = vec![Signal {
        kind: SignalKind::VariesInPlace,
        weight: 12,
        detail: format!("{distinct} different values seen in this place"),
    }];

    if sightings > 1 {
        // Capped: something seen four hundred times is not four hundred times more
        // likely to be an identifier than something seen four times.
        let weight = (sightings as i32).min(6) * 2;
        signals.push(Signal {
            kind: SignalKind::Repeated,
            weight,
            detail: format!("seen in {sightings} requests"),
        });
    }

    if let Some(preceding) = &first.preceding {
        if names_a_collection(preceding) {
            signals.push(Signal {
                kind: SignalKind::ResourceLikePath,
                weight: 8,
                detail: format!("follows /{preceding}/ in the path"),
            });
        }
    }

    let echoes = responses.iter().filter(|body| body.contains(value)).count();
    if echoes > 0 {
        signals.push(Signal {
            kind: SignalKind::AppearsInResponse,
            weight: 5,
            detail: format!("came back in {echoes} responses"),
        });
    }

    if declared.contains(value) {
        signals.push(Signal {
            kind: SignalKind::MatchesDeclaredObject,
            weight: 15,
            detail: "already declared as an object elsewhere in this project".into(),
        });
    }

    if let Some(name) = &first.name {
        let leaf = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
        if PAGING_NAMES.contains(&leaf.as_str()) {
            signals.push(Signal {
                kind: SignalKind::CommonPaginationName,
                weight: -14,
                detail: format!("{leaf} usually means paging or formatting, not identity"),
            });
        }
    }

    // Weak evidence against, and only for the path: a plain lowercase word in a URL is
    // far more often an endpoint name than an object. Never evidence *for* anything —
    // nothing is suggested because it has digits in it.
    if matches!(first.location, ObjectLocation::PathSegment { .. }) && reads_like_a_word(value) {
        signals.push(Signal {
            kind: SignalKind::ReadsLikeAWord,
            weight: -10,
            detail: "a plain word in a path is usually an endpoint name".into(),
        });
    }

    if value.chars().count() <= 2 {
        signals.push(Signal {
            kind: SignalKind::VeryShort,
            weight: -4,
            detail: "short enough to be a flag or an enum".into(),
        });
    }

    signals
}

/// Whether a value reads as an English-ish word rather than an identifier.
fn reads_like_a_word(value: &str) -> bool {
    value.len() > 2
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '-' || c == '_')
        && !value.contains('-')
        && !value.contains('_')
}

/// Whether a header field name suggests it carries an identifier.
fn names_an_identifier(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("-id")
        || lower.ends_with("_id")
        || lower.ends_with("-ids")
        || lower.contains("-object")
        || lower.contains("tenant")
        || lower.contains("account")
}

/// Whether a path segment reads like a collection: `/accounts/1000`.
///
/// Deliberately crude — it is worth eight points, not a decision.
fn names_a_collection(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    lower.len() > 2
        && lower.ends_with('s')
        && lower
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c == '-' || c == '_')
}

fn query_pairs(query: Option<&str>) -> impl Iterator<Item = (&str, &str)> {
    query
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        })
}

/// Every scalar leaf in a JSON document, with its pointer.
fn collect_json(value: &serde_json::Value, pointer: String, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                collect_json(child, format!("{pointer}/{key}"), out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                collect_json(child, format!("{pointer}/{index}"), out);
            }
        }
        serde_json::Value::String(text) => {
            out.push((pointer.trim_start_matches('/').to_string(), text.clone()))
        }
        serde_json::Value::Number(number) => out.push((
            pointer.trim_start_matches('/').to_string(),
            number.to_string(),
        )),
        // A boolean or a null is not an identifier in any application.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hexora_storage::{
        CandidateFilter, CapturedExchange, MemoryBlobStore, Project, StoredRequest,
    };
    use hexora_types::candidate::{CandidateStatus, Strength};
    use hexora_types::http::{
        Header, Headers, HttpRequest, HttpResponse, HttpService, HttpVersion,
    };
    use hexora_types::identity::Identity;
    use hexora_types::object::ObjectDeclaration;

    use super::*;

    /// A project with a traffic store, and nothing that can reach a network.
    ///
    /// There is no transport in this module's tests at all, which is the point: the
    /// suggestion subsystem reads what has already been captured and cannot send.
    struct Fixture {
        project: Project,
        traffic: Arc<TrafficStore>,
    }

    fn fixture() -> Fixture {
        let project = Project::in_memory().unwrap();
        let traffic = Arc::new(TrafficStore::new(
            project.metadata().clone(),
            Arc::new(MemoryBlobStore::new()),
        ));
        Fixture { project, traffic }
    }

    impl Fixture {
        fn capture(&self, method: &str, target: &str, body: &str, response: &str) -> RequestId {
            let service = HttpService::new("api.example.com", 443, true);
            let mut request = HttpRequest::get(service, target);
            request.method = method.to_string();
            request.body = bytes::Bytes::copy_from_slice(body.as_bytes());
            self.record(request, response)
        }

        fn record(&self, request: HttpRequest, response: &str) -> RequestId {
            let mut headers = Headers::new();
            headers.set("Content-Type", "application/json");
            self.traffic
                .record(&CapturedExchange {
                    request,
                    raw_request: None,
                    response: HttpResponse {
                        status: 200,
                        reason: None,
                        version: HttpVersion::Http11,
                        headers,
                        body: bytes::Bytes::copy_from_slice(response.as_bytes()),
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
                .unwrap()
        }

        fn run(&self) -> Suggestions {
            analyze(
                &self.traffic,
                &self.project.objects(),
                &self.project.candidates(),
            )
            .unwrap()
        }

        fn suggestions(&self) -> Vec<IdentifierCandidate> {
            self.project
                .candidates()
                .list(&CandidateFilter::default())
                .unwrap()
        }

        fn suggestion(&self, value: &str) -> IdentifierCandidate {
            self.suggestions()
                .into_iter()
                .find(|c| c.value == value)
                .unwrap_or_else(|| panic!("no suggestion for {value:?}"))
        }
    }

    // -----------------------------------------------------------------------
    // What gets suggested, and what does not
    // -----------------------------------------------------------------------

    #[test]
    fn a_path_segment_that_varies_is_suggested_and_the_ones_that_do_not_are_left_alone() {
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/1000/invoices", "", "{}");
        fixture.capture("GET", "/api/accounts/2000/invoices", "", "{}");

        fixture.run();
        let offered: Vec<String> = fixture.suggestions().into_iter().map(|c| c.value).collect();

        assert!(offered.contains(&"1000".to_string()), "{offered:?}");
        assert!(offered.contains(&"2000".to_string()), "{offered:?}");
        // `api`, `accounts` and `invoices` never vary, so they are structure. This is
        // the whole difference between this and a "looks numeric" heuristic.
        assert!(!offered.contains(&"api".to_string()), "{offered:?}");
        assert!(!offered.contains(&"accounts".to_string()), "{offered:?}");
        assert!(!offered.contains(&"invoices".to_string()), "{offered:?}");
    }

    #[test]
    fn three_spellings_of_the_same_number_are_three_different_candidates() {
        // `1000`, `"1000"` and `%31%30%30%30` may all mean the same object to the
        // application, and a tool that normalised them would show the tester one row
        // and then replay a spelling the application never received. They are kept
        // apart, and any relationship between them is the tester's to assert.
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/1000", "", "{}");
        fixture.capture("GET", "/api/accounts/2000", "", "{}");
        fixture.capture("GET", "/api/accounts/%31%30%30%30", "", "{}");
        fixture.capture("POST", "/api/accounts?id=1000", r#"{"id":"1000"}"#, "{}");
        fixture.capture("POST", "/api/accounts?id=2000", r#"{"id":"2000"}"#, "{}");

        fixture.run();
        let offered: Vec<String> = fixture.suggestions().into_iter().map(|c| c.value).collect();

        assert!(offered.contains(&"1000".to_string()), "{offered:?}");
        assert!(
            offered.contains(&"%31%30%30%30".to_string()),
            "the percent-encoded spelling is preserved exactly: {offered:?}"
        );
        // The two spellings are separate rows, so a tester replaying one of them
        // replays the bytes the application actually received.
        assert_ne!(
            fixture.suggestion("1000").id,
            fixture.suggestion("%31%30%30%30").id
        );
    }

    #[test]
    fn the_same_value_in_two_different_places_is_two_candidates() {
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/1000/x", "", "{}");
        fixture.capture("GET", "/api/accounts/2000/x", "", "{}");
        fixture.capture("GET", "/api/search?owner=1000", "", "{}");
        fixture.capture("GET", "/api/search?owner=2000", "", "{}");

        fixture.run();
        let places: Vec<String> = fixture
            .suggestions()
            .into_iter()
            .filter(|c| c.value == "1000")
            .map(|c| c.descriptor)
            .collect();

        // Where a value sits is part of what it is: replaying it needs the place.
        assert!(
            places.iter().any(|d| d.contains("path segment")),
            "{places:?}"
        );
        assert!(places.iter().any(|d| d.contains("query")), "{places:?}");
    }

    proptest::proptest! {
        /// Whatever the bytes were, that is what is offered and where.
        ///
        /// The property that matters for replay: a candidate is a thing the tester will
        /// eventually put back into a request, so any transformation between observing
        /// it and storing it would produce a test of a value the application never saw.
        #[test]
        fn a_path_segment_is_offered_exactly_as_it_was_observed(
            first in "[A-Za-z0-9._~%!$&*+,;=:@-]{1,24}",
            second in "[A-Za-z0-9._~%!$&*+,;=:@-]{1,24}",
        ) {
            proptest::prop_assume!(first != second);

            let fixture = fixture();
            fixture.capture("GET", &format!("/api/accounts/{first}/invoices"), "", "{}");
            fixture.capture("GET", &format!("/api/accounts/{second}/invoices"), "", "{}");
            fixture.run();

            let offered = fixture.suggestions();
            let found = offered.iter().find(|c| c.value == first);
            proptest::prop_assert!(
                found.is_some(),
                "{first:?} not offered among {:?}",
                offered.iter().map(|c| &c.value).collect::<Vec<_>>()
            );
            proptest::prop_assert_eq!(
                found.unwrap().location.clone(),
                ObjectLocation::PathSegment { index: 2 }
            );
        }

        /// A suggestion never acquires an owner, whatever the traffic looked like.
        #[test]
        fn no_amount_of_traffic_produces_an_ownership_claim(
            values in proptest::collection::vec("[a-z0-9-]{1,12}", 2..6),
        ) {
            let fixture = fixture();
            for value in &values {
                fixture.capture("GET", &format!("/api/accounts/{value}"), "", "{}");
            }
            fixture.run();

            for candidate in fixture.suggestions() {
                let json = serde_json::to_string(&candidate).unwrap();
                proptest::prop_assert!(!json.contains("owner"), "{json}");
                proptest::prop_assert!(!json.contains("identity"), "{json}");
            }
        }
    }

    #[test]
    fn top_level_endpoint_names_are_not_suggested_as_identifiers() {
        // The failure this test exists for: `/status`, `/profile` and `/accounts/{id}`
        // all have *something* at segment 0, and those somethings differ. Variation
        // alone therefore "proves" that `status` is an identifier. It is not — nothing
        // is holding still around it, because the thing that varies is the endpoint.
        let fixture = fixture();
        fixture.capture("GET", "/status", "", "{}");
        fixture.capture("GET", "/profile", "", "{}");
        fixture.capture("GET", "/accounts/acct-1000", "", "{}");
        fixture.capture("GET", "/accounts/acct-2000", "", "{}");

        fixture.run();
        let offered: Vec<String> = fixture.suggestions().into_iter().map(|c| c.value).collect();

        assert!(offered.contains(&"acct-1000".to_string()), "{offered:?}");
        assert!(offered.contains(&"acct-2000".to_string()), "{offered:?}");
        assert!(!offered.contains(&"status".to_string()), "{offered:?}");
        assert!(!offered.contains(&"profile".to_string()), "{offered:?}");
        assert!(!offered.contains(&"accounts".to_string()), "{offered:?}");
    }

    #[test]
    fn a_word_in_a_path_argues_against_itself_without_ruling_itself_out() {
        // A word that varies where an endpoint is holding still is still offered — it
        // may well be a slug — but it is ranked below an id-shaped value, and the
        // reason is written down where a reviewer can disagree with it.
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/alice", "", "{}");
        fixture.capture("GET", "/api/accounts/bob", "", "{}");

        fixture.run();
        let alice = fixture.suggestion("alice");
        assert!(
            alice
                .signals
                .iter()
                .any(|s| s.kind == SignalKind::ReadsLikeAWord && s.weight < 0),
            "{:?}",
            alice.signals
        );
    }

    #[test]
    fn a_number_that_never_varies_is_not_suggested() {
        // `/api/v2/...` has a number in it and it is not an identifier.
        let fixture = fixture();
        fixture.capture("GET", "/api/v2/accounts/1000", "", "{}");
        fixture.capture("GET", "/api/v2/accounts/2000", "", "{}");

        fixture.run();
        let offered: Vec<String> = fixture.suggestions().into_iter().map(|c| c.value).collect();
        assert!(!offered.contains(&"v2".to_string()), "{offered:?}");
        assert!(offered.contains(&"1000".to_string()), "{offered:?}");
    }

    #[test]
    fn a_query_parameter_that_varies_is_suggested() {
        let fixture = fixture();
        fixture.capture("GET", "/api/profile?user_id=1000", "", "{}");
        fixture.capture("GET", "/api/profile?user_id=2000", "", "{}");

        fixture.run();
        let candidate = fixture.suggestion("1000");
        assert_eq!(candidate.descriptor, "query parameter user_id");
        assert!(matches!(candidate.location, ObjectLocation::Query { .. }));
    }

    #[test]
    fn a_paging_parameter_is_talked_down_by_its_name() {
        let fixture = fixture();
        for page in ["1", "2", "3"] {
            fixture.capture(
                "GET",
                &format!("/api/accounts/1000/invoices?page={page}"),
                "",
                "{}",
            );
        }
        for account in ["1000", "2000"] {
            fixture.capture(
                "GET",
                &format!("/api/accounts/{account}/invoices?page=1"),
                "",
                "{}",
            );
        }

        fixture.run();
        let account = fixture.suggestion("2000");
        let page = fixture.suggestion("3");

        assert!(
            account.score > page.score,
            "an account id must outrank a page number: {} vs {}",
            account.score,
            page.score
        );
        assert!(page
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::CommonPaginationName));
        assert_eq!(page.strength(), Strength::Low);
    }

    #[test]
    fn a_json_field_that_varies_is_suggested_with_its_field_name() {
        let fixture = fixture();
        fixture.capture("POST", "/api/lookup", r#"{"accountId":"1000"}"#, "{}");
        fixture.capture("POST", "/api/lookup", r#"{"accountId":"2000"}"#, "{}");

        fixture.run();
        let candidate = fixture.suggestion("1000");
        assert!(
            candidate.descriptor.contains("accountId"),
            "{}",
            candidate.descriptor
        );
    }

    #[test]
    fn a_form_field_that_varies_is_suggested() {
        let fixture = fixture();
        fixture.capture("POST", "/api/lookup", "account=1000&action=view", "{}");
        fixture.capture("POST", "/api/lookup", "account=2000&action=view", "{}");

        fixture.run();
        let candidate = fixture.suggestion("1000");
        assert!(
            candidate.descriptor.contains("form field account"),
            "{}",
            candidate.descriptor
        );
        // `action` is the same in both, so it is not offered.
        assert!(fixture.suggestions().iter().all(|c| c.value != "view"));
    }

    #[test]
    fn a_credential_header_is_never_suggested_as_an_identifier() {
        // It varies between requests more reliably than anything else in them, which
        // is exactly why the filter is on the field name rather than on the behaviour.
        let fixture = fixture();
        for token in ["TOKEN_A", "TOKEN_B"] {
            let service = HttpService::new("api.example.com", 443, true);
            let mut request = HttpRequest::get(service, "/api/profile");
            request
                .headers
                .set("Authorization", format!("Bearer {token}"));
            request.headers.set("Cookie", format!("session={token}"));
            fixture.record(request, "{}");
        }

        fixture.run();
        let offered: Vec<String> = fixture.suggestions().into_iter().map(|c| c.value).collect();
        assert!(
            offered.iter().all(|v| !v.contains("TOKEN")),
            "a credential is not an object identifier: {offered:?}"
        );
    }

    #[test]
    fn an_identifier_looking_header_is_suggested() {
        let fixture = fixture();
        for tenant in ["acme", "globex"] {
            let service = HttpService::new("api.example.com", 443, true);
            let mut request = HttpRequest::get(service, "/api/profile");
            request.headers.append(Header::new("X-Tenant-Id", tenant));
            fixture.record(request, "{}");
        }

        fixture.run();
        let candidate = fixture.suggestion("acme");
        assert_eq!(candidate.descriptor, "header X-Tenant-Id");
    }

    // -----------------------------------------------------------------------
    // Exactness
    // -----------------------------------------------------------------------

    #[test]
    fn an_encoded_value_stays_encoded_and_is_its_own_suggestion() {
        // `%31%30%30%30` and `1000` are different strings on the wire, an application
        // may accept one and refuse the other, and which it accepts is sometimes the
        // finding. Nothing here decodes anything.
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/1000/invoices", "", "{}");
        fixture.capture("GET", "/api/accounts/%31%30%30%30/invoices", "", "{}");
        fixture.capture("GET", "/api/accounts/2000/invoices", "", "{}");

        fixture.run();
        let offered: Vec<String> = fixture.suggestions().into_iter().map(|c| c.value).collect();
        assert!(offered.contains(&"1000".to_string()), "{offered:?}");
        assert!(
            offered.contains(&"%31%30%30%30".to_string()),
            "the encoded form is preserved exactly: {offered:?}"
        );
    }

    #[test]
    fn the_same_value_in_two_places_is_two_suggestions() {
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/1000/invoices?owner=1000", "", "{}");
        fixture.capture("GET", "/api/accounts/2000/invoices?owner=2000", "", "{}");

        fixture.run();
        let for_1000: Vec<IdentifierCandidate> = fixture
            .suggestions()
            .into_iter()
            .filter(|c| c.value == "1000")
            .collect();

        assert_eq!(for_1000.len(), 2, "one for the path, one for the query");
        let descriptors: Vec<&str> = for_1000.iter().map(|c| c.descriptor.as_str()).collect();
        assert!(descriptors.iter().any(|d| d.starts_with("path segment")));
        assert!(descriptors.iter().any(|d| d.starts_with("query parameter")));
    }

    // -----------------------------------------------------------------------
    // Signals, and being able to argue with them
    // -----------------------------------------------------------------------

    #[test]
    fn every_suggestion_can_say_why_it_was_suggested() {
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/1000/invoices", "", r#"{"id":"1000"}"#);
        fixture.capture("GET", "/api/accounts/1000/profile", "", r#"{"id":"1000"}"#);
        fixture.capture("GET", "/api/accounts/2000/invoices", "", "{}");

        fixture.run();
        let candidate = fixture.suggestion("1000");

        let kinds: Vec<SignalKind> = candidate.signals.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&SignalKind::VariesInPlace));
        assert!(kinds.contains(&SignalKind::Repeated));
        assert!(kinds.contains(&SignalKind::ResourceLikePath));
        assert!(kinds.contains(&SignalKind::AppearsInResponse));

        // The score is the arithmetic, not a number beside it.
        let sum: i32 = candidate.signals.iter().map(|s| s.weight).sum();
        assert_eq!(candidate.score, sum);
        // And every reason says what it saw, so it can be argued with.
        assert!(candidate.signals.iter().all(|s| !s.detail.is_empty()));
    }

    #[test]
    fn a_value_already_declared_as_an_object_is_the_strongest_signal() {
        let fixture = fixture();
        let identity = Identity::bearer("User A", "t");
        fixture.project.identities().put(&identity).unwrap();
        fixture
            .project
            .objects()
            .put(
                &ObjectDeclaration::new(
                    "account",
                    "1000",
                    identity.id,
                    ObjectLocation::PathSegment { index: 2 },
                )
                .unwrap(),
            )
            .unwrap();

        fixture.capture("GET", "/api/accounts/1000/invoices", "", "{}");
        fixture.capture("GET", "/api/accounts/2000/invoices", "", "{}");
        fixture.run();

        let declared = fixture.suggestion("1000");
        assert!(declared
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::MatchesDeclaredObject));
        assert!(declared.score > fixture.suggestion("2000").score);
    }

    // -----------------------------------------------------------------------
    // The line this milestone must not cross
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_never_infers_an_owner() {
        let fixture = fixture();
        let identity = Identity::bearer("User A", "t");
        fixture.project.identities().put(&identity).unwrap();

        fixture.capture("GET", "/api/accounts/1000/invoices", "", "{}");
        fixture.capture("GET", "/api/accounts/2000/invoices", "", "{}");
        fixture.run();

        // Suggestions exist...
        assert!(!fixture.suggestions().is_empty());
        // ...and not one object declaration was created by analysis. Ownership is a
        // human's assertion, and a suggestion that quietly became one would put a
        // fabricated premise underneath every finding built on it.
        assert_eq!(fixture.project.objects().count().unwrap(), 0);

        let json = serde_json::to_string(&fixture.suggestion("1000")).unwrap();
        assert!(!json.contains("owner"), "{json}");
        assert!(!json.contains(&identity.id.to_string()), "{json}");
    }

    #[test]
    fn analysis_never_writes_a_finding() {
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/1000/invoices", "", "{}");
        fixture.capture("GET", "/api/accounts/2000/invoices", "", "{}");
        fixture.run();
        assert_eq!(fixture.project.findings().count().unwrap(), 0);
    }

    #[test]
    fn analysis_never_modifies_the_traffic_it_read() {
        let fixture = fixture();
        let id = fixture.capture("GET", "/api/accounts/1000/invoices?x=%2F", "body", "{}");
        fixture.capture("GET", "/api/accounts/2000/invoices?x=%2F", "body", "{}");

        let before: StoredRequest = fixture.traffic.request(id).unwrap();
        fixture.run();
        let after = fixture.traffic.request(id).unwrap();

        assert_eq!(before.path, after.path);
        assert_eq!(before.body, after.body);
        assert_eq!(before.headers_raw, after.headers_raw);
        assert_eq!(fixture.traffic.count().unwrap(), 2, "and none was added");
    }

    // -----------------------------------------------------------------------
    // Living with the queue
    // -----------------------------------------------------------------------

    #[test]
    fn running_analysis_twice_refreshes_rather_than_duplicating() {
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/1000/invoices", "", "{}");
        fixture.capture("GET", "/api/accounts/2000/invoices", "", "{}");

        let first = fixture.run();
        let count = fixture.project.candidates().count().unwrap();
        assert!(first.created > 0);

        let second = fixture.run();
        assert_eq!(second.created, 0);
        assert!(second.refreshed > 0);
        assert_eq!(fixture.project.candidates().count().unwrap(), count);
    }

    #[test]
    fn a_reviewed_suggestion_is_not_resurrected_by_a_later_run() {
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/1000/invoices", "", "{}");
        fixture.capture("GET", "/api/accounts/2000/invoices", "", "{}");
        fixture.run();

        let rejected = fixture.suggestion("2000");
        fixture
            .project
            .candidates()
            .set_status(rejected.id, CandidateStatus::Rejected)
            .unwrap();

        let again = fixture.run();
        assert!(again.reviewed > 0);
        assert_eq!(
            fixture
                .project
                .candidates()
                .get(rejected.id)
                .unwrap()
                .status,
            CandidateStatus::Rejected,
            "a queue that undoes human decisions is one nobody works through"
        );
    }

    #[test]
    fn suggestions_survive_the_project_being_closed_and_reopened() {
        // The reason they are persisted at all: traffic is captured on Monday and
        // reviewed on Tuesday.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");

        let value = {
            let project = Project::open(&path).unwrap();
            let traffic = Arc::new(project.traffic());
            let fixture = Fixture { project, traffic };
            fixture.capture("GET", "/api/accounts/1000/invoices", "", "{}");
            fixture.capture("GET", "/api/accounts/2000/invoices", "", "{}");
            fixture.run();

            let candidate = fixture.suggestion("1000");
            fixture
                .project
                .candidates()
                .set_status(candidate.id, CandidateStatus::Accepted)
                .unwrap();
            candidate.value
        };

        let reopened = Project::open(&path).unwrap();
        let accepted = reopened
            .candidates()
            .list(&CandidateFilter {
                status: Some(CandidateStatus::Accepted),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].value, value);
        assert!(
            !accepted[0].signals.is_empty(),
            "and its reasons came back too"
        );
    }

    #[test]
    fn a_suggestion_whose_traffic_was_pruned_says_so_rather_than_going_quiet() {
        let fixture = fixture();
        let first = fixture.capture("GET", "/api/accounts/1000/invoices", "", "{}");
        fixture.capture("GET", "/api/accounts/1000/profile", "", "{}");
        fixture.capture("GET", "/api/accounts/2000/invoices", "", "{}");
        fixture.run();

        let before = fixture.suggestion("1000");
        assert_eq!(before.occurrences, 2);
        assert_eq!(before.live_observations, 2);
        assert!(!before.has_missing_traffic());

        // Traffic goes; the reviewed decision and the count of what analysis saw stay.
        fixture
            .project
            .metadata()
            .connection()
            .unwrap()
            .execute(
                "DELETE FROM requests WHERE id = ?1",
                hexora_storage::rusqlite::params![first.to_string()],
            )
            .unwrap();

        let after = fixture.project.candidates().get(before.id).unwrap();
        assert_eq!(after.occurrences, 2, "what analysis saw does not change");
        assert_eq!(after.live_observations, 1, "what can still be shown does");
        assert!(after.has_missing_traffic());
    }

    #[test]
    fn a_project_with_no_traffic_offers_nothing_and_says_so() {
        let fixture = fixture();
        let result = fixture.run();
        assert_eq!(result.total(), 0);
        assert_eq!(result.exchanges, 0);
        assert!(fixture.suggestions().is_empty());
    }

    #[test]
    fn one_request_alone_suggests_nothing() {
        // Nothing varies, so nothing is distinguishable from structure. A tool that
        // guessed from a single request would be guessing from its shape.
        let fixture = fixture();
        fixture.capture("GET", "/api/accounts/1000/invoices", "", "{}");
        let result = fixture.run();
        assert_eq!(result.total(), 0);
    }
}

//! Running every passive check over a project's traffic.
//!
//! # It takes no transport
//!
//! ```ignore
//! pub fn scan(project: &Project, selection: &Selection) -> Result<Summary>
//! ```
//!
//! That signature is the invariant. There is no `HttpTransport` here, no
//! [`Lab`](hexora_verify::Lab), and nothing in a [`Project`](hexora_storage::Project)
//! that can reach a network — so "the passive scanner makes no requests" is not a
//! rule anybody keeps, it is a property of what the function was given. A test that
//! mocked a transport would be testing a parameter that does not exist.
//!
//! # Scope
//!
//! The proxy records everything it sees, because it has to see a host before anybody
//! can decide whether it is in bounds. A project therefore contains the tester's own
//! browsing, and analysing it would mean producing observations about systems nobody
//! is authorized to test.
//!
//! So a scan reads **in-scope traffic only** by default, counts what it skipped, and
//! says so. `--everything` is available and says what it is doing.
//!
//! # Deduplication
//!
//! Five hundred endpoints on one host missing the same header is one thing to fix.
//! Observations are grouped by [`Observation::fingerprint`] — detector, host,
//! condition, location — and each group becomes one finding citing up to
//! [`EVIDENCE_PER_GROUP`] exchanges, with a count of how many it was seen in.
//!
//! The grouping is coarse and the evidence is not: the exact exchange is still there
//! to open, which is the whole point of the fingerprint being built from a condition
//! rather than from a URL.

use std::collections::BTreeMap;

use hexora_storage::repository::{Cursor, Limit};
use hexora_storage::{DetectorRun, Project, RunStatus, ScanRun};
use hexora_types::finding::{Evidence, Hypothesis};
use hexora_types::http::Headers;
use hexora_types::ids::{RequestId, ScanRunId, TargetId};
use hexora_types::programme::Programme;
use hexora_types::verify::{Observation, Verification, Verified};
use hexora_types::Result;

use crate::checks;
use crate::{
    redacted_request_headers, redacted_response_headers, Exchange, PassiveCheck, CREDENTIAL_HEADERS,
};

/// How many exchanges one grouped observation cites.
///
/// Three is enough to show a pattern is a pattern and few enough that a report does
/// not become a list of URLs.
pub const EVIDENCE_PER_GROUP: usize = 3;

/// How many exchanges one pass will read before stopping and saying so.
///
/// A ceiling rather than a target: the run record says how many were read and how
/// many were skipped, so a truncated pass is visible rather than silent.
pub const MAX_EXCHANGES: u32 = 20_000;

/// What a run was asked to look at.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    /// Only this host.
    pub host: Option<String>,
    /// Only this detector, by id.
    pub detector: Option<String>,
    /// Only traffic captured at or after this RFC 3339 instant.
    pub since: Option<String>,
    /// Stop after this many exchanges.
    pub limit: Option<u32>,
    /// Read out-of-scope traffic too.
    ///
    /// Off by default. A project holds whatever the proxy saw, including the
    /// tester's own browsing, and reporting on systems nobody declared is not a
    /// service to anybody.
    pub everything: bool,
}

impl Selection {
    /// How the selection reads in a run record.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        match &self.host {
            Some(host) => parts.push(format!("host={host}")),
            None => parts.push("all in-scope hosts".into()),
        }
        if let Some(detector) = &self.detector {
            parts.push(format!("detector={detector}"));
        }
        if let Some(since) = &self.since {
            parts.push(format!("since={since}"));
        }
        if let Some(limit) = self.limit {
            parts.push(format!("limit={limit}"));
        }
        if self.everything {
            parts.push("including out-of-scope traffic".into());
        }
        parts.join(", ")
    }
}

/// One grouped observation and the finding it became, if it became one.
#[derive(Debug, Clone)]
pub struct Grouped {
    /// The observation, as first seen.
    pub observation: Observation,
    /// How many exchanges showed it.
    pub occurrences: u32,
    /// Up to [`EVIDENCE_PER_GROUP`] of them, for a reader to open.
    pub exchanges: Vec<RequestId>,
    /// The host it is about.
    pub host: String,
    /// The exchange it was first seen on, kept for building the writeup.
    ///
    /// Held rather than re-read: looking one up by id afterwards meant a pass over
    /// the history per group, which is a full table scan per finding. An exchange is
    /// headers and metadata — no bodies — so keeping one per distinct observation
    /// costs little and the number of distinct observations is what the grouping
    /// exists to keep small.
    first: Exchange,
    /// The finding, when the observation was reportable.
    pub finding: Option<Verified>,
}

/// What a pass produced.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    /// The run, as recorded.
    pub run: Option<ScanRun>,
    /// Exchanges examined.
    pub exchanges_read: u64,
    /// Exchanges deliberately not examined.
    pub exchanges_skipped: u64,
    /// Grouped observations, worst first.
    pub observations: Vec<Grouped>,
    /// Suspicions raised, which stop here.
    pub hypotheses: Vec<Hypothesis>,
    /// One exchange per distinct endpoint the pass examined.
    ///
    /// Bounded by the number of distinct `(method, path)` pairs rather than by the
    /// number of exchanges, so a search page loaded forty times contributes one. It is
    /// what an active run needs in order to know what there is to probe, and computing
    /// it here means the active run tests exactly the traffic the passive pass
    /// reported on rather than a second, differently-filtered set.
    ///
    /// **Traffic Hexora generated is left out**, whichever subsystem generated it.
    ///
    /// A project accumulates the tool's own requests: probes from the scanner, replays
    /// from the authorization matrix. Reading those back as though they were the
    /// application's traffic goes wrong in two ways, and both have happened:
    ///
    /// * an endpoint described by a probe is reported as `?q=hxa3f9<>"';()hxb1k2` — a
    ///   URL nobody's application has, named in a finding about that application;
    /// * an endpoint described by an *anonymous* authorization replay carries no
    ///   credential, so every check that needs authenticated traffic silently stops
    ///   raising work for it after the first run.
    ///
    /// The line is [`Origin::is_automated`](hexora_engine::transport::Origin) draws:
    /// the proxy and the repeater are a person doing something, everything else is
    /// Hexora doing something.
    pub endpoints: Vec<Exchange>,
    /// What each detector did, including the ones that found nothing.
    pub detectors: Vec<DetectorRun>,
    /// The programme's terms, as they stood when the pass ran.
    ///
    /// Carried on the summary rather than looked up again by whoever prints it: the
    /// reasons a reader is shown must be the reasons that were actually applied, and a
    /// second read could return a profile somebody edited in between.
    pub programme: Programme,
}

impl Summary {
    /// The findings, dropping observations that were context rather than issues.
    pub fn findings(&self) -> Vec<&Verified> {
        self.observations
            .iter()
            .filter_map(|group| group.finding.as_ref())
            .collect()
    }

    /// How many observations were worth reporting.
    pub fn reportable(&self) -> usize {
        self.observations
            .iter()
            .filter(|group| group.observation.is_reportable())
            .count()
    }
}

/// Reads a project's traffic and says what the checks saw.
///
/// Takes a project and a selection. No transport, no lab, nothing that sends.
pub fn scan(project: &Project, selection: &Selection) -> Result<Summary> {
    let started_at = chrono::Utc::now();
    let traffic = project.traffic();
    let scope = project.settings().scope()?;
    // Read once, at the start. Every exclusion a reader is shown is one that was
    // actually applied to this pass.
    let programme = project.settings().programme()?;

    let checks: Vec<Box<dyn PassiveCheck>> = checks::all()
        .into_iter()
        .filter(|check| match &selection.detector {
            Some(wanted) => check.about().id.0 == wanted,
            None => true,
        })
        .collect();

    let mut counts: BTreeMap<String, DetectorRun> = checks
        .iter()
        .map(|check| {
            let info = check.about();
            (
                info.id.to_string(),
                DetectorRun {
                    detector: info.id.to_string(),
                    version: info.version.to_string(),
                    mode: info.mode,
                    observations: 0,
                    hypotheses: 0,
                    reportable: 0,
                    excluded: programme
                        .excluded(&info.id.to_string())
                        .map(|exclusion| exclusion.reason.clone()),
                },
            )
        })
        .collect();

    let mut groups: BTreeMap<String, Grouped> = BTreeMap::new();
    let mut hypotheses = Vec::new();
    let mut endpoints: BTreeMap<(String, String), Exchange> = BTreeMap::new();
    // One key per (check, endpoint, claim) already raised.
    let mut raised: std::collections::BTreeSet<(String, String, String)> =
        std::collections::BTreeSet::new();
    let mut read = 0u64;
    let mut skipped = 0u64;
    let ceiling = selection.limit.unwrap_or(MAX_EXCHANGES).min(MAX_EXCHANGES);

    let mut cursor: Option<Cursor> = None;
    'pages: loop {
        let page = traffic.history(cursor.as_ref(), Limit::new(Limit::MAX))?;
        let next = page.next.clone();

        for row in page.items {
            if read >= ceiling as u64 {
                skipped += 1;
                continue;
            }
            if !wanted(&row, selection, &scope) {
                skipped += 1;
                continue;
            }

            let Some(exchange) = assemble(project, &row)? else {
                // No response stored: there is nothing for a response check to look
                // at, and counting it as read would overstate what was examined.
                skipped += 1;
                continue;
            };
            read += 1;

            // Query strings differ between two loads of one page; the endpoint does
            // not. Keyed without the query so `?q=shoes` and `?q=hats` are one place.
            if human_driven(&exchange.origin) {
                let endpoint = exchange
                    .path
                    .split('?')
                    .next()
                    .unwrap_or(&exchange.path)
                    .to_string();
                // One exchange stands for the endpoint, and **an authenticated one
                // beats an anonymous one**.
                //
                // First-seen used to win, which against a real application meant a
                // cookie-only request shadowed the one carrying the session — same
                // method, same path, different credentials — and every cross-identity
                // experiment then reported "there is nobody to say whose session it
                // was" about an endpoint whose authenticated traffic was sitting in the
                // project two rows away.
                //
                // Presence of the header, not its value: what is held here is the
                // redacted view, and the value is nobody's business at this point.
                let key = (exchange.method.clone(), endpoint);
                match endpoints.entry(key) {
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert(exchange.clone());
                    }
                    std::collections::btree_map::Entry::Occupied(mut held) => {
                        if carries_a_session(&exchange) && !carries_a_session(held.get()) {
                            held.insert(exchange.clone());
                        }
                    }
                }
            }

            for check in &checks {
                let id = check.about().id.to_string();

                for observation in check.observe(&exchange) {
                    if let Some(entry) = counts.get_mut(&id) {
                        entry.observations += 1;
                        if observation.is_reportable() {
                            entry.reportable += 1;
                        }
                    }
                    let key = observation.fingerprint(&exchange.host);
                    match groups.get_mut(&key) {
                        Some(group) => {
                            group.occurrences += 1;
                            if group.exchanges.len() < EVIDENCE_PER_GROUP {
                                group.exchanges.push(exchange.id);
                            }
                        }
                        None => {
                            groups.insert(
                                key,
                                Grouped {
                                    observation,
                                    occurrences: 1,
                                    exchanges: vec![exchange.id],
                                    host: exchange.host.clone(),
                                    first: exchange.clone(),
                                    finding: None,
                                },
                            );
                        }
                    }
                }

                for hypothesis in check.suspect(&exchange) {
                    if let Some(entry) = counts.get_mut(&id) {
                        entry.hypotheses += 1;
                    }
                    // One suspicion per endpoint per check, not one per host.
                    //
                    // This used to collapse to one per host, on the reasoning that a
                    // scheduler would rather test a host than a URL. Building the
                    // scheduler showed that to be exactly wrong: two endpoints on one
                    // host routinely differ — a demo application with a reflecting
                    // `/reflect` and a correctly allowlisted `/allowed` produced one
                    // hypothesis, the active run tested whichever came first, and the
                    // real bug was never probed.
                    //
                    // The count is bounded by distinct endpoints rather than by
                    // exchanges, which is the number that matters, and the active
                    // scheduler shows the total and its request ceiling before it
                    // sends anything.
                    let key = (id.clone(), exchange.path.clone(), hypothesis.claim.clone());
                    if raised.insert(key) {
                        hypotheses.push(hypothesis);
                    }
                }
            }
        }

        match next {
            Some(next) => cursor = Some(next),
            None => break 'pages,
        }
    }

    // Findings, last, from the grouped observations rather than per exchange.
    let by_id: BTreeMap<String, &Box<dyn PassiveCheck>> = checks
        .iter()
        .map(|check| (check.about().id.to_string(), check))
        .collect();

    let mut observations: Vec<Grouped> = groups.into_values().collect();
    for group in &mut observations {
        if !group.observation.is_reportable() {
            continue;
        }
        let Some(check) = by_id.get(&group.observation.detector) else {
            continue;
        };
        // The one place a passive observation becomes a claim, and so the one place a
        // programme's terms can take effect without hiding anything. The observation
        // stays in the list with its evidence and its severity; what it does not become
        // is a finding in somebody's project. Hypotheses are untouched on purpose — an
        // exclusion for "CORS without proven impact" is a reason to run the experiment
        // that proves impact, not a reason to skip it.
        if programme.excluded(&group.observation.detector).is_some() {
            continue;
        }
        let exchange = group.first.clone();
        let target = exchange.target;
        group.finding = conclude(check.as_ref(), group, &exchange, target);
    }

    // Worst first, then by how widespread. A reader works down this list.
    observations.sort_by(|a, b| {
        a.observation
            .severity
            .rank()
            .cmp(&b.observation.severity.rank())
            .then(b.occurrences.cmp(&a.occurrences))
            .then(a.observation.about.cmp(&b.observation.about))
    });

    let run = ScanRun {
        id: ScanRunId::new(),
        selection: selection.describe(),
        started_at,
        completed_at: Some(chrono::Utc::now()),
        status: RunStatus::Completed,
        exchanges_read: read,
        exchanges_skipped: skipped,
        // Not a placeholder. A passive pass has no transport, so zero is the measured
        // truth rather than a value nobody filled in.
        requests_sent: 0,
        stopped_because: None,
        tool_version: hexora_types::VERSION.to_string(),
        detectors: counts.values().cloned().collect(),
    };
    project.scans().record(&run)?;

    Ok(Summary {
        programme,
        endpoints: endpoints.into_values().collect(),
        exchanges_read: read,
        exchanges_skipped: skipped,
        detectors: run.detectors.clone(),
        run: Some(run),
        observations,
        hypotheses,
    })
}

/// Whether this request was sent with something that authenticates it.
///
/// By header name. The scanner holds a redacted view, so the value is not available and
/// is not wanted: the question is which of two exchanges for one endpoint is the
/// authenticated one, and a name answers that.
fn carries_a_session(exchange: &Exchange) -> bool {
    exchange.request_headers.get("authorization").is_some()
}

/// Turns a grouped observation into a finding.
///
/// The one place a passive result becomes a claim, and it goes through the same door
/// everything else does: a [`Verification`], which for a fact that needs no
/// experiment is [`Verification::Observed`] — and whose ceiling is a lead.
///
/// The check does not get to choose this. It supplies prose; the verification is the
/// scanner's, identically for every observation, which is why no passive check can
/// state anything more firmly than any other.
fn conclude(
    check: &dyn PassiveCheck,
    group: &Grouped,
    exchange: &Exchange,
    target: TargetId,
) -> Option<Verified> {
    let seen = if group.occurrences > 1 {
        format!(
            "{} Seen on {} exchanges against {}.",
            group.observation.observed, group.occurrences, group.host
        )
    } else {
        group.observation.observed.clone()
    };

    let evidence: Vec<Evidence> = group
        .exchanges
        .iter()
        .map(|request| Evidence::Exchange {
            request: *request,
            response: None,
            note: format!(
                "{} — expected: {}",
                group.observation.observed, group.observation.expected
            ),
        })
        .collect();

    let verification = Verification::Observed {
        note: seen,
        evidence,
    };
    Verified::conclude(
        &as_hypothesis(&group.observation),
        &verification,
        check.writeup(&group.observation, exchange, target),
    )
}

/// The observation, in the shape `Verified::conclude` takes.
///
/// A small adapter rather than a second constructor: an observation and a hypothesis
/// answer different questions but a finding is completed the same way from either,
/// and having one door is the point of the door.
fn as_hypothesis(observation: &Observation) -> Hypothesis {
    Hypothesis {
        detector: observation.detector.clone(),
        claim: observation.about.clone(),
        source_request: observation.exchange,
        location: observation.location.clone(),
        provisional_severity: observation.severity,
    }
}

/// Whether an exchange is one this run was asked to look at.
fn wanted(
    row: &hexora_storage::StoredTraffic,
    selection: &Selection,
    scope: &hexora_types::scope::Scope,
) -> bool {
    let Some(host) = host_of(&row.url) else {
        return false;
    };

    if let Some(wanted) = &selection.host {
        if !host.eq_ignore_ascii_case(wanted) {
            return false;
        }
    }
    if let Some(since) = &selection.since {
        if row.sent_at.as_str() < since.as_str() {
            return false;
        }
    }
    if !selection.everything {
        let service = hexora_types::http::HttpService::new(
            host,
            port_of(&row.url).unwrap_or(if row.secure { 443 } else { 80 }),
            row.secure,
        );
        if !scope.contains(&service, path_of(&row.url)) {
            return false;
        }
    }
    true
}

/// Whether an exchange was made because a person did something.
///
/// The proxy saw a browser; the repeater sent what somebody typed. Everything else —
/// the scanner, the authorization matrix, a future fuzzer — is Hexora's own traffic,
/// and reading it back as the application's is how a tool starts reporting on itself.
///
/// Matched on the stored string rather than on
/// [`Origin`](hexora_engine::transport::Origin), because this crate deliberately does
/// not depend on the transport layer. An origin nobody recognises is treated as
/// Hexora's, which is the direction to be wrong in.
fn human_driven(origin: &str) -> bool {
    matches!(origin, "proxy" | "repeater")
}

/// Reads one stored exchange by id, into the shape a check sees.
///
/// The same assembly a pass uses, including the redaction — which is the reason this
/// exists rather than each caller reading the tables itself. An active check settles a
/// hypothesis a passive one raised, and it must not be handed the credential the
/// passive side was carefully not given.
///
/// `Ok(None)` means the project no longer holds a response for that request, which is
/// a normal answer and not an error: a hypothesis can outlive the traffic behind it.
pub fn exchange_at(project: &Project, request: RequestId) -> Result<Option<Exchange>> {
    let traffic = project.traffic();
    let Ok((status, _, _, response_headers)) = traffic.response_head(request) else {
        return Ok(None);
    };
    let stored = traffic.request(request)?;
    let raw_request_headers = Headers::from_block(&stored.headers_raw);
    let authenticated = raw_request_headers.iter().any(|header| {
        CREDENTIAL_HEADERS
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
    });

    Ok(Some(Exchange {
        id: request,
        target: traffic.target_of(request)?,
        host: stored.service.host.clone(),
        port: stored.service.port,
        secure: stored.service.secure,
        method: stored.method.clone(),
        url: format!("{}{}", stored.service.origin(), stored.path),
        path: stored.path.clone(),
        status,
        request_headers: redacted_request_headers(&raw_request_headers),
        response_headers: redacted_response_headers(&Headers::from_block(&response_headers)),
        // Not carried on the request row. Only the checks that ask "did this response
        // have content" use it, and none of them runs from this path today; stating a
        // zero it did not measure would be worse than the gap.
        response_bytes: 0,
        authenticated,
        tls: traffic.tls_of(request)?,
        sent_at: stored.sent_at.clone(),
        origin: stored.origin.clone(),
    }))
}

/// Reads one exchange into the shape a check sees.
fn assemble(project: &Project, row: &hexora_storage::StoredTraffic) -> Result<Option<Exchange>> {
    let traffic = project.traffic();
    let Ok((status, _, _, response_headers)) = traffic.response_head(row.id) else {
        return Ok(None);
    };
    let request = traffic.request(row.id)?;

    let raw_request_headers = Headers::from_block(&request.headers_raw);
    // Asked *before* redaction, because afterwards there is deliberately nothing
    // left to ask.
    let authenticated = raw_request_headers.iter().any(|header| {
        CREDENTIAL_HEADERS
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
    });

    Ok(Some(Exchange {
        id: row.id,
        target: row.target,
        host: request.service.host.clone(),
        port: request.service.port,
        secure: request.service.secure,
        method: row.method.clone(),
        url: row.url.clone(),
        path: request.path.clone(),
        status,
        request_headers: redacted_request_headers(&raw_request_headers),
        response_headers: redacted_response_headers(&Headers::from_block(&response_headers)),
        response_bytes: row.response_bytes,
        authenticated,
        tls: traffic.tls_of(row.id)?,
        sent_at: row.sent_at.clone(),
        origin: request.origin.clone(),
    }))
}

fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?']).next()?;
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority);
    (!host.is_empty()).then_some(host)
}

fn port_of(url: &str) -> Option<u16> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?']).next()?;
    authority.rsplit_once(':')?.1.parse().ok()
}

fn path_of(url: &str) -> &str {
    match url.split_once("://") {
        Some((_, rest)) => match rest.find('/') {
            Some(at) => &rest[at..],
            None => "/",
        },
        None => "/",
    }
}

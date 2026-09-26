//! # The frontier and the scoped fetch (CR.b)
//!
//! CR.a reads one captured response and reports the links in it, sending nothing. This
//! module is the part that turns those links into a crawl: a frontier of URLs to visit,
//! each fetched through the same [`ScopeGuard`] every other automated subsystem sends
//! through, each response fed back through [`extract`] to discover more, until the
//! frontier empties or a budget is spent.
//!
//! ## Nothing runs away
//!
//! Three bounds hold at once, and every one exists so that a crawl over a hostile or
//! generated site cannot turn into unbounded work or unbounded traffic:
//!
//! * a hard ceiling on how many requests are sent ([`CrawlBudget::max_requests`]),
//! * a maximum link depth from the seeds ([`CrawlBudget::max_depth`]), and
//! * a per-host fetch cap ([`CrawlBudget::max_per_host`]).
//!
//! A URL is visited at most once. A politeness pause separates fetches, and because the
//! loop is sequential there is only ever one request in flight — one host at a time, the
//! same discipline the active scheduler (M13.3) enforces.
//!
//! ## Scope is not a filter applied afterwards
//!
//! The crawl runs as [`Origin::Crawler`], an automated origin. Every candidate is put to
//! the guard *before* a socket is opened: an out-of-scope URL comes back
//! [`ScopeDecision::Refused`] and is **recorded, not fetched** — it appears in
//! [`CrawlReport::skipped`] so a tester can see what the site linked to without the
//! crawler ever having touched it. This module never opens a connection the guard did
//! not permit, and it is never a second way onto the network: it holds a `ScopeGuard`,
//! not a bare transport.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use hexora_engine::guard::ScopeGuard;
use hexora_engine::transport::{Exchange, HttpTransport, Origin, SendOptions};
use hexora_types::http::{HttpRequest, HttpService};

use crate::extract;

/// The bounds a crawl runs within. Defaults are deliberately modest: a crawl is a
/// convenience that widens coverage, not something that should surprise a tester with
/// its volume.
#[derive(Debug, Clone)]
pub struct CrawlBudget {
    /// The most requests the crawl will send, across all hosts. The crawl stops with
    /// [`CrawlStop::RequestCeiling`] once this many have gone out.
    pub max_requests: usize,
    /// The deepest a followed link may be from a seed. Seeds are depth 0; a link found
    /// on a seed is depth 1. Links deeper than this are recorded, not followed.
    pub max_depth: usize,
    /// The most requests sent to any one host.
    pub max_per_host: usize,
    /// How long to wait between fetches. Keeps the crawl from hammering a target.
    pub delay: Duration,
}

impl Default for CrawlBudget {
    fn default() -> Self {
        Self {
            max_requests: 500,
            max_depth: 8,
            max_per_host: 200,
            delay: Duration::from_millis(250),
        }
    }
}

/// Why a candidate was not fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Out of scope for an automated origin: the guard refused it.
    OutOfScope,
    /// Deeper than [`CrawlBudget::max_depth`].
    DepthLimit,
    /// Its host had already been fetched [`CrawlBudget::max_per_host`] times.
    PerHostLimit,
    /// It could not be parsed into a real `http(s)`/`ws(s)` URL.
    Unfetchable,
}

/// A URL the crawl discovered but chose not to follow, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The absolute URL, as discovered.
    pub url: String,
    /// Why it was not fetched.
    pub reason: SkipReason,
}

/// Why a crawl ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlStop {
    /// The frontier drained: everything reachable within the budget was visited.
    FrontierEmpty,
    /// [`CrawlBudget::max_requests`] was reached; there may be more to visit.
    RequestCeiling,
}

/// What a crawl did.
///
/// The fetched exchanges are returned rather than recorded here: this crate does not own
/// a project store, and recording is the caller's deliberate act (the same separation the
/// repeater keeps). The caller records [`Self::fetched`] so the scanner can work over what
/// the crawl found.
#[derive(Debug)]
pub struct CrawlReport {
    /// The exchanges the crawl completed, in the order they were fetched.
    pub fetched: Vec<Exchange>,
    /// URLs discovered but not followed, deduplicated by URL (first reason kept).
    pub skipped: Vec<Skipped>,
    /// Why the crawl stopped.
    pub stopped: CrawlStop,
}

/// One item waiting to be fetched: its request (already parsed and scope-approved) and
/// how deep it is from a seed.
struct Pending {
    request: HttpRequest,
    depth: usize,
}

/// Crawls from `seeds`, following in-scope links through `guard` until the frontier
/// empties or `budget` is spent.
///
/// `seeds` are absolute URLs — typically gathered from traffic already captured. Each is
/// put to the guard like any other candidate, so a seed that is out of scope is recorded,
/// not fetched.
pub async fn crawl<T, S, I>(guard: &ScopeGuard<T>, seeds: I, budget: &CrawlBudget) -> CrawlReport
where
    T: HttpTransport,
    S: Into<String>,
    I: IntoIterator<Item = S>,
{
    let options = SendOptions::automated(Origin::Crawler);

    let mut frontier: VecDeque<Pending> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut per_host: HashMap<String, usize> = HashMap::new();
    let mut fetched: Vec<Exchange> = Vec::new();
    let mut skipped: Vec<Skipped> = Vec::new();

    // Considers one candidate: dedup, parse, scope-check and depth-check it, and either
    // enqueue it or record why not. Kept as a closure over the mutable crawl state so both
    // the seeding pass and the per-response discovery pass go through exactly one policy.
    let consider =
        |url: String,
         depth: usize,
         frontier: &mut VecDeque<Pending>,
         visited: &mut HashSet<String>,
         skipped: &mut Vec<Skipped>| {
            if !visited.insert(url.clone()) {
                return;
            }
            let Ok((service, path)) = HttpService::parse_url(&url) else {
                skipped.push(Skipped {
                    url,
                    reason: SkipReason::Unfetchable,
                });
                return;
            };
            let request = HttpRequest::get(service, path);
            if !guard.decide(&request, &options).permits_sending() {
                skipped.push(Skipped {
                    url,
                    reason: SkipReason::OutOfScope,
                });
                return;
            }
            if depth > budget.max_depth {
                skipped.push(Skipped {
                    url,
                    reason: SkipReason::DepthLimit,
                });
                return;
            }
            frontier.push_back(Pending { request, depth });
        };

    for seed in seeds {
        consider(
            seed.into(),
            0,
            &mut frontier,
            &mut visited,
            &mut skipped,
        );
    }

    let stopped = loop {
        let Some(item) = frontier.pop_front() else {
            break CrawlStop::FrontierEmpty;
        };
        if fetched.len() >= budget.max_requests {
            break CrawlStop::RequestCeiling;
        }

        let host = item.request.service.host.clone();
        let count = per_host.entry(host).or_insert(0);
        if *count >= budget.max_per_host {
            skipped.push(Skipped {
                url: item.request.url(),
                reason: SkipReason::PerHostLimit,
            });
            continue;
        }
        *count += 1;

        let base_url = item.request.url();
        let child_depth = item.depth + 1;
        match guard.send(item.request, options.clone()).await {
            Ok(exchange) => {
                let content_type = exchange
                    .response
                    .headers
                    .get("content-type")
                    .map(|h| h.value_lossy().into_owned())
                    .unwrap_or_default();
                // Feed the response back through CR.a to discover the next ring of links.
                for link in extract(&base_url, &content_type, &exchange.response.body) {
                    consider(
                        link.url,
                        child_depth,
                        &mut frontier,
                        &mut visited,
                        &mut skipped,
                    );
                }
                fetched.push(exchange);
            }
            // A transport error on one URL is a coverage gap, not a reason to abandon the
            // crawl: the site map simply will not include what could not be fetched.
            Err(error) => {
                tracing::debug!(url = %base_url, %error, "crawl fetch failed");
            }
        }

        if !budget.delay.is_zero() {
            tokio::time::sleep(budget.delay).await;
        }
    };

    CrawlReport {
        fetched,
        skipped,
        stopped,
    }
}

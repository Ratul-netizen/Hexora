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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nullhawk_engine::guard::ScopeGuard;
use nullhawk_engine::transport::{Exchange, HttpTransport, Origin, SendOptions};
use nullhawk_types::http::{Header, HttpRequest, HttpService};
use nullhawk_types::identity::Identity;

use crate::robots::Robots;
use crate::{extract, LinkSource};

/// The product token the crawler identifies itself with — sent as `User-Agent` and
/// matched against `robots.txt` groups. A site that wants to steer or exclude Nullhawk's
/// crawl can name it.
pub const CRAWLER_USER_AGENT: &str = "Nullhawk";

/// Substrings in a request target that mark a link as likely state-changing. A crawl that
/// followed every link would log itself out or delete records; a link whose path or query
/// contains one of these is recorded, not followed, unless the tester opts in. The list is
/// deliberately conservative about *following* — over-recording a benign link is a coverage
/// note, following a destructive one is damage.
const DESTRUCTIVE_TOKENS: &[&str] = &[
    "logout",
    "log-out",
    "logoff",
    "signout",
    "sign-out",
    "delete",
    "remove",
    "destroy",
    "revoke",
    "deactivate",
    "unsubscribe",
    "purge",
    "terminate",
];

/// Whether a request target looks state-changing. Checked against the path and query only,
/// so a host named `delete.example.com` does not trip it.
fn looks_destructive(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    DESTRUCTIVE_TOKENS.iter().any(|t| lower.contains(t))
}

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
    /// A form action. A form is discovered, never auto-submitted — submitting is a
    /// deliberate act, like the intruder's.
    Form,
    /// Its target looks state-changing (`logout`, `delete`, `remove`…). Recorded so a
    /// tester can decide, never auto-followed.
    LooksDestructive,
    /// `robots.txt` asked crawlers to stay out of this path.
    RobotsDisallowed,
}

/// The safety controls a crawl runs under. Every default is the cautious one; a tester
/// relaxes them deliberately, and the report still records what was skipped so the choice
/// is visible either way.
#[derive(Debug, Clone)]
pub struct CrawlPolicy {
    /// Follow links whose target looks state-changing. Default `false`: record, don't follow.
    pub follow_destructive: bool,
    /// Ignore `robots.txt`. Default `false`: respect it.
    pub ignore_robots: bool,
}

impl Default for CrawlPolicy {
    // Spelled out rather than derived: that the default for each control is the *cautious*
    // one is the point, not an accident of `bool`'s default, and a reader should see it.
    #[allow(clippy::derivable_impls)]
    fn default() -> Self {
        Self {
            follow_destructive: false,
            ignore_robots: false,
        }
    }
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
    /// The cancel handle was set — a tester stopped the crawl. What had been fetched by
    /// then is in the report; the frontier may still have held work.
    Cancelled,
}

/// Stops a running crawl. Cloneable and thread-safe: take a handle before the crawl starts
/// (with [`Crawler::cancel_handle`]) and set it from a signal handler. The crawl checks it
/// before each fetch and stops with [`CrawlStop::Cancelled`], returning what it has — the
/// same promise the active scheduler's `Cancel` makes, so a stopped crawl still feeds the
/// project the pages it reached.
#[derive(Debug, Clone, Default)]
pub struct CrawlCancel(Arc<AtomicBool>);

impl CrawlCancel {
    /// A fresh, un-set handle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the crawl to stop before its next fetch.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether a stop has been requested.
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
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

/// A bounded, scope-checked crawl over a scope-guarded transport.
///
/// Built once and then run: the guard it holds is the only way it reaches the network, so
/// it is a *producer* under scope, never a second door onto it. Defaults are cautious —
/// a modest [`CrawlBudget`] and a [`CrawlPolicy`] that respects `robots.txt` and does not
/// follow destructive-looking links; the builder methods relax or tighten them.
///
/// ```no_run
/// # async fn f<T: nullhawk_engine::transport::HttpTransport>(guard: &nullhawk_engine::guard::ScopeGuard<T>) {
/// use nullhawk_crawl::Crawler;
/// let report = Crawler::new(guard).run(["https://example.test/"]).await;
/// # let _ = report;
/// # }
/// ```
pub struct Crawler<'a, T: HttpTransport> {
    guard: &'a ScopeGuard<T>,
    budget: CrawlBudget,
    policy: CrawlPolicy,
    attached: Vec<Header>,
    identity: Option<Identity>,
    cancel: CrawlCancel,
}

impl<'a, T: HttpTransport> Crawler<'a, T> {
    /// A crawler over `guard`, with the default budget and cautious policy, unauthenticated.
    pub fn new(guard: &'a ScopeGuard<T>) -> Self {
        Self {
            guard,
            budget: CrawlBudget::default(),
            policy: CrawlPolicy::default(),
            attached: Vec::new(),
            identity: None,
            cancel: CrawlCancel::new(),
        }
    }

    /// Sets the bounds the crawl runs within.
    pub fn budget(mut self, budget: CrawlBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Sets the safety policy (robots, destructive links).
    pub fn policy(mut self, policy: CrawlPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Headers the programme requires on every request (a research identifier, say),
    /// applied to each in-scope request exactly as the repeater applies them — in scope,
    /// attached; out of scope, never sent at all.
    pub fn attaching(mut self, headers: Vec<Header>) -> Self {
        self.attached = headers;
        self
    }

    /// Crawls as a declared identity: its credential authenticates every in-scope request,
    /// so the crawl reaches behind the login. The caller records each fetched page under
    /// this identity, which is what makes a crawl as User A and a crawl as User B two
    /// attributable maps rather than one.
    pub fn crawling_as(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// A handle that stops this crawl. Clone it before [`Self::run`] and set it from a
    /// signal handler to stop cleanly with what has been fetched so far.
    pub fn cancel_handle(&self) -> CrawlCancel {
        self.cancel.clone()
    }

    /// Crawls from `seeds`, following in-scope links until the frontier empties, the budget
    /// is spent, or the crawl is cancelled.
    ///
    /// `seeds` are absolute URLs — typically gathered from traffic already captured. Each is
    /// put to the guard like any other candidate, so a seed that is out of scope is
    /// recorded, not fetched. Seeds are the tester's explicit choice, so the destructive-link
    /// and form guards apply only to links the crawl *discovers*, not to what it was handed.
    pub async fn run<S, I>(&self, seeds: I) -> CrawlReport
    where
        S: Into<String>,
        I: IntoIterator<Item = S>,
    {
        let budget = &self.budget;
        let policy = &self.policy;
        let attached = &self.attached[..];
        let identity = self.identity.as_ref();
        let guard = self.guard;
        let options = SendOptions::automated(Origin::Crawler);

        let mut frontier: VecDeque<Pending> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut per_host: HashMap<String, usize> = HashMap::new();
        let mut robots_by_host: HashMap<String, Robots> = HashMap::new();
        let mut fetched: Vec<Exchange> = Vec::new();
        let mut skipped: Vec<Skipped> = Vec::new();

        // Considers one candidate: dedup, then run every check that can be made without
        // sending — scope, depth, and (for a *discovered* link) the form and destructive-link
        // guards — and either enqueue it or record why not. Kept as a closure over the crawl
        // state so the seeding pass and the per-response discovery pass share one policy.
        let consider = |url: String,
                        depth: usize,
                        source: Option<LinkSource>,
                        frontier: &mut VecDeque<Pending>,
                        visited: &mut HashSet<String>,
                        skipped: &mut Vec<Skipped>| {
            if !visited.insert(url.clone()) {
                return;
            }
            // A form is discovered, never auto-submitted — regardless of its method.
            if source == Some(LinkSource::FormAction) {
                skipped.push(Skipped {
                    url,
                    reason: SkipReason::Form,
                });
                return;
            }
            let Ok((service, path)) = HttpService::parse_url(&url) else {
                skipped.push(Skipped {
                    url,
                    reason: SkipReason::Unfetchable,
                });
                return;
            };
            // Discovered links are auto-followed, so the destructive-link guard applies to
            // them; a seed (no source) is the tester's own choice and is exempt.
            if source.is_some() && !policy.follow_destructive && looks_destructive(&path) {
                skipped.push(Skipped {
                    url,
                    reason: SkipReason::LooksDestructive,
                });
                return;
            }
            let mut request = HttpRequest::get(service, path);
            request.headers.set("User-Agent", CRAWLER_USER_AGENT);
            if !guard.decide(&request, &options).permits_sending() {
                skipped.push(Skipped {
                    url,
                    reason: SkipReason::OutOfScope,
                });
                return;
            }
            // In scope: attach the programme's headers, so this crawl's traffic carries
            // whatever marks it as authorized research. Done after the scope decision so a
            // refused request never has them applied — the repeater's discipline.
            for header in attached {
                request
                    .headers
                    .set(&header.name, header.value_lossy().into_owned());
            }
            // The identity's credential last, so it wins any collision with a programme
            // header — the credential decides who the request is from.
            if let Some(identity) = identity {
                identity.authenticate(&mut request.headers);
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
                None,
                &mut frontier,
                &mut visited,
                &mut skipped,
            );
        }

        let stopped = loop {
            // Checked before every fetch, so a cancelled crawl stops promptly and returns what
            // it has rather than abandoning it.
            if self.cancel.is_stopped() {
                break CrawlStop::Cancelled;
            }
            let Some(item) = frontier.pop_front() else {
                break CrawlStop::FrontierEmpty;
            };
            if fetched.len() >= budget.max_requests {
                break CrawlStop::RequestCeiling;
            }

            let service = item.request.service.clone();
            let host = service.host.clone();

            // Respect robots.txt by default: fetch it once per host (this fetch is overhead, so
            // it is not counted against the ceiling or the per-host cap), then honour it.
            if !policy.ignore_robots {
                if !robots_by_host.contains_key(&host) {
                    let robots = fetch_robots(guard, &service, &options, attached, identity).await;
                    robots_by_host.insert(host.clone(), robots);
                }
                if let Some(robots) = robots_by_host.get(&host) {
                    if !robots.allows(&item.request.path) {
                        skipped.push(Skipped {
                            url: item.request.url(),
                            reason: SkipReason::RobotsDisallowed,
                        });
                        continue;
                    }
                }
            }

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
                            Some(link.source),
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
}

/// Fetches and parses a host's `robots.txt`. Any failure — refused by scope, a network
/// error, a non-2xx — is treated as "no rules": absence is not prohibition.
async fn fetch_robots<T: HttpTransport>(
    guard: &ScopeGuard<T>,
    service: &HttpService,
    options: &SendOptions,
    attached: &[Header],
    identity: Option<&Identity>,
) -> Robots {
    let mut request = HttpRequest::get(service.clone(), "/robots.txt");
    request.headers.set("User-Agent", CRAWLER_USER_AGENT);
    if !guard.decide(&request, options).permits_sending() {
        return Robots::allow_all();
    }
    for header in attached {
        request
            .headers
            .set(&header.name, header.value_lossy().into_owned());
    }
    if let Some(identity) = identity {
        identity.authenticate(&mut request.headers);
    }
    match guard.send(request, options.clone()).await {
        Ok(exchange) if exchange.response.is_success() => {
            Robots::parse(&exchange.response.body, CRAWLER_USER_AGENT)
        }
        _ => Robots::allow_all(),
    }
}

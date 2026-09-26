//! `hexora crawl` — a bounded, scope-checked crawl that feeds the project.
//!
//! The crawler is a producer of automated traffic, so it obeys the same discipline as the
//! active scanner and is spelled out the same way:
//!
//! 1. Work out the seeds — the URLs to start from — which sends nothing.
//! 2. Print the plan: the seeds, the bounds, and the safety policy.
//! 3. Stop there on `--dry-run`. Nothing was sent.
//! 4. Ask, unless `--yes`. A non-interactive stdin answers *no*.
//! 5. Crawl, through the project's scope guard, and record every page it fetched.
//!
//! Seeds come from the traffic the project already holds — the in-scope URLs the proxy
//! captured — unless the tester names them with `--url`. Out-of-scope links are recorded
//! as found, never fetched; forms are discovered, never submitted; destructive-looking
//! links and `robots.txt` are respected by default. Ctrl-C stops the crawl before its next
//! request, and what it had fetched by then is still written into the project.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hexora_crawl::{CrawlBudget, CrawlPolicy, CrawlReport, CrawlStop, Crawler, SkipReason};
use hexora_engine::guard::ScopeGuard;
use hexora_engine::transport::{HttpTransport, Origin};
use hexora_http::{TcpTransport, TlsConfig};
use hexora_storage::repository::{Cursor, Limit};
use hexora_storage::{CapturedExchange, Project, TrafficStore};
use hexora_types::scope::Scope;
use hexora_types::{HexoraError, Result};

/// The most seed URLs gathered from captured traffic. A crawl that started from ten
/// thousand seeds would spend its budget before following a single link; past this the
/// seeds are the newest captured, and the crawl discovers the rest for itself.
const MAX_SEED_URLS: usize = 1000;

/// How many history rows to read per page while gathering seeds.
const SEED_PAGE: u32 = 500;

/// Options for `hexora crawl`.
pub struct Args {
    pub project: PathBuf,
    /// Explicit seed URLs. When present, captured traffic is not used for seeds.
    pub seeds: Vec<String>,
    /// Crawl as this identity (label or id), reaching behind the login.
    pub identity: Option<String>,
    pub max_requests: Option<usize>,
    pub max_depth: Option<usize>,
    pub max_per_host: Option<usize>,
    pub delay_ms: Option<u64>,
    /// Follow links that look state-changing (`logout`, `delete`…).
    pub follow_destructive: bool,
    /// Ignore `robots.txt`.
    pub ignore_robots: bool,
    /// Work out the plan and send nothing.
    pub dry_run: bool,
    /// Do not ask before sending.
    pub yes: bool,
    /// Do not verify the target's TLS certificate.
    pub insecure: bool,
    /// Do not write the fetched pages into the project.
    pub no_save: bool,
    pub json: bool,
}

/// Runs a bounded crawl and records what it fetched.
pub fn run(args: Args) -> Result<()> {
    let project = crate::open_project(&args.project)?;
    let scope = project.settings().scope()?;
    let attached = project.settings().attached_headers()?;

    // Resolve the identity to crawl as, if one was named, before anything is sent.
    let identity = match &args.identity {
        Some(who) => Some(crate::identity::resolve(&project.identities(), who)?),
        None => None,
    };

    let seeds = if args.seeds.is_empty() {
        gather_seeds(&project, &scope)?
    } else {
        args.seeds.clone()
    };

    if seeds.is_empty() {
        return nothing_to_crawl(args.json);
    }

    let budget = budget_from(&args);
    let policy = CrawlPolicy {
        follow_destructive: args.follow_destructive,
        ignore_robots: args.ignore_robots,
    };
    let identity_label = identity.as_ref().map(|i| i.label.clone());
    let identity_id = identity.as_ref().map(|i| i.id);

    if args.json {
        print_plan_json(&seeds, &budget, &policy, identity_label.as_deref());
    } else {
        print_plan(&seeds, &budget, &policy, identity_label.as_deref());
    }

    if args.dry_run {
        if !args.json {
            println!();
            println!("Nothing was sent. Re-run without --dry-run to crawl.");
        }
        return Ok(());
    }

    // Asked before anything goes out, and only ever here.
    if !args.yes && !args.json {
        println!();
        if !crate::proxy::confirm("Crawl these targets?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    if !args.yes && args.json {
        return Err(HexoraError::invalid_input(
            "--yes",
            "a crawl sends traffic, and --json cannot ask. Pass --yes to say that is \
             intended, or use --dry-run to see the plan",
        ));
    }

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    // The crawler is automated traffic by definition, so the guard refuses out-of-scope
    // targets rather than flagging them the way it would a request a person typed.
    let guard = ScopeGuard::new(transport, Arc::new(scope));
    let mut crawler = Crawler::new(&guard)
        .budget(budget)
        .policy(policy)
        .attaching(attached);
    if let Some(identity) = identity {
        crawler = crawler.crawling_as(identity);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))?;
    let report = runtime.block_on(stoppable(&crawler, seeds));

    let store = Arc::new(project.traffic());
    let recorded = if args.no_save {
        0
    } else {
        record_fetched(&store, &report, identity_id)?
    };

    if args.json {
        print_summary_json(&report, recorded, args.no_save);
    } else {
        print_summary(&report, recorded, args.no_save);
    }
    Ok(())
}

/// Runs the crawl with Ctrl-C wired to its cancel handle.
///
/// The same promise the active scheduler makes: the first Ctrl-C stops the crawl before
/// its next request and returns what it had, so those pages are still recorded. A second
/// Ctrl-C is not intercepted — the handler is dropped as the select resolves — so a tester
/// who wants the process gone still gets it.
async fn stoppable<T: HttpTransport>(crawler: &Crawler<'_, T>, seeds: Vec<String>) -> CrawlReport {
    let cancel = crawler.cancel_handle();
    let run = crawler.run(seeds);
    tokio::pin!(run);

    tokio::select! {
        report = &mut run => report,
        signal = tokio::signal::ctrl_c() => {
            if signal.is_err() {
                eprintln!("Ctrl-C could not be handled here; the crawl will finish within its budget.");
            } else {
                eprintln!();
                eprintln!("Stopping. No further request will be sent — one already on the");
                eprintln!("wire will finish, and what was fetched will still be saved.");
                cancel.stop();
            }
            (&mut run).await
        }
    }
}

/// Records every fetched page as crawler-origin traffic, so the scanner can work over it.
fn record_fetched(
    store: &TrafficStore,
    report: &CrawlReport,
    identity: Option<hexora_types::ids::IdentityId>,
) -> Result<usize> {
    let mut recorded = 0;
    for exchange in &report.fetched {
        let captured = CapturedExchange {
            request: exchange.request.clone(),
            raw_request: exchange.raw_request.clone(),
            response: exchange.response.clone(),
            encoded_body: exchange.encoded_body.clone(),
            content_encoding: exchange.content_encoding.clone(),
            origin: Origin::Crawler.as_str(),
            identity,
            parent: None,
            quirks: Vec::new(),
            tls: exchange.tls.clone(),
            duration_ms: exchange.duration.as_millis().min(u128::from(u32::MAX)) as u32,
        };
        store.record(&captured)?;
        recorded += 1;
    }
    Ok(recorded)
}

/// Gathers in-scope seed URLs from captured traffic, newest first, deduplicated.
fn gather_seeds(project: &Project, scope: &Scope) -> Result<Vec<String>> {
    let store = project.traffic();
    let mut seeds = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cursor: Option<Cursor> = None;

    loop {
        let page = store.history(cursor.as_ref(), Limit::new(SEED_PAGE))?;
        for item in &page.items {
            if !in_scope(scope, &item.url) {
                continue;
            }
            if seen.insert(item.url.clone()) {
                seeds.push(item.url.clone());
                if seeds.len() >= MAX_SEED_URLS {
                    return Ok(seeds);
                }
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok(seeds)
}

/// Whether a captured URL is in the project's scope.
fn in_scope(scope: &Scope, url: &str) -> bool {
    match hexora_types::http::HttpService::parse_url(url) {
        Ok((service, path)) => scope.contains(&service, &path),
        Err(_) => false,
    }
}

/// The budget from the flags, falling back to the crawler's cautious defaults.
fn budget_from(args: &Args) -> CrawlBudget {
    let mut budget = CrawlBudget::default();
    if let Some(max) = args.max_requests {
        budget.max_requests = max;
    }
    if let Some(depth) = args.max_depth {
        budget.max_depth = depth;
    }
    if let Some(per_host) = args.max_per_host {
        budget.max_per_host = per_host;
    }
    if let Some(delay) = args.delay_ms {
        budget.delay = Duration::from_millis(delay);
    }
    budget
}

fn nothing_to_crawl(json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "seeds": 0,
                "note": "no in-scope traffic to seed a crawl; capture some, or pass --url",
            })
        );
        return Ok(());
    }
    println!("Nothing to crawl.");
    println!();
    println!("A crawl starts from URLs this project already holds, in scope, and it found");
    println!("none. Capture some traffic through the proxy first, or name a starting point");
    println!("with --url https://target.example/.");
    Ok(())
}

fn print_plan(
    seeds: &[String],
    budget: &CrawlBudget,
    policy: &CrawlPolicy,
    identity: Option<&str>,
) {
    println!("Crawl plan");
    println!(
        "  as:           {}",
        identity.unwrap_or("unauthenticated")
    );
    println!("  seeds:        {}", seeds.len());
    for seed in seeds.iter().take(5) {
        println!("    {seed}");
    }
    if seeds.len() > 5 {
        println!("    … and {} more", seeds.len() - 5);
    }
    println!("  max requests: {}", budget.max_requests);
    println!("  max depth:    {}", budget.max_depth);
    println!("  per host:     {}", budget.max_per_host);
    println!("  delay:        {} ms", budget.delay.as_millis());
    println!(
        "  robots.txt:   {}",
        if policy.ignore_robots {
            "IGNORED (--ignore-robots)"
        } else {
            "respected"
        }
    );
    println!(
        "  destructive:  {}",
        if policy.follow_destructive {
            "FOLLOWED (--follow-destructive)"
        } else {
            "recorded, not followed"
        }
    );
    println!();
    println!("Forms are discovered but never submitted. Out-of-scope links are recorded, not fetched.");
}

fn print_plan_json(
    seeds: &[String],
    budget: &CrawlBudget,
    policy: &CrawlPolicy,
    identity: Option<&str>,
) {
    println!(
        "{}",
        serde_json::json!({
            "plan": {
                "identity": identity,
                "seeds": seeds,
                "max_requests": budget.max_requests,
                "max_depth": budget.max_depth,
                "max_per_host": budget.max_per_host,
                "delay_ms": budget.delay.as_millis(),
                "respect_robots": !policy.ignore_robots,
                "follow_destructive": policy.follow_destructive,
            }
        })
    );
}

fn stop_reason(stop: CrawlStop) -> &'static str {
    match stop {
        CrawlStop::FrontierEmpty => "the frontier drained — everything reachable was visited",
        CrawlStop::RequestCeiling => "the request ceiling was reached — more may remain",
        CrawlStop::Cancelled => "cancelled — the crawl was stopped before it finished",
    }
}

fn print_summary(report: &CrawlReport, recorded: usize, no_save: bool) {
    println!();
    println!("{} page(s) fetched.", report.fetched.len());
    println!("Stopped: {}.", stop_reason(report.stopped));

    if !report.skipped.is_empty() {
        println!();
        println!("Not followed ({}):", report.skipped.len());
        let mut by_reason: std::collections::BTreeMap<&str, usize> = Default::default();
        for skipped in &report.skipped {
            *by_reason.entry(skip_word(skipped.reason)).or_default() += 1;
        }
        for (why, count) in by_reason {
            println!("  {count} — {why}");
        }
    }

    println!();
    if no_save {
        println!("Nothing was written into the project (--no-save).");
    } else {
        println!("Recorded {recorded} page(s) into the project for scanning.");
    }
}

fn print_summary_json(report: &CrawlReport, recorded: usize, no_save: bool) {
    let mut by_reason: std::collections::BTreeMap<&str, usize> = Default::default();
    for skipped in &report.skipped {
        *by_reason.entry(skip_word(skipped.reason)).or_default() += 1;
    }
    println!(
        "{}",
        serde_json::json!({
            "fetched": report.fetched.len(),
            "recorded": if no_save { 0 } else { recorded },
            "stopped": match report.stopped {
                CrawlStop::FrontierEmpty => "frontier_empty",
                CrawlStop::RequestCeiling => "request_ceiling",
                CrawlStop::Cancelled => "cancelled",
            },
            "skipped": report.skipped.len(),
            "skipped_by_reason": by_reason,
        })
    );
}

/// A short reason word for the skip summary.
fn skip_word(reason: SkipReason) -> &'static str {
    match reason {
        SkipReason::OutOfScope => "out of scope (recorded, not fetched)",
        SkipReason::DepthLimit => "past the depth limit",
        SkipReason::PerHostLimit => "past the per-host cap",
        SkipReason::Unfetchable => "not a fetchable URL",
        SkipReason::Form => "a form (discovered, never submitted)",
        SkipReason::LooksDestructive => "looks destructive (recorded, not followed)",
        SkipReason::RobotsDisallowed => "disallowed by robots.txt",
    }
}

//! `nullhawk browse` — browser-driven capture.
//!
//! The static crawler (`nullhawk crawl`) reads the links in the bytes as delivered. A
//! single-page app whose routes and XHR endpoints only exist after JavaScript runs is
//! invisible to it — and so is the surface those endpoints are. This drives a real
//! headless browser through an **in-process capturing proxy**, so the requests the page's
//! own JavaScript makes land in the project exactly as if a tester had browsed it by hand.
//!
//! ```text
//!   browser ──→ in-process proxy (captures, scope-checks) ──→ target
//!      │                    │
//!   navigates seeds,   records every exchange into the project,
//!   JS runs, XHR fires  so the scanner and the repeater see them too
//! ```
//!
//! # Bounded, and in scope
//!
//! It navigates the seeds, waits for each page to settle, and follows the links the
//! *rendered* DOM exposes — same-origin, in-scope, to a shallow depth and a page ceiling.
//! It does not submit forms (a POST is state-changing) and it does not log in (crawling as
//! an identity is a later step); both are stated gaps rather than quiet ones.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use nullhawk_browser::{Browser, Cdp, LaunchOptions};
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_proxy::{
    CertificateAuthority, ExchangeObserver, ProjectCapture, ProxyConfig, ProxyServer,
};
use nullhawk_storage::repository::{Cursor, Limit};
use nullhawk_types::error::{NullhawkError, Result};
use nullhawk_types::http::HttpService;
use nullhawk_types::scope::Scope;

/// Options for `nullhawk browse`.
pub struct Args<'a> {
    pub project: &'a Path,
    /// Starting URLs. When empty, in-scope URLs the project already captured are used.
    pub seeds: &'a [String],
    /// The most pages to navigate.
    pub max_pages: usize,
    /// How deep rendered links are followed from a seed.
    pub max_depth: usize,
    /// Milliseconds to wait after each page loads, for its XHR/fetch to complete.
    pub settle_ms: u64,
    /// Show the browser window instead of running it headless.
    pub show: bool,
    /// Do not verify the target's TLS certificate (self-signed test targets).
    pub insecure: bool,
    pub json: bool,
}

/// How many captured URLs to read when gathering seeds, and the most seeds to take.
const SEED_PAGE: usize = 500;
const MAX_SEED_URLS: usize = 50;

pub fn run(args: Args<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let scope = project.settings().scope()?;
    if scope.is_empty() {
        return Err(NullhawkError::invalid_input(
            "scope",
            "browsing captures only in-scope navigation, and this project has no scope. \
             Declare the programme's hosts with `nullhawk scope add`",
        ));
    }

    // Seeds: what the tester named, or the in-scope URLs already captured. Either way, only
    // the ones in scope are navigated — an out-of-scope seed would send a browser somewhere
    // nobody authorized.
    let mut seeds: Vec<String> = if args.seeds.is_empty() {
        gather_seeds(&project, &scope)?
    } else {
        args.seeds.to_vec()
    };
    seeds.retain(|url| in_scope(&scope, url));
    if seeds.is_empty() {
        return nothing_to_browse(args.json);
    }

    let ca_dir = crate::proxy::resolve_ca_dir(None)?;
    let ca = Arc::new(CertificateAuthority::load_or_create(&ca_dir)?);
    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any()).http2(true)
    } else {
        TcpTransport::new().http2(true)
    };

    // In-scope only: a browse navigates declared hosts, so the browser's own background
    // chatter — update pings, telemetry — is noise that does not belong in the project.
    let capture = Arc::new(ProjectCapture::new(Arc::new(project.traffic())).in_scope_only());
    let counter = capture.clone();
    let observer: Arc<dyn ExchangeObserver> = capture;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| NullhawkError::Internal(format!("failed to start the async runtime: {e}")))?;

    let json = args.json;
    let outcome = runtime.block_on(async move {
        let config = ProxyConfig {
            // An ephemeral loopback port: the browser is the only client, and it is told
            // the port that was actually bound.
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Default::default()
        };
        let server =
            ProxyServer::bind(config, Arc::new(scope.clone()), transport, observer, ca).await?;
        let addr = server.local_addr()?;
        let proxy_task = tokio::spawn(async move {
            let _ = server.serve().await;
        });

        let result = drive(&scope, addr, &seeds, &args).await;

        // The proxy's only job was to capture this browse; nothing else uses it.
        proxy_task.abort();
        result
    })?;

    let captured = counter.recorded();
    report(&outcome, captured, json);
    Ok(())
}

/// What a browse did, for the summary.
struct Browsed {
    pages: usize,
    links_found: usize,
    failures: usize,
}

/// Launches the browser through the proxy and walks the seeds and their rendered links.
async fn drive(
    scope: &Scope,
    proxy: SocketAddr,
    seeds: &[String],
    args: &Args<'_>,
) -> Result<Browsed> {
    let browser = Browser::launch_with(&LaunchOptions {
        headless: !args.show,
        // The browser sends everything through our proxy, and accepts the proxy's MITM
        // certificate without it being installed — the proxy is the capture chokepoint.
        proxy: Some(addr_string(proxy)),
        ignore_certificate_errors: true,
    })?;
    let mut cdp = browser.connect().await?;

    let mut queue: VecDeque<(String, usize)> = seeds.iter().map(|url| (url.clone(), 0)).collect();
    let mut visited: HashSet<String> = HashSet::new();
    let mut browsed = Browsed {
        pages: 0,
        links_found: 0,
        failures: 0,
    };

    while let Some((url, depth)) = queue.pop_front() {
        if browsed.pages >= args.max_pages {
            break;
        }
        if !visited.insert(url.clone()) || !in_scope(scope, &url) {
            continue;
        }

        browsed.pages += 1;
        if cdp.navigate(&url, Duration::from_secs(20)).await.is_err() {
            browsed.failures += 1;
            continue;
        }
        // The load event has fired; this is the window for the page's own XHR/fetch to run
        // and be captured before the next navigation replaces the document.
        tokio::time::sleep(Duration::from_millis(args.settle_ms)).await;

        if depth < args.max_depth {
            for link in rendered_links(&mut cdp).await {
                browsed.links_found += 1;
                if in_scope(scope, &link) && same_origin(&url, &link) && !visited.contains(&link) {
                    queue.push_back((link, depth + 1));
                }
            }
        }
    }

    // The browser is killed when this handle drops; keep it alive until here.
    drop(browser);
    Ok(browsed)
}

/// The hrefs the rendered DOM exposes, read after JavaScript has had its say.
async fn rendered_links(cdp: &mut Cdp) -> Vec<String> {
    let expr = "JSON.stringify(Array.from(document.querySelectorAll('a[href]'), a => a.href))";
    match cdp.eval(expr).await {
        Ok(value) => value
            .as_str()
            .and_then(|json| serde_json::from_str::<Vec<String>>(json).ok())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Whether two URLs share a scheme, host and port — the boundary a crawl should not cross
/// without a fresh decision.
fn same_origin(a: &str, b: &str) -> bool {
    match (HttpService::parse_url(a), HttpService::parse_url(b)) {
        (Ok((sa, _)), Ok((sb, _))) => {
            sa.host.eq_ignore_ascii_case(&sb.host) && sa.port == sb.port && sa.secure == sb.secure
        }
        _ => false,
    }
}

fn addr_string(addr: SocketAddr) -> String {
    format!("{}:{}", addr.ip(), addr.port())
}

/// Whether a URL is in the project's scope.
fn in_scope(scope: &Scope, url: &str) -> bool {
    match HttpService::parse_url(url) {
        Ok((service, path)) => scope.contains(&service, &path),
        Err(_) => false,
    }
}

/// In-scope URLs the project already holds, to seed a browse when none were named.
fn gather_seeds(project: &nullhawk_storage::Project, scope: &Scope) -> Result<Vec<String>> {
    let store = project.traffic();
    let mut seeds = Vec::new();
    let mut seen = HashSet::new();
    let mut cursor: Option<Cursor> = None;
    loop {
        let page = store.history(cursor.as_ref(), Limit::new(SEED_PAGE as u32))?;
        for item in &page.items {
            if in_scope(scope, &item.url) && seen.insert(item.url.clone()) {
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

fn report(browsed: &Browsed, captured: u64, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "pages": browsed.pages,
                "links_found": browsed.links_found,
                "failures": browsed.failures,
                "captured": captured,
            })
        );
        return;
    }
    println!(
        "Browsed {} page(s); {} failed to load. {} link(s) seen in rendered pages.",
        browsed.pages, browsed.failures, browsed.links_found,
    );
    println!(
        "{captured} exchange(s) captured into the project — including the JavaScript-driven \
         requests a static crawl cannot see."
    );
    println!();
    println!("  nullhawk history <project>        the captured traffic");
    println!("  nullhawk scan passive <project>   read it for leads");
    println!("  nullhawk scan active <project>    settle what it raised");
}

fn nothing_to_browse(json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::json!({ "pages": 0, "captured": 0 }));
    } else {
        println!(
            "No in-scope URL to browse. Name one with --url, or capture some traffic first \
             with `nullhawk proxy`."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_is_scheme_host_and_port() {
        assert!(same_origin(
            "https://app.example.com/a",
            "https://app.example.com/b?x=1"
        ));
        // A different host, a different port, and a different scheme each cross the line.
        assert!(!same_origin(
            "https://app.example.com/a",
            "https://evil.example.com/a"
        ));
        assert!(!same_origin(
            "https://app.example.com/a",
            "https://app.example.com:8443/a"
        ));
        assert!(!same_origin(
            "https://app.example.com/a",
            "http://app.example.com/a"
        ));
    }

    #[test]
    fn a_relative_or_junk_href_is_not_a_same_origin_link() {
        // rendered_links hands back whatever the DOM says; a value that is not an absolute
        // http(s) URL must not be treated as a crawlable same-origin link.
        assert!(!same_origin(
            "https://app.example.com/",
            "javascript:void(0)"
        ));
        assert!(!same_origin("https://app.example.com/", "/relative/path"));
    }
}

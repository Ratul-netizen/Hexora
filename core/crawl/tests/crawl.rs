//! CR.b — the frontier and the scoped fetch, driven against a mock site.
//!
//! The site is served entirely in memory: no socket is opened, so these tests exercise
//! the frontier logic — dedup, depth, ceilings, scope — without a network. Scope is real,
//! though: the crawler holds a `ScopeGuard`, and an out-of-scope link is refused by the
//! guard before `send` is ever reached.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hexora_crawl::{crawl, CrawlBudget, CrawlPolicy, CrawlStop, SkipReason};
use hexora_engine::guard::ScopeGuard;
use hexora_engine::transport::{Exchange, HttpTransport, SendOptions};
use hexora_types::error::Result;
use hexora_types::http::{Headers, HttpRequest, HttpResponse, HttpVersion};
use hexora_types::raw::{RawH2Request, RawRequest};
use hexora_types::scope::{Scope, ScopeRule};

/// An in-memory site: request path → (content-type, body). A path that is not present
/// answers 404 with an empty body, the way a real crawl meets dead links.
struct MockSite {
    pages: HashMap<&'static str, (&'static str, String)>,
}

impl MockSite {
    fn new() -> Self {
        Self {
            pages: HashMap::new(),
        }
    }

    fn page(mut self, path: &'static str, content_type: &'static str, body: impl Into<String>) -> Self {
        self.pages.insert(path, (content_type, body.into()));
        self
    }
}

#[async_trait]
impl HttpTransport for MockSite {
    async fn send(&self, request: HttpRequest, _options: SendOptions) -> Result<Exchange> {
        let (status, content_type, body) = match self.pages.get(request.path.as_str()) {
            Some((ct, body)) => (200u16, *ct, body.clone()),
            None => (404u16, "text/plain", String::new()),
        };
        let mut headers = Headers::new();
        headers.set("content-type", content_type);
        let response = HttpResponse {
            status,
            reason: None,
            version: HttpVersion::Http11,
            headers,
            body: body.into(),
            truncated: false,
        };
        Ok(Exchange {
            request,
            response,
            encoded_body: None,
            content_encoding: None,
            raw_request: None,
            duration: Duration::ZERO,
            tls: None,
        })
    }

    async fn send_raw(&self, _request: RawRequest, _options: SendOptions) -> Result<Exchange> {
        unreachable!("the crawler never sends raw")
    }

    async fn send_raw_h2(&self, _request: RawH2Request, _options: SendOptions) -> Result<Exchange> {
        unreachable!("the crawler never sends frame-level HTTP/2")
    }
}

/// A guard scoped to `site.test`, wrapping a mock site linked as:
/// `/` → `/a`, `/b`, and an out-of-scope `https://evil.test/x`; `/a` → `/c`; `/b` → `/a`.
fn scoped_site() -> ScopeGuard<MockSite> {
    let site = MockSite::new()
        .page(
            "/",
            "text/html",
            r#"<a href="/a">a</a><a href="/b">b</a><a href="https://evil.test/x">evil</a><a href="/a">dup</a>"#,
        )
        .page("/a", "text/html", r#"<a href="/c">c</a>"#)
        .page("/b", "text/html", r#"<a href="/a">back to a</a>"#)
        .page("/c", "text/html", "<p>leaf, no links</p>");
    let scope = Scope::new().include(ScopeRule::host("site.test"));
    ScopeGuard::new(site, Arc::new(scope))
}

fn no_delay(budget: CrawlBudget) -> CrawlBudget {
    CrawlBudget {
        delay: Duration::ZERO,
        ..budget
    }
}

fn fetched_paths(report: &hexora_crawl::CrawlReport) -> Vec<String> {
    report.fetched.iter().map(|e| e.request.path.clone()).collect()
}

#[tokio::test]
async fn crawls_the_whole_in_scope_site_once_each() {
    let guard = scoped_site();
    let report = crawl(&guard, ["https://site.test/"], &no_delay(CrawlBudget::default()), &CrawlPolicy::default()).await;

    let mut paths = fetched_paths(&report);
    paths.sort();
    assert_eq!(paths, vec!["/", "/a", "/b", "/c"]);
    assert_eq!(report.stopped, CrawlStop::FrontierEmpty);

    // The out-of-scope link was recorded, not followed — and nothing else was skipped.
    let out: Vec<_> = report
        .skipped
        .iter()
        .filter(|s| s.reason == SkipReason::OutOfScope)
        .collect();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].url, "https://evil.test/x");
}

#[tokio::test]
async fn the_request_ceiling_stops_the_crawl() {
    let guard = scoped_site();
    let budget = no_delay(CrawlBudget {
        max_requests: 2,
        ..CrawlBudget::default()
    });
    let report = crawl(&guard, ["https://site.test/"], &budget, &CrawlPolicy::default()).await;

    assert_eq!(report.fetched.len(), 2);
    assert_eq!(report.stopped, CrawlStop::RequestCeiling);
}

#[tokio::test]
async fn depth_zero_fetches_only_the_seed_and_records_its_links() {
    let guard = scoped_site();
    let budget = no_delay(CrawlBudget {
        max_depth: 0,
        ..CrawlBudget::default()
    });
    let report = crawl(&guard, ["https://site.test/"], &budget, &CrawlPolicy::default()).await;

    assert_eq!(fetched_paths(&report), vec!["/"]);
    assert_eq!(report.stopped, CrawlStop::FrontierEmpty);
    // /a and /b were in scope but too deep, so they are recorded rather than followed.
    let too_deep: Vec<_> = report
        .skipped
        .iter()
        .filter(|s| s.reason == SkipReason::DepthLimit)
        .map(|s| s.url.clone())
        .collect();
    assert!(too_deep.contains(&"https://site.test/a".to_string()));
    assert!(too_deep.contains(&"https://site.test/b".to_string()));
}

#[tokio::test]
async fn the_per_host_cap_bounds_one_host() {
    let guard = scoped_site();
    let budget = no_delay(CrawlBudget {
        max_per_host: 1,
        ..CrawlBudget::default()
    });
    let report = crawl(&guard, ["https://site.test/"], &budget, &CrawlPolicy::default()).await;

    assert_eq!(report.fetched.len(), 1);
    assert!(report
        .skipped
        .iter()
        .any(|s| s.reason == SkipReason::PerHostLimit));
}

#[tokio::test]
async fn an_out_of_scope_seed_is_recorded_and_nothing_is_sent() {
    let guard = scoped_site();
    let report = crawl(&guard, ["https://evil.test/"], &no_delay(CrawlBudget::default()), &CrawlPolicy::default()).await;

    assert!(report.fetched.is_empty());
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].reason, SkipReason::OutOfScope);
}

// ---- CR.c: the safety layer ----

fn guard_over(site: MockSite) -> ScopeGuard<MockSite> {
    let scope = Scope::new().include(ScopeRule::host("site.test"));
    ScopeGuard::new(site, Arc::new(scope))
}

#[tokio::test]
async fn a_destructive_link_is_recorded_not_followed() {
    let guard = guard_over(
        MockSite::new()
            .page(
                "/",
                "text/html",
                r#"<a href="/logout">out</a><a href="/safe">safe</a>"#,
            )
            .page("/safe", "text/html", "ok")
            .page("/logout", "text/html", "bye"),
    );

    let report = crawl(
        &guard,
        ["https://site.test/"],
        &no_delay(CrawlBudget::default()),
        &CrawlPolicy::default(),
    )
    .await;

    let paths = fetched_paths(&report);
    assert!(paths.contains(&"/safe".to_string()));
    assert!(!paths.contains(&"/logout".to_string()));
    assert!(report.skipped.iter().any(|s| {
        s.reason == SkipReason::LooksDestructive && s.url.ends_with("/logout")
    }));
}

#[tokio::test]
async fn opting_in_follows_the_destructive_link() {
    let guard = guard_over(
        MockSite::new()
            .page("/", "text/html", r#"<a href="/logout">out</a>"#)
            .page("/logout", "text/html", "bye"),
    );

    let policy = CrawlPolicy {
        follow_destructive: true,
        ignore_robots: false,
    };
    let report = crawl(
        &guard,
        ["https://site.test/"],
        &no_delay(CrawlBudget::default()),
        &policy,
    )
    .await;

    assert!(fetched_paths(&report).contains(&"/logout".to_string()));
}

#[tokio::test]
async fn a_form_is_discovered_but_never_auto_submitted() {
    let guard = guard_over(MockSite::new().page(
        "/",
        "text/html",
        r#"<form action="/submit" method="post"><input name="x"></form>"#,
    ));

    let report = crawl(
        &guard,
        ["https://site.test/"],
        &no_delay(CrawlBudget::default()),
        &CrawlPolicy::default(),
    )
    .await;

    assert_eq!(fetched_paths(&report), vec!["/"]);
    assert!(report.skipped.iter().any(|s| {
        s.reason == SkipReason::Form && s.url.ends_with("/submit")
    }));
}

#[tokio::test]
async fn robots_disallow_is_respected_by_default() {
    let guard = guard_over(
        MockSite::new()
            .page("/robots.txt", "text/plain", "User-agent: *\nDisallow: /private")
            .page(
                "/",
                "text/html",
                r#"<a href="/private/x">p</a><a href="/public">pub</a>"#,
            )
            .page("/private/x", "text/html", "secret")
            .page("/public", "text/html", "ok"),
    );

    let report = crawl(
        &guard,
        ["https://site.test/"],
        &no_delay(CrawlBudget::default()),
        &CrawlPolicy::default(),
    )
    .await;

    let paths = fetched_paths(&report);
    assert!(paths.contains(&"/public".to_string()));
    assert!(!paths.contains(&"/private/x".to_string()));
    assert!(report.skipped.iter().any(|s| {
        s.reason == SkipReason::RobotsDisallowed && s.url.ends_with("/private/x")
    }));
}

#[tokio::test]
async fn robots_can_be_overridden_loudly() {
    let guard = guard_over(
        MockSite::new()
            .page("/robots.txt", "text/plain", "User-agent: *\nDisallow: /private")
            .page("/", "text/html", r#"<a href="/private/x">p</a>"#)
            .page("/private/x", "text/html", "secret"),
    );

    let policy = CrawlPolicy {
        follow_destructive: false,
        ignore_robots: true,
    };
    let report = crawl(
        &guard,
        ["https://site.test/"],
        &no_delay(CrawlBudget::default()),
        &policy,
    )
    .await;

    assert!(fetched_paths(&report).contains(&"/private/x".to_string()));
}

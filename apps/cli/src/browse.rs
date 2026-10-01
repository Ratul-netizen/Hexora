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

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nullhawk_browser::{Browser, Cdp, LaunchOptions};
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_proxy::{
    CertificateAuthority, ExchangeObserver, ProjectCapture, ProxyConfig, ProxyServer,
};
use nullhawk_storage::repository::{Cursor, Limit};
use nullhawk_types::error::{NullhawkError, Result};
use nullhawk_types::http::HttpService;
use nullhawk_types::identity::{Credential, Identity};
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
    /// Crawl as this identity (label or id): its cookie session is injected into the browser.
    pub identity: Option<&'a str>,
    /// Record a login: capture the session from a hand-driven login into this identity.
    pub record_login: Option<&'a str>,
    /// Seconds to wait for a login when recording one.
    pub login_timeout: u64,
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

    // The identity to carry into the browser, if one was named. Only a cookie session has a
    // browser equivalent — a bearer or header credential does not — so a non-cookie identity
    // is refused here rather than silently crawling anonymously.
    let cookie_header = match args.identity {
        Some(who) => {
            let identity = crate::identity::resolve(&project.identities(), who)?;
            match cookie_header_of(&identity) {
                Some(header) => Some(header),
                None => {
                    return Err(NullhawkError::invalid_input(
                        "--identity",
                        format!(
                            "{} is not a cookie-based identity, and only a cookie session can \
                             be carried into a browser. Use `nullhawk crawl --identity` for a \
                             bearer or header identity",
                            identity.label
                        ),
                    ))
                }
            }
        }
        None => None,
    };

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
    let record_label = args.record_login.map(str::to_string);
    let project_path = args.project.to_path_buf();
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

        // Two modes through the same captured proxy: record a login (wait for a session), or
        // crawl (navigate and follow links).
        let result = if args.record_login.is_some() {
            capture_login(addr, &seeds, &args)
                .await
                .map(Outcome::Captured)
        } else {
            drive(&scope, addr, &seeds, &args, cookie_header.as_deref())
                .await
                .map(Outcome::Crawled)
        };

        // The proxy's only job was this browse; nothing else uses it.
        proxy_task.abort();
        result
    })?;

    let captured = counter.recorded();
    match outcome {
        Outcome::Crawled(browsed) => report(&browsed, captured, json),
        Outcome::Captured(login) => {
            // record_label is Some here: capture_login runs only when --record-login was given.
            save_login(
                &project,
                &project_path,
                &record_label.unwrap_or_default(),
                login,
                json,
            )?
        }
    }
    Ok(())
}

/// What a browse produced: a crawl's tally, or a recorded login's captured session.
enum Outcome {
    Crawled(Browsed),
    Captured(Option<CapturedLogin>),
}

/// A session captured from a hand-driven login.
struct CapturedLogin {
    /// The full `Cookie:` header value for the in-scope cookies the browser held.
    cookie_header: String,
    /// The cookie names that appeared or changed during the login — the likely session.
    session_names: Vec<String>,
}

/// Saves a captured login as a cookie identity, creating it or updating one with the same
/// label. The session cookies are the ones that changed during the login, so cross-identity
/// testing compares exactly the value that says who the caller is.
fn save_login(
    project: &nullhawk_storage::Project,
    project_path: &Path,
    label: &str,
    login: Option<CapturedLogin>,
    json: bool,
) -> Result<()> {
    let Some(login) = login else {
        if json {
            println!("{}", serde_json::json!({ "captured": false }));
        } else {
            println!(
                "No session was captured — no cookie appeared or changed on an in-scope host \
                 within the timeout. Log in before it elapses, or raise --login-timeout."
            );
        }
        return Ok(());
    };

    let store = project.identities();
    let scope = project.settings().scope()?;
    // The replayable login: the captured request whose response set the session. Stored on
    // the identity so `identity renew <label>` can replay it to refresh the session without a
    // second hand-login. A session a script set with no Set-Cookie response leaves none.
    let replay = find_login_request(&project.traffic(), &scope, &login.session_names);

    // Reuse an existing identity with this label — keeping its id, privilege, ownership and
    // extra headers — so a re-recorded login refreshes the session in place rather than
    // leaving two identities that differ only in cookie. A brand-new one is a logged-in user.
    let identity = match crate::identity::resolve(&store, label) {
        Ok(existing) => Identity {
            credential: Credential::Cookie {
                value: nullhawk_types::redact::Secret::new(login.cookie_header),
            },
            session_cookies: login.session_names.clone(),
            // A fresh recording's login wins; an old one is kept only if none was found now.
            login_request: replay.or(existing.login_request),
            ..existing
        },
        Err(_) => Identity {
            id: nullhawk_types::ids::IdentityId::new(),
            label: label.to_string(),
            privilege: nullhawk_types::identity::PrivilegeLevel::User,
            credential: Credential::Cookie {
                value: nullhawk_types::redact::Secret::new(login.cookie_header),
            },
            extra_headers: Vec::new(),
            owned_object_ids: Vec::new(),
            session_cookies: login.session_names.clone(),
            login_request: replay,
        },
    };
    store.put(&identity)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "captured": true,
                "identity": label,
                "session_cookies": login.session_names,
                "replay_request": replay.map(|id| id.to_string()),
            })
        );
    } else {
        println!(
            "Captured a session for `{label}` ({}). Crawl behind the login with `nullhawk \
             browse <project> --identity {label}` or test authorization with it.",
            if login.session_names.is_empty() {
                "no session cookie identified".to_string()
            } else {
                format!("session cookie(s): {}", login.session_names.join(", "))
            },
        );
        if replay.is_some() {
            println!();
            println!(
                "The login was recorded. When the session expires, replay it to mint a fresh \
                 one — no second log-in:"
            );
            println!(
                "  nullhawk identity renew {} {label}",
                project_path.display()
            );
        }
    }
    Ok(())
}

/// The captured request whose response set a session cookie — the login to replay.
///
/// Newest first, so a re-login's request is preferred over an older one. A session a script
/// set with `document.cookie` rather than a `Set-Cookie` response leaves no such request, and
/// this returns None rather than offering one that cannot reproduce the session.
fn find_login_request(
    traffic: &nullhawk_storage::TrafficStore,
    scope: &Scope,
    session_names: &[String],
) -> Option<nullhawk_types::ids::RequestId> {
    if session_names.is_empty() {
        return None;
    }
    let page = traffic.history(None, Limit::new(200)).ok()?;
    for item in &page.items {
        if !in_scope(scope, &item.url) {
            continue;
        }
        let Ok((_, _, _, headers)) = traffic.response_head(item.id) else {
            continue;
        };
        if sets_a_session_cookie(&headers, session_names) {
            return Some(item.id);
        }
    }
    None
}

/// Whether a raw response head sets one of the session cookies with a `Set-Cookie`.
fn sets_a_session_cookie(headers_raw: &[u8], session_names: &[String]) -> bool {
    let text = String::from_utf8_lossy(headers_raw);
    text.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("set-cookie:")
            && session_names
                .iter()
                .any(|name| lower.contains(&format!("{}=", name.to_ascii_lowercase())))
    })
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
    inject: Option<&str>,
) -> Result<Browsed> {
    let browser = Browser::launch_with(&LaunchOptions {
        headless: !args.show,
        // The browser sends everything through our proxy, and accepts the proxy's MITM
        // certificate without it being installed — the proxy is the capture chokepoint.
        proxy: Some(addr_string(proxy)),
        ignore_certificate_errors: true,
    })?;
    let mut cdp = browser.connect().await?;

    // Plant the identity's session cookies before the first navigation, on every origin the
    // seeds name, so a page that needs a session is fetched as that principal from the start.
    if let Some(cookie_header) = inject {
        inject_cookies(&mut cdp, cookie_header, &seed_origins(seeds)).await;
    }

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

/// The `Cookie:` header value for a cookie identity, or None for any other kind — only a
/// cookie session has a browser equivalent.
fn cookie_header_of(identity: &Identity) -> Option<String> {
    match &identity.credential {
        Credential::Cookie { value } => Some(value.expose().clone()),
        _ => None,
    }
}

/// Plants each cookie from a `Cookie:` header value into the browser, for every given
/// origin. The `url` form of `setCookie` is used rather than a bare domain: it is the one
/// that reliably binds a cookie to an exact origin, including a loopback IP and port, which
/// a bare `domain` does not. The Network domain is enabled first so the store exists before
/// any navigation.
async fn inject_cookies(cdp: &mut Cdp, cookie_header: &str, origins: &[String]) {
    let _ = cdp.call("Network.enable", serde_json::json!({})).await;
    for pair in cookie_header.split(';') {
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        for origin in origins {
            let _ = cdp
                .call(
                    "Network.setCookie",
                    serde_json::json!({
                        "name": name.trim(),
                        "value": value.trim(),
                        "url": origin,
                    }),
                )
                .await;
        }
    }
}

/// Opens a visible browser at the login page and waits for a session to appear.
///
/// Always visible — a login is something a person does — and it watches the browser's own
/// cookie store rather than parsing traffic, so whatever the login sets (a cookie from a
/// redirect, a header, or script) is seen the same way. A cookie that appears or changes
/// value on an in-scope host is taken to be the session.
async fn capture_login(
    proxy: SocketAddr,
    seeds: &[String],
    args: &Args<'_>,
) -> Result<Option<CapturedLogin>> {
    let login_url = seeds.first().ok_or_else(|| {
        NullhawkError::invalid_input("--url", "recording a login needs the login page's URL")
    })?;
    let browser = Browser::launch_with(&LaunchOptions {
        // A login is driven by a person, so the window must be visible whatever --show says.
        headless: false,
        proxy: Some(addr_string(proxy)),
        ignore_certificate_errors: true,
    })?;
    let mut cdp = browser.connect().await?;
    let hosts = login_hosts(seeds);
    let _ = cdp.navigate(login_url, Duration::from_secs(20)).await;
    let baseline = read_cookies(&mut cdp, &hosts).await;

    eprintln!(
        "A browser window has opened at {login_url}. Log in there — waiting up to {}s for a \
         session to appear.",
        args.login_timeout
    );

    let deadline = Instant::now() + Duration::from_secs(args.login_timeout);
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let now = read_cookies(&mut cdp, &hosts).await;
        let changed: Vec<String> = now
            .iter()
            .filter(|(name, value)| baseline.get(name.as_str()) != Some(value))
            .map(|(name, _)| name.clone())
            .collect();
        if !changed.is_empty() {
            let cookie_header = cookie_header_from(&now);
            drop(browser);
            return Ok(Some(CapturedLogin {
                cookie_header,
                session_names: changed,
            }));
        }
    }

    // Timed out. If the browser holds in-scope cookies anyway, capture them — better than
    // nothing — but single out no name as the session, since none was seen to change.
    let now = read_cookies(&mut cdp, &hosts).await;
    drop(browser);
    if now.is_empty() {
        Ok(None)
    } else {
        Ok(Some(CapturedLogin {
            cookie_header: cookie_header_from(&now),
            session_names: Vec::new(),
        }))
    }
}

/// The in-scope cookies the browser holds, name → value.
async fn read_cookies(cdp: &mut Cdp, hosts: &[String]) -> BTreeMap<String, String> {
    let _ = cdp.call("Network.enable", serde_json::json!({})).await;
    let mut cookies = BTreeMap::new();
    let Ok(value) = cdp
        .call("Network.getAllCookies", serde_json::json!({}))
        .await
    else {
        return cookies;
    };
    let Some(list) = value.get("cookies").and_then(|c| c.as_array()) else {
        return cookies;
    };
    for cookie in list {
        let name = cookie.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let val = cookie.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let domain = cookie
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim_start_matches('.');
        if !name.is_empty()
            && !domain.is_empty()
            && hosts.iter().any(|h| h == domain || h.ends_with(domain))
        {
            cookies.insert(name.to_string(), val.to_string());
        }
    }
    cookies
}

/// A `Cookie:` header value assembled from a cookie map.
fn cookie_header_from(cookies: &BTreeMap<String, String>) -> String {
    cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// The distinct hosts the seed URLs name — whose cookies the login's session is among.
fn login_hosts(seeds: &[String]) -> Vec<String> {
    let mut hosts = Vec::new();
    for seed in seeds {
        if let Ok((service, _)) = HttpService::parse_url(seed) {
            if !hosts.contains(&service.host) {
                hosts.push(service.host);
            }
        }
    }
    hosts
}

/// The distinct origins (`scheme://host:port/`) the seed URLs name, to plant the session on.
fn seed_origins(seeds: &[String]) -> Vec<String> {
    let mut origins = Vec::new();
    for seed in seeds {
        if let Ok((service, _)) = HttpService::parse_url(seed) {
            let scheme = if service.secure { "https" } else { "http" };
            let origin = format!("{scheme}://{}:{}/", service.host, service.port);
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
    }
    origins
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
    fn a_cookie_header_is_assembled_in_a_stable_order() {
        let mut cookies = BTreeMap::new();
        cookies.insert("session".to_string(), "abc".to_string());
        cookies.insert("csrf".to_string(), "def".to_string());
        // BTreeMap order is stable, so the same jar always yields the same header.
        assert_eq!(cookie_header_from(&cookies), "csrf=def; session=abc");
        assert_eq!(cookie_header_from(&BTreeMap::new()), "");
    }

    #[test]
    fn a_response_that_sets_the_session_cookie_is_the_login() {
        let names = vec!["session".to_string()];
        // The login response: a Set-Cookie for the session.
        let login = b"HTTP/1.1 302 Found\r\nSet-Cookie: session=abc; Path=/\r\nLocation: /\r\n";
        assert!(sets_a_session_cookie(login, &names));
        // A response that sets some *other* cookie, or none, is not the login.
        assert!(!sets_a_session_cookie(
            b"Set-Cookie: csrf=xyz; Path=/\r\n",
            &names
        ));
        assert!(!sets_a_session_cookie(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
            &names
        ));
        // Case-insensitive on the header and the cookie name.
        assert!(sets_a_session_cookie(
            b"set-cookie: SESSION=abc\r\n",
            &names
        ));
    }

    #[test]
    fn login_hosts_are_the_distinct_seed_hosts() {
        let hosts = login_hosts(&[
            "https://app.example.com/login".into(),
            "https://app.example.com/".into(),
            "http://127.0.0.1:8000/signin".into(),
        ]);
        assert_eq!(
            hosts,
            vec!["app.example.com".to_string(), "127.0.0.1".to_string()]
        );
    }

    #[test]
    fn seed_origins_are_distinct_scheme_host_port_roots() {
        // The session is planted per origin; a path or a repeat must not change or multiply it.
        let origins = seed_origins(&[
            "https://app.example.com/dashboard".into(),
            "https://app.example.com/settings".into(),
            "http://127.0.0.1:8000/x".into(),
        ]);
        assert_eq!(
            origins,
            vec![
                "https://app.example.com:443/".to_string(),
                "http://127.0.0.1:8000/".to_string(),
            ]
        );
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

//! # hexora-crawl
//!
//! Discovering endpoints from traffic Hexora already holds (CR.a), so the scanner has more
//! than what a tester happened to proxy.
//!
//! ## This step sends nothing
//!
//! The crawler as a whole sends traffic, and that traffic goes through the active scheduler
//! and the scope guard like every other automated request (CR.b onward). *This* module is
//! the part that sends nothing: it reads a captured response and reports the URLs it
//! references — anchors, form actions, resource sources, and URL-shaped strings in scripts —
//! each resolved against the response's own address the way a browser resolves a link. It
//! *offers* endpoints, the way the identifier analyzer offers identifiers; whether any is
//! fetched is a later, deliberate decision.
//!
//! ## Honest about what it is
//!
//! It is a static extractor, not a browser. It finds the links in the bytes as delivered; a
//! single-page app whose routes and XHR endpoints only exist after JavaScript runs needs the
//! browser-driven crawl (M18), and this never pretends otherwise. Its output is bounded —
//! a hostile response cannot make it yield without limit — and it never resolves a candidate
//! it cannot make a real `http(s)`/`ws(s)` URL of.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

use hexora_types::http::HttpService;

pub mod frontier;
pub mod robots;
pub use frontier::{
    crawl, CrawlBudget, CrawlPolicy, CrawlReport, CrawlStop, SkipReason, Skipped,
    CRAWLER_USER_AGENT,
};

/// The largest response body the extractor will scan, and the most links it will return.
///
/// A crawl over a hostile or generated page must not turn one response into unbounded work;
/// past these the extractor stops, which is a coverage note, not a correctness problem.
const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;
const MAX_LINKS: usize = 20_000;

/// Where in a response a link was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSource {
    /// An `href` attribute — an anchor or a stylesheet link.
    Href,
    /// A `src` attribute — a script, image or frame.
    Src,
    /// A form's `action`, with the method it declared.
    FormAction,
    /// A URL-shaped string in a script, JSON or other text body.
    Text,
}

/// One discovered endpoint, resolved to an absolute URL, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// The absolute, fragment-stripped URL.
    pub url: String,
    /// Where in the response it was referenced.
    pub source: LinkSource,
    /// For a form, the method it declared (uppercased); `None` otherwise.
    pub method: Option<String>,
}

/// Extracts the endpoints a captured response references, resolved against `base_url`.
///
/// `base_url` is the address of the response itself (the request's URL); `content_type` steers
/// what is scanned — HTML gets its attributes and forms read, and any text body is scanned for
/// URL-shaped strings so a script or a JSON config still yields its endpoints. Results are
/// deduplicated by URL, keeping the first place each was seen, and bounded by [`MAX_LINKS`].
pub fn extract(base_url: &str, content_type: &str, body: &[u8]) -> Vec<Discovered> {
    let slice = &body[..body.len().min(MAX_SCAN_BYTES)];
    let text = String::from_utf8_lossy(slice);
    let lower = text.to_ascii_lowercase();
    let is_html = content_type.to_ascii_lowercase().contains("html");

    let mut out: Vec<Discovered> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut push = |candidate: &str, source: LinkSource, method: Option<String>| {
        if out.len() >= MAX_LINKS {
            return;
        }
        if let Some(url) = resolve(base_url, candidate) {
            if seen.insert(url.clone()) {
                out.push(Discovered { url, source, method });
            }
        }
    };

    if is_html {
        // Forms first, so a form's action is recorded with its method rather than as a bare
        // href/src elsewhere.
        for (action, method) in scan_forms(&text, &lower) {
            push(&action, LinkSource::FormAction, Some(method));
        }
        for value in scan_attribute(&text, &lower, "href") {
            push(&value, LinkSource::Href, None);
        }
        for value in scan_attribute(&text, &lower, "src") {
            push(&value, LinkSource::Src, None);
        }
    }

    // Any text body — including the HTML's inline scripts — is scanned for absolute URLs, so a
    // fetch() target or a configured API base still surfaces.
    for value in scan_url_strings(&text) {
        push(&value, LinkSource::Text, None);
    }

    out
}

/// Resolves a candidate reference against a base URL, or `None` if it is not a fetchable
/// `http(s)`/`ws(s)` endpoint (a `javascript:`/`mailto:`/`data:` scheme, or an empty or
/// fragment-only reference).
fn resolve(base_url: &str, candidate: &str) -> Option<String> {
    let candidate = candidate.trim();
    // Drop the fragment: it never reaches the server.
    let candidate = candidate.split('#').next().unwrap_or("").trim();
    if candidate.is_empty() {
        return None;
    }

    // A colon before the first '/' or '?' means the reference carries a scheme (RFC 3986),
    // whether or not it uses `//` — so `mailto:` and `javascript:` are recognised as schemes,
    // not mistaken for relative paths.
    let authority_or_path = candidate.find(['/', '?']).unwrap_or(candidate.len());
    if let Some(colon) = candidate[..authority_or_path].find(':') {
        let scheme = &candidate[..colon];
        let is_scheme = scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
        if is_scheme {
            let fetchable = matches!(
                scheme.to_ascii_lowercase().as_str(),
                "http" | "https" | "ws" | "wss"
            );
            if fetchable && candidate[colon..].starts_with("://") {
                let (service, path) = HttpService::parse_url(candidate).ok()?;
                return Some(format!("{}{}", service.origin(), path));
            }
            // Another scheme (mailto:, tel:, javascript:, data:…), or an http-family scheme
            // without an authority — not something to fetch.
            return None;
        }
    }

    let (base, base_path) = HttpService::parse_url(base_url).ok()?;
    let origin = base.origin();

    if let Some(rest) = candidate.strip_prefix("//") {
        // Scheme-relative: keep the base's scheme.
        let (service, path) = HttpService::parse_url(&format!("{}://{rest}", base.scheme())).ok()?;
        return Some(format!("{}{}", service.origin(), path));
    }
    if candidate.starts_with('/') {
        return Some(format!("{origin}{}", normalize_path(candidate)));
    }

    // Relative to the base path's directory.
    let dir = match base_path.rsplit_once('/') {
        Some((prefix, _)) => prefix,
        None => "",
    };
    Some(format!("{origin}{}", normalize_path(&format!("{dir}/{candidate}"))))
}

/// Collapses `.` and `..` segments in an absolute path, so a relative link resolves to a real
/// path rather than one with `../` a server would reject.
fn normalize_path(path: &str) -> String {
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segments.join("/"));
    if let Some(query) = query {
        out.push('?');
        out.push_str(query);
    }
    out
}

/// Finds the values of an attribute (`href`, `src`, …) across a document.
fn scan_attribute(text: &str, lower: &str, attr: &str) -> Vec<String> {
    let needle = format!("{attr}=");
    let bytes = lower.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(pos) = lower[i..].find(&needle) {
        let start = i + pos;
        let value_start = start + needle.len();
        i = value_start;
        // Only at an attribute boundary — preceded by whitespace, `<`, or a quote — so
        // `data-href=` or a word ending in the name is not mistaken for the attribute.
        let boundary = start == 0
            || matches!(
                bytes[start - 1],
                b' ' | b'\t' | b'\n' | b'\r' | b'<' | b'"' | b'\'' | b'/'
            );
        if !boundary || value_start >= text.len() {
            continue;
        }
        let value = read_attribute_value(&text[value_start..]);
        if !value.is_empty() {
            out.push(value);
        }
    }
    out
}

/// Reads an attribute value beginning at (just after) the `=`: quoted, or up to a delimiter.
fn read_attribute_value(s: &str) -> String {
    let bytes = s.as_bytes();
    match bytes.first() {
        Some(b'"') => s[1..].split('"').next().unwrap_or("").to_string(),
        Some(b'\'') => s[1..].split('\'').next().unwrap_or("").to_string(),
        _ => s
            .split(|c: char| c.is_whitespace() || c == '>')
            .next()
            .unwrap_or("")
            .to_string(),
    }
}

/// Finds each `<form>`'s action and method.
fn scan_forms(text: &str, lower: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(pos) = lower[i..].find("<form") {
        let start = i + pos;
        let end = lower[start..].find('>').map_or(lower.len(), |e| start + e);
        let tag = &text[start..end.min(text.len())];
        let tag_lower = &lower[start..end.min(lower.len())];
        i = end + 1;
        if let Some(action) = scan_attribute(tag, tag_lower, "action").into_iter().next() {
            let method = scan_attribute(tag, tag_lower, "method")
                .into_iter()
                .next()
                .map(|m| m.trim().to_ascii_uppercase())
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "GET".to_string());
            out.push((action, method));
        }
    }
    out
}

/// Finds absolute `http(s)`/`ws(s)` URLs embedded in a text body (a script, JSON, …).
fn scan_url_strings(text: &str) -> Vec<String> {
    const SCHEMES: [&str; 4] = ["https://", "http://", "wss://", "ws://"];
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lower.len() {
        let next = SCHEMES
            .iter()
            .filter_map(|s| lower[i..].find(s).map(|p| (i + p, s.len())))
            .min_by_key(|(pos, _)| *pos);
        let Some((start, _)) = next else { break };
        let url: String = text[start..]
            .chars()
            .take_while(|&c| !c.is_whitespace() && !matches!(c, '"' | '\'' | '<' | '>' | '`' | ')' | '(' | ']' | '['))
            .collect();
        i = start + url.len().max(1);
        if url.len() > "https://".len() {
            out.push(url);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urls(discovered: &[Discovered]) -> Vec<&str> {
        discovered.iter().map(|d| d.url.as_str()).collect()
    }

    #[test]
    fn html_anchors_are_resolved_absolute_relative_and_scheme_relative() {
        let body = br##"<html><body>
            <a href="https://other.test/abs">abs</a>
            <a href="/root/page">root</a>
            <a href="sub/leaf">relative</a>
            <a href="//cdn.test/x.js">scheme-relative</a>
            <a href="#section">fragment only</a>
            <a href="mailto:a@b.test">mail</a>
        </body></html>"##;
        let found = extract("https://app.test/dir/index.html", "text/html", body);
        let got = urls(&found);
        assert!(got.contains(&"https://other.test/abs"));
        assert!(got.contains(&"https://app.test/root/page"));
        assert!(got.contains(&"https://app.test/dir/sub/leaf"));
        assert!(got.contains(&"https://cdn.test/x.js"));
        // A fragment-only link and a mailto: are not endpoints.
        assert!(!got.iter().any(|u| u.contains("section")));
        assert!(!got.iter().any(|u| u.contains("mailto")));
    }

    #[test]
    fn a_form_is_recorded_with_its_method() {
        let body = br#"<form action="/login" method="post"><input name="u"></form>"#;
        let found = extract("https://app.test/", "text/html", body);
        let form = found.iter().find(|d| d.source == LinkSource::FormAction).unwrap();
        assert_eq!(form.url, "https://app.test/login");
        assert_eq!(form.method.as_deref(), Some("POST"));
    }

    #[test]
    fn a_dotdot_relative_link_is_normalized() {
        let found = extract("https://app.test/a/b/c.html", "text/html", br#"<a href="../x">"#);
        assert_eq!(urls(&found), vec!["https://app.test/a/x"]);
    }

    #[test]
    fn urls_in_a_script_body_are_found() {
        let body = br#"const api = "https://api.test/v1/users"; fetch("https://api.test/v1/orders")"#;
        let found = extract("https://app.test/app.js", "application/javascript", body);
        let got = urls(&found);
        assert!(got.contains(&"https://api.test/v1/users"));
        assert!(got.contains(&"https://api.test/v1/orders"));
    }

    #[test]
    fn results_are_deduplicated() {
        let body = br#"<a href="/x">1</a><a href="/x">2</a><a href="/x">3</a>"#;
        let found = extract("https://app.test/", "text/html", body);
        assert_eq!(found.iter().filter(|d| d.url == "https://app.test/x").count(), 1);
    }

    #[test]
    fn arbitrary_bytes_produce_no_panic_and_a_bounded_result() {
        // Hostile or binary input must not panic and must not yield unbounded output.
        let body: Vec<u8> = (0..=255u8).cycle().take(50_000).collect();
        let found = extract("https://app.test/", "text/html", &body);
        assert!(found.len() <= MAX_LINKS);
    }
}

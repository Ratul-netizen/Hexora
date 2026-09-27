//! `nullhawk sitemap` — the coverage a project holds, as a host → path tree.
//!
//! Read-only, and sends nothing: it reads the traffic already captured, groups it by host
//! and path, marks what is out of scope, and — with `--forms` — reads the HTML bodies to
//! list the forms that were discovered but never submitted. It is the visible answer to
//! "what has this engagement actually reached?", and the payoff of the crawler: after a
//! crawl, the pages it fetched are here.

use std::path::PathBuf;

use nullhawk_crawl::{CapturedPage, SiteMap};
use nullhawk_storage::repository::{Cursor, Limit};
use nullhawk_storage::{StoredTraffic, TrafficStore};
use nullhawk_types::http::HttpService;
use nullhawk_types::Result;

/// History rows read per page.
const PAGE: u32 = 500;

/// Options for `nullhawk sitemap`.
pub struct Args {
    pub project: PathBuf,
    /// Show only this host (bare host or `host:port`).
    pub host: Option<String>,
    /// Read HTML bodies and list discovered forms. Off by default (it reads bodies).
    pub forms: bool,
    pub json: bool,
}

/// Prints the project's coverage tree.
pub fn run(args: Args) -> Result<()> {
    let project = crate::open_project(&args.project)?;
    let scope = project.settings().scope()?;
    let store = project.traffic();

    let mut pages = Vec::new();
    let mut cursor: Option<Cursor> = None;
    loop {
        let page = store.history(cursor.as_ref(), Limit::new(PAGE))?;
        for item in &page.items {
            if let Some(host) = &args.host {
                if !matches_host(&item.url, host) {
                    continue;
                }
            }
            let (content_type, body) = if args.forms {
                read_body_for_forms(&store, item)
            } else {
                (String::new(), Vec::new())
            };
            pages.push(CapturedPage {
                url: item.url.clone(),
                method: item.method.clone(),
                status: item.status,
                identity: item.identity.clone(),
                content_type,
                body,
            });
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    let map = SiteMap::build(pages, &scope);
    if args.json {
        print_json(&map);
    } else {
        print_tree(&map, args.forms);
    }
    Ok(())
}

/// Whether a captured URL's authority matches the `--host` filter (bare host or host:port).
fn matches_host(url: &str, want: &str) -> bool {
    match HttpService::parse_url(url) {
        Ok((service, _)) => service.host == want || service.authority() == want,
        Err(_) => false,
    }
}

/// Reads a row's content type and, for HTML, its body — best effort. A read error just
/// means no form view for that row, never a failed command.
fn read_body_for_forms(store: &TrafficStore, item: &StoredTraffic) -> (String, Vec<u8>) {
    let content_type = match store.response_head(item.id) {
        Ok((_, _, _, headers_raw)) => content_type_of(&headers_raw),
        Err(_) => return (String::new(), Vec::new()),
    };
    if !content_type.to_ascii_lowercase().contains("html") {
        return (content_type, Vec::new());
    }
    let body = store.response_body(item.id, false).unwrap_or_default();
    (content_type, body)
}

/// Finds the `Content-Type` value in a raw response header block.
fn content_type_of(headers_raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(headers_raw);
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-type") {
                return value.trim().to_string();
            }
        }
    }
    String::new()
}

fn print_tree(map: &SiteMap, forms: bool) {
    if map.hosts.is_empty() && map.out_of_scope.is_empty() {
        println!("No traffic captured yet — nothing to map.");
        println!();
        println!("Capture some through the proxy, or run `nullhawk crawl <project>`, then");
        println!("come back here to see what was reached.");
        return;
    }

    for host in &map.hosts {
        let scheme = if host.secure { "https" } else { "http" };
        println!("{scheme}://{}", host.host);
        for path in &host.paths {
            let mut line = format!("  {:<40} {}", path.path, path.methods.join(","));
            if !path.statuses.is_empty() {
                let statuses: Vec<String> = path.statuses.iter().map(|s| s.to_string()).collect();
                line.push_str(&format!("  [{}]", statuses.join(",")));
            }
            if !path.identities.is_empty() {
                line.push_str(&format!("  as: {}", path.identities.join(", ")));
            }
            println!("{line}");
        }
        if forms && !host.forms.is_empty() {
            println!("  forms (discovered, never submitted):");
            for form in &host.forms {
                println!("    {} {}", form.method, form.action);
            }
        }
        println!();
    }

    if !map.out_of_scope.is_empty() {
        println!(
            "Out of scope ({}) — seen, never part of the map:",
            map.out_of_scope.len()
        );
        for url in &map.out_of_scope {
            println!("  {url}");
        }
        println!();
    }

    let form_total: usize = map.hosts.iter().map(|h| h.forms.len()).sum();
    print!("{} host(s), {} path(s)", map.hosts.len(), map.path_count());
    if forms {
        print!(", {form_total} form(s) found");
    } else {
        print!(" (pass --forms to also list discovered forms)");
    }
    println!(".");
}

fn print_json(map: &SiteMap) {
    let hosts: Vec<_> = map
        .hosts
        .iter()
        .map(|host| {
            serde_json::json!({
                "host": host.host,
                "secure": host.secure,
                "paths": host.paths.iter().map(|p| serde_json::json!({
                    "path": p.path,
                    "methods": p.methods,
                    "statuses": p.statuses,
                    "identities": p.identities,
                })).collect::<Vec<_>>(),
                "forms": host.forms.iter().map(|f| serde_json::json!({
                    "action": f.action,
                    "method": f.method,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "hosts": hosts,
            "out_of_scope": map.out_of_scope,
            "host_count": map.hosts.len(),
            "path_count": map.path_count(),
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_is_read_case_insensitively_from_a_raw_header_block() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nX: y\r\n";
        assert_eq!(content_type_of(raw), "text/html; charset=utf-8");
        assert_eq!(
            content_type_of(b"content-type:application/json\n"),
            "application/json"
        );
        assert_eq!(content_type_of(b"Server: nginx\r\n"), "");
    }

    #[test]
    fn host_filter_matches_bare_host_and_authority() {
        assert!(matches_host("https://a.test/x", "a.test"));
        assert!(matches_host("https://a.test:8443/x", "a.test:8443"));
        assert!(matches_host("https://a.test:8443/x", "a.test"));
        assert!(!matches_host("https://b.test/x", "a.test"));
        assert!(!matches_host("not a url", "a.test"));
    }
}

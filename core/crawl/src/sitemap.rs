//! # The site map (CR.e)
//!
//! The coverage answer, made visible. A crawl (and every other capture) leaves the
//! project holding a pile of exchanges; this turns that pile into a host → path tree a
//! tester can read: what was fetched, under which methods and statuses, which identity
//! reached each path, what is out of scope, and — reusing CR.a — what forms were
//! discovered but never submitted.
//!
//! ## It sends nothing
//!
//! Like CR.a, this is pure: it is built from captured pages and a scope, and it opens no
//! connection. The same function feeds the CLI and (later) the desktop window, so the two
//! surfaces cannot disagree about what coverage a project has.

use std::collections::{BTreeMap, BTreeSet};

use hexora_types::http::HttpService;
use hexora_types::scope::Scope;

use crate::{extract, LinkSource};

/// One captured exchange the site map is built from. The body and content type are only
/// needed to find forms; a caller that does not want the form view can leave them empty.
#[derive(Debug, Clone)]
pub struct CapturedPage {
    /// The absolute URL that was requested.
    pub url: String,
    /// The request method.
    pub method: String,
    /// The response status, when one was received.
    pub status: Option<u16>,
    /// The label of the identity the request was sent as, when it was sent as one.
    pub identity: Option<String>,
    /// The response's `Content-Type`, for deciding whether to read forms.
    pub content_type: String,
    /// The response body, for form discovery. Empty when the caller is not building the
    /// form view.
    pub body: Vec<u8>,
}

/// One path under a host, and everything seen about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathEntry {
    /// The request target (path plus query).
    pub path: String,
    /// The methods this path was requested with.
    pub methods: Vec<String>,
    /// The response statuses seen for it.
    pub statuses: Vec<u16>,
    /// The identities that reached it, by label.
    pub identities: Vec<String>,
}

/// A form discovered on a host — found, never submitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormEntry {
    /// The form's action, resolved to an absolute URL.
    pub action: String,
    /// The method it declared (uppercased).
    pub method: String,
}

/// Everything captured for one host (authority), as a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMap {
    /// The authority — host, plus port when it is not the scheme default.
    pub host: String,
    /// Whether it was reached over TLS.
    pub secure: bool,
    /// The paths fetched under it, sorted.
    pub paths: Vec<PathEntry>,
    /// The forms discovered under it, sorted.
    pub forms: Vec<FormEntry>,
}

/// The coverage a project holds: the in-scope host tree, and the out-of-scope URLs seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiteMap {
    /// In-scope hosts, sorted by authority.
    pub hosts: Vec<HostMap>,
    /// URLs that were captured but are out of the project's scope, deduplicated and sorted.
    pub out_of_scope: Vec<String>,
}

/// Accumulates one path's facts before it is frozen into a [`PathEntry`].
#[derive(Default)]
struct PathAcc {
    methods: BTreeSet<String>,
    statuses: BTreeSet<u16>,
    identities: BTreeSet<String>,
}

/// Accumulates one host's facts.
struct HostAcc {
    secure: bool,
    paths: BTreeMap<String, PathAcc>,
    forms: BTreeSet<(String, String)>, // (action, method)
}

impl SiteMap {
    /// Builds the coverage tree from captured pages and the project's scope.
    ///
    /// An in-scope page joins its host's tree; an out-of-scope one is recorded in
    /// [`Self::out_of_scope`] and never grafted onto the tree — the same distinction the
    /// crawler draws, made visible. A page whose URL cannot be parsed is dropped: it was
    /// never a real target.
    pub fn build(pages: impl IntoIterator<Item = CapturedPage>, scope: &Scope) -> Self {
        let mut hosts: BTreeMap<String, HostAcc> = BTreeMap::new();
        let mut out_of_scope: BTreeSet<String> = BTreeSet::new();

        for page in pages {
            let Ok((service, path)) = HttpService::parse_url(&page.url) else {
                continue;
            };
            if !scope.contains(&service, &path) {
                out_of_scope.insert(page.url.clone());
                continue;
            }

            let host = hosts.entry(service.authority()).or_insert_with(|| HostAcc {
                secure: service.secure,
                paths: BTreeMap::new(),
                forms: BTreeSet::new(),
            });

            let entry = host.paths.entry(path).or_default();
            entry.methods.insert(page.method.to_ascii_uppercase());
            if let Some(status) = page.status {
                entry.statuses.insert(status);
            }
            if let Some(identity) = &page.identity {
                entry.identities.insert(identity.clone());
            }

            // Forms are discovered, never submitted — so the map is where a tester sees
            // them. Only HTML bodies carry them, and only when the caller supplied one.
            if !page.body.is_empty() && page.content_type.to_ascii_lowercase().contains("html") {
                for link in extract(&page.url, &page.content_type, &page.body) {
                    if link.source == LinkSource::FormAction {
                        let method = link.method.unwrap_or_else(|| "GET".to_string());
                        host.forms.insert((link.url, method));
                    }
                }
            }
        }

        let hosts = hosts
            .into_iter()
            .map(|(authority, acc)| HostMap {
                host: authority,
                secure: acc.secure,
                paths: acc
                    .paths
                    .into_iter()
                    .map(|(path, p)| PathEntry {
                        path,
                        methods: p.methods.into_iter().collect(),
                        statuses: p.statuses.into_iter().collect(),
                        identities: p.identities.into_iter().collect(),
                    })
                    .collect(),
                forms: acc
                    .forms
                    .into_iter()
                    .map(|(action, method)| FormEntry { action, method })
                    .collect(),
            })
            .collect();

        Self {
            hosts,
            out_of_scope: out_of_scope.into_iter().collect(),
        }
    }

    /// The total number of distinct in-scope paths across all hosts.
    pub fn path_count(&self) -> usize {
        self.hosts.iter().map(|h| h.paths.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexora_types::scope::{Scope, ScopeRule};

    fn page(url: &str, method: &str, status: u16, identity: Option<&str>) -> CapturedPage {
        CapturedPage {
            url: url.to_string(),
            method: method.to_string(),
            status: Some(status),
            identity: identity.map(|s| s.to_string()),
            content_type: String::new(),
            body: Vec::new(),
        }
    }

    fn scoped() -> Scope {
        Scope::new().include(ScopeRule::host("a.test"))
    }

    #[test]
    fn builds_a_host_path_tree_with_methods_statuses_and_identities() {
        let pages = vec![
            page("https://a.test/", "GET", 200, None),
            page("https://a.test/admin", "GET", 200, Some("admin")),
            page("https://a.test/admin", "POST", 403, Some("guest")),
        ];
        let map = SiteMap::build(pages, &scoped());

        assert_eq!(map.hosts.len(), 1);
        let host = &map.hosts[0];
        assert_eq!(host.host, "a.test");
        assert!(host.secure);
        assert_eq!(map.path_count(), 2);

        let admin = host.paths.iter().find(|p| p.path == "/admin").unwrap();
        assert_eq!(admin.methods, vec!["GET", "POST"]);
        assert_eq!(admin.statuses, vec![200, 403]);
        assert_eq!(admin.identities, vec!["admin", "guest"]);
    }

    #[test]
    fn out_of_scope_pages_are_listed_not_grafted_onto_the_tree() {
        let pages = vec![
            page("https://a.test/", "GET", 200, None),
            page("https://evil.test/x", "GET", 200, None),
        ];
        let map = SiteMap::build(pages, &scoped());

        assert_eq!(map.hosts.len(), 1);
        assert_eq!(map.out_of_scope, vec!["https://evil.test/x"]);
    }

    #[test]
    fn forms_are_discovered_from_html_bodies() {
        let mut p = page("https://a.test/login", "GET", 200, None);
        p.content_type = "text/html".to_string();
        p.body = br#"<form action="/session" method="post"><input name="pw"></form>"#.to_vec();
        let map = SiteMap::build(vec![p], &scoped());

        let host = &map.hosts[0];
        assert_eq!(host.forms.len(), 1);
        assert_eq!(host.forms[0].action, "https://a.test/session");
        assert_eq!(host.forms[0].method, "POST");
    }

    #[test]
    fn a_port_becomes_part_of_the_host_key() {
        let pages = vec![page("https://a.test:8443/", "GET", 200, None)];
        let scope = Scope::new().include(ScopeRule::host("a.test").with_ports([8443]));
        let map = SiteMap::build(pages, &scope);
        assert_eq!(map.hosts[0].host, "a.test:8443");
    }
}

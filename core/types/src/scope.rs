//! Project scope: the set of hosts and paths Hexora is authorized to test.
//!
//! Scope is a **safety control**, not a convenience filter. Automated subsystems —
//! scanner, fuzzer, workflows, AI tools — must not send traffic to a target that is
//! not in scope; the engine boundary enforces this and returns
//! [`crate::error::HexoraError::OutOfScope`]. See `docs/security-invariants.md`,
//! invariant 1.
//!
//! # Design decisions
//!
//! **Deny wins.** An exclusion always beats an inclusion, so a tester can carve
//! `/logout` or `/admin/delete` out of an otherwise in-scope host and trust it.
//!
//! **Empty means nothing.** A scope with no rules matches nothing, rather than
//! everything. A freshly created or misconfigured project must not become a licence
//! to scan the internet.
//!
//! **Match both forms.** A path is compared in both its raw and its normalized form,
//! and an exclusion matching *either* wins. `/admin`, `/%61dmin` and `/x/../admin`
//! reach the same handler on most servers, so a scope that blocked only the literal
//! spelling would be trivially bypassed by a payload generator.
//!
//! **Wildcards never cover IP literals.** `*.example.com` matches subdomains only,
//! and no host pattern containing a wildcard matches a bare address. Authorization
//! for a hostname does not extend to whatever address it currently resolves to.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::http::HttpService;

/// How a scope rule matches a request path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PathMatch {
    /// Matches every path on the host.
    Any,
    /// Matches paths starting with this prefix.
    Prefix {
        /// The prefix, e.g. `/api/`.
        value: String,
    },
    /// Matches this exact path, ignoring the query string.
    Exact {
        /// The full path, e.g. `/api/v1/users`.
        value: String,
    },
}

impl PathMatch {
    /// Whether this pattern matches a single already-prepared path form.
    fn matches_form(&self, path: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Prefix { value } => path.starts_with(value.as_str()),
            Self::Exact { value } => path == value,
        }
    }
}

/// Which transport a rule applies to.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemeMatch {
    #[default]
    Any,
    HttpOnly,
    HttpsOnly,
}

impl SchemeMatch {
    fn matches(&self, secure: bool) -> bool {
        match self {
            Self::Any => true,
            Self::HttpOnly => !secure,
            Self::HttpsOnly => secure,
        }
    }
}

/// One scope rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRule {
    /// Host pattern: an exact hostname, an IP literal, or `*.example.com`.
    pub host: String,
    /// Which ports the rule covers. Empty means any port.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Whether the rule applies to plaintext, TLS, or both.
    #[serde(default)]
    pub scheme: SchemeMatch,
    /// Which paths the rule covers.
    pub path: PathMatch,
}

impl ScopeRule {
    /// A rule covering every path on a host, on any port and scheme.
    pub fn host(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            ports: Vec::new(),
            scheme: SchemeMatch::Any,
            path: PathMatch::Any,
        }
    }

    /// Restricts this rule to a path prefix.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path = PathMatch::Prefix {
            value: prefix.into(),
        };
        self
    }

    /// Restricts this rule to an exact path.
    pub fn with_exact_path(mut self, path: impl Into<String>) -> Self {
        self.path = PathMatch::Exact { value: path.into() };
        self
    }

    /// Restricts this rule to specific ports.
    pub fn with_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.ports = ports.into_iter().collect();
        self
    }

    /// Restricts this rule to one transport.
    pub fn with_scheme(mut self, scheme: SchemeMatch) -> Self {
        self.scheme = scheme;
        self
    }

    /// Whether this rule covers the given service and path.
    ///
    /// The path is tested in both raw and normalized form; matching either counts.
    /// For an inclusion that is slightly permissive, for an exclusion it is what
    /// makes the exclusion hold against encoding tricks.
    pub fn matches(&self, service: &HttpService, path: &str) -> bool {
        if !self.matches_host(&service.host) {
            return false;
        }
        if !self.ports.is_empty() && !self.ports.contains(&service.port) {
            return false;
        }
        if !self.scheme.matches(service.secure) {
            return false;
        }
        let raw = strip_query(path);
        if self.path.matches_form(raw) {
            return true;
        }
        let normalized = normalize_path(raw);
        self.path.matches_form(&normalized)
    }

    fn matches_host(&self, host: &str) -> bool {
        let host = normalize_host(host);
        let pattern = normalize_host(&self.host);

        match pattern.strip_prefix("*.") {
            Some(suffix) => {
                // A wildcard is a *name* pattern. Letting it match an address literal
                // would mean a scope for *.example.com silently authorized whatever
                // 203.0.113.10 happens to be today.
                if is_ip_literal(&host) {
                    return false;
                }
                // Must be a strictly deeper label: the apex is not covered, and
                // "notexample.com" must not match "*.example.com".
                host.len() > suffix.len() + 1
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
            None => {
                if let (Some(a), Some(b)) = (parse_ip(&host), parse_ip(&pattern)) {
                    // Compare addresses numerically so 127.0.0.1 and ::ffff:127.0.0.1,
                    // or ::1 and 0:0:0:0:0:0:0:1, are recognised as the same host.
                    return a == b;
                }
                host == pattern
            }
        }
    }
}

/// The complete scope of a project.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// Hosts and paths the tester is authorized to touch.
    #[serde(default)]
    pub include: Vec<ScopeRule>,
    /// Carve-outs that override [`Scope::include`].
    #[serde(default)]
    pub exclude: Vec<ScopeRule>,
}

impl Scope {
    /// An empty scope. Nothing is in scope until a rule is added.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an inclusion rule.
    pub fn include(mut self, rule: ScopeRule) -> Self {
        self.include.push(rule);
        self
    }

    /// Adds an exclusion rule, which takes precedence over every inclusion.
    pub fn exclude(mut self, rule: ScopeRule) -> Self {
        self.exclude.push(rule);
        self
    }

    /// Whether Hexora is authorized to send this request.
    ///
    /// Exclusions are evaluated first and are absolute.
    pub fn contains(&self, service: &HttpService, path: &str) -> bool {
        if self.exclude.iter().any(|r| r.matches(service, path)) {
            return false;
        }
        self.include.iter().any(|r| r.matches(service, path))
    }

    /// Whether any rule has been configured.
    ///
    /// The UI uses this to warn that an empty scope blocks all automated testing,
    /// rather than appearing to work while silently doing nothing.
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Normalization helpers
// ---------------------------------------------------------------------------

/// Lowercases a host, strips a fully-qualified trailing dot, and unwraps the brackets
/// around an IPv6 literal.
fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

fn parse_ip(host: &str) -> Option<std::net::IpAddr> {
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Some(std::net::IpAddr::V4(v4));
    }
    let v6 = host.parse::<Ipv6Addr>().ok()?;
    // Treat an IPv4-mapped address as the IPv4 address it represents, so a rule
    // written either way covers both spellings.
    match v6.to_ipv4_mapped() {
        Some(v4) => Some(std::net::IpAddr::V4(v4)),
        None => Some(std::net::IpAddr::V6(v6)),
    }
}

fn is_ip_literal(host: &str) -> bool {
    parse_ip(host).is_some()
}

fn strip_query(path: &str) -> &str {
    let end = path.find(['?', '#']).unwrap_or(path.len());
    &path[..end]
}

/// Percent-decodes a path and removes `.`/`..` segments and empty segments.
///
/// This is the form an origin server is most likely to have resolved the request to,
/// so exclusions are checked against it as well as against the literal path.
/// Percent-encoded `/` (`%2f`) is decoded *before* segment splitting deliberately:
/// the aim is to see through the encoding, not to reproduce any one server's
/// behaviour exactly.
fn normalize_path(path: &str) -> String {
    let decoded = percent_decode(path);
    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut out = String::with_capacity(decoded.len());
    for segment in &segments {
        out.push('/');
        out.push_str(segment);
    }
    // Two cases need a trailing slash for the same reason — the normalized form must
    // still name a directory-ish path: an empty result is the root, and a path that
    // ended in a slash keeps it so `/a/` does not collapse into `/a`.
    if out.is_empty() || decoded.ends_with('/') {
        out.push('/');
    }
    out
}

/// Decodes `%XX` escapes. Invalid escapes are left as literal text, which is what
/// permissive servers do and is the conservative choice for a security control.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            match (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push(hi << 4 | lo);
                    i += 3;
                    continue;
                }
                _ => { /* malformed escape: fall through and keep the '%' */ }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Paths are byte strings; anything that is not valid UTF-8 is kept lossily,
    // which is fine because the result is only ever compared, never sent.
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn https(host: &str) -> HttpService {
        HttpService::new(host, 443, true)
    }

    #[test]
    fn empty_scope_denies_everything() {
        let scope = Scope::new();
        assert!(!scope.contains(&https("example.com"), "/"));
        assert!(scope.is_empty());
    }

    #[test]
    fn exact_host_rule_matches_only_that_host() {
        let scope = Scope::new().include(ScopeRule::host("example.com"));
        assert!(scope.contains(&https("example.com"), "/anything"));
        assert!(!scope.contains(&https("evil.com"), "/"));
        assert!(!scope.contains(&https("api.example.com"), "/"));
    }

    #[test]
    fn host_matching_ignores_case_and_a_trailing_dot() {
        let scope = Scope::new().include(ScopeRule::host("Example.COM"));
        assert!(scope.contains(&https("example.com"), "/"));
        assert!(scope.contains(&https("EXAMPLE.com."), "/"));
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_the_apex() {
        let scope = Scope::new().include(ScopeRule::host("*.example.com"));
        assert!(scope.contains(&https("api.example.com"), "/"));
        assert!(scope.contains(&https("a.b.example.com"), "/"));
        assert!(!scope.contains(&https("example.com"), "/"));
    }

    #[test]
    fn wildcard_does_not_match_a_suffix_lookalike_domain() {
        let scope = Scope::new().include(ScopeRule::host("*.example.com"));
        assert!(!scope.contains(&https("notexample.com"), "/"));
        assert!(!scope.contains(&https("evil-example.com"), "/"));
        assert!(!scope.contains(&https("example.com.evil.net"), "/"));
    }

    #[test]
    fn wildcard_never_covers_an_ip_literal() {
        let scope = Scope::new().include(ScopeRule::host("*.example.com"));
        assert!(!scope.contains(&https("203.0.113.10"), "/"));
        assert!(!scope.contains(&https("::1"), "/"));
    }

    #[test]
    fn ipv4_literals_match_exactly() {
        let scope = Scope::new().include(ScopeRule::host("127.0.0.1"));
        assert!(scope.contains(&https("127.0.0.1"), "/"));
        assert!(!scope.contains(&https("127.0.0.2"), "/"));
    }

    #[test]
    fn ipv6_literals_match_regardless_of_spelling_or_brackets() {
        let scope = Scope::new().include(ScopeRule::host("::1"));
        assert!(scope.contains(&https("::1"), "/"));
        assert!(scope.contains(&https("[::1]"), "/"));
        assert!(scope.contains(&https("0:0:0:0:0:0:0:1"), "/"));
        assert!(!scope.contains(&https("::2"), "/"));
    }

    #[test]
    fn ipv4_mapped_ipv6_is_the_same_host_as_the_ipv4_address() {
        let scope = Scope::new().include(ScopeRule::host("127.0.0.1"));
        assert!(scope.contains(&https("::ffff:127.0.0.1"), "/"));
    }

    #[test]
    fn exclusions_override_inclusions() {
        let scope = Scope::new()
            .include(ScopeRule::host("example.com"))
            .exclude(ScopeRule::host("example.com").with_prefix("/logout"));
        assert!(scope.contains(&https("example.com"), "/account"));
        assert!(!scope.contains(&https("example.com"), "/logout"));
        assert!(!scope.contains(&https("example.com"), "/logout?next=/"));
    }

    #[test]
    fn exclusion_wins_even_when_added_before_the_inclusion() {
        let scope = Scope::new()
            .exclude(ScopeRule::host("example.com").with_prefix("/admin"))
            .include(ScopeRule::host("example.com"));
        assert!(!scope.contains(&https("example.com"), "/admin/delete"));
    }

    #[test]
    fn an_exclusion_cannot_be_bypassed_with_percent_encoding() {
        let scope = Scope::new()
            .include(ScopeRule::host("example.com"))
            .exclude(ScopeRule::host("example.com").with_prefix("/admin"));
        assert!(!scope.contains(&https("example.com"), "/%61dmin"));
        assert!(!scope.contains(&https("example.com"), "/%61%64%6d%69%6e/delete"));
    }

    #[test]
    fn an_exclusion_cannot_be_bypassed_with_dot_segments() {
        let scope = Scope::new()
            .include(ScopeRule::host("example.com"))
            .exclude(ScopeRule::host("example.com").with_prefix("/admin"));
        assert!(!scope.contains(&https("example.com"), "/public/../admin"));
        assert!(!scope.contains(&https("example.com"), "/./admin"));
        assert!(!scope.contains(&https("example.com"), "//admin"));
    }

    #[test]
    fn an_exclusion_cannot_be_bypassed_with_an_encoded_slash() {
        let scope = Scope::new()
            .include(ScopeRule::host("example.com"))
            .exclude(ScopeRule::host("example.com").with_prefix("/admin"));
        assert!(!scope.contains(&https("example.com"), "/%2fadmin"));
    }

    #[test]
    fn a_malformed_percent_escape_does_not_panic() {
        let scope = Scope::new().include(ScopeRule::host("example.com"));
        for path in ["/%", "/%z", "/%2", "/%%%", "/%ff%fe"] {
            let _ = scope.contains(&https("example.com"), path);
        }
    }

    #[test]
    fn port_restrictions_are_enforced() {
        let scope = Scope::new().include(ScopeRule::host("example.com").with_ports([8080]));
        assert!(scope.contains(&HttpService::new("example.com", 8080, false), "/"));
        assert!(!scope.contains(&https("example.com"), "/"));
    }

    #[test]
    fn scheme_restrictions_are_enforced() {
        let scope = Scope::new()
            .include(ScopeRule::host("example.com").with_scheme(SchemeMatch::HttpsOnly));
        assert!(scope.contains(&https("example.com"), "/"));
        assert!(!scope.contains(&HttpService::new("example.com", 80, false), "/"));
    }

    #[test]
    fn exact_path_ignores_the_query_and_fragment() {
        let scope =
            Scope::new().include(ScopeRule::host("example.com").with_exact_path("/api/v1/users"));
        assert!(scope.contains(&https("example.com"), "/api/v1/users?page=2"));
        assert!(scope.contains(&https("example.com"), "/api/v1/users#top"));
        assert!(!scope.contains(&https("example.com"), "/api/v1/users/1"));
    }

    #[test]
    fn normalization_preserves_a_trailing_slash() {
        assert_eq!(normalize_path("/a/b/"), "/a/b/");
        assert_eq!(normalize_path("/a/b"), "/a/b");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "/");
    }

    #[test]
    fn normalization_cannot_escape_above_the_root() {
        assert_eq!(normalize_path("/../../etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn percent_decoding_leaves_malformed_escapes_alone() {
        assert_eq!(percent_decode("/a%zz"), "/a%zz");
        assert_eq!(percent_decode("/a%2"), "/a%2");
        assert_eq!(percent_decode("/a%2Fb"), "/a/b");
    }
}

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// The core safety property: whatever the rules and whatever the path, an
        /// excluded request is never reported as in scope.
        #[test]
        fn exclusion_always_beats_inclusion(
            host in "[a-z]{1,8}\\.(com|net)",
            path in "(/[a-zA-Z0-9%._~-]{0,8}){0,4}",
        ) {
            let scope = Scope::new()
                .include(ScopeRule::host(host.clone()))
                .exclude(ScopeRule::host(host.clone()));
            prop_assert!(!scope.contains(&HttpService::new(host, 443, true), &path));
        }

        /// Normalization is idempotent, so a second pass cannot reveal a path form
        /// the first pass missed.
        #[test]
        fn normalization_is_idempotent(path in "(/[a-zA-Z0-9%._~-]{0,8}){0,5}") {
            let once = normalize_path(&path);
            prop_assert_eq!(normalize_path(&once), once.clone());
        }

        /// Normalization never leaves a dot segment behind.
        #[test]
        fn normalization_removes_all_dot_segments(path in "(/(\\.|\\.\\.|[a-z]{1,4})){0,6}") {
            let normalized = normalize_path(&path);
            for segment in normalized.split('/') {
                prop_assert!(segment != "." && segment != "..", "left {segment:?} in {normalized:?}");
            }
        }

        /// Scope matching must not panic on arbitrary input; a hostile target
        /// controls the paths that reach it.
        #[test]
        fn matching_never_panics(path in ".{0,64}") {
            let scope = Scope::new()
                .include(ScopeRule::host("example.com"))
                .exclude(ScopeRule::host("example.com").with_prefix("/admin"));
            let _ = scope.contains(&HttpService::new("example.com", 443, true), &path);
        }
    }
}

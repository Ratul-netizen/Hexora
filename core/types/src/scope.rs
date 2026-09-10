//! Project scope: the set of hosts and paths Hexora is authorized to test.
//!
//! Scope is a **safety control**, not a convenience filter. Automated subsystems —
//! scanner, fuzzer, workflows, AI tools — refuse to send traffic to a target that is
//! not in scope, and the engine returns [`crate::error::HexoraError::OutOfScope`].
//!
//! Two design decisions matter here:
//!
//! 1. **Deny wins.** An exclusion always beats an inclusion, so a tester can carve a
//!    `/logout` or `/admin/delete` endpoint out of an otherwise in-scope host and
//!    trust it.
//! 2. **Empty scope means nothing is in scope**, not everything. A misconfigured or
//!    freshly created project must not become a licence to scan the internet.
//!
//! Host matching supports a single leading `*.` wildcard, which matches subdomains
//! but *not* the apex — `*.example.com` does not match `example.com`, because
//! authorization for a subdomain often does not extend to the parent.

use serde::{Deserialize, Serialize};

use crate::http::HttpService;

/// How a scope rule matches a request path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PathMatch {
    /// Matches every path on the host.
    Any,
    /// Matches paths starting with this prefix.
    Prefix { value: String },
    /// Matches this exact path, ignoring the query string.
    Exact { value: String },
}

impl PathMatch {
    fn matches(&self, path: &str) -> bool {
        let without_query = path.split('?').next().unwrap_or(path);
        match self {
            Self::Any => true,
            Self::Prefix { value } => without_query.starts_with(value.as_str()),
            Self::Exact { value } => without_query == value,
        }
    }
}

/// One scope rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRule {
    /// Host pattern: an exact hostname, or `*.example.com` for subdomains.
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

/// Which transport a rule applies to.
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
        self.path = PathMatch::Prefix { value: prefix.into() };
        self
    }

    /// Restricts this rule to specific ports.
    pub fn with_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.ports = ports.into_iter().collect();
        self
    }

    /// Whether this rule covers the given service and path.
    pub fn matches(&self, service: &HttpService, path: &str) -> bool {
        self.matches_host(&service.host)
            && (self.ports.is_empty() || self.ports.contains(&service.port))
            && self.scheme.matches(service.secure)
            && self.path.matches(path)
    }

    fn matches_host(&self, host: &str) -> bool {
        match self.host.strip_prefix("*.") {
            // A subdomain wildcard matches any deeper label, never the apex itself.
            Some(suffix) => {
                host.len() > suffix.len() + 1
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
            None => self.host.eq_ignore_ascii_case(host),
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
    /// rather than silently doing nothing.
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
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
    fn host_matching_is_case_insensitive() {
        let scope = Scope::new().include(ScopeRule::host("Example.COM"));
        assert!(scope.contains(&https("example.com"), "/"));
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
        // The classic bypass: attacker registers notexample.com
        assert!(!scope.contains(&https("notexample.com"), "/"));
        assert!(!scope.contains(&https("evil-example.com"), "/"));
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
    fn port_restrictions_are_enforced() {
        let scope = Scope::new().include(ScopeRule::host("example.com").with_ports([8080]));
        assert!(scope.contains(&HttpService::new("example.com", 8080, false), "/"));
        assert!(!scope.contains(&https("example.com"), "/"));
    }

    #[test]
    fn scheme_restrictions_are_enforced() {
        let mut rule = ScopeRule::host("example.com");
        rule.scheme = SchemeMatch::HttpsOnly;
        let scope = Scope::new().include(rule);
        assert!(scope.contains(&https("example.com"), "/"));
        assert!(!scope.contains(&HttpService::new("example.com", 80, false), "/"));
    }

    #[test]
    fn exact_path_ignores_the_query_string() {
        let mut rule = ScopeRule::host("example.com");
        rule.path = PathMatch::Exact { value: "/api/v1/users".into() };
        let scope = Scope::new().include(rule);
        assert!(scope.contains(&https("example.com"), "/api/v1/users?page=2"));
        assert!(!scope.contains(&https("example.com"), "/api/v1/users/1"));
    }
}

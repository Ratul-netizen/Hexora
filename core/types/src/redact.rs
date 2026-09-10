//! Secret redaction.
//!
//! Hexora handles credentials for a living: session cookies, bearer tokens, API keys
//! and client certificates all flow through the engine. The threat model
//! (`docs/threat-model.md`) requires that none of this reaches logs, crash reports,
//! telemetry or exported reports unless the user explicitly opts in.
//!
//! The mechanism is [`Secret<T>`]: a wrapper whose `Debug` and `Display`
//! implementations print a placeholder. Getting the real value requires calling
//! [`Secret::expose`], which is greppable in review.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Header names whose values are redacted by default in logs and exports.
///
/// Compared case-insensitively. This is a floor, not a ceiling: the value-based
/// detector in the scanner catches secrets in headers not listed here.
pub const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
    "x-goog-api-key",
    "authentication",
    "www-authenticate",
    "proxy-authenticate",
];

/// The placeholder substituted for a redacted value.
pub const REDACTED: &str = "<redacted>";

/// Returns whether a header name is redacted by default.
pub fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name))
}

/// A value that must not appear in logs, `Debug` output or error messages.
///
/// `Secret` deliberately does not implement `Display`. To read the inner value you
/// must call [`Secret::expose`], which makes every read auditable with a single grep.
///
/// ```
/// use hexora_types::redact::Secret;
/// let token = Secret::new("hunter2".to_string());
/// assert_eq!(format!("{token:?}"), "<redacted>");
/// assert_eq!(token.expose(), "hunter2");
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wraps a value as secret.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Reveals the inner value.
    ///
    /// Every call site is a place where a secret can escape. Keep them few, keep
    /// them close to the point of use, and never pass the result to a logger.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper and returns the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// How aggressively to redact when rendering traffic outside the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionPolicy {
    /// Redact known-sensitive headers only. The default for logs and reports.
    #[default]
    SensitiveHeaders,
    /// Redact known-sensitive headers plus anything the secret detector flags.
    Aggressive,
    /// No redaction. Only reachable when the user explicitly opts in per export.
    Disabled,
}

impl RedactionPolicy {
    /// Applies this policy to a single header, returning the value to render.
    pub fn apply_header<'a>(&self, name: &str, value: &'a str) -> &'a str {
        match self {
            Self::Disabled => value,
            Self::SensitiveHeaders | Self::Aggressive => {
                if is_sensitive_header(name) {
                    REDACTED
                } else {
                    value
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_never_leaks_the_value() {
        let s = Secret::new("super-secret-token".to_string());
        let rendered = format!("{s:?}");
        assert_eq!(rendered, REDACTED);
        assert!(!rendered.contains("super-secret-token"));
    }

    #[test]
    fn secret_nested_in_a_struct_still_redacts() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Creds {
            user: String,
            password: Secret<String>,
        }
        let c = Creds { user: "admin".into(), password: Secret::new("p4ssw0rd".into()) };
        let rendered = format!("{c:?}");
        assert!(rendered.contains("admin"));
        assert!(!rendered.contains("p4ssw0rd"), "{rendered}");
    }

    #[test]
    fn sensitive_header_matching_is_case_insensitive() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("AUTHORIZATION"));
        assert!(is_sensitive_header("set-cookie"));
        assert!(!is_sensitive_header("content-type"));
    }

    #[test]
    fn default_policy_redacts_auth_but_keeps_content_type() {
        let p = RedactionPolicy::default();
        assert_eq!(p.apply_header("Authorization", "Bearer abc"), REDACTED);
        assert_eq!(p.apply_header("Content-Type", "application/json"), "application/json");
    }

    #[test]
    fn disabled_policy_passes_values_through() {
        let p = RedactionPolicy::Disabled;
        assert_eq!(p.apply_header("Authorization", "Bearer abc"), "Bearer abc");
    }
}

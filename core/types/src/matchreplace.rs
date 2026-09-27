//! Match-and-replace rules: rewrite proxied traffic by rule (M7).
//!
//! A rule names a part of the exchange it acts on, a pattern to find, and what to put in its
//! place. The proxy applies enabled rules to in-scope traffic — request rules on the way out,
//! response rules on the way back. This module is only the *data*: the pattern is a plain
//! string here, and compiling it (and applying it) lives in the proxy, so the low-level types
//! crate stays free of a regex engine.
//!
//! # What a rule can reach
//!
//! [`RuleTarget`] deliberately mirrors Burp's five everyday targets rather than every field an
//! exchange has. A tester who knows Burp already knows these; anything finer is a job for an
//! extension, not a built-in rule.
//!
//! # Add, and remove
//!
//! An empty pattern on a header target is "add this header" (there is nothing to match, so the
//! replacement is simply appended). An empty replacement is "remove what matched". Both are the
//! conventions Burp established, and a tester reaches for them without thinking.

use serde::{Deserialize, Serialize};

/// The part of an exchange a rule acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleTarget {
    /// The request's header lines. An empty pattern adds the replacement as a new header.
    RequestHeader,
    /// The request body.
    RequestBody,
    /// The request's first line — its method and target (`GET /path`).
    RequestFirstLine,
    /// The response's header lines. An empty pattern adds the replacement as a new header.
    ResponseHeader,
    /// The response body.
    ResponseBody,
}

impl RuleTarget {
    /// Whether this target is part of the request (rather than the response).
    pub fn is_request(self) -> bool {
        matches!(
            self,
            RuleTarget::RequestHeader | RuleTarget::RequestBody | RuleTarget::RequestFirstLine
        )
    }

    /// Whether this target is a header section (where an empty pattern means "add a header").
    pub fn is_header(self) -> bool {
        matches!(self, RuleTarget::RequestHeader | RuleTarget::ResponseHeader)
    }

    /// A short, stable label for reports and the CLI.
    pub fn label(self) -> &'static str {
        match self {
            RuleTarget::RequestHeader => "request header",
            RuleTarget::RequestBody => "request body",
            RuleTarget::RequestFirstLine => "request first line",
            RuleTarget::ResponseHeader => "response header",
            RuleTarget::ResponseBody => "response body",
        }
    }

    /// Parses a target from its CLI spelling (hyphen or underscore, any case).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "request-header" | "req-header" => Some(RuleTarget::RequestHeader),
            "request-body" | "req-body" => Some(RuleTarget::RequestBody),
            "request-first-line" | "request-line" | "req-line" => {
                Some(RuleTarget::RequestFirstLine)
            }
            "response-header" | "resp-header" => Some(RuleTarget::ResponseHeader),
            "response-body" | "resp-body" => Some(RuleTarget::ResponseBody),
            _ => None,
        }
    }

    /// Every target's CLI spelling, for help text and error messages.
    pub fn spellings() -> &'static str {
        "request-header, request-body, request-first-line, response-header, response-body"
    }
}

/// One match-and-replace rule.
///
/// Ordered application matters: rules run in the order they are stored, so a later rule sees the
/// output of an earlier one. `name` is the identity used to remove or toggle a rule, and is kept
/// unique by the code that stores them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchReplaceRule {
    /// A human label, unique within a project.
    pub name: String,
    /// Whether the rule is applied. A disabled rule is kept but skipped.
    pub enabled: bool,
    /// Which part of the exchange it acts on.
    pub target: RuleTarget,
    /// Whether [`pattern`](Self::pattern) is a regular expression rather than a literal.
    pub is_regex: bool,
    /// What to find. Empty, on a header target, means "add the replacement as a new header".
    pub pattern: String,
    /// What to put in its place. Empty means "remove what matched".
    pub replacement: String,
}

impl MatchReplaceRule {
    /// A rule with the given parts, enabled.
    pub fn new(
        name: impl Into<String>,
        target: RuleTarget,
        is_regex: bool,
        pattern: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            target,
            is_regex,
            pattern: pattern.into(),
            replacement: replacement.into(),
        }
    }

    /// A one-line description for the CLI and reports.
    pub fn summary(&self) -> String {
        let how = if self.is_regex { "regex" } else { "literal" };
        let state = if self.enabled { "" } else { " (disabled)" };
        if self.pattern.is_empty() && self.target.is_header() {
            format!(
                "{}{}: add {} header `{}`",
                self.name,
                state,
                self.target.label(),
                self.replacement
            )
        } else if self.replacement.is_empty() {
            format!(
                "{}{}: {} — remove {} matching {} `{}`",
                self.name,
                state,
                self.target.label(),
                self.target.label(),
                how,
                self.pattern
            )
        } else {
            format!(
                "{}{}: {} — {} `{}` -> `{}`",
                self.name,
                state,
                self.target.label(),
                how,
                self.pattern,
                self.replacement
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_round_trip_through_their_cli_spelling() {
        for target in [
            RuleTarget::RequestHeader,
            RuleTarget::RequestBody,
            RuleTarget::RequestFirstLine,
            RuleTarget::ResponseHeader,
            RuleTarget::ResponseBody,
        ] {
            let spelled = target.label().replace(' ', "-");
            assert_eq!(RuleTarget::parse(&spelled), Some(target), "{spelled}");
        }
        assert_eq!(
            RuleTarget::parse("REQUEST_HEADER"),
            Some(RuleTarget::RequestHeader)
        );
        assert_eq!(RuleTarget::parse("nonsense"), None);
    }

    #[test]
    fn a_rule_serialises_and_reads_back() {
        let rule = MatchReplaceRule::new(
            "strip-csp",
            RuleTarget::ResponseHeader,
            false,
            "Content-Security-Policy:",
            "",
        );
        let json = serde_json::to_string(&rule).unwrap();
        let back: MatchReplaceRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn summary_names_the_three_shapes() {
        let add = MatchReplaceRule::new("id", RuleTarget::RequestHeader, false, "", "X-Trace: 1");
        assert!(
            add.summary().contains("add request header"),
            "{}",
            add.summary()
        );

        let remove =
            MatchReplaceRule::new("drop", RuleTarget::ResponseHeader, false, "Server:", "");
        assert!(remove.summary().contains("remove"), "{}", remove.summary());

        let sub = MatchReplaceRule::new("sub", RuleTarget::RequestBody, true, "admin", "guest");
        assert!(sub.summary().contains("-> `guest`"), "{}", sub.summary());
    }
}

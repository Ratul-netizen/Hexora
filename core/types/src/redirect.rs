//! Where a `Location` header would actually send somebody.
//!
//! The naive check is `location.contains(my_value)`, and it is wrong in both
//! directions. These all contain `hexora-probe.invalid`, and only three of them send a
//! browser there:
//!
//! ```text
//! https://hexora-probe.invalid/               → hexora-probe.invalid     taken
//! //hexora-probe.invalid/                     → hexora-probe.invalid     taken
//! https://app.example.com@hexora-probe.invalid → hexora-probe.invalid    taken
//! /redirect?to=https://hexora-probe.invalid   → app.example.com          carried
//! https://app.example.com/?next=hexora-probe.invalid → app.example.com   carried
//! https://hexora-probe.invalid.app.example.com → a fourth host entirely
//! ```
//!
//! So the value is resolved the way a browser resolves it, and the answer is a **host**
//! rather than a substring. A tool that reported the last three as open redirects is a
//! tool whose redirect findings get skipped.
//!
//! # Nothing here follows anything
//!
//! This module reads a header. It has no transport, cannot fetch, and the check built
//! on it never sends a request to a destination a target named — which would mean
//! generating traffic to a host nobody authorized, and doing it *because a target asked
//! for it*. Inspecting the header answers the question; following it is how a scanner
//! ends up somewhere it should not be.
//!
//! # The probe destination never resolves
//!
//! The check uses `.invalid` (RFC 2606), so even a mistake — a browser opened by hand,
//! a library that follows automatically — reaches nothing. It also cannot be
//! registered by anybody, so a redirect Hexora reported last year cannot be turned into
//! a live one by somebody buying the domain.

use serde::{Deserialize, Serialize};

/// How a browser would get to the destination.
///
/// The distinctions are the point: the first three are a caller choosing somebody
/// else's host, and two of them routinely get past filters that only look for `http`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reach {
    /// A path on the host that was asked. The ordinary case.
    SameHost,
    /// A different host, named with a scheme: `https://elsewhere/`.
    Absolute,
    /// A different host, reached with `//elsewhere` — the scheme comes from the page.
    ///
    /// The form most often missed. A filter that rejects anything containing `http`
    /// lets this straight through, and a browser treats it as a full redirect.
    ProtocolRelative,
    /// A different host reached past a `@`: `https://trusted@elsewhere/`.
    ///
    /// Everything before the `@` is userinfo and is not the host, which is exactly why
    /// it defeats a check that looks for its own domain at the start of the value.
    Userinfo,
    /// A scheme that is not `http` or `https`.
    ///
    /// `javascript:` and `data:` in a `Location` are not a redirect to a host; they are
    /// a different problem, and browsers vary in whether they honour them.
    OtherScheme {
        /// The scheme, lowercased.
        scheme: String,
    },
    /// The header could not be read as a destination at all.
    Unreadable,
}

impl Reach {
    /// Whether the caller chose a host other than the one being asked.
    ///
    /// The single question a redirect check exists to answer.
    pub fn leaves_the_host(&self) -> bool {
        matches!(
            self,
            Self::Absolute | Self::ProtocolRelative | Self::Userinfo
        )
    }

    /// How it reads in a finding.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SameHost => "a path on the same host",
            Self::Absolute => "an absolute URL naming another host",
            Self::ProtocolRelative => {
                "a protocol-relative URL (`//host`), which a browser follows as a full \
                 redirect and a filter looking for `http` does not see"
            }
            Self::Userinfo => {
                "a URL whose host sits after an `@`, so the part that looks like the \
                 expected host is userinfo and is not where it goes"
            }
            Self::OtherScheme { .. } => "a scheme that is not http or https",
            Self::Unreadable => "something this check could not read as a destination",
        }
    }
}

/// Where a `Location` value points, resolved against the request it answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    /// The host a browser would end up at, lowercased.
    ///
    /// `None` for a destination with no host — a relative path, or a `javascript:`
    /// URL.
    pub host: Option<String>,
    /// How it gets there.
    pub reach: Reach,
    /// The header value as sent, truncated.
    pub location: String,
}

impl Destination {
    /// Whether this destination is the host `expected`, or somewhere else.
    pub fn stays_on(&self, expected: &str) -> bool {
        match &self.host {
            None => true,
            Some(host) => same_host(host, expected),
        }
    }
}

/// The longest `Location` value quoted back.
const LOCATION_LIMIT: usize = 200;

/// Resolves a `Location` value against the host that produced it.
///
/// `base_host` is the host the request went to. Everything is decided from the value
/// itself and that host; nothing is fetched.
pub fn resolve(base_host: &str, location: &str) -> Destination {
    let raw = truncate(location);
    let value = location.trim();

    if value.is_empty() {
        return Destination {
            host: None,
            reach: Reach::Unreadable,
            location: raw,
        };
    }

    // WHATWG URL parsing treats a backslash as a slash for http(s), so `/\evil.example`
    // is `//evil.example` — a protocol-relative URL — in every current browser. A check
    // that read it as a path would miss one of the most-used filter bypasses there is.
    let normalized: String = value
        .chars()
        .map(|c| if c == '\\' { '/' } else { c })
        .collect();

    // `//host/path`: the scheme comes from the page, the host does not.
    if let Some(rest) = normalized.strip_prefix("//") {
        let (host, reach) = authority_of(rest);
        return finish(host, reach, Reach::ProtocolRelative, base_host, raw);
    }

    if let Some((scheme, rest)) = scheme_of(&normalized) {
        if scheme != "http" && scheme != "https" {
            return Destination {
                host: None,
                reach: Reach::OtherScheme { scheme },
                location: raw,
            };
        }
        let Some(rest) = rest.strip_prefix("//") else {
            // `http:/path` and `http:path` are legal and stay on the host.
            return Destination {
                host: Some(base_host.to_ascii_lowercase()),
                reach: Reach::SameHost,
                location: raw,
            };
        };
        let (host, reach) = authority_of(rest);
        return finish(host, reach, Reach::Absolute, base_host, raw);
    }

    // Everything else is a path, and a path stays where it is.
    Destination {
        host: Some(base_host.to_ascii_lowercase()),
        reach: Reach::SameHost,
        location: raw,
    }
}

/// Builds the destination, collapsing to `SameHost` when it did not actually leave.
///
/// `https://app.example.com/x` served by `app.example.com` is an absolute URL and is
/// not a redirect anywhere: reporting the *form* rather than the *destination* is how
/// a check produces noise.
fn finish(
    host: Option<String>,
    found: Option<Reach>,
    otherwise: Reach,
    base_host: &str,
    raw: String,
) -> Destination {
    let Some(host) = host else {
        return Destination {
            host: None,
            reach: Reach::Unreadable,
            location: raw,
        };
    };
    if same_host(&host, base_host) {
        return Destination {
            host: Some(host),
            reach: Reach::SameHost,
            location: raw,
        };
    }
    Destination {
        host: Some(host),
        reach: found.unwrap_or(otherwise),
        location: raw,
    }
}

/// The host in an authority, and whether it was reached past a `@`.
///
/// The authority ends at the first `/`, `?` or `#`. Userinfo is everything before the
/// **last** `@` in it, which is what a browser does and what makes
/// `https://app.example.com@elsewhere/` go to `elsewhere`.
fn authority_of(rest: &str) -> (Option<String>, Option<Reach>) {
    // Extra leading slashes are skipped rather than ending the authority: for a
    // special scheme the URL parser consumes every `/` and `\` before the host, so
    // `///elsewhere` and `/\/elsewhere` both go to `elsewhere`. A parser that stopped
    // at the first one would read them as paths and miss the bypass.
    let rest = rest.trim_start_matches('/');
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();

    let (host_part, reach) = match authority.rfind('@') {
        Some(at) => (&authority[at + 1..], Some(Reach::Userinfo)),
        None => (authority, None),
    };

    // A port is not part of the host. An IPv6 literal keeps its brackets, so the colon
    // inside it is not mistaken for a port separator.
    let host = if let Some(end) = host_part.strip_prefix('[').and_then(|r| r.find(']')) {
        &host_part[..end + 2]
    } else {
        host_part.split(':').next().unwrap_or_default()
    };

    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return (None, reach);
    }
    (Some(host.to_ascii_lowercase()), reach)
}

/// The scheme of an absolute URL, lowercased, and what follows the colon.
///
/// A scheme is a letter followed by letters, digits, `+`, `-` or `.`. Anything else
/// before a colon is not a scheme — `/redirect?to=https://x` has a colon in it and is
/// a path.
fn scheme_of(value: &str) -> Option<(String, &str)> {
    let colon = value.find(':')?;
    let scheme = &value[..colon];
    let mut chars = scheme.chars();
    if !chars.next()?.is_ascii_alphabetic() {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return None;
    }
    Some((scheme.to_ascii_lowercase(), &value[colon + 1..]))
}

/// Whether two hosts are the same host.
///
/// Exact, case-insensitive, trailing dot ignored. Deliberately **not** a suffix test:
/// `evil.example.com` ends with `example.com` and is a different party's machine, and
/// treating it as the same one is the mistake the attack is built around.
fn same_host(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

fn truncate(value: &str) -> String {
    let value = value.trim();
    if value.chars().count() <= LOCATION_LIMIT {
        return value.to_string();
    }
    let mut cut: String = value.chars().take(LOCATION_LIMIT).collect();
    cut.push('…');
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "app.example.com";

    fn to(location: &str) -> Destination {
        resolve(BASE, location)
    }

    // -----------------------------------------------------------------------
    // Staying put
    // -----------------------------------------------------------------------

    #[test]
    fn a_path_stays_on_the_host() {
        for location in ["/dashboard", "dashboard", "/a/b?c=1#d", "?only=query"] {
            let destination = to(location);
            assert_eq!(destination.reach, Reach::SameHost, "{location}");
            assert!(destination.stays_on(BASE), "{location}");
        }
    }

    #[test]
    fn an_absolute_url_naming_the_same_host_has_not_gone_anywhere() {
        // Reporting the *form* rather than the destination is how a check makes noise.
        let destination = to("https://app.example.com/dashboard");
        assert_eq!(destination.reach, Reach::SameHost);
        assert!(destination.stays_on(BASE));
    }

    #[test]
    fn a_value_merely_carried_in_a_query_string_is_not_a_destination() {
        // The single most common false positive a substring check produces.
        for location in [
            "/redirect?to=https://hexora-probe.invalid",
            "https://app.example.com/login?next=https://hexora-probe.invalid",
            "/?u=//hexora-probe.invalid",
        ] {
            let destination = to(location);
            assert!(
                destination.stays_on(BASE),
                "{location} was read as leaving the host"
            );
            assert!(!destination.reach.leaves_the_host(), "{location}");
        }
    }

    // -----------------------------------------------------------------------
    // Leaving
    // -----------------------------------------------------------------------

    #[test]
    fn an_absolute_url_to_another_host_leaves() {
        let destination = to("https://hexora-probe.invalid/next");
        assert_eq!(destination.reach, Reach::Absolute);
        assert_eq!(destination.host.as_deref(), Some("hexora-probe.invalid"));
        assert!(!destination.stays_on(BASE));
        assert!(destination.reach.leaves_the_host());
    }

    #[test]
    fn a_protocol_relative_url_leaves_and_carries_no_scheme_to_filter_on() {
        // The form a filter rejecting anything containing `http` lets straight through.
        let destination = to("//hexora-probe.invalid/next");
        assert_eq!(destination.reach, Reach::ProtocolRelative);
        assert_eq!(destination.host.as_deref(), Some("hexora-probe.invalid"));
        assert!(!destination.stays_on(BASE));
    }

    #[test]
    fn a_backslash_is_a_slash_to_a_browser() {
        // WHATWG URL parsing normalises `\` to `/` for http(s), so these are
        // protocol-relative. A check that read them as paths would miss a bypass that
        // is in every cheat sheet.
        for location in [
            "/\\hexora-probe.invalid",
            "\\\\hexora-probe.invalid",
            "/\\/hexora-probe.invalid",
        ] {
            let destination = to(location);
            assert!(
                !destination.stays_on(BASE),
                "{location} was read as staying put"
            );
            assert_eq!(
                destination.host.as_deref(),
                Some("hexora-probe.invalid"),
                "{location}"
            );
        }
    }

    #[test]
    fn the_host_is_what_follows_the_last_at_sign() {
        // Everything before `@` is userinfo. This is what defeats a check looking for
        // its own domain at the start of the value.
        let destination = to("https://app.example.com@hexora-probe.invalid/");
        assert_eq!(destination.reach, Reach::Userinfo);
        assert_eq!(destination.host.as_deref(), Some("hexora-probe.invalid"));
        assert!(!destination.stays_on(BASE));

        let destination = to("https://a@b@hexora-probe.invalid/");
        assert_eq!(destination.host.as_deref(), Some("hexora-probe.invalid"));
    }

    #[test]
    fn a_host_that_merely_ends_with_the_expected_one_is_a_different_machine() {
        // The attack the whole comparison exists to survive.
        let destination = to("https://app.example.com.hexora-probe.invalid/");
        assert_eq!(
            destination.host.as_deref(),
            Some("app.example.com.hexora-probe.invalid")
        );
        assert!(!destination.stays_on(BASE));
    }

    #[test]
    fn a_host_that_starts_with_the_expected_one_is_also_a_different_machine() {
        let destination = to("https://hexora-probe.invalid.app.example.com.evil/");
        assert!(!destination.stays_on(BASE));
    }

    #[test]
    fn a_fragment_does_not_end_up_being_the_host() {
        // `https://elsewhere#@app.example.com` goes to `elsewhere`: the fragment ends
        // the authority before the `@` is reached.
        let destination = to("https://hexora-probe.invalid#@app.example.com");
        assert_eq!(destination.host.as_deref(), Some("hexora-probe.invalid"));
        assert!(!destination.stays_on(BASE));
    }

    // -----------------------------------------------------------------------
    // Not a host at all
    // -----------------------------------------------------------------------

    #[test]
    fn a_scheme_that_is_not_http_is_kept_apart() {
        // A different problem from a redirect, and browsers disagree about honouring
        // it. Saying which one it is beats calling it an open redirect.
        for (location, scheme) in [
            ("javascript:alert(1)", "javascript"),
            ("data:text/html,<x>", "data"),
            ("MAILTO:a@b", "mailto"),
        ] {
            let destination = to(location);
            assert_eq!(
                destination.reach,
                Reach::OtherScheme {
                    scheme: scheme.into()
                },
                "{location}"
            );
            assert!(!destination.reach.leaves_the_host(), "{location}");
        }
    }

    #[test]
    fn a_scheme_relative_path_stays_on_the_host() {
        assert_eq!(to("http:/dashboard").reach, Reach::SameHost);
        assert_eq!(to("https:dashboard").reach, Reach::SameHost);
    }

    #[test]
    fn an_empty_or_unreadable_location_says_so() {
        for location in ["", "   ", "//", "https://"] {
            assert!(
                matches!(to(location).reach, Reach::Unreadable | Reach::SameHost),
                "{location} produced {:?}",
                to(location).reach
            );
        }
    }

    #[test]
    fn a_port_is_not_part_of_the_host() {
        assert_eq!(
            to("https://hexora-probe.invalid:8443/").host.as_deref(),
            Some("hexora-probe.invalid")
        );
        assert_eq!(
            resolve("app.example.com", "https://app.example.com:8443/").reach,
            Reach::SameHost,
            "a different port on the same host is still the same host"
        );
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets() {
        let destination = to("https://[2001:db8::1]:8443/x");
        assert_eq!(destination.host.as_deref(), Some("[2001:db8::1]"));
        assert!(!destination.stays_on(BASE));
    }

    #[test]
    fn a_trailing_dot_does_not_make_a_host_a_different_one() {
        assert!(to("https://app.example.com./x").stays_on(BASE));
    }

    #[test]
    fn hostile_input_does_not_panic() {
        for location in [
            "/".repeat(5000),
            "\\".repeat(5000),
            "@".repeat(500),
            format!("https://{}/", "a".repeat(5000)),
            "https://[::1".to_string(),
            "\u{202e}https://x".to_string(),
            ":".to_string(),
            "://x".to_string(),
        ] {
            let _ = to(&location);
        }
    }

    #[test]
    fn the_header_is_quoted_back_but_not_at_any_length() {
        let long = format!("https://hexora-probe.invalid/{}", "a".repeat(5000));
        let destination = to(&long);
        assert!(destination.location.chars().count() <= LOCATION_LIMIT + 1);
        assert!(destination.location.ends_with('…'));
    }
}

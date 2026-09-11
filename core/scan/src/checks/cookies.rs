//! `cookies.security` — what a `Set-Cookie` declared about itself.
//!
//! # The value is never read
//!
//! A cookie's *name* is what this check reports; its value is parsed off and thrown
//! away in the same expression. That is not a policy applied carefully at the end, it
//! is the shape of [`Cookie::parse`]: there is no field holding the value, so no
//! observation, finding, report or IPC payload can carry one.
//!
//! This matters more here than anywhere else in the scanner, because a `Set-Cookie`
//! on authenticated traffic *is* the session.
//!
//! # Context, not a checklist
//!
//! "Missing `HttpOnly`" is not a finding on its own — plenty of cookies are read by
//! script on purpose, and a consent banner's preference cookie is not a session. So
//! each observation records what kind of cookie it was talking about:
//!
//! | Shape | What is asked of it |
//! | ----- | ------------------- |
//! | Session (no `Expires`/`Max-Age`) | `Secure` on HTTPS, `HttpOnly`, `SameSite` |
//! | Persistent | `Secure` on HTTPS, `SameSite` |
//! | Any, on plaintext | that it was not sent over plaintext at all |
//!
//! A cookie whose name says it is a session — the usual suspects, plus anything
//! ending `session`, `sid` or `auth` — is held to the session standard whatever its
//! expiry, because that is the one whose theft matters.

use super::prelude::*;

/// The check.
pub struct CookieAttributes;

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("cookies.security"),
    name: "Cookie attribute analysis",
    version: "1.0.0",
    about: "Set-Cookie attributes, in the context of the cookie they were on",
    mode: DetectorMode::Passive,
    observes: true,
    hypothesizes: false,
    settles: None,
};

/// A `Set-Cookie`, with the value deliberately absent.
///
/// Parsed into this rather than handled as a string so that the value has nowhere to
/// live. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    /// The cookie's name. Reported; never the value.
    pub name: String,
    /// Whether `Secure` was present.
    pub secure: bool,
    /// Whether `HttpOnly` was present.
    pub http_only: bool,
    /// The `SameSite` value, lowercased, when one was given.
    pub same_site: Option<String>,
    /// Whether it carried an `Expires` or `Max-Age`.
    pub persistent: bool,
}

impl Cookie {
    /// Reads a `Set-Cookie` value, keeping the name and the attributes.
    ///
    /// Returns `None` for a header with no name at all, which is the one shape that
    /// says nothing. Everything else is accepted: a malformed cookie from a hostile
    /// application is still a cookie the browser will try to store, and refusing to
    /// look at it would be refusing to look at the interesting one.
    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split(';');
        let pair = parts.next()?.trim();
        // The value is split off here and dropped. It is never bound to a name.
        let name = match pair.split_once('=') {
            Some((name, _)) => name.trim(),
            None => pair,
        };
        if name.is_empty() {
            return None;
        }

        let mut cookie = Self {
            name: name.to_string(),
            secure: false,
            http_only: false,
            same_site: None,
            persistent: false,
        };

        for attribute in parts {
            let attribute = attribute.trim();
            let (key, attribute_value) = match attribute.split_once('=') {
                Some((key, value)) => (key.trim(), Some(value.trim())),
                None => (attribute, None),
            };
            match key.to_ascii_lowercase().as_str() {
                "secure" => cookie.secure = true,
                "httponly" => cookie.http_only = true,
                "samesite" => cookie.same_site = attribute_value.map(|v| v.to_ascii_lowercase()),
                "expires" | "max-age" => cookie.persistent = true,
                _ => {}
            }
        }
        Some(cookie)
    }

    /// Whether the name says this is the cookie whose theft matters.
    pub fn looks_like_a_session(&self) -> bool {
        let name = self.name.to_ascii_lowercase();
        const EXACT: &[&str] = &[
            "sessionid",
            "session_id",
            "jsessionid",
            "phpsessid",
            "asp.net_sessionid",
            "connect.sid",
            "_session_id",
        ];
        EXACT.contains(&name.as_str())
            || name.ends_with("session")
            || name.ends_with("sid")
            || name.ends_with("auth")
            || name.ends_with("token")
    }

    /// How this cookie is described in an observation.
    fn shape(&self) -> &'static str {
        match (self.looks_like_a_session(), self.persistent) {
            (true, _) => "session cookie",
            (false, true) => "persistent cookie",
            (false, false) => "session-scoped cookie",
        }
    }
}

impl PassiveCheck for CookieAttributes {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn observe(&self, exchange: &Exchange) -> Vec<Observation> {
        let mut found = Vec::new();

        for header in exchange.response_headers.get_all("set-cookie") {
            let Some(cookie) = Cookie::parse(&crate::text(header)) else {
                continue;
            };
            let session = cookie.looks_like_a_session();

            if !exchange.secure {
                found.push(observation(
                    &INFO,
                    exchange,
                    format!(
                        "Cookie {} set over plaintext on {}",
                        cookie.name, exchange.host
                    ),
                    "a cookie is set on an encrypted connection",
                    "it was set over plaintext HTTP",
                    format!(
                        "The {} was handed out in the clear, so anybody on the path \
                         already has it. Marking it Secure afterwards does not \
                         retrieve it.",
                        cookie.shape()
                    ),
                    if session {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    Significance::Reportable,
                    header_at("Set-Cookie"),
                ));
                // Everything else about this cookie is secondary to having been sent
                // in the clear, and repeating it three times would bury that.
                continue;
            }

            if !cookie.secure {
                found.push(observation(
                    &INFO,
                    exchange,
                    format!("Cookie {} without Secure on {}", cookie.name, exchange.host),
                    "a cookie set over HTTPS is marked Secure",
                    "the attribute is absent",
                    format!(
                        "Without it the browser will send this {} over plaintext if \
                         anything ever sends the user to http://, which is a thing an \
                         attacker on the network can arrange.",
                        cookie.shape()
                    ),
                    if session {
                        Severity::Medium
                    } else {
                        Severity::Low
                    },
                    Significance::Reportable,
                    header_at("Set-Cookie"),
                ));
            }

            if session && !cookie.http_only {
                found.push(observation(
                    &INFO,
                    exchange,
                    format!(
                        "Cookie {} without HttpOnly on {}",
                        cookie.name, exchange.host
                    ),
                    "a session cookie is marked HttpOnly",
                    "the attribute is absent",
                    "The name says this is a session, and script can read it. That \
                     turns any script injection anywhere on the origin into session \
                     theft. Hexora has not looked for an injection — this is about \
                     what one would be worth."
                        .to_string(),
                    Severity::Medium,
                    Significance::Reportable,
                    header_at("Set-Cookie"),
                ));
            }

            match cookie.same_site.as_deref() {
                None => found.push(observation(
                    &INFO,
                    exchange,
                    format!(
                        "Cookie {} without SameSite on {}",
                        cookie.name, exchange.host
                    ),
                    "a cookie declares a SameSite policy",
                    "the attribute is absent",
                    format!(
                        "Browsers default this differently and have changed the \
                         default before. Declaring it is how the {} behaves the same \
                         way everywhere.",
                        cookie.shape()
                    ),
                    Severity::Low,
                    Significance::Reportable,
                    header_at("Set-Cookie"),
                )),
                Some("none") if session => found.push(observation(
                    &INFO,
                    exchange,
                    format!(
                        "Cookie {} is SameSite=None on {}",
                        cookie.name, exchange.host
                    ),
                    "a session cookie is not sent on cross-site requests",
                    "SameSite=None, so it is",
                    "The cookie travels on requests another site makes. That is \
                     sometimes deliberate and is worth confirming rather than \
                     assuming."
                        .to_string(),
                    Severity::Low,
                    Significance::Reportable,
                    header_at("Set-Cookie"),
                )),
                Some(_) => {}
            }
        }

        found
    }

    fn writeup(&self, observation: &Observation, exchange: &Exchange, target: TargetId) -> Writeup {
        Writeup {
            target,
            title: observation.about.clone(),
            description: format!(
                "{} Expected: {}. Observed: {}.",
                observation.rationale, observation.expected, observation.observed
            ),
            impact: "What a cookie attribute costs depends on what the cookie is. \
                     This is recorded as a lead so a tester can say which of those \
                     applies here."
                .into(),
            remediation: "Set the attributes the cookie's purpose calls for: Secure \
                          on anything sent over HTTPS, HttpOnly on anything script \
                          has no reason to read, and an explicit SameSite."
                .into(),
            reproduction: format!(
                "Request {} {} and read the Set-Cookie header. The cookie's value is \
                 not recorded here.",
                exchange.method, exchange.url
            ),
            cwe: Some("CWE-1004".into()),
            owasp: Some("A05:2021 Security Misconfiguration".into()),
            source: source(&INFO),
            severity: observation.severity,
            location: observation.location.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::checks::test_support::*;

    use super::*;

    const SESSION: &str = "sessionid=super-secret-session-value";

    #[test]
    fn a_cookie_value_is_never_kept_anywhere() {
        // The property this check is shaped around. `Cookie` has no field for it, so
        // this is checking the shape rather than a habit.
        let cookie = Cookie::parse(SESSION).unwrap();
        assert_eq!(cookie.name, "sessionid");

        let exchange = exchange(https().response(200, &[]).header("Set-Cookie", SESSION));
        let found = CookieAttributes.observe(&exchange);
        assert!(!found.is_empty());

        let rendered = format!("{found:?}");
        assert!(
            !rendered.contains("super-secret-session-value"),
            "a cookie value reached an observation: {rendered}"
        );

        let writeup = CookieAttributes.writeup(&found[0], &exchange, TargetId::new());
        let rendered = format!("{writeup:?}");
        assert!(
            !rendered.contains("super-secret-session-value"),
            "a cookie value reached a writeup: {rendered}"
        );
    }

    #[test]
    fn a_session_cookie_over_plaintext_outranks_everything_else_about_it() {
        let exchange = exchange(plaintext().response(200, &[]).header("Set-Cookie", SESSION));
        let found = CookieAttributes.observe(&exchange);

        assert_eq!(found.len(), 1, "one thing to say, not four: {found:#?}");
        assert!(found[0].about.contains("over plaintext"));
        assert_eq!(found[0].severity, Severity::High);
    }

    #[test]
    fn a_fully_attributed_session_cookie_produces_nothing() {
        // The negative control.
        let exchange = exchange(https().response(200, &[]).header(
            "Set-Cookie",
            "sessionid=x; Secure; HttpOnly; SameSite=Lax; Path=/",
        ));
        assert!(CookieAttributes.observe(&exchange).is_empty());
    }

    #[test]
    fn a_non_session_cookie_is_not_held_to_the_session_standard() {
        // A preference cookie script is supposed to read. Asking for HttpOnly here
        // would be asking the application to break itself.
        let exchange = exchange(
            https()
                .response(200, &[])
                .header("Set-Cookie", "theme=dark; Secure; SameSite=Lax"),
        );
        let found = CookieAttributes.observe(&exchange);
        assert!(
            !found.iter().any(|o| o.about.contains("HttpOnly")),
            "{found:#?}"
        );
    }

    #[test]
    fn names_that_say_session_are_treated_as_one() {
        for name in [
            "sessionid",
            "JSESSIONID",
            "connect.sid",
            "app_session",
            "csrf_token",
            "my-auth",
        ] {
            let cookie = Cookie::parse(&format!("{name}=x")).unwrap();
            assert!(cookie.looks_like_a_session(), "{name}");
        }
        for name in ["theme", "locale", "cart"] {
            let cookie = Cookie::parse(&format!("{name}=x")).unwrap();
            assert!(!cookie.looks_like_a_session(), "{name}");
        }
    }

    #[test]
    fn malformed_set_cookie_headers_do_not_stop_the_check() {
        // Input comes from a hostile application. None of these may panic, and none
        // of them may take the well-formed cookie down with them.
        let exchange = exchange(
            https()
                .response(200, &[])
                .header("Set-Cookie", "")
                .header("Set-Cookie", "=novalue")
                .header("Set-Cookie", ";;;")
                .header("Set-Cookie", "noequals")
                .header("Set-Cookie", "a=b; SameSite")
                .header("Set-Cookie", "sessionid=x; Secure; HttpOnly; SameSite=Lax"),
        );
        let found = CookieAttributes.observe(&exchange);
        // `noequals` and `a=b` are real cookies missing attributes; the empty and
        // nameless ones say nothing and are skipped.
        assert!(
            found.iter().all(|o| !o.about.contains("Cookie  ")),
            "{found:#?}"
        );
        assert!(
            !found.iter().any(|o| o.about.contains("sessionid")),
            "the well-formed cookie survived the malformed ones: {found:#?}"
        );
    }

    #[test]
    fn attribute_casing_is_not_a_finding() {
        let exchange = exchange(https().response(200, &[]).header(
            "set-cookie",
            "sessionid=x; SECURE; httponly; samesite=STRICT",
        ));
        assert!(CookieAttributes.observe(&exchange).is_empty());
    }

    #[test]
    fn a_session_cookie_sent_cross_site_is_worth_confirming() {
        let exchange = exchange(
            https()
                .response(200, &[])
                .header("Set-Cookie", "sessionid=x; Secure; HttpOnly; SameSite=None"),
        );
        let found = CookieAttributes.observe(&exchange);
        assert_eq!(found.len(), 1);
        assert!(found[0].about.contains("SameSite=None"));
    }
}

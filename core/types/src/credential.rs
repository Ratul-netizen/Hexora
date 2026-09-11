//! Breaking a credential on purpose, without ever writing one down.
//!
//! An application can fail to check a session in two different ways, and a
//! cross-identity matrix sees neither of them — both identities in a matrix have valid
//! credentials, so an endpoint that accepts *any* token looks exactly like one that
//! checks properly:
//!
//! ```text
//! sent nothing at all        →  200   the endpoint needs no session
//! sent a broken signature    →  200   the endpoint has a session and does not verify it
//! ```
//!
//! The second is the sharper finding and the harder one to get at, because the probe
//! has to be *derived from a credential the server issued*. A random string is rejected
//! for being unparseable and proves nothing; the same token with one character of its
//! signature changed is well-formed, belongs to a real session, and is wrong.
//!
//! # The value never leaves this module
//!
//! A credential with one character changed is, for disclosure purposes, the credential.
//! Writing one into an evidence note would put a working session in a report through
//! the back door — so nothing here returns the original, [`Tampered`] has no `Display`
//! and a redacting `Debug`, and [`Tampered::describe`] says what was done to it without
//! quoting either form.
//!
//! ```text
//! wrong:  sent `Bearer eyJhbGciOi...Qs4w` and it was accepted
//! right:  sent the captured token with the last character of its signature changed
//! ```

use crate::http::Header;

/// A credential found on a request, taken apart far enough to break precisely.
///
/// Never derives `Debug` or `Clone` by hand into anything that prints: the whole point
/// is that the value does not travel.
pub struct Credential {
    /// The header it was on, as written.
    name: String,
    /// The scheme prefix, when the header has one: `Bearer`, `Basic`.
    scheme: Option<String>,
    /// The part that identifies the session.
    value: String,
    /// For a cookie, the name of the cookie the value came from.
    cookie: Option<String>,
    /// The rest of a `Cookie` header, so the others travel unchanged.
    rest: Vec<(String, String)>,
}

impl std::fmt::Debug for Credential {
    /// Says what it is, never what it holds.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("name", &self.name)
            .field("scheme", &self.scheme)
            .field("cookie", &self.cookie)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// The header names that carry a session.
///
/// The same list the scanner redacts on, for the same reason: a value on one of these
/// is a credential, not data.
pub const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-session-token",
];

/// Cookie names that usually carry a session rather than a preference.
///
/// A `Cookie` header holds several values and only some of them are the session.
/// Matched on stems, so `JSESSIONID` and `laravel_session` are both covered.
const SESSION_COOKIE_STEMS: &[&str] = &[
    "session", "sess", "sid", "auth", "token", "jwt", "login", "remember",
];

impl Credential {
    /// Reads a credential off a header, if that header carries one.
    ///
    /// Returns `None` for a header that is not a credential, and for one whose value is
    /// empty or too short to break meaningfully — a two-character token is not a
    /// session and tampering with it tests nothing.
    pub fn read(header: &Header) -> Option<Self> {
        let name = header.name.clone();
        let lower = name.to_ascii_lowercase();
        if !CREDENTIAL_HEADERS.iter().any(|known| *known == lower) {
            return None;
        }

        let raw = header.value_lossy().to_string();
        if lower == "cookie" {
            return Self::from_cookie(name, &raw);
        }

        let (scheme, value) = match raw.split_once(' ') {
            Some((scheme, rest)) if !rest.trim().is_empty() => {
                (Some(scheme.to_string()), rest.trim().to_string())
            }
            _ => (None, raw.trim().to_string()),
        };

        (value.chars().count() >= MIN_LENGTH).then_some(Self {
            name,
            scheme,
            value,
            cookie: None,
            rest: Vec::new(),
        })
    }

    /// The session cookie out of a `Cookie` header, with the others kept.
    fn from_cookie(name: String, raw: &str) -> Option<Self> {
        let pairs: Vec<(String, String)> = raw
            .split(';')
            .filter_map(|pair| {
                let pair = pair.trim();
                let (key, value) = pair.split_once('=')?;
                Some((key.trim().to_string(), value.trim().to_string()))
            })
            .collect();

        let (index, _) = pairs.iter().enumerate().find(|(_, (key, value))| {
            let lower = key.to_ascii_lowercase();
            value.chars().count() >= MIN_LENGTH
                && SESSION_COOKIE_STEMS.iter().any(|stem| lower.contains(stem))
        })?;

        let (cookie, value) = pairs[index].clone();
        let rest = pairs
            .iter()
            .enumerate()
            .filter(|(at, _)| *at != index)
            .map(|(_, pair)| pair.clone())
            .collect();

        Some(Self {
            name,
            scheme: None,
            value,
            cookie: Some(cookie),
            rest,
        })
    }

    /// The header this was found on.
    pub fn header(&self) -> &str {
        &self.name
    }

    /// The same credential with one character of its value changed.
    ///
    /// For a JWT the character is taken from the **signature** and nowhere else: the
    /// header and payload stay byte-identical, so an application that accepts the
    /// result is not verifying the signature — a far more precise statement than "a
    /// modified token was accepted", which could also mean the token was never parsed.
    ///
    /// For anything else, the last character of the value. Deterministic, so the same
    /// credential always produces the same probe and a re-run is comparable.
    pub fn tamper(&self) -> Tampered {
        let (broken, what) = break_value(&self.value);

        let value = match (&self.scheme, &self.cookie) {
            (Some(scheme), _) => format!("{scheme} {broken}"),
            (None, Some(cookie)) => {
                let mut pairs = vec![format!("{cookie}={broken}")];
                pairs.extend(self.rest.iter().map(|(k, v)| format!("{k}={v}")));
                pairs.join("; ")
            }
            (None, None) => broken,
        };

        Tampered {
            name: self.name.clone(),
            value,
            what,
        }
    }
}

/// The shortest value worth breaking.
///
/// Below this it is a flag or a preference, not a session, and tampering tests nothing.
const MIN_LENGTH: usize = 8;

/// A credential deliberately broken, ready to send and never to print.
///
/// Carries no `Display` and a redacting `Debug`, because one character's difference
/// from a working session is not a meaningful difference where disclosure is
/// concerned.
pub struct Tampered {
    name: String,
    value: String,
    what: What,
}

impl std::fmt::Debug for Tampered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tampered")
            .field("name", &self.name)
            .field("what", &self.what)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Which part of a credential was changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum What {
    /// One character of a JWT's signature. Header and payload are untouched.
    JwtSignature,
    /// One character at the end of an opaque value.
    LastCharacter,
}

impl Tampered {
    /// The header name to set.
    pub fn header(&self) -> &str {
        &self.name
    }

    /// The header value to send.
    ///
    /// The one accessor that yields the bytes, named so that a reviewer can find every
    /// place they are used.
    pub fn expose_value(&self) -> &str {
        &self.value
    }

    /// What was done, for an evidence note, quoting neither the original nor the probe.
    pub fn describe(&self) -> String {
        match self.what {
            What::JwtSignature => format!(
                "the captured `{}` credential with one character of its JWT signature \
                 changed — the header and payload are byte-identical to the real one",
                self.name
            ),
            What::LastCharacter => format!(
                "the captured `{}` credential with its last character changed",
                self.name
            ),
        }
    }
}

/// Changes one character, and says which part it came from.
fn break_value(value: &str) -> (String, What) {
    // A JWT is three dot-separated parts. Breaking the signature and nothing else is
    // what turns "a modified token was accepted" into "the signature is not verified".
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() == 3 && parts.iter().all(|part| !part.is_empty()) {
        if let Some(signature) = flip_last(parts[2]) {
            return (
                format!("{}.{}.{}", parts[0], parts[1], signature),
                What::JwtSignature,
            );
        }
    }

    match flip_last(value) {
        Some(broken) => (broken, What::LastCharacter),
        // Nothing to change. `read` already refuses values this short, so this is
        // unreachable from the public path and is a safe answer rather than a panic.
        None => (value.to_string(), What::LastCharacter),
    }
}

/// The same string with its last character replaced by a different one.
///
/// Stays inside the alphabet the value already uses, so a base64url token remains
/// base64url and is rejected — if it is rejected — for being *wrong* rather than for
/// being unparseable.
fn flip_last(value: &str) -> Option<String> {
    let last = value.chars().next_back()?;
    let replacement = match last {
        'a'..='y' | 'A'..='Y' | '0'..='8' => char::from_u32(last as u32 + 1)?,
        'z' => 'a',
        'Z' => 'A',
        '9' => '0',
        '-' => '_',
        '_' => '-',
        // An unexpected character: change it to something from the same broad class
        // rather than guessing.
        _ => 'A',
    };
    let mut broken: String = value.chars().collect();
    broken.pop();
    broken.push(replacement);
    Some(broken)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> Header {
        Header::new(name, value)
    }

    // -----------------------------------------------------------------------
    // What counts as a credential
    // -----------------------------------------------------------------------

    #[test]
    fn a_bearer_token_is_read_with_its_scheme_kept_apart() {
        let credential = Credential::read(&header("Authorization", "Bearer abcdefghijkl"))
            .expect("a credential");
        assert_eq!(credential.header(), "Authorization");

        let tampered = credential.tamper();
        assert!(
            tampered.expose_value().starts_with("Bearer "),
            "the scheme has to survive or the server rejects the shape rather than the \
             value: {:?}",
            tampered
        );
        assert_ne!(tampered.expose_value(), "Bearer abcdefghijkl");
    }

    #[test]
    fn a_header_that_is_not_a_credential_is_not_one() {
        for (name, value) in [
            ("Accept", "text/html"),
            ("User-Agent", "curl/8.21.0"),
            ("Referer", "https://app.example.com/"),
        ] {
            assert!(
                Credential::read(&header(name, value)).is_none(),
                "{name} was read as a credential"
            );
        }
    }

    #[test]
    fn a_value_too_short_to_be_a_session_is_left_alone() {
        assert!(Credential::read(&header("X-Api-Key", "abc")).is_none());
        assert!(Credential::read(&header("Authorization", "Bearer ab")).is_none());
    }

    // -----------------------------------------------------------------------
    // Breaking a JWT precisely
    // -----------------------------------------------------------------------

    #[test]
    fn only_the_signature_of_a_jwt_is_changed() {
        // The whole reason this is worth doing carefully: header and payload identical
        // means an application that accepts it is not verifying the signature, which is
        // a different and much sharper statement than "a modified token was accepted".
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.QcDefGhIjKlMnOpQrStUvW";
        let credential =
            Credential::read(&header("Authorization", &format!("Bearer {jwt}"))).unwrap();
        let tampered = credential.tamper();

        let sent = tampered
            .expose_value()
            .strip_prefix("Bearer ")
            .expect("the scheme survives");
        let original: Vec<&str> = jwt.split('.').collect();
        let broken: Vec<&str> = sent.split('.').collect();

        assert_eq!(broken.len(), 3);
        assert_eq!(broken[0], original[0], "the header must not change");
        assert_eq!(broken[1], original[1], "the payload must not change");
        assert_ne!(broken[2], original[2], "the signature must change");
        assert_eq!(
            broken[2].len(),
            original[2].len(),
            "a different length would be rejected for its shape"
        );
        assert!(tampered.describe().contains("signature"));
    }

    #[test]
    fn an_opaque_token_has_its_last_character_changed() {
        let credential = Credential::read(&header("X-Api-Key", "abcdefghijklmnop")).unwrap();
        let tampered = credential.tamper();
        assert_eq!(tampered.expose_value().len(), "abcdefghijklmnop".len());
        assert_ne!(tampered.expose_value(), "abcdefghijklmnop");
        assert!(tampered.describe().contains("last character"));
    }

    #[test]
    fn a_broken_value_stays_in_the_alphabet_it_started_in() {
        // A base64url token that stops being base64url is rejected for its shape, and
        // the experiment then proves nothing about whether the value was checked.
        let credential =
            Credential::read(&header("Authorization", "Bearer aGVsbG8td29ybGQ")).unwrap();
        let sent = credential.tamper();
        let value = sent.expose_value().strip_prefix("Bearer ").unwrap();
        assert!(
            value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{value}"
        );
    }

    // -----------------------------------------------------------------------
    // Cookies
    // -----------------------------------------------------------------------

    #[test]
    fn the_session_cookie_is_broken_and_the_others_travel_unchanged() {
        let credential = Credential::read(&header(
            "Cookie",
            "theme=dark; sessionid=abcdefghijklmnop; lang=en",
        ))
        .expect("a session cookie");

        let sent = credential.tamper();
        let value = sent.expose_value();
        assert!(value.contains("theme=dark"), "{value}");
        assert!(value.contains("lang=en"), "{value}");
        assert!(value.contains("sessionid="), "{value}");
        assert!(
            !value.contains("sessionid=abcdefghijklmnop"),
            "the session cookie was not changed: {value}"
        );
    }

    #[test]
    fn a_cookie_header_with_nothing_session_shaped_is_not_a_credential() {
        assert!(Credential::read(&header("Cookie", "theme=dark; lang=en")).is_none());
    }

    #[test]
    fn session_cookies_are_recognised_however_they_are_named() {
        for name in [
            "sessionid",
            "JSESSIONID",
            "laravel_session",
            "PHPSESSID",
            "auth_token",
            "remember_me",
        ] {
            assert!(
                Credential::read(&header("Cookie", &format!("{name}=abcdefghijklmnop"))).is_some(),
                "{name} was not recognised as a session"
            );
        }
    }

    // -----------------------------------------------------------------------
    // The value does not travel
    // -----------------------------------------------------------------------

    #[test]
    fn neither_form_of_the_credential_can_be_printed_by_accident() {
        // A credential with one character changed is, for disclosure purposes, the
        // credential. `Debug` is the way one ends up in a log or an error message.
        let secret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.SuPeRsEcReTsIgNaTuRe";
        let credential =
            Credential::read(&header("Authorization", &format!("Bearer {secret}"))).unwrap();
        let tampered = credential.tamper();

        let printed = format!("{credential:?}{tampered:?}{}", tampered.describe());
        assert!(!printed.contains("SuPeRsEcReTsIgNaTuRe"), "{printed}");
        assert!(!printed.contains("eyJhbGciOiJIUzI1NiJ9"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    #[test]
    fn describing_the_tampering_names_the_header_and_nothing_else() {
        let credential = Credential::read(&header("X-Api-Key", "supersecretapikeyvalue")).unwrap();
        let described = credential.tamper().describe();
        assert!(described.contains("X-Api-Key"));
        assert!(!described.contains("supersecret"), "{described}");
    }

    #[test]
    fn the_same_credential_always_produces_the_same_probe() {
        // A re-run has to be comparable with the run before it.
        let build = || {
            Credential::read(&header("Authorization", "Bearer abcdefghijklmnop"))
                .unwrap()
                .tamper()
                .expose_value()
                .to_string()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn hostile_input_does_not_panic() {
        for value in [
            String::new(),
            " ".repeat(100),
            "Bearer ".to_string(),
            "..".to_string(),
            "a.b.".to_string(),
            ".".repeat(50),
            "\u{202e}".repeat(20),
            "Bearer ".to_string() + &"\u{10FFFF}".to_string().repeat(20),
        ] {
            if let Some(credential) = Credential::read(&header("Authorization", &value)) {
                let _ = credential.tamper();
            }
            if let Some(credential) = Credential::read(&header("Cookie", &value)) {
                let _ = credential.tamper();
            }
        }
    }
}

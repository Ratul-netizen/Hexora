//! Keeping a declared identity's session current, from traffic a person generated.
//!
//! # The problem this solves
//!
//! A captured credential is a decaying asset. Declare an identity today, and by
//! tomorrow every authorization result reads:
//!
//! ```text
//! the credential the request was captured with may no longer be valid — so
//! nothing is established either way
//! ```
//!
//! That is not a hypothetical. Against a real bug bounty target, three of five active
//! checks came back inconclusive for exactly that reason on the first run. Cross-identity
//! testing is the best thing this tool does and it is worthless without live sessions.
//!
//! # Why not a recorded login sequence
//!
//! Burp and AppScan record the login and replay it. Two reasons Hexora starts elsewhere:
//!
//! **A recorded login has to hold the password.** Everything else in this codebase goes
//! the other way — `hexora identity add` refuses a credential as an argument and takes
//! `--from-env` or `--from-file`, because `ps` and shell history both capture arguments.
//! Storing a replayable password to avoid retyping a token is a poor trade.
//!
//! **It does not survive the defences real targets have.** The programme this was built
//! against sends `h-captcha-response` with its login POST. A replayed captcha token is
//! a rejected login, and MFA, device checks and SSO all fail the same way. A recorded
//! sequence works on targets that have none of those, which is not the interesting set.
//!
//! So the human logs in — through the proxy, as they already do — and Hexora *notices*.
//! The person solves the captcha, because that is what captchas are for.
//!
//! # What must not happen
//!
//! **Hexora must never adopt its own traffic.** This codebase has made that mistake
//! twice already in other forms, and here it would be worse than confusing: the
//! `auth.enforcement` check deliberately sends a request whose JWT signature has one
//! character changed. Adopting *that* would replace a working session with a
//! deliberately broken one, and every later result would be wrong in a way that looks
//! like a finding. So only proxy traffic is eligible — a person's browser, nothing else.
//!
//! **A value is never printed.** Not to the console, not to a log, not into an error.
//! The caller is told the host, the time and the size, which is enough to decide whether
//! to accept it and nothing like enough to use.

use hexora_storage::TrafficStore;
use hexora_types::identity::{Credential, Identity};
use hexora_types::ids::RequestId;
use hexora_types::scope::Scope;
use hexora_types::Result;

/// A newer credential found in traffic, offered for a declared identity.
///
/// Carries no value: [`Renewal::credential`] hands one over exactly once, to a caller
/// that is about to store it.
#[derive(Clone)]
pub struct Renewal {
    /// The request it came from, so a person can look at it.
    pub source: RequestId,
    /// The host that issued it.
    pub host: String,
    /// When that request was sent, RFC 3339.
    pub sent_at: String,
    /// How long the value is, in bytes.
    ///
    /// A size is the most that can be said about a credential without saying it. It is
    /// enough to notice that a 12-byte value is not a session cookie.
    pub length: usize,
    /// The header the credential sits in, e.g. `Cookie`.
    pub slot: String,
    value: String,
}

/// Prints everything about the renewal except the thing it carries.
///
/// Written by hand because `#[derive(Debug)]` does not care that a field is private —
/// it prints it anyway. A test holds this, and it caught the derived version.
impl std::fmt::Debug for Renewal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Renewal")
            .field("source", &self.source)
            .field("host", &self.host)
            .field("sent_at", &self.sent_at)
            .field("length", &self.length)
            .field("slot", &self.slot)
            .field("value", &"[redacted]")
            .finish()
    }
}

impl Renewal {
    /// The credential, shaped for the identity it will replace.
    ///
    /// Consumes the renewal, because there is no reason to read one twice and every
    /// additional copy of a credential is somewhere else it can leak from.
    pub fn credential(self, existing: &Credential) -> Credential {
        match existing {
            Credential::Bearer { .. } => Credential::Bearer {
                // The stored form is the token without its scheme, which is how
                // `Credential::apply` writes it back.
                token: strip_bearer(&self.value).to_string().into(),
            },
            Credential::Cookie { .. } => Credential::Cookie {
                value: self.value.into(),
            },
            Credential::Header { name, .. } => Credential::Header {
                name: name.clone(),
                value: self.value.into(),
            },
            // Basic credentials are a username and a password, not a session, and
            // nothing a browser sends renews them. An identity that authenticates this
            // way is left alone rather than half-updated.
            other => other.clone(),
        }
    }
}

/// The header a credential occupies, lowercase.
///
/// `None` for a credential that occupies no header, which is the anonymous one.
pub fn slot_of(credential: &Credential) -> Option<String> {
    match credential {
        Credential::None => None,
        Credential::Bearer { .. } | Credential::Basic { .. } => Some("authorization".into()),
        Credential::Cookie { .. } => Some("cookie".into()),
        Credential::Header { name, .. } => Some(name.to_ascii_lowercase()),
    }
}

/// Looks through recent traffic for a newer credential in this identity's slot.
///
/// Newest first, and it stops at the first eligible request rather than reading the
/// whole history: a session is renewed by the most recent login, not by the best one.
///
/// Eligible means all of:
///
/// * sent by the **proxy** — a person's browser. Not the repeater, whose drafts a
///   tester may have edited by hand, and emphatically not the scanner or the
///   authorization engine, which send credentials they broke on purpose;
/// * to a host this project declared, so a session from an unrelated site a tester
///   happened to visit cannot be adopted — and to `host` specifically, when one is
///   named, because cookies are per host and an engagement's scope covers many;
/// * carrying the header this identity's credential occupies, non-empty;
/// * **different** from what the identity already holds — otherwise there is nothing
///   to do, and saying so is more useful than a needless write.
pub fn find_renewal(
    traffic: &TrafficStore,
    scope: &Scope,
    identity: &Identity,
    limit: usize,
    host: Option<&str>,
) -> Result<Option<Renewal>> {
    let Some(slot) = slot_of(&identity.credential) else {
        return Ok(None);
    };
    let current = current_value(&identity.credential);

    let mut cursor = None;
    let mut read = 0usize;
    loop {
        let page = traffic.history(
            cursor.as_ref(),
            hexora_storage::repository::Limit::new(hexora_storage::repository::Limit::MAX),
        )?;
        let next = page.next.clone();

        for row in page.items {
            if read >= limit {
                return Ok(None);
            }
            read += 1;

            // The URL is the authority here: `StoredTraffic` carries the absolute URL
            // it was sent to, and re-deriving host and path from it keeps this in step
            // with what the row actually says rather than with a second parse.
            let Some((service, path)) = service_of(&row.url, row.secure) else {
                continue;
            };
            if !scope.contains(&service, &path) {
                continue;
            }
            // Cookies are per host, and an engagement's scope covers many. Against a
            // real target the newest in-scope cookie came from the image CDN, which is
            // not the session the API accepts. A caller that knows which host matters
            // says so; a caller that does not is told which one this came from.
            if host.is_some_and(|wanted| !service.host.eq_ignore_ascii_case(wanted)) {
                continue;
            }

            let stored = match traffic.request(row.id) {
                Ok(stored) => stored,
                Err(_) => continue,
            };
            // The line that matters. See the module docs: adopting Hexora's own
            // traffic would mean adopting a credential Hexora broke on purpose.
            if stored.origin != "proxy" {
                continue;
            }

            let Some(value) = header_value(&stored.headers_raw, &slot) else {
                continue;
            };
            if value.is_empty() || Some(value.as_str()) == current.as_deref() {
                continue;
            }

            return Ok(Some(Renewal {
                source: row.id,
                host: service.host.clone(),
                sent_at: row.sent_at.clone(),
                length: value.len(),
                slot: slot.clone(),
                value,
            }));
        }

        match next {
            Some(next) => cursor = Some(next),
            None => return Ok(None),
        }
    }
}

/// Splits a stored absolute URL back into a service and a path.
fn service_of(url: &str, secure: bool) -> Option<(hexora_types::http::HttpService, String)> {
    let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], rest[at..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (authority, if secure { 443 } else { 80 }),
    };
    if host.is_empty() {
        return None;
    }
    Some((
        hexora_types::http::HttpService::new(host, port, secure),
        path,
    ))
}

/// What the identity currently holds in its slot, for comparison only.
fn current_value(credential: &Credential) -> Option<String> {
    match credential {
        Credential::Bearer { token } => Some(token.expose().clone()),
        Credential::Cookie { value } => Some(value.expose().clone()),
        Credential::Header { value, .. } => Some(value.expose().clone()),
        _ => None,
    }
}

fn strip_bearer(value: &str) -> &str {
    let trimmed = value.trim();
    match trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        true => trimmed[7..].trim_start(),
        false => trimmed,
    }
}

/// Reads one header out of a stored header block.
///
/// The block is stored as bytes on purpose — storage keeps what was sent rather than a
/// parsed view — so this reads it the same way, and tolerates the block being invalid
/// UTF-8 by looking only at the lines that are.
fn header_value(raw: &[u8], wanted: &str) -> Option<String> {
    for line in raw.split(|byte| *byte == b'\n') {
        let line = match std::str::from_utf8(line) {
            Ok(line) => line.trim_end_matches('\r'),
            Err(_) => continue,
        };
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(wanted) {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_is_the_header_the_credential_occupies() {
        assert_eq!(slot_of(&Credential::None), None);
        assert_eq!(
            slot_of(&Credential::Bearer {
                token: "t".to_string().into()
            }),
            Some("authorization".into())
        );
        assert_eq!(
            slot_of(&Credential::Cookie {
                value: "a=b".to_string().into()
            }),
            Some("cookie".into())
        );
        assert_eq!(
            slot_of(&Credential::Header {
                name: "X-API-Key".into(),
                value: "k".to_string().into()
            }),
            Some("x-api-key".into())
        );
    }

    #[test]
    fn a_header_is_read_out_of_a_stored_block() {
        let raw = b"Host: example.com\r\nCookie: session=abc; csrf=def\r\nAccept: */*";
        assert_eq!(
            header_value(raw, "cookie").as_deref(),
            Some("session=abc; csrf=def")
        );
        assert_eq!(header_value(raw, "authorization"), None);
    }

    #[test]
    fn a_header_block_that_is_not_utf8_does_not_lose_the_lines_that_are() {
        // Storage keeps what was sent, and what was sent is not always valid UTF-8.
        // A single bad line must not hide the credential on the next one.
        let mut raw = b"Host: example.com\r\nX-Junk: ".to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(b"\r\nCookie: session=abc");
        assert_eq!(header_value(&raw, "cookie").as_deref(), Some("session=abc"));
    }

    #[test]
    fn a_bearer_renewal_is_stored_without_its_scheme() {
        // `Credential::apply` writes the scheme back on, so keeping it here would send
        // `Authorization: Bearer Bearer eyJ…`.
        let renewal = Renewal {
            source: RequestId::new(),
            host: "example.com".into(),
            sent_at: "2026-01-01T00:00:00Z".into(),
            length: 10,
            slot: "authorization".into(),
            value: "Bearer eyJhbGciOi".into(),
        };
        let credential = renewal.credential(&Credential::Bearer {
            token: "old".to_string().into(),
        });
        match credential {
            Credential::Bearer { token } => assert_eq!(token.expose(), "eyJhbGciOi"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_renewal_says_nothing_about_the_value_it_carries() {
        // The one thing this type must never do. `Debug` is derived, so this is a test
        // about `Secret` not being the only guard — the field is private and the only
        // way out is `credential`, which hands it straight to storage.
        let renewal = Renewal {
            source: RequestId::new(),
            host: "example.com".into(),
            sent_at: "2026-01-01T00:00:00Z".into(),
            length: 40,
            slot: "cookie".into(),
            value: "session=SUPERSECRETVALUE".into(),
        };
        assert!(
            !format!("{renewal:?}").contains("SUPERSECRET"),
            "a renewal printed the credential it carries"
        );
    }

    #[test]
    fn basic_credentials_are_left_alone_rather_than_half_updated() {
        // A username and password is not a session, and no browser request renews one.
        let renewal = Renewal {
            source: RequestId::new(),
            host: "example.com".into(),
            sent_at: "2026-01-01T00:00:00Z".into(),
            length: 4,
            slot: "authorization".into(),
            value: "Basic abcd".into(),
        };
        let existing = Credential::Basic {
            username: "alice".into(),
            password: "pw".to_string().into(),
        };
        match renewal.credential(&existing) {
            Credential::Basic { username, .. } => assert_eq!(username, "alice"),
            other => panic!("{other:?}"),
        }
    }
}

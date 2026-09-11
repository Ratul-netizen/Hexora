//! Reading what a credential says about itself — when it dies, and whose it is.
//!
//! # Why this exists
//!
//! A run against a real target replayed twenty requests as a declared identity and got
//! twenty `401`s. Every one was doomed before it left: the token had expired
//! eighty-five minutes earlier, and the token **said so** — `exp` is an unencrypted
//! field in the middle of every JWT, sitting in the project the whole time.
//!
//! Twenty requests at somebody's production API to learn something that was written
//! down. That is the cost, and it is charged to the target rather than to us. The
//! result was worse than nothing: a run that reported "tested 20" and established
//! nothing, which reads like coverage.
//!
//! # What it does not do
//!
//! Decide that a credential is *valid*. An unexpired token can be revoked, scoped
//! elsewhere, or simply wrong, and only the application knows. This answers the one
//! question that can be answered without asking: **has the credential's own stated
//! lifetime already ended?** A `None` means "nothing here says otherwise", never "this
//! will work".
//!
//! Nothing is decrypted and no signature is checked. The payload of a JWT is base64url,
//! not ciphertext — reading it is not an attack on anything, and the value read is a
//! timestamp rather than anything worth protecting.

use serde::{Deserialize, Serialize};

/// What a credential says about its own lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lifetime {
    /// When it stops being accepted, as a Unix timestamp.
    pub expires_at: i64,
    /// When it was issued, where the token says.
    pub issued_at: Option<i64>,
}

impl Lifetime {
    /// Whether the stated expiry has passed.
    pub fn expired_at(&self, now: i64) -> bool {
        self.expires_at <= now
    }

    /// How long it has left, or how long since it went, in seconds.
    pub fn remaining(&self, now: i64) -> i64 {
        self.expires_at - now
    }

    /// How it reads for somebody deciding whether to bother.
    pub fn describe(&self, now: i64) -> String {
        let remaining = self.remaining(now);
        if remaining > 0 {
            format!("valid for another {}", duration(remaining))
        } else {
            format!("expired {} ago", duration(-remaining))
        }
    }
}

fn duration(seconds: i64) -> String {
    match seconds {
        s if s < 90 => format!("{s} second(s)"),
        s if s < 5400 => format!("{} minute(s)", s / 60),
        s => format!("{} hour(s)", s / 3600),
    }
}

/// Who a bearer token says it belongs to, if it says.
///
/// # Why byte-equality was not enough
///
/// Attribution — *whose session was this request sent with?* — compared credentials
/// byte for byte. Exact or nothing, which is the right instinct: guessing whose session
/// something was is how a cross-identity test invents a finding.
///
/// It cannot work for a token that rotates. An application issues a new JWT every half
/// hour, so the identity's **current** token is never the token in a **past** request,
/// and every captured exchange reads as belonging to nobody. Measured against a real
/// application: a request carrying `user.id 6aa42fa1…` and a declared identity holding
/// a token for `user.id 6aa42fa1…` did not match, because the two tokens had different
/// expiry times.
///
/// The subject is the way through, and it is not a guess. A JWT is the application's own
/// signed statement about who the caller is; two tokens naming the same subject were
/// issued to the same person, and that is what the application itself concluded when it
/// served the request.
///
/// Read from `sub` first, then `user.id`, then `user_id` — the spelling varies and the
/// meaning does not. `None` when the token says nothing, and nothing is inferred from
/// silence.
pub fn subject_of(token: &str) -> Option<String> {
    let claims = claims(token)?;
    if let Some(sub) = claims.get("sub").and_then(|v| v.as_str()) {
        return Some(sub.to_string());
    }
    if let Some(id) = claims
        .get("user")
        .and_then(|user| user.get("id"))
        .and_then(|v| v.as_str())
    {
        return Some(id.to_string());
    }
    claims
        .get("user_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// The decoded payload of a JWT, or `None` for anything that is not one.
fn claims(token: &str) -> Option<serde_json::Value> {
    let token = token.strip_prefix("Bearer ").unwrap_or(token).trim();
    let mut parts = token.split('.');
    let (_header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if signature.is_empty() || parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&base64url(payload)?).ok()
}

/// The lifetime a bearer token states, if it states one.
///
/// `None` for anything that is not a JWT, and for a JWT whose payload does not carry an
/// `exp` — an opaque session id says nothing about itself and this makes nothing up.
pub fn of_jwt(token: &str) -> Option<Lifetime> {
    let claims = claims(token)?;
    let expires_at = claims.get("exp")?.as_i64()?;

    Some(Lifetime {
        expires_at,
        issued_at: claims.get("iat").and_then(serde_json::Value::as_i64),
    })
}

/// Decodes unpadded base64url, which is how a JWT writes its parts.
fn base64url(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;

    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            // Padding is not part of base64url and a JWT never writes it, but a value
            // copied through something that added it should still read.
            b'=' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JWT with the given claims, signed by nobody. Only the payload is read.
    fn token(claims: &str) -> String {
        let encode = |bytes: &[u8]| {
            const ALPHABET: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let b = [
                    chunk[0],
                    *chunk.get(1).unwrap_or(&0),
                    *chunk.get(2).unwrap_or(&0),
                ];
                let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
                let indices = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
                for (i, idx) in indices.iter().enumerate() {
                    if i <= chunk.len() {
                        out.push(ALPHABET[*idx as usize] as char);
                    }
                }
            }
            out
        };
        format!(
            "{}.{}.{}",
            encode(br#"{"alg":"HS256"}"#),
            encode(claims.as_bytes()),
            "c2lnbmF0dXJl"
        )
    }

    #[test]
    fn a_jwt_states_when_it_stops_working() {
        // The real numbers: Wolt's tokens last half an hour, and the one that sent
        // twenty doomed requests had expired eighty-five minutes earlier.
        let lifetime = of_jwt(&token(r#"{"exp":1789156566,"iat":1789154766}"#)).unwrap();
        assert_eq!(lifetime.expires_at, 1789156566);
        assert_eq!(lifetime.issued_at, Some(1789154766));
        assert_eq!(lifetime.expires_at - lifetime.issued_at.unwrap(), 1800);

        assert!(lifetime.expired_at(1789161648));
        assert!(!lifetime.expired_at(1789155000));
        assert!(lifetime.describe(1789161648).contains("expired"));
        assert!(lifetime.describe(1789155000).contains("valid for another"));
    }

    #[test]
    fn a_bearer_prefix_is_tolerated() {
        let raw = token(r#"{"exp":100}"#);
        assert_eq!(of_jwt(&format!("Bearer {raw}")), of_jwt(&raw));
    }

    #[test]
    fn anything_that_is_not_a_jwt_says_nothing() {
        // An opaque session id knows nothing about itself, and inventing a lifetime for
        // one would be worse than having none: a run would refuse to start over a
        // number nobody wrote.
        for value in [
            "",
            "opaque-session-value",
            "one.two",
            "one.two.three.four",
            "not-base64!.{}.sig",
        ] {
            assert!(of_jwt(value).is_none(), "{value:?}");
        }
    }

    #[test]
    fn a_jwt_without_an_expiry_says_nothing() {
        // Some tokens genuinely do not expire, and a missing `exp` is not a zero.
        assert!(of_jwt(&token(r#"{"sub":"alice"}"#)).is_none());
    }

    #[test]
    fn an_empty_signature_is_not_a_jwt_worth_reading() {
        // `alg:none` shaped. Nothing here verifies signatures, but a value in that
        // shape is not a credential an application issued.
        let unsigned = format!("{}.{}.", "eyJhbGciOiJub25lIn0", "eyJleHAiOjEwMH0");
        assert!(of_jwt(&unsigned).is_none());
    }

    #[test]
    fn durations_read_as_a_person_would_say_them() {
        let lifetime = Lifetime {
            expires_at: 1_000_000,
            issued_at: None,
        };
        assert!(lifetime.describe(1_000_000 - 30).contains("30 second(s)"));
        assert!(lifetime.describe(1_000_000 - 600).contains("10 minute(s)"));
        assert!(lifetime.describe(1_000_000 + 7200).contains("2 hour(s)"));
    }
}

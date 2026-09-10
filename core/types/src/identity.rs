//! Testing identities.
//!
//! Authorization testing is one of Hexora's flagship capabilities, and it rests on a
//! simple idea: the same request, replayed as several different principals, should
//! produce *different* responses. To do that the engine needs a first-class notion of
//! "who am I sending this as".
//!
//! An [`Identity`] bundles the credential material that turns an anonymous request
//! into an authenticated one. Credentials are wrapped in [`Secret`] so they never
//! reach logs, and the [`Identity`] itself carries the privilege ordering the
//! comparison engine needs to decide whether a difference is a *finding* or simply
//! the application working correctly.

use serde::{Deserialize, Serialize};

use crate::http::{Header, Headers};
use crate::ids::IdentityId;
use crate::redact::Secret;

/// How much authority an identity is expected to have.
///
/// The authorization engine uses this to decide the direction of a violation:
/// a lower-privilege identity seeing a higher-privilege identity's data is a finding;
/// the reverse usually is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeLevel {
    /// No credentials at all.
    Anonymous,
    /// An ordinary authenticated user.
    User,
    /// An elevated but non-administrative role.
    Elevated,
    /// Full administrative access.
    Administrator,
}

/// The credential material that authenticates a request as some principal.
///
/// Deliberately **not** `Serialize`: it holds [`Secret`] values, which have no
/// `Serialize` impl, so deriving one here would be a compile error. Persisting a
/// credential is a decision that must be written out explicitly with
/// [`crate::redact::exposed`] on the storage path (M3), rather than something a
/// `to_string` on a containing struct can do by accident.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Credential {
    /// No credentials. Requests are sent exactly as written.
    None,
    /// A bearer token placed in the `Authorization` header.
    Bearer {
        /// The token, without the `Bearer ` prefix.
        token: Secret<String>,
    },
    /// HTTP Basic credentials.
    Basic {
        /// The user-id, which RFC 7617 forbids from containing a colon.
        username: String,
        /// The password.
        password: Secret<String>,
    },
    /// One or more cookies.
    Cookie {
        /// The full `Cookie` header value, e.g. `session=abc; csrf=def`.
        value: Secret<String>,
    },
    /// An arbitrary header, e.g. `X-API-Key`.
    Header {
        /// The header name.
        name: String,
        /// The header value.
        value: Secret<String>,
    },
}

impl Credential {
    /// Applies this credential to a header list, replacing any existing value.
    ///
    /// Replace rather than append is correct here: an identity's credential must be
    /// unambiguous, and a request carrying two `Authorization` headers tells you
    /// nothing about which principal the server saw.
    pub fn apply(&self, headers: &mut Headers) {
        match self {
            Self::None => {
                // Strip anything the recorded request carried, so "anonymous" really
                // is anonymous rather than "whatever the browser last sent".
                headers.remove("Authorization");
                headers.remove("Cookie");
            }
            Self::Bearer { token } => {
                headers.set("Authorization", format!("Bearer {}", token.expose()));
            }
            Self::Basic { username, password } => {
                let encoded = base64_standard(format!("{username}:{}", password.expose()));
                headers.set("Authorization", format!("Basic {encoded}"));
            }
            Self::Cookie { value } => {
                headers.set("Cookie", value.expose().clone());
            }
            Self::Header { name, value } => {
                headers.set(name, value.expose().clone());
            }
        }
    }

    /// Which header names this credential controls, so comparison logic can exclude
    /// them when diffing two identities' requests.
    pub fn header_names(&self) -> Vec<&str> {
        match self {
            Self::None => vec!["Authorization", "Cookie"],
            Self::Bearer { .. } | Self::Basic { .. } => vec!["Authorization"],
            Self::Cookie { .. } => vec!["Cookie"],
            Self::Header { name, .. } => vec![name.as_str()],
        }
    }
}

/// A principal that requests can be replayed as.
///
/// Not `Serialize`, for the same reason as [`Credential`]. Anything that needs to show
/// an identity to the frontend or put it in a report sends a redacted view built for
/// that purpose, never this type.
#[derive(Debug, Clone, Deserialize)]
pub struct Identity {
    /// Stable identifier.
    pub id: IdentityId,
    /// Display name, e.g. "User A" or "admin@example.com".
    pub label: String,
    /// How much authority this identity is expected to have.
    pub privilege: PrivilegeLevel,
    /// The credential material that authenticates as this principal.
    pub credential: Credential,
    /// Extra headers to send for this identity, e.g. a tenant selector.
    #[serde(default)]
    pub extra_headers: Vec<Header>,
    /// Object identifiers known to belong to this identity.
    ///
    /// The authorization engine substitutes these into request parameters to build
    /// cross-identity access attempts, and uses them to recognise leaked data in a
    /// response.
    #[serde(default)]
    pub owned_object_ids: Vec<String>,
}

impl Identity {
    /// The built-in anonymous identity.
    pub fn anonymous() -> Self {
        Self {
            id: IdentityId::new(),
            label: "Anonymous".into(),
            privilege: PrivilegeLevel::Anonymous,
            credential: Credential::None,
            extra_headers: Vec::new(),
            owned_object_ids: Vec::new(),
        }
    }

    /// Builds an authenticated identity from a bearer token.
    pub fn bearer(label: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            id: IdentityId::new(),
            label: label.into(),
            privilege: PrivilegeLevel::User,
            credential: Credential::Bearer {
                token: Secret::new(token.into()),
            },
            extra_headers: Vec::new(),
            owned_object_ids: Vec::new(),
        }
    }

    /// Rewrites a header list so the request is sent as this identity.
    pub fn authenticate(&self, headers: &mut Headers) {
        self.credential.apply(headers);
        for header in &self.extra_headers {
            headers.set(&header.name, header.value_lossy().into_owned());
        }
    }

    /// Whether a response reaching `self` while containing data owned by `other`
    /// would constitute a privilege violation.
    ///
    /// Equal-privilege identities still violate each other: two ordinary users
    /// reading each other's records is exactly the IDOR case.
    pub fn violated_by_access_to(&self, other: &Identity) -> bool {
        self.id != other.id && self.privilege <= other.privilege
    }
}

/// Minimal base64 (standard alphabet, padded).
///
/// Kept local so `hexora-types` stays dependency-light; the engine crates use the
/// `base64` crate where performance matters.
fn base64_standard(input: impl AsRef<[u8]>) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_ref();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
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
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_credentials_set_the_authorization_header() {
        let identity = Identity::bearer("User A", "tok-123");
        let mut headers = Headers::new();
        identity.authenticate(&mut headers);
        assert_eq!(
            headers.get("Authorization").unwrap().value_lossy(),
            "Bearer tok-123"
        );
    }

    #[test]
    fn authenticating_replaces_rather_than_duplicates_credentials() {
        let mut headers = Headers::new();
        headers.append(Header::new("Authorization", "Bearer stale"));
        Identity::bearer("User A", "fresh").authenticate(&mut headers);
        assert_eq!(headers.count("Authorization"), 1);
        assert_eq!(
            headers.get("Authorization").unwrap().value_lossy(),
            "Bearer fresh"
        );
    }

    #[test]
    fn anonymous_strips_inherited_credentials() {
        let mut headers = Headers::new();
        headers.append(Header::new("Authorization", "Bearer leftover"));
        headers.append(Header::new("Cookie", "session=leftover"));
        Identity::anonymous().authenticate(&mut headers);
        assert!(headers.get("Authorization").is_none());
        assert!(
            headers.get("Cookie").is_none(),
            "anonymous must really be anonymous"
        );
    }

    #[test]
    fn secrets_do_not_leak_through_identity_debug_output() {
        let identity = Identity::bearer("User A", "super-secret-token");
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("User A"));
        assert!(!rendered.contains("super-secret-token"), "{rendered}");
    }

    /// Obviously-fake fixture credentials.
    ///
    /// Hexora's own repository must stay clean for secret scanners. That means no
    /// credential-shaped literal anywhere in the tree — not even a real RFC's worked
    /// example, which is still a valid Base64 Basic Authentication string and will be
    /// flagged as one. Naming the values this way makes it unambiguous to a human
    /// reviewer that nothing here was ever live.
    const TEST_USER: &str = "TEST_USER";
    const TEST_PASSWORD: &str = "TEST_PASSWORD_NOT_A_SECRET";

    #[test]
    fn basic_auth_encodes_credentials_correctly() {
        let cred = Credential::Basic {
            username: TEST_USER.into(),
            password: Secret::new(TEST_PASSWORD.into()),
        };
        let mut headers = Headers::new();
        cred.apply(&mut headers);

        let value = headers
            .get("Authorization")
            .unwrap()
            .value_lossy()
            .into_owned();
        let payload = value
            .strip_prefix("Basic ")
            .expect("RFC 7617 requires the Basic scheme prefix");

        // Decoded with an independently written decoder rather than compared against a
        // hard-coded base64 string. That keeps this a genuine round-trip check *and*
        // keeps a Basic-auth credential literal out of the repository.
        assert_eq!(
            base64_decode(payload),
            format!("{TEST_USER}:{TEST_PASSWORD}").into_bytes(),
            "RFC 7617 encodes user-id:password"
        );
    }

    /// A minimal standard-alphabet base64 decoder, for tests only.
    fn base64_decode(input: &str) -> Vec<u8> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0u32;
        let mut bit_count = 0u32;
        let mut out = Vec::new();
        for byte in input.bytes().filter(|b| *b != b'=') {
            let value = ALPHABET
                .iter()
                .position(|c| *c == byte)
                .unwrap_or_else(|| panic!("invalid base64 character {byte:?}"));
            bits = (bits << 6) | value as u32;
            bit_count += 6;
            if bit_count >= 8 {
                bit_count -= 8;
                out.push((bits >> bit_count) as u8);
            }
        }
        out
    }

    #[test]
    fn base64_pads_correctly_for_every_input_length() {
        assert_eq!(base64_standard("f"), "Zg==");
        assert_eq!(base64_standard("fo"), "Zm8=");
        assert_eq!(base64_standard("foo"), "Zm9v");
        assert_eq!(base64_standard("foob"), "Zm9vYg==");
        assert_eq!(base64_standard("fooba"), "Zm9vYmE=");
        assert_eq!(base64_standard("foobar"), "Zm9vYmFy");
    }

    #[test]
    fn peer_users_violate_each_other() {
        let a = Identity::bearer("User A", "a");
        let b = Identity::bearer("User B", "b");
        assert!(
            a.violated_by_access_to(&b),
            "peer-to-peer access is the IDOR case"
        );
    }

    #[test]
    fn an_admin_reading_user_data_is_not_a_violation() {
        let user = Identity::bearer("User A", "a");
        let mut admin = Identity::bearer("Admin", "root");
        admin.privilege = PrivilegeLevel::Administrator;
        assert!(!admin.violated_by_access_to(&user));
        assert!(user.violated_by_access_to(&admin));
    }

    #[test]
    fn an_identity_never_violates_itself() {
        let a = Identity::bearer("User A", "a");
        assert!(!a.violated_by_access_to(&a));
    }
}

//! Declared object identifiers, and where they live in a request.
//!
//! An authorization matrix replays a request *as written*. That answers "can User B
//! reach this URL?" and cannot answer "can User B reach **User A's** invoice?",
//! because the tester may only ever have captured User B asking for their own.
//!
//! Constructing that second request needs two facts the tool cannot derive:
//!
//! * **which value in the request identifies an object**, and
//! * **who that object belongs to.**
//!
//! Both are declared by a human. Nothing here guesses. A value that merely *looks*
//! like an identifier is not one — `/api/v2/users` has a `2` in it — and a tool that
//! guessed would generate traffic against an endpoint nobody authorized and then
//! reason about the result as if it meant something.
//!
//! # What a declaration is, and is not
//!
//! [`ObjectDeclaration`] says: *this exact string, at this exact place in a request,
//! is an object belonging to this identity.* It is data entry. It causes no traffic
//! on its own; running the test is a separate, explicit act.
//!
//! It is **not** evidence of ownership. It is the tester's assertion of ownership,
//! and every finding built on it says so — which is why a constructed attempt that
//! cannot demonstrate the returned object really is the declared one produces a lead
//! rather than a finding.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::HexoraError;
use crate::ids::{IdentityId, ObjectId, RequestId};

/// The longest identifier that may be declared.
///
/// Not a guess about identifier formats: it is a bound on what will be spliced into
/// a request line. Without one, a declaration is a way to make Hexora emit a request
/// head of arbitrary size, and the limit for those belongs at the point the value
/// enters the system rather than at the point it reaches the socket.
pub const MAX_IDENTIFIER_LEN: usize = 512;

/// Where in a request an object identifier sits.
///
/// Deliberately four places and no parser framework. Each one is addressed the way it
/// is addressed on the wire — a path segment by index, a query parameter by name
/// *and* occurrence, a header the same, a body by byte offset — so a substitution
/// touches those bytes and nothing else.
///
/// There is no JSON pointer variant, on purpose. Parsing a body to `serde_json` and
/// re-serializing it would reorder keys, drop duplicate keys and rewrite whitespace,
/// which is exactly the normalization the rest of this codebase refuses to do; a
/// request that changed in ways the tester did not ask for is not the request they
/// meant to send. [`ObjectLocation::Body`] covers JSON, form and XML bodies alike by
/// replacing the identifier's bytes where they actually are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObjectLocation {
    /// The nth `/`-separated segment of the request target, counting from zero after
    /// the leading slash.
    PathSegment {
        /// Which segment.
        index: usize,
    },
    /// The value of a query parameter.
    Query {
        /// The parameter name, as written.
        name: String,
        /// Which occurrence, for a query string that repeats a name. Duplicate
        /// parameters are frequently the point of a test, so they are addressed
        /// rather than collapsed.
        occurrence: usize,
    },
    /// The value of a header field.
    Header {
        /// The field name, as written.
        name: String,
        /// Which occurrence, for a repeated field.
        occurrence: usize,
    },
    /// A byte range in the request body.
    Body {
        /// Byte offset of the identifier in the body as sent.
        offset: usize,
    },
    /// No place was recorded.
    ///
    /// The honest answer when a tester knows an identifier belongs to somebody
    /// without having captured a request containing it — which is the ordinary case
    /// for the object you are trying to *reach*. A run substitutes it wherever the
    /// sender's own object sits in the request being built from, and the attempt
    /// records that concrete place.
    Anywhere,
}

impl ObjectLocation {
    /// A short description for a table or a report.
    pub fn describe(&self) -> String {
        match self {
            Self::PathSegment { index } => format!("path segment {index}"),
            Self::Query { name, occurrence } => match occurrence {
                0 => format!("query parameter {name}"),
                n => format!("query parameter {name} (occurrence {n})"),
            },
            Self::Header { name, occurrence } => match occurrence {
                0 => format!("header {name}"),
                n => format!("header {name} (occurrence {n})"),
            },
            Self::Body { offset } => format!("body at byte {offset}"),
            Self::Anywhere => "wherever this kind of object appears".to_string(),
        }
    }

    /// A stable key, so two declarations of the same value in the same place are the
    /// same declaration.
    pub fn key(&self) -> String {
        match self {
            Self::PathSegment { index } => format!("path:{index}"),
            Self::Query { name, occurrence } => format!("query:{name}:{occurrence}"),
            Self::Header { name, occurrence } => format!("header:{name}:{occurrence}"),
            Self::Body { offset } => format!("body:{offset}"),
            Self::Anywhere => "anywhere".to_string(),
        }
    }
}

/// An object identifier a tester has declared, and who it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectDeclaration {
    /// Stable identifier.
    pub id: ObjectId,
    /// What kind of object it is, e.g. `invoice`. For the reader, not for matching.
    pub name: String,
    /// The identifier itself, exactly as it appears in the request.
    pub value: String,
    /// The identity the tester says owns it.
    pub owner: IdentityId,
    /// The request the value was found in, when it was declared from one.
    pub source_request: Option<RequestId>,
    /// Where in that request it sat.
    pub location: ObjectLocation,
    /// When it was declared.
    pub created_at: DateTime<Utc>,
}

impl ObjectDeclaration {
    /// Builds a declaration, rejecting anything that cannot safely be spliced into a
    /// request.
    ///
    /// The checks are the reason this is a constructor rather than a struct literal.
    /// A declared value ends up in a request line, a header field or a body, so a
    /// value carrying CR or LF is request splitting waiting for somewhere to happen —
    /// and it would happen inside a tool the tester trusts to send what it says it is
    /// sending.
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        owner: IdentityId,
        location: ObjectLocation,
    ) -> crate::Result<Self> {
        let name = name.into();
        let value = value.into();
        validate_identifier(&value)?;
        if name.trim().is_empty() {
            return Err(HexoraError::invalid_input(
                "name",
                "an object declaration needs a name, e.g. \"invoice\"",
            ));
        }

        Ok(Self {
            id: ObjectId::new(),
            name,
            value,
            owner,
            source_request: None,
            location,
            created_at: Utc::now(),
        })
    }

    /// Records which request the value was found in.
    pub fn found_in(mut self, request: RequestId) -> Self {
        self.source_request = Some(request);
        self
    }

    /// A one-line description, for tables and confirmations.
    pub fn describe(&self) -> String {
        format!(
            "{} {} in {}",
            self.name,
            self.value,
            self.location.describe()
        )
    }
}

/// Checks that a value may be spliced into a request.
///
/// Rejected: empty values, anything over [`MAX_IDENTIFIER_LEN`], and any control
/// character. CR and LF are the ones that matter — a header value containing them
/// splits the request — but no identifier legitimately contains a NUL or a vertical
/// tab either, and a narrow allowlist here costs a tester nothing while removing a
/// class of surprise entirely.
pub fn validate_identifier(value: &str) -> crate::Result<()> {
    if value.is_empty() {
        return Err(HexoraError::invalid_input(
            "value",
            "an object identifier cannot be empty",
        ));
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(HexoraError::invalid_input(
            "value",
            format!(
                "an object identifier may be at most {MAX_IDENTIFIER_LEN} bytes; this \
                 one is {}",
                value.len()
            ),
        ));
    }
    if let Some(bad) = value.chars().find(|c| c.is_control()) {
        return Err(HexoraError::invalid_input(
            "value",
            format!(
                "an object identifier cannot contain control characters (found {:?}). \
                 A value carrying CR or LF would split the request it is spliced into",
                bad
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration(value: &str) -> crate::Result<ObjectDeclaration> {
        ObjectDeclaration::new(
            "invoice",
            value,
            IdentityId::new(),
            ObjectLocation::PathSegment { index: 1 },
        )
    }

    #[test]
    fn a_plain_identifier_is_accepted() {
        let declared = declaration("invoice-1001").unwrap();
        assert_eq!(declared.value, "invoice-1001");
        assert!(declared.source_request.is_none());
    }

    #[test]
    fn a_value_containing_crlf_is_refused() {
        // It would be spliced into a request line or a header field, where CRLF ends
        // the message. A tool that sent that quietly would be lying about what it
        // sent.
        let error = declaration("invoice\r\nX-Injected: 1").unwrap_err();
        assert_eq!(error.code(), "invalid_input");
        assert!(error.to_string().contains("control"), "{error}");
    }

    #[test]
    fn an_oversized_identifier_is_refused() {
        let error = declaration(&"a".repeat(MAX_IDENTIFIER_LEN + 1)).unwrap_err();
        assert!(error.to_string().contains("512"), "{error}");
    }

    #[test]
    fn an_empty_identifier_is_refused() {
        assert!(declaration("").is_err());
    }

    #[test]
    fn a_declaration_needs_a_name() {
        let error = ObjectDeclaration::new(
            "  ",
            "invoice-1001",
            IdentityId::new(),
            ObjectLocation::PathSegment { index: 0 },
        )
        .unwrap_err();
        assert!(error.to_string().contains("name"), "{error}");
    }

    #[test]
    fn duplicate_query_parameters_are_addressed_rather_than_collapsed() {
        let first = ObjectLocation::Query {
            name: "id".into(),
            occurrence: 0,
        };
        let second = ObjectLocation::Query {
            name: "id".into(),
            occurrence: 1,
        };
        assert_ne!(first.key(), second.key());
        assert!(
            second.describe().contains("occurrence 1"),
            "{}",
            second.describe()
        );
    }

    #[test]
    fn a_location_round_trips_through_json() {
        let location = ObjectLocation::Body { offset: 412 };
        let json = serde_json::to_string(&location).unwrap();
        let back: ObjectLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(location, back);
    }
}

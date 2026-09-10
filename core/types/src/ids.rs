//! Stable identifiers for persisted entities.
//!
//! All Hexora IDs are UUIDv7: time-ordered, so they sort chronologically and index
//! well in SQLite, while staying globally unique so a project can be merged from
//! several collaborating testers without renumbering.
//!
//! The [`define_id`] macro produces a distinct newtype per entity, which makes it a
//! compile error to pass a `RequestId` where a `FindingId` is expected.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::HexoraError;

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// The short prefix used when rendering this ID to the user.
            pub const PREFIX: &'static str = $prefix;

            /// Generates a new time-ordered identifier.
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an existing UUID, e.g. when loading from the database.
            pub const fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            /// The underlying UUID.
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0.simple())
            }
        }

        impl FromStr for $name {
            type Err = HexoraError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let body = s.strip_prefix(concat!($prefix, "_")).unwrap_or(s);
                Uuid::parse_str(body).map(Self).map_err(|e| {
                    HexoraError::invalid_input(stringify!($name), e.to_string())
                })
            }
        }
    };
}

define_id!(
    /// Identifies a project (one `.hexora` database).
    ProjectId,
    "prj"
);
define_id!(
    /// Identifies a target host or application within a project.
    TargetId,
    "tgt"
);
define_id!(
    /// Identifies a captured or crafted HTTP request.
    RequestId,
    "req"
);
define_id!(
    /// Identifies an HTTP response. Paired with exactly one [`RequestId`].
    ResponseId,
    "res"
);
define_id!(
    /// Identifies one WebSocket message.
    WsMessageId,
    "ws"
);
define_id!(
    /// Identifies a vulnerability finding.
    FindingId,
    "fnd"
);
define_id!(
    /// Identifies a scanner job.
    ScanJobId,
    "scn"
);
define_id!(
    /// Identifies a fuzzing/intruder attack run.
    AttackId,
    "atk"
);
define_id!(
    /// Identifies an out-of-band interaction.
    InteractionId,
    "oob"
);
define_id!(
    /// Identifies a workflow definition.
    WorkflowId,
    "wfl"
);
define_id!(
    /// Identifies a single workflow execution.
    WorkflowRunId,
    "wrn"
);
define_id!(
    /// Identifies a testing identity (anonymous, user A, admin, ...).
    IdentityId,
    "idn"
);
define_id!(
    /// Identifies an installed extension instance.
    ExtensionId,
    "ext"
);
define_id!(
    /// Identifies an audit-log event.
    AuditEventId,
    "aud"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_render_with_their_prefix() {
        let id = RequestId::new();
        assert!(id.to_string().starts_with("req_"), "{id}");
    }

    #[test]
    fn ids_round_trip_through_display_and_parse() {
        let id = FindingId::new();
        let parsed: FindingId = id.to_string().parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn parsing_accepts_a_bare_uuid_without_the_prefix() {
        let id = TargetId::new();
        let bare = id.as_uuid().to_string();
        assert_eq!(bare.parse::<TargetId>().unwrap(), id);
    }

    #[test]
    fn parsing_rejects_garbage() {
        assert!("not-a-uuid".parse::<TargetId>().is_err());
    }

    #[test]
    fn uuidv7_ids_sort_in_creation_order() {
        let mut ids: Vec<RequestId> = (0..64).map(|_| RequestId::new()).collect();
        let generated = ids.clone();
        ids.sort();
        assert_eq!(ids, generated, "UUIDv7 ids must sort chronologically");
    }

    #[test]
    fn ids_are_unique() {
        let a = RequestId::new();
        let b = RequestId::new();
        assert_ne!(a, b);
    }
}

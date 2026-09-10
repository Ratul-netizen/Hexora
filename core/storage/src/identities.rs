//! Persisting testing identities.
//!
//! An authorization test is only as reproducible as the identities it ran as. A
//! matrix that proves "User B read User A's invoice" is worthless in a report if
//! nobody can say afterwards *which* credential User B was, so identities live in the
//! project alongside the traffic they produced.
//!
//! # Why writing a credential is deliberately awkward
//!
//! [`hexora_types::Credential`] has no `Serialize` impl, by design: a struct holding a
//! [`Secret`](hexora_types::Secret) that tries to derive one fails to compile rather
//! than leaking the value (see `core/types/src/redact.rs`). Persistence therefore
//! cannot happen by accident — it needs the explicit mirror type below, which opts
//! each secret field into cleartext with `#[serde(with = "redact::exposed")]`.
//!
//! That mirror is the single place in Hexora where a credential is written out in the
//! clear, which is exactly the property review needs: one greppable location to
//! examine, rather than "wherever serde happened to reach".
//!
//! # What this does not do yet
//!
//! The stored credential is **not encrypted at rest**. `docs/threat-model.md` calls
//! for encryption under a project passphrase; that is not implemented, so a project
//! file is as sensitive as the credentials it holds. [`IdentityStore::put`] says so in
//! its own documentation rather than leaving a tester to assume otherwise.

use hexora_types::identity::{Credential, Identity, PrivilegeLevel};
use hexora_types::ids::IdentityId;
use hexora_types::redact::Secret;
use hexora_types::Header;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::error::{Result, StorageError};
use crate::MetadataDb;

/// A [`Credential`] in the one form that may be written to disk.
///
/// Structurally identical to `Credential` and tagged the same way, so a project
/// written by one release reads back in the next. The difference is only that every
/// secret field names [`hexora_types::redact::exposed`] explicitly.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredCredential {
    None,
    Bearer {
        #[serde(with = "hexora_types::redact::exposed")]
        token: Secret<String>,
    },
    Basic {
        username: String,
        #[serde(with = "hexora_types::redact::exposed")]
        password: Secret<String>,
    },
    Cookie {
        #[serde(with = "hexora_types::redact::exposed")]
        value: Secret<String>,
    },
    Header {
        name: String,
        #[serde(with = "hexora_types::redact::exposed")]
        value: Secret<String>,
    },
}

impl From<&Credential> for StoredCredential {
    fn from(credential: &Credential) -> Self {
        match credential {
            Credential::None => Self::None,
            Credential::Bearer { token } => Self::Bearer {
                token: Secret::new(token.expose().clone()),
            },
            Credential::Basic { username, password } => Self::Basic {
                username: username.clone(),
                password: Secret::new(password.expose().clone()),
            },
            Credential::Cookie { value } => Self::Cookie {
                value: Secret::new(value.expose().clone()),
            },
            Credential::Header { name, value } => Self::Header {
                name: name.clone(),
                value: Secret::new(value.expose().clone()),
            },
        }
    }
}

impl From<StoredCredential> for Credential {
    fn from(stored: StoredCredential) -> Self {
        match stored {
            StoredCredential::None => Self::None,
            StoredCredential::Bearer { token } => Self::Bearer { token },
            StoredCredential::Basic { username, password } => Self::Basic { username, password },
            StoredCredential::Cookie { value } => Self::Cookie { value },
            StoredCredential::Header { name, value } => Self::Header { name, value },
        }
    }
}

/// Reads and writes the identities a project tests as.
#[derive(Debug, Clone)]
pub struct IdentityStore {
    db: MetadataDb,
}

impl IdentityStore {
    /// Opens the identity store over a project's metadata database.
    pub fn new(db: MetadataDb) -> Self {
        Self { db }
    }

    /// Inserts an identity, or replaces the one already stored under its id.
    ///
    /// **The credential is written in cleartext.** Project files are as sensitive as
    /// the sessions they hold; encryption at rest is not implemented.
    pub fn put(&self, identity: &Identity) -> Result<()> {
        let credential = serde_json::to_string(&StoredCredential::from(&identity.credential))
            .map_err(|e| StorageError::Decode {
                entity: "Credential",
                reason: e.to_string(),
            })?;
        let extra_headers =
            serde_json::to_string(&identity.extra_headers).map_err(|e| StorageError::Decode {
                entity: "extra headers",
                reason: e.to_string(),
            })?;
        let owned = serde_json::to_string(&identity.owned_object_ids).map_err(|e| {
            StorageError::Decode {
                entity: "owned object ids",
                reason: e.to_string(),
            }
        })?;

        let conn = self.db.connection()?;
        conn.execute(
            "INSERT INTO identities
                (id, label, privilege, credential_json, extra_headers, owned_object_ids,
                 created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                label = excluded.label,
                privilege = excluded.privilege,
                credential_json = excluded.credential_json,
                extra_headers = excluded.extra_headers,
                owned_object_ids = excluded.owned_object_ids",
            params![
                identity.id.to_string(),
                identity.label,
                privilege_str(identity.privilege),
                credential,
                extra_headers,
                owned,
                crate::traffic::now(),
            ],
        )?;
        Ok(())
    }

    /// Every stored identity, in creation order.
    pub fn list(&self) -> Result<Vec<Identity>> {
        let conn = self.db.connection()?;
        let mut statement = conn.prepare(
            "SELECT id, label, privilege, credential_json, extra_headers, owned_object_ids
             FROM identities ORDER BY id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;

        let mut identities = Vec::new();
        for row in rows {
            identities.push(decode(row?)?);
        }
        Ok(identities)
    }

    /// One identity by id.
    pub fn get(&self, id: IdentityId) -> Result<Identity> {
        self.list()?
            .into_iter()
            .find(|identity| identity.id == id)
            .ok_or_else(|| StorageError::NotFound {
                entity: "identity",
                id: id.to_string(),
            })
    }

    /// One identity by its label, which is what a tester types on the command line.
    ///
    /// Labels are not unique in the schema — two engagements' worth of "Admin" is a
    /// reasonable thing to have — so an ambiguous label is an error rather than a
    /// silent pick of the first match. Choosing for the tester here would mean sending
    /// a request as the wrong principal, which is the one mistake this whole subsystem
    /// exists to make impossible.
    pub fn by_label(&self, label: &str) -> Result<Identity> {
        let mut matches = self
            .list()?
            .into_iter()
            .filter(|identity| identity.label.eq_ignore_ascii_case(label));

        let first = matches.next().ok_or_else(|| StorageError::NotFound {
            entity: "identity",
            id: label.to_string(),
        })?;
        if matches.next().is_some() {
            return Err(StorageError::Ambiguous {
                entity: "identity",
                id: label.to_string(),
            });
        }
        Ok(first)
    }

    /// Removes an identity. Requests already sent as it keep their traffic; the
    /// `requests.identity_id` foreign key is `ON DELETE SET NULL`.
    ///
    /// Returns whether a row was removed.
    pub fn delete(&self, id: IdentityId) -> Result<bool> {
        let conn = self.db.connection()?;
        let affected = conn.execute(
            "DELETE FROM identities WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(affected > 0)
    }
}

fn decode(row: (String, String, String, String, String, String)) -> Result<Identity> {
    let (id, label, privilege, credential, extra_headers, owned) = row;

    let stored: StoredCredential =
        serde_json::from_str(&credential).map_err(|e| StorageError::Decode {
            entity: "Credential",
            reason: e.to_string(),
        })?;
    let extra_headers: Vec<Header> =
        serde_json::from_str(&extra_headers).map_err(|e| StorageError::Decode {
            entity: "extra headers",
            reason: e.to_string(),
        })?;
    let owned_object_ids: Vec<String> =
        serde_json::from_str(&owned).map_err(|e| StorageError::Decode {
            entity: "owned object ids",
            reason: e.to_string(),
        })?;

    Ok(Identity {
        id: id.parse().map_err(|e| StorageError::Decode {
            entity: "IdentityId",
            reason: format!("{e}"),
        })?,
        label,
        privilege: parse_privilege(&privilege)?,
        credential: stored.into(),
        extra_headers,
        owned_object_ids,
    })
}

fn privilege_str(privilege: PrivilegeLevel) -> &'static str {
    match privilege {
        PrivilegeLevel::Anonymous => "anonymous",
        PrivilegeLevel::User => "user",
        PrivilegeLevel::Elevated => "elevated",
        PrivilegeLevel::Administrator => "administrator",
    }
}

fn parse_privilege(value: &str) -> Result<PrivilegeLevel> {
    match value {
        "anonymous" => Ok(PrivilegeLevel::Anonymous),
        "user" => Ok(PrivilegeLevel::User),
        "elevated" => Ok(PrivilegeLevel::Elevated),
        "administrator" => Ok(PrivilegeLevel::Administrator),
        other => Err(StorageError::Decode {
            entity: "PrivilegeLevel",
            reason: format!("unknown privilege {other:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TOKEN: &str = "TEST_TOKEN_NOT_A_SECRET";

    fn store() -> IdentityStore {
        IdentityStore::new(MetadataDb::in_memory().unwrap())
    }

    #[test]
    fn an_identity_survives_a_round_trip() {
        let store = store();
        let mut identity = Identity::bearer("User A", TEST_TOKEN);
        identity.owned_object_ids = vec!["acct-1".into(), "acct-2".into()];
        identity.extra_headers = vec![Header::new("X-Tenant", "acme")];
        store.put(&identity).unwrap();

        let read = store.get(identity.id).unwrap();
        assert_eq!(read.label, "User A");
        assert_eq!(read.privilege, PrivilegeLevel::User);
        assert_eq!(read.owned_object_ids, ["acct-1", "acct-2"]);
        assert_eq!(read.extra_headers[0].name, "X-Tenant");
        match read.credential {
            Credential::Bearer { token } => assert_eq!(token.expose(), TEST_TOKEN),
            other => panic!("credential changed kind on the way back: {other:?}"),
        }
    }

    #[test]
    fn every_privilege_level_round_trips() {
        let store = store();
        for privilege in [
            PrivilegeLevel::Anonymous,
            PrivilegeLevel::User,
            PrivilegeLevel::Elevated,
            PrivilegeLevel::Administrator,
        ] {
            let mut identity = Identity::bearer(format!("{privilege:?}"), TEST_TOKEN);
            identity.privilege = privilege;
            store.put(&identity).unwrap();
            assert_eq!(store.get(identity.id).unwrap().privilege, privilege);
        }
    }

    #[test]
    fn every_credential_kind_round_trips() {
        let store = store();
        let credentials = [
            Credential::None,
            Credential::Bearer {
                token: Secret::new(TEST_TOKEN.into()),
            },
            Credential::Basic {
                username: "TEST_USER".into(),
                password: Secret::new("TEST_PASSWORD_NOT_A_SECRET".into()),
            },
            Credential::Cookie {
                value: Secret::new("session=TEST_SESSION".into()),
            },
            Credential::Header {
                name: "X-API-Key".into(),
                value: Secret::new("TEST_KEY".into()),
            },
        ];

        for credential in credentials {
            let mut identity = Identity::anonymous();
            identity.label = format!("{credential:?}");
            identity.credential = credential.clone();
            store.put(&identity).unwrap();

            // Compared by the header it produces rather than by structural equality:
            // what matters is that the credential still authenticates the same way.
            let mut expected = hexora_types::Headers::new();
            credential.apply(&mut expected);
            let mut actual = hexora_types::Headers::new();
            store
                .get(identity.id)
                .unwrap()
                .credential
                .apply(&mut actual);
            assert_eq!(
                header_block(&expected),
                header_block(&actual),
                "{credential:?} did not survive storage"
            );
        }
    }

    fn header_block(headers: &hexora_types::Headers) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|h| (h.name.clone(), h.value_lossy().into_owned()))
            .collect()
    }

    #[test]
    fn putting_the_same_id_twice_updates_rather_than_duplicates() {
        let store = store();
        let mut identity = Identity::bearer("User A", TEST_TOKEN);
        store.put(&identity).unwrap();
        identity.label = "User A (renamed)".into();
        store.put(&identity).unwrap();

        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].label, "User A (renamed)");
    }

    #[test]
    fn an_ambiguous_label_is_refused_rather_than_guessed() {
        let store = store();
        store.put(&Identity::bearer("Admin", TEST_TOKEN)).unwrap();
        store.put(&Identity::bearer("Admin", TEST_TOKEN)).unwrap();

        let error = store.by_label("Admin").unwrap_err();
        assert!(
            matches!(error, StorageError::Ambiguous { .. }),
            "sending as the wrong principal must never be a silent default: {error}"
        );
    }

    #[test]
    fn labels_are_matched_without_regard_to_case() {
        let store = store();
        let identity = Identity::bearer("User A", TEST_TOKEN);
        store.put(&identity).unwrap();
        assert_eq!(store.by_label("user a").unwrap().id, identity.id);
    }

    #[test]
    fn deleting_reports_whether_anything_was_removed() {
        let store = store();
        let identity = Identity::bearer("User A", TEST_TOKEN);
        store.put(&identity).unwrap();
        assert!(store.delete(identity.id).unwrap());
        assert!(!store.delete(identity.id).unwrap());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn a_missing_identity_is_not_found_rather_than_empty() {
        let error = store().get(IdentityId::new()).unwrap_err();
        assert!(matches!(error, StorageError::NotFound { .. }), "{error}");
    }
}

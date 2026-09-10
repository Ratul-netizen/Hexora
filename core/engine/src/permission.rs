//! The extension permission model.
//!
//! Installing an extension means running someone else's code inside a tool that holds
//! session cookies, bearer tokens and a client's traffic. The model here follows one
//! rule, stated as invariant 4 in `docs/security-invariants.md`:
//!
//! > **Nothing is granted implicitly.** An extension receives exactly the
//! > capabilities the user approved, and a capability that was never granted is not
//! > available at any later point.
//!
//! Two properties do the work:
//!
//! * A [`GrantSet`] can only ever be *narrowed* after construction
//!   ([`GrantSet::revoke`], [`GrantSet::intersect`]). There is deliberately no `add`
//!   method, so no code path can quietly widen an extension's reach at runtime.
//! * Capabilities are [ordered by implication](Capability::implies), so a check for
//!   `ProjectRead` is satisfied by a `ProjectWrite` grant, and a grant of the narrow
//!   capability never satisfies a check for the broad one.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Something an extension may be permitted to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Observe HTTP traffic passing through the proxy.
    ///
    /// This includes `Authorization` headers and cookies, so it is a genuinely
    /// sensitive grant and the UI presents it as one.
    HttpRead,
    /// Send requests through the engine. Still subject to project scope.
    HttpSend,
    /// Read stored project data: targets, history, findings.
    ProjectRead,
    /// Modify project data, including creating findings.
    ProjectWrite,
    /// Contribute UI: tabs, context-menu entries, editors.
    Ui,
    /// Register scanner checks.
    Scanner,
    /// Define and run workflows.
    Workflow,
    /// Read and write files outside the project directory.
    Filesystem,
    /// Open network connections that do not go through the engine, and therefore are
    /// not covered by scope enforcement or traffic capture.
    RawNetwork,
    /// Execute other programs.
    ProcessExecute,
    /// Read stored identity credentials in cleartext.
    Credentials,
}

impl Capability {
    /// Every capability, for rendering an install dialog.
    pub const ALL: &'static [Capability] = &[
        Capability::HttpRead,
        Capability::HttpSend,
        Capability::ProjectRead,
        Capability::ProjectWrite,
        Capability::Ui,
        Capability::Scanner,
        Capability::Workflow,
        Capability::Filesystem,
        Capability::RawNetwork,
        Capability::ProcessExecute,
        Capability::Credentials,
    ];

    /// Whether holding `self` implies holding `other`.
    ///
    /// Only the write-implies-read direction exists. Nothing implies
    /// [`Capability::Credentials`], [`Capability::Filesystem`],
    /// [`Capability::RawNetwork`] or [`Capability::ProcessExecute`]: those are the
    /// capabilities that turn a misbehaving extension into a compromise of the
    /// tester's machine or the client's credentials, so each must be asked for by
    /// name.
    pub fn implies(&self, other: Capability) -> bool {
        *self == other || matches!((self, other), (Self::ProjectWrite, Self::ProjectRead))
    }

    /// Whether this capability warrants a prominent warning at install time.
    pub fn is_dangerous(&self) -> bool {
        matches!(
            self,
            Self::Filesystem | Self::RawNetwork | Self::ProcessExecute | Self::Credentials
        )
    }

    /// A one-line explanation for the install dialog, phrased as consequence rather
    /// than as mechanism — "can read your saved credentials" tells the user something
    /// they can act on; "CREDENTIALS" does not.
    pub fn explanation(&self) -> &'static str {
        match self {
            Self::HttpRead => "See all proxied traffic, including cookies and auth tokens",
            Self::HttpSend => "Send requests to in-scope targets",
            Self::ProjectRead => "Read project data: targets, history and findings",
            Self::ProjectWrite => "Modify project data and create findings",
            Self::Ui => "Add tabs and menu entries to the interface",
            Self::Scanner => "Register scanner checks that run against targets",
            Self::Workflow => "Define and run workflows",
            Self::Filesystem => "Read and write files anywhere on this machine",
            Self::RawNetwork => "Open connections that bypass scope enforcement and traffic capture",
            Self::ProcessExecute => "Run other programs on this machine",
            Self::Credentials => "Read stored credentials for your testing identities",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::HttpRead => "http:read",
            Self::HttpSend => "http:send",
            Self::ProjectRead => "project:read",
            Self::ProjectWrite => "project:write",
            Self::Ui => "ui",
            Self::Scanner => "scanner",
            Self::Workflow => "workflow",
            Self::Filesystem => "filesystem",
            Self::RawNetwork => "network:raw",
            Self::ProcessExecute => "process:execute",
            Self::Credentials => "credentials",
        };
        f.write_str(name)
    }
}

/// The capabilities actually granted to one extension.
///
/// Constructed once from what the user approved and never widened afterwards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantSet {
    granted: BTreeSet<Capability>,
}

impl GrantSet {
    /// An extension with no permissions at all. This is the starting point for every
    /// extension, and the result of denying an install prompt.
    pub fn none() -> Self {
        Self::default()
    }

    /// Records what the user approved.
    ///
    /// This is the only way to introduce a capability, and it is called once, at
    /// install or when the user edits permissions — never from a code path an
    /// extension can reach.
    pub fn granted_by_user(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self { granted: capabilities.into_iter().collect() }
    }

    /// Whether this grant set permits `capability`.
    pub fn allows(&self, capability: Capability) -> bool {
        self.granted.iter().any(|held| held.implies(capability))
    }

    /// Removes a capability.
    pub fn revoke(&mut self, capability: Capability) {
        self.granted.remove(&capability);
    }

    /// Narrows this set to what `other` also permits.
    ///
    /// Used when an extension spawns a sub-task or a nested runtime: the child can
    /// never hold more than its parent.
    pub fn intersect(&self, other: &GrantSet) -> Self {
        Self { granted: self.granted.iter().copied().filter(|c| other.allows(*c)).collect() }
    }

    /// The granted capabilities, for display.
    pub fn capabilities(&self) -> impl Iterator<Item = Capability> + '_ {
        self.granted.iter().copied()
    }

    /// Whether nothing is granted.
    pub fn is_empty(&self) -> bool {
        self.granted.is_empty()
    }

    /// Whether any granted capability warrants a prominent install warning.
    pub fn has_dangerous(&self) -> bool {
        self.granted.iter().any(Capability::is_dangerous)
    }
}

/// What an extension declares it needs, from its manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRequest {
    /// Capabilities without which the extension cannot function.
    #[serde(default)]
    pub required: Vec<Capability>,
    /// Capabilities that enable extra features but can be declined.
    #[serde(default)]
    pub optional: Vec<Capability>,
}

impl PermissionRequest {
    /// Whether a grant set covers everything the extension declared as required.
    ///
    /// The runtime refuses to enable an extension whose required capabilities were
    /// declined, rather than loading it into a state where it fails unpredictably
    /// halfway through a scan.
    pub fn satisfied_by(&self, grants: &GrantSet) -> bool {
        self.required.iter().all(|c| grants.allows(*c))
    }

    /// Everything the extension asked for, required and optional.
    pub fn all(&self) -> impl Iterator<Item = Capability> + '_ {
        self.required.iter().chain(self.optional.iter()).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_extension_starts_with_nothing() {
        let grants = GrantSet::none();
        assert!(grants.is_empty());
        for capability in Capability::ALL {
            assert!(!grants.allows(*capability), "{capability} was granted implicitly");
        }
    }

    #[test]
    fn only_granted_capabilities_are_allowed() {
        let grants = GrantSet::granted_by_user([Capability::HttpRead, Capability::Ui]);
        assert!(grants.allows(Capability::HttpRead));
        assert!(grants.allows(Capability::Ui));
        assert!(!grants.allows(Capability::HttpSend));
        assert!(!grants.allows(Capability::Filesystem));
    }

    #[test]
    fn write_access_implies_read_access() {
        let grants = GrantSet::granted_by_user([Capability::ProjectWrite]);
        assert!(grants.allows(Capability::ProjectRead));
    }

    #[test]
    fn read_access_does_not_imply_write_access() {
        let grants = GrantSet::granted_by_user([Capability::ProjectRead]);
        assert!(!grants.allows(Capability::ProjectWrite));
    }

    #[test]
    fn reading_traffic_does_not_imply_being_able_to_send_it() {
        let grants = GrantSet::granted_by_user([Capability::HttpRead]);
        assert!(!grants.allows(Capability::HttpSend), "observing is not the same as acting");
    }

    #[test]
    fn dangerous_capabilities_are_never_implied_by_anything() {
        let everything_benign = GrantSet::granted_by_user(
            Capability::ALL.iter().copied().filter(|c| !c.is_dangerous()),
        );
        for capability in Capability::ALL.iter().filter(|c| c.is_dangerous()) {
            assert!(
                !everything_benign.allows(*capability),
                "{capability} must be requested by name"
            );
        }
    }

    #[test]
    fn revoking_takes_effect_immediately() {
        let mut grants = GrantSet::granted_by_user([Capability::Filesystem]);
        assert!(grants.allows(Capability::Filesystem));
        grants.revoke(Capability::Filesystem);
        assert!(!grants.allows(Capability::Filesystem));
    }

    #[test]
    fn intersecting_can_only_narrow() {
        let parent = GrantSet::granted_by_user([Capability::HttpRead, Capability::ProjectRead]);
        let child_request = GrantSet::granted_by_user([
            Capability::HttpRead,
            Capability::Filesystem,
            Capability::Credentials,
        ]);
        let effective = parent.intersect(&child_request);
        assert!(effective.allows(Capability::HttpRead));
        assert!(!effective.allows(Capability::Filesystem), "a child cannot exceed its parent");
        assert!(!effective.allows(Capability::Credentials));
        assert!(!effective.allows(Capability::ProjectRead));
    }

    #[test]
    fn an_extension_with_declined_requirements_is_not_satisfied() {
        let request = PermissionRequest {
            required: vec![Capability::HttpRead, Capability::Scanner],
            optional: vec![Capability::Filesystem],
        };
        let partial = GrantSet::granted_by_user([Capability::HttpRead]);
        assert!(!request.satisfied_by(&partial));

        let full = GrantSet::granted_by_user([Capability::HttpRead, Capability::Scanner]);
        assert!(request.satisfied_by(&full), "declining an optional permission must still work");
    }

    #[test]
    fn dangerous_grants_are_flagged_for_the_install_dialog() {
        assert!(GrantSet::granted_by_user([Capability::ProcessExecute]).has_dangerous());
        assert!(!GrantSet::granted_by_user([Capability::Ui, Capability::HttpRead]).has_dangerous());
    }

    #[test]
    fn every_capability_has_a_distinct_name_and_an_explanation() {
        let mut names = BTreeSet::new();
        for capability in Capability::ALL {
            assert!(names.insert(capability.to_string()), "duplicate name for {capability:?}");
            assert!(!capability.explanation().is_empty());
        }
        assert_eq!(names.len(), Capability::ALL.len());
    }

    #[test]
    fn grants_round_trip_through_serialization() {
        let grants = GrantSet::granted_by_user([Capability::HttpRead, Capability::ProjectWrite]);
        let json = serde_json::to_string(&grants).unwrap();
        let back: GrantSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, grants);
    }
}

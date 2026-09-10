//! The AI tool-permission gate.
//!
//! The AI layer is useful precisely because it can act: read traffic, craft requests,
//! start a scan. That is also why it is the most dangerous component in the product.
//! An LLM that misreads a scope, loops, or is steered by injected text in a *response
//! body it was asked to analyse* can send thousands of requests at a client's
//! production system.
//!
//! So the AI never calls the engine directly. It proposes a [`ToolCall`]; the gate
//! classifies it, and anything with real-world impact stops for a human.
//!
//! ```text
//! AI ──proposes──→ ToolGate ──→ Approval::Automatic  → run
//!                     │
//!                     ├──→ Approval::AskUser{...}   → wait for a person
//!                     └──→ Approval::Forbidden      → never
//! ```
//!
//! Invariants 1 and 5 (`docs/security-invariants.md`) both apply: approval here is
//! *additional* to scope enforcement, never a substitute for it. An approved tool call
//! still goes through [`crate::guard::ScopeGuard`].
//!
//! Prompt injection is treated as a given, not an edge case. Response bodies are
//! attacker-controlled text, so no approval decision is ever derived from model
//! output — only from the structure of the call itself.

use serde::{Deserialize, Serialize};

/// Something the AI layer wants to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum ToolCall {
    /// Read exchanges already captured.
    ReadTraffic {
        /// Maximum number of exchanges to return.
        limit: u32,
    },
    /// Inspect the target map.
    InspectTarget,
    /// Read existing findings.
    ReadFindings,
    /// Compose a request without sending it.
    DraftRequest,
    /// Send requests to a target.
    SendRequests {
        /// Host that will receive the traffic.
        target: String,
        /// How many requests will be sent. Shown verbatim in the approval prompt.
        count: u32,
    },
    /// Start a scanner job.
    RunScan {
        /// Host that will be scanned.
        target: String,
    },
    /// Start a fuzzing attack.
    RunFuzz {
        /// Host that will be fuzzed.
        target: String,
        /// Approximate request count. Shown verbatim in the approval prompt.
        requests: u32,
    },
    /// Record a finding.
    CreateFinding,
    /// Change project settings or scope.
    ModifyProject,
    /// Read stored identity credentials in cleartext.
    ReadCredentials,
}

/// What the gate decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    /// Safe to run without asking: read-only, no traffic, no data loss.
    Automatic,
    /// Requires a human decision, with this summary shown to them.
    AskUser(ApprovalPrompt),
    /// Never permitted through this interface, whatever the user says.
    ///
    /// Reserved for actions where an approval dialog would be
    /// security theatre — the user cannot meaningfully evaluate a request to dump
    /// credentials that originated inside a model's reasoning.
    Forbidden {
        /// Why the call is refused, shown to the user.
        reason: &'static str,
    },
}

impl Approval {
    /// Whether the call may proceed with no further interaction.
    pub fn is_automatic(&self) -> bool {
        matches!(self, Self::Automatic)
    }

    /// Whether the call is refused outright.
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Self::Forbidden { .. })
    }
}

/// The details a person needs in order to approve or refuse.
///
/// Deliberately concrete. "The assistant wants to run a scan" is not a decision
/// anyone can make; "send about 12 000 requests to api.example.com at 50/s, roughly
/// 4 minutes" is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPrompt {
    /// What will happen, in one line.
    pub summary: String,
    /// The host that will receive traffic, if any.
    pub target: Option<String>,
    /// How many requests will be sent, if any.
    pub request_count: Option<u32>,
    /// Whether the action changes stored project data.
    pub mutates_project: bool,
}

/// How long an approval lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalScope {
    /// This call only.
    Once,
    /// Every call of this kind for the rest of the project.
    Project,
}

/// Classifies AI tool calls.
#[derive(Debug, Clone)]
pub struct ToolGate {
    /// Above this many requests, a send is always worth a human glance even if the
    /// user previously approved sending in general.
    bulk_threshold: u32,
}

impl Default for ToolGate {
    fn default() -> Self {
        Self {
            bulk_threshold: 100,
        }
    }
}

impl ToolGate {
    /// A gate with the default bulk threshold.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the request count above which a send counts as bulk traffic.
    pub fn with_bulk_threshold(mut self, threshold: u32) -> Self {
        self.bulk_threshold = threshold;
        self
    }

    /// Classifies one proposed call.
    pub fn classify(&self, call: &ToolCall) -> Approval {
        match call {
            // Read-only, no traffic leaves the machine, nothing changes.
            ToolCall::ReadTraffic { .. }
            | ToolCall::InspectTarget
            | ToolCall::ReadFindings
            | ToolCall::DraftRequest => Approval::Automatic,

            // Cleartext credentials are never handed to the model. If a human wants
            // them, they read them in the UI.
            ToolCall::ReadCredentials => Approval::Forbidden {
                reason: "stored credentials are never exposed to the AI layer",
            },

            // Anything that puts packets on the wire needs a person, every time.
            ToolCall::SendRequests { target, count } => Approval::AskUser(ApprovalPrompt {
                summary: format!("Send {count} request(s) to {target}"),
                target: Some(target.clone()),
                request_count: Some(*count),
                mutates_project: false,
            }),
            ToolCall::RunScan { target } => Approval::AskUser(ApprovalPrompt {
                summary: format!("Run an active scan against {target}"),
                target: Some(target.clone()),
                request_count: None,
                mutates_project: true,
            }),
            ToolCall::RunFuzz { target, requests } => Approval::AskUser(ApprovalPrompt {
                summary: format!("Fuzz {target} with approximately {requests} requests"),
                target: Some(target.clone()),
                request_count: Some(*requests),
                mutates_project: true,
            }),

            ToolCall::CreateFinding => Approval::AskUser(ApprovalPrompt {
                summary: "Record a new finding in the project".into(),
                target: None,
                request_count: None,
                mutates_project: true,
            }),
            ToolCall::ModifyProject => Approval::AskUser(ApprovalPrompt {
                summary: "Change project settings or scope".into(),
                target: None,
                request_count: None,
                mutates_project: true,
            }),
        }
    }

    /// Whether a previously granted [`ApprovalScope::Project`] approval covers this
    /// call, or whether it must be re-approved.
    ///
    /// A blanket approval never covers a bulk send. "Yes, you may send requests"
    /// given for a three-request probe must not silently authorize fifty thousand.
    pub fn covered_by_standing_approval(&self, call: &ToolCall) -> bool {
        match call {
            ToolCall::SendRequests { count, .. } => *count <= self.bulk_threshold,
            ToolCall::RunFuzz { .. } => false,
            ToolCall::RunScan { .. } => false,
            ToolCall::ReadCredentials => false,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_calls_run_without_interrupting_the_user() {
        let gate = ToolGate::new();
        for call in [
            ToolCall::ReadTraffic { limit: 100 },
            ToolCall::InspectTarget,
            ToolCall::ReadFindings,
            ToolCall::DraftRequest,
        ] {
            assert!(gate.classify(&call).is_automatic(), "{call:?}");
        }
    }

    #[test]
    fn credentials_are_never_available_to_the_ai() {
        let approval = ToolGate::new().classify(&ToolCall::ReadCredentials);
        assert!(approval.is_forbidden());
        assert!(!ToolGate::new().covered_by_standing_approval(&ToolCall::ReadCredentials));
    }

    #[test]
    fn every_call_that_sends_traffic_requires_approval() {
        let gate = ToolGate::new();
        for call in [
            ToolCall::SendRequests {
                target: "example.com".into(),
                count: 1,
            },
            ToolCall::RunScan {
                target: "example.com".into(),
            },
            ToolCall::RunFuzz {
                target: "example.com".into(),
                requests: 10,
            },
        ] {
            assert!(
                !gate.classify(&call).is_automatic(),
                "{call:?} must stop for a human"
            );
        }
    }

    #[test]
    fn an_approval_prompt_states_the_target_and_the_volume() {
        let gate = ToolGate::new();
        let call = ToolCall::SendRequests {
            target: "api.example.com".into(),
            count: 12_000,
        };
        let Approval::AskUser(prompt) = gate.classify(&call) else {
            panic!("bulk traffic must ask");
        };
        assert_eq!(prompt.target.as_deref(), Some("api.example.com"));
        assert_eq!(prompt.request_count, Some(12_000));
        assert!(prompt.summary.contains("12000"), "{}", prompt.summary);
    }

    #[test]
    fn a_standing_approval_does_not_cover_bulk_traffic() {
        let gate = ToolGate::new().with_bulk_threshold(100);
        assert!(gate.covered_by_standing_approval(&ToolCall::SendRequests {
            target: "example.com".into(),
            count: 3
        }));
        assert!(!gate.covered_by_standing_approval(&ToolCall::SendRequests {
            target: "example.com".into(),
            count: 50_000
        }));
    }

    #[test]
    fn scans_and_fuzzing_are_re_approved_every_time() {
        let gate = ToolGate::new();
        assert!(!gate.covered_by_standing_approval(&ToolCall::RunScan {
            target: "example.com".into()
        }));
        assert!(!gate.covered_by_standing_approval(&ToolCall::RunFuzz {
            target: "example.com".into(),
            requests: 10
        }));
    }

    #[test]
    fn writing_to_the_project_requires_approval_and_says_so() {
        let gate = ToolGate::new();
        for call in [ToolCall::CreateFinding, ToolCall::ModifyProject] {
            let Approval::AskUser(prompt) = gate.classify(&call) else {
                panic!("{call:?} must ask");
            };
            assert!(prompt.mutates_project, "{call:?}");
        }
    }

    #[test]
    fn tool_calls_round_trip_through_serialization() {
        let call = ToolCall::RunFuzz {
            target: "example.com".into(),
            requests: 500,
        };
        let json = serde_json::to_string(&call).unwrap();
        let back: ToolCall = serde_json::from_str(&json).unwrap();
        assert_eq!(back, call);
    }
}

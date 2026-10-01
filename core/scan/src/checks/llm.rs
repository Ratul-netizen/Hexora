//! `llm.endpoint` — surfacing LLM/chat endpoints so a tester knows to test them for injection.
//!
//! LLM prompt-injection auto-discovery (LLM.b), within the safe-methods rule the scheduler
//! enforces. It cannot read bodies — the passive scan does not load them — so it recognises an
//! LLM call from what it *can* see: a body-bearing method, a JSON content type, and a
//! chat-shaped path.
//!
//! It reports the endpoint as a **lead**, not a hypothesis for the active scanner to settle.
//! Testing prompt injection means sending payloads, and the target is a `POST`: an automated
//! run never replays a request that is not safe to repeat, and Nullhawk will not make an
//! exception to that for a guess about what an endpoint does. The tester tests it deliberately
//! with `nullhawk llm <url>`, which is consent — the same line the crawler and the active
//! scanner draw.
//!
//! The path list mirrors `nullhawk_llm::looks_like_llm_path`, duplicated rather than depended on
//! because the passive scanner is network-free by design and must not pull in the transport
//! crate the LLM tester needs.

use super::prelude::*;

/// The check.
pub struct LlmEndpoints;

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("llm.endpoint"),
    name: "LLM endpoint",
    version: "1.0.0",
    about: "requests that look like LLM/chat calls, worth testing for prompt injection",
    mode: DetectorMode::Passive,
    observes: true,
    hypothesizes: false,
    settles: None,
    intrusiveness: nullhawk_types::verify::Intrusiveness::Silent,
};

/// Path fragments that mark a chat/LLM endpoint. Mirrors `nullhawk_llm::looks_like_llm_path`.
const LLM_PATH_HINTS: &[&str] = &[
    "chat",
    "completion",
    "generate",
    "/llm",
    "/ai/",
    "/ask",
    "message",
    "prompt",
    "converse",
    "respond",
    "assistant",
];

/// Whether an exchange looks like an LLM/chat call from its method, content type and path.
fn looks_like_llm(exchange: &Exchange) -> bool {
    let method = exchange.method.to_ascii_uppercase();
    let body_bearing = matches!(method.as_str(), "POST" | "PUT" | "PATCH");
    let json = exchange
        .request_headers
        .get("content-type")
        .map(|h| h.value_lossy().to_ascii_lowercase().contains("json"))
        .unwrap_or(false);
    let path = exchange.path.to_ascii_lowercase();
    let chatty = LLM_PATH_HINTS.iter().any(|hint| path.contains(hint));
    body_bearing && json && chatty
}

impl PassiveCheck for LlmEndpoints {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn observe(&self, exchange: &Exchange) -> Vec<Observation> {
        if !looks_like_llm(exchange) {
            return Vec::new();
        }
        vec![observation(
            &INFO,
            exchange,
            "LLM endpoint — test it for prompt injection",
            "an endpoint whose own instructions user input cannot override",
            format!(
                "{} {} looks like an LLM/chat call: a JSON body to a chat-shaped path",
                exchange.method,
                endpoint(&exchange.url),
            ),
            "Prompt injection lets text in a user field override the model's instructions. \
             Testing it means sending payloads, and this is a POST, which an automated run \
             will not replay — so it is surfaced as a lead to test deliberately.",
            Severity::Info,
            Significance::Reportable,
            None,
        )]
    }

    fn writeup(&self, observation: &Observation, exchange: &Exchange, target: TargetId) -> Writeup {
        Writeup {
            target,
            title: observation.about.clone(),
            description: format!(
                "{} looks like a request to an LLM. If text a user controls can override the \
                 model's own instructions, an attacker controls its behaviour and its output \
                 — which the application then trusts. This is a lead, not a confirmed issue: \
                 the passive scan does not send the payloads that would settle it.",
                observation.observed,
            ),
            impact: "Where a user can steer the model, anything built on the model's output — \
                     shown to a user, used in a query, handed to a tool — is attacker-\
                     influenced. The impact is whatever that output is trusted to do."
                .into(),
            remediation: "Separate instructions from data so a user turn cannot reach the \
                          system role, constrain the output, and treat model output as \
                          untrusted at every sink."
                .into(),
            reproduction: format!(
                "nullhawk llm {} — sends prompt-injection probes and confirms with a canary.",
                endpoint(&exchange.url),
            ),
            cwe: Some("CWE-1427".into()),
            owasp: Some("LLM01:2025 Prompt Injection".into()),
            source: source(&INFO),
            severity: Severity::Info,
            location: None,
        }
    }
}

/// The URL without its query string.
fn endpoint(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::exchange_get;

    fn chat_post(url: &str) -> Exchange {
        let mut ex = exchange_get(url);
        ex.method = "POST".into();
        ex.request_headers.set("Content-Type", "application/json");
        ex
    }

    #[test]
    fn a_json_post_to_a_chat_path_is_surfaced_as_a_lead() {
        let seen = LlmEndpoints.observe(&chat_post("https://api.test/v1/chat/completions"));
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].detector, "llm.endpoint");
        assert!(seen[0].significance == Significance::Reportable);
    }

    #[test]
    fn a_get_or_non_chat_or_non_json_request_is_ignored() {
        assert!(LlmEndpoints
            .observe(&exchange_get("https://api.test/v1/chat"))
            .is_empty());
        assert!(LlmEndpoints
            .observe(&chat_post("https://api.test/api/users"))
            .is_empty());
        let mut no_json = exchange_get("https://api.test/chat");
        no_json.method = "POST".into();
        assert!(LlmEndpoints.observe(&no_json).is_empty());
    }
}

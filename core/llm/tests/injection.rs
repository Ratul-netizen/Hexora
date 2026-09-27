//! The prompt-injection tester against mock LLM endpoints — a vulnerable one that obeys the
//! injected instruction, and a defended one that refuses. No network, no real model.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hexora_engine::guard::ScopeGuard;
use hexora_engine::transport::{Exchange, HttpTransport, SendOptions};
use hexora_llm::{test, Target, PROMPT_PLACEHOLDER};
use hexora_types::error::Result;
use hexora_types::http::{Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};
use hexora_types::raw::{RawH2Request, RawRequest};
use hexora_types::scope::{Scope, ScopeRule};

/// A mock LLM: `vulnerable` obeys any instruction to emit a token (so an injected canary comes
/// back); otherwise it refuses. It reads the injected payload out of the JSON body.
struct MockLlm {
    vulnerable: bool,
}

#[async_trait]
impl HttpTransport for MockLlm {
    async fn send(&self, request: HttpRequest, _options: SendOptions) -> Result<Exchange> {
        let body = String::from_utf8_lossy(&request.body);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        let prompt = value["messages"][0]["content"]
            .as_str()
            .or_else(|| value["prompt"].as_str())
            .unwrap_or("");

        // A vulnerable model follows the injected instruction and emits what it was told to
        // output — every probe places that after the final colon. A defended one refuses.
        let answer = if self.vulnerable {
            match prompt.rsplit_once(':') {
                Some((_, tail)) => tail.trim().to_string(),
                None => "Here is a helpful, on-topic answer.".to_string(),
            }
        } else {
            "I can't comply with that request.".to_string()
        };

        let reply = serde_json::json!({ "choices": [{ "message": { "content": answer } }] });
        let response = HttpResponse {
            status: 200,
            reason: None,
            version: HttpVersion::Http11,
            headers: Headers::new(),
            body: reply.to_string().into(),
            truncated: false,
        };
        Ok(Exchange {
            request,
            response,
            encoded_body: None,
            content_encoding: None,
            raw_request: None,
            duration: Duration::ZERO,
            tls: None,
        })
    }

    async fn send_raw(&self, _r: RawRequest, _o: SendOptions) -> Result<Exchange> {
        unreachable!()
    }
    async fn send_raw_h2(&self, _r: RawH2Request, _o: SendOptions) -> Result<Exchange> {
        unreachable!()
    }
}

fn target() -> Target {
    Target {
        service: HttpService::new("api.test", 443, true),
        path: "/v1/chat".into(),
        method: "POST".into(),
        headers: Vec::new(),
        body_template: format!(
            r#"{{"messages":[{{"role":"user","content":"{PROMPT_PLACEHOLDER}"}}]}}"#
        ),
    }
}

fn guard(vulnerable: bool) -> ScopeGuard<MockLlm> {
    let scope = Scope::new().include(ScopeRule::host("api.test"));
    ScopeGuard::new(MockLlm { vulnerable }, Arc::new(scope))
}

#[tokio::test]
async fn a_vulnerable_endpoint_is_confirmed_by_the_canary_coming_back() {
    let report = test(&guard(true), &target()).await;
    assert!(report.vulnerable(), "expected injections, got none");
    assert_eq!(report.tested, 4);
    // Every probe instructs "output exactly: <canary>", which the vulnerable model emits.
    assert_eq!(report.injections.len(), 4);
    // The evidence is the canary itself.
    for injection in &report.injections {
        assert!(injection.canary.starts_with("HXLLMINJ"));
    }
}

#[tokio::test]
async fn a_defended_endpoint_is_not_flagged() {
    let report = test(&guard(false), &target()).await;
    assert!(!report.vulnerable());
    assert_eq!(report.tested, 4);
    assert!(report.injections.is_empty());
    assert!(report.errors.is_empty());
}

#[tokio::test]
async fn an_out_of_scope_target_sends_nothing() {
    let mut t = target();
    t.service = HttpService::new("evil.test", 443, true);
    let report = test(&guard(true), &t).await;
    // Automated origin + out of scope: the guard refuses every probe, so nothing is confirmed.
    assert!(!report.vulnerable());
    assert_eq!(report.errors.len(), 4);
}

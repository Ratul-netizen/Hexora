//! Match-and-replace: rewriting proxied traffic by rule (M7).
//!
//! Burp and Caido both let a tester say "wherever you see X in this part of the exchange, put
//! Y instead", and it is one of the most-reached-for features in a manual session — strip a
//! `Content-Security-Policy` to make an injected script run, force a header a client omits,
//! turn `debug=false` into `debug=true` on every request without touching each one by hand.
//! Hexora had only the narrow special case of *attaching* named headers ([`crate::attach`]);
//! this is the general form.
//!
//! # The same three bounds the header attacher has
//!
//! Rewriting a browser's traffic is not a small thing, so it keeps the bounds that make
//! [`crate::attach::Attaching`] safe:
//!
//! - **In scope only.** A tester's browser goes to their own mail and their own bank. Rules
//!   apply only to hosts the project declared, and an empty scope means nowhere.
//! - **Opt in, per project.** Off unless somebody added a rule; the proxy says what it will do.
//! - **Recorded as sent.** The capture observer sees the request after rules run and the
//!   response before they run on the way back, so the history is what actually crossed the wire.
//!
//! # What a rule reaches
//!
//! The five [`RuleTarget`](hexora_types::matchreplace::RuleTarget)s — request/response headers
//! and bodies, and the request's first line. A body rewrite that changes the length updates a
//! present `Content-Length` so the peer is not told a lie about how many bytes follow.

use std::sync::Arc;

use async_trait::async_trait;
use hexora_types::http::{Header, HttpRequest, HttpResponse};
use hexora_types::matchreplace::{MatchReplaceRule, RuleTarget};
use hexora_types::scope::Scope;
use regex::Regex;

use crate::hook::{Interceptor, RequestVerdict, ResponseVerdict};

/// One rule with its pattern compiled, ready to apply.
#[derive(Debug)]
struct Compiled {
    target: RuleTarget,
    /// `Some` when the rule is a regex; `None` for a literal pattern.
    regex: Option<Regex>,
    pattern: String,
    replacement: String,
}

impl Compiled {
    /// Replaces every match of the pattern in `haystack`, literal or regex.
    ///
    /// A literal replacement is taken verbatim; regex `$1`-style references are **not**
    /// expanded, so a replacement containing `$` means the dollar sign, which is the least
    /// surprising behaviour for a rewrite rule a tester typed.
    fn rewrite(&self, haystack: &str) -> String {
        match &self.regex {
            Some(re) => re
                .replace_all(haystack, NoExpand(&self.replacement))
                .into_owned(),
            None => haystack.replace(&self.pattern, &self.replacement),
        }
    }

    /// Whether the pattern would match `haystack` at all.
    fn matches(&self, haystack: &str) -> bool {
        match &self.regex {
            Some(re) => re.is_match(haystack),
            None => haystack.contains(&self.pattern),
        }
    }
}

/// A literal replacement string for `Regex::replace_all` — no `$1` expansion.
struct NoExpand<'a>(&'a str);
impl regex::Replacer for NoExpand<'_> {
    fn replace_append(&mut self, _: &regex::Captures<'_>, dst: &mut String) {
        dst.push_str(self.0);
    }
}

/// A compiled set of match-and-replace rules, split by the exchange half they touch.
#[derive(Debug)]
pub struct Rewriter {
    request_rules: Vec<Compiled>,
    response_rules: Vec<Compiled>,
}

impl Rewriter {
    /// Compiles the enabled rules, returning an error naming the first rule whose regex does
    /// not compile — so a bad pattern is rejected when it is added, not silently ignored when
    /// the proxy runs.
    pub fn compile(rules: &[MatchReplaceRule]) -> Result<Self, String> {
        let mut request_rules = Vec::new();
        let mut response_rules = Vec::new();
        for rule in rules {
            if !rule.enabled {
                continue;
            }
            let regex = if rule.is_regex {
                Some(
                    Regex::new(&rule.pattern)
                        .map_err(|e| format!("rule `{}` has an invalid regex: {e}", rule.name))?,
                )
            } else {
                None
            };
            let compiled = Compiled {
                target: rule.target,
                regex,
                pattern: rule.pattern.clone(),
                replacement: rule.replacement.clone(),
            };
            if rule.target.is_request() {
                request_rules.push(compiled);
            } else {
                response_rules.push(compiled);
            }
        }
        Ok(Self {
            request_rules,
            response_rules,
        })
    }

    /// Whether there is any enabled rule at all.
    pub fn is_empty(&self) -> bool {
        self.request_rules.is_empty() && self.response_rules.is_empty()
    }

    /// Applies the request rules, returning a rewritten request when anything changed.
    pub fn apply_request(&self, request: &HttpRequest) -> Option<HttpRequest> {
        if self.request_rules.is_empty() {
            return None;
        }
        let mut out = request.clone();
        let mut changed = false;
        for rule in &self.request_rules {
            match rule.target {
                RuleTarget::RequestFirstLine => {
                    let line = format!("{} {}", out.method, out.path);
                    let new = rule.rewrite(&line);
                    if new != line {
                        if let Some((method, path)) = new.split_once(' ') {
                            out.method = method.to_string();
                            out.path = path.to_string();
                        } else {
                            // No space left: read it all as the target, method unchanged.
                            out.path = new;
                        }
                        changed = true;
                    }
                }
                RuleTarget::RequestHeader => {
                    changed |= rewrite_headers(&mut out.headers, rule);
                }
                RuleTarget::RequestBody => {
                    changed |= rewrite_body(&mut out.headers, &mut out.body, rule);
                }
                _ => {}
            }
        }
        changed.then_some(out)
    }

    /// Applies the response rules, returning a rewritten response when anything changed.
    pub fn apply_response(&self, response: &HttpResponse) -> Option<HttpResponse> {
        if self.response_rules.is_empty() {
            return None;
        }
        let mut out = response.clone();
        let mut changed = false;
        for rule in &self.response_rules {
            match rule.target {
                RuleTarget::ResponseHeader => {
                    changed |= rewrite_headers(&mut out.headers, rule);
                }
                RuleTarget::ResponseBody => {
                    changed |= rewrite_body(&mut out.headers, &mut out.body, rule);
                }
                _ => {}
            }
        }
        changed.then_some(out)
    }
}

/// Rewrites a header section by rule, mutating `headers` in place. Returns whether it changed.
fn rewrite_headers(headers: &mut hexora_types::http::Headers, rule: &Compiled) -> bool {
    // An empty pattern is "add this header": there is nothing to match, so the replacement is
    // parsed as `Name: value` and set (replacing any same-named header rather than duplicating).
    if rule.pattern.is_empty() {
        if let Some((name, value)) = rule.replacement.split_once(':') {
            headers.set(name.trim(), value.trim().to_string());
            return true;
        }
        return false;
    }

    let mut rebuilt = hexora_types::http::Headers::new();
    let mut changed = false;
    for header in headers.iter() {
        let line = format!("{}: {}", header.name, header.value_lossy());
        if !rule.matches(&line) {
            rebuilt.append(header.clone());
            continue;
        }
        let new = rule.rewrite(&line);
        changed = true;
        if let Some((name, value)) = new.split_once(':') {
            let name = name.trim();
            if !name.is_empty() {
                rebuilt.append(Header::new(name, value.trim_start().to_string()));
            }
            // An empty name (or the whole line emptied) drops the header — a "remove" rule.
        }
        // A line rewritten to something without a colon is dropped: it is no longer a header.
    }
    if changed {
        *headers = rebuilt;
    }
    changed
}

/// Rewrites a body by rule and keeps a present `Content-Length` honest. Returns whether it
/// changed.
fn rewrite_body(
    headers: &mut hexora_types::http::Headers,
    body: &mut bytes::Bytes,
    rule: &Compiled,
) -> bool {
    let text = String::from_utf8_lossy(body);
    let new = rule.rewrite(&text);
    if new == text {
        return false;
    }
    let bytes = bytes::Bytes::from(new.into_bytes());
    let len = bytes.len();
    *body = bytes;
    // Do not tell the peer a length that is now wrong. Only touch a Content-Length that is
    // actually present; a chunked or length-less body is left for the transport to frame.
    if headers.get("content-length").is_some() {
        headers.set("Content-Length", len.to_string());
    }
    true
}

/// Applies match-and-replace rules to in-scope proxied traffic, then defers to `inner`.
///
/// Wraps another interceptor so interception and rewriting compose: the inner interceptor sees
/// the request as it will actually be sent (rules applied), because a tester pausing a request
/// to read it should read what goes out.
pub struct Rewriting {
    rewriter: Arc<Rewriter>,
    scope: Arc<Scope>,
    inner: Arc<dyn Interceptor>,
}

impl Rewriting {
    /// Rewrites traffic inside `scope` by `rewriter`, then defers to `inner`.
    pub fn new(rewriter: Arc<Rewriter>, scope: Arc<Scope>, inner: Arc<dyn Interceptor>) -> Self {
        Self {
            rewriter,
            scope,
            inner,
        }
    }

    /// Whether this request is one the project declared. The whole guard: a host nobody
    /// declared is somebody else's, and its traffic is not ours to rewrite.
    fn applies_to(&self, request: &HttpRequest) -> bool {
        !self.rewriter.is_empty() && self.scope.contains(&request.service, &request.path)
    }
}

#[async_trait]
impl Interceptor for Rewriting {
    async fn on_request(&self, request: &HttpRequest) -> RequestVerdict {
        if !self.applies_to(request) {
            return self.inner.on_request(request).await;
        }

        let rewritten = self.rewriter.apply_request(request);
        let effective = rewritten.clone().unwrap_or_else(|| request.clone());

        match self.inner.on_request(&effective).await {
            // The inner interceptor was happy with the request it saw — the rewritten one.
            RequestVerdict::Forward => match rewritten {
                Some(edited) => RequestVerdict::Replace(Box::new(edited)),
                None => RequestVerdict::Forward,
            },
            // A tester edited it. Re-apply, because an edit is not a decision to stop
            // rewriting; the rules describe what should go out however the request got there.
            RequestVerdict::Replace(edited) => {
                let reapplied = self.rewriter.apply_request(&edited).unwrap_or(*edited);
                RequestVerdict::Replace(Box::new(reapplied))
            }
            other => other,
        }
    }

    async fn on_response(&self, request: &HttpRequest, response: &HttpResponse) -> ResponseVerdict {
        let gated = self.scope.contains(&request.service, &request.path);
        match self.inner.on_response(request, response).await {
            ResponseVerdict::Forward if gated => match self.rewriter.apply_response(response) {
                Some(edited) => ResponseVerdict::Replace(Box::new(edited)),
                None => ResponseVerdict::Forward,
            },
            ResponseVerdict::Replace(edited) if gated => {
                match self.rewriter.apply_response(&edited) {
                    Some(reapplied) => ResponseVerdict::Replace(Box::new(reapplied)),
                    None => ResponseVerdict::Replace(edited),
                }
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use hexora_types::http::HttpService;
    use hexora_types::scope::ScopeRule;

    use super::*;
    use crate::hook::PassThrough;

    fn rule(
        target: RuleTarget,
        is_regex: bool,
        pattern: &str,
        replacement: &str,
    ) -> MatchReplaceRule {
        MatchReplaceRule::new("r", target, is_regex, pattern, replacement)
    }

    fn request(host: &str, path: &str) -> HttpRequest {
        HttpRequest::get(HttpService::new(host, 443, true), path)
    }

    fn sent(verdict: RequestVerdict) -> HttpRequest {
        match verdict {
            RequestVerdict::Replace(request) => *request,
            other => panic!("expected a replacement, got {other:?}"),
        }
    }

    fn rewriting(rules: &[MatchReplaceRule], scope: Scope) -> Rewriting {
        Rewriting::new(
            Arc::new(Rewriter::compile(rules).unwrap()),
            Arc::new(scope),
            Arc::new(PassThrough),
        )
    }

    #[test]
    fn a_literal_body_substitution_updates_content_length() {
        let rewriter =
            Rewriter::compile(&[rule(RuleTarget::RequestBody, false, "false", "true")]).unwrap();
        let mut req = request("t.com", "/");
        req.headers.set("Content-Length", "11");
        req.body = bytes::Bytes::from_static(b"debug=false");
        let out = rewriter.apply_request(&req).expect("changed");
        assert_eq!(&out.body[..], b"debug=true");
        assert_eq!(
            out.headers.get("content-length").unwrap().value_lossy(),
            "10"
        );
    }

    #[test]
    fn an_empty_pattern_adds_a_header() {
        let rewriter =
            Rewriter::compile(&[rule(RuleTarget::RequestHeader, false, "", "X-Test: 1")]).unwrap();
        let out = rewriter
            .apply_request(&request("t.com", "/"))
            .expect("changed");
        assert_eq!(out.headers.get("x-test").unwrap().value_lossy(), "1");
    }

    #[test]
    fn an_empty_replacement_removes_a_matching_header() {
        let rewriter = Rewriter::compile(&[rule(
            RuleTarget::ResponseHeader,
            false,
            "Content-Security-Policy:",
            "",
        )])
        .unwrap();
        let mut resp = HttpResponse {
            status: 200,
            reason: None,
            version: hexora_types::http::HttpVersion::Http11,
            headers: hexora_types::http::Headers::new(),
            body: bytes::Bytes::new(),
            truncated: false,
        };
        resp.headers
            .set("Content-Security-Policy", "default-src 'none'");
        resp.headers.set("X-Keep", "yes");
        let out = rewriter.apply_response(&resp).expect("changed");
        assert!(
            out.headers.get("content-security-policy").is_none(),
            "stripped"
        );
        assert!(out.headers.get("x-keep").is_some(), "others kept");
    }

    #[test]
    fn a_regex_rewrites_the_first_line() {
        let rewriter = Rewriter::compile(&[rule(
            RuleTarget::RequestFirstLine,
            true,
            r"/user/\d+",
            "/user/1",
        )])
        .unwrap();
        let out = rewriter
            .apply_request(&request("t.com", "/user/42/profile"))
            .expect("changed");
        assert_eq!(out.path, "/user/1/profile");
    }

    #[test]
    fn a_dollar_in_a_regex_replacement_is_literal() {
        // A tester who types `$5` in a replacement means five dollars, not capture group 5.
        let rewriter = Rewriter::compile(&[rule(
            RuleTarget::RequestBody,
            true,
            r"price=\d+",
            "price=$5",
        )])
        .unwrap();
        let mut req = request("t.com", "/");
        req.body = bytes::Bytes::from_static(b"price=100");
        let out = rewriter.apply_request(&req).expect("changed");
        assert_eq!(&out.body[..], b"price=$5");
    }

    #[test]
    fn an_invalid_regex_is_rejected_at_compile_time() {
        let err = Rewriter::compile(&[rule(RuleTarget::RequestBody, true, "(unclosed", "x")])
            .unwrap_err();
        assert!(err.contains("invalid regex"), "{err}");
    }

    #[test]
    fn a_disabled_rule_is_not_compiled() {
        let mut r = rule(RuleTarget::RequestBody, false, "a", "b");
        r.enabled = false;
        assert!(Rewriter::compile(&[r]).unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_out_of_scope_request_is_left_alone() {
        let rw = rewriting(
            &[rule(RuleTarget::RequestFirstLine, false, "/a", "/b")],
            Scope::new().include(ScopeRule::host("target.com")),
        );
        let verdict = rw.on_request(&request("mail.example.com", "/a")).await;
        assert!(matches!(verdict, RequestVerdict::Forward), "{verdict:?}");
    }

    #[tokio::test]
    async fn an_in_scope_request_is_rewritten() {
        let rw = rewriting(
            &[rule(RuleTarget::RequestFirstLine, false, "/a", "/b")],
            Scope::new().include(ScopeRule::host("target.com")),
        );
        let out = sent(rw.on_request(&request("target.com", "/a")).await);
        assert_eq!(out.path, "/b");
    }

    #[tokio::test]
    async fn an_empty_scope_rewrites_nothing() {
        let rw = rewriting(
            &[rule(RuleTarget::RequestFirstLine, false, "/a", "/b")],
            Scope::new(),
        );
        let verdict = rw.on_request(&request("target.com", "/a")).await;
        assert!(matches!(verdict, RequestVerdict::Forward), "{verdict:?}");
    }
}

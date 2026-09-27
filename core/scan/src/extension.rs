//! Extension-backed passive checks (M20).
//!
//! An installed passive-check extension is a WASM module plus the capabilities the user granted.
//! This turns one into a [`PassiveCheck`] the scanner runs alongside the built-ins and the custom
//! checks: it serialises the exchange the scanner already assembled to JSON, runs the module in
//! the [`hexora_wasm`] sandbox, and folds the observations the module returns back into the scan.
//!
//! # The module runs with nothing but the bytes it is given
//!
//! The sandbox instantiates the module with **no host imports** — no filesystem, network or clock
//! — so a passive extension can only compute over the one exchange handed to it. It is bounded by
//! fuel and a memory cap, so a hostile or buggy module fails its run rather than the scan. The
//! module is compiled once (per scan) and run with a fresh instance per exchange, so one
//! exchange's run cannot leak state into the next.
//!
//! # The capability gate, and what a module never sees
//!
//! An extension runs here only if it passes [`hexora_wasm::may_run_passive`]: a passive kind,
//! switched on, holding `http:read`. Without that grant it never sees the traffic. And it sees the
//! same redacted exchange every check sees — credential request headers and `Set-Cookie` values
//! arrive already replaced (see [`crate::Exchange`]), so an extension cannot read a secret back
//! out of the traffic it was permitted to observe.
//!
//! # Only ever a lead
//!
//! Like a custom check, an extension implements `observe` only; the scanner concludes its
//! observations as leads capped at `Confidence::Reported`. An extension cannot raise a hypothesis
//! the active scheduler would try to settle, and it cannot overclaim.

use hexora_ext::InstalledExtension;
use hexora_wasm::{Limits, Sandbox};
use serde::{Deserialize, Serialize};

use crate::checks::prelude::*;

/// Compiles the installed passive-check extensions into passive checks.
///
/// An extension is skipped — never a hard error, so one bad extension cannot fail a scan — when
/// it does not pass the capability gate, carries no module bytes, or its module does not compile.
pub fn load(exts: &[InstalledExtension]) -> Vec<Box<dyn PassiveCheck>> {
    let mut out: Vec<Box<dyn PassiveCheck>> = Vec::new();
    for ext in exts {
        if hexora_wasm::may_run_passive(ext).is_err() {
            continue;
        }
        if ext.module.is_empty() {
            tracing::warn!(
                id = %ext.manifest.id,
                "extension is enabled but carries no module bytes; skipping"
            );
            continue;
        }
        match Sandbox::compile(&ext.module) {
            Ok(sandbox) => out.push(Box::new(ExtensionCheck::new(ext, sandbox))),
            Err(e) => tracing::warn!(
                id = %ext.manifest.id,
                error = %e,
                "extension module did not compile; skipping"
            ),
        }
    }
    out
}

/// A compiled extension, presented to the scanner as a passive check.
struct ExtensionCheck {
    info: DetectorInfo,
    name: String,
    sandbox: Sandbox,
    limits: Limits,
}

impl ExtensionCheck {
    fn new(ext: &InstalledExtension, sandbox: Sandbox) -> Self {
        let about = ext
            .manifest
            .description
            .clone()
            .unwrap_or_else(|| format!("{} (extension)", ext.manifest.name));
        Self {
            info: DetectorInfo {
                id: DetectorId(crate::custom::intern(&ext.manifest.id)),
                name: crate::custom::intern(&ext.manifest.name),
                version: crate::custom::intern(&ext.manifest.version),
                about: crate::custom::intern(&about),
                mode: DetectorMode::Passive,
                observes: true,
                hypothesizes: false,
                settles: None,
            },
            name: ext.manifest.name.clone(),
            sandbox,
            limits: Limits::default(),
        }
    }
}

impl PassiveCheck for ExtensionCheck {
    fn about(&self) -> DetectorInfo {
        self.info
    }

    fn observe(&self, exchange: &Exchange) -> Vec<Observation> {
        let input = match serde_json::to_string(&ExchangeView::of(exchange)) {
            Ok(json) => json,
            Err(_) => return Vec::new(),
        };
        let output = match self.sandbox.run_passive(&input, &self.limits) {
            Ok(out) => out,
            Err(e) => {
                // A trap, running out of fuel, or a bad memory range: a contained failure. The
                // extension produces nothing for this exchange, and the scan carries on.
                tracing::warn!(id = %self.info.id.0, error = %e, "extension run failed");
                return Vec::new();
            }
        };
        let raw: Vec<RawObservation> = match serde_json::from_str(&output) {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(
                    id = %self.info.id.0,
                    error = %e,
                    "extension output was not a JSON array of observations"
                );
                return Vec::new();
            }
        };
        raw.into_iter()
            .filter(|o| !o.title.trim().is_empty())
            .map(|o| {
                observation(
                    &self.info,
                    exchange,
                    format!("{} on {}", o.title, exchange.host),
                    "no exchange matches this extension's check",
                    o.detail.unwrap_or_else(|| o.title.clone()),
                    format!("reported by the {} extension", self.name),
                    o.severity.map(Into::into).unwrap_or(Severity::Medium),
                    Significance::Reportable,
                    None,
                )
            })
            .collect()
    }

    fn writeup(&self, observation: &Observation, exchange: &Exchange, target: TargetId) -> Writeup {
        Writeup {
            target,
            title: self.name.clone(),
            description: observation.observed.clone(),
            impact: "As judged by the extension that produced this lead.".into(),
            remediation: "See the extension's guidance.".into(),
            reproduction: format!(
                "Request {} {} and run the extension.",
                exchange.method, exchange.url
            ),
            cwe: None,
            owasp: None,
            source: source(&self.info),
            severity: observation.severity,
            location: observation.location.clone(),
        }
    }
}

/// The exchange as an extension module receives it: metadata and the redacted headers, no bodies.
///
/// This is the stable input contract for a passive-check module (extension API version 1). It
/// mirrors what every built-in and custom check sees — the same redacted headers, the same absence
/// of bodies — so an extension is no more privileged than the checks shipped in the box.
#[derive(Debug, Serialize)]
struct ExchangeView<'a> {
    method: &'a str,
    url: &'a str,
    host: &'a str,
    path: &'a str,
    port: u16,
    secure: bool,
    status: u16,
    authenticated: bool,
    response_bytes: u64,
    origin: &'a str,
    request_headers: Vec<HeaderView<'a>>,
    response_headers: Vec<HeaderView<'a>>,
}

impl<'a> ExchangeView<'a> {
    fn of(exchange: &'a Exchange) -> Self {
        Self {
            method: &exchange.method,
            url: &exchange.url,
            host: &exchange.host,
            path: &exchange.path,
            port: exchange.port,
            secure: exchange.secure,
            status: exchange.status,
            authenticated: exchange.authenticated,
            response_bytes: exchange.response_bytes,
            origin: &exchange.origin,
            request_headers: header_views(&exchange.request_headers),
            response_headers: header_views(&exchange.response_headers),
        }
    }
}

/// One header, name and (already-redacted) value.
#[derive(Debug, Serialize)]
struct HeaderView<'a> {
    name: &'a str,
    value: String,
}

fn header_views(headers: &hexora_types::http::Headers) -> Vec<HeaderView<'_>> {
    headers
        .iter()
        .map(|h| HeaderView {
            name: &h.name,
            value: h.value_lossy().into_owned(),
        })
        .collect()
}

/// One observation as a module emits it. `title` is required; `detail` and `severity` are
/// optional, so the simplest useful module returns `[{"title":"..."}]`.
#[derive(Debug, Deserialize)]
struct RawObservation {
    title: String,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    severity: Option<RawSeverity>,
}

/// The severity words a module may use; an unrecognised value fails to deserialise and the whole
/// observation is skipped, so a typo cannot silently downgrade a lead to a default.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<RawSeverity> for Severity {
    fn from(value: RawSeverity) -> Self {
        match value {
            RawSeverity::Info => Severity::Info,
            RawSeverity::Low => Severity::Low,
            RawSeverity::Medium => Severity::Medium,
            RawSeverity::High => Severity::High,
            RawSeverity::Critical => Severity::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_support::*;
    use hexora_ext::{InstalledExtension, Manifest};

    /// A WASM module (bump allocator + `run`) whose `run` body is the given WAT. Mirrors the
    /// harness in `hexora-wasm`, so tests here exercise the real sandbox path.
    fn module(run_body: &str) -> Vec<u8> {
        let src = format!(
            r#"(module
              (memory (export "memory") 1)
              (global $bump (mut i32) (i32.const 1024))
              (func (export "alloc") (param $len i32) (result i32)
                (local $p i32)
                global.get $bump local.set $p
                global.get $bump local.get $len i32.add global.set $bump
                local.get $p)
              {run_body})"#
        );
        wat::parse_str(&src).expect("valid WAT")
    }

    fn passive_ext(module: Vec<u8>) -> InstalledExtension {
        let manifest = Manifest::parse(
            br#"{"id":"com.example.t","name":"T","version":"1.0.0","api_version":1,
                 "kind":"passive_check","entry":"t.wasm","permissions":{"required":["http_read"]}}"#,
        )
        .unwrap();
        InstalledExtension::install_required_only(manifest).with_module(module)
    }

    /// A module that writes `[{"title":"seen","severity":"high"}]` at offset 0 and returns it.
    fn one_high_observation() -> Vec<u8> {
        let json = r#"[{\"title\":\"seen\",\"severity\":\"high\"}]"#;
        let len = r#"[{"title":"seen","severity":"high"}]"#.len();
        module(&format!(
            r#"(data (i32.const 0) "{json}")
               (func (export "run") (param i32) (param i32) (result i64)
                 (i64.const {len}))"#
        ))
    }

    #[test]
    fn an_extension_observation_becomes_a_reportable_lead() {
        let checks = load(&[passive_ext(one_high_observation())]);
        assert_eq!(checks.len(), 1, "the extension should load as one check");
        let found = checks[0].observe(&exchange(https().response(200, &[])));
        assert_eq!(found.len(), 1);
        assert!(found[0].is_reportable());
        assert_eq!(found[0].severity, Severity::High);
    }

    #[test]
    fn a_disabled_or_ungranted_extension_does_not_load() {
        // Passive but http_read declined -> installs disabled -> not loaded.
        let manifest = Manifest::parse(
            br#"{"id":"com.example.d","name":"D","version":"1","api_version":1,
                 "kind":"passive_check","entry":"d.wasm","permissions":{"required":["http_read"]}}"#,
        )
        .unwrap();
        let declined =
            InstalledExtension::install(manifest, []).with_module(one_high_observation());
        assert!(!declined.enabled);
        assert!(load(&[declined]).is_empty());
    }

    #[test]
    fn an_extension_with_no_module_is_skipped() {
        let ext = passive_ext(Vec::new());
        assert!(load(&[ext]).is_empty());
    }

    #[test]
    fn an_empty_output_array_yields_no_observations() {
        // Writes `[]` at offset 0.
        let m = module(
            r#"(data (i32.const 0) "[]")
               (func (export "run") (param i32) (param i32) (result i64)
                 (i64.const 2))"#,
        );
        let checks = load(&[passive_ext(m)]);
        assert!(checks[0]
            .observe(&exchange(https().response(200, &[])))
            .is_empty());
    }

    #[test]
    fn a_module_that_returns_garbage_produces_nothing_rather_than_failing() {
        // Writes `not json` and returns it — the run succeeds, parsing does not.
        let m = module(
            r#"(data (i32.const 0) "not json")
               (func (export "run") (param i32) (param i32) (result i64)
                 (i64.const 8))"#,
        );
        let checks = load(&[passive_ext(m)]);
        assert!(checks[0]
            .observe(&exchange(https().response(200, &[])))
            .is_empty());
    }
}

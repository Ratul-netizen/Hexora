//! DOM-based XSS detection — Nullhawk's answer to Burp's DOM Invader.
//!
//! Server-side XSS is visible in the response; DOM XSS is not. The payload never reaches the
//! server — it flows from a client-side **source** (`location.hash`, `location.search`,
//! `document.referrer`) into a dangerous **sink** (`innerHTML`, `document.write`, `eval`) inside
//! the page's own JavaScript, and only a real browser running that JavaScript can see it happen.
//!
//! So this drives a real browser over CDP. Before the page loads, it installs a script that
//! wraps the common sinks; it then navigates with a unique **canary** in a source and reads back
//! which sinks the canary reached. A canary that arrives at a sink is a proven source→sink flow —
//! the thing a grep of the response can never show.
//!
//! # It reports a flow, not an exploit
//!
//! A canary reaching `innerHTML` means the source flows to that sink. Whether it is exploitable
//! depends on the page's own encoding and framework, which this does not decide. Like every
//! passive lead in Nullhawk, it says what it saw — the flow — and leaves the proof to the tester.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use nullhawk_types::Result;

use crate::launch::{Browser, LaunchOptions};
use crate::Cdp;

/// The client-side sources a canary is planted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The URL fragment (`location.hash`) — the most common DOM-XSS source.
    Fragment,
    /// The query string (`location.search`).
    Query,
}

impl Source {
    /// A short label for reports.
    pub fn label(self) -> &'static str {
        match self {
            Source::Fragment => "location.hash",
            Source::Query => "location.search",
        }
    }

    /// Builds a URL that carries `canary` in this source.
    pub fn inject(self, target: &str, canary: &str) -> String {
        // The fragment is client-only, so it is always dropped before we place ours.
        let base = target.split('#').next().unwrap_or(target);
        match self {
            Source::Fragment => format!("{base}#{canary}"),
            Source::Query => {
                if base.contains('?') {
                    format!("{base}&nullhawk={canary}")
                } else {
                    format!("{base}?nullhawk={canary}")
                }
            }
        }
    }
}

/// One place a canary reached a sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkHit {
    /// Which source the canary was planted in.
    pub source: String,
    /// The sink it reached (`innerHTML`, `document.write`, …).
    pub sink: String,
    /// The value the sink received (truncated), for evidence.
    pub sample: String,
}

/// What a DOM-XSS test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomXssReport {
    /// The page tested.
    pub target: String,
    /// The sources that were tried.
    pub sources_tested: Vec<String>,
    /// The source→sink flows found. Empty means no canary reached an instrumented sink.
    pub hits: Vec<SinkHit>,
}

impl DomXssReport {
    /// Whether any source→sink flow was found.
    pub fn vulnerable(&self) -> bool {
        !self.hits.is_empty()
    }
}

/// The script installed before every document loads: it wraps the common DOM-XSS sinks and
/// records every value they receive into `window.__nullhawk_sinks`, truncated and capped. The
/// caller filters those records for its canary — so the page's own innocent sink use is ignored.
const INSTRUMENTATION: &str = r#"
(function () {
  if (window.__nullhawk_installed) return;
  window.__nullhawk_installed = true;
  window.__nullhawk_sinks = [];
  function rec(sink, value) {
    try {
      var v = String(value);
      if (v.length > 400) v = v.slice(0, 400);
      if (window.__nullhawk_sinks.length < 300) window.__nullhawk_sinks.push({ sink: sink, value: v });
    } catch (e) {}
  }
  ["innerHTML", "outerHTML"].forEach(function (prop) {
    var desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
    if (desc && desc.set) {
      var orig = desc.set;
      Object.defineProperty(Element.prototype, prop, {
        configurable: true,
        get: desc.get,
        set: function (v) { rec(prop, v); return orig.call(this, v); }
      });
    }
  });
  var iah = Element.prototype.insertAdjacentHTML;
  if (iah) {
    Element.prototype.insertAdjacentHTML = function (pos, html) {
      rec("insertAdjacentHTML", html); return iah.call(this, pos, html);
    };
  }
  ["write", "writeln"].forEach(function (m) {
    var orig = document[m];
    if (orig) {
      document[m] = function () {
        rec("document." + m, Array.prototype.join.call(arguments, ""));
        return orig.apply(document, arguments);
      };
    }
  });
  var _eval = window.eval;
  window.eval = function (s) { rec("eval", s); return _eval(s); };
  ["setTimeout", "setInterval"].forEach(function (m) {
    var orig = window[m];
    window[m] = function (fn) {
      if (typeof fn === "string") rec(m, fn);
      return orig.apply(window, arguments);
    };
  });
})();
"#;

/// A sink record read back from the page.
#[derive(Debug, Deserialize)]
struct SinkEntry {
    sink: String,
    value: String,
}

/// A unique, HTML-safe canary for one navigation.
fn fresh_canary() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Alphanumeric only: it must survive as a literal substring through a sink, and never
    // introduce markup of its own — the flow is what we are proving, not execution.
    format!("nullhawkdom{nanos:x}{n:x}")
}

/// Drives a real browser to test one page for DOM XSS, planting a canary in each source.
///
/// Launches a throwaway browser (headless by default), installs the sink instrumentation once,
/// then navigates once per source and reads back the flows. The browser is killed on drop.
pub async fn test(target: &str, headless: bool, timeout: Duration) -> Result<DomXssReport> {
    if crate::launch::find_browser().is_none() {
        return Err(nullhawk_types::NullhawkError::Internal(
            "no Chrome/Edge/Chromium found to drive; set NULLHAWK_BROWSER to its path".to_string(),
        ));
    }

    let options = LaunchOptions {
        headless,
        ..LaunchOptions::default()
    };
    let browser = Browser::launch_with(&options)?;
    let mut cdp = browser.connect().await?;

    cdp.call("Page.enable", Value::Null).await?;
    // Runs on every document the page navigates to, before its own scripts.
    cdp.call(
        "Page.addScriptToEvaluateOnNewDocument",
        json!({ "source": INSTRUMENTATION }),
    )
    .await?;

    let sources = [Source::Fragment, Source::Query];
    let mut hits = Vec::new();
    for source in sources {
        let canary = fresh_canary();
        let url = source.inject(target, &canary);
        for (sink, sample) in scan_once(&mut cdp, &url, &canary, timeout).await? {
            hits.push(SinkHit {
                source: source.label().to_string(),
                sink,
                sample,
            });
        }
    }

    Ok(DomXssReport {
        target: target.to_string(),
        sources_tested: sources.iter().map(|s| s.label().to_string()).collect(),
        hits,
    })
}

/// Navigates to one canary-bearing URL and returns the sink hits that carried the canary.
async fn scan_once(
    cdp: &mut Cdp,
    url: &str,
    canary: &str,
    timeout: Duration,
) -> Result<Vec<(String, String)>> {
    cdp.navigate(url, timeout).await?;
    // A short settle for scripts that run after load (framework hydration, timers).
    tokio::time::sleep(Duration::from_millis(400)).await;

    let raw = cdp
        .eval("JSON.stringify(window.__nullhawk_sinks || [])")
        .await?;
    let text = raw.as_str().unwrap_or("[]");
    let entries: Vec<SinkEntry> = serde_json::from_str(text).unwrap_or_default();

    Ok(entries
        .into_iter()
        .filter(|e| e.value.contains(canary))
        .map(|e| (e.sink, e.value.clone()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_injection_replaces_any_existing_hash() {
        assert_eq!(
            Source::Fragment.inject("https://t.com/p?a=1#old", "CAN"),
            "https://t.com/p?a=1#CAN"
        );
        assert_eq!(
            Source::Fragment.inject("https://t.com/", "CAN"),
            "https://t.com/#CAN"
        );
    }

    #[test]
    fn query_injection_appends_and_drops_the_fragment() {
        assert_eq!(
            Source::Query.inject("https://t.com/p#frag", "CAN"),
            "https://t.com/p?nullhawk=CAN"
        );
        assert_eq!(
            Source::Query.inject("https://t.com/p?a=1", "CAN"),
            "https://t.com/p?a=1&nullhawk=CAN"
        );
    }

    #[test]
    fn a_canary_is_unique_per_call_and_html_safe() {
        let a = fresh_canary();
        let b = fresh_canary();
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()), "{a}");
    }

    #[test]
    fn sink_entries_parse_and_filter_by_canary() {
        let json = r#"[{"sink":"innerHTML","value":"<b>nullhawkdomABC</b>"},{"sink":"eval","value":"safe()"}]"#;
        let entries: Vec<SinkEntry> = serde_json::from_str(json).unwrap();
        let hits: Vec<_> = entries
            .into_iter()
            .filter(|e| e.value.contains("nullhawkdomABC"))
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sink, "innerHTML");
    }

    #[test]
    fn a_report_with_no_hits_is_not_vulnerable() {
        let report = DomXssReport {
            target: "x".into(),
            sources_tested: vec![],
            hits: vec![],
        };
        assert!(!report.vulnerable());
    }
}

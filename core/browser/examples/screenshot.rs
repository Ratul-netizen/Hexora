//! Drives a headless browser over CDP to screenshot a page — a reliable capture that waits
//! for the app to settle, unlike a one-shot `--screenshot`. Dogfoods M18.a.
//!
//! ```console
//! $ chrome --headless=new --remote-debugging-port=9222 --window-size=1440,900 <url> &
//! $ cargo run -p hexora-browser --example screenshot -- 9222 out.png 2000
//! ```
//!
//! Args: `<port> <out.png> [settle_ms]`. Connects to a page target, waits `settle_ms` for the
//! page's own async work to finish, captures a PNG, and writes it.

use std::time::Duration;

use base64::Engine as _;
use hexora_browser::{discover_page_ws_url, Cdp};
use serde_json::json;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let port: u16 = args.next().and_then(|s| s.parse().ok()).unwrap_or(9222);
    let out = args.next().unwrap_or_else(|| "out.png".to_string());
    let settle_ms: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(2000);

    let ws = discover_page_ws_url("127.0.0.1", port)
        .await
        .expect("discover page target");
    let mut cdp = Cdp::connect(&ws).await.expect("connect CDP");

    cdp.call("Page.enable", json!({})).await.expect("Page.enable");
    cdp.call("Runtime.enable", json!({})).await.ok();
    // Let the SPA's async boot (the invoke chain) run to completion before capturing.
    tokio::time::sleep(Duration::from_millis(settle_ms)).await;

    // Optional 4th arg: a tab label to click before capturing.
    if let Some(label) = std::env::args().nth(4) {
        let js = format!(
            "(()=>{{const b=[...document.querySelectorAll('button.tab')].find(x=>x.textContent.trim()==={label:?});if(b){{b.click();return true}}return false}})()",
        );
        let _ = cdp
            .call("Runtime.evaluate", json!({ "expression": js, "returnByValue": true }))
            .await;
        tokio::time::sleep(Duration::from_millis(900)).await;
    }

    // Optional 5th arg: an arbitrary JS expression to run after the tab click (e.g. fill an
    // input and click a button), then settle before capturing.
    if let Some(expr) = std::env::args().nth(5) {
        let _ = cdp
            .call("Runtime.evaluate", json!({ "expression": expr, "returnByValue": true }))
            .await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }

    // Probe: what did the app actually render?
    if let Ok(probe) = cdp
        .call(
            "Runtime.evaluate",
            json!({ "expression": "JSON.stringify({len:(document.body.innerText||'').length, top:!!document.querySelector('.top'), root:(document.getElementById('root')||{}).childElementCount||0, err:(window.__lastError||'')})", "returnByValue": true }),
        )
        .await
    {
        eprintln!("probe: {}", probe.get("result").and_then(|r| r.get("value")).and_then(|v| v.as_str()).unwrap_or("?"));
    }

    let result = cdp
        .call(
            "Page.captureScreenshot",
            json!({ "format": "png", "captureBeyondViewport": false }),
        )
        .await
        .expect("captureScreenshot");
    let b64 = result
        .get("data")
        .and_then(|v| v.as_str())
        .expect("screenshot data");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("decode base64");
    std::fs::write(&out, &bytes).expect("write png");
    eprintln!("wrote {} ({} bytes)", out, bytes.len());
}

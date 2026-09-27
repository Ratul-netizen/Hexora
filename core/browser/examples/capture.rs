//! Launches the installed browser routed through a proxy and navigates it to a URL — the
//! M18.c capture path. Everything the page fetches goes through the proxy (Nullhawk's scope
//! guard + capture); this only drives the browser.
//!
//! ```console
//! $ cargo run -p nullhawk-browser --example capture -- 127.0.0.1:8751 http://target.test/
//! ```
//!
//! Args: `<proxy host:port> <url> [settle_ms]`.

use std::time::Duration;

use nullhawk_browser::{Browser, LaunchOptions};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let proxy = args.next().expect("proxy host:port");
    let url = args.next().expect("url to navigate to");
    let settle_ms: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1500);

    let browser =
        Browser::launch_with(&LaunchOptions::through_proxy(proxy)).expect("launch through proxy");
    let mut cdp = browser.connect().await.expect("connect CDP");

    cdp.navigate(&url, Duration::from_secs(20))
        .await
        .expect("navigate");
    // Let late subresources (XHR, images) finish flowing through the proxy before we quit.
    tokio::time::sleep(Duration::from_millis(settle_ms)).await;

    let landed = cdp.current_url().await.unwrap_or_default();
    eprintln!("navigated to {landed}");
    // Browser is killed on drop; the proxy keeps what it captured.
}

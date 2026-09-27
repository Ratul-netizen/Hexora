//! # Launch and attach (M18.b)
//!
//! Driving the browser already on the machine means first finding it and starting it with a
//! DevTools port — or attaching to one a tester already has running. Nothing here ships a
//! browser: if neither Chrome nor Edge is installed, [`find_browser`] returns `None` and the
//! caller says so plainly rather than pretending to a capability it lacks.
//!
//! A launched browser gets a **throwaway profile** (so it shares nothing with the tester's
//! real one) and is torn down when the [`Browser`] handle drops — no orphaned headless
//! process left behind.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use hexora_types::error::{HexoraError, Result};

use crate::Cdp;

/// Which browser was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKind {
    /// Google Chrome.
    Chrome,
    /// Microsoft Edge (Chromium-based; speaks CDP).
    Edge,
    /// Chromium.
    Chromium,
}

impl BrowserKind {
    /// A human name.
    pub fn label(self) -> &'static str {
        match self {
            BrowserKind::Chrome => "Chrome",
            BrowserKind::Edge => "Edge",
            BrowserKind::Chromium => "Chromium",
        }
    }
}

/// Options for a launch.
#[derive(Debug, Clone)]
pub struct LaunchOptions {
    /// Run without a visible window. On for automated crawling; off to watch it work.
    pub headless: bool,
    /// Route all the browser's traffic through this proxy (`host:port`), so it flows through
    /// Hexora's scope guard and capture like any other proxied browsing. `None` lets the
    /// browser talk to targets directly (no capture).
    pub proxy: Option<String>,
    /// Do not verify TLS certificates. Set when pointing the browser at Hexora's intercepting
    /// proxy without installing its CA into the browser's trust store.
    pub ignore_certificate_errors: bool,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        Self {
            headless: true,
            proxy: None,
            ignore_certificate_errors: false,
        }
    }
}

impl LaunchOptions {
    /// Options that route the browser through `proxy` (`host:port`) and trust it, the shape a
    /// capture session uses: everything the browser fetches goes through Hexora.
    ///
    /// Pair with a proxy in **in-scope-only** recording mode: a driven browser generates a lot
    /// of out-of-scope noise — its own telemetry and third-party resources — and scope
    /// filtering at the proxy is what keeps the captured traffic the target's, definitively,
    /// rather than relying on browser flags to mute every phone-home.
    pub fn through_proxy(proxy: impl Into<String>) -> Self {
        Self {
            headless: true,
            proxy: Some(proxy.into()),
            ignore_certificate_errors: true,
        }
    }
}

/// Finds an installed Chrome, Edge or Chromium, or `None` if none is present.
///
/// `HEXORA_BROWSER` overrides the search with an explicit executable path, so a tester can
/// point at a build the search does not know.
pub fn find_browser() -> Option<(PathBuf, BrowserKind)> {
    if let Some(explicit) = std::env::var_os("HEXORA_BROWSER") {
        let path = PathBuf::from(explicit);
        if path.exists() {
            let kind = classify(&path);
            return Some((path, kind));
        }
    }
    for (path, kind) in candidate_browsers() {
        if path.exists() {
            return Some((path, kind));
        }
    }
    None
}

/// Guesses the kind from an executable path.
fn classify(path: &Path) -> BrowserKind {
    let name = path.to_string_lossy().to_ascii_lowercase();
    if name.contains("edge") || name.contains("msedge") {
        BrowserKind::Edge
    } else if name.contains("chromium") {
        BrowserKind::Chromium
    } else {
        BrowserKind::Chrome
    }
}

/// The known install locations to probe, most-preferred first.
fn candidate_browsers() -> Vec<(PathBuf, BrowserKind)> {
    let mut out = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let pf86 =
            std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let chrome = r"Google\Chrome\Application\chrome.exe";
        let edge = r"Microsoft\Edge\Application\msedge.exe";
        out.push((PathBuf::from(&pf).join(chrome), BrowserKind::Chrome));
        out.push((PathBuf::from(&pf86).join(chrome), BrowserKind::Chrome));
        if !local.is_empty() {
            out.push((PathBuf::from(&local).join(chrome), BrowserKind::Chrome));
        }
        out.push((PathBuf::from(&pf86).join(edge), BrowserKind::Edge));
        out.push((PathBuf::from(&pf).join(edge), BrowserKind::Edge));
    }

    #[cfg(target_os = "macos")]
    {
        out.push((
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            BrowserKind::Chrome,
        ));
        out.push((
            PathBuf::from("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            BrowserKind::Edge,
        ));
        out.push((
            PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
            BrowserKind::Chromium,
        ));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for (name, kind) in [
            ("google-chrome", BrowserKind::Chrome),
            ("google-chrome-stable", BrowserKind::Chrome),
            ("chromium", BrowserKind::Chromium),
            ("chromium-browser", BrowserKind::Chromium),
            ("microsoft-edge", BrowserKind::Edge),
        ] {
            out.push((PathBuf::from("/usr/bin").join(name), kind));
            out.push((PathBuf::from("/usr/local/bin").join(name), kind));
        }
    }

    out
}

/// A launched browser, driven over CDP. Killed and its throwaway profile removed when dropped.
#[derive(Debug)]
pub struct Browser {
    child: Child,
    // Removed on drop; kept only for that.
    _profile: tempfile::TempDir,
    port: u16,
    kind: BrowserKind,
}

impl Browser {
    /// Finds a browser and launches it headless with a throwaway profile.
    pub fn launch() -> Result<Browser> {
        Self::launch_with(&LaunchOptions::default())
    }

    /// Launches with explicit options.
    pub fn launch_with(options: &LaunchOptions) -> Result<Browser> {
        let (exe, kind) = find_browser().ok_or_else(|| {
            HexoraError::invalid_input(
                "browser",
                "no Chrome, Edge or Chromium found; install one or set HEXORA_BROWSER to its path",
            )
        })?;
        Self::launch_exe(&exe, kind, options)
    }

    /// Launches a specific executable.
    pub fn launch_exe(exe: &Path, kind: BrowserKind, options: &LaunchOptions) -> Result<Browser> {
        let profile = tempfile::TempDir::new()
            .map_err(|e| HexoraError::Internal(format!("creating a browser profile dir: {e}")))?;

        let mut command = Command::new(exe);
        command
            // Port 0 lets the OS pick; the real port is read back from DevToolsActivePort.
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", profile.path().display()))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-extensions");
        // Quiet the browser's own phone-home, so a proxied capture is the target's traffic and
        // not Chrome talking to Google. Without these, update/sync/telemetry requests land in
        // the project alongside the page's real requests. This is the well-worn automation set.
        for flag in [
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--disable-domain-reliability",
            "--disable-client-side-phishing-detection",
            "--disable-default-apps",
            "--no-service-autorun",
            "--metrics-recording-only",
            "--disable-background-timer-throttling",
            "--disable-breakpad",
            "--disable-features=Translate,OptimizationHints,MediaRouter,InterestFeedContentSuggestions,CalculateNativeWinOcclusion",
        ] {
            command.arg(flag);
        }
        command.arg("about:blank");
        if options.headless {
            command.arg("--headless=new");
            command.arg("--disable-gpu");
        }
        if let Some(proxy) = &options.proxy {
            command.arg(format!("--proxy-server={proxy}"));
            // Even localhost must be proxied, or captured coverage would have holes.
            command.arg("--proxy-bypass-list=<-loopback>");
        }
        if options.ignore_certificate_errors {
            command.arg("--ignore-certificate-errors");
        }

        let mut child = command.spawn().map_err(|e| {
            HexoraError::invalid_input("browser", format!("could not start {}: {e}", exe.display()))
        })?;

        let port = match read_devtools_port(profile.path(), Duration::from_secs(15)) {
            Ok(port) => port,
            Err(error) => {
                // Do not leak the process if it started but never wrote its port.
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };

        Ok(Browser {
            child,
            _profile: profile,
            port,
            kind,
        })
    }

    /// The DevTools port this browser is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Which browser this is.
    pub fn kind(&self) -> BrowserKind {
        self.kind
    }

    /// Connects a CDP session to this browser's first page target.
    pub async fn connect(&self) -> Result<Cdp> {
        let ws = crate::discover_page_ws_url("127.0.0.1", self.port).await?;
        Cdp::connect(&ws).await
    }

    /// The browser's product string, e.g. `HeadlessChrome/…`.
    pub async fn version(&self) -> Result<String> {
        crate::browser_version("127.0.0.1", self.port).await
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        // Kill the browser process; its child processes exit with it. The profile dir is
        // removed by TempDir's own Drop. Both are best-effort — a tester quitting Hexora
        // should never see an error because a headless helper was slow to die.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Attaches to a browser already running with a DevTools port, without owning its lifecycle.
pub async fn attach(port: u16) -> Result<Cdp> {
    let ws = crate::discover_page_ws_url("127.0.0.1", port).await?;
    Cdp::connect(&ws).await
}

/// Reads the actual debugging port from the `DevToolsActivePort` file the browser writes into
/// its profile on startup. Polls until it appears or `timeout` elapses.
fn read_devtools_port(profile: &Path, timeout: Duration) -> Result<u16> {
    let marker = profile.join("DevToolsActivePort");
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(contents) = std::fs::read_to_string(&marker) {
            // First line is the port; the second is the browser target's WS path.
            if let Some(first) = contents.lines().next() {
                if let Ok(port) = first.trim().parse::<u16>() {
                    return Ok(port);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(HexoraError::Internal(
                "the browser did not report a DevTools port in time".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_reads_the_kind_from_the_path() {
        assert_eq!(classify(Path::new(r"C:\...\msedge.exe")), BrowserKind::Edge);
        assert_eq!(
            classify(Path::new("/usr/bin/chromium")),
            BrowserKind::Chromium
        );
        assert_eq!(
            classify(Path::new("/opt/google/chrome/chrome")),
            BrowserKind::Chrome
        );
    }

    #[test]
    fn finding_a_browser_never_panics() {
        // On a machine with a browser this is Some; on a bare CI box, None. Either is fine —
        // the point is that probing the filesystem does not panic.
        let _ = find_browser();
    }

    /// Live: launches the installed browser headless and reads its version, then drops it.
    #[tokio::test]
    #[ignore = "launches a real browser"]
    async fn live_launch_and_version() {
        let browser = Browser::launch().expect("launch a browser");
        eprintln!(
            "launched {} on port {}",
            browser.kind().label(),
            browser.port()
        );
        let product = browser.version().await.expect("get version");
        assert!(!product.is_empty());
        eprintln!("product: {product}");
    }

    /// Live: launches, navigates to a self-contained page and reads the rendered DOM back.
    /// A `data:` URL keeps it hermetic — the navigate/eval path is exercised with no server.
    #[tokio::test]
    #[ignore = "launches a real browser"]
    async fn live_navigate_and_read_dom() {
        let browser = Browser::launch().expect("launch a browser");
        let mut cdp = browser.connect().await.expect("connect");
        cdp.navigate(
            "data:text/html,<title>Hexora Nav</title><h1>hi there</h1>",
            Duration::from_secs(10),
        )
        .await
        .expect("navigate");

        let title = cdp.eval("document.title").await.expect("title");
        assert_eq!(title.as_str(), Some("Hexora Nav"));
        let text = cdp.eval("document.body.innerText").await.expect("text");
        assert!(text.as_str().unwrap_or("").contains("hi there"), "{text:?}");
    }
}

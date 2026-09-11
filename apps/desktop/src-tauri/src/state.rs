//! What the desktop client is holding open.
//!
//! All application state lives here rather than in the frontend. A React store that
//! believed a different thing about a project than the engine did would eventually
//! show a request that was never sent, and a security tool that displays the wrong
//! request is worse than one that shows nothing.
//!
//! # The proxy is a task, not an object
//!
//! [`hexora_proxy::ProxyServer::serve`] consumes the server and loops until the
//! process ends, which is right for a CLI and wrong for a window with a stop button.
//! So the server is moved into a task and [`RunningProxy`] holds the handle; stopping
//! aborts the task, which drops the listener and closes the port.
//!
//! In-flight connections are dropped when that happens. That is the intended
//! behaviour: "stop" from a UI means stop now, and a browser retrying a request it
//! just lost is a better outcome than a stop button that appears not to work.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hexora_storage::{Project, TrafficStore};
use hexora_types::error::{HexoraError, Result};

/// An open project, and anything running against it.
pub struct AppState {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    project: Option<OpenProject>,
    proxy: Option<RunningProxy>,
    scan: Option<hexora_active::Cancel>,
}

/// A project the window is working in.
pub struct OpenProject {
    /// Where it is on disk.
    pub path: PathBuf,
    /// Its name, as recorded when it was created.
    pub name: String,
    /// The store, shared with whatever is capturing into it.
    pub traffic: Arc<TrafficStore>,
    /// Kept alive because it owns the blob store the traffic store borrows.
    _project: Project,
}

/// A proxy listening on behalf of this window.
pub struct RunningProxy {
    /// The address actually bound.
    pub addr: SocketAddr,
    /// The project it is recording into.
    pub project: PathBuf,
    /// Aborting this closes the listener.
    handle: tokio::task::JoinHandle<()>,
}

impl RunningProxy {
    /// Builds a handle for an already-spawned proxy task.
    pub fn new(addr: SocketAddr, project: PathBuf, handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            addr,
            project,
            handle,
        }
    }

    /// Whether the task is still running.
    ///
    /// A proxy whose task has ended — a bind that was taken away, a panic — must not
    /// keep being reported as listening, or a tester will wonder why nothing is being
    /// captured.
    pub fn is_running(&self) -> bool {
        !self.handle.is_finished()
    }

    /// Stops the proxy, closing the port.
    pub fn stop(self) {
        self.handle.abort();
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().ok();
        f.debug_struct("AppState")
            .field(
                "project",
                &inner
                    .as_ref()
                    .and_then(|i| i.project.as_ref().map(|p| p.path.clone())),
            )
            .field(
                "proxy",
                &inner
                    .as_ref()
                    .and_then(|i| i.proxy.as_ref().map(|p| p.addr)),
            )
            .finish()
    }
}

impl AppState {
    /// Nothing open.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Opens a project, replacing whatever was open.
    ///
    /// Stops a running proxy first: leaving it capturing into a project the window is
    /// no longer showing would write traffic somewhere nobody is looking.
    pub fn open_project(&self, path: &Path, name: String, project: Project) -> Result<()> {
        let traffic = Arc::new(project.traffic());
        let open = OpenProject {
            path: path.to_path_buf(),
            name,
            traffic,
            _project: project,
        };

        let mut inner = self.lock()?;
        if let Some(proxy) = inner.proxy.take() {
            proxy.stop();
        }
        inner.project = Some(open);
        Ok(())
    }

    /// The traffic store of the open project.
    pub fn traffic(&self) -> Result<Arc<TrafficStore>> {
        let inner = self.lock()?;
        inner
            .project
            .as_ref()
            .map(|p| p.traffic.clone())
            .ok_or_else(no_project)
    }

    /// The open project's path and name.
    pub fn project_summary(&self) -> Result<Option<(PathBuf, String)>> {
        let inner = self.lock()?;
        Ok(inner
            .project
            .as_ref()
            .map(|p| (p.path.clone(), p.name.clone())))
    }

    /// The open project's directory.
    pub fn project_path(&self) -> Result<PathBuf> {
        let inner = self.lock()?;
        inner
            .project
            .as_ref()
            .map(|p| p.path.clone())
            .ok_or_else(no_project)
    }

    /// Records a newly started proxy, replacing any previous one.
    pub fn set_proxy(&self, proxy: RunningProxy) -> Result<()> {
        let mut inner = self.lock()?;
        if let Some(previous) = inner.proxy.take() {
            previous.stop();
        }
        inner.proxy = Some(proxy);
        Ok(())
    }

    /// Stops the proxy if one is running. Returns whether there was one.
    pub fn stop_proxy(&self) -> Result<bool> {
        let mut inner = self.lock()?;
        match inner.proxy.take() {
            Some(proxy) => {
                proxy.stop();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Records the token for a scan that is starting, and hands back a clone.
    ///
    /// Held here rather than in the command, because the whole point is that a
    /// *different* command — the one the stop button calls — has to be able to reach
    /// it while the run is still going.
    pub fn begin_scan(&self) -> Result<hexora_active::Cancel> {
        let mut inner = self.lock()?;
        let cancel = hexora_active::Cancel::new();
        inner.scan = Some(cancel.clone());
        Ok(cancel)
    }

    /// Forgets the token for a scan that has ended.
    ///
    /// Called whether the run finished or failed. A token left behind would make the
    /// stop button look live when there is nothing to stop, and — worse — a later run
    /// would find a token somebody had already pulled.
    pub fn end_scan(&self) -> Result<()> {
        let mut inner = self.lock()?;
        inner.scan = None;
        Ok(())
    }

    /// Stops a running scan before its next request. Returns whether there was one.
    ///
    /// What it can promise is exactly what [`hexora_active::Cancel`] promises: no
    /// further request is sent. A request already on the wire completes, because
    /// nothing can recall one.
    pub fn stop_scan(&self) -> Result<bool> {
        let inner = self.lock()?;
        match &inner.scan {
            Some(cancel) => {
                cancel.stop();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Whether a scan is running that could be stopped.
    pub fn scan_running(&self) -> Result<bool> {
        Ok(self.lock()?.scan.is_some())
    }

    /// Where the proxy is listening, if it is.
    ///
    /// Clears a handle whose task has ended, so a proxy that died is reported as
    /// stopped rather than as still listening.
    pub fn proxy_address(&self) -> Result<Option<SocketAddr>> {
        let mut inner = self.lock()?;
        match &inner.proxy {
            Some(proxy) if proxy.is_running() => Ok(Some(proxy.addr)),
            Some(_) => {
                inner.proxy = None;
                Ok(None)
            }
            None => Ok(None),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(|_| {
            HexoraError::Internal("the application state lock was poisoned".to_string())
        })
    }
}

fn no_project() -> HexoraError {
    HexoraError::invalid_input("project", "no project is open")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(state: &AppState) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        let project = Project::open(&path).unwrap();
        state
            .open_project(&path, "Test".to_string(), project)
            .unwrap();
        dir
    }

    #[test]
    fn nothing_is_open_to_begin_with() {
        let state = AppState::new();
        assert!(state.project_summary().unwrap().is_none());
        assert!(state.proxy_address().unwrap().is_none());
        assert!(!state.scan_running().unwrap());
    }

    #[test]
    fn a_stop_button_reaches_the_run_it_is_meant_to_stop() {
        // The whole reason the token lives here. The run holds a clone and the stop
        // command holds the state, and they have to be the same signal or the button
        // does nothing while looking as though it did something.
        let state = AppState::new();
        let cancel = state.begin_scan().unwrap();
        assert!(state.scan_running().unwrap());
        assert!(!cancel.stopped());

        assert!(state.stop_scan().unwrap(), "there was a run to stop");
        assert!(cancel.stopped(), "the run's own token was not pulled");
    }

    #[test]
    fn stopping_when_nothing_is_running_says_so_rather_than_pretending() {
        let state = AppState::new();
        assert!(!state.stop_scan().unwrap());
    }

    #[test]
    fn a_finished_run_leaves_no_token_behind() {
        // A token left behind would make the stop button look live with nothing to
        // stop — and, worse, the next run would find a signal somebody had already
        // pulled and would refuse to send anything.
        let state = AppState::new();
        let first = state.begin_scan().unwrap();
        first.stop();
        state.end_scan().unwrap();

        assert!(!state.scan_running().unwrap());
        let second = state.begin_scan().unwrap();
        assert!(
            !second.stopped(),
            "a new run inherited the previous run's stop signal"
        );
    }

    #[test]
    fn asking_for_traffic_with_no_project_is_a_clear_error() {
        // Not a panic and not an empty list: an empty history and "you have not opened
        // anything" look identical in a UI, and only one of them is actionable.
        let state = AppState::new();
        let err = state.traffic().unwrap_err();
        assert_eq!(err.code(), "invalid_input");
        assert!(err.to_string().contains("no project"), "{err}");
    }

    #[test]
    fn an_opened_project_is_reported_and_queryable() {
        let state = AppState::new();
        let _dir = open(&state);

        let (path, name) = state.project_summary().unwrap().unwrap();
        assert!(path.ends_with("engagement"));
        assert_eq!(name, "Test");
        assert_eq!(state.traffic().unwrap().count().unwrap(), 0);
    }

    #[tokio::test]
    async fn stopping_reports_whether_there_was_anything_to_stop() {
        let state = AppState::new();
        assert!(!state.stop_proxy().unwrap());

        let handle = tokio::spawn(async { std::future::pending::<()>().await });
        state
            .set_proxy(RunningProxy::new(
                "127.0.0.1:8080".parse().unwrap(),
                PathBuf::from("p"),
                handle,
            ))
            .unwrap();

        assert!(state.proxy_address().unwrap().is_some());
        assert!(state.stop_proxy().unwrap());
        assert!(state.proxy_address().unwrap().is_none());
    }

    #[tokio::test]
    async fn starting_a_second_proxy_stops_the_first() {
        // Two listeners recording into one project would double every exchange.
        let state = AppState::new();

        let first = tokio::spawn(async { std::future::pending::<()>().await });
        let first_abort = first.abort_handle();
        state
            .set_proxy(RunningProxy::new(
                "127.0.0.1:8080".parse().unwrap(),
                PathBuf::from("p"),
                first,
            ))
            .unwrap();

        let second = tokio::spawn(async { std::future::pending::<()>().await });
        state
            .set_proxy(RunningProxy::new(
                "127.0.0.1:8081".parse().unwrap(),
                PathBuf::from("p"),
                second,
            ))
            .unwrap();

        tokio::task::yield_now().await;
        assert!(first_abort.is_finished(), "the first proxy must be stopped");
        assert_eq!(
            state.proxy_address().unwrap().unwrap().port(),
            8081,
            "and the second is the one reported"
        );
    }

    #[tokio::test]
    async fn opening_a_different_project_stops_the_proxy() {
        // Otherwise it keeps capturing into a project the window is no longer showing.
        let state = AppState::new();
        let _dir = open(&state);

        let handle = tokio::spawn(async { std::future::pending::<()>().await });
        state
            .set_proxy(RunningProxy::new(
                "127.0.0.1:8080".parse().unwrap(),
                PathBuf::from("p"),
                handle,
            ))
            .unwrap();

        let _second = open(&state);
        assert!(
            state.proxy_address().unwrap().is_none(),
            "a proxy must not outlive the project it was recording into"
        );
    }

    #[tokio::test]
    async fn a_proxy_whose_task_ended_is_reported_as_stopped() {
        // A bind that was taken away, or a panic. Reporting it as listening would
        // leave a tester wondering why nothing is being captured.
        let state = AppState::new();
        let handle = tokio::spawn(async {});
        state
            .set_proxy(RunningProxy::new(
                "127.0.0.1:8080".parse().unwrap(),
                PathBuf::from("p"),
                handle,
            ))
            .unwrap();

        // Let the task finish.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(state.proxy_address().unwrap().is_none());
    }
}

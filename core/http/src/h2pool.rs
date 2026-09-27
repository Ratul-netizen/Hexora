//! A per-host pool of HTTP/2 connections (M5.1b).
//!
//! HTTP/2 multiplexes many requests over one connection, so opening a fresh one per
//! request — as the HTTP/1.x path still does — throws away the protocol's main advantage
//! and re-pays a TLS handshake every time. This pool keeps one connection per host alive
//! and hands out a stream on it for each request.
//!
//! # Reuse without serialising
//!
//! A [`h2::client::SendRequest`] is cheaply cloneable and the connection's I/O runs on its
//! own task, so concurrent requests to the same host each clone the handle and open their
//! own stream — they multiplex, they do not queue behind one another. The fast path here
//! never holds a lock across an `await` for that reason: it clones the handle out and lets
//! the caller open its stream unimpeded.
//!
//! # One connection per host, not one per race
//!
//! Establishing is the one thing that must be serialised: two requests that both miss the
//! pool at once should share the connection the first of them opens, not open two. A
//! per-host gate does that, and only that — different hosts still connect concurrently,
//! which is what keeps a multi-host scan fast.
//!
//! A connection that has gone away (GOAWAY, reset, a dropped socket) is detected when its
//! handle refuses to become ready, and is evicted so the next request reconnects. Nothing
//! here decides *whether* to speak HTTP/2 — that is ALPN's job, upstream — so a host that
//! only ever spoke HTTP/1.1 simply never has an entry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use nullhawk_types::tls::TlsInfo;

/// A connection is keyed by the host and port it reaches. The TLS settings are fixed for
/// the transport that owns the pool, so they are not part of the key.
type Key = (String, u16);

/// A live HTTP/2 handle and the TLS facts of the connection it belongs to.
type Pooled = (h2::client::SendRequest<Bytes>, TlsInfo);

/// A per-host pool of reusable HTTP/2 connections.
#[derive(Default)]
pub(crate) struct H2Pool {
    /// Live connections. Guarded by a std mutex held only for the map operation itself —
    /// never across an `await`, so a slow host cannot block a fast one.
    conns: Mutex<HashMap<Key, Pooled>>,
    /// Per-host establishment gates, so a first-connect race opens one connection.
    gates: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<()>>>>,
}

impl std::fmt::Debug for H2Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let live = self.conns.lock().map(|c| c.len()).unwrap_or(0);
        f.debug_struct("H2Pool").field("live", &live).finish()
    }
}

impl H2Pool {
    /// An empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a handle to a live pooled connection for `key`, or `None` when there is
    /// none — evicting an entry whose connection has gone away.
    ///
    /// Readiness is what proves the connection is still usable: a handle to a connection
    /// the peer has closed refuses to become ready, and that is the signal to reconnect.
    /// The returned handle is ready to open a stream.
    pub async fn reuse(&self, key: &Key) -> Option<Pooled> {
        let pooled = {
            let conns = self.conns.lock().unwrap();
            conns.get(key).cloned()
        };
        let (handle, tls) = pooled?;

        match handle.ready().await {
            Ok(ready) => Some((ready, tls)),
            Err(_) => {
                self.conns.lock().unwrap().remove(key);
                None
            }
        }
    }

    /// The per-host establishment gate. Held by a caller across the connect and handshake
    /// so a concurrent miss for the same host waits and then finds the connection pooled,
    /// rather than opening a second one.
    pub fn gate(&self, key: &Key) -> Arc<tokio::sync::Mutex<()>> {
        self.gates
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_default()
            .clone()
    }

    /// Records a freshly established connection for reuse.
    pub fn store(&self, key: Key, handle: h2::client::SendRequest<Bytes>, tls: TlsInfo) {
        self.conns.lock().unwrap().insert(key, (handle, tls));
    }

    /// Drops a connection from the pool.
    ///
    /// Called when a request on a reused connection fails: readiness cannot always tell a
    /// connection that closed between the check and the send, so a failure on a *reused*
    /// connection is itself the signal that it is gone, and the caller reconnects.
    pub fn evict(&self, key: &Key) {
        self.conns.lock().unwrap().remove(key);
    }
}

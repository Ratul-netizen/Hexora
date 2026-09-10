//! Sending each exchange to several observers.
//!
//! Recording traffic and reacting to it are separate concerns that are almost always
//! both wanted. The CLI prints a line *and* writes to the project; the desktop client
//! writes to the project *and* pushes an event to the UI. Neither observer should have
//! to know the other exists.
//!
//! # Order and isolation
//!
//! Observers run in the order they were added, and one that panics does not stop the
//! others — a UI event channel that has gone away must not take the capture that is
//! producing evidence down with it.

use hexora_engine::guard::ScopeDecision;
use hexora_engine::transport::Exchange;

use crate::server::ExchangeObserver;

/// Sends every exchange to several observers in turn.
#[derive(Default)]
pub struct Fanout {
    observers: Vec<Box<dyn ExchangeObserver>>,
}

impl std::fmt::Debug for Fanout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fanout")
            .field("observers", &self.observers.len())
            .finish()
    }
}

impl Fanout {
    /// An empty fan-out, which discards everything until something is added.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an observer, which will run after those already added.
    pub fn with(mut self, observer: impl ExchangeObserver) -> Self {
        self.observers.push(Box::new(observer));
        self
    }

    /// Adds an already-boxed observer.
    pub fn push(&mut self, observer: Box<dyn ExchangeObserver>) {
        self.observers.push(observer);
    }

    /// How many observers will be called.
    pub fn len(&self) -> usize {
        self.observers.len()
    }

    /// Whether nothing is listening.
    pub fn is_empty(&self) -> bool {
        self.observers.is_empty()
    }
}

impl ExchangeObserver for Fanout {
    fn observe(&self, exchange: &Exchange, decision: ScopeDecision) {
        for observer in &self.observers {
            // Isolated deliberately. An observer that panics — a UI channel whose
            // receiver has gone away, say — must not prevent the one after it from
            // recording the exchange. Evidence outranks notification.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observer.observe(exchange, decision);
            }));
            if result.is_err() {
                tracing::error!(
                    url = %exchange.request.url(),
                    "an exchange observer panicked; the remaining observers still ran"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use hexora_types::http::{Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};

    use super::*;

    fn exchange() -> Exchange {
        Exchange {
            encoded_body: None,
            content_encoding: None,
            raw_request: None,
            request: HttpRequest::get(HttpService::new("example.com", 443, true), "/"),
            response: HttpResponse {
                status: 200,
                reason: Some("OK".into()),
                version: HttpVersion::Http11,
                headers: Headers::new(),
                body: bytes::Bytes::new(),
                truncated: false,
            },
            duration: std::time::Duration::from_millis(1),
            tls: None,
        }
    }

    struct Counter(Arc<AtomicUsize>);

    impl ExchangeObserver for Counter {
        fn observe(&self, _: &Exchange, _: ScopeDecision) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Recorder(Arc<Mutex<Vec<&'static str>>>, &'static str);

    impl ExchangeObserver for Recorder {
        fn observe(&self, _: &Exchange, _: ScopeDecision) {
            self.0.lock().unwrap().push(self.1);
        }
    }

    struct Panicking;

    impl ExchangeObserver for Panicking {
        fn observe(&self, _: &Exchange, _: ScopeDecision) {
            panic!("this observer is broken");
        }
    }

    #[test]
    fn every_observer_sees_every_exchange() {
        let count = Arc::new(AtomicUsize::new(0));
        let fanout = Fanout::new()
            .with(Counter(count.clone()))
            .with(Counter(count.clone()));

        fanout.observe(&exchange(), ScopeDecision::Allowed);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn observers_run_in_the_order_they_were_added() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let fanout = Fanout::new()
            .with(Recorder(order.clone(), "first"))
            .with(Recorder(order.clone(), "second"));

        fanout.observe(&exchange(), ScopeDecision::Allowed);
        assert_eq!(*order.lock().unwrap(), vec!["first", "second"]);
    }

    #[test]
    fn a_panicking_observer_does_not_stop_the_ones_after_it() {
        // The case this exists for: a UI event channel whose receiver has gone away
        // must not take down the capture that is producing the evidence.
        let count = Arc::new(AtomicUsize::new(0));
        let fanout = Fanout::new().with(Panicking).with(Counter(count.clone()));

        fanout.observe(&exchange(), ScopeDecision::Allowed);
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "the recording observer must still have run"
        );
    }

    #[test]
    fn an_empty_fanout_discards_without_complaint() {
        let fanout = Fanout::new();
        assert!(fanout.is_empty());
        fanout.observe(&exchange(), ScopeDecision::Allowed);
    }

    #[test]
    fn the_scope_decision_reaches_every_observer_unchanged() {
        let seen = Arc::new(Mutex::new(Vec::new()));

        struct Decisions(Arc<Mutex<Vec<ScopeDecision>>>);
        impl ExchangeObserver for Decisions {
            fn observe(&self, _: &Exchange, decision: ScopeDecision) {
                self.0.lock().unwrap().push(decision);
            }
        }

        let fanout = Fanout::new()
            .with(Decisions(seen.clone()))
            .with(Decisions(seen.clone()));
        fanout.observe(&exchange(), ScopeDecision::AllowedOutOfScope);

        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                ScopeDecision::AllowedOutOfScope,
                ScopeDecision::AllowedOutOfScope
            ]
        );
    }
}

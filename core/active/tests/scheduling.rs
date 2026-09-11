//! What a run promises the systems it tests, checked against a lab that records.
//!
//! These are not tests of a check's reasoning — that lives next to each check. They
//! are tests of the properties a client is entitled to: one host is never sent two
//! requests at once, the ceiling holds, stopping stops, and scope is re-asked rather
//! than assumed.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hexora_active::{run, ActiveCheck, Budget, Cancel, Plan, Subject};
use hexora_repeater::{Draft, Sent};
use hexora_storage::{CapturedExchange, Project};
use hexora_types::finding::{FindingSource, Hypothesis, Severity};
use hexora_types::http::{Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};
use hexora_types::identity::Identity;
use hexora_types::ids::RequestId;
use hexora_types::verify::{DetectorId, DetectorInfo, DetectorMode, Verification, Writeup};
use hexora_types::Result;
use hexora_verify::Lab;

// ---------------------------------------------------------------------------
// A lab that records instead of sending
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Call {
    host: String,
    at: Instant,
}

/// A lab that answers instantly and writes down what it was asked to do.
struct Recorder {
    calls: Mutex<Vec<Call>>,
    /// Hosts this lab claims are out of scope.
    out_of_scope: Vec<String>,
    /// How long each "request" takes, so overlap is observable.
    latency: Duration,
    /// Pulled when a given number of requests have been made, to test cancellation.
    stop_after: Option<(usize, Cancel)>,
    project: Arc<Project>,
}

impl Recorder {
    fn new(project: Arc<Project>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            out_of_scope: Vec::new(),
            latency: Duration::from_millis(20),
            stop_after: None,
            project,
        }
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

#[async_trait]
impl Lab for Recorder {
    async fn experiment(&self, draft: &Draft, _: Option<&Identity>) -> Result<Sent> {
        let host = draft.request.service.host.clone();
        let index = {
            let mut calls = self.calls.lock().unwrap();
            calls.push(Call {
                host: host.clone(),
                at: Instant::now(),
            });
            calls.len()
        };
        tokio::time::sleep(self.latency).await;
        if let Some((after, cancel)) = &self.stop_after {
            if index >= *after {
                cancel.stop();
            }
        }

        // Whatever the check asked for, reflected — so the reflection check reaches
        // its strongest verdict and the scheduler is exercised at full request count.
        let origin = draft
            .request
            .headers
            .get("origin")
            .map(|h| h.value_lossy().to_string())
            .unwrap_or_default();
        let mut headers = Headers::new();
        headers.set("Access-Control-Allow-Origin", origin);
        headers.set("Access-Control-Allow-Credentials", "true");

        let id = self
            .project
            .traffic()
            .record(&CapturedExchange {
                request: draft.request.clone(),
                response: HttpResponse {
                    status: 200,
                    reason: None,
                    version: HttpVersion::Http11,
                    headers,
                    body: bytes::Bytes::new(),
                    truncated: false,
                },
                encoded_body: None,
                raw_request: None,
                content_encoding: None,
                origin: "scanner",
                identity: None,
                parent: draft.parent,
                quirks: Vec::new(),
                tls: None,
                duration_ms: 1,
            })
            .unwrap();

        let response = self.project.traffic().request(id).unwrap();
        let _ = response;
        Ok(Sent {
            id,
            parent: draft.parent,
            identity: None,
            exchange: hexora_engine::transport::Exchange {
                request: draft.request.clone(),
                response: HttpResponse {
                    status: 200,
                    reason: None,
                    version: HttpVersion::Http11,
                    headers: {
                        let mut headers = Headers::new();
                        let origin = draft
                            .request
                            .headers
                            .get("origin")
                            .map(|h| h.value_lossy().to_string())
                            .unwrap_or_default();
                        headers.set("Access-Control-Allow-Origin", origin);
                        headers.set("Access-Control-Allow-Credentials", "true");
                        headers
                    },
                    body: bytes::Bytes::new(),
                    truncated: false,
                },
                encoded_body: None,
                content_encoding: None,
                raw_request: None,
                duration: Duration::from_millis(1),
                tls: None,
            },
            decision: hexora_engine::guard::ScopeDecision::Allowed,
        })
    }

    fn would_leave_scope(&self, draft: &Draft, _: Option<&Identity>) -> bool {
        self.out_of_scope.contains(&draft.request.service.host)
    }

    fn draft_of(&self, request: RequestId) -> Result<Draft> {
        let stored = self.project.traffic().request(request)?;
        let mut headers = Headers::from_block(&stored.headers_raw);
        headers.set("Host", stored.service.authority());
        Ok(Draft::derived_from(
            HttpRequest {
                method: stored.method.clone(),
                path: stored.path.clone(),
                version: HttpVersion::Http11,
                headers,
                body: bytes::Bytes::from(stored.body.clone()),
                service: stored.service.clone(),
            },
            Some(request),
        ))
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Captures one exchange that looks like the CORS hypothesis's source.
fn capture(project: &Project, host: &str) -> RequestId {
    let service = HttpService::new(host, 443, true);
    let mut request = HttpRequest::get(service, "/api/me");
    request.headers.set("Origin", "https://app.example.com");
    let mut response = Headers::new();
    response.set("Access-Control-Allow-Origin", "https://app.example.com");
    response.set("Access-Control-Allow-Credentials", "true");

    project
        .traffic()
        .record(&CapturedExchange {
            request,
            response: HttpResponse {
                status: 200,
                reason: None,
                version: HttpVersion::Http11,
                headers: response,
                body: bytes::Bytes::from("{}"),
                truncated: false,
            },
            encoded_body: None,
            raw_request: None,
            content_encoding: None,
            origin: "proxy",
            identity: None,
            parent: None,
            quirks: Vec::new(),
            tls: None,
            duration_ms: 1,
        })
        .unwrap()
}

fn suspicion(source: RequestId, host: &str) -> Hypothesis {
    Hypothesis {
        detector: "cors.configuration".into(),
        claim: format!("{host} may reflect any Origin it is sent, with credentials allowed"),
        source_request: source,
        location: None,
        provisional_severity: Severity::High,
    }
}

/// A check that sends exactly `requests` requests and says nothing interesting.
struct Chatty {
    requests: usize,
}

#[async_trait]
impl ActiveCheck for Chatty {
    fn about(&self) -> DetectorInfo {
        DetectorInfo {
            id: DetectorId("test.chatty"),
            name: "Chatty",
            version: "1.0.0",
            about: "a check that sends a fixed number of requests",
            mode: DetectorMode::Active,
            observes: false,
            hypothesizes: false,
            settles: None,
        }
    }

    fn handles(&self, hypothesis: &Hypothesis) -> bool {
        hypothesis.detector == "cors.configuration"
    }

    async fn settle(
        &self,
        subject: &Subject,
        lab: &dyn Lab,
        _budget: &Budget,
    ) -> Result<Verification> {
        let mut sent = 0;
        for _ in 0..self.requests {
            if lab.experiment(&subject.draft, None).await.is_ok() {
                sent += 1;
            }
        }
        Ok(Verification::Refuted {
            note: format!("sent {sent} request(s) and established nothing"),
        })
    }

    fn writeup(&self, subject: &Subject, _: &Verification) -> Writeup {
        Writeup {
            target: subject.target,
            title: "chatty".into(),
            description: String::new(),
            impact: String::new(),
            remediation: String::new(),
            reproduction: String::new(),
            cwe: None,
            owasp: None,
            source: FindingSource::ActiveScan {
                detector: "test.chatty".into(),
                version: "1.0.0".into(),
            },
            severity: Severity::Info,
            location: None,
        }
    }
}

fn chatty(requests: usize) -> Vec<Box<dyn ActiveCheck>> {
    vec![Box::new(Chatty { requests })]
}

// ---------------------------------------------------------------------------
// The plan sends nothing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preparing_a_plan_sends_nothing_at_all() {
    // The property `--dry-run` rests on. Not "the flag was honoured" — the sending
    // function was never called.
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "api.example.com");
    let lab = Recorder::new(project.clone());

    let plan = Plan::prepare(
        &project,
        &lab,
        &chatty(1),
        &[suspicion(source, "api.example.com")],
        &Budget::default(),
    )
    .unwrap();

    assert_eq!(plan.work.len(), 1);
    assert_eq!(lab.count(), 0, "preparing a plan put traffic on the wire");
    assert!(plan.describe().contains("api.example.com"));
}

#[tokio::test]
async fn a_hypothesis_nothing_can_settle_is_reported_rather_than_dropped() {
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "api.example.com");
    let lab = Recorder::new(project.clone());

    let mut unhandled = suspicion(source, "api.example.com");
    unhandled.detector = "something.nobody.verifies".into();

    let plan = Plan::prepare(&project, &lab, &chatty(1), &[unhandled], &Budget::default()).unwrap();

    assert!(plan.work.is_empty());
    assert_eq!(plan.skipped.len(), 1);
    assert!(
        plan.skipped[0].why.contains("no check in this build"),
        "{:?}",
        plan.skipped[0]
    );
}

#[tokio::test]
async fn a_hypothesis_whose_traffic_is_gone_is_not_guessed_at() {
    let project = Arc::new(Project::in_memory().unwrap());
    let lab = Recorder::new(project.clone());

    let plan = Plan::prepare(
        &project,
        &lab,
        &chatty(1),
        &[suspicion(RequestId::new(), "api.example.com")],
        &Budget::default(),
    )
    .unwrap();

    assert!(plan.work.is_empty());
    assert!(plan.skipped[0].why.contains("no longer holds"));
}

#[tokio::test]
async fn an_out_of_scope_target_is_one_line_in_the_plan_and_never_a_request() {
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "not-ours.example.com");
    let mut lab = Recorder::new(project.clone());
    lab.out_of_scope = vec!["not-ours.example.com".into()];

    let plan = Plan::prepare(
        &project,
        &lab,
        &chatty(1),
        &[suspicion(source, "not-ours.example.com")],
        &Budget::default(),
    )
    .unwrap();

    assert!(plan.work.is_empty(), "an out-of-scope host was queued");
    assert!(plan.skipped[0].why.contains("not in the project's scope"));

    let outcome = run(&plan, &lab, &chatty(1), &Cancel::new()).await.unwrap();
    assert_eq!(outcome.requests_sent, 0);
    assert_eq!(lab.count(), 0);
}

// ---------------------------------------------------------------------------
// What the run promises the target
// ---------------------------------------------------------------------------

#[tokio::test]
async fn one_host_is_never_sent_two_requests_at_the_same_time() {
    // The promise a global concurrency limit cannot make. Eight requests spread over
    // eight hosts is polite; eight aimed at one host is a small denial of service.
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "api.example.com");
    let lab = Recorder::new(project.clone());

    let hypotheses: Vec<Hypothesis> = (0..4)
        .map(|i| {
            let mut h = suspicion(source, "api.example.com");
            h.claim = format!("suspicion {i}");
            h
        })
        .collect();

    let budget = Budget {
        hosts_at_once: 4,
        pause: Duration::from_millis(0),
        max_requests: 100,
        per_hypothesis: 2,
    };
    let plan = Plan::prepare(&project, &lab, &chatty(2), &hypotheses, &budget).unwrap();
    assert_eq!(plan.work.len(), 4);

    run(&plan, &lab, &chatty(2), &Cancel::new()).await.unwrap();

    // Each "request" takes 20ms. If any two overlapped, two starts would be closer
    // together than that.
    let calls = lab.calls();
    assert_eq!(calls.len(), 8);
    for pair in calls.windows(2) {
        let gap = pair[1].at.duration_since(pair[0].at);
        assert!(
            gap >= Duration::from_millis(15),
            "two requests to one host overlapped: {gap:?}"
        );
    }
}

#[tokio::test]
async fn different_hosts_are_worked_at_the_same_time() {
    // The other half: politeness per host must not mean a four-hour run.
    let project = Arc::new(Project::in_memory().unwrap());
    let lab = Recorder::new(project.clone());

    let hypotheses: Vec<Hypothesis> = ["a.example.com", "b.example.com", "c.example.com"]
        .iter()
        .map(|host| suspicion(capture(&project, host), host))
        .collect();

    let budget = Budget {
        hosts_at_once: 3,
        pause: Duration::from_millis(0),
        max_requests: 100,
        per_hypothesis: 1,
    };
    let plan = Plan::prepare(&project, &lab, &chatty(1), &hypotheses, &budget).unwrap();
    assert_eq!(plan.by_host().len(), 3);

    let started = Instant::now();
    run(&plan, &lab, &chatty(1), &Cancel::new()).await.unwrap();
    let took = started.elapsed();

    assert_eq!(lab.count(), 3);
    assert!(
        took < Duration::from_millis(55),
        "three hosts took {took:?}, which is sequential rather than concurrent"
    );
}

#[tokio::test]
async fn the_pause_between_requests_to_one_host_is_honoured() {
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "api.example.com");
    let lab = Recorder::new(project.clone());

    let budget = Budget {
        hosts_at_once: 1,
        pause: Duration::from_millis(80),
        max_requests: 10,
        per_hypothesis: 1,
    };
    let two: Vec<Hypothesis> = (0..2)
        .map(|i| {
            let mut h = suspicion(source, "api.example.com");
            h.claim = format!("suspicion {i}");
            h
        })
        .collect();
    let plan = Plan::prepare(&project, &lab, &chatty(1), &two, &budget).unwrap();

    let started = Instant::now();
    run(&plan, &lab, &chatty(1), &Cancel::new()).await.unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(80),
        "the pause between experiments on one host was skipped"
    );
}

#[tokio::test]
async fn the_request_ceiling_holds_even_against_a_check_that_loops() {
    // The reason the ceiling is enforced by the lab the check is handed rather than by
    // each check's own restraint. This one asks for fifty.
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "api.example.com");
    let lab = Recorder::new(project.clone());

    let budget = Budget {
        hosts_at_once: 1,
        pause: Duration::from_millis(0),
        max_requests: 3,
        per_hypothesis: 3,
    };
    let plan = Plan::prepare(
        &project,
        &lab,
        &chatty(50),
        &[suspicion(source, "api.example.com")],
        &budget,
    )
    .unwrap();

    let outcome = run(&plan, &lab, &chatty(50), &Cancel::new()).await.unwrap();
    assert_eq!(lab.count(), 3, "the ceiling did not hold");
    assert_eq!(outcome.requests_sent, 3);
}

#[tokio::test]
async fn a_run_that_hit_its_ceiling_says_so_rather_than_reading_as_finished() {
    // The failure this crate most has to avoid: a truncated run whose reader concludes
    // "clean" instead of "unfinished".
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "api.example.com");
    let lab = Recorder::new(project.clone());

    let many: Vec<Hypothesis> = (0..5)
        .map(|i| {
            let mut h = suspicion(source, "api.example.com");
            h.claim = format!("suspicion {i}");
            h
        })
        .collect();
    let budget = Budget {
        hosts_at_once: 1,
        pause: Duration::from_millis(0),
        max_requests: 2,
        per_hypothesis: 1,
    };
    let plan = Plan::prepare(&project, &lab, &chatty(1), &many, &budget).unwrap();
    assert!(plan.exceeds_ceiling());

    let outcome = run(&plan, &lab, &chatty(1), &Cancel::new()).await.unwrap();
    assert!(!outcome.complete());
    assert_eq!(
        outcome.stopped,
        Some(hexora_active::StoppedBecause::CeilingReached)
    );
    assert!(outcome.stopped.unwrap().as_str().contains("not performed"));
}

#[tokio::test]
async fn stopping_a_run_stops_the_next_request() {
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "api.example.com");
    let cancel = Cancel::new();
    let mut lab = Recorder::new(project.clone());
    lab.stop_after = Some((2, cancel.clone()));

    let many: Vec<Hypothesis> = (0..6)
        .map(|i| {
            let mut h = suspicion(source, "api.example.com");
            h.claim = format!("suspicion {i}");
            h
        })
        .collect();
    let budget = Budget {
        hosts_at_once: 1,
        pause: Duration::from_millis(0),
        max_requests: 50,
        per_hypothesis: 1,
    };
    let plan = Plan::prepare(&project, &lab, &chatty(1), &many, &budget).unwrap();

    let outcome = run(&plan, &lab, &chatty(1), &cancel).await.unwrap();

    assert!(lab.count() <= 3, "sent {} after stopping", lab.count());
    assert_eq!(
        outcome.stopped,
        Some(hexora_active::StoppedBecause::Cancelled)
    );
    assert!(!outcome.complete());
}

#[tokio::test]
async fn a_finished_run_says_it_finished() {
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "api.example.com");
    let lab = Recorder::new(project.clone());

    let budget = Budget {
        hosts_at_once: 1,
        pause: Duration::from_millis(0),
        max_requests: 50,
        per_hypothesis: 2,
    };
    let plan = Plan::prepare(
        &project,
        &lab,
        &chatty(1),
        &[suspicion(source, "api.example.com")],
        &budget,
    )
    .unwrap();

    let outcome = run(&plan, &lab, &chatty(1), &Cancel::new()).await.unwrap();
    assert!(outcome.complete());
    assert_eq!(outcome.judged.len(), 1);
    assert_eq!(outcome.refuted().count(), 1, "a refutation is a result");
    assert!(
        outcome.findings().is_empty(),
        "a refutation is not a finding"
    );
}

// ---------------------------------------------------------------------------
// The reflection check, end to end through the scheduler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_reflecting_application_is_confirmed_by_two_different_origins() {
    // The loop M13.2 left open: a hypothesis a passive check could not settle,
    // settled.
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "api.example.com");
    let lab = Recorder::new(project.clone());
    let checks = hexora_active::active_checks();

    let plan = Plan::prepare(
        &project,
        &lab,
        &checks,
        &[suspicion(source, "api.example.com")],
        &Budget::default(),
    )
    .unwrap();

    let outcome = run(&plan, &lab, &checks, &Cancel::new()).await.unwrap();

    assert_eq!(lab.count(), 2, "two unrelated origins, not one asked twice");
    let judged = &outcome.judged[0];
    assert!(
        matches!(judged.verification, Verification::Reproduced { .. }),
        "{:?}",
        judged.verification
    );
    let finding = judged.finding.as_ref().expect("a finding").clone();
    let finding = finding.into_finding();
    assert_eq!(finding.confidence, hexora_types::Confidence::Confirmed);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(
        finding.evidence.len(),
        3,
        "the capture and both probes are cited"
    );
}

#[tokio::test]
async fn the_probes_carry_an_origin_that_can_never_be_a_real_site() {
    let project = Arc::new(Project::in_memory().unwrap());
    let source = capture(&project, "api.example.com");
    let lab = Recorder::new(project.clone());
    let checks = hexora_active::active_checks();

    let plan = Plan::prepare(
        &project,
        &lab,
        &checks,
        &[suspicion(source, "api.example.com")],
        &Budget::default(),
    )
    .unwrap();
    run(&plan, &lab, &checks, &Cancel::new()).await.unwrap();

    // Every request went to the target host. The origin is a header; nothing is sent
    // to the probe domain, which is the point of it being unresolvable.
    for call in lab.calls() {
        assert_eq!(call.host, "api.example.com");
    }
}

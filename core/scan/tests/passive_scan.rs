//! The passive scanner, end to end over a real project.
//!
//! Everything here builds a project, records exchanges into it exactly as the proxy
//! would, and runs the scanner. No transport is constructed anywhere in this file —
//! there is nowhere to put one, which is the point of the first test.

use bytes::Bytes;
use hexora_scan::passive::{scan, Selection};
use hexora_storage::{CapturedExchange, MemoryBlobStore, Project, TrafficStore};
use hexora_types::http::{Header, Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};
use hexora_types::scope::{Scope, ScopeRule};
use std::sync::Arc;

/// A project with traffic, and no way to send anything.
struct Fixture {
    project: Project,
    traffic: Arc<TrafficStore>,
}

fn fixture() -> Fixture {
    let project = Project::in_memory().unwrap();
    project
        .metadata()
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO project (id, name, created_at, updated_at)
             VALUES ('prj_default', 'test', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
    project
        .settings()
        .set_scope(&Scope::new().include(ScopeRule::host("api.example.com")))
        .unwrap();

    let traffic = Arc::new(TrafficStore::new(
        project.metadata().clone(),
        Arc::new(MemoryBlobStore::new()),
    ));
    Fixture { project, traffic }
}

impl Fixture {
    /// Records one exchange, as the proxy does.
    fn capture(
        &self,
        host: &str,
        secure: bool,
        path: &str,
        request_headers: &[(&str, &str)],
        status: u16,
        response_headers: &[(&str, &str)],
    ) {
        let service = HttpService::new(host, if secure { 443 } else { 80 }, secure);
        let mut request = HttpRequest::get(service, path);
        for (name, value) in request_headers {
            request
                .headers
                .append(Header::new((*name).to_string(), *value));
        }

        let mut headers = Headers::new();
        for (name, value) in response_headers {
            headers.append(Header::new((*name).to_string(), *value));
        }

        self.traffic
            .record(&CapturedExchange {
                request,
                raw_request: None,
                response: HttpResponse {
                    status,
                    reason: None,
                    version: HttpVersion::Http11,
                    headers,
                    body: Bytes::from_static(b"{\"ok\":true}"),
                    truncated: false,
                },
                encoded_body: None,
                content_encoding: None,
                origin: "proxy",
                identity: None,
                parent: None,
                quirks: Vec::new(),
                tls: None,
                duration_ms: 1,
            })
            .unwrap();
    }

    fn scan(&self, selection: Selection) -> hexora_scan::passive::Summary {
        scan(&self.project, &selection).unwrap()
    }
}

// ---------------------------------------------------------------------------
// The hard invariant
// ---------------------------------------------------------------------------

#[test]
fn the_scanner_has_nowhere_to_put_a_transport() {
    // M13.2's hard invariant, checked the only way it can honestly be checked.
    //
    // `scan(&Project, &Selection)` takes no transport, no Lab, and nothing that can
    // reach a network. There is no mock to install because there is no parameter to
    // install it into — a test that asserted "the mock was never called" would be
    // weaker than this, because it would imply a transport existed and was merely
    // unused.
    //
    // This test runs a full scan over a project built with `MemoryBlobStore` and an
    // in-memory database, inside a process with no runtime started. If the scanner
    // ever acquires a way to send, this stops compiling or starts needing one.
    let fixture = fixture();
    fixture.capture("api.example.com", true, "/a", &[], 200, &[]);

    let summary = fixture.scan(Selection::default());
    assert_eq!(summary.exchanges_read, 1);
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

#[test]
fn out_of_scope_traffic_is_skipped_and_counted_rather_than_analysed() {
    // A project holds whatever the proxy saw, including the tester's own browsing.
    let fixture = fixture();
    fixture.capture("api.example.com", true, "/a", &[], 200, &[]);
    fixture.capture("news.example.org", true, "/b", &[], 200, &[]);
    fixture.capture("mail.google.com", true, "/c", &[], 200, &[]);

    let summary = fixture.scan(Selection::default());
    assert_eq!(summary.exchanges_read, 1);
    assert_eq!(summary.exchanges_skipped, 2);
    assert!(
        summary
            .observations
            .iter()
            .all(|group| group.host == "api.example.com"),
        "{:#?}",
        summary.observations
    );
}

#[test]
fn out_of_scope_traffic_can_be_asked_for_explicitly() {
    let fixture = fixture();
    fixture.capture("api.example.com", true, "/a", &[], 200, &[]);
    fixture.capture("news.example.org", true, "/b", &[], 200, &[]);

    let summary = fixture.scan(Selection {
        everything: true,
        ..Selection::default()
    });
    assert_eq!(summary.exchanges_read, 2);
    assert!(summary
        .run
        .as_ref()
        .unwrap()
        .selection
        .contains("including out-of-scope"));
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

#[test]
fn five_hundred_endpoints_missing_one_header_are_one_finding() {
    // The property a scanner lives or dies by. Without it this produces five hundred
    // rows and the findings list becomes something people close.
    let fixture = fixture();
    for index in 0..500 {
        fixture.capture(
            "api.example.com",
            true,
            &format!("/endpoint/{index}"),
            &[],
            200,
            &[("Content-Type", "application/json")],
        );
    }

    let summary = fixture.scan(Selection::default());
    let hsts: Vec<_> = summary
        .observations
        .iter()
        .filter(|group| {
            group
                .observation
                .about
                .contains("Strict-Transport-Security")
        })
        .collect();

    assert_eq!(hsts.len(), 1, "one thing to fix, one row");
    assert_eq!(hsts[0].occurrences, 500);
    // And the evidence is still exact: three real exchanges a reader can open.
    assert_eq!(
        hsts[0].exchanges.len(),
        hexora_scan::passive::EVIDENCE_PER_GROUP
    );
    assert_eq!(summary.findings().len(), 1);
}

#[test]
fn the_same_condition_on_two_hosts_stays_two_findings() {
    // Grouping is per host: two servers missing the same header are two things to
    // fix, usually by two teams.
    let fixture = fixture();
    fixture
        .project
        .settings()
        .set_scope(
            &Scope::new()
                .include(ScopeRule::host("api.example.com"))
                .include(ScopeRule::host("cdn.example.com")),
        )
        .unwrap();
    fixture.capture("api.example.com", true, "/a", &[], 200, &[]);
    fixture.capture("cdn.example.com", true, "/b", &[], 200, &[]);

    let summary = fixture.scan(Selection::default());
    let hosts: Vec<&str> = summary
        .observations
        .iter()
        .filter(|group| {
            group
                .observation
                .about
                .contains("Strict-Transport-Security")
        })
        .map(|group| group.host.as_str())
        .collect();
    assert_eq!(hosts.len(), 2, "{hosts:?}");
}

// ---------------------------------------------------------------------------
// What comes out, and what does not
// ---------------------------------------------------------------------------

#[test]
fn a_correctly_configured_application_produces_no_findings() {
    // The negative control. A clean run must be silent, or nothing else here means
    // anything.
    let fixture = fixture();
    fixture.capture(
        "api.example.com",
        true,
        "/account",
        &[],
        200,
        &[
            ("Content-Type", "application/json"),
            ("Strict-Transport-Security", "max-age=63072000"),
            ("Cache-Control", "no-store"),
        ],
    );

    let summary = fixture.scan(Selection::default());
    assert!(summary.findings().is_empty(), "{:#?}", summary.observations);
    assert!(summary.hypotheses.is_empty());
}

#[test]
fn a_technology_banner_is_listed_and_never_filed() {
    let fixture = fixture();
    fixture.capture(
        "api.example.com",
        true,
        "/a",
        &[],
        200,
        &[
            ("Content-Type", "application/json"),
            ("Strict-Transport-Security", "max-age=1"),
            ("Server", "nginx/1.24.0"),
        ],
    );

    let summary = fixture.scan(Selection::default());
    assert_eq!(summary.observations.len(), 1);
    assert!(summary.observations[0]
        .observation
        .about
        .contains("nginx/1.24.0"));
    assert!(
        summary.findings().is_empty(),
        "a banner must not reach the findings list"
    );
}

#[test]
fn a_reflected_origin_becomes_a_hypothesis_and_not_a_finding() {
    let fixture = fixture();
    fixture.capture(
        "api.example.com",
        true,
        "/a",
        &[("Origin", "https://evil.example")],
        200,
        &[
            ("Content-Type", "application/json"),
            ("Strict-Transport-Security", "max-age=1"),
            ("Access-Control-Allow-Origin", "https://evil.example"),
            ("Access-Control-Allow-Credentials", "true"),
            ("Vary", "Origin"),
        ],
    );

    let summary = fixture.scan(Selection::default());
    assert_eq!(summary.hypotheses.len(), 1, "{:#?}", summary.hypotheses);
    assert_eq!(summary.hypotheses[0].detector, "cors.configuration");
    assert!(
        summary.findings().is_empty(),
        "nothing verified it, so nothing may claim it: {:#?}",
        summary.findings()
    );
}

#[test]
fn two_endpoints_on_one_host_each_get_their_own_suspicion() {
    // A regression, and the bug that building the active scheduler exposed. These
    // used to collapse to one hypothesis per host, so an active run tested whichever
    // endpoint came first and the other was never probed — against a real application
    // with a reflecting endpoint and a correctly allowlisted one, that means the bug
    // is the half that goes untested.
    let fixture = fixture();
    for path in ["/reflect", "/allowed"] {
        fixture.capture(
            "api.example.com",
            true,
            path,
            &[("Origin", "https://app.example.com")],
            200,
            &[
                ("Content-Type", "application/json"),
                ("Strict-Transport-Security", "max-age=1"),
                ("Access-Control-Allow-Origin", "https://app.example.com"),
                ("Access-Control-Allow-Credentials", "true"),
                ("Vary", "Origin"),
            ],
        );
    }

    let summary = fixture.scan(Selection::default());
    assert_eq!(
        summary.hypotheses.len(),
        2,
        "one per endpoint, so an active run can test both: {:#?}",
        summary.hypotheses
    );
}

#[test]
fn the_same_endpoint_seen_many_times_is_still_one_suspicion() {
    // The other half. Deduplication per endpoint must not become no deduplication:
    // a page loaded forty times is one thing to test, not forty.
    let fixture = fixture();
    for _ in 0..40 {
        fixture.capture(
            "api.example.com",
            true,
            "/reflect",
            &[("Origin", "https://app.example.com")],
            200,
            &[
                ("Content-Type", "application/json"),
                ("Strict-Transport-Security", "max-age=1"),
                ("Access-Control-Allow-Origin", "https://app.example.com"),
                ("Access-Control-Allow-Credentials", "true"),
                ("Vary", "Origin"),
            ],
        );
    }

    let summary = fixture.scan(Selection::default());
    assert_eq!(summary.hypotheses.len(), 1, "{:#?}", summary.hypotheses);
}

#[test]
fn every_finding_is_a_lead_and_never_more() {
    // The ceiling a passive check cannot exceed. Checked over a response that
    // triggers several detectors at once.
    let fixture = fixture();
    fixture.capture(
        "api.example.com",
        true,
        "/page",
        &[("Cookie", "sessionid=secret")],
        200,
        &[
            ("Content-Type", "text/html"),
            ("Set-Cookie", "sessionid=abc"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
        ],
    );

    let summary = fixture.scan(Selection::default());
    assert!(!summary.findings().is_empty());
    for finding in summary.findings() {
        assert_eq!(
            finding.finding().confidence,
            hexora_types::Confidence::Reported,
            "{}",
            finding.finding().title
        );
        assert!(
            !finding.finding().confidence.is_actionable(),
            "a passive result must reach a report as a lead"
        );
    }
}

#[test]
fn every_finding_cites_an_exchange_the_project_can_resolve() {
    let fixture = fixture();
    fixture.capture("api.example.com", true, "/a", &[], 200, &[]);

    let summary = fixture.scan(Selection::default());
    assert!(!summary.findings().is_empty());

    for finding in summary.findings() {
        assert!(
            !finding.finding().evidence.is_empty(),
            "a result with no evidence is not evidence of anything"
        );
        for evidence in &finding.finding().evidence {
            if let hexora_types::finding::Evidence::Exchange { request, .. } = evidence {
                fixture
                    .traffic
                    .request(*request)
                    .expect("the cited exchange has to be in the project");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

#[test]
fn no_credential_reaches_an_observation_a_finding_or_a_run_record() {
    // The regression test this milestone most needs. Passive scanning reads
    // authenticated traffic by definition, so every value below is one that must
    // never come back out.
    const SECRETS: &[&str] = &[
        "Bearer super-secret-token",
        "sessionid=do-not-leak-me",
        "api-key-abcdef123456",
    ];

    let fixture = fixture();
    fixture.capture(
        "api.example.com",
        true,
        "/account?ok=1",
        &[
            ("Authorization", SECRETS[0]),
            ("Cookie", SECRETS[1]),
            ("X-Api-Key", SECRETS[2]),
        ],
        200,
        &[
            ("Content-Type", "text/html"),
            ("Set-Cookie", "sessionid=do-not-leak-me; Path=/"),
            ("Server", "nginx/1.24.0"),
        ],
    );

    let summary = fixture.scan(Selection::default());
    assert!(!summary.observations.is_empty());

    // Everything the scanner produced, in every form it can be rendered in.
    let mut rendered = format!("{:?}{:?}", summary.observations, summary.hypotheses);
    for finding in summary.findings() {
        rendered.push_str(&format!("{:?}", finding.finding()));
        rendered.push_str(&serde_json::to_string(finding.finding()).unwrap());
    }
    rendered.push_str(&format!("{:?}", summary.run));

    for secret in SECRETS {
        assert!(
            !rendered.contains(secret),
            "{secret:?} escaped into scanner output"
        );
    }
    // The cookie's *name* is expected and useful; its value is not.
    assert!(
        rendered.contains("sessionid"),
        "the name is what gets reported"
    );
    assert!(!rendered.contains("do-not-leak-me"));
}

// ---------------------------------------------------------------------------
// The run record
// ---------------------------------------------------------------------------

#[test]
fn a_run_records_every_detector_including_the_silent_ones() {
    // The row that turns "found nothing" into a fact. Without it a retest cannot
    // tell a clean application from a check nobody ran.
    let fixture = fixture();
    fixture.capture("api.example.com", true, "/a", &[], 200, &[]);

    let summary = fixture.scan(Selection::default());
    let run = summary.run.as_ref().unwrap();

    assert_eq!(run.detectors.len(), hexora_scan::checks::all().len());
    let tls = run
        .detectors
        .iter()
        .find(|detector| detector.detector == "tls.observations")
        .unwrap();
    assert_eq!(
        tls.observations, 0,
        "no handshake was recorded for this exchange"
    );
    assert_eq!(tls.version, "1.0.0");

    // And it is readable back out of the project afterwards.
    let stored = fixture.project.scans().get(run.id).unwrap();
    assert_eq!(stored.exchanges_read, 1);
    assert_eq!(stored.status, hexora_storage::RunStatus::Completed);
}

#[test]
fn a_second_identical_run_does_not_pile_up_findings() {
    // `FindingStore::record` keys on the claim, so re-running refreshes rather than
    // duplicating — but only if the scanner's titles are stable across runs, which
    // is what this actually checks.
    let fixture = fixture();
    fixture.capture("api.example.com", true, "/a", &[], 200, &[]);

    let first = fixture.scan(Selection::default());
    for finding in first.findings() {
        fixture.project.findings().record(finding).unwrap();
    }
    let after_first = fixture.project.findings().count().unwrap();

    let second = fixture.scan(Selection::default());
    for finding in second.findings() {
        fixture.project.findings().record(finding).unwrap();
    }

    assert_eq!(
        fixture.project.findings().count().unwrap(),
        after_first,
        "the same claim twice is one row"
    );
    assert_eq!(
        fixture.project.scans().count().unwrap(),
        2,
        "two runs, though"
    );
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

#[test]
fn a_detector_filter_runs_only_that_detector() {
    let fixture = fixture();
    fixture.capture(
        "api.example.com",
        true,
        "/a",
        &[],
        200,
        &[("Server", "nginx")],
    );

    let summary = fixture.scan(Selection {
        detector: Some("disclosure.headers".into()),
        ..Selection::default()
    });

    assert_eq!(summary.detectors.len(), 1);
    assert_eq!(summary.detectors[0].detector, "disclosure.headers");
    assert!(summary
        .observations
        .iter()
        .all(|group| group.observation.detector == "disclosure.headers"));
}

#[test]
fn a_host_filter_narrows_what_is_read() {
    let fixture = fixture();
    fixture
        .project
        .settings()
        .set_scope(
            &Scope::new()
                .include(ScopeRule::host("api.example.com"))
                .include(ScopeRule::host("cdn.example.com")),
        )
        .unwrap();
    fixture.capture("api.example.com", true, "/a", &[], 200, &[]);
    fixture.capture("cdn.example.com", true, "/b", &[], 200, &[]);

    let summary = fixture.scan(Selection {
        host: Some("cdn.example.com".into()),
        ..Selection::default()
    });
    assert_eq!(summary.exchanges_read, 1);
    assert!(summary
        .observations
        .iter()
        .all(|group| group.host == "cdn.example.com"));
}

#[test]
fn a_limit_stops_the_pass_and_says_so() {
    let fixture = fixture();
    for index in 0..10 {
        fixture.capture("api.example.com", true, &format!("/{index}"), &[], 200, &[]);
    }

    let summary = fixture.scan(Selection {
        limit: Some(4),
        ..Selection::default()
    });
    assert_eq!(summary.exchanges_read, 4);
    assert_eq!(summary.exchanges_skipped, 6, "a truncated pass is visible");
}

#[test]
fn an_empty_project_is_a_run_that_read_nothing_rather_than_an_error() {
    let fixture = fixture();
    let summary = fixture.scan(Selection::default());

    assert_eq!(summary.exchanges_read, 0);
    assert!(summary.observations.is_empty());
    // The detectors are still recorded as having run over nothing, which is exactly
    // the distinction the run record exists for.
    assert_eq!(summary.detectors.len(), hexora_scan::checks::all().len());
}

// ---------------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------------

#[test]
fn malformed_and_hostile_traffic_does_not_stop_the_pass() {
    // Scanner input comes from applications that are, at best, indifferent to
    // whether Hexora can read them.
    let fixture = fixture();

    fixture.capture("api.example.com", true, "/empty", &[], 204, &[]);
    fixture.capture(
        "api.example.com",
        true,
        "/redirect",
        &[],
        302,
        &[("Location", "/elsewhere")],
    );
    fixture.capture("api.example.com", true, "/not-modified", &[], 304, &[]);
    fixture.capture(
        "api.example.com",
        true,
        "/duplicates",
        &[],
        200,
        &[
            ("Set-Cookie", "a=1"),
            ("Set-Cookie", ""),
            ("Set-Cookie", ";;;"),
            ("Cache-Control", "max-age=abc"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Origin", "https://other.example"),
        ],
    );
    fixture.capture(
        "api.example.com",
        true,
        "/enormous",
        &[],
        200,
        &[("X-Long", &"a".repeat(16_384))],
    );

    let summary = fixture.scan(Selection::default());
    assert_eq!(summary.exchanges_read, 5, "every one of them was read");
    assert!(summary.run.is_some());
}

#[test]
fn a_non_utf8_header_value_is_read_without_panicking() {
    let fixture = fixture();
    let service = HttpService::new("api.example.com", 443, true);
    let request = HttpRequest::get(service, "/binary");

    let mut headers = Headers::new();
    headers.append(Header {
        name: "Server".into(),
        value: Bytes::from_static(&[0xff, 0xfe, b'n', b'g', b'i', b'n', b'x']),
    });

    fixture
        .traffic
        .record(&CapturedExchange {
            request,
            raw_request: None,
            response: HttpResponse {
                status: 200,
                reason: None,
                version: HttpVersion::Http11,
                headers,
                body: Bytes::from_static(&[0x00, 0xff, 0xfe]),
                truncated: false,
            },
            encoded_body: None,
            content_encoding: None,
            origin: "proxy",
            identity: None,
            parent: None,
            quirks: Vec::new(),
            tls: None,
            duration_ms: 1,
        })
        .unwrap();

    let summary = fixture.scan(Selection::default());
    assert_eq!(summary.exchanges_read, 1);
    // The banner is still reported; the undecodable bytes became replacement
    // characters rather than an error or a panic.
    assert!(summary
        .observations
        .iter()
        .any(|group| group.observation.about.contains("Technology disclosure")));
}

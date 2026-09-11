//! Adopting a fresh session from traffic a person generated — and refusing to adopt
//! one from traffic Hexora generated itself.

use std::sync::Arc;

use hexora_authz::session::find_renewal;
use hexora_storage::{CapturedExchange, MemoryBlobStore, Project, TrafficStore};
use hexora_types::http::{Header, Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};
use hexora_types::identity::{Credential, Identity, PrivilegeLevel};
use hexora_types::scope::{Scope, ScopeRule};

fn store(project: &Project) -> Arc<TrafficStore> {
    Arc::new(TrafficStore::new(
        project.metadata().clone(),
        Arc::new(MemoryBlobStore::new()),
    ))
}

fn scope() -> Scope {
    Scope::new().include(ScopeRule::host("api.example.com"))
}

fn identity(cookie: &str) -> Identity {
    Identity {
        id: hexora_types::ids::IdentityId::new(),
        label: "Me".into(),
        privilege: PrivilegeLevel::User,
        credential: Credential::Cookie {
            value: cookie.to_string().into(),
        },
        extra_headers: Vec::new(),
        owned_object_ids: Vec::new(),
    }
}

/// Records one exchange carrying a `Cookie`, attributed to `origin`.
fn capture(traffic: &TrafficStore, host: &str, origin: &'static str, cookie: &str) {
    let mut request = HttpRequest::get(HttpService::new(host, 443, true), "/me");
    request.headers.set("Cookie", cookie.to_string());

    traffic
        .record(&CapturedExchange {
            request,
            raw_request: None,
            response: HttpResponse {
                status: 200,
                reason: Some("OK".into()),
                version: HttpVersion::Http11,
                headers: Headers::new(),
                body: bytes::Bytes::from_static(b"{}"),
                truncated: false,
            },
            encoded_body: None,
            content_encoding: None,
            origin,
            identity: None,
            parent: None,
            quirks: Vec::new(),
            tls: None,
            duration_ms: 10,
        })
        .unwrap();
}

#[test]
fn a_newer_session_from_the_proxy_is_offered() {
    let project = Project::in_memory().unwrap();
    let traffic = store(&project);
    capture(&traffic, "api.example.com", "proxy", "session=FRESH");

    let found = find_renewal(&traffic, &scope(), &identity("session=STALE"), 100, None)
        .unwrap()
        .expect("the proxy saw a newer session");

    assert_eq!(found.host, "api.example.com");
    assert_eq!(found.slot, "cookie");
    assert_eq!(found.length, "session=FRESH".len());
}

#[test]
fn a_credential_hexora_broke_on_purpose_is_never_adopted() {
    // The one that would be a disaster. `auth.enforcement` sends the captured request
    // with the JWT signature altered by one character, to see whether the application
    // checks it. That request is in the project's history like any other. Adopting it
    // would replace a working session with a deliberately invalid one, and every later
    // result would be wrong in a way that reads like a finding.
    let project = Project::in_memory().unwrap();
    let traffic = store(&project);

    // Newest last: these are the checks' own replays, recorded after the real session.
    capture(&traffic, "api.example.com", "proxy", "session=REAL");
    capture(&traffic, "api.example.com", "scanner", "session=TAMPERED");
    capture(
        &traffic,
        "api.example.com",
        "authz",
        "session=ANOTHER_IDENTITY",
    );
    capture(
        &traffic,
        "api.example.com",
        "repeater",
        "session=HAND_EDITED",
    );

    let found = find_renewal(&traffic, &scope(), &identity("session=STALE"), 100, None)
        .unwrap()
        .expect("the proxy's session is still there to find");

    assert_eq!(
        found.length,
        "session=REAL".len(),
        "adopted something Hexora sent rather than what the browser sent"
    );
}

#[test]
fn a_session_for_a_host_nobody_declared_is_not_adopted() {
    // A tester's browser goes everywhere. A cookie from their webmail is not this
    // engagement's session, and storing it would send it to the target.
    let project = Project::in_memory().unwrap();
    let traffic = store(&project);
    capture(
        &traffic,
        "mail.example.net",
        "proxy",
        "session=SOMEBODY_ELSES",
    );

    assert!(
        find_renewal(&traffic, &scope(), &identity("session=STALE"), 100, None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn an_unchanged_session_is_not_offered_as_a_renewal() {
    // Nothing to do is a result. A needless write would touch the row and tell the
    // tester something changed when nothing did.
    let project = Project::in_memory().unwrap();
    let traffic = store(&project);
    capture(&traffic, "api.example.com", "proxy", "session=SAME");

    assert!(
        find_renewal(&traffic, &scope(), &identity("session=SAME"), 100, None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn an_anonymous_identity_has_no_session_to_renew() {
    let project = Project::in_memory().unwrap();
    let traffic = store(&project);
    capture(&traffic, "api.example.com", "proxy", "session=FRESH");

    assert!(
        find_renewal(&traffic, &scope(), &Identity::anonymous(), 100, None)
            .unwrap()
            .is_none(),
        "the anonymous principal is anonymous on purpose"
    );
}

#[test]
fn the_newest_proxy_session_wins() {
    let project = Project::in_memory().unwrap();
    let traffic = store(&project);
    capture(&traffic, "api.example.com", "proxy", "session=OLDER");
    capture(&traffic, "api.example.com", "proxy", "session=NEWEST_ONE");

    let found = find_renewal(&traffic, &scope(), &identity("session=STALE"), 100, None)
        .unwrap()
        .unwrap();
    assert_eq!(found.length, "session=NEWEST_ONE".len());
}

#[test]
fn the_adopted_credential_keeps_the_identitys_shape() {
    let project = Project::in_memory().unwrap();
    let traffic = store(&project);

    let mut request = HttpRequest::get(HttpService::new("api.example.com", 443, true), "/me");
    request
        .headers
        .set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.fresh");
    request.headers.append(Header::new("Accept", "*/*"));
    traffic
        .record(&CapturedExchange {
            request,
            raw_request: None,
            response: HttpResponse {
                status: 200,
                reason: Some("OK".into()),
                version: HttpVersion::Http11,
                headers: Headers::new(),
                body: bytes::Bytes::from_static(b"{}"),
                truncated: false,
            },
            encoded_body: None,
            content_encoding: None,
            origin: "proxy",
            identity: None,
            parent: None,
            quirks: Vec::new(),
            tls: None,
            duration_ms: 10,
        })
        .unwrap();

    let bearer = Identity {
        credential: Credential::Bearer {
            token: "stale".to_string().into(),
        },
        ..identity("unused")
    };

    let found = find_renewal(&traffic, &scope(), &bearer, 100, None)
        .unwrap()
        .unwrap();
    assert_eq!(found.slot, "authorization");

    match found.credential(&bearer.credential) {
        // Stored without the scheme, because `Credential::apply` writes it back on.
        Credential::Bearer { token } => assert_eq!(token.expose(), "eyJhbGciOiJIUzI1NiJ9.fresh"),
        other => panic!("{other:?}"),
    }
}

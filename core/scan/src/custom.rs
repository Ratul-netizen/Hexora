//! User-defined passive checks (M15.5).
//!
//! A [`nullhawk_types::custom::CustomCheck`] is a saved query plus a finding template. This turns
//! one into a [`PassiveCheck`] the scanner runs alongside the built-ins: it builds a query
//! [`Record`](nullhawk_query::Record) from the exchange the scanner already assembled, runs the
//! compiled query, and on a match emits one observation carrying the check's name, severity and
//! message.
//!
//! # Only metadata and headers
//!
//! The passive scanner assembles an exchange without its bodies (see the module docs on
//! [`crate::Exchange`]), so a custom check matches on metadata and headers. [`validate`] refuses
//! a query that reaches for a body when the check is added, so a check never silently fails to
//! match.
//!
//! # Only ever a lead
//!
//! The check implements `observe` and leaves `suspect` at its default, so it never raises a
//! hypothesis. The scanner concludes its observations as leads capped at `Confidence::Reported`.
//! A user cannot write a check that overclaims.

use std::collections::HashSet;
use std::sync::Mutex;

use nullhawk_query::{Field, Query};
use nullhawk_types::custom::CustomCheck as CustomDef;

use crate::checks::prelude::*;

/// Compiles the enabled custom checks into passive checks, skipping any whose query does not
/// compile or reaches for a body (both are refused at add time, so this is belt-and-braces).
pub fn load(defs: &[CustomDef]) -> Vec<Box<dyn PassiveCheck>> {
    let mut out: Vec<Box<dyn PassiveCheck>> = Vec::new();
    for def in defs {
        if !def.enabled {
            continue;
        }
        if let Ok(check) = compile(def) {
            out.push(Box::new(check));
        }
    }
    out
}

/// Checks that a definition is usable: its query compiles and touches no body field.
///
/// Returned as a `String` because it is shown to whoever is adding the check.
pub fn validate(def: &CustomDef) -> Result<(), String> {
    let query = Query::parse(&def.query).map_err(|e| e.message)?;
    reject_bodies(&query)
}

fn reject_bodies(query: &Query) -> Result<(), String> {
    if query.references(Field::ResponseBody)
        || query.references(Field::RequestBody)
        || query.references(Field::RequestSize)
    {
        return Err(
            "a custom check matches on request/response metadata and headers, not bodies; \
             remove req.body, resp.body and req.size from the query"
                .to_string(),
        );
    }
    Ok(())
}

fn compile(def: &CustomDef) -> Result<CustomCheck, String> {
    let query = Query::parse(&def.query).map_err(|e| e.message)?;
    reject_bodies(&query)?;
    Ok(CustomCheck {
        info: DetectorInfo {
            id: DetectorId(intern(&def.id)),
            name: intern(&def.name),
            version: "1.0.0",
            about: intern(&def.message),
            mode: DetectorMode::Passive,
            observes: true,
            hypothesizes: false,
            settles: None,
            intrusiveness: nullhawk_types::verify::Intrusiveness::Silent,
        },
        query,
        name: def.name.clone(),
        message: def.message.clone(),
        severity: def.severity,
        source_query: def.query.clone(),
    })
}

/// A compiled custom check.
pub struct CustomCheck {
    info: DetectorInfo,
    query: Query,
    name: String,
    message: String,
    severity: Severity,
    source_query: String,
}

impl CustomCheck {
    /// Builds a query record from the exchange the scanner assembled (metadata + headers).
    fn record(exchange: &Exchange) -> nullhawk_query::Record {
        nullhawk_query::Record {
            method: exchange.method.clone(),
            host: exchange.host.clone(),
            path: exchange.path.clone(),
            url: exchange.url.clone(),
            scheme: if exchange.secure {
                "https".into()
            } else {
                "http".into()
            },
            port: exchange.port,
            status: (exchange.status != 0).then_some(exchange.status),
            duration_ms: None,
            identity: None,
            secure: exchange.secure,
            response_size: exchange.response_bytes,
            origin: Some(exchange.origin.clone()),
            request_size: None,
            request_headers: Some(header_lines(&exchange.request_headers)),
            response_headers: Some(header_lines(&exchange.response_headers)),
            request_body: None,
            response_body: None,
        }
    }
}

impl PassiveCheck for CustomCheck {
    fn about(&self) -> DetectorInfo {
        self.info
    }

    fn observe(&self, exchange: &Exchange) -> Vec<Observation> {
        let record = Self::record(exchange);
        if !self.query.matches(&record) {
            return Vec::new();
        }
        vec![observation(
            &self.info,
            exchange,
            format!("{} on {}", self.name, exchange.host),
            "no exchange matches this custom check",
            self.message.clone(),
            format!("matched the custom check's query: {}", self.source_query),
            self.severity,
            Significance::Reportable,
            None,
        )]
    }

    fn writeup(&self, observation: &Observation, exchange: &Exchange, target: TargetId) -> Writeup {
        Writeup {
            target,
            title: self.name.clone(),
            description: self.message.clone(),
            impact: "As judged by whoever wrote this custom check.".into(),
            remediation: "See the check's guidance.".into(),
            reproduction: format!(
                "Request {} {} and evaluate: {}",
                exchange.method, exchange.url, self.source_query
            ),
            cwe: None,
            owasp: None,
            source: source(&self.info),
            severity: self.severity,
            location: observation.location.clone(),
        }
    }
}

/// Header lines `Name: value`, for the query evaluator. Values are the redacted ones the
/// scanner already put on the exchange, so a custom check cannot read a credential back out.
fn header_lines(headers: &nullhawk_types::http::Headers) -> Vec<String> {
    headers
        .iter()
        .map(|h| format!("{}: {}", h.name, h.value_lossy()))
        .collect()
}

/// Leaks a string once and reuses it thereafter, so runtime-loaded checks can satisfy the
/// `&'static str` a [`DetectorInfo`] requires without leaking on every scan. Bounded to the
/// set of distinct id/name/message strings a session ever sees.
///
/// Shared with [`crate::extension`], which faces the same `&'static str` requirement for
/// extension-backed checks loaded at runtime.
pub(crate) fn intern(value: &str) -> &'static str {
    static POOL: Mutex<Option<HashSet<&'static str>>> = Mutex::new(None);
    let mut guard = POOL.lock().unwrap();
    let pool = guard.get_or_insert_with(HashSet::new);
    if let Some(existing) = pool.get(value) {
        return existing;
    }
    let leaked: &'static str = Box::leak(value.to_string().into_boxed_str());
    pool.insert(leaked);
    leaked
}

#[cfg(test)]
mod tests {
    use crate::checks::test_support::*;

    use super::*;

    fn def(query: &str) -> CustomDef {
        CustomDef::new(
            "custom.test",
            "Test check",
            Severity::Medium,
            query,
            "matched",
        )
    }

    #[test]
    fn a_matching_query_emits_one_reportable_observation() {
        let check = compile(&def("resp.header:x-debug")).unwrap();
        let exchange = exchange(https().response(200, &[("X-Debug", "1")]));
        let found = check.observe(&exchange);
        assert_eq!(found.len(), 1);
        assert!(found[0].is_reportable());
        assert_eq!(found[0].severity, Severity::Medium);
    }

    #[test]
    fn a_non_matching_query_says_nothing() {
        let check = compile(&def("resp.header:x-debug")).unwrap();
        let exchange = exchange(https().response(200, &[("Content-Type", "text/html")]));
        assert!(check.observe(&exchange).is_empty());
    }

    #[test]
    fn a_status_query_matches_on_metadata() {
        let check = compile(&def("status>=500")).unwrap();
        assert_eq!(
            check.observe(&exchange(https().response(503, &[]))).len(),
            1
        );
        assert!(check
            .observe(&exchange(https().response(200, &[])))
            .is_empty());
    }

    #[test]
    fn a_body_query_is_refused() {
        assert!(validate(&def("resp.body:secret")).is_err());
        assert!(validate(&def("req.size>100")).is_err());
    }

    #[test]
    fn an_invalid_query_is_refused() {
        assert!(validate(&def("bogus=1")).is_err());
    }

    #[test]
    fn a_valid_metadata_query_passes_validation() {
        assert!(validate(&def("status=200 AND resp.header:content-type")).is_ok());
    }

    #[test]
    fn interning_reuses_the_same_pointer() {
        let a = intern("custom.same");
        let b = intern("custom.same");
        assert!(
            std::ptr::eq(a, b),
            "the same string must intern to one leak"
        );
    }
}

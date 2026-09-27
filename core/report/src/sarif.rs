//! SARIF 2.1.0 rendering — the report as a machine result, for a pipeline.
//!
//! The other three renderers address a human: a ticket, a client, a reader. This one
//! addresses a CI system. [SARIF](https://sarifweb.azurewebsites.net/) is the format
//! GitHub code scanning and GitLab ingest natively, so a `hexora report --format sarif`
//! uploaded from a pipeline puts every established finding into the platform's own
//! security tab, next to the code, with no bespoke integration.
//!
//! ## Why this is more than a fourth encoding
//!
//! Two properties of the finding store make Hexora's SARIF worth more than a scanner
//! that emits the same schema:
//!
//! **The results carry a stable identity.** A finding keeps its id across runs — a
//! re-test updates the row rather than writing a new one (see the findings store,
//! M12.2). That id becomes the SARIF `partialFingerprints` entry, which is exactly what
//! a platform uses to tell an *existing* finding from a *new* one. So the "fail the
//! build only on new findings" gate that a consultancy actually wants falls out of the
//! data model rather than being reconstructed by fuzzy line-matching.
//!
//! **A lead is never dressed as a result that fails a build.** Established findings are
//! emitted at their severity's level (`error`/`warning`/`note`); unverified leads are
//! emitted at `note` and tagged `unverified`, so they appear in the security tab for a
//! human to weigh but never turn a pipeline red. This is the same rule the Markdown and
//! HTML reports keep — leads are counted, not hidden, and never mixed in — carried into
//! the one format where the distinction has teeth.
//!
//! Credentials do not travel: the results carry titles, locations and metadata, not the
//! quoted traffic. The full transcript stays in the human-facing formats under their
//! redaction policy.

use serde_json::{json, Map, Value};

use hexora_types::finding::{Finding, FindingSource, Severity};

use crate::{Citation, CitedEvidence, Report, ReportedFinding};

/// The SARIF specification version this renderer targets.
const SARIF_VERSION: &str = "2.1.0";
/// The published schema for editors and validators that follow `$schema`.
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// Renders a [`Report`] as a SARIF 2.1.0 log.
///
/// Deterministic for a given report: the tool version comes from the crate, and every
/// other value is read from the report, so rendering the same project twice produces the
/// same bytes — which is what lets a pipeline diff one run against the last.
pub fn render(report: &Report) -> String {
    // Rules are collected in first-seen order so the output is stable, and each result
    // refers to its rule by index as SARIF prefers.
    let mut rules: Vec<Value> = Vec::new();
    let mut rule_index: Vec<String> = Vec::new();

    let mut results: Vec<Value> = Vec::new();

    for reported in &report.findings {
        results.push(result_for(
            reported,
            /* unverified = */ false,
            &mut rules,
            &mut rule_index,
        ));
    }
    // Leads reach the security tab so a reviewer can see them, but always at `note`
    // level and flagged, so they are never the reason a build fails.
    for reported in &report.leads {
        results.push(result_for(
            reported,
            /* unverified = */ true,
            &mut rules,
            &mut rule_index,
        ));
    }

    let driver = json!({
        "name": "Hexora",
        "informationUri": "https://github.com/Ratul-netizen/Hexora",
        "version": env!("CARGO_PKG_VERSION"),
        "rules": rules,
    });

    let run = json!({
        "tool": { "driver": driver },
        "automationDetails": { "id": report.engagement.title },
        "invocations": [ { "executionSuccessful": true } ],
        "results": results,
    });

    let log = json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [ run ],
    });

    serde_json::to_string_pretty(&log).unwrap_or_else(|e| format!("{{\"error\":{e:?}}}"))
}

/// Builds one SARIF `result`, registering its rule if this is the first time the rule is
/// seen. Returns the result object; the rule is pushed into `rules` as a side effect.
fn result_for(
    reported: &ReportedFinding,
    unverified: bool,
    rules: &mut Vec<Value>,
    rule_index: &mut Vec<String>,
) -> Value {
    let finding = &reported.finding;
    let rule_id = rule_id(&finding.source);

    let index = match rule_index.iter().position(|id| id == &rule_id) {
        Some(i) => i,
        None => {
            rules.push(rule_for(&rule_id, finding));
            rule_index.push(rule_id.clone());
            rules.len() - 1
        }
    };

    // A lead never fails a build, whatever its provisional severity.
    let level = if unverified {
        "note"
    } else {
        sarif_level(finding.severity)
    };

    let mut properties = Map::new();
    properties.insert(
        "severity".into(),
        json!(crate::severity_word(finding.severity)),
    );
    properties.insert(
        "confidence".into(),
        json!(crate::confidence_word(finding.confidence)),
    );
    properties.insert("status".into(), json!(crate::status_word(finding.status)));
    properties.insert("raisedBy".into(), json!(crate::raised_by(&finding.source)));
    properties.insert("unverified".into(), json!(unverified));
    // GitHub orders and colours findings by this numeric string. Derived from the
    // severity we already assigned rather than parsed out of a CVSS vector, so a finding
    // without a vector still sorts correctly.
    properties.insert(
        "security-severity".into(),
        json!(security_severity(finding.severity)),
    );
    if let Some(cwe) = &finding.cwe {
        properties.insert("cwe".into(), json!(cwe));
    }
    if let Some(owasp) = &finding.owasp {
        properties.insert("owasp".into(), json!(owasp));
    }
    if let Some(cvss) = &finding.cvss {
        properties.insert("cvss".into(), json!(cvss));
    }

    let mut result = Map::new();
    result.insert("ruleId".into(), json!(rule_id));
    result.insert("ruleIndex".into(), json!(index));
    result.insert("level".into(), json!(level));
    result.insert("message".into(), json!({ "text": message_text(finding) }));
    result.insert("locations".into(), json!(locations_for(reported)));
    // The finding's own id is the fingerprint: it is stable across runs by construction,
    // so a platform correlates this result with the same finding in the previous run and
    // a "new findings only" gate works without guessing.
    result.insert(
        "partialFingerprints".into(),
        json!({ "hexoraFindingId/v1": finding.id.to_string() }),
    );
    result.insert("properties".into(), Value::Object(properties));

    Value::Object(result)
}

/// Builds a SARIF `reportingDescriptor` (a rule) from a representative finding.
///
/// Several findings can share a rule — every missing-security-header finding comes from
/// one detector — so the rule carries the general description and each result carries the
/// specifics. The first finding seen for a rule supplies its prose, which is stable
/// because findings are rendered in a fixed order.
fn rule_for(rule_id: &str, finding: &Finding) -> Value {
    let mut properties = Map::new();
    properties.insert(
        "security-severity".into(),
        json!(security_severity(finding.severity)),
    );
    let mut tags = vec![json!("security")];
    if let Some(cwe) = &finding.cwe {
        // The `external/cwe/cwe-639` form is the tag GitHub links to a CWE page.
        if let Some(number) = cwe
            .strip_prefix("CWE-")
            .or_else(|| cwe.strip_prefix("cwe-"))
        {
            tags.push(json!(format!("external/cwe/cwe-{number}")));
        }
        properties.insert("cwe".into(), json!(cwe));
    }
    if let Some(owasp) = &finding.owasp {
        tags.push(json!("owasp"));
        properties.insert("owasp".into(), json!(owasp));
    }
    properties.insert("tags".into(), json!(tags));

    let mut descriptor = Map::new();
    descriptor.insert("id".into(), json!(rule_id));
    descriptor.insert("name".into(), json!(rule_name(rule_id)));
    descriptor.insert("shortDescription".into(), json!({ "text": finding.title }));
    // The remediation belongs on the rule, not the result: it is advice about the class
    // of problem, and SARIF renders `help` where a reader looks for "how do I fix this".
    if !finding.remediation.trim().is_empty() {
        descriptor.insert("help".into(), json!({ "text": finding.remediation }));
    }
    descriptor.insert(
        "defaultConfiguration".into(),
        json!({ "level": sarif_level(finding.severity) }),
    );
    if let Some(cwe) = &finding.cwe {
        if let Some(number) = cwe
            .strip_prefix("CWE-")
            .or_else(|| cwe.strip_prefix("cwe-"))
        {
            descriptor.insert(
                "helpUri".into(),
                json!(format!(
                    "https://cwe.mitre.org/data/definitions/{number}.html"
                )),
            );
        }
    }
    descriptor.insert("properties".into(), Value::Object(properties));

    Value::Object(descriptor)
}

/// The stable machine identifier for the rule a finding belongs to.
///
/// A detector's own id is used where there is one, so the SARIF rule id matches the
/// string `hexora detectors` prints and a retest can tell a fixed application from a
/// changed check. The subsystems that are not a named detector get a fixed id each.
fn rule_id(source: &FindingSource) -> String {
    match source {
        FindingSource::PassiveScan { detector, .. }
        | FindingSource::ActiveScan { detector, .. } => detector.clone(),
        FindingSource::AuthorizationTest => "authz".into(),
        FindingSource::Extension { extension } => format!("ext.{extension}"),
        FindingSource::Ai { .. } => "ai".into(),
        FindingSource::Manual => "manual".into(),
    }
}

/// A human-friendly rule name derived from the dotted id, e.g.
/// `active.sqli.error_based` → `Active Sqli Error Based`.
fn rule_name(rule_id: &str) -> String {
    let mut out = String::new();
    for (i, word) in rule_id
        .split(['.', '_'])
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        if i > 0 {
            out.push(' ');
        }
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    if out.is_empty() {
        rule_id.to_string()
    } else {
        out
    }
}

/// Maps a Hexora severity to the SARIF result level a pipeline acts on.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// The `security-severity` numeric string GitHub uses to order and colour findings.
fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

/// The one-line message a platform shows against the finding.
fn message_text(finding: &Finding) -> String {
    let first_line = finding
        .description
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    if first_line.is_empty() {
        finding.title.clone()
    } else {
        format!("{} — {}", finding.title, first_line)
    }
}

/// The SARIF `locations` array for a finding.
///
/// The URL of the exchange behind the finding is the location a reader wants; a
/// finding's declared parameter, when it has one, becomes a logical location so the
/// security tab can say *where* in the request the issue lives. A finding whose evidence
/// the project can no longer resolve gets no physical location rather than a fabricated
/// one — the same discipline the human reports keep for a missing citation.
fn locations_for(reported: &ReportedFinding) -> Vec<Value> {
    let mut physical: Option<Value> = None;
    if let Some(url) = primary_url(reported) {
        physical = Some(json!({ "artifactLocation": { "uri": url } }));
    }

    let logical = reported.finding.location.as_ref().map(|loc| {
        json!([ {
            "name": loc.name,
            "kind": format!("{:?}", loc.part).to_lowercase(),
        } ])
    });

    if physical.is_none() && logical.is_none() {
        return Vec::new();
    }

    let mut location = Map::new();
    if let Some(p) = physical {
        location.insert("physicalLocation".into(), p);
    }
    if let Some(l) = logical {
        location.insert("logicalLocations".into(), l);
    }
    vec![Value::Object(location)]
}

/// The URL of the exchange most representative of a finding: the request that
/// demonstrates it, or the variant of a comparison — the request whose result *is* the
/// finding. `None` when no cited exchange resolved.
fn primary_url(reported: &ReportedFinding) -> Option<String> {
    for evidence in &reported.evidence {
        let citation = match evidence {
            CitedEvidence::Exchange { exchange, .. } => Some(exchange),
            CitedEvidence::Comparison { variant, .. } => Some(variant),
            CitedEvidence::OutOfBand { request, .. } => Some(request),
            CitedEvidence::Timing { request, .. } => Some(request),
            CitedEvidence::Excerpt { .. } => None,
        };
        if let Some(Citation::Resolved(transcript)) = citation {
            return Some(transcript.url.clone());
        }
    }
    None
}

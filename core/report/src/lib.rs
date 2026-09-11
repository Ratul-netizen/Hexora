//! # hexora-report
//!
//! The document at the end of the engagement.
//!
//! Everything a report needs is already in the project: the claims, how firmly each
//! is established, and the exact exchanges behind them. This crate reads that back
//! and renders it — as Markdown for a repository or a ticket, as HTML for something a
//! client opens, or as JSON for whatever consumes it next.
//!
//! ## Four rules, and the reasons they exist
//!
//! **A report says what was tested, not only what was found.** A document listing
//! zero findings and nothing else reads as "the application is secure", which is a
//! claim no tool is entitled to make. Every report carries the scope it was held to,
//! the identities it tested as, and how many exchanges it looked at, so a reader can
//! see the shape of the hole as well as the shape of the work.
//!
//! **Leads are never mixed with established issues.** Anything below
//! [`Confidence::Firm`] goes in its own section, after the findings, labelled as
//! unverified. A tester who hands a client a Tentative similarity match presented as
//! a vulnerability spends the next meeting losing an argument, and the report loses
//! the ones that were real.
//!
//! **Every claim carries its exchange.** Evidence is resolved against the project's
//! traffic, so the report contains the request and the response, not an id that the
//! reader would have to go and look up. Where a cited exchange is no longer in the
//! project the report *says so* rather than printing a reference that resolves to
//! nothing — see [`Citation::Missing`].
//!
//! **Credentials do not travel.** Sensitive headers are redacted by default under
//! [`RedactionPolicy`], and the report states that it did so. A reader who cannot
//! tell whether a blank `Authorization` header means "redacted" or "not sent" cannot
//! reproduce anything.
//!
//! ## Excluded findings are counted, not hidden
//!
//! Findings triaged as false positives or duplicates stay out of the body — that is
//! what triage is for — but the count appears in the summary. A report that silently
//! dropped them would hide a human decision that a reviewer may want to question.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod html;
pub mod markdown;

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use hexora_storage::repository::{Cursor, Limit};
use hexora_storage::{FindingFilter, Project};
use hexora_types::error::Result;
use hexora_types::finding::{Confidence, Evidence, Finding, FindingStatus, Severity};
use hexora_types::identity::{Credential, PrivilegeLevel};
use hexora_types::ids::{IdentityId, RequestId, ResponseId};
use hexora_types::redact::{is_sensitive_header, RedactionPolicy, REDACTED};
use hexora_types::scope::{PathMatch, SchemeMatch, Scope};
use serde::Serialize;

/// Which output a report is rendered as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// Markdown, for a repository, a ticket or a pull request.
    #[default]
    Markdown,
    /// A self-contained HTML page, for handing to somebody who is not a developer.
    Html,
    /// The report model itself, for whatever consumes it next.
    Json,
}

impl Format {
    /// The file extension conventionally used for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Html => "html",
            Self::Json => "json",
        }
    }
}

/// How to build a report.
#[derive(Debug, Clone)]
pub struct ReportOptions {
    /// Document title. Defaults to the project name.
    pub title: Option<String>,
    /// Omit findings below this severity.
    pub min_severity: Option<Severity>,
    /// Leave the unverified leads out entirely rather than putting them in their own
    /// section.
    pub actionable_only: bool,
    /// How much of each body to quote, in bytes.
    pub body_excerpt_bytes: usize,
    /// How aggressively to redact rendered traffic.
    pub redaction: RedactionPolicy,
    /// When the report was produced. A parameter rather than a call to the clock, so
    /// a test — or a build that renders the same project twice — gets the same bytes.
    pub generated_at: DateTime<Utc>,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            title: None,
            min_severity: None,
            actionable_only: false,
            body_excerpt_bytes: 2048,
            redaction: RedactionPolicy::default(),
            generated_at: Utc::now(),
        }
    }
}

/// A finished report, ready to render.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// What was tested, and when.
    pub engagement: Engagement,
    /// What the engagement was authorized to touch.
    pub scope: ScopeSummary,
    /// The principals traffic was replayed as. Never their credentials.
    pub identities: Vec<IdentitySummary>,
    /// How much traffic the conclusions were drawn from.
    pub coverage: Coverage,
    /// Established issues, worst first.
    pub findings: Vec<ReportedFinding>,
    /// Candidates that have not been verified, kept apart from the findings.
    pub leads: Vec<ReportedFinding>,
    /// What was left out, and why.
    pub excluded: Excluded,
    /// Redaction applied to the traffic quoted below.
    pub redaction: RedactionPolicy,
    /// Anything the reader has to know to weigh the document, in the report itself
    /// rather than in a release note nobody reads.
    pub caveats: Vec<String>,
}

/// The engagement a report is about.
#[derive(Debug, Clone, Serialize)]
pub struct Engagement {
    /// Document title.
    pub title: String,
    /// The project's name, as recorded when it was created.
    pub project: String,
    /// When the project was created, RFC 3339.
    pub started_at: Option<String>,
    /// When this document was produced.
    pub generated_at: String,
    /// The version of Hexora that produced it.
    pub tool_version: String,
}

/// The scope the engagement was held to.
#[derive(Debug, Clone, Serialize)]
pub struct ScopeSummary {
    /// Hosts and paths declared as authorized.
    pub included: Vec<String>,
    /// Rules that override the inclusions.
    pub excluded: Vec<String>,
}

impl ScopeSummary {
    /// Whether no host was ever declared.
    pub fn is_empty(&self) -> bool {
        self.included.is_empty() && self.excluded.is_empty()
    }
}

/// One identity, as a report may describe it.
///
/// Built by hand rather than serialized from
/// [`Identity`](hexora_types::identity::Identity), which has no `Serialize` impl
/// precisely so that a credential cannot reach a document by accident.
#[derive(Debug, Clone, Serialize)]
pub struct IdentitySummary {
    /// Display name.
    pub label: String,
    /// How much authority it was expected to have.
    pub privilege: String,
    /// What kind of credential it carried — the kind, never the value.
    pub credential: String,
    /// Object identifiers declared as belonging to this identity.
    pub owns: Vec<String>,
}

/// How much traffic the report draws on.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Coverage {
    /// Distinct hosts seen.
    pub targets: u64,
    /// Exchanges recorded in the project.
    pub exchanges: u64,
    /// Findings recorded, before any filtering.
    pub findings_recorded: u64,
}

/// What the report left out, so the omission is visible.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Excluded {
    /// Findings a human marked as false positives.
    pub false_positives: u64,
    /// Findings a human marked as duplicates.
    pub duplicates: u64,
    /// Findings dropped by a severity filter on this render.
    pub below_severity: u64,
    /// Leads dropped because the render asked for established issues only.
    pub leads_omitted: u64,
}

impl Excluded {
    /// Whether anything at all was left out.
    pub fn is_empty(&self) -> bool {
        self.false_positives == 0
            && self.duplicates == 0
            && self.below_severity == 0
            && self.leads_omitted == 0
    }
}

/// A finding together with the traffic that supports it.
#[derive(Debug, Clone, Serialize)]
pub struct ReportedFinding {
    /// The finding as recorded in the project.
    pub finding: Finding,
    /// Its evidence, resolved against the project's traffic.
    pub evidence: Vec<CitedEvidence>,
}

/// One piece of evidence, with its exchanges resolved.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CitedEvidence {
    /// A single exchange that demonstrates the issue.
    Exchange {
        /// What the reader should notice.
        note: String,
        /// The exchange itself.
        exchange: Citation,
    },
    /// Two exchanges whose difference is the point.
    Comparison {
        /// The observable difference.
        difference: String,
        /// The control.
        baseline: Citation,
        /// The request whose result is the finding.
        variant: Citation,
    },
    /// A byte range within a response body.
    Excerpt {
        /// The response the excerpt came from.
        response: ResponseId,
        /// Byte offset into the recorded body.
        offset: usize,
        /// The excerpt, redaction already applied by whoever recorded it.
        excerpt: String,
    },
    /// An out-of-band interaction attributed to a request.
    OutOfBand {
        /// The protocol it arrived on.
        protocol: String,
        /// The interaction identifier.
        interaction: String,
        /// The request believed to have caused it.
        request: Citation,
    },
    /// A measured timing difference.
    Timing {
        /// The request that was timed.
        request: Citation,
        /// Control samples, milliseconds.
        baseline_ms: Vec<u64>,
        /// Variant samples, milliseconds.
        variant_ms: Vec<u64>,
    },
}

/// A reference to an exchange, resolved or explicitly not.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Citation {
    /// The exchange was read back from the project.
    Resolved(Box<Transcript>),
    /// The project no longer holds it.
    ///
    /// Printed as a stated gap rather than as a bare id, because a citation that
    /// silently resolves to nothing is worse than no citation: the reader believes
    /// the claim was checkable.
    Missing {
        /// The id that was cited.
        request: RequestId,
        /// Why it could not be read back.
        reason: String,
    },
}

impl Citation {
    /// The request id, however the citation turned out.
    pub fn request_id(&self) -> RequestId {
        match self {
            Self::Resolved(t) => t.request,
            Self::Missing { request, .. } => *request,
        }
    }

    /// Whether the exchange behind this citation is actually in the document.
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }
}

/// One exchange, rendered for a reader.
#[derive(Debug, Clone, Serialize)]
pub struct Transcript {
    /// The request id, so the reader can open it in the project.
    pub request: RequestId,
    /// The method, verbatim.
    pub method: String,
    /// The absolute URL.
    pub url: String,
    /// The protocol version token.
    pub http_version: String,
    /// When it was sent, RFC 3339.
    pub sent_at: String,
    /// Which subsystem sent it — `proxy`, `repeater`, `authz`.
    pub origin: String,
    /// How the request reached the socket: `structured` or `raw`.
    ///
    /// A structured request is reproduced by serializing the model, so what is quoted
    /// below is what went out. A raw one was sent byte for byte, and what is quoted is
    /// a *reading* of those bytes with credentials removed — close, and not identical.
    /// A report that let a reader assume otherwise would be wrong about the one thing
    /// raw mode exists to control.
    pub mode: String,
    /// The identity it was sent as, by label, when it was sent as one.
    pub identity: Option<String>,
    /// Request headers, after redaction.
    pub request_headers: Vec<(String, String)>,
    /// The request body.
    pub request_body: BodyExcerpt,
    /// The response status, or `None` if none was recorded.
    pub status: Option<u16>,
    /// The reason phrase, as sent.
    pub reason: Option<String>,
    /// Response headers, after redaction.
    pub response_headers: Vec<(String, String)>,
    /// The response body.
    pub response_body: BodyExcerpt,
}

/// As much of a body as the report quotes.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BodyExcerpt {
    /// The quoted text, absent for a binary body.
    pub text: Option<String>,
    /// The body's full size in bytes.
    pub total_bytes: usize,
    /// Whether the quote stops short of the whole body.
    pub truncated: bool,
    /// Whether the body was binary and therefore not quoted.
    pub binary: bool,
}

impl BodyExcerpt {
    /// Whether there is nothing to show.
    pub fn is_empty(&self) -> bool {
        self.total_bytes == 0
    }

    /// A one-line description for a reader, e.g. `4.1 kB, truncated`.
    pub fn note(&self) -> String {
        if self.total_bytes == 0 {
            return "empty".to_string();
        }
        let mut note = format!("{} bytes", self.total_bytes);
        if self.binary {
            note.push_str(", binary — not quoted");
        } else if self.truncated {
            note.push_str(", truncated");
        }
        note
    }
}

impl Report {
    /// Reads a project and builds the report it supports.
    pub fn build(project: &Project, options: &ReportOptions) -> Result<Self> {
        let findings = all_findings(project)?;
        let recorded = findings.len() as u64;

        let mut excluded = Excluded::default();
        let mut kept = Vec::new();
        for finding in findings {
            match finding.status {
                FindingStatus::FalsePositive => excluded.false_positives += 1,
                FindingStatus::Duplicate => excluded.duplicates += 1,
                _ if below(&finding, options.min_severity) => excluded.below_severity += 1,
                _ if options.actionable_only && !finding.confidence.is_actionable() => {
                    excluded.leads_omitted += 1;
                }
                _ => kept.push(finding),
            }
        }

        let traffic = project.traffic();
        // Resolved once. Every replayed request names an identity, and asking the
        // store per citation would re-read the same handful of rows for every claim.
        let labels: HashMap<IdentityId, String> = project
            .identities()
            .list()?
            .into_iter()
            .map(|identity| (identity.id, identity.label))
            .collect();
        let mut caveats = Vec::new();
        let mut dangling = 0usize;

        let mut established = Vec::new();
        let mut leads = Vec::new();
        for finding in kept {
            let evidence: Vec<CitedEvidence> = finding
                .evidence
                .iter()
                .map(|e| cite(&traffic, &labels, e, options))
                .collect();
            dangling += evidence.iter().filter(|e| !fully_resolved(e)).count();
            let reported = ReportedFinding { finding, evidence };
            if reported.finding.confidence.is_actionable() {
                established.push(reported);
            } else {
                leads.push(reported);
            }
        }

        if dangling > 0 {
            caveats.push(format!(
                "{dangling} cited exchange{} could not be read back from this project \
                 and {} shown as missing. A citation that resolves to nothing is \
                 reported rather than dropped.",
                if dangling == 1 { "" } else { "s" },
                if dangling == 1 { "is" } else { "are" },
            ));
        }
        if options.redaction != RedactionPolicy::Disabled {
            caveats.push(format!(
                "Credentials are redacted: header values shown as {REDACTED} were sent \
                 with a real value. Requests below will not reproduce as printed \
                 without them."
            ));
        }
        if !leads.is_empty() {
            caveats.push(format!(
                "{} unverified lead{} listed separately. They are candidates, not \
                 established issues, and must not be reported as vulnerabilities \
                 without reproduction.",
                leads.len(),
                if leads.len() == 1 { " is" } else { "s are" },
            ));
        }

        let engagement = engagement(project, options)?;
        Ok(Self {
            engagement,
            scope: scope_summary(&project.settings().scope()?),
            identities: identities(project)?,
            coverage: coverage(project, recorded)?,
            findings: established,
            leads,
            excluded,
            redaction: options.redaction,
            caveats,
        })
    }

    /// Renders the report in one of the supported formats.
    ///
    /// JSON is produced from the same model the documents render, so a consumer that
    /// reads it is looking at exactly what a reader of the HTML sees.
    pub fn render(&self, format: Format) -> String {
        match format {
            Format::Markdown => markdown::render(self),
            Format::Html => html::render(self),
            Format::Json => serde_json::to_string_pretty(self)
                .unwrap_or_else(|e| format!("{{\"error\":{e:?}}}")),
        }
    }

    /// How many findings there are at each severity, worst first.
    ///
    /// Counts established findings only: a summary table that folded in unverified
    /// leads would inflate exactly the number a reader takes away.
    pub fn severity_counts(&self) -> Vec<(Severity, usize)> {
        let levels = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];
        levels
            .into_iter()
            .map(|level| {
                (
                    level,
                    self.findings
                        .iter()
                        .filter(|f| f.finding.severity == level)
                        .count(),
                )
            })
            .filter(|(_, count)| *count > 0)
            .collect()
    }

    /// The sentence a reader gets before anything else.
    ///
    /// A clean run says what was covered rather than "no issues": absence of evidence
    /// is not what a zero here means, and a report that implies otherwise is the one
    /// that gets quoted back after a breach.
    pub fn headline(&self) -> String {
        let established = self.findings.len();
        let leads = self.leads.len();
        if established == 0 {
            return format!(
                "No issues were established across {} exchange{} on {} target{}. \
                 That is a statement about what was tested, not a clean bill of health.",
                self.coverage.exchanges,
                plural(self.coverage.exchanges),
                self.coverage.targets,
                plural(self.coverage.targets),
            );
        }
        let mut line = format!(
            "{established} established issue{} across {} exchange{}",
            if established == 1 { "" } else { "s" },
            self.coverage.exchanges,
            plural(self.coverage.exchanges),
        );
        if leads > 0 {
            line.push_str(&format!(
                ", plus {leads} unverified lead{}",
                if leads == 1 { "" } else { "s" }
            ));
        }
        line.push('.');
        line
    }
}

/// The lines under "what this report leaves out", one per non-zero reason.
///
/// Shared by both renderers so the two documents cannot drift into leaving out
/// different things, and phrased per count because "1 unverified leads" reads like a
/// bug in the tool — which is not the impression a report should give about its own
/// omissions.
fn omission_lines(excluded: &Excluded) -> Vec<(u64, &'static str)> {
    [
        (
            excluded.false_positives,
            "triaged as a false positive",
            "triaged as false positives",
        ),
        (
            excluded.duplicates,
            "triaged as a duplicate",
            "triaged as duplicates",
        ),
        (
            excluded.below_severity,
            "below the severity filter this render used",
            "below the severity filter this render used",
        ),
        (
            excluded.leads_omitted,
            "unverified lead, omitted by request",
            "unverified leads, omitted by request",
        ),
    ]
    .into_iter()
    .filter(|(count, _, _)| *count > 0)
    .map(|(count, one, many)| (count, if count == 1 { one } else { many }))
    .collect()
}

fn plural(count: u64) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

fn below(finding: &Finding, floor: Option<Severity>) -> bool {
    floor.is_some_and(|floor| finding.severity < floor)
}

fn fully_resolved(evidence: &CitedEvidence) -> bool {
    match evidence {
        CitedEvidence::Exchange { exchange, .. } => exchange.is_resolved(),
        CitedEvidence::Comparison {
            baseline, variant, ..
        } => baseline.is_resolved() && variant.is_resolved(),
        CitedEvidence::OutOfBand { request, .. } | CitedEvidence::Timing { request, .. } => {
            request.is_resolved()
        }
        // Nothing to resolve: the excerpt is the evidence.
        CitedEvidence::Excerpt { .. } => true,
    }
}

/// Every finding in the project, in the store's triage order.
///
/// Paged rather than fetched in one query, but assembled in memory: a report is read
/// end to end by a person, so a project with more findings than fit in memory has a
/// triage problem that a streaming renderer would only hide.
fn all_findings(project: &Project) -> Result<Vec<Finding>> {
    let store = project.findings();
    let filter = FindingFilter::default();
    let mut cursor: Option<Cursor> = None;
    let mut all = Vec::new();
    loop {
        let page = store.list(&filter, cursor.as_ref(), Limit::new(Limit::MAX))?;
        let last = page.next.is_none();
        all.extend(page.items);
        if last {
            return Ok(all);
        }
        cursor = page.next;
    }
}

fn engagement(project: &Project, options: &ReportOptions) -> Result<Engagement> {
    let conn = project.metadata().connection()?;
    let row: Option<(String, String)> = conn
        .query_row("SELECT name, created_at FROM project LIMIT 1", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .ok();

    let (name, started_at) = match row {
        Some((name, created)) => (name, Some(created)),
        None => ("Untitled engagement".to_string(), None),
    };

    Ok(Engagement {
        title: options
            .title
            .clone()
            .unwrap_or_else(|| format!("{name} — security assessment")),
        project: name,
        started_at,
        generated_at: options
            .generated_at
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

fn coverage(project: &Project, findings_recorded: u64) -> Result<Coverage> {
    // Both counts come off one connection. Borrowing a second while the first is
    // still held deadlocks any project whose pool has one connection — which is every
    // in-memory one, because a second SQLite in-memory connection would be a second
    // empty database.
    let conn = project.metadata().connection()?;
    let count = |table: &str| -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap_or(0)
    };
    Ok(Coverage {
        targets: count("targets").max(0) as u64,
        exchanges: count("requests").max(0) as u64,
        findings_recorded,
    })
}

fn identities(project: &Project) -> Result<Vec<IdentitySummary>> {
    Ok(project
        .identities()
        .list()?
        .into_iter()
        .map(|identity| IdentitySummary {
            label: identity.label,
            privilege: privilege_word(identity.privilege).to_string(),
            credential: credential_kind(&identity.credential).to_string(),
            owns: identity.owned_object_ids,
        })
        .collect())
}

fn privilege_word(privilege: PrivilegeLevel) -> &'static str {
    match privilege {
        PrivilegeLevel::Anonymous => "anonymous",
        PrivilegeLevel::User => "user",
        PrivilegeLevel::Elevated => "elevated",
        PrivilegeLevel::Administrator => "administrator",
    }
}

/// The *kind* of credential, never its value.
fn credential_kind(credential: &Credential) -> &'static str {
    match credential {
        Credential::None => "none",
        Credential::Bearer { .. } => "bearer token",
        Credential::Basic { .. } => "HTTP basic",
        Credential::Cookie { .. } => "cookie",
        Credential::Header { .. } => "custom header",
    }
}

fn scope_summary(scope: &Scope) -> ScopeSummary {
    ScopeSummary {
        included: scope.include.iter().map(rule_line).collect(),
        excluded: scope.exclude.iter().map(rule_line).collect(),
    }
}

fn rule_line(rule: &hexora_types::scope::ScopeRule) -> String {
    let scheme = match rule.scheme {
        SchemeMatch::Any => "",
        SchemeMatch::HttpOnly => "http:// only, ",
        SchemeMatch::HttpsOnly => "https:// only, ",
    };
    let path = match &rule.path {
        PathMatch::Any => String::new(),
        PathMatch::Prefix { value } => format!("{value}*"),
        PathMatch::Exact { value } => value.clone(),
    };
    let ports = if rule.ports.is_empty() {
        String::new()
    } else {
        format!(
            " (ports {})",
            rule.ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!("{scheme}{}{path}{ports}", rule.host)
}

fn cite(
    traffic: &hexora_storage::TrafficStore,
    labels: &HashMap<IdentityId, String>,
    evidence: &Evidence,
    options: &ReportOptions,
) -> CitedEvidence {
    match evidence {
        Evidence::Exchange { request, note, .. } => CitedEvidence::Exchange {
            note: note.clone(),
            exchange: transcribe(traffic, labels, *request, options),
        },
        Evidence::Comparison {
            baseline,
            variant,
            difference,
        } => CitedEvidence::Comparison {
            difference: difference.clone(),
            baseline: transcribe(traffic, labels, *baseline, options),
            variant: transcribe(traffic, labels, *variant, options),
        },
        Evidence::ResponseExcerpt {
            response,
            offset,
            excerpt,
        } => CitedEvidence::Excerpt {
            response: *response,
            offset: *offset,
            excerpt: excerpt.clone(),
        },
        Evidence::OutOfBand {
            request,
            interaction,
            protocol,
        } => CitedEvidence::OutOfBand {
            protocol: protocol.clone(),
            interaction: interaction.to_string(),
            request: transcribe(traffic, labels, *request, options),
        },
        Evidence::Timing {
            request,
            baseline_ms,
            variant_ms,
        } => CitedEvidence::Timing {
            request: transcribe(traffic, labels, *request, options),
            baseline_ms: baseline_ms.clone(),
            variant_ms: variant_ms.clone(),
        },
    }
}

/// Reads one exchange back out of the project, or records why it could not be.
fn transcribe(
    traffic: &hexora_storage::TrafficStore,
    labels: &HashMap<IdentityId, String>,
    request: RequestId,
    options: &ReportOptions,
) -> Citation {
    let stored = match traffic.request(request) {
        Ok(stored) => stored,
        Err(e) => {
            return Citation::Missing {
                request,
                reason: e.to_string(),
            }
        }
    };

    // A response is genuinely optional: a request that timed out is still evidence,
    // and "no response was recorded" is a fact about the target, not a gap.
    let (status, reason, response_headers, response_body) = match traffic.response_head(request) {
        Ok((status, reason, _version, headers)) => {
            let body = traffic.response_body(request, false).unwrap_or_default();
            (
                Some(status),
                reason,
                headers_of(&headers, options.redaction),
                excerpt(&body, options.body_excerpt_bytes),
            )
        }
        Err(_) => (None, None, Vec::new(), BodyExcerpt::default()),
    };

    // By label rather than by id: "sent as User B" is checkable against the claim a
    // finding makes, and `idn_01a08c…` is not. An identity deleted since the run
    // leaves the id, which is still better than a name the project cannot confirm.
    let identity = stored
        .identity
        .map(|id| labels.get(&id).cloned().unwrap_or_else(|| id.to_string()));

    Citation::Resolved(Box::new(Transcript {
        request,
        url: url_of(&stored),
        mode: stored.mode.as_str().to_string(),
        method: stored.method.clone(),
        http_version: stored.http_version.clone(),
        sent_at: stored.sent_at.clone(),
        origin: stored.origin.clone(),
        identity,
        request_headers: headers_of(&stored.headers_raw, options.redaction),
        request_body: excerpt(&stored.body, options.body_excerpt_bytes),
        status,
        reason,
        response_headers,
        response_body,
    }))
}

fn url_of(stored: &hexora_storage::StoredRequest) -> String {
    // Proxied requests are stored in absolute form; everything else needs the origin
    // putting back in front of the path.
    if stored.path.starts_with("http://") || stored.path.starts_with("https://") {
        stored.path.clone()
    } else {
        format!("{}{}", stored.service.origin(), stored.path)
    }
}

/// Splits a raw header block into name/value pairs, redacting as it goes.
///
/// Line-based rather than a full parse: the block is quoted as it was sent, so a
/// duplicated or oddly cased header — which may be the point of the finding —
/// survives into the report unchanged.
fn headers_of(raw: &[u8], policy: RedactionPolicy) -> Vec<(String, String)> {
    String::from_utf8_lossy(raw)
        .split("\r\n")
        .flat_map(|line| line.split('\n'))
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            let name = name.trim();
            let value = value.trim();
            let rendered = if policy.apply_header(name, value) == value {
                value.to_string()
            } else {
                // Says how long the real value was: enough to tell a missing header
                // from a redacted one without disclosing the credential.
                format!("{REDACTED} ({} bytes)", value.len())
            };
            Some((name.to_string(), rendered))
        })
        .collect()
}

/// Quotes as much of a body as the options allow.
fn excerpt(body: &[u8], limit: usize) -> BodyExcerpt {
    if body.is_empty() {
        return BodyExcerpt::default();
    }
    let head = &body[..body.len().min(limit)];
    if looks_binary(head) {
        return BodyExcerpt {
            text: None,
            total_bytes: body.len(),
            truncated: head.len() < body.len(),
            binary: true,
        };
    }
    BodyExcerpt {
        text: Some(String::from_utf8_lossy(head).into_owned()),
        total_bytes: body.len(),
        truncated: head.len() < body.len(),
        binary: false,
    }
}

/// Whether a body should be quoted at all.
///
/// A NUL byte settles it; otherwise the test is the proportion of control characters,
/// because an image or a protobuf pasted into a report is noise that pushes the
/// evidence off the page.
fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.contains(&0) {
        return true;
    }
    let control = bytes
        .iter()
        .filter(|b| **b < 0x09 || (**b > 0x0d && **b < 0x20))
        .count();
    control * 10 > bytes.len()
}

/// Whether a header name is one the report redacts by default. Re-exported so the
/// renderers and the CLI agree on the answer.
pub fn redacts(name: &str) -> bool {
    is_sensitive_header(name)
}

/// What raised a finding, for a reader who wants to know where it came from.
///
/// Names the check and, where the row records one, its version — which is what lets a
/// later comparison tell "the application was fixed" from "the check was rewritten".
/// A human's own finding says so rather than naming a detector.
pub fn raised_by(source: &hexora_types::finding::FindingSource) -> String {
    use hexora_types::finding::FindingSource as S;
    let versioned = |kind: &str, detector: &String, version: &String| {
        if version.is_empty() {
            format!("{kind} check {detector}")
        } else {
            format!("{kind} check {detector} {version}")
        }
    };
    match source {
        S::PassiveScan { detector, version } => versioned("passive", detector, version),
        S::ActiveScan { detector, version } => versioned("active", detector, version),
        S::AuthorizationTest => "the authorization tests".into(),
        S::Extension { extension } => format!("the {extension} extension"),
        S::Ai { model } => format!("the AI layer ({model})"),
        S::Manual => "a tester".into(),
    }
}

/// A short label for a confidence level, as the documents print it.
pub fn confidence_word(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Reported => "reported",
        Confidence::Tentative => "tentative",
        Confidence::Firm => "firm",
        Confidence::Confirmed => "confirmed",
    }
}

/// A short label for a severity, as the documents print it.
pub fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

/// A short label for a triage state.
pub fn status_word(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::New => "new",
        FindingStatus::Triaged => "triaged",
        FindingStatus::Confirmed => "confirmed",
        FindingStatus::FalsePositive => "false positive",
        FindingStatus::Duplicate => "duplicate",
        FindingStatus::Reported => "reported",
        FindingStatus::Fixed => "fixed",
        FindingStatus::Accepted => "accepted",
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use hexora_storage::CapturedExchange;
    use hexora_types::finding::{Evidence, FindingSource, Location, MessagePart, Severity};
    use hexora_types::http::{
        Header, Headers, HttpRequest, HttpResponse, HttpService, HttpVersion,
    };
    use hexora_types::ids::{FindingId, TargetId};

    use super::*;

    /// A project with one exchange in it, and the request id to cite.
    fn project_with_traffic() -> (Project, RequestId, TargetId) {
        let project = Project::in_memory().unwrap();
        let id = record(
            &project,
            "/accounts/acct-1000",
            200,
            br#"{"id":"acct-1000"}"#,
        );
        let target = project.traffic().target_of(id).unwrap();
        (project, id, target)
    }

    fn record(project: &Project, path: &str, status: u16, body: &[u8]) -> RequestId {
        let mut request = HttpRequest::get(HttpService::new("api.example.com", 443, true), path);
        request.headers.append(Header::new(
            "Authorization",
            "Bearer sk-live-not-a-real-token",
        ));
        request
            .headers
            .append(Header::new("Accept", "application/json"));

        let mut headers = Headers::new();
        headers.append(Header::new("Content-Type", "application/json"));

        project
            .traffic()
            .record(&CapturedExchange {
                request,
                response: HttpResponse {
                    status,
                    reason: Some("OK".into()),
                    version: HttpVersion::Http11,
                    headers,
                    body: Bytes::copy_from_slice(body),
                    truncated: false,
                },
                encoded_body: None,
                raw_request: None,
                content_encoding: None,
                origin: "authz",
                identity: None,
                parent: None,
                quirks: Vec::new(),
                tls: None,
                duration_ms: 12,
            })
            .unwrap()
    }

    /// A finding wrapped the way a verification would wrap it.
    ///
    /// These tests are about rendering, not about the verification ladder, so they
    /// use the test-only constructor rather than staging an experiment. It is off in
    /// every shipped binary.
    fn finding(
        target: TargetId,
        confidence: Confidence,
        evidence: Vec<Evidence>,
    ) -> hexora_types::verify::Verified {
        hexora_types::verify::Verified::from_trusted_finding(raw_finding(
            target, confidence, evidence,
        ))
    }

    fn raw_finding(target: TargetId, confidence: Confidence, evidence: Vec<Evidence>) -> Finding {
        let now = Utc::now();
        Finding {
            id: FindingId::new(),
            target,
            title: "Broken object-level authorization in GET /accounts/{id}".into(),
            severity: Severity::High,
            confidence,
            location: Some(Location {
                part: MessagePart::Path,
                name: "/accounts/acct-1000".into(),
            }),
            description: "User B received User A's account.".into(),
            impact: "Any authenticated user can read any account.".into(),
            remediation: "Scope the lookup to the session.".into(),
            reproduction: "Send the request as User A, then as User B, and compare.".into(),
            evidence,
            cwe: Some("CWE-639".into()),
            owasp: Some("API1:2023 Broken Object Level Authorization".into()),
            cvss: None,
            source: FindingSource::AuthorizationTest,
            created_at: now,
            updated_at: now,
            status: FindingStatus::New,
        }
    }

    fn one_exchange(request: RequestId) -> Vec<Evidence> {
        vec![Evidence::Exchange {
            request,
            response: None,
            note: "the response carried another account".into(),
        }]
    }

    fn options() -> ReportOptions {
        ReportOptions {
            generated_at: DateTime::from_timestamp(1_760_000_000, 0).unwrap(),
            ..ReportOptions::default()
        }
    }

    #[test]
    fn an_empty_project_reports_what_was_tested_rather_than_a_clean_bill_of_health() {
        let project = Project::in_memory().unwrap();
        let report = Report::build(&project, &options()).unwrap();

        assert!(report.findings.is_empty());
        assert!(
            report.headline().contains("not a clean bill of health"),
            "{}",
            report.headline()
        );

        let markdown = report.render(Format::Markdown);
        assert!(markdown.contains("## Coverage"), "{markdown}");
        assert!(markdown.contains("## Scope"), "{markdown}");
    }

    #[test]
    fn a_cited_exchange_is_quoted_in_full_rather_than_referenced_by_id() {
        let (project, request, target) = project_with_traffic();
        let other = record(&project, "/accounts/acct-2000", 200, b"{}");
        project
            .findings()
            .save(&finding(
                target,
                Confidence::Confirmed,
                vec![Evidence::Comparison {
                    baseline: request,
                    variant: other,
                    difference: "User B received acct-1000".into(),
                }],
            ))
            .unwrap();

        let markdown = Report::build(&project, &options())
            .unwrap()
            .render(Format::Markdown);

        assert!(
            markdown.contains("GET https://api.example.com/accounts/acct-1000"),
            "the request line itself has to be in the document:\n{markdown}"
        );
        assert!(markdown.contains("acct-1000"), "{markdown}");
        assert!(markdown.contains(&request.to_string()), "{markdown}");
    }

    #[test]
    fn a_credential_is_redacted_by_default_and_its_absence_is_stated() {
        let (project, request, target) = project_with_traffic();
        project
            .findings()
            .save(&finding(target, Confidence::Firm, one_exchange(request)))
            .unwrap();

        let report = Report::build(&project, &options()).unwrap();
        let markdown = report.render(Format::Markdown);
        assert!(
            !markdown.contains("sk-live-not-a-real-token"),
            "a report must never carry a credential:\n{markdown}"
        );
        assert!(markdown.contains(REDACTED), "{markdown}");
        assert!(
            report.caveats.iter().any(|c| c.contains("redacted")),
            "the reader has to be told why the request will not reproduce as printed"
        );
    }

    #[test]
    fn opting_out_of_redaction_is_the_only_way_a_credential_appears() {
        let (project, request, target) = project_with_traffic();
        project
            .findings()
            .save(&finding(target, Confidence::Firm, one_exchange(request)))
            .unwrap();

        let markdown = Report::build(
            &project,
            &ReportOptions {
                redaction: RedactionPolicy::Disabled,
                ..options()
            },
        )
        .unwrap()
        .render(Format::Markdown);

        assert!(markdown.contains("sk-live-not-a-real-token"), "{markdown}");
    }

    #[test]
    fn a_citation_the_project_cannot_resolve_is_printed_as_missing() {
        let (project, _, target) = project_with_traffic();
        let ghost = RequestId::new();
        project
            .findings()
            .save(&finding(target, Confidence::Firm, one_exchange(ghost)))
            .unwrap();

        let report = Report::build(&project, &options()).unwrap();
        let markdown = report.render(Format::Markdown);
        assert!(
            markdown.contains("is not in this project"),
            "a dangling citation is stated, never silently dropped:\n{markdown}"
        );
        assert!(
            report
                .caveats
                .iter()
                .any(|c| c.contains("could not be read back")),
            "{:?}",
            report.caveats
        );
    }

    #[test]
    fn leads_are_kept_out_of_the_findings_section() {
        let (project, request, target) = project_with_traffic();
        project
            .findings()
            .save(&finding(
                target,
                Confidence::Tentative,
                one_exchange(request),
            ))
            .unwrap();

        let report = Report::build(&project, &options()).unwrap();
        assert!(
            report.findings.is_empty(),
            "a Tentative claim is not a finding"
        );
        assert_eq!(report.leads.len(), 1);
        assert!(report.severity_counts().is_empty());

        let markdown = report.render(Format::Markdown);
        let findings_at = markdown.find("## Findings").unwrap();
        let leads_at = markdown.find("## Unverified leads").unwrap();
        assert!(leads_at > findings_at, "leads come after, never before");
    }

    #[test]
    fn asking_for_established_issues_only_omits_the_leads_and_counts_them() {
        let (project, request, target) = project_with_traffic();
        project
            .findings()
            .save(&finding(
                target,
                Confidence::Tentative,
                one_exchange(request),
            ))
            .unwrap();

        let report = Report::build(
            &project,
            &ReportOptions {
                actionable_only: true,
                ..options()
            },
        )
        .unwrap();

        assert!(report.leads.is_empty());
        assert_eq!(report.excluded.leads_omitted, 1);
        assert!(report
            .render(Format::Markdown)
            .contains("What this report leaves out"));
    }

    #[test]
    fn a_false_positive_is_counted_but_not_printed() {
        let (project, request, target) = project_with_traffic();
        let mut dismissed = raw_finding(target, Confidence::Confirmed, one_exchange(request));
        dismissed.title = "A claim somebody dismissed".into();
        dismissed.status = FindingStatus::FalsePositive;
        project
            .findings()
            .save(&hexora_types::verify::Verified::from_trusted_finding(
                dismissed,
            ))
            .unwrap();

        let report = Report::build(&project, &options()).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.excluded.false_positives, 1);
        assert_eq!(report.coverage.findings_recorded, 1);

        let markdown = report.render(Format::Markdown);
        assert!(
            !markdown.contains("A claim somebody dismissed"),
            "{markdown}"
        );
        assert!(
            markdown.contains("1 triaged as a false positive"),
            "a count of one has to read like one:
{markdown}"
        );
    }

    #[test]
    fn a_severity_filter_reports_what_it_dropped() {
        let (project, request, target) = project_with_traffic();
        let mut low = raw_finding(target, Confidence::Confirmed, one_exchange(request));
        low.severity = Severity::Low;
        project
            .findings()
            .save(&hexora_types::verify::Verified::from_trusted_finding(low))
            .unwrap();

        let report = Report::build(
            &project,
            &ReportOptions {
                min_severity: Some(Severity::High),
                ..options()
            },
        )
        .unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.excluded.below_severity, 1);
    }

    #[test]
    fn a_reflected_payload_cannot_execute_in_the_html_report() {
        let project = Project::in_memory().unwrap();
        let request = record(
            &project,
            "/search?q=x",
            200,
            b"<html><script>alert(document.domain)</script></html>",
        );
        let target = project.traffic().target_of(request).unwrap();
        project
            .findings()
            .save(&finding(
                target,
                Confidence::Confirmed,
                one_exchange(request),
            ))
            .unwrap();

        let html = Report::build(&project, &options())
            .unwrap()
            .render(Format::Html);
        assert!(
            !html.contains("<script>alert"),
            "a report must not execute the payload it documents"
        );
        assert!(html.contains("&lt;script&gt;alert"), "{html}");
    }

    #[test]
    fn the_json_render_is_the_same_model_the_documents_use() {
        let (project, request, target) = project_with_traffic();
        project
            .findings()
            .save(&finding(
                target,
                Confidence::Confirmed,
                one_exchange(request),
            ))
            .unwrap();

        let json = Report::build(&project, &options())
            .unwrap()
            .render(Format::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 1);
        assert_eq!(
            parsed["findings"][0]["evidence"][0]["exchange"]["state"],
            "resolved"
        );
        assert!(!json.contains("sk-live-not-a-real-token"));
    }

    #[test]
    fn rendering_the_same_project_twice_produces_the_same_bytes() {
        let (project, request, target) = project_with_traffic();
        project
            .findings()
            .save(&finding(
                target,
                Confidence::Confirmed,
                one_exchange(request),
            ))
            .unwrap();

        let first = Report::build(&project, &options())
            .unwrap()
            .render(Format::Markdown);
        let second = Report::build(&project, &options())
            .unwrap()
            .render(Format::Markdown);
        assert_eq!(first, second, "a report has to be diffable between runs");
    }

    #[test]
    fn a_binary_body_is_described_rather_than_pasted_into_the_document() {
        let quoted = excerpt(&[0x89, b'P', b'N', b'G', 0x00, 0x1a, 0x0a], 2048);
        assert!(quoted.binary);
        assert!(quoted.text.is_none());
        assert!(quoted.note().contains("binary"));
    }

    #[test]
    fn a_long_body_is_truncated_and_says_so() {
        let body = vec![b'a'; 10_000];
        let quoted = excerpt(&body, 100);
        assert!(quoted.truncated);
        assert_eq!(quoted.total_bytes, 10_000);
        assert_eq!(quoted.text.unwrap().len(), 100);
    }

    #[test]
    fn a_redacted_header_says_how_long_the_real_value_was() {
        let headers = headers_of(
            b"Authorization: Bearer abcdef\r\nAccept: */*",
            RedactionPolicy::SensitiveHeaders,
        );
        assert_eq!(headers[1], ("Accept".into(), "*/*".into()));
        assert!(headers[0].1.contains(REDACTED));
        assert!(
            headers[0].1.contains("13 bytes"),
            "a reader has to be able to tell a redacted header from an absent one: {:?}",
            headers[0]
        );
    }

    #[test]
    fn a_duplicated_header_survives_into_the_report() {
        // Two Content-Length headers may be the entire point of a finding, so the
        // block is rendered as sent rather than normalized into a map.
        let headers = headers_of(
            b"Content-Length: 5\r\nContent-Length: 7",
            RedactionPolicy::default(),
        );
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn an_identity_summary_carries_the_kind_of_credential_and_never_the_value() {
        let project = Project::in_memory().unwrap();
        project
            .identities()
            .put(&hexora_types::identity::Identity::bearer(
                "User B",
                "sk-live-xyz",
            ))
            .unwrap();

        let report = Report::build(&project, &options()).unwrap();
        assert_eq!(report.identities[0].credential, "bearer token");

        let rendered = report.render(Format::Markdown) + &report.render(Format::Json);
        assert!(!rendered.contains("sk-live-xyz"));
    }
}

//! `hexora run` — a whole engagement in one declarative file.
//!
//! ZAP's Automation Framework is the entire CI story in one YAML file, and it is the piece a
//! pipeline needs that Burp Pro makes you buy Enterprise for. This runs an ordered plan —
//! import a spec, crawl, scan, report — against a project, non-interactively, and can fail the
//! build when findings cross a severity you name.
//!
//! ```yaml
//! project: ./engagement
//! scope: ["*.target.com"]
//! steps:
//!   - { step: import, openapi: ./openapi.yaml, base: https://api.target.com, send: true }
//!   - { step: crawl,  seeds: ["https://target.com/"], max_requests: 500 }
//!   - { step: scan }
//!   - { step: report, format: sarif, output: ./findings.sarif }
//! fail_on: high
//! ```
//!
//! # It is the plan that consents
//!
//! Every step that sends traffic runs as though `--yes` was given, because writing the step
//! into the plan is the decision the prompt would otherwise ask for. Paths are resolved
//! relative to the plan file, so a plan checked into a repo works wherever it is run from.

use std::path::{Path, PathBuf};

use hexora_storage::repository::Limit;
use hexora_storage::FindingFilter;
use hexora_types::finding::Severity;
use hexora_types::{HexoraError, Result};
use serde::Deserialize;

/// A whole engagement, declared.
#[derive(Debug, Deserialize)]
struct Plan {
    /// The project directory. Created if it does not exist.
    project: String,
    /// Hosts to declare in scope before anything runs.
    #[serde(default)]
    scope: Vec<String>,
    /// The steps, in order.
    #[serde(default)]
    steps: Vec<Step>,
    /// Fail the run (non-zero exit) if a finding at or above this severity exists.
    #[serde(default)]
    fail_on: Option<String>,
}

/// One step of a plan. Internally tagged by a `step:` field: `{ step: scan }`,
/// `{ step: crawl, ... }`, …
#[derive(Debug, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
enum Step {
    Import(ImportStep),
    Crawl(CrawlStep),
    Scan(ScanStep),
    Report(ReportStep),
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ImportStep {
    openapi: Option<String>,
    graphql: Option<String>,
    base: Option<String>,
    url: Option<String>,
    send: bool,
    include_writes: bool,
    insecure: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CrawlStep {
    seeds: Vec<String>,
    max_requests: Option<usize>,
    max_depth: Option<usize>,
    insecure: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ScanStep {
    host: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ReportStep {
    format: Option<String>,
    output: Option<String>,
    severity: Option<String>,
}

/// Runs a plan file end to end.
pub fn run(plan_path: &Path, json: bool) -> Result<()> {
    let text = std::fs::read_to_string(plan_path)
        .map_err(|e| HexoraError::invalid_input("plan", format!("{}: {e}", plan_path.display())))?;
    let plan: Plan = serde_yaml_ng::from_str(&text)
        .map_err(|e| HexoraError::invalid_input("plan", format!("not a valid plan: {e}")))?;

    // Paths in the plan are relative to the plan file, so a checked-in plan is portable.
    let base_dir = plan_path.parent().unwrap_or_else(|| Path::new("."));
    let resolve = |p: &str| -> PathBuf {
        let path = Path::new(p);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base_dir.join(path)
        }
    };

    // Sending traffic is automated work; a plan that does it needs the entitlement, once.
    let sends = plan.steps.iter().any(|s| match s {
        Step::Import(i) => i.send,
        Step::Crawl(_) => true,
        _ => false,
    });
    if sends {
        crate::license::gate().require(hexora_engine::license::Feature::ActiveScanner)?;
    }

    let project = resolve(&plan.project);
    if !project.join("project.db").exists() {
        crate::project::init(&project, None, json)?;
    }
    step_line(json, &format!("project {}", project.display()));

    for host in &plan.scope {
        crate::scope::add(&project, host, None, false, json)?;
    }

    for (index, step) in plan.steps.iter().enumerate() {
        run_step(&project, step, index + 1, plan.steps.len(), &resolve, json)?;
    }

    // Fail the build when findings cross the named severity — the whole point in CI.
    if let Some(threshold) = &plan.fail_on {
        return fail_on(&project, threshold, json);
    }

    if !json {
        println!();
        println!("Plan complete.");
    }
    Ok(())
}

/// Runs one step by handing it to the same code path the matching command uses.
fn run_step(
    project: &Path,
    step: &Step,
    n: usize,
    total: usize,
    resolve: &impl Fn(&str) -> PathBuf,
    json: bool,
) -> Result<()> {
    match step {
        Step::Import(i) => {
            step_line(json, &format!("[{n}/{total}] import"));
            match (&i.openapi, &i.graphql) {
                (Some(spec), None) => crate::import::openapi(crate::import::Args {
                    project,
                    spec: &resolve(spec),
                    base: i.base.as_deref(),
                    send: i.send,
                    include_writes: i.include_writes,
                    max: None,
                    insecure: i.insecure,
                    yes: true,
                    json,
                }),
                (None, Some(spec)) => {
                    let url = i.url.as_deref().ok_or_else(|| {
                        HexoraError::invalid_input("import", "a graphql import step needs a `url`")
                    })?;
                    crate::import::graphql(crate::import::GraphqlArgs {
                        project,
                        spec: &resolve(spec),
                        url,
                        send: i.send,
                        include_mutations: i.include_writes,
                        max: None,
                        insecure: i.insecure,
                        yes: true,
                        json,
                    })
                }
                _ => Err(HexoraError::invalid_input(
                    "import",
                    "an import step needs exactly one of `openapi` or `graphql`",
                )),
            }
        }
        Step::Crawl(c) => {
            step_line(json, &format!("[{n}/{total}] crawl"));
            crate::crawl::run(crate::crawl::Args {
                project: project.to_path_buf(),
                seeds: c.seeds.clone(),
                identity: None,
                max_requests: c.max_requests,
                max_depth: c.max_depth,
                max_per_host: None,
                delay_ms: None,
                follow_destructive: false,
                ignore_robots: false,
                dry_run: false,
                yes: true,
                insecure: c.insecure,
                no_save: false,
                json,
            })
        }
        Step::Scan(s) => {
            step_line(json, &format!("[{n}/{total}] scan"));
            crate::scan::passive(crate::scan::Args {
                project,
                detector: None,
                host: s.host.as_deref(),
                since: None,
                limit: s.limit,
                everything: false,
                no_save: false,
                json,
            })
        }
        Step::Report(r) => {
            step_line(json, &format!("[{n}/{total}] report"));
            let output = r.output.as_ref().map(|o| resolve(o));
            crate::report::run(crate::report::ReportArgs {
                project,
                format: r.format.as_deref(),
                output: output.as_deref(),
                title: None,
                severity: r.severity.as_deref(),
                actionable: false,
                show_secrets: false,
                no_poc: false,
                excerpt_bytes: 2048,
                json,
            })
        }
    }
}

/// Checks the findings against a severity threshold and returns an error (non-zero exit) when
/// any finding meets or exceeds it.
fn fail_on(project: &Path, threshold: &str, json: bool) -> Result<()> {
    let severity = Severity::parse(threshold).ok_or_else(|| {
        HexoraError::invalid_input(
            "fail_on",
            format!("{threshold:?} is not a severity (info, low, medium, high, critical)"),
        )
    })?;
    let store = crate::open_project(project)?;
    let filter = FindingFilter {
        min_severity: Some(severity),
        ..FindingFilter::default()
    };
    let page = store.findings().list(&filter, None, Limit::new(1))?;
    let breached = !page.items.is_empty();

    if json {
        println!(
            "{}",
            serde_json::json!({ "fail_on": severity.as_str(), "breached": breached })
        );
    } else {
        println!();
    }
    if breached {
        return Err(HexoraError::invalid_input(
            "fail_on",
            format!("findings at or above `{}` were recorded", severity.as_str()),
        ));
    }
    if !json {
        println!(
            "Plan complete. No findings at or above `{}`.",
            severity.as_str()
        );
    }
    Ok(())
}

/// A progress line, suppressed under `--json` so the JSON stays clean.
fn step_line(json: bool, message: &str) {
    if !json {
        eprintln!("== {message} ==");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_plan_parses_into_ordered_steps() {
        let yaml = r#"
project: ./engagement
scope: ["*.target.com", "api.target.com"]
steps:
  - { step: import, openapi: ./api.yaml, base: "https://api.target.com", send: true }
  - { step: crawl, seeds: ["https://target.com/"], max_requests: 500 }
  - { step: scan }
  - { step: report, format: sarif, output: ./out.sarif }
fail_on: high
"#;
        let plan: Plan = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(plan.project, "./engagement");
        assert_eq!(plan.scope.len(), 2);
        assert_eq!(plan.steps.len(), 4);
        assert_eq!(plan.fail_on.as_deref(), Some("high"));
        assert!(matches!(plan.steps[0], Step::Import(_)));
        assert!(matches!(plan.steps[1], Step::Crawl(_)));
        assert!(matches!(plan.steps[2], Step::Scan(_)));
        assert!(matches!(plan.steps[3], Step::Report(_)));
        if let Step::Import(i) = &plan.steps[0] {
            assert_eq!(i.openapi.as_deref(), Some("./api.yaml"));
            assert!(i.send);
        }
    }

    #[test]
    fn an_unknown_step_is_a_clean_error() {
        let yaml = "project: ./p\nsteps:\n  - { step: nonsense }\n";
        assert!(serde_yaml_ng::from_str::<Plan>(yaml).is_err());
    }

    #[test]
    fn a_minimal_plan_needs_only_a_project() {
        let plan: Plan = serde_yaml_ng::from_str("project: ./p\n").unwrap();
        assert!(plan.steps.is_empty());
        assert!(plan.scope.is_empty());
        assert!(plan.fail_on.is_none());
    }
}

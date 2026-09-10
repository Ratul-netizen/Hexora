//! `hexora report` — the document at the end of the engagement.
//!
//! Everything the report needs is already in the project, so this command is a render
//! and nothing more: it sends no traffic, changes no triage state and writes nothing
//! back. Running it twice on an unchanged project produces the same bytes, which is
//! what makes a report diffable between the first draft and the retest.
//!
//! Markdown by default, because it goes straight into a ticket or a repository. HTML
//! when the reader is not a developer, JSON when something else consumes it next.

use std::path::Path;

use hexora_report::{Format, Report, ReportOptions};
use hexora_types::redact::RedactionPolicy;
use hexora_types::{HexoraError, Result};

/// Options for `hexora report`.
pub struct ReportArgs<'a> {
    pub project: &'a Path,
    /// `markdown`, `html` or `json`.
    pub format: Option<&'a str>,
    /// Where to write it. Stdout when absent.
    pub output: Option<&'a Path>,
    /// Document title. Defaults to the project name.
    pub title: Option<&'a str>,
    /// Omit findings below this severity.
    pub severity: Option<&'a str>,
    /// Leave the unverified leads out entirely.
    pub actionable: bool,
    /// Include credentials in the quoted traffic.
    pub show_secrets: bool,
    /// How much of each body to quote.
    pub excerpt_bytes: usize,
    /// The global `--json` flag, which selects the JSON render when `--format` was
    /// not given.
    pub json: bool,
}

/// Builds a report from a project and writes it out.
pub fn run(args: ReportArgs<'_>) -> Result<()> {
    let format = match args.format {
        Some(name) => parse_format(name)?,
        None if args.json => Format::Json,
        None => Format::Markdown,
    };

    let project = crate::open_project(args.project)?;
    let options = ReportOptions {
        title: args.title.map(str::to_owned),
        min_severity: args
            .severity
            .map(crate::findings::parse_severity)
            .transpose()?,
        actionable_only: args.actionable,
        body_excerpt_bytes: args.excerpt_bytes,
        redaction: if args.show_secrets {
            RedactionPolicy::Disabled
        } else {
            RedactionPolicy::SensitiveHeaders
        },
        generated_at: chrono::Utc::now(),
    };

    let report = Report::build(&project, &options)?;
    let rendered = report.render(format);

    match args.output {
        None => {
            print!("{rendered}");
            if !rendered.ends_with('\n') {
                println!();
            }
        }
        Some(path) => {
            std::fs::write(path, &rendered).map_err(|e| {
                HexoraError::invalid_input("--output", format!("{}: {e}", path.display()))
            })?;
            // To stderr, so `hexora report … --output x.md` stays quiet on stdout and
            // the summary still shows up when the render is piped somewhere.
            eprintln!(
                "Wrote {} ({} bytes): {}",
                path.display(),
                rendered.len(),
                report.headline()
            );
            if !report.leads.is_empty() {
                eprintln!(
                    "{} unverified lead{} listed separately. Re-run the test with \
                     --verify before presenting any of them as an issue.",
                    report.leads.len(),
                    if report.leads.len() == 1 {
                        " is"
                    } else {
                        "s are"
                    }
                );
            }
        }
    }

    if args.show_secrets {
        // Said even when the render went to stdout: the file that just landed on disk
        // is now as sensitive as the credentials in it, and nothing else will say so.
        eprintln!(
            "warning: --show-secrets was given, so this report contains real \
             credentials. Treat it as a secret, not as a deliverable."
        );
    }
    Ok(())
}

fn parse_format(value: &str) -> Result<Format> {
    match value.to_ascii_lowercase().as_str() {
        "markdown" | "md" => Ok(Format::Markdown),
        "html" => Ok(Format::Html),
        "json" => Ok(Format::Json),
        other => Err(HexoraError::invalid_input(
            "--format",
            format!("{other:?} is not one of markdown, html, json"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_are_accepted_in_the_forms_people_type() {
        assert_eq!(parse_format("MD").unwrap(), Format::Markdown);
        assert_eq!(parse_format("html").unwrap(), Format::Html);
        assert!(parse_format("pdf").is_err());
    }

    #[test]
    fn an_unknown_format_lists_the_ones_that_exist() {
        let error = parse_format("docx").unwrap_err().to_string();
        assert!(error.contains("markdown"), "{error}");
    }

    #[test]
    fn a_report_over_a_fresh_project_writes_a_file_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();

        let out = dir.path().join("report.md");
        run(ReportArgs {
            project: &path,
            format: Some("markdown"),
            output: Some(&out),
            title: None,
            severity: None,
            actionable: false,
            show_secrets: false,
            excerpt_bytes: 2048,
            json: false,
        })
        .unwrap();

        let written = std::fs::read_to_string(&out).unwrap();
        assert!(written.contains("Acme"), "{written}");
        assert!(
            written.contains("not a statement"),
            "an empty report must not read as a clean bill of health:\n{written}"
        );
    }

    #[test]
    fn the_title_can_be_set_for_a_client_facing_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();

        let out = dir.path().join("report.html");
        run(ReportArgs {
            project: &path,
            format: Some("html"),
            output: Some(&out),
            title: Some("Acme Q1 web application assessment"),
            severity: None,
            actionable: false,
            show_secrets: false,
            excerpt_bytes: 2048,
            json: false,
        })
        .unwrap();

        let written = std::fs::read_to_string(&out).unwrap();
        assert!(written.contains("<title>Acme Q1 web application assessment</title>"));
    }

    #[test]
    fn a_directory_that_is_not_a_project_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("notes.txt"), "hello").unwrap();
        let error = run(ReportArgs {
            project: dir.path(),
            format: None,
            output: None,
            title: None,
            severity: None,
            actionable: false,
            show_secrets: false,
            excerpt_bytes: 2048,
            json: false,
        })
        .unwrap_err();
        assert_eq!(error.code(), "invalid_input");
    }
}

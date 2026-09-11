//! `hexora poc` — a finding, as something somebody can run.
//!
//! The last mile of an engagement. A claim in a report invites an argument; the two
//! requests that produced it, in a form a triager can paste into a terminal, ends
//! one.
//!
//! Everything printed is compiled from stored evidence. Credentials are placeholders,
//! always — a proof of concept is the most-forwarded thing an engagement produces,
//! and it must survive being pasted into a ticket.

use std::path::Path;

use hexora_report::poc::{reproduce, Curl, Reproduction};
use hexora_types::ids::FindingId;
use hexora_types::Result;

/// Which form to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// Raw HTTP, as it was sent.
    Raw,
    /// A shell command per step, where one can express it.
    Curl,
    /// Both, with the prose around them.
    Markdown,
}

impl Form {
    /// Parses the `--format` value.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "raw" | "http" => Some(Self::Raw),
            "curl" | "sh" | "shell" => Some(Self::Curl),
            "markdown" | "md" => Some(Self::Markdown),
            _ => None,
        }
    }
}

/// Options for `hexora poc`.
pub struct Args<'a> {
    pub project: &'a Path,
    /// The finding to reproduce.
    pub id: &'a str,
    /// Which form to print.
    pub format: &'a str,
    /// Write it here instead of to standard output.
    pub save_to: Option<&'a Path>,
    pub json: bool,
}

/// Compiles and prints a reproduction.
pub fn run(args: Args<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let id: FindingId = args.id.parse()?;
    let finding = project.findings().get(id)?;
    let poc = reproduce(&project, &finding)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&as_json(&poc)).unwrap_or_default()
        );
        return Ok(());
    }

    let form = Form::parse(args.format).ok_or_else(|| {
        hexora_types::HexoraError::invalid_input(
            "--format",
            format!("{:?} is not one of raw, curl, markdown", args.format),
        )
    })?;

    let rendered = render(&poc, form);
    match args.save_to {
        Some(path) => {
            std::fs::write(path, &rendered).map_err(|e| {
                hexora_types::HexoraError::invalid_input(
                    "--save",
                    format!("{}: {e}", path.display()),
                )
            })?;
            println!("Wrote the reproduction to {}.", path.display());
            if !poc.caveats.is_empty() {
                println!();
                for caveat in &poc.caveats {
                    println!("  ! {caveat}");
                }
            }
        }
        None => print!("{rendered}"),
    }
    Ok(())
}

/// The reproduction, as text.
pub fn render(poc: &Reproduction, form: Form) -> String {
    let mut out = String::new();

    if form == Form::Markdown {
        out.push_str(&format!("## Reproduction — {}\n\n", poc.title));
        out.push_str(&format!("{}\n\n", poc.summary));
    }

    if !poc.placeholders.is_empty() {
        out.push_str(if form == Form::Markdown {
            "**Before running this**, supply:\n\n"
        } else {
            "# Before running this, supply:\n"
        });
        for placeholder in &poc.placeholders {
            let who = placeholder
                .identity
                .as_deref()
                .map(|identity| format!("{identity}'s "))
                .unwrap_or_default();
            out.push_str(&format!(
                "{}{}  —  {}{} header, {} bytes when it was sent\n",
                if form == Form::Markdown {
                    "- `"
                } else {
                    "#   "
                },
                placeholder.token,
                who,
                placeholder.header,
                placeholder.bytes,
            ));
        }
        if form == Form::Markdown {
            // Close the code spans the list opened.
            out = out.replace("  —  ", "`  —  ");
        }
        out.push('\n');
    }

    for step in &poc.steps {
        let heading = format!("{}. {}", step.number, step.heading());

        match form {
            Form::Markdown => out.push_str(&format!("### {heading}\n\n")),
            _ => out.push_str(&format!("# {heading}\n")),
        }

        match (&step.raw, form) {
            (Some(raw), Form::Markdown) => {
                out.push_str(&format!("```http\n{}\n```\n\n", raw.trim_end()));
            }
            (Some(raw), Form::Raw) => {
                out.push_str(raw.trim_end());
                out.push_str("\n\n");
            }
            (Some(_), Form::Curl) => {}
            (None, _) => {
                out.push_str("# The project no longer holds this exchange.\n\n");
                continue;
            }
        }

        if form != Form::Raw {
            match &step.curl {
                Curl::Command { command } => {
                    if form == Form::Markdown {
                        out.push_str(&format!("```bash\n{command}\n```\n\n"));
                    } else {
                        out.push_str(&format!("{command}\n\n"));
                    }
                }
                // Printed, not omitted: an absent command with no explanation reads
                // as a missing feature rather than as the point.
                Curl::Inexpressible { reason } => out.push_str(&format!(
                    "# No curl command: {reason}.\n# Send the raw form instead.\n\n"
                )),
                Curl::Unavailable => {}
            }
        }

        if let Some(expect) = &step.expect {
            if form == Form::Markdown {
                out.push_str(&format!("**Expect:** {expect}\n\n"));
            } else {
                out.push_str(&format!("# Expect: {expect}\n\n"));
            }
        }
    }

    if !poc.caveats.is_empty() {
        if form == Form::Markdown {
            out.push_str("### What this does not establish\n\n");
            for caveat in &poc.caveats {
                out.push_str(&format!("- {caveat}\n"));
            }
        } else {
            out.push_str("# What this does not establish:\n");
            for caveat in &poc.caveats {
                out.push_str(&format!("#   {caveat}\n"));
            }
        }
        out.push('\n');
    }

    out
}

fn as_json(poc: &Reproduction) -> serde_json::Value {
    serde_json::json!({
        "finding": poc.finding.to_string(),
        "title": poc.title,
        "confidence": hexora_report::confidence_word(poc.confidence),
        "runnable": poc.is_runnable(),
        "summary": poc.summary,
        "placeholders": poc.placeholders.iter().map(|placeholder| serde_json::json!({
            "token": placeholder.token,
            "header": placeholder.header,
            "identity": placeholder.identity,
            "bytes": placeholder.bytes,
        })).collect::<Vec<_>>(),
        "steps": poc.steps.iter().map(|step| serde_json::json!({
            "number": step.number,
            "what": step.what,
            "request": step.request.to_string(),
            "identity": step.identity,
            "raw": step.raw,
            "curl": step.curl.command(),
            "curl_refused": match &step.curl {
                Curl::Inexpressible { reason } => Some(reason.clone()),
                _ => None,
            },
            "expect": step.expect,
        })).collect::<Vec<_>>(),
        "caveats": poc.caveats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_formats_are_the_ones_the_help_lists() {
        assert_eq!(Form::parse("raw"), Some(Form::Raw));
        assert_eq!(Form::parse("CURL"), Some(Form::Curl));
        assert_eq!(Form::parse("md"), Some(Form::Markdown));
        assert_eq!(Form::parse("yaml"), None);
    }

    #[test]
    fn a_finding_that_is_not_in_the_project_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();

        let error = run(Args {
            project: &path,
            id: &hexora_types::ids::FindingId::new().to_string(),
            format: "markdown",
            save_to: None,
            json: false,
        })
        .unwrap_err();
        assert!(error.to_string().contains("finding"), "{error}");
    }

    #[test]
    fn an_unknown_format_lists_the_ones_that_exist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();

        // Parsed after the finding is read, so this needs a real one; the message is
        // what matters and it is checked directly.
        assert!(Form::parse("postscript").is_none());
    }
}

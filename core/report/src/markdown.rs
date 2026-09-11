//! Markdown rendering.
//!
//! The format that goes into a repository, a ticket or a pull request, and the one a
//! reviewer can diff between two runs. Everything the HTML page says, this says too:
//! there is one report model and two renderers, not two reports.
//!
//! Response bodies are quoted inside fenced blocks. A body containing a fence of its
//! own would otherwise end the block early and let a hostile target lay out the rest
//! of the document — so the fence used is always longer than the longest run of
//! backticks in the content. See [`fence_for`].

use std::fmt::Write as _;

use crate::{
    confidence_word, severity_word, status_word, BodyExcerpt, Citation, CitedEvidence, Report,
    ReportedFinding, Transcript,
};

/// Renders a report as Markdown.
pub fn render(report: &Report) -> String {
    let mut out = String::with_capacity(8 * 1024);
    let e = &report.engagement;

    let _ = writeln!(out, "# {}\n", e.title);
    let _ = writeln!(out, "{}\n", report.headline());

    let _ = writeln!(out, "| | |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(out, "| Project | {} |", e.project);
    if let Some(started) = &e.started_at {
        let _ = writeln!(out, "| Started | {started} |");
    }
    let _ = writeln!(out, "| Report generated | {} |", e.generated_at);
    let _ = writeln!(out, "| Tool | hexora {} |", e.tool_version);
    let _ = writeln!(out);

    summary(&mut out, report);
    scope(&mut out, report);
    identities(&mut out, report);
    caveats(&mut out, report);

    if report.findings.is_empty() {
        let _ = writeln!(out, "## Findings\n");
        let _ = writeln!(
            out,
            "None established. This is a record of what was tested, not a statement \
             that the application is free of vulnerabilities: the coverage above is \
             the limit of what the claim covers.\n"
        );
    } else {
        let _ = writeln!(out, "## Findings\n");
        for (index, finding) in report.findings.iter().enumerate() {
            write_finding(&mut out, index + 1, finding);
        }
    }

    if !report.leads.is_empty() {
        let _ = writeln!(out, "## Unverified leads\n");
        let _ = writeln!(
            out,
            "The tests below produced results consistent with an issue but did not \
             establish one. They are listed so the work is not lost and so somebody \
             can finish it — not as findings.\n"
        );
        for (index, lead) in report.leads.iter().enumerate() {
            write_finding(&mut out, index + 1, lead);
        }
    }

    omissions(&mut out, report);
    out
}

fn summary(out: &mut String, report: &Report) {
    let counts = report.severity_counts();
    if counts.is_empty() {
        return;
    }
    let _ = writeln!(out, "## Summary\n");
    let _ = writeln!(out, "| Severity | Established findings |");
    let _ = writeln!(out, "| --- | --- |");
    for (severity, count) in counts {
        let _ = writeln!(out, "| {} | {count} |", severity_word(severity));
    }
    let _ = writeln!(out);
}

fn scope(out: &mut String, report: &Report) {
    let _ = writeln!(out, "## Scope\n");
    if report.scope.is_empty() {
        let _ = writeln!(
            out,
            "No scope was declared in this project. Automated testing refuses to send \
             traffic to undeclared hosts, so anything below came from the proxy or \
             from requests sent by hand.\n"
        );
        return;
    }
    for rule in &report.scope.included {
        let _ = writeln!(out, "- {rule}");
    }
    for rule in &report.scope.excluded {
        let _ = writeln!(out, "- **excluded:** {rule}");
    }
    let _ = writeln!(out);
}

fn identities(out: &mut String, report: &Report) {
    if report.identities.is_empty() {
        return;
    }
    let _ = writeln!(out, "## Identities tested as\n");
    let _ = writeln!(
        out,
        "| Identity | Privilege | Credential | Declared objects |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for identity in &report.identities {
        let owns = if identity.owns.is_empty() {
            "—".to_string()
        } else {
            identity.owns.join(", ")
        };
        let _ = writeln!(
            out,
            "| {} | {} | {} | {owns} |",
            identity.label, identity.privilege, identity.credential
        );
    }
    let _ = writeln!(
        out,
        "\nCredential kinds only. No credential value is stored in this document.\n"
    );
}

fn caveats(out: &mut String, report: &Report) {
    let _ = writeln!(out, "## Coverage\n");
    let _ = writeln!(
        out,
        "{} exchange{} across {} target{}, {} finding{} recorded.\n",
        report.coverage.exchanges,
        if report.coverage.exchanges == 1 {
            ""
        } else {
            "s"
        },
        report.coverage.targets,
        if report.coverage.targets == 1 {
            ""
        } else {
            "s"
        },
        report.coverage.findings_recorded,
        if report.coverage.findings_recorded == 1 {
            ""
        } else {
            "s"
        },
    );
    if report.caveats.is_empty() {
        return;
    }
    for caveat in &report.caveats {
        let _ = writeln!(out, "- {caveat}");
    }
    let _ = writeln!(out);
}

fn omissions(out: &mut String, report: &Report) {
    if report.excluded.is_empty() {
        return;
    }
    let _ = writeln!(out, "## What this report leaves out\n");
    let x = &report.excluded;
    for (count, reason) in crate::omission_lines(x) {
        let _ = writeln!(out, "- {count} {reason}");
    }
    let _ = writeln!(
        out,
        "\nCounted rather than hidden: each one is a decision somebody made, and a \
         reviewer is entitled to ask about it.\n"
    );
}

/// The runnable reproduction, for a reader who would rather run it than read it.
///
/// Placed above the evidence on purpose: a triager who can reproduce the behaviour in
/// thirty seconds rarely needs to read the transcripts, and a triager who cannot is
/// exactly the one who will.
fn render_reproduction(out: &mut String, poc: &crate::poc::Reproduction) {
    let _ = writeln!(out, "**Run it**\n");

    if !poc.placeholders.is_empty() {
        let _ = writeln!(
            out,
            "Supply these first — Hexora never puts a real credential in a report:\n"
        );
        for placeholder in &poc.placeholders {
            let who = placeholder
                .identity
                .as_deref()
                .map(|identity| format!("{identity}'s "))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "- `{}` — {}`{}` header ({} bytes as sent)",
                placeholder.token, who, placeholder.header, placeholder.bytes
            );
        }
        let _ = writeln!(out);
    }

    for step in &poc.steps {
        let _ = writeln!(out, "{}. {}\n", step.number, step.heading());

        match &step.curl {
            crate::poc::Curl::Command { command } => {
                let _ = writeln!(out, "```bash\n{command}\n```\n");
            }
            crate::poc::Curl::Inexpressible { reason } => {
                // Said rather than omitted: an absent command with no explanation
                // reads as a missing feature rather than as the point.
                let _ = writeln!(
                    out,
                    "No `curl` equivalent — {reason}. Send the request quoted under \
                     Evidence, byte for byte.\n"
                );
            }
            crate::poc::Curl::Unavailable => {
                let _ = writeln!(out, "The project no longer holds this exchange.\n");
            }
        }

        if let Some(expect) = &step.expect {
            let _ = writeln!(out, "Expect: {expect}\n");
        }
    }

    for caveat in &poc.caveats {
        let _ = writeln!(out, "> {caveat}\n");
    }
}

fn write_finding(out: &mut String, index: usize, reported: &ReportedFinding) {
    let f = &reported.finding;
    let _ = writeln!(out, "### {index}. {}\n", f.title);
    let _ = writeln!(
        out,
        "**{}** · confidence: {} · status: {} · raised by {}",
        severity_word(f.severity),
        confidence_word(f.confidence),
        status_word(f.status),
        crate::raised_by(&f.source),
    );
    let mut tags = Vec::new();
    if let Some(cwe) = &f.cwe {
        tags.push(cwe.clone());
    }
    if let Some(owasp) = &f.owasp {
        tags.push(owasp.clone());
    }
    if let Some(cvss) = &f.cvss {
        tags.push(cvss.clone());
    }
    if !tags.is_empty() {
        let _ = writeln!(out, "\n{}", tags.join(" · "));
    }
    if let Some(location) = &f.location {
        let _ = writeln!(out, "\nLocation: {:?} `{}`", location.part, location.name);
    }
    let _ = writeln!(out, "\n{}\n", f.description);

    let _ = writeln!(out, "**Impact.** {}\n", f.impact);
    let _ = writeln!(out, "**Remediation.** {}\n", f.remediation);

    if !f.reproduction.trim().is_empty() {
        let _ = writeln!(out, "**Reproduction**\n");
        for line in f.reproduction.lines() {
            let _ = writeln!(out, "{line}");
        }
        let _ = writeln!(out);
    }

    if let Some(poc) = &reported.reproduction {
        render_reproduction(out, poc);
    }

    let _ = writeln!(out, "**Evidence**\n");
    if reported.evidence.is_empty() {
        let _ = writeln!(
            out,
            "None attached. Nothing above `reported` confidence can reach this state, \
             so this claim is a lead only.\n"
        );
    }
    for evidence in &reported.evidence {
        write_evidence(out, evidence);
    }
    let _ = writeln!(out, "---\n");
}

fn write_evidence(out: &mut String, evidence: &CitedEvidence) {
    match evidence {
        CitedEvidence::Exchange { note, exchange } => {
            let _ = writeln!(out, "{note}\n");
            write_citation(out, exchange, "The exchange");
        }
        CitedEvidence::Comparison {
            difference,
            baseline,
            variant,
        } => {
            let _ = writeln!(out, "{difference}\n");
            write_citation(out, baseline, "Baseline");
            write_citation(out, variant, "Variant");
        }
        CitedEvidence::Excerpt {
            response,
            offset,
            excerpt,
        } => {
            let _ = writeln!(
                out,
                "From response `{response}`, at byte {offset}:\n\n```\n{excerpt}\n```\n"
            );
        }
        CitedEvidence::OutOfBand {
            protocol,
            interaction,
            request,
        } => {
            let _ = writeln!(
                out,
                "An out-of-band {protocol} interaction (`{interaction}`) was attributed \
                 to this request.\n"
            );
            write_citation(out, request, "The request");
        }
        CitedEvidence::Timing {
            request,
            baseline_ms,
            variant_ms,
        } => {
            let _ = writeln!(
                out,
                "Timing: baseline {baseline_ms:?} ms, variant {variant_ms:?} ms. Samples \
                 rather than an average, so a reader can see whether the difference \
                 survives the noise.\n"
            );
            write_citation(out, request, "The request");
        }
    }
}

fn write_citation(out: &mut String, citation: &Citation, label: &str) {
    match citation {
        Citation::Missing { request, reason } => {
            let _ = writeln!(
                out,
                "> **{label} (`{request}`) is not in this project.** {reason}\n>\n> \
                 The claim above cannot be checked from this document.\n"
            );
        }
        Citation::Resolved(transcript) => write_transcript(out, transcript, label),
    }
}

fn write_transcript(out: &mut String, t: &Transcript, label: &str) {
    let sent_as = match &t.identity {
        Some(identity) => format!(", sent as {identity}"),
        None => String::new(),
    };
    let _ = writeln!(
        out,
        "*{label} — `{}`, via {}{sent_as}, at {}*\n",
        t.request, t.origin, t.sent_at
    );
    if t.mode == "raw" {
        let _ = writeln!(
            out,
            "> Sent in **raw mode**: byte for byte, as written. What follows is a \
             reading of those bytes with credentials removed, not the bytes \
             themselves.\n"
        );
    }

    let mut block = String::new();
    let _ = writeln!(block, "{} {} {}", t.method, t.url, t.http_version);
    for (name, value) in &t.request_headers {
        let _ = writeln!(block, "{name}: {value}");
    }
    push_body(&mut block, &t.request_body);

    match t.status {
        None => {
            let _ = writeln!(block, "\n(no response was recorded for this request)");
        }
        Some(status) => {
            let _ = writeln!(
                block,
                "\n{} {status} {}",
                t.http_version,
                t.reason.as_deref().unwrap_or("")
            );
            for (name, value) in &t.response_headers {
                let _ = writeln!(block, "{name}: {value}");
            }
            push_body(&mut block, &t.response_body);
        }
    }

    // The closing fence gets a line of its own even when the body did not end in a
    // newline: a fence welded onto the last byte of a response is not a code block.
    let fence = fence_for(&block);
    let _ = writeln!(
        out,
        "{fence}http\n{}\n{fence}\n",
        block.trim_end_matches('\n')
    );
}

fn push_body(block: &mut String, body: &BodyExcerpt) {
    if body.is_empty() {
        return;
    }
    let _ = writeln!(block);
    match &body.text {
        Some(text) => {
            let _ = writeln!(block, "{}", text.trim_end_matches(['\r', '\n']));
            if body.truncated {
                let _ = writeln!(block, "… [{}]", body.note());
            }
        }
        None => {
            let _ = writeln!(block, "[{}]", body.note());
        }
    }
}

/// A fence long enough that nothing in `content` can close it early.
///
/// A response body is attacker-controlled. Three backticks in one would otherwise end
/// the code block and let the target write Markdown into a document a client reads —
/// a small injection with a large audience.
fn fence_for(content: &str) -> String {
    let longest = content.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    "`".repeat(longest.max(2) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fence_outgrows_the_backticks_in_the_body() {
        assert_eq!(fence_for("nothing special"), "```");
        assert_eq!(fence_for("a ``` b"), "````");
        assert_eq!(fence_for("a ````` b"), "``````");
    }

    #[test]
    fn a_body_that_tries_to_close_the_block_cannot() {
        let mut out = String::new();
        push_body(
            &mut out,
            &BodyExcerpt {
                text: Some("```\n# Not a heading".into()),
                total_bytes: 20,
                truncated: false,
                binary: false,
            },
        );
        let fence = fence_for(&out);
        assert!(
            fence.len() > 3,
            "a body containing a fence must not be quoted with one the same length"
        );
    }

    #[test]
    fn an_empty_body_adds_nothing() {
        let mut out = String::new();
        push_body(&mut out, &BodyExcerpt::default());
        assert!(out.is_empty());
    }

    #[test]
    fn a_truncated_body_says_so_inside_the_block() {
        let mut out = String::new();
        push_body(
            &mut out,
            &BodyExcerpt {
                text: Some("{\"a\":1".into()),
                total_bytes: 40_000,
                truncated: true,
                binary: false,
            },
        );
        assert!(out.contains("40000 bytes"), "{out}");
        assert!(out.contains("truncated"), "{out}");
    }

    #[test]
    fn a_binary_body_is_described_rather_than_pasted() {
        let mut out = String::new();
        push_body(
            &mut out,
            &BodyExcerpt {
                text: None,
                total_bytes: 91_000,
                truncated: true,
                binary: true,
            },
        );
        assert!(out.contains("binary"), "{out}");
    }
}

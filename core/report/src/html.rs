//! HTML rendering.
//!
//! One self-contained file: no scripts, no external stylesheet, no font pulled from a
//! CDN. A report is opened on a client's machine, often from an email attachment, and
//! a document that phones out on open would leak when and where it was read.
//!
//! # Everything is escaped
//!
//! A report quotes response bodies from an application that was being attacked, and
//! the whole point of some findings is that the target reflects input. Pasting that
//! into HTML unescaped would turn the report into the delivery vehicle for the
//! payload it documents — read by a client, on their machine, with the report's
//! contents as the bait. [`escape`] is applied to every interpolated value without
//! exception; there is no "trusted" string in this module.

use std::fmt::Write as _;

use crate::{
    confidence_word, severity_word, status_word, BodyExcerpt, Citation, CitedEvidence, Report,
    ReportedFinding, Transcript,
};

/// The stylesheet, inlined so the document is one file.
const STYLE: &str = "\
:root { color-scheme: light dark; --fg: #16181d; --bg: #ffffff; --muted: #5b6270;
        --line: #d9dde5; --panel: #f6f7f9; --crit: #8b1a1a; --high: #b3401a;
        --med: #8a6d0b; --low: #35618a; --info: #5b6270; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e6e8ec; --bg: #14161a; --muted: #9aa2b1; --line: #2b3038;
          --panel: #1b1e24; --crit: #ff8a8a; --high: #ffab7a; --med: #e2c66a;
          --low: #8ab6e6; --info: #9aa2b1; } }
* { box-sizing: border-box; }
body { margin: 0 auto; padding: 2.5rem 1.25rem 6rem; max-width: 52rem; background: var(--bg);
       color: var(--fg); font: 16px/1.6 -apple-system, BlinkMacSystemFont, 'Segoe UI',
       Roboto, Helvetica, Arial, sans-serif; }
h1 { font-size: 1.9rem; line-height: 1.25; margin: 0 0 .5rem; }
h2 { font-size: 1.3rem; margin: 2.5rem 0 .75rem; padding-bottom: .35rem;
     border-bottom: 1px solid var(--line); }
h3 { font-size: 1.1rem; margin: 2rem 0 .5rem; }
p, li { margin: .55rem 0; }
.lede { font-size: 1.05rem; color: var(--muted); margin-bottom: 1.5rem; }
table { border-collapse: collapse; width: 100%; margin: .75rem 0; font-size: .95rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
pre { background: var(--panel); border: 1px solid var(--line); border-radius: 6px;
      padding: .75rem .9rem; overflow-x: auto; font-size: .85rem; line-height: 1.45;
      white-space: pre-wrap; word-break: break-word; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px;
         border: 1px solid currentColor; font-size: .78rem; font-weight: 600;
         letter-spacing: .02em; }
.sev-critical { color: var(--crit); } .sev-high { color: var(--high); }
.sev-medium { color: var(--med); } .sev-low { color: var(--low); }
.sev-info { color: var(--info); }
.meta { color: var(--muted); font-size: .9rem; margin: .3rem 0 1rem; }
.caption { color: var(--muted); font-size: .85rem; margin: 1rem 0 .3rem; }
.note { border-left: 3px solid var(--line); padding: .1rem 0 .1rem .9rem;
        color: var(--muted); }
.missing { border-left-color: var(--high); color: var(--high); }
.finding { border-top: 1px solid var(--line); padding-top: .5rem; margin-top: 2.5rem; }
footer { margin-top: 4rem; color: var(--muted); font-size: .85rem; }
";

/// Renders a report as a self-contained HTML page.
pub fn render(report: &Report) -> String {
    let mut out = String::with_capacity(16 * 1024);
    let e = &report.engagement;

    let _ = writeln!(out, "<!doctype html>");
    let _ = writeln!(out, "<html lang=\"en\"><head><meta charset=\"utf-8\">");
    let _ = writeln!(
        out,
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    );
    let _ = writeln!(out, "<title>{}</title>", escape(&e.title));
    let _ = writeln!(out, "<style>{STYLE}</style></head><body>");

    let _ = writeln!(out, "<h1>{}</h1>", escape(&e.title));
    let _ = writeln!(out, "<p class=\"lede\">{}</p>", escape(&report.headline()));

    let _ = writeln!(out, "<table><tbody>");
    row(&mut out, "Project", &e.project);
    if let Some(started) = &e.started_at {
        row(&mut out, "Started", started);
    }
    row(&mut out, "Report generated", &e.generated_at);
    row(&mut out, "Tool", &format!("hexora {}", e.tool_version));
    let _ = writeln!(out, "</tbody></table>");

    summary(&mut out, report);
    scope(&mut out, report);
    programme(&mut out, report);
    identities(&mut out, report);
    coverage(&mut out, report);

    let _ = writeln!(out, "<h2>Findings</h2>");
    if report.findings.is_empty() {
        let _ = writeln!(
            out,
            "<p>None established. This is a record of what was tested, not a statement \
             that the application is free of vulnerabilities: the coverage above is the \
             limit of what the claim covers.</p>"
        );
    } else {
        for (index, finding) in report.findings.iter().enumerate() {
            write_finding(&mut out, index + 1, finding);
        }
    }

    if !report.leads.is_empty() {
        let _ = writeln!(out, "<h2>Unverified leads</h2>");
        let _ = writeln!(
            out,
            "<p>The tests below produced results consistent with an issue but did not \
             establish one. They are listed so the work is not lost and so somebody can \
             finish it — not as findings.</p>"
        );
        for (index, lead) in report.leads.iter().enumerate() {
            write_finding(&mut out, index + 1, lead);
        }
    }

    omissions(&mut out, report);

    let _ = writeln!(
        out,
        "<footer>Produced by hexora {} on {}. Every claim above cites the exchange it \
         rests on; nothing in this document was generated without one.</footer>",
        escape(&e.tool_version),
        escape(&e.generated_at)
    );
    let _ = writeln!(out, "</body></html>");
    out
}

fn row(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(
        out,
        "<tr><th>{}</th><td>{}</td></tr>",
        escape(label),
        escape(value)
    );
}

fn summary(out: &mut String, report: &Report) {
    let counts = report.severity_counts();
    if counts.is_empty() {
        return;
    }
    let _ = writeln!(out, "<h2>Summary</h2>");
    let _ = writeln!(
        out,
        "<table><thead><tr><th>Severity</th><th>Established findings</th></tr></thead><tbody>"
    );
    for (severity, count) in counts {
        let word = severity_word(severity);
        let _ = writeln!(
            out,
            "<tr><td><span class=\"badge sev-{}\">{}</span></td><td>{count}</td></tr>",
            word.to_lowercase(),
            escape(word)
        );
    }
    let _ = writeln!(out, "</tbody></table>");
}

fn scope(out: &mut String, report: &Report) {
    let _ = writeln!(out, "<h2>Scope</h2>");
    if report.scope.is_empty() {
        let _ = writeln!(
            out,
            "<p>No scope was declared in this project. Automated testing refuses to send \
             traffic to undeclared hosts, so anything below came from the proxy or from \
             requests sent by hand.</p>"
        );
        return;
    }
    let _ = writeln!(out, "<ul>");
    for rule in &report.scope.included {
        let _ = writeln!(out, "<li><code>{}</code></li>", escape(rule));
    }
    for rule in &report.scope.excluded {
        let _ = writeln!(
            out,
            "<li><strong>excluded:</strong> <code>{}</code></li>",
            escape(rule)
        );
    }
    let _ = writeln!(out, "</ul>");
}

/// The terms the engagement was conducted under.
///
/// Escaped like everything else here: a programme name and an exclusion reason are
/// typed by a person and could as easily be typed by somebody who wants this document
/// to do something when it is opened.
fn programme(out: &mut String, report: &Report) {
    let programme = &report.programme;
    if programme.is_empty() {
        return;
    }

    let _ = writeln!(out, "<h2>Programme</h2>");
    if let Some(name) = &programme.name {
        let _ = writeln!(
            out,
            "<p>Tested under the terms of <strong>{}</strong>.</p>",
            escape(name)
        );
    }
    if let Some(url) = &programme.policy_url {
        // As text, not as a link. A report is handed to somebody who did not choose
        // this URL, and a clickable destination a third party supplied is not one this
        // document should be offering them.
        let _ = writeln!(out, "<p>Terms: <code>{}</code></p>", escape(url));
    }
    if programme.exclusions.is_empty() {
        return;
    }

    let _ = writeln!(
        out,
        "<p>These finding classes were <strong>not reported</strong>, because this \
         programme does not accept them. They were still looked for; their absence \
         below says nothing about the application.</p>"
    );
    let _ = writeln!(
        out,
        "<table><thead><tr><th>Check</th><th>Why it was not reported</th></tr></thead><tbody>"
    );
    for exclusion in &programme.exclusions {
        let _ = writeln!(
            out,
            "<tr><td><code>{}</code></td><td>{}</td></tr>",
            escape(&exclusion.detector),
            escape(&exclusion.reason)
        );
    }
    let _ = writeln!(out, "</tbody></table>");
}

fn identities(out: &mut String, report: &Report) {
    if report.identities.is_empty() {
        return;
    }
    let _ = writeln!(out, "<h2>Identities tested as</h2>");
    let _ = writeln!(
        out,
        "<table><thead><tr><th>Identity</th><th>Privilege</th><th>Credential</th>\
         <th>Declared objects</th></tr></thead><tbody>"
    );
    for identity in &report.identities {
        let owns = if identity.owns.is_empty() {
            "—".to_string()
        } else {
            identity.owns.join(", ")
        };
        let _ = writeln!(
            out,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            escape(&identity.label),
            escape(&identity.privilege),
            escape(&identity.credential),
            escape(&owns)
        );
    }
    let _ = writeln!(out, "</tbody></table>");
    let _ = writeln!(
        out,
        "<p class=\"meta\">Credential kinds only. No credential value is stored in this \
         document.</p>"
    );
}

fn coverage(out: &mut String, report: &Report) {
    let _ = writeln!(out, "<h2>Coverage</h2>");
    let _ = writeln!(
        out,
        "<p>{} exchanges across {} targets, {} findings recorded.</p>",
        report.coverage.exchanges, report.coverage.targets, report.coverage.findings_recorded
    );
    if report.caveats.is_empty() {
        return;
    }
    let _ = writeln!(out, "<ul>");
    for caveat in &report.caveats {
        let _ = writeln!(out, "<li>{}</li>", escape(caveat));
    }
    let _ = writeln!(out, "</ul>");
}

fn omissions(out: &mut String, report: &Report) {
    if report.excluded.is_empty() {
        return;
    }
    let x = &report.excluded;
    let _ = writeln!(out, "<h2>What this report leaves out</h2><ul>");
    for (count, reason) in crate::omission_lines(x) {
        let _ = writeln!(out, "<li>{count} {}</li>", escape(reason));
    }
    let _ = writeln!(
        out,
        "</ul><p class=\"meta\">Counted rather than hidden: each one is a decision \
         somebody made, and a reviewer is entitled to ask about it.</p>"
    );
}

/// The runnable reproduction.
///
/// Every value that came from the application — a header name, a URL, a reason — is
/// escaped on the way in. The page carries no script and loads nothing, so a
/// reproduction block is text in a `<pre>` and cannot become anything else.
fn render_reproduction(out: &mut String, poc: &crate::poc::Reproduction) {
    let _ = writeln!(out, "<p><strong>Run it</strong></p>");

    if !poc.placeholders.is_empty() {
        out.push_str(
            "<p>Supply these first — Hexora never puts a real credential in a \
             report.</p><ul>",
        );
        for placeholder in &poc.placeholders {
            let who = placeholder
                .identity
                .as_deref()
                .map(|identity| format!("{}&rsquo;s ", escape(identity)))
                .unwrap_or_default();
            out.push_str(&format!(
                "<li><code>{}</code> — {}<code>{}</code> header ({} bytes as sent)</li>",
                escape(&placeholder.token),
                who,
                escape(&placeholder.header),
                placeholder.bytes
            ));
        }
        out.push_str("</ul>");
    }

    out.push_str("<ol class=\"steps\">");
    for step in &poc.steps {
        out.push_str(&format!("<li><p>{}</p>", escape(&step.heading())));

        match &step.curl {
            crate::poc::Curl::Command { command } => {
                out.push_str(&format!("<pre><code>{}</code></pre>", escape(command)));
            }
            crate::poc::Curl::Inexpressible { reason } => {
                out.push_str(&format!(
                    "<p class=\"note\">No <code>curl</code> equivalent — {}. Send the \
                     request quoted under Evidence, byte for byte.</p>",
                    escape(reason)
                ));
            }
            crate::poc::Curl::Unavailable => {
                out.push_str("<p class=\"note\">The project no longer holds this exchange.</p>");
            }
        }

        if let Some(expect) = &step.expect {
            out.push_str(&format!(
                "<p><strong>Expect:</strong> {}</p>",
                escape(expect)
            ));
        }
        out.push_str("</li>");
    }
    out.push_str("</ol>");

    for caveat in &poc.caveats {
        out.push_str(&format!("<p class=\"note\">{}</p>", escape(caveat)));
    }
}

fn write_finding(out: &mut String, index: usize, reported: &ReportedFinding) {
    let f = &reported.finding;
    let word = severity_word(f.severity);
    let _ = writeln!(out, "<section class=\"finding\">");
    let _ = writeln!(
        out,
        "<h3>{index}. {} <span class=\"badge sev-{}\">{}</span></h3>",
        escape(&f.title),
        word.to_lowercase(),
        escape(word)
    );

    let mut meta = vec![
        format!("confidence: {}", confidence_word(f.confidence)),
        format!("status: {}", status_word(f.status)),
        // Which check said so, and which version of it. Escaped with everything
        // else below: a detector id is ours, but an extension's is not.
        format!("raised by {}", crate::raised_by(&f.source)),
    ];
    for tag in [f.cwe.as_ref(), f.owasp.as_ref(), f.cvss.as_ref()]
        .into_iter()
        .flatten()
    {
        meta.push(tag.clone());
    }
    if let Some(location) = &f.location {
        meta.push(format!("{:?} {}", location.part, location.name));
    }
    let _ = writeln!(out, "<p class=\"meta\">{}</p>", escape(&meta.join(" · ")));

    let _ = writeln!(out, "<p>{}</p>", escape(&f.description));
    let _ = writeln!(out, "<p><strong>Impact.</strong> {}</p>", escape(&f.impact));
    let _ = writeln!(
        out,
        "<p><strong>Remediation.</strong> {}</p>",
        escape(&f.remediation)
    );

    if !f.reproduction.trim().is_empty() {
        let _ = writeln!(out, "<p><strong>Reproduction</strong></p>");
        let _ = writeln!(out, "<pre><code>{}</code></pre>", escape(&f.reproduction));
    }

    if let Some(poc) = &reported.reproduction {
        render_reproduction(out, poc);
    }

    let _ = writeln!(out, "<p><strong>Evidence</strong></p>");
    if reported.evidence.is_empty() {
        let _ = writeln!(
            out,
            "<p class=\"note\">None attached. Nothing above <code>reported</code> \
             confidence can reach this state, so this claim is a lead only.</p>"
        );
    }
    for evidence in &reported.evidence {
        write_evidence(out, evidence);
    }
    let _ = writeln!(out, "</section>");
}

fn write_evidence(out: &mut String, evidence: &CitedEvidence) {
    match evidence {
        CitedEvidence::Exchange { note, exchange } => {
            let _ = writeln!(out, "<p>{}</p>", escape(note));
            write_citation(out, exchange, "The exchange");
        }
        CitedEvidence::Comparison {
            difference,
            baseline,
            variant,
        } => {
            let _ = writeln!(out, "<p>{}</p>", escape(difference));
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
                "<p class=\"caption\">From response <code>{}</code>, at byte {offset}</p>\
                 <pre><code>{}</code></pre>",
                escape(&response.to_string()),
                escape(excerpt)
            );
        }
        CitedEvidence::OutOfBand {
            protocol,
            interaction,
            request,
        } => {
            let _ = writeln!(
                out,
                "<p>An out-of-band {} interaction (<code>{}</code>) was attributed to \
                 this request.</p>",
                escape(protocol),
                escape(interaction)
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
                "<p>Timing: baseline {} ms, variant {} ms. Samples rather than an \
                 average, so a reader can see whether the difference survives the \
                 noise.</p>",
                escape(&format!("{baseline_ms:?}")),
                escape(&format!("{variant_ms:?}"))
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
                "<p class=\"note missing\"><strong>{} (<code>{}</code>) is not in this \
                 project.</strong> {} The claim above cannot be checked from this \
                 document.</p>",
                escape(label),
                escape(&request.to_string()),
                escape(reason)
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
        "<p class=\"caption\">{} — <code>{}</code>, via {}{}, at {}</p>",
        escape(label),
        escape(&t.request.to_string()),
        escape(&t.origin),
        escape(&sent_as),
        escape(&t.sent_at)
    );

    if t.mode == "raw" {
        let _ = writeln!(
            out,
            "<p class=\"note\">Sent in <strong>raw mode</strong>: byte for byte, as \
             written. What follows is a reading of those bytes with credentials \
             removed, not the bytes themselves.</p>"
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

    let _ = writeln!(
        out,
        "<pre><code>{}</code></pre>",
        escape(block.trim_end_matches('\n'))
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

/// Escapes text for insertion anywhere in the document.
///
/// Both quote forms are escaped as well as the three structural characters, so the
/// same function is correct inside an attribute as in element text. One escaper with
/// no context argument is deliberate: a per-context set would eventually be called
/// with the wrong one.
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 16);
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_script_tag_in_a_body_does_not_become_a_script_tag() {
        let escaped = escape("<script>alert(document.domain)</script>");
        assert!(!escaped.contains("<script"), "{escaped}");
        assert!(escaped.contains("&lt;script&gt;"), "{escaped}");
    }

    #[test]
    fn quotes_are_escaped_so_attributes_cannot_be_broken_out_of() {
        assert_eq!(escape("a\"b'c"), "a&quot;b&#39;c");
    }

    #[test]
    fn ampersands_are_escaped_once_and_not_twice() {
        assert_eq!(escape("a & b"), "a &amp; b");
        assert_eq!(escape("&amp;"), "&amp;amp;");
    }
}

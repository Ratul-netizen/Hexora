import { useState } from "react";

import { describeError, renderReport, type ReportView as Rendered } from "../ipc";

/**
 * The write-up, previewed before it is written.
 *
 * A render sends no traffic and changes no triage state, which is why this view can
 * show the document itself rather than a description of it. What you read here is
 * byte-for-byte what lands on disk.
 */
export function ReportView({ hasProject }: { hasProject: boolean }) {
  const [format, setFormat] = useState("markdown");
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("");
  const [actionable, setActionable] = useState(false);
  const [showSecrets, setShowSecrets] = useState(false);
  const [path, setPath] = useState("");
  const [report, setReport] = useState<Rendered | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function render(saveTo: string | null) {
    setBusy(true);
    setError(null);
    try {
      setReport(
        await renderReport({
          format,
          title: title.trim() === "" ? null : title,
          severity: severity === "" ? null : severity,
          actionable,
          showSecrets,
          saveTo,
        }),
      );
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (!hasProject) {
    return <p className="placeholder">Open a project to write it up.</p>;
  }

  return (
    <div className="report">
      <section className="card">
        <h2>Report</h2>
        <p className="muted">
          Everything it contains is already in the project: the claims, how firmly
          each is established, and the exact exchanges behind them. Leads are kept in
          their own section, and findings triaged away are counted rather than
          hidden.
        </p>

        <div className="row">
          <label className="field">
            <span>Format</span>
            <select value={format} onChange={(e) => setFormat(e.target.value)}>
              <option value="markdown">Markdown — a ticket or a repository</option>
              <option value="html">HTML — a page to hand to a client</option>
              <option value="json">JSON — whatever reads it next</option>
            </select>
          </label>

          <label className="field">
            <span>Lowest severity to include</span>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">everything</option>
              <option value="low">low and above</option>
              <option value="medium">medium and above</option>
              <option value="high">high and above</option>
              <option value="critical">critical only</option>
            </select>
          </label>
        </div>

        <label className="field">
          <span>Title</span>
          <input
            type="text"
            value={title}
            placeholder="defaults to the project name"
            onChange={(e) => setTitle(e.target.value)}
          />
        </label>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={actionable}
            onChange={(e) => setActionable(e.target.checked)}
          />
          <span>
            Established issues only
            <span className="muted small">
              {" "}
              — leads are dropped from the document and counted in what it left out.
            </span>
          </span>
        </label>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={showSecrets}
            onChange={(e) => setShowSecrets(e.target.checked)}
          />
          <span>
            Include real credentials in the quoted traffic
            <span className="muted small">
              {" "}
              — the result is a secret, not a deliverable. Requests reproduce exactly
              as printed; anyone who opens the file has the sessions in it.
            </span>
          </span>
        </label>

        <div className="row">
          <button onClick={() => void render(null)} disabled={busy}>
            {busy ? "Rendering…" : "Preview"}
          </button>
          <input
            type="text"
            value={path}
            placeholder="C:\engagements\acme\report.md"
            spellCheck={false}
            onChange={(e) => setPath(e.target.value)}
          />
          <button
            onClick={() => void render(path)}
            disabled={busy || path.trim() === ""}
          >
            Write it
          </button>
        </div>

        {showSecrets && (
          <p className="notice warn">
            This render will contain real credentials.
          </p>
        )}
        {error && <p className="error-text">{error}</p>}
      </section>

      {report && (
        <section className="card">
          <h2>{report.headline}</h2>
          <p className="muted small">
            {report.findings} established, {report.leads} lead
            {report.leads === 1 ? "" : "s"} ·{" "}
            {report.bytes.toLocaleString()} bytes
            {report.path !== null && (
              <>
                {" "}
                · written to <span className="mono">{report.path}</span>
              </>
            )}
          </p>

          {report.caveats.length > 0 && (
            <ul className="caveats">
              {report.caveats.map((caveat, index) => (
                <li key={index} className="muted small">
                  {caveat}
                </li>
              ))}
            </ul>
          )}

          {/* The document as text, even for HTML. Rendering the HTML would mean
              executing markup that came from the application under test — the
              report quotes response bodies, and some findings exist precisely
              because that application reflects input. */}
          <pre className="body report-preview">{report.content}</pre>
        </section>
      )}
    </div>
  );
}

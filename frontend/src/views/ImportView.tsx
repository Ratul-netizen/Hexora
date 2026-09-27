import { useState } from "react";

import {
  describeError,
  importParse,
  importSend,
  type ImportPreview,
  type ImportResult,
  type LicenseStatus,
} from "../ipc";

/**
 * Import an API description (OpenAPI 3.x / Swagger 2.0) and turn it into traffic the scanner
 * can work over. An API has no HTML links for the crawler to follow; its spec is the map.
 *
 * Paste the spec, preview the operations it implies (path parameters filled, required query
 * parameters appended), then send the safe ones through the project's scope guard — writes are
 * sent only when explicitly included. Nothing is sent until you press Send.
 */
export function ImportView({
  hasProject,
  license,
}: {
  hasProject: boolean;
  license: LicenseStatus | null;
}) {
  const [spec, setSpec] = useState("");
  const [base, setBase] = useState("");
  const [includeWrites, setIncludeWrites] = useState(false);
  const [insecure, setInsecure] = useState(false);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const free = (license?.tier ?? "Free") === "Free";

  if (!hasProject) {
    return <p className="placeholder">Open a project to import an API spec into it.</p>;
  }

  async function parse() {
    setError(null);
    setResult(null);
    try {
      setPreview(await importParse(spec, base.trim() === "" ? null : base.trim()));
    } catch (e) {
      setError(describeError(e));
      setPreview(null);
    }
  }

  async function send() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = await importSend({
        spec,
        base: base.trim() === "" ? null : base.trim(),
        includeWrites,
        insecure,
      });
      setResult(r);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  const writes = preview?.operations.filter((o) => !o.safe).length ?? 0;

  return (
    <div className="import">
      <section className="card">
        <h2>Import an API spec</h2>
        <p className="muted">
          OpenAPI 3.x or Swagger 2.0, JSON or YAML. Preview the operations, then send the safe
          ones (GET/HEAD/OPTIONS) through the scope guard and record them for scanning. Writes are
          sent only when you tick “include writes”.
        </p>

        <label className="field">
          <span>Spec — paste the JSON or YAML</span>
          <textarea
            rows={8}
            className="query"
            placeholder={'{ "openapi": "3.0.0", "servers": [...], "paths": { ... } }'}
            value={spec}
            onChange={(e) => setSpec(e.target.value)}
          />
        </label>

        <label className="field">
          <span>Base URL — override, or supply one the spec omits</span>
          <input
            type="text"
            placeholder="https://api.target.com"
            value={base}
            onChange={(e) => setBase(e.target.value)}
          />
        </label>

        <div className="toggles">
          <label className="check">
            <input
              type="checkbox"
              checked={includeWrites}
              onChange={(e) => setIncludeWrites(e.target.checked)}
            />
            Include writes (POST/PUT/PATCH/DELETE)
          </label>
          <label className="check">
            <input type="checkbox" checked={insecure} onChange={(e) => setInsecure(e.target.checked)} />
            Do not verify TLS
          </label>
        </div>

        {free && (
          <p className="callout warn">
            Sending an import needs the Pro tier (it is automated traffic). Previewing is free.
            Start a trial or activate a licence on the Licence tab.
          </p>
        )}

        <div className="row">
          <button className="secondary" disabled={spec.trim() === ""} onClick={parse}>
            Preview
          </button>
          <button className="primary" disabled={busy || free || spec.trim() === ""} onClick={send}>
            {busy ? "Sending…" : "Send (records traffic)"}
          </button>
        </div>
      </section>

      {error && <p className="callout danger">{error}</p>}

      {result && (
        <p className="callout ok">
          Recorded {result.recorded} operation(s) from {result.base} into the project
          {result.failed > 0 && ` (${result.failed} did not complete)`}. Scan the new traffic on
          the Scan tab.
        </p>
      )}

      {preview && (
        <section className="card">
          <h2>{preview.title ?? "Operations"}</h2>
          <p className="muted small">
            Base {preview.base} — {preview.operations.length} operation(s), {writes} write(s).
          </p>
          <table className="grid">
            <thead>
              <tr>
                <th>Method</th>
                <th>URL</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {preview.operations.map((op, i) => (
                <tr key={i} className={op.safe ? "" : "muted"}>
                  <td>
                    {op.method}
                    {!op.safe && <span className="tag">write</span>}
                  </td>
                  <td>
                    <code>{op.url}</code>
                  </td>
                  <td>{op.summary ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}

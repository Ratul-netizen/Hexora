import { useEffect, useState } from "react";

import {
  checkAdd,
  checkList,
  checkRemove,
  checkSetEnabled,
  describeError,
  type CustomCheck,
} from "../ipc";

/**
 * Custom scan checks — Nullhawk's answer to Burp's BChecks.
 *
 * A check is a query plus a finding template. It runs during a passive scan and files a lead
 * when its query matches a captured exchange. Checks match on request/response metadata and
 * headers (the same fields as the History query box); body fields are refused because the
 * passive scanner does not load bodies. A custom check can only ever produce a lead — never an
 * actionable finding, and never a hypothesis the active scanner would chase.
 */
const SEVERITIES = ["info", "low", "medium", "high", "critical"];

export function ChecksView({ hasProject }: { hasProject: boolean }) {
  const [checks, setChecks] = useState<CustomCheck[]>([]);
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [query, setQuery] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!hasProject) return;
    checkList()
      .then(setChecks)
      .catch((e) => setError(describeError(e)));
  }, [hasProject]);

  if (!hasProject) {
    return <p className="placeholder">Open a project to manage custom scan checks.</p>;
  }

  async function add() {
    setBusy(true);
    setError(null);
    try {
      const next = await checkAdd({
        id: id.trim(),
        name: name.trim(),
        severity,
        query,
        message,
        disabled: false,
      });
      setChecks(next);
      setId("");
      setName("");
      setQuery("");
      setMessage("");
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(checkId: string) {
    setError(null);
    try {
      setChecks(await checkRemove(checkId));
    } catch (e) {
      setError(describeError(e));
    }
  }

  async function toggle(check: CustomCheck) {
    setError(null);
    try {
      setChecks(await checkSetEnabled(check.id, !check.enabled));
    } catch (e) {
      setError(describeError(e));
    }
  }

  return (
    <div className="checks">
      <section className="card">
        <h2>Custom scan checks</h2>
        <p className="muted">
          A query plus a finding template. Runs during a passive scan and files a lead when the
          query matches. Matches on metadata and headers (same fields as the History query);
          bodies are not available. A custom check can only ever raise a lead.
        </p>

        <div className="row">
          <label className="field">
            <span>Id</span>
            <input
              type="text"
              placeholder="custom.exposed-actuator"
              value={id}
              onChange={(e) => setId(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Severity</span>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
        </div>

        <label className="field">
          <span>Name — the finding title</span>
          <input
            type="text"
            placeholder="Spring Boot actuator exposed"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>

        <label className="field">
          <span>Query — when this matches, a lead is filed</span>
          <input
            type="text"
            className="query"
            placeholder="path:/actuator AND status=200"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>

        <label className="field">
          <span>Message — what the match means</span>
          <input
            type="text"
            placeholder="An actuator endpoint answered without authentication"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
        </label>

        <button
          className="primary"
          disabled={busy || id.trim() === "" || name.trim() === "" || query.trim() === ""}
          onClick={add}
        >
          {busy ? "Adding…" : "Add check"}
        </button>
      </section>

      {error && <p className="callout danger">{error}</p>}

      <section className="card">
        <h2>Checks ({checks.length})</h2>
        {checks.length === 0 ? (
          <p className="muted small">No checks yet. They run when you scan passively.</p>
        ) : (
          <table className="grid">
            <thead>
              <tr>
                <th>On</th>
                <th>Id</th>
                <th>Severity</th>
                <th>Query</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {checks.map((check) => (
                <tr key={check.id} className={check.enabled ? "" : "muted"}>
                  <td>
                    <input type="checkbox" checked={check.enabled} onChange={() => toggle(check)} />
                  </td>
                  <td>
                    {check.id}
                    <div className="muted small">{check.name}</div>
                  </td>
                  <td>
                    <span className="tag">{check.severity}</span>
                  </td>
                  <td>
                    <code>{check.query}</code>
                  </td>
                  <td>
                    <button className="secondary" onClick={() => remove(check.id)}>
                      ✕
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

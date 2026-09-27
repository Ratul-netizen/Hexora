import { useEffect, useState } from "react";

import {
  describeError,
  matchReplaceAdd,
  matchReplaceList,
  matchReplaceRemove,
  matchReplaceSetEnabled,
  type MatchReplaceRule,
  type RuleTarget,
} from "../ipc";

/**
 * Match & Replace: rules that rewrite proxied traffic (Burp/Caido's everyday feature).
 *
 * Rules apply to in-scope traffic only — request rules on the way out, response rules on the
 * way back — for the same reason the header attacher is scope-bound: a tester's browser goes to
 * their own mail and bank, and those are not ours to rewrite. An empty pattern on a header
 * target adds a header; an empty replacement removes what matched.
 */
const TARGETS: { id: RuleTarget; label: string }[] = [
  { id: "request-header", label: "Request header" },
  { id: "request-body", label: "Request body" },
  { id: "request-first-line", label: "Request first line" },
  { id: "response-header", label: "Response header" },
  { id: "response-body", label: "Response body" },
];

export function MatchReplaceView({ hasProject }: { hasProject: boolean }) {
  const [rules, setRules] = useState<MatchReplaceRule[]>([]);
  const [name, setName] = useState("");
  const [target, setTarget] = useState<RuleTarget>("request-header");
  const [pattern, setPattern] = useState("");
  const [replacement, setReplacement] = useState("");
  const [isRegex, setIsRegex] = useState(false);
  const [disabled, setDisabled] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!hasProject) return;
    matchReplaceList()
      .then(setRules)
      .catch((e) => setError(describeError(e)));
  }, [hasProject]);

  if (!hasProject) {
    return <p className="placeholder">Open a project to manage match-and-replace rules.</p>;
  }

  const isHeader = target === "request-header" || target === "response-header";

  async function add() {
    setBusy(true);
    setError(null);
    try {
      const next = await matchReplaceAdd({
        name: name.trim(),
        target,
        isRegex,
        pattern,
        replacement,
        disabled,
      });
      setRules(next);
      setName("");
      setPattern("");
      setReplacement("");
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(ruleName: string) {
    setError(null);
    try {
      setRules(await matchReplaceRemove(ruleName));
    } catch (e) {
      setError(describeError(e));
    }
  }

  async function toggle(rule: MatchReplaceRule) {
    setError(null);
    try {
      setRules(await matchReplaceSetEnabled(rule.name, !rule.enabled));
    } catch (e) {
      setError(describeError(e));
    }
  }

  return (
    <div className="matchreplace">
      <section className="card">
        <h2>Match &amp; Replace</h2>
        <p className="muted">
          Rewrites proxied traffic by rule when the proxy runs. Rules apply to in-scope hosts
          only. An empty match on a header target adds a header; an empty replacement removes what
          matched. Rules run in order.
        </p>

        <div className="row">
          <label className="field">
            <span>Name</span>
            <input
              type="text"
              placeholder="strip-csp"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Target</span>
            <select value={target} onChange={(e) => setTarget(e.target.value as RuleTarget)}>
              {TARGETS.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <label className="field">
          <span>
            Match{" "}
            <span className="muted small">
              {isHeader ? "— leave empty to add the replacement as a header" : ""}
            </span>
          </span>
          <input
            type="text"
            placeholder={isHeader ? "Content-Security-Policy:" : "debug=false"}
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
          />
        </label>

        <label className="field">
          <span>
            Replace <span className="muted small">— leave empty to remove what matched</span>
          </span>
          <input
            type="text"
            placeholder={isHeader ? "X-Trace: 1" : "debug=true"}
            value={replacement}
            onChange={(e) => setReplacement(e.target.value)}
          />
        </label>

        <div className="toggles">
          <label className="check">
            <input type="checkbox" checked={isRegex} onChange={(e) => setIsRegex(e.target.checked)} />
            Match is a regular expression
          </label>
          <label className="check">
            <input type="checkbox" checked={disabled} onChange={(e) => setDisabled(e.target.checked)} />
            Add disabled
          </label>
        </div>

        <button className="primary" disabled={busy || name.trim() === ""} onClick={add}>
          {busy ? "Adding…" : "Add rule"}
        </button>
      </section>

      {error && <p className="callout danger">{error}</p>}

      <section className="card">
        <h2>Rules ({rules.length})</h2>
        {rules.length === 0 ? (
          <p className="muted small">No rules yet. Added rules apply when the proxy runs.</p>
        ) : (
          <table className="grid">
            <thead>
              <tr>
                <th>On</th>
                <th>Name</th>
                <th>Target</th>
                <th>Match</th>
                <th>Replace</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.name} className={rule.enabled ? "" : "muted"}>
                  <td>
                    <input type="checkbox" checked={rule.enabled} onChange={() => toggle(rule)} />
                  </td>
                  <td>{rule.name}</td>
                  <td>
                    {rule.target_label}
                    {rule.is_regex && <span className="tag">regex</span>}
                  </td>
                  <td>
                    <code>{rule.pattern || "(empty)"}</code>
                  </td>
                  <td>
                    <code>{rule.replacement || "(empty)"}</code>
                  </td>
                  <td>
                    <button className="secondary" onClick={() => remove(rule.name)}>
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

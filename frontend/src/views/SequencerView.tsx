import { useState } from "react";

import {
  describeError,
  sequencerRun,
  type SequencerReport,
} from "../ipc";

/**
 * Sequencer: how unpredictable is a token? Paste a set of tokens, or extract them from captured
 * traffic by response header or cookie name, and read the entropy the sample shows.
 *
 * It measures, it does not certify: a token can look random and come from a predictable
 * generator, so this flags the clearly-weak ones and says plainly when the sample is too small.
 */
type Source = "paste" | "cookie" | "header";

export function SequencerView({ hasProject }: { hasProject: boolean }) {
  const [source, setSource] = useState<Source>("paste");
  const [tokens, setTokens] = useState("");
  const [header, setHeader] = useState("");
  const [cookie, setCookie] = useState("");
  const [query, setQuery] = useState("");
  const [report, setReport] = useState<SequencerReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      const r = await sequencerRun({
        tokens: source === "paste" ? tokens : null,
        header: source === "header" ? header.trim() || null : null,
        cookie: source === "cookie" ? cookie.trim() || null : null,
        query: source === "paste" ? null : query.trim() || null,
        limit: null,
      });
      setReport(r);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  const canExtract = hasProject || source === "paste";

  return (
    <div className="sequencer">
      <section className="card">
        <h2>Sequencer</h2>
        <p className="muted">
          Measures how unpredictable a token is — session ids, CSRF and reset tokens. Paste a set,
          or extract them from captured traffic. It flags the clearly-weak ones; it never certifies
          a token as safe.
        </p>

        <label className="field">
          <span>Source</span>
          <select value={source} onChange={(e) => setSource(e.target.value as Source)}>
            <option value="paste">Paste tokens</option>
            <option value="cookie">Extract a cookie from captured traffic</option>
            <option value="header">Extract a response header from captured traffic</option>
          </select>
        </label>

        {source === "paste" && (
          <label className="field">
            <span>Tokens — one per line</span>
            <textarea
              rows={8}
              className="query"
              placeholder={"a1b2c3...\nd4e5f6...\n..."}
              value={tokens}
              onChange={(e) => setTokens(e.target.value)}
            />
          </label>
        )}
        {source === "cookie" && (
          <label className="field">
            <span>Cookie name</span>
            <input
              type="text"
              placeholder="session"
              value={cookie}
              onChange={(e) => setCookie(e.target.value)}
            />
          </label>
        )}
        {source === "header" && (
          <label className="field">
            <span>Response header name</span>
            <input
              type="text"
              placeholder="X-CSRF-Token"
              value={header}
              onChange={(e) => setHeader(e.target.value)}
            />
          </label>
        )}
        {source !== "paste" && (
          <>
            <label className="field">
              <span>Only exchanges matching this query (optional)</span>
              <input
                type="text"
                className="query"
                placeholder="path:/login AND status=200"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </label>
            {!hasProject && (
              <p className="callout warn">Open a project to extract tokens from its traffic.</p>
            )}
          </>
        )}

        <button
          className="primary"
          disabled={busy || !canExtract || (source === "paste" && tokens.trim() === "")}
          onClick={run}
        >
          {busy ? "Analysing…" : "Analyse"}
        </button>
      </section>

      {error && <p className="callout danger">{error}</p>}

      {report && (
        <section className="card">
          <h2>Result</h2>
          <p className={verdictClass(report.verdict)}>
            <strong>Verdict: {report.verdict}</strong>
          </p>
          <dl className="kv">
            <dt>Samples</dt>
            <dd>
              {report.samples} ({report.unique} unique)
            </dd>
            <dt>Length</dt>
            <dd>
              {report.min_len}–{report.max_len} chars
            </dd>
            <dt>Charset</dt>
            <dd>{report.charset_size} distinct characters</dd>
            <dt>Entropy</dt>
            <dd>
              {report.bits_per_char.toFixed(2)} bits/char → ~{report.bits_per_token.toFixed(0)}{" "}
              bits/token
            </dd>
          </dl>

          {report.signals.length > 0 ? (
            <div className="callout warn">
              <strong>Signals</strong>
              <ul className="reasons">
                {report.signals.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="muted small">No predictability signals.</p>
          )}
          <p className="muted small">
            An estimate from a sample: a token can look random and still come from a predictable
            generator. This flags the clearly-weak ones; it does not certify the rest as safe.
          </p>
        </section>
      )}
    </div>
  );
}

function verdictClass(verdict: string): string {
  if (verdict.startsWith("weak")) return "callout danger";
  if (verdict.startsWith("strong")) return "callout ok";
  return "callout warn";
}

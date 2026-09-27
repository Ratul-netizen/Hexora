import { useState } from "react";

import {
  describeError,
  runLlmTest,
  type LicenseStatus,
  type LlmReport,
} from "../ipc";

/**
 * LLM security testing: point the prompt-injection, system-prompt-disclosure and
 * output-handling probes at one LLM-backed endpoint.
 *
 * This sends requests, so it is spelled out and gated like the active scanner. The endpoint's
 * host is the scope — naming it is the tester's consent — and the button is the consent to
 * send. Injection is a confirmation (the model emitted a canary it was told to); disclosure is
 * a lead to verify; unsafe output is the injection-to-XSS chain.
 */
export function LlmView({ license }: { license: LicenseStatus | null }) {
  const [url, setUrl] = useState("");
  const [method, setMethod] = useState("POST");
  const [template, setTemplate] = useState("");
  const [headers, setHeaders] = useState("");
  const [insecure, setInsecure] = useState(false);
  const [report, setReport] = useState<LlmReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const free = (license?.tier ?? "Free") === "Free";

  async function test() {
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      const result = await runLlmTest({
        url: url.trim(),
        template: template.trim() === "" ? null : template.trim(),
        method: method.trim() === "" ? null : method.trim(),
        headers: headers
          .split("\n")
          .map((h) => h.trim())
          .filter((h) => h !== ""),
        insecure,
      });
      setReport(result);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="llm">
      <section className="card">
        <h2>LLM endpoint test</h2>
        <p className="muted">
          Sends prompt-injection, system-prompt-disclosure and output-handling probes to one
          LLM-backed endpoint. The endpoint's host is the scope; nothing else is contacted.
        </p>

        <label className="field">
          <span>Endpoint URL</span>
          <input
            type="text"
            placeholder="https://api.example/v1/chat/completions"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </label>

        <div className="row">
          <label className="field">
            <span>Method</span>
            <input
              type="text"
              value={method}
              onChange={(e) => setMethod(e.target.value)}
            />
          </label>
        </div>

        <label className="field">
          <span>
            Body template — must contain <code>{"{{PROMPT}}"}</code> where the user prompt goes.
            Leave empty for an OpenAI-style chat body.
          </span>
          <textarea
            rows={3}
            placeholder={'{"messages":[{"role":"user","content":"{{PROMPT}}"}]}'}
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
          />
        </label>

        <label className="field">
          <span>Headers — one per line, <code>Name: value</code> (e.g. an API key)</span>
          <textarea
            rows={2}
            placeholder="Authorization: Bearer sk-…"
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
          />
        </label>

        <div className="toggles">
          <label className="check">
            <input
              type="checkbox"
              checked={insecure}
              onChange={(e) => setInsecure(e.target.checked)}
            />
            Do not verify TLS
          </label>
        </div>

        {free && (
          <p className="callout warn">
            LLM testing needs the Pro tier. Start a trial or activate a licence on the Licence
            tab.
          </p>
        )}

        <p className="callout warn">
          This sends probe requests to the endpoint. Only test systems you are authorized to
          test.
        </p>

        <button
          className="primary"
          disabled={busy || free || url.trim() === ""}
          onClick={test}
        >
          {busy ? "Testing…" : "Run LLM test (sends traffic)"}
        </button>
      </section>

      {error && <p className="callout danger">{error}</p>}

      {report && <LlmResult report={report} />}
    </div>
  );
}

function LlmResult({ report }: { report: LlmReport }) {
  const clean =
    report.injections.length === 0 &&
    report.disclosures.length === 0 &&
    report.unsafe_output.length === 0;

  return (
    <>
      <section className="card">
        <h2>Result</h2>
        <p className="muted small">
          {report.tested} injection probe(s) reached the endpoint.
        </p>

        {/* Prompt injection — a confirmation. */}
        {report.injections.length > 0 ? (
          <div className="callout danger">
            <strong>Prompt injection confirmed ({report.injections.length})</strong>
            <ul className="reasons">
              {report.injections.map((i) => (
                <li key={i.probe}>
                  <span className="tag">{i.category}</span> the model emitted the injected
                  canary <code>{i.canary}</code>{" "}
                  <span className="muted small">({i.probe})</span>
                </li>
              ))}
            </ul>
            <p className="small">
              The application's own instructions were overridden by user input. Treat any
              downstream use of this model's output as attacker-controlled.
            </p>
          </div>
        ) : (
          <p className="callout ok">
            No prompt injection confirmed — each probe told the model to emit a random token and
            none came back. A refutation of these payloads, not a guarantee.
          </p>
        )}

        {/* System-prompt disclosure — leads, not confirmations. */}
        {report.disclosures.length > 0 ? (
          <div className="callout warn">
            <strong>Possible system-prompt disclosure ({report.disclosures.length})</strong>
            <ul className="reasons">
              {report.disclosures.map((d) => (
                <li key={d.probe}>
                  signals: {d.signals.join(", ")}
                  <div className="excerpt">{d.excerpt}</div>
                </li>
              ))}
            </ul>
            <p className="small">
              Heuristic: a model can also invent plausible-looking instructions. Confirm the
              excerpt is the endpoint's actual hidden prompt before reporting.
            </p>
          </div>
        ) : (
          <p className="muted small">
            No system-prompt disclosure elicited by the extraction probes.
          </p>
        )}

        {/* Insecure output handling — the injection-to-impact chain. */}
        {report.unsafe_output.length > 0 ? (
          <div className="callout danger">
            <strong>Insecure output handling ({report.unsafe_output.length})</strong>
            <ul className="reasons">
              {report.unsafe_output.map((u) => (
                <li key={u.probe}>
                  <span className="tag">{u.context}</span> the model emitted{" "}
                  <code>&lt;</code>/<code>&gt;</code> unencoded — marker returned raw:{" "}
                  <code>{u.marker}</code>
                </li>
              ))}
            </ul>
            <p className="small">
              Anywhere this output is rendered as markup — a chat UI, an email, a report — that
              is cross-site scripting via the model. Encode model output at the sink.
            </p>
          </div>
        ) : (
          <p className="muted small">
            Model output came back encoded (or the marker did not survive): no unsafe output
            handling seen.
          </p>
        )}

        {clean && (
          <p className="muted small">
            Nothing confirmed at this endpoint against these probes.
          </p>
        )}
      </section>

      {report.errors.length > 0 && (
        <section className="card">
          <h3 className="muted">Not sent ({report.errors.length})</h3>
          <ul className="reasons">
            {report.errors.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}

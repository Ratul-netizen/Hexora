import { useState } from "react";

import {
  describeError,
  domxssRun,
  type DomXssReport,
  type LicenseStatus,
} from "../ipc";

/**
 * DOM-based XSS — Hexora's answer to Burp's DOM Invader.
 *
 * DOM XSS never reaches the server, so captured traffic cannot show it. This drives the user's
 * installed Chrome/Edge over CDP: it wraps the dangerous DOM sinks before the page loads,
 * navigates with a canary in each client-side source, and reports which sinks the canary
 * reached — a proven source→sink flow. It reports the flow, not the exploit: whether the sink
 * parses the canary as markup is the tester's next step.
 */
export function DomXssView({ license }: { license: LicenseStatus | null }) {
  const [url, setUrl] = useState("");
  const [headed, setHeaded] = useState(false);
  const [report, setReport] = useState<DomXssReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const free = (license?.tier ?? "Free") === "Free";

  async function run() {
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      setReport(await domxssRun({ url: url.trim(), headed, timeoutSecs: null }));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="domxss">
      <section className="card">
        <h2>DOM XSS</h2>
        <p className="muted">
          Drives a real browser to the page with a canary in <code>location.hash</code> and{" "}
          <code>location.search</code>, and reports which DOM sinks the canary reached. Sinks
          wrapped: innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, string timers.
        </p>

        <label className="field">
          <span>Page URL</span>
          <input
            type="text"
            placeholder="https://target.example/page#"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </label>

        <div className="toggles">
          <label className="check">
            <input type="checkbox" checked={headed} onChange={(e) => setHeaded(e.target.checked)} />
            Show the browser window (headed)
          </label>
        </div>

        {free && (
          <p className="callout warn">
            DOM-XSS testing needs the Pro tier. Start a trial or activate a licence on the Licence
            tab.
          </p>
        )}

        <p className="callout warn">
          This launches a browser and navigates to the page. Only test pages you are authorized to
          test. A Chrome/Edge install is required.
        </p>

        <button className="primary" disabled={busy || free || url.trim() === ""} onClick={run}>
          {busy ? "Driving the browser…" : "Test for DOM XSS"}
        </button>
      </section>

      {error && <p className="callout danger">{error}</p>}

      {report && (
        <section className="card">
          <h2>Result</h2>
          <p className="muted small">
            Tested sources: {report.sources_tested.join(", ")}.
          </p>
          {report.vulnerable ? (
            <div className="callout danger">
              <strong>DOM XSS flow confirmed ({report.hits.length})</strong>
              <ul className="reasons">
                {report.hits.map((h, i) => (
                  <li key={i}>
                    <span className="tag">{h.source}</span> → <code>{h.sink}</code>
                    <div className="excerpt">{h.sample}</div>
                  </li>
                ))}
              </ul>
              <p className="small">
                A client-side source flowed into a dangerous sink inside the page's own
                JavaScript. Confirm the canary can carry markup that the sink then parses.
              </p>
            </div>
          ) : (
            <p className="callout ok">
              No source reached an instrumented sink — a result about these sources and sinks, not
              a guarantee.
            </p>
          )}
        </section>
      )}
    </div>
  );
}

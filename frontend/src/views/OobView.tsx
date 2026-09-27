import { useState } from "react";

import {
  describeError,
  runOobTest,
  type LicenseStatus,
  type OobReport,
} from "../ipc";

/**
 * Out-of-band testing (Collaborator): inject a payload that calls back to a server you
 * control into each query parameter of a target, then poll for the callbacks it provokes.
 *
 * A callback carrying the payload's token proves the target used the parameter value to make
 * an out-of-band request — a blind SSRF, or an injection that fetched a URL. Blind by nature:
 * the response says nothing, so the collaborator is the only witness. Run the collaborator
 * with `nullhawk oob serve` on a host the target can reach, and give its authority below.
 */
export function OobView({ license }: { license: LicenseStatus | null }) {
  const [url, setUrl] = useState("");
  const [collaborator, setCollaborator] = useState("");
  const [method, setMethod] = useState("GET");
  const [headers, setHeaders] = useState("");
  const [wait, setWait] = useState("5");
  const [insecure, setInsecure] = useState(false);
  const [report, setReport] = useState<OobReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const free = (license?.tier ?? "Free") === "Free";

  async function test() {
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      const result = await runOobTest({
        url: url.trim(),
        collaborator: collaborator.trim(),
        method: method.trim() === "" ? null : method.trim(),
        headers: headers
          .split("\n")
          .map((h) => h.trim())
          .filter((h) => h !== ""),
        waitSecs: Number(wait) || 5,
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
    <div className="oob">
      <section className="card">
        <h2>Out-of-band parameter test</h2>
        <p className="muted">
          Injects a collaborator payload into each query parameter of the target, waits, then
          polls for the callback it provokes. A callback proves a blind out-of-band request —
          an SSRF, or an injection that fetched a URL — that the response never showed.
        </p>

        <label className="field">
          <span>Target URL — with the query parameters to test</span>
          <input
            type="text"
            placeholder="https://target.example/fetch?url=x&next=y"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </label>

        <div className="row">
          <label className="field">
            <span>Collaborator authority — the host your `oob serve` answers on</span>
            <input
              type="text"
              placeholder="oast.example:8081"
              value={collaborator}
              onChange={(e) => setCollaborator(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Method</span>
            <input
              type="text"
              value={method}
              onChange={(e) => setMethod(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Wait (seconds)</span>
            <input
              type="text"
              value={wait}
              onChange={(e) => setWait(e.target.value)}
            />
          </label>
        </div>

        <label className="field">
          <span>Headers — one per line, <code>Name: value</code></span>
          <textarea
            rows={2}
            placeholder="Cookie: session=…"
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
            Out-of-band testing needs the Pro tier. Start a trial or activate a licence on the
            Licence tab.
          </p>
        )}

        <p className="callout warn">
          This sends one probe per parameter to the target. Only test systems you are authorized
          to test, and run the collaborator on a host you control.
        </p>

        <button
          className="primary"
          disabled={busy || free || url.trim() === "" || collaborator.trim() === ""}
          onClick={test}
        >
          {busy ? "Probing and waiting…" : "Run OOB test (sends traffic)"}
        </button>
      </section>

      {error && <p className="callout danger">{error}</p>}

      {report && (
        <section className="card">
          <h2>Result</h2>
          <p className="muted small">
            Probed {report.parameters.length} parameter(s) — {report.parameters.join(", ")} —
            against {report.collaborator}, waited {report.waited}s.
          </p>

          {report.confirmed ? (
            <div className="callout danger">
              <strong>Out-of-band interaction confirmed ({report.hits.length})</strong>
              {report.hits.map((hit) => (
                <div key={hit.parameter} className="hit">
                  <p>
                    parameter <code>{hit.parameter}</code> — the target reached the collaborator:
                  </p>
                  <ul className="reasons">
                    {hit.interactions.map((i, idx) => (
                      <li key={idx}>
                        <span className="tag">{i.protocol.toUpperCase()}</span> {i.method}{" "}
                        {i.path} from {i.source}{" "}
                        <span className="muted small">at {i.at}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
              <p className="small">
                The target used a parameter value to reach a server it does not control. The
                response never showed it; the callback is the proof.
              </p>
            </div>
          ) : (
            <p className="callout ok">
              No out-of-band interactions within {report.waited}s. Not proof of safety — a target
              may call back more slowly, or only resolve DNS. Raise the wait, or test again.
            </p>
          )}
        </section>
      )}
    </div>
  );
}

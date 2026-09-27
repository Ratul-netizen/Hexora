import { useState } from "react";

import {
  describeError,
  raceRun,
  type LicenseStatus,
  type RaceReport,
} from "../ipc";

/**
 * Race conditions — Burp's turbo/single-packet intruder, Caido's Pipeline.
 *
 * A check-then-act with no lock lets two requests both pass the check before either commits.
 * This replays a captured request N times concurrently and shows the spread: more than one 2xx
 * on a single-use action is the race. Like the fuzzer it concludes nothing — whether the side
 * effect was meant to happen once is the tester's call.
 */
export function RaceView({
  hasProject,
  requestId,
  license,
}: {
  hasProject: boolean;
  requestId: string | null;
  license: LicenseStatus | null;
}) {
  const [id, setId] = useState(requestId ?? "");
  const [count, setCount] = useState("20");
  const [insecure, setInsecure] = useState(false);
  const [report, setReport] = useState<RaceReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const free = (license?.tier ?? "Free") === "Free";

  if (!hasProject) {
    return <p className="placeholder">Open a project, then race one of its captured requests.</p>;
  }

  async function run() {
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      setReport(await raceRun({ id: id.trim(), count: Number(count) || 20, insecure }));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="race">
      <section className="card">
        <h2>Race a request</h2>
        <p className="muted">
          Replays a captured request many times at once. More than one 2xx on a single-use action
          — a coupon, a withdrawal, an invite — is a race: the requests passed the check before any
          committed.
        </p>

        <div className="row">
          <label className="field grow">
            <span>Request id — copy it from History</span>
            <input
              type="text"
              placeholder="a request id from this project"
              value={id}
              onChange={(e) => setId(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Concurrent copies</span>
            <input type="text" value={count} onChange={(e) => setCount(e.target.value)} />
          </label>
        </div>

        <div className="toggles">
          <label className="check">
            <input type="checkbox" checked={insecure} onChange={(e) => setInsecure(e.target.checked)} />
            Do not verify TLS
          </label>
        </div>

        {free && (
          <p className="callout warn">
            Racing needs the Pro tier. Start a trial or activate a licence on the Licence tab.
          </p>
        )}

        <p className="callout warn">
          This sends the request concurrently, and replays state-changing methods. Only test
          systems you are authorized to test.
        </p>

        <button className="primary" disabled={busy || free || id.trim() === ""} onClick={run}>
          {busy ? "Racing…" : "Race (sends concurrent traffic)"}
        </button>
      </section>

      {error && <p className="callout danger">{error}</p>}

      {report && (
        <section className="card">
          <h2>Result</h2>
          <p className="muted small">
            {report.sent} sent, {report.answered} answered
            {report.failed > 0 && `, ${report.failed} did not complete`}.
          </p>
          <table className="grid">
            <thead>
              <tr>
                <th>Status</th>
                <th>Bytes</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              {report.groups.map((g, i) => (
                <tr key={i} className={g.status >= 200 && g.status < 300 ? "" : "muted"}>
                  <td>{g.status}</td>
                  <td>{g.bytes}</td>
                  <td>{g.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {report.successes_2xx > 1 ? (
            <p className="callout danger">
              {report.successes_2xx} concurrent requests returned a 2xx. If this action was meant
              to happen only once, that is a race — confirm the side effect happened more than
              once.
            </p>
          ) : (
            <p className="callout ok">
              At most one request succeeded — no sign of a single-use action being repeated under
              this timing.
            </p>
          )}
        </section>
      )}
    </div>
  );
}

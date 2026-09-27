import { useState } from "react";

import {
  describeError,
  fuzzSlots,
  runFuzz,
  type FuzzRun,
  type FuzzSlot,
  type LicenseStatus,
} from "../ipc";

/**
 * Intruder / fuzzer: take a request that already works, vary one thing in it, and read the
 * column that does not match.
 *
 * It concludes nothing — a response that differs is a response that differs; whether it
 * matters is the tester's judgement. It will replay a state-changing method, and it says so
 * first. Pick a captured request by its id (copy it from History), choose where the payload
 * goes, and paste a list.
 */
export function FuzzerView({
  hasProject,
  requestId,
  license,
}: {
  hasProject: boolean;
  requestId: string | null;
  license: LicenseStatus | null;
}) {
  const [id, setId] = useState(requestId ?? "");
  const [slots, setSlots] = useState<FuzzSlot[] | null>(null);
  const [at, setAt] = useState("");
  const [replacing, setReplacing] = useState("");
  const [payloads, setPayloads] = useState("");
  const [delayMs, setDelayMs] = useState("");
  const [maxRequests, setMaxRequests] = useState("");
  const [insecure, setInsecure] = useState(false);
  const [run, setRun] = useState<FuzzRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loadingSlots, setLoadingSlots] = useState(false);

  const free = (license?.tier ?? "Free") === "Free";

  if (!hasProject) {
    return <p className="placeholder">Open a project, then fuzz one of its captured requests.</p>;
  }

  async function loadSlots() {
    setLoadingSlots(true);
    setError(null);
    setSlots(null);
    try {
      const found = await fuzzSlots(id.trim());
      setSlots(found);
      const first = found[0];
      if (first && at === "") setAt(first.name);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setLoadingSlots(false);
    }
  }

  async function fuzz() {
    setBusy(true);
    setError(null);
    setRun(null);
    try {
      const result = await runFuzz({
        id: id.trim(),
        at: replacing.trim() !== "" ? null : at.trim() === "" ? null : at.trim(),
        replacing: replacing.trim() === "" ? null : replacing.trim(),
        payloads: payloads
          .split("\n")
          .map((p) => p.replace(/\r$/, ""))
          .filter((p) => p !== ""),
        delayMs: delayMs.trim() === "" ? null : Number(delayMs),
        maxRequests: maxRequests.trim() === "" ? null : Number(maxRequests),
        insecure,
      });
      setRun(result);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fuzzer">
      <section className="card">
        <h2>Fuzz a request</h2>
        <p className="muted">
          Sends one captured request once per payload, varying a single slot. It concludes
          nothing — a difference is a difference; what it means is your call.
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
          <button
            className="secondary"
            disabled={loadingSlots || id.trim() === ""}
            onClick={loadSlots}
          >
            {loadingSlots ? "Loading…" : "List slots"}
          </button>
        </div>

        {slots && slots.length > 0 && (
          <label className="field">
            <span>Vary this slot</span>
            <select value={at} onChange={(e) => setAt(e.target.value)}>
              {slots.map((s) => (
                <option key={`${s.kind}:${s.name}`} value={s.name}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
        )}
        {slots && slots.length === 0 && (
          <p className="muted small">
            This request has no query parameter or header to address — use “replace a value”
            below instead.
          </p>
        )}

        <label className="field">
          <span>…or replace a value wherever it appears in the request (overrides the slot)</span>
          <input
            type="text"
            placeholder="e.g. the current value of the field"
            value={replacing}
            onChange={(e) => setReplacing(e.target.value)}
          />
        </label>

        <label className="field">
          <span>Payloads — one per line</span>
          <textarea
            rows={5}
            placeholder={"admin\nadministrator\nroot\noperator"}
            value={payloads}
            onChange={(e) => setPayloads(e.target.value)}
          />
        </label>

        <div className="row">
          <label className="field">
            <span>Delay between requests (ms)</span>
            <input
              type="text"
              placeholder="0"
              value={delayMs}
              onChange={(e) => setDelayMs(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Max requests</span>
            <input
              type="text"
              placeholder="payloads + 1"
              value={maxRequests}
              onChange={(e) => setMaxRequests(e.target.value)}
            />
          </label>
        </div>

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
            The fuzzer needs the Pro tier. Start a trial or activate a licence on the Licence
            tab.
          </p>
        )}

        <p className="callout warn">
          This sends one request per payload to the captured request's host. A state-changing
          method (POST/PUT/DELETE) will be replayed — the result says so. Only fuzz systems you
          are authorized to test.
        </p>

        <button
          className="primary"
          disabled={busy || free || id.trim() === "" || payloads.trim() === ""}
          onClick={fuzz}
        >
          {busy ? "Sending…" : "Fuzz (sends traffic)"}
        </button>
      </section>

      {error && <p className="callout danger">{error}</p>}

      {run && <FuzzResult run={run} />}
    </div>
  );
}

function FuzzResult({ run }: { run: FuzzRun }) {
  return (
    <section className="card">
      <h2>Result</h2>
      <p className="muted">{run.summary}</p>

      {run.state_changing && (
        <p className="callout warn">
          {run.method} may change data on the target — this run replayed it {run.requests_sent}{" "}
          time(s).
        </p>
      )}
      {!run.complete && run.stopped_because && (
        <p className="callout warn">This run is unfinished: {run.stopped_because}</p>
      )}

      {run.baseline && (
        <p className="muted small">
          {run.baseline.error
            ? `The unchanged request did not complete: ${run.baseline.error}`
            : `The unchanged request answered ${run.baseline.status} in ${run.baseline.bytes} bytes.`}
        </p>
      )}

      {run.groups.length > 0 && (
        <table className="grid">
          <thead>
            <tr>
              <th>Status</th>
              <th>Bytes</th>
              <th>Count</th>
              <th>Payloads</th>
            </tr>
          </thead>
          <tbody>
            {run.groups.map((g, i) => (
              <tr key={i} className={g.as_unchanged ? "muted" : ""}>
                <td>{g.status}</td>
                <td>{g.bytes}</td>
                <td>{g.count}</td>
                <td>
                  {g.examples.join(", ")}
                  {g.as_unchanged && " ← as the unchanged request"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {run.outliers.length > 0 ? (
        <>
          <h3>{run.outliers.length} payload(s) did not behave like the rest</h3>
          <table className="grid">
            <thead>
              <tr>
                <th>Payload</th>
                <th>Status</th>
                <th>Bytes</th>
              </tr>
            </thead>
            <tbody>
              {run.outliers.map((o, i) => (
                <tr key={i}>
                  <td>
                    <code>{o.payload}</code>
                  </td>
                  <td>{o.status}</td>
                  <td>{o.bytes}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small">
            Nothing here is a finding: what a difference means is a judgement about this
            application.
          </p>
        </>
      ) : (
        <p className="muted small">
          Nothing stood out. Every payload that answered behaved like the others.
        </p>
      )}
    </section>
  );
}

import { useEffect, useState } from "react";

import {
  describeError,
  fuzzSlots,
  modeSharesOneList,
  runFuzz,
  type AttackMode,
  type FuzzRun,
  type FuzzSlot,
  type LicenseStatus,
} from "../ipc";

/**
 * Intruder / fuzzer with the four Burp attack shapes.
 *
 * - **Sniper** — one payload list, walked through each marked position in turn.
 * - **Battering ram** — one list, the same value in every position at once.
 * - **Pitchfork** — one list per position, advanced in lockstep.
 * - **Cluster bomb** — one list per position, every combination.
 *
 * It concludes nothing — a response that differs is a response that differs; whether it
 * matters is the tester's judgement. It will replay a state-changing method and says so first.
 */
const MODES: { id: AttackMode; label: string; blurb: string }[] = [
  { id: "sniper", label: "Sniper", blurb: "one list, each position in turn" },
  { id: "battering-ram", label: "Battering ram", blurb: "one list, all positions at once" },
  { id: "pitchfork", label: "Pitchfork", blurb: "one list per position, in lockstep" },
  { id: "cluster-bomb", label: "Cluster bomb", blurb: "one list per position, every combination" },
];

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
  const [mode, setMode] = useState<AttackMode>("sniper");
  const [positions, setPositions] = useState<string[]>([""]);
  const [replacing, setReplacing] = useState("");
  const [lists, setLists] = useState<string[]>([""]);
  const [delayMs, setDelayMs] = useState("");
  const [maxRequests, setMaxRequests] = useState("");
  const [insecure, setInsecure] = useState(false);
  const [run, setRun] = useState<FuzzRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loadingSlots, setLoadingSlots] = useState(false);

  const free = (license?.tier ?? "Free") === "Free";
  const oneList = modeSharesOneList(mode);

  // Keep the number of payload boxes in step with the mode and the positions: one shared box
  // for sniper/battering-ram, one per position for pitchfork/cluster-bomb.
  useEffect(() => {
    setLists((prev) => {
      const want = oneList ? 1 : Math.max(1, positions.length);
      if (prev.length === want) return prev;
      const next = prev.slice(0, want);
      while (next.length < want) next.push("");
      return next;
    });
  }, [oneList, positions.length]);

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
      if (first && positions.every((p) => p.trim() === "")) {
        setPositions([first.name]);
      }
    } catch (e) {
      setError(describeError(e));
    } finally {
      setLoadingSlots(false);
    }
  }

  function setPositionAt(index: number, value: string) {
    setPositions((prev) => prev.map((p, i) => (i === index ? value : p)));
  }
  function addPosition() {
    setPositions((prev) => [...prev, ""]);
  }
  function removePosition(index: number) {
    setPositions((prev) => (prev.length > 1 ? prev.filter((_, i) => i !== index) : prev));
  }
  function setListAt(index: number, value: string) {
    setLists((prev) => prev.map((l, i) => (i === index ? value : l)));
  }

  async function fuzz() {
    setBusy(true);
    setError(null);
    setRun(null);
    try {
      const usingReplacing = replacing.trim() !== "";
      const result = await runFuzz({
        id: id.trim(),
        mode,
        positions: usingReplacing
          ? []
          : positions.map((p) => p.trim()).filter((p) => p !== ""),
        replacing: usingReplacing ? replacing.trim() : null,
        payloadLists: lists.map((text) =>
          text
            .split("\n")
            .map((p) => p.replace(/\r$/, ""))
            .filter((p) => p !== ""),
        ),
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

  const canRun =
    !busy &&
    !free &&
    id.trim() !== "" &&
    lists.some((l) => l.trim() !== "") &&
    (replacing.trim() !== "" || positions.some((p) => p.trim() !== ""));

  return (
    <div className="fuzzer">
      <section className="card">
        <h2>Fuzz a request</h2>
        <p className="muted">
          Sends one captured request once per payload placement, in one of the four Intruder
          shapes. It concludes nothing — a difference is a difference; what it means is your call.
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
          <button className="secondary" disabled={loadingSlots || id.trim() === ""} onClick={loadSlots}>
            {loadingSlots ? "Loading…" : "List slots"}
          </button>
        </div>

        <label className="field">
          <span>Attack mode</span>
          <select value={mode} onChange={(e) => setMode(e.target.value as AttackMode)}>
            {MODES.map((m) => (
              <option key={m.id} value={m.id}>
                {m.label} — {m.blurb}
              </option>
            ))}
          </select>
        </label>

        {/* Slot autocomplete from the loaded request. */}
        {slots && (
          <datalist id="fuzz-slots">
            {slots.map((s) => (
              <option key={`${s.kind}:${s.name}`} value={s.name}>
                {s.label}
              </option>
            ))}
          </datalist>
        )}

        {replacing.trim() === "" && (
          <div className="field">
            <span>
              Positions{" "}
              <span className="muted small">
                {oneList
                  ? "— one payload list is shared across all of them"
                  : "— each has its own payload list below"}
              </span>
            </span>
            {positions.map((name, i) => (
              <div key={i} className="position-row">
                <input
                  type="text"
                  list="fuzz-slots"
                  placeholder="query parameter or header name"
                  value={name}
                  onChange={(e) => setPositionAt(i, e.target.value)}
                />
                {positions.length > 1 && (
                  <button className="secondary" onClick={() => removePosition(i)} title="remove">
                    ✕
                  </button>
                )}
                {!oneList && (
                  <textarea
                    rows={4}
                    placeholder={`payloads for ${name.trim() || `position ${i + 1}`} — one per line`}
                    value={lists[i] ?? ""}
                    onChange={(e) => setListAt(i, e.target.value)}
                  />
                )}
              </div>
            ))}
            <button className="secondary" onClick={addPosition}>
              + Add position
            </button>
          </div>
        )}

        {replacing.trim() === "" && oneList && (
          <label className="field">
            <span>Payloads — one per line, used in every position</span>
            <textarea
              rows={5}
              placeholder={"admin\nadministrator\nroot\noperator"}
              value={lists[0] ?? ""}
              onChange={(e) => setListAt(0, e.target.value)}
            />
          </label>
        )}

        <label className="field">
          <span>
            …or, for a single position, replace a value wherever it appears (overrides positions;
            uses the first payload list)
          </span>
          <input
            type="text"
            placeholder="e.g. the current value of the field"
            value={replacing}
            onChange={(e) => setReplacing(e.target.value)}
          />
        </label>
        {replacing.trim() !== "" && (
          <label className="field">
            <span>Payloads — one per line</span>
            <textarea
              rows={5}
              placeholder={"admin\nadministrator\nroot"}
              value={lists[0] ?? ""}
              onChange={(e) => setListAt(0, e.target.value)}
            />
          </label>
        )}

        <div className="row">
          <label className="field">
            <span>Delay between requests (ms)</span>
            <input type="text" placeholder="0" value={delayMs} onChange={(e) => setDelayMs(e.target.value)} />
          </label>
          <label className="field">
            <span>Max requests</span>
            <input
              type="text"
              placeholder="whole attack"
              value={maxRequests}
              onChange={(e) => setMaxRequests(e.target.value)}
            />
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
            The fuzzer needs the Pro tier. Start a trial or activate a licence on the Licence tab.
          </p>
        )}

        <p className="callout warn">
          This sends one request per placement to the captured request's host. A state-changing
          method (POST/PUT/DELETE) will be replayed — the result says so. Only fuzz systems you are
          authorized to test.
        </p>

        <button className="primary" disabled={!canRun} onClick={fuzz}>
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
          {run.method} may change data on the target — this run replayed it {run.requests_sent} time(s).
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
          <h3>{run.outliers.length} placement(s) did not behave like the rest</h3>
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
            Nothing here is a finding: what a difference means is a judgement about this application.
          </p>
        </>
      ) : (
        <p className="muted small">
          Nothing stood out. Every placement that answered behaved like the others.
        </p>
      )}
    </section>
  );
}

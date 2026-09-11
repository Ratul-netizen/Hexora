import { useCallback, useEffect, useState } from "react";

import {
  describeError,
  listDetectors,
  scanActivePlan,
  scanActiveRun,
  scanPassive,
  type ActiveRunView,
  type DetectorView,
  type ObservationView,
  type PlanView,
  type ScanView as ScanResult,
} from "../ipc";

/**
 * The passive pass: what the checks saw in traffic already captured.
 *
 * Sends nothing. The three counts are kept apart on purpose, because they are three
 * different things and collapsing them is how a scanner starts overstating itself:
 *
 * - an **observation** is a fact about the traffic;
 * - a **hypothesis** is a suspicion that needs an experiment this pass did not run;
 * - a **finding** is an observation worth reporting, and every one of them is a lead.
 *
 * A detector that saw nothing is still listed, saying so. Silence has to be a fact
 * rather than an absence, or a retest cannot tell it from "never ran".
 */
export function ScanView({
  hasProject,
  onOpenExchange,
}: {
  hasProject: boolean;
  onOpenExchange: (id: string) => void;
}) {
  const [detectors, setDetectors] = useState<DetectorView[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [only, setOnly] = useState("");
  const [everything, setEverything] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      setDetectors(await listDetectors());
      setError(null);
    } catch (e) {
      setError(describeError(e));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      setResult(await scanPassive(only || null, everything));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (!hasProject) {
    return <p className="placeholder">Open a project to scan its traffic.</p>;
  }

  const passive = detectors.filter((detector) => detector.mode === "passive");

  return (
    <div className="scan">
      <section className="card">
        <h2>Passive scan</h2>
        <p className="muted">
          Reads exchanges this project has already captured and says what the checks
          saw. It sends nothing, so it is safe to run at any point in an engagement —
          including on a project whose client has gone home.
        </p>

        <div className="toolbar">
          <button onClick={() => void run()} disabled={busy}>
            {busy ? "Reading traffic…" : "Run passive scan"}
          </button>
          <select value={only} onChange={(e) => setOnly(e.target.value)}>
            <option value="">every passive check</option>
            {passive.map((detector) => (
              <option key={detector.id} value={detector.id}>
                {detector.name}
              </option>
            ))}
          </select>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={everything}
              onChange={(e) => setEverything(e.target.checked)}
            />
            <span>Include out-of-scope traffic</span>
          </label>
        </div>

        <p className="muted small">
          Out-of-scope traffic is skipped by default: a project holds whatever the
          proxy saw, including your own browsing, and reporting on systems nobody
          declared is not a service to anybody.
        </p>

        {error && <p className="error-text">{error}</p>}
      </section>

      {result && <Results result={result} onOpenExchange={onOpenExchange} />}

      <ActivePass onOpenExchange={onOpenExchange} />

      <section className="card">
        <h3>What this build checks for ({detectors.length})</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Check</th>
                <th>Version</th>
                <th>Mode</th>
                <th>Produces</th>
                <th>What it looks for</th>
              </tr>
            </thead>
            <tbody>
              {detectors.map((detector) => (
                <tr key={detector.id}>
                  <td>
                    {detector.name}
                    <div className="muted small mono">{detector.id}</div>
                  </td>
                  <td className="mono">{detector.version}</td>
                  <td>
                    {/* The field that decides whether this is safe to run against
                        production at 3pm. */}
                    <span className={detector.sends ? "tag insecure" : "tag"}>
                      {detector.mode}
                    </span>
                  </td>
                  <td className="muted small">{produces(detector)}</td>
                  <td className="wrap">{detector.about}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function Results({
  result,
  onOpenExchange,
}: {
  result: ScanResult;
  onOpenExchange: (id: string) => void;
}) {
  const reportable = result.observations.filter((o) => o.reportable);
  const context = result.observations.filter((o) => !o.reportable);

  return (
    <>
      <section className="card">
        <dl className="facts">
          <dt>Exchanges analyzed</dt>
          <dd>{result.exchanges_read}</dd>
          <dt>Exchanges skipped</dt>
          <dd>{result.exchanges_skipped}</dd>
          <dt>Detectors executed</dt>
          <dd>{result.detectors.length}</dd>
          <dt>Observations</dt>
          <dd>{result.observations.length}</dd>
          <dt>Hypotheses</dt>
          <dd>{result.hypotheses.length}</dd>
          <dt>Findings</dt>
          <dd>
            {result.findings}
            {result.findings > 0 && (
              <span className="muted small">
                {" "}
                — {result.recorded_new} new, {result.recorded_refreshed} refreshed
              </span>
            )}
          </dd>
        </dl>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Detector</th>
                <th>Version</th>
                <th>Observations</th>
                <th>Hypotheses</th>
              </tr>
            </thead>
            <tbody>
              {result.detectors.map((detector) => (
                <tr key={detector.detector}>
                  <td className="mono small">{detector.detector}</td>
                  <td className="mono small">{detector.version}</td>
                  <td>{detector.observations}</td>
                  <td>{detector.hypotheses}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small">
          {/* The sentence the run record exists for. */}A detector listed with zero
          ran and saw nothing, which is different from not having run.
        </p>
      </section>

      <Observations
        title="Observations"
        rows={reportable}
        onOpenExchange={onOpenExchange}
        note="Each of these became a finding, and every one is a lead: it says what was seen, not that the application is exploitable."
      />

      {result.hypotheses.length > 0 && (
        <section className="card">
          <h3>Hypotheses ({result.hypotheses.length})</h3>
          <ul className="claims">
            {result.hypotheses.map((hypothesis, index) => (
              <li key={index}>
                <span className="mono small">{hypothesis.detector}</span>{" "}
                {hypothesis.claim}
                <div className="muted small">
                  <button
                    className="link"
                    title={hypothesis.source_request}
                    onClick={() => onOpenExchange(hypothesis.source_request)}
                  >
                    open the exchange
                  </button>
                  <span className="mono"> {hypothesis.provisional_severity} if verified</span>
                </div>
              </li>
            ))}
          </ul>
          <p className="muted small">
            Suspicions, not results. Settling one needs a request this pass did not
            make, so none of them is a finding and none of them is in the project.
          </p>
        </section>
      )}

      <Observations
        title="Context"
        rows={context}
        onOpenExchange={onOpenExchange}
        note="True, and not issues. These are recorded so a tester can see them, and are never filed as findings."
      />
    </>
  );
}

/**
 * The active pass: the experiments the passive one could not run.
 *
 * Two steps, never one. The plan is worked out by a command that has no way to send —
 * it is a different call, not a flag — and the run happens only after somebody has
 * seen how many requests would go where and pressed the second button.
 */
function ActivePass({ onOpenExchange }: { onOpenExchange: (id: string) => void }) {
  const [plan, setPlan] = useState<PlanView | null>(null);
  const [outcome, setOutcome] = useState<ActiveRunView | null>(null);
  const [ceiling, setCeiling] = useState("200");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const maxRequests = () => {
    const parsed = Number.parseInt(ceiling, 10);
    return Number.isFinite(parsed) ? parsed : null;
  };

  async function preview() {
    setBusy(true);
    setError(null);
    setOutcome(null);
    try {
      setPlan(await scanActivePlan(maxRequests()));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  async function send() {
    setBusy(true);
    setError(null);
    try {
      setOutcome(await scanActiveRun(maxRequests()));
      setPlan(null);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Active scan</h2>
      <p className="muted">
        Settles suspicions the passive pass raised, by sending requests. It invents no
        work of its own: run the passive pass first, and everything below comes from
        what it found. Nothing is sent until you have seen the plan.
      </p>

      <div className="toolbar">
        <label>
          Request ceiling{" "}
          <input
            className="narrow"
            value={ceiling}
            onChange={(e) => setCeiling(e.target.value)}
            inputMode="numeric"
          />
        </label>
        <button onClick={() => void preview()} disabled={busy}>
          {busy ? "Working…" : "Show me what it would send"}
        </button>
      </div>

      {error && <p className="notice warn">{error}</p>}

      {plan && <Plan plan={plan} busy={busy} onSend={() => void send()} onOpenExchange={onOpenExchange} />}
      {outcome && <Outcome outcome={outcome} />}
    </section>
  );
}

/** What a run would do, before it does any of it. */
function Plan({
  plan,
  busy,
  onSend,
  onOpenExchange,
}: {
  plan: PlanView;
  busy: boolean;
  onSend: () => void;
  onOpenExchange: (id: string) => void;
}) {
  if (plan.experiments.length === 0) {
    return (
      <div className="plan">
        {plan.out_of_scope > 0 ? (
          /* "Nothing to test" and "everything that could be tested is out of
             bounds" are different sentences, and only one of them is about the
             application. */
          <p className="notice">
            No in-scope hypothesis to settle. {plan.out_of_scope} suspicion(s) stand on
            traffic that is no longer in this project's scope, so nothing would be sent
            to it. That is the scope working, not the application being clean.
          </p>
        ) : (
          <p className="muted">
            Nothing to test. Run the passive pass first; if it raises no suspicion,
            there is no experiment for this one to perform.
          </p>
        )}
        <Skipped rows={plan.skipped} />
      </div>
    );
  }

  return (
    <div className="plan">
      <p>
        <strong>
          {plan.experiments.length} experiment(s), at most {plan.requests_at_most}{" "}
          request(s)
        </strong>
      </p>
      <ul className="differences">
        {plan.hosts.map(([host, experiments, requests]) => (
          <li key={host}>
            <code>{host}</code> — {experiments} experiment(s), at most {requests}{" "}
            request(s)
          </li>
        ))}
      </ul>
      <p className="muted small">{plan.budget}</p>
      {plan.exceeds_ceiling && (
        <p className="notice warn">
          This plan can reach its request ceiling. A run that stops there will say so
          rather than reading as a finished one.
        </p>
      )}

      <details>
        <summary className="muted small">
          The {plan.experiments.length} suspicion(s) that would be tested
        </summary>
        <ul className="claims">
          {plan.experiments.map((experiment, index) => (
            <li key={index}>
              <span className="mono small">{experiment.detector}</span>{" "}
              {experiment.claim}
              <div className="muted small">
                <button
                  className="link"
                  onClick={() => onOpenExchange(experiment.source_request)}
                >
                  open the exchange
                </button>
              </div>
            </li>
          ))}
        </ul>
      </details>

      <Skipped rows={plan.skipped} />

      <div className="toolbar">
        <button className="primary" onClick={onSend} disabled={busy}>
          {busy ? "Running…" : `Send ${plan.requests_at_most} request(s) at most`}
        </button>
      </div>
    </div>
  );
}

/** What a run did. */
function Outcome({ outcome }: { outcome: ActiveRunView }) {
  const established = outcome.settled.filter((s) => s.finding !== null);
  const refuted = outcome.settled.filter((s) => s.verification === "refuted");
  const unclear = outcome.settled.filter((s) => s.verification === "inconclusive");

  return (
    <div className="plan">
      <p>
        <strong>
          {outcome.requests_sent} request(s) sent across {outcome.settled.length}{" "}
          experiment(s).
        </strong>
      </p>

      {/* First, because it is the sentence that must never be mistaken for a clean
          result. */}
      {!outcome.complete && (
        <p className="notice warn">
          This run is unfinished: {outcome.unfinished_note}
        </p>
      )}

      {established.length > 0 && (
        <>
          <h3>Established ({established.length})</h3>
          <ul className="findings-brief">
            {established.map((settled, index) => (
              <li key={index}>
                <span className={`badge sev-${settled.severity}`}>
                  {settled.severity}
                </span>{" "}
                <span className="muted small">{settled.confidence}</span>{" "}
                {settled.title}
                <div className="muted small">{settled.note}</div>
              </li>
            ))}
          </ul>
        </>
      )}

      {refuted.length > 0 && (
        <>
          <h3>Ruled out ({refuted.length})</h3>
          <ul className="claims">
            {refuted.map((settled, index) => (
              <li key={index}>
                {settled.claim}
                <div className="muted small">{settled.note}</div>
              </li>
            ))}
          </ul>
          <p className="muted small">
            A refutation is a result. It is what stops a suspicion following you
            around for the rest of an engagement — and it is not a finding, so nothing
            was filed for it.
          </p>
        </>
      )}

      {unclear.length > 0 && (
        <>
          <h3>Could not be established either way ({unclear.length})</h3>
          <ul className="claims">
            {unclear.map((settled, index) => (
              <li key={index}>
                {settled.claim}
                <div className="muted small">{settled.note}</div>
              </li>
            ))}
          </ul>
        </>
      )}

      <Skipped rows={outcome.skipped} />

      <p className="muted small">
        {outcome.recorded_new + outcome.recorded_refreshed === 0
          ? "No finding was recorded."
          : `${outcome.recorded_new} new, ${outcome.recorded_refreshed} refreshed in the project.`}
      </p>
    </div>
  );
}

/** Hypotheses nothing was sent for, and why. */
function Skipped({ rows }: { rows: { detector: string; claim: string; why: string }[] }) {
  if (rows.length === 0) return null;
  return (
    <details>
      <summary className="muted small">Not tested ({rows.length})</summary>
      <ul className="claims">
        {rows.map((skipped, index) => (
          <li key={index}>
            <span className="mono small">{skipped.detector}</span> {skipped.claim}
            <div className="muted small">{skipped.why}</div>
          </li>
        ))}
      </ul>
    </details>
  );
}

function Observations({
  title,
  rows,
  note,
  onOpenExchange,
}: {
  title: string;
  rows: ObservationView[];
  note: string;
  onOpenExchange: (id: string) => void;
}) {
  if (rows.length === 0) return null;
  return (
    <section className="card">
      <h3>
        {title} ({rows.length})
      </h3>
      <ul className="claims">
        {rows.map((row, index) => (
          <li key={index}>
            <span className={`tag ${row.severity}`}>{row.severity}</span>{" "}
            {row.about}
            {row.occurrences > 1 && (
              <span className="muted small"> ×{row.occurrences}</span>
            )}
            <div className="muted small">
              expected: {row.expected} · observed: {row.observed}
            </div>
            <div className="muted small">
              {/* Numbered rather than labelled with the id: these are time-ordered
                  UUIDs, so three of them share a prefix and three links reading
                  `req_01a08ec9…` tell a reader nothing. The full id is on hover and
                  in the report. */}
              {row.exchanges.map((id, position) => (
                <button
                  key={id}
                  className="link"
                  title={id}
                  onClick={() => onOpenExchange(id)}
                >
                  exchange {position + 1}
                </button>
              ))}
              {row.occurrences > row.exchanges.length && (
                <span> of {row.occurrences}</span>
              )}
              <span className="mono">
                {" "}
                {row.detector} {row.version}
              </span>
            </div>
          </li>
        ))}
      </ul>
      <p className="muted small">{note}</p>
    </section>
  );
}

function produces(detector: DetectorView): string {
  if (detector.observes && detector.hypothesizes) return "observations + hypotheses";
  if (detector.observes) return "observations";
  if (detector.hypothesizes) return "hypotheses";
  // The third product, and the one a check that only *settles* other checks' work
  // has. Without this it read as "nothing", which is what an active verifier looks
  // like if you only ask what it raises.
  if (detector.settles) return `settles ${detector.settles}`;
  return "nothing";
}

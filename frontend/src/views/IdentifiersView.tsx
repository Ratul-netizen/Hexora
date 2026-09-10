import { useCallback, useEffect, useState } from "react";

import {
  analyzeCandidates,
  decideCandidate,
  describeError,
  listCandidates,
  type CandidateView,
} from "../ipc";

/**
 * Values that might be object identifiers.
 *
 * The view exists because declaring every identifier by hand is what keeps
 * constructed authorization testing narrower than it should be. It does not exist to
 * do the declaring. Three things are kept apart here, and the wording is deliberate:
 *
 * - a **suggestion** — Hexora noticed this value varying where an identifier would;
 * - an **object** — a tester says this value is an account, an invoice, a document;
 * - **ownership** — a tester says whose it is.
 *
 * Accepting a suggestion does the first only. It creates no declaration, names no
 * identity, and starts no test. Analysis reads captured traffic and sends nothing.
 */
export function IdentifiersView({ hasProject }: { hasProject: boolean }) {
  const [candidates, setCandidates] = useState<CandidateView[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [showReviewed, setShowReviewed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      setCandidates(await listCandidates());
      setError(null);
    } catch (e) {
      setError(describeError(e));
    }
  }, []);

  useEffect(() => {
    if (hasProject) void reload();
  }, [hasProject, reload]);

  async function run(work: () => Promise<CandidateView[]>) {
    setBusy(true);
    setError(null);
    try {
      setCandidates(await work());
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (!hasProject) {
    return <p className="placeholder">Open a project to review its traffic.</p>;
  }

  const proposed = candidates.filter((c) => c.status === "proposed");
  const shown = showReviewed ? candidates : proposed;
  const decided = candidates.length - proposed.length;

  return (
    <div className="identifiers">
      <section className="card">
        <h2>Identifier suggestions</h2>
        <p className="muted">
          Values that vary where an object identifier would. Every one is a
          suggestion: accepting one says it <em>is</em> an identifier, and says
          nothing about whose it is. Declaring an owner is a separate step on the
          Authorization tab.
        </p>

        <div className="toolbar">
          <button onClick={() => void run(analyzeCandidates)} disabled={busy}>
            {busy ? "Reading traffic…" : "Analyze captured traffic"}
          </button>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={showReviewed}
              onChange={(e) => setShowReviewed(e.target.checked)}
            />
            <span>Show decided ({decided})</span>
          </label>
          <span className="muted small">
            Analysis reads the project. It sends no request and creates no finding.
          </span>
        </div>

        {error && <p className="error-text">{error}</p>}
      </section>

      {shown.length === 0 ? (
        <section className="card">
          <p className="placeholder">
            {candidates.length === 0
              ? "Nothing suggested yet."
              : "Everything suggested has been decided."}
          </p>
          {candidates.length === 0 && (
            <p className="muted small">
              A value is only offered when it <em>varies</em> where an identifier
              would: two requests differing in one path segment, or one parameter. A
              single request cannot show that, so capture a little more traffic and
              analyze again.
            </p>
          )}
        </section>
      ) : (
        <section className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Value</th>
                  <th>Where</th>
                  <th>Seen</th>
                  <th>Strength</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {shown.map((candidate) => (
                  <Row
                    key={candidate.id}
                    candidate={candidate}
                    expanded={open === candidate.id}
                    busy={busy}
                    onToggle={() =>
                      setOpen(open === candidate.id ? null : candidate.id)
                    }
                    onDecide={(status) =>
                      void run(() => decideCandidate(candidate.id, status))
                    }
                  />
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

function Row({
  candidate,
  expanded,
  busy,
  onToggle,
  onDecide,
}: {
  candidate: CandidateView;
  expanded: boolean;
  busy: boolean;
  onToggle: () => void;
  onDecide: (status: "accepted" | "rejected") => void;
}) {
  return (
    <>
      <tr className={expanded ? "open" : undefined}>
        {/* The value is not truncated and is shown in the same font the request
            panes use: a candidate that reads differently here than it did on the
            wire is a candidate you cannot replay. */}
        <td className="mono wrap">{candidate.value}</td>
        <td>{candidate.location}</td>
        <td>
          {candidate.occurrences}
          {candidate.live_observations < candidate.occurrences && (
            <span className="muted small">
              {" "}
              ({candidate.live_observations} still here)
            </span>
          )}
        </td>
        <td>
          <span className="chip">
            {candidate.strength} · {candidate.score}
          </span>
        </td>
        <td>{candidate.status}</td>
        <td className="actions">
          <button className="link" onClick={onToggle}>
            {expanded ? "hide why" : "why?"}
          </button>
          {candidate.status === "proposed" && (
            <>
              <button disabled={busy} onClick={() => onDecide("accepted")}>
                Accept
              </button>
              <button disabled={busy} onClick={() => onDecide("rejected")}>
                Reject
              </button>
            </>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="reasons">
          <td colSpan={6}>
            {/* A score of 25 that cannot be argued with is a score nobody trusts.
                The signs are printed because a reason arguing against is as useful
                as one arguing for. */}
            <table className="signals">
              <tbody>
                {candidate.signals.map((signal, index) => (
                  <tr key={index}>
                    <td className={signal.weight < 0 ? "weight against" : "weight"}>
                      {signal.weight > 0 ? `+${signal.weight}` : signal.weight}
                    </td>
                    <td>{signal.kind}</td>
                    <td className="muted">{signal.detail}</td>
                  </tr>
                ))}
                <tr>
                  <td className="weight">{candidate.score}</td>
                  <td colSpan={2}>total</td>
                </tr>
              </tbody>
            </table>
            {candidate.source_request && (
              <p className="muted small mono">
                first seen in {candidate.source_request}
              </p>
            )}
            <p className="muted small">
              Accepting records that this is an identifier. It declares no object and
              names no owner — to say who it belongs to, declare it on the
              Authorization tab.
            </p>
          </td>
        </tr>
      )}
    </>
  );
}

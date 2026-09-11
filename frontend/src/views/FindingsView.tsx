import { useCallback, useEffect, useState } from "react";

import {
  describeError,
  findingDetail,
  findingReproduction,
  listFindings,
  triageFinding,
  type FindingDetail,
  type FindingRow,
  type ReproductionView,
} from "../ipc";

const PAGE_SIZE = 200;

/**
 * The finding, as steps somebody can run.
 *
 * Compiled on demand rather than with the finding: most of the time a reader wants
 * the claim and the evidence, and building a reproduction means reading every cited
 * exchange back out of the project.
 *
 * Every credential is a placeholder — replaced when the reproduction was compiled,
 * not when it is displayed, so this component could not show one if it tried.
 */
function Reproduce({
  id,
  onOpenExchange,
}: {
  id: string;
  onOpenExchange: (id: string) => void;
}) {
  const [poc, setPoc] = useState<ReproductionView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Cleared when the selected finding changes, so the panel never shows one
  // finding's steps under another's title.
  useEffect(() => {
    setPoc(null);
    setError(null);
  }, [id]);

  async function compile() {
    setBusy(true);
    setError(null);
    try {
      setPoc(await findingReproduction(id));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (poc === null) {
    return (
      <div className="row wrap">
        <button onClick={() => void compile()} disabled={busy}>
          {busy ? "Compiling…" : "Compile a reproduction"}
        </button>
        <span className="muted small">
          Built from the exchanges this finding cites, with every credential replaced
          by a placeholder.
        </span>
        {error && <p className="error-text">{error}</p>}
      </div>
    );
  }

  return (
    <div className="poc">
      {poc.placeholders.length > 0 && (
        <>
          <p className="muted small">
            Supply these first — Hexora never puts a real credential in a
            reproduction:
          </p>
          <ul className="delta">
            {poc.placeholders.map((placeholder) => (
              <li key={placeholder.token}>
                <span className="mono">{placeholder.token}</span>{" "}
                {placeholder.identity ? `${placeholder.identity}'s ` : ""}
                {placeholder.header} header, {placeholder.bytes} bytes as sent
              </li>
            ))}
          </ul>
        </>
      )}

      <ol className="claims">
        {poc.steps.map((step) => (
          <li key={step.number}>
            {/* Numbered in the text: `.claims` drops list markers, and a
                reproduction whose steps read as an unordered pile is one somebody
                runs in the wrong order. */}
            <p>
              <strong>{step.number}.</strong> {step.heading}
            </p>
            {step.curl && <pre className="body">{step.curl}</pre>}
            {step.curl_refused && (
              /* Said rather than omitted: an absent command with no explanation
                 reads as a missing feature rather than as the point. */
              <p className="muted small">
                No curl equivalent — {step.curl_refused}. Send the raw form below.
              </p>
            )}
            {step.raw && <pre className="body">{step.raw}</pre>}
            {step.expect && (
              <p className="muted small">
                <strong>Expect:</strong> {step.expect}
              </p>
            )}
            <button className="link" onClick={() => onOpenExchange(step.request)}>
              open the exchange
            </button>
          </li>
        ))}
      </ol>

      {poc.caveats.map((caveat, index) => (
        <p key={index} className="notice">
          {caveat}
        </p>
      ))}
    </div>
  );
}

const TRIAGE_STATES = [
  "new",
  "triaged",
  "confirmed",
  "false-positive",
  "duplicate",
  "reported",
  "fixed",
  "accepted",
] as const;

/**
 * What the project claims, and how firmly.
 *
 * Ordered the way a tester triages: worst first, and within a severity the
 * established ones before the leads. Confidence sits next to severity rather than
 * being folded into it — "how bad if true" and "how sure are we" are different
 * questions, and a tool that merges them is why people stop believing tool output.
 */
export function FindingsView({
  hasProject,
  refreshToken,
  onOpenExchange,
}: {
  hasProject: boolean;
  /** Changes when a run files something, prompting a reload. */
  refreshToken: number;
  onOpenExchange: (id: string) => void;
}) {
  const [rows, setRows] = useState<FindingRow[]>([]);
  const [total, setTotal] = useState(0);
  const [actionable, setActionable] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    if (!hasProject) return;
    try {
      const page = await listFindings({
        severity: null,
        status: null,
        actionable,
        after: null,
        limit: PAGE_SIZE,
      });
      setRows(page.rows);
      setTotal(page.total);
      setError(null);
    } catch (e) {
      setError(describeError(e));
    }
  }, [hasProject, actionable]);

  useEffect(() => {
    void reload();
  }, [reload, refreshToken]);

  useEffect(() => {
    if (selected === null) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    findingDetail(selected)
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch((e) => {
        if (!cancelled) setError(describeError(e));
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  async function triage(id: string, status: string) {
    try {
      await triageFinding(id, status);
      await reload();
      const refreshed = await findingDetail(id);
      setDetail(refreshed);
    } catch (e) {
      setError(describeError(e));
    }
  }

  if (!hasProject) {
    return <p className="placeholder">Open a project to see its findings.</p>;
  }

  const leads = rows.filter((row) => !row.actionable).length;

  return (
    <div className="findings">
      <div className="toolbar">
        <label className="checkbox">
          <input
            type="checkbox"
            checked={actionable}
            onChange={(e) => setActionable(e.target.checked)}
          />
          <span>Established issues only</span>
        </label>
        <span className="muted">
          {rows.length.toLocaleString()} of {total.toLocaleString()}
        </span>
        <button onClick={() => void reload()}>Reload</button>
      </div>

      {error && <p className="error-text">{error}</p>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>Title</th>
              <th className="numeric">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.id}
                className={row.id === selected ? "selected" : ""}
                onClick={() => setSelected(row.id)}
              >
                <td>
                  <span className={`badge sev-${row.severity}`}>
                    {row.severity}
                  </span>
                </td>
                <td className={row.actionable ? "" : "muted"}>
                  {row.confidence}
                </td>
                <td className="muted">{row.status}</td>
                <td>{row.title}</td>
                <td className="numeric">{row.evidence_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && (
          <p className="placeholder">
            {total === 0
              ? "Nothing recorded yet. Run an authorization matrix from History."
              : "Nothing matches that filter."}
          </p>
        )}
      </div>

      {/* Said once, at the bottom, rather than marked on every row: the distinction
          matters and a repeated warning is one people learn to skip. */}
      {leads > 0 && (
        <p className="muted small">
          {leads} of these are leads, not established issues. They need verifying
          before they go in a report.
        </p>
      )}

      {detail && (
        <Detail
          detail={detail}
          onTriage={(status) => void triage(detail.row.id, status)}
          onOpenExchange={onOpenExchange}
        />
      )}
    </div>
  );
}

/**
 * One finding in full — the answer to "why is this a finding?".
 *
 * Every claim ends in the exchanges it rests on, and those are buttons: a finding
 * whose evidence cannot be opened is a finding nobody can check.
 */
function Detail({
  detail,
  onTriage,
  onOpenExchange,
}: {
  detail: FindingDetail;
  onTriage: (status: string) => void;
  onOpenExchange: (id: string) => void;
}) {
  const tags = [detail.cwe, detail.owasp, detail.cvss, detail.location].filter(
    (tag): tag is string => tag !== null,
  );

  return (
    <div className="detail">
      <header className="detail-header">
        <span>
          <span className={`badge sev-${detail.row.severity}`}>
            {detail.row.severity}
          </span>{" "}
          <strong>{detail.row.title}</strong>
        </span>
        <span className="muted">
          {detail.row.confidence} · first seen {detail.created_at}
        </span>
      </header>

      {tags.length > 0 && <p className="muted small">{tags.join(" · ")}</p>}

      <p>{detail.description}</p>

      <dl className="facts">
        <dt>Impact</dt>
        <dd>{detail.impact}</dd>
        <dt>Remediation</dt>
        <dd>{detail.remediation}</dd>
      </dl>

      <h3>Reproduction</h3>
      <pre className="body">{detail.reproduction}</pre>

      <Reproduce id={detail.row.id} onOpenExchange={onOpenExchange} />

      <h3>Evidence</h3>
      {detail.evidence.length === 0 ? (
        <p className="muted">
          None attached, so this claim is a lead only. Nothing above “reported”
          confidence can reach this state.
        </p>
      ) : (
        <ul className="evidence">
          {detail.evidence.map((item, index) => (
            <li key={index}>
              <p>{item.summary}</p>
              <div className="row">
                {item.requests.map((id) => (
                  <button
                    key={id}
                    className="link"
                    onClick={() => onOpenExchange(id)}
                  >
                    open {id.slice(0, 12)}…
                  </button>
                ))}
              </div>
            </li>
          ))}
        </ul>
      )}

      <h3>Triage</h3>
      <p className="muted small">
        A decision recorded here survives the test being run again: re-running
        refreshes the claim and leaves the judgement alone.
      </p>
      <div className="row wrap">
        {TRIAGE_STATES.map((state) => (
          <button
            key={state}
            className={detail.row.status === state ? "active" : ""}
            onClick={() => onTriage(state)}
          >
            {state}
          </button>
        ))}
      </div>
    </div>
  );
}

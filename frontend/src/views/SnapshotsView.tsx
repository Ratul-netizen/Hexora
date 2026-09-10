import { useCallback, useEffect, useState } from "react";

import {
  compareSnapshots,
  deleteSnapshot,
  describeError,
  listSnapshots,
  takeSnapshot,
  type ClaimChange,
  type Comparison,
  type SnapshotView,
} from "../ipc";

/**
 * What the engagement looked like then, and what changed since.
 *
 * Every other store in a project is live: findings are refreshed in place when a test
 * is re-run, candidates re-scored, scope edited. That is what a working project needs
 * and exactly what a retest cannot use — so a snapshot is a copy, taken by hand,
 * that a later run cannot rewrite.
 *
 * The word this view will not print is *fixed*. A finding is what a test produced;
 * its absence from a later snapshot is the absence of a result. Every disappearance
 * is shown with the reason it is missing, and only one of the three reasons is about
 * the application at all.
 */
export function SnapshotsView({ hasProject }: { hasProject: boolean }) {
  const [snapshots, setSnapshots] = useState<SnapshotView[]>([]);
  const [label, setLabel] = useState("");
  const [note, setNote] = useState("");
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [against, setAgainst] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      setSnapshots(await listSnapshots());
      setError(null);
    } catch (e) {
      setError(describeError(e));
    }
  }, []);

  useEffect(() => {
    if (hasProject) void reload();
  }, [hasProject, reload]);

  async function run<T>(work: () => Promise<T>, then: (value: T) => void) {
    setBusy(true);
    setError(null);
    try {
      then(await work());
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (!hasProject) {
    return <p className="placeholder">Open a project to record where it stands.</p>;
  }

  return (
    <div className="snapshots">
      <section className="card">
        <h2>Snapshots</h2>
        <p className="muted">
          A consultant tests, the client fixes, the consultant comes back — and the
          only question on the second visit is what changed. Take one before the fixes
          start. The traffic itself is not copied: a snapshot is a record to compare
          against, not a backup.
        </p>

        <div className="toolbar">
          <input
            type="text"
            value={label}
            placeholder="before the fix"
            onChange={(e) => setLabel(e.target.value)}
          />
          <input
            type="text"
            value={note}
            placeholder="note (optional)"
            onChange={(e) => setNote(e.target.value)}
          />
          <button
            disabled={busy}
            onClick={() =>
              void run(
                () => takeSnapshot(label.trim() || null, note.trim() || null),
                (rows) => {
                  setSnapshots(rows);
                  setLabel("");
                  setNote("");
                },
              )
            }
          >
            {busy ? "Recording…" : "Take a snapshot"}
          </button>
        </div>

        {error && <p className="error-text">{error}</p>}
      </section>

      {snapshots.length === 0 ? (
        <section className="card">
          <p className="placeholder">No snapshots yet.</p>
          <p className="muted small">
            A snapshot is what makes a retest answerable. Without one there is nothing
            for the next visit to compare against, because everything else in the
            project moves.
          </p>
        </section>
      ) : (
        <section className="card">
          <label className="field">
            <span>Compare against</span>
            <select value={against} onChange={(e) => setAgainst(e.target.value)}>
              {/* The default, because it is the comparison a retest actually asks and
                  it must not require saving a second snapshot first. */}
              <option value="">the project as it stands</option>
              {snapshots.map((snapshot) => (
                <option key={snapshot.id} value={snapshot.id}>
                  {snapshot.label}
                </option>
              ))}
            </select>
          </label>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Taken</th>
                  <th>Findings</th>
                  <th>Exchanges</th>
                  <th>Tool</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {snapshots.map((snapshot) => (
                  <tr key={snapshot.id}>
                    <td>
                      {snapshot.label}
                      {snapshot.note && (
                        <div className="muted small">{snapshot.note}</div>
                      )}
                    </td>
                    <td>{new Date(snapshot.taken_at).toLocaleString()}</td>
                    <td>{snapshot.findings}</td>
                    <td>{snapshot.exchanges}</td>
                    <td className="mono small">{snapshot.tool_version}</td>
                    <td className="actions">
                      <button
                        disabled={busy}
                        onClick={() =>
                          void run(
                            () =>
                              compareSnapshots(snapshot.id, against || null),
                            setComparison,
                          )
                        }
                      >
                        Compare
                      </button>
                      <button
                        className="link"
                        disabled={busy}
                        onClick={() =>
                          void run(() => deleteSnapshot(snapshot.id), (rows) => {
                            setSnapshots(rows);
                            setComparison(null);
                          })
                        }
                      >
                        delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

        </section>
      )}

      {comparison && <ComparisonPanel comparison={comparison} />}
    </div>
  );
}

function ComparisonPanel({ comparison }: { comparison: Comparison }) {
  const appeared = comparison.findings.filter(
    (c) => c.change.kind === "appeared",
  );
  const gone = comparison.findings.filter((c) => c.change.kind === "gone");
  const changed = comparison.findings.filter((c) => c.change.kind === "changed");
  const untested = comparison.findings.filter(
    (c) => c.change.kind === "unchanged" && !c.change.restated,
  );
  const reconfirmed = comparison.findings.filter(
    (c) => c.change.kind === "unchanged" && c.change.restated,
  );

  const nothing =
    appeared.length === 0 &&
    gone.length === 0 &&
    changed.length === 0 &&
    untested.length === 0;

  return (
    <section className="card">
      <h2>
        {comparison.from.label} → {comparison.to.label}
      </h2>
      <p className="muted small">
        {new Date(comparison.from.taken_at).toLocaleString()} →{" "}
        {new Date(comparison.to.taken_at).toLocaleString()}
      </p>

      {!comparison.same_tool && (
        /* Printed before anything it undermines, because it undermines all of it. */
        <p className="notice">
          Different builds took these ({comparison.from.tool_version} →{" "}
          {comparison.to.tool_version}). A claim that stopped appearing could be the
          application or could be Hexora, and nothing here can tell them apart.
        </p>
      )}

      {nothing && (
        <p className="muted">
          {reconfirmed.length > 0
            ? `Nothing moved. ${reconfirmed.length} claim(s) were re-tested and still stand.`
            : "Nothing changed."}
        </p>
      )}

      <Group title="Appeared" rows={appeared} />
      <Group title="Gone" rows={gone} />
      <Group title="Changed" rows={changed} />
      <Group
        title="Standing, but nothing re-tested them"
        rows={untested}
        footnote="Nothing wrote to these between the two snapshots. They are standing on evidence gathered before the earlier one, so they are neither confirmed still-present nor shown to be gone. Re-run the tests that raised them."
      />
      <Group title="Re-tested and unchanged" rows={reconfirmed} />

      {(comparison.scope.added.length > 0 ||
        comparison.scope.removed.length > 0) && (
        <>
          <h3>Scope</h3>
          <ul className="delta">
            {comparison.scope.added.map((line, i) => (
              <li key={`a${i}`} className="added">
                + {line.excluded ? "exclude" : "include"} {describeRule(line.rule)}
              </li>
            ))}
            {comparison.scope.removed.map((line, i) => (
              <li key={`r${i}`} className="removed">
                − {line.excluded ? "exclude" : "include"} {describeRule(line.rule)}
              </li>
            ))}
          </ul>
          {comparison.scope.removed.length > 0 && (
            <p className="muted small">
              A host that left scope stopped being tested. That is not the same as
              having been fixed.
            </p>
          )}
        </>
      )}

      <SetDelta title="Identities" change={comparison.identities} />
      <SetDelta title="Declared objects" change={comparison.objects} />

      <h3>Volumes</h3>
      <ul className="delta">
        <CountRow label="exchanges" count={comparison.counts.exchanges} />
        <CountRow label="suggestions" count={comparison.counts.candidates} />
        <CountRow label="findings" count={comparison.counts.findings} />
      </ul>
    </section>
  );
}

function Group({
  title,
  rows,
  footnote,
}: {
  title: string;
  rows: ClaimChange[];
  footnote?: string;
}) {
  if (rows.length === 0) return null;
  return (
    <>
      <h3>
        {title} ({rows.length})
      </h3>
      <ul className="claims">
        {rows.map((row, index) => (
          <li key={index}>
            <span className="mono small">{badge(row)}</span> {row.claim.title}
            {row.change.kind === "gone" && (
              /* The reason, every time. A "gone" list without it is a fix report. */
              <div className="muted small">{explain(row)}</div>
            )}
            {row.change.kind === "changed" && (
              <div className="muted small">
                was {state(row.change.before)} → now {state(row.change.after)}
              </div>
            )}
          </li>
        ))}
      </ul>
      {footnote && <p className="muted small">{footnote}</p>}
    </>
  );
}

function SetDelta({
  title,
  change,
}: {
  title: string;
  change: { added: string[]; removed: string[] };
}) {
  if (change.added.length === 0 && change.removed.length === 0) return null;
  return (
    <>
      <h3>{title}</h3>
      <ul className="delta">
        {change.added.map((value) => (
          <li key={`a${value}`} className="added">
            + {value}
          </li>
        ))}
        {change.removed.map((value) => (
          <li key={`r${value}`} className="removed">
            − {value}
          </li>
        ))}
      </ul>
    </>
  );
}

function CountRow({
  label,
  count,
}: {
  label: string;
  count: { before: number; after: number };
}) {
  const delta = count.after - count.before;
  if (delta === 0) return null;
  return (
    <li className={delta > 0 ? "added" : "removed"}>
      {label} {count.before} → {count.after} ({delta > 0 ? "+" : ""}
      {delta})
    </li>
  );
}

function badge(row: ClaimChange): string {
  switch (row.change.kind) {
    case "appeared":
    case "unchanged":
      return state(row.change.state);
    case "changed":
      return state(row.change.after);
    case "gone":
      return state(row.change.before);
  }
}

function state(value: { severity: string; confidence: string }): string {
  return `[${value.severity}/${value.confidence}]`;
}

function explain(row: ClaimChange): string {
  if (row.change.kind !== "gone") return "";
  switch (row.change.because.kind) {
    case "not_reproduced":
      return "not reproduced — the same check ran and did not raise it again. That is not proof it is fixed.";
    case "source_silent":
      return 'inconclusive — nothing from that check appears in the later snapshot, and Hexora cannot tell "ran and found nothing" from "never ran".';
    case "tool_changed":
      return `inconclusive — the snapshots were taken by different builds (${row.change.because.from} → ${row.change.because.to}).`;
  }
}

function describeRule(rule: {
  host: string;
  ports: number[];
  path: { kind?: string; value?: string };
}): string {
  const ports = rule.ports.length > 0 ? `:${rule.ports.join(",")}` : "";
  const path = rule.path?.value ?? "";
  return `${rule.host}${ports}${path}`;
}

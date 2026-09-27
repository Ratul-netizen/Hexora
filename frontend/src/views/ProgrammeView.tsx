import { useEffect, useState } from "react";

import {
  describeError,
  headerAdd,
  headerList,
  headerRemove,
  programmeAllow,
  programmeExclude,
  programmeSet,
  programmeShow,
  type AttachedHeader,
  type Programme,
} from "../ipc";

/**
 * The engagement's terms: the headers every request carries (bug-bounty identification) and the
 * programme rules — its name, policy URL, and the finding classes it will not accept.
 *
 * An excluded class is still looked for and still listed; it is only kept out of the filed
 * findings, because a run that files forty rejected classes is a run whose output gets skipped.
 */
export function ProgrammeView({ hasProject }: { hasProject: boolean }) {
  const [headers, setHeaders] = useState<AttachedHeader[]>([]);
  const [programme, setProgramme] = useState<Programme | null>(null);
  const [headerInput, setHeaderInput] = useState("");
  const [name, setName] = useState("");
  const [policyUrl, setPolicyUrl] = useState("");
  const [exDetector, setExDetector] = useState("");
  const [exReason, setExReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!hasProject) return;
    headerList().then(setHeaders).catch((e) => setError(describeError(e)));
    programmeShow()
      .then((p) => {
        setProgramme(p);
        setName(p.name ?? "");
        setPolicyUrl(p.policy_url ?? "");
      })
      .catch((e) => setError(describeError(e)));
  }, [hasProject]);

  if (!hasProject) {
    return <p className="placeholder">Open a project to set its engagement terms.</p>;
  }

  const guard = (p: Promise<void>) => p.catch((e) => setError(describeError(e)));

  return (
    <div className="programme">
      <section className="card">
        <h2>Attached headers</h2>
        <p className="muted">
          Put on every request Nullhawk sends — the scanner's probes, the intruder, every replay.
          Bug-bounty programmes require researchers to identify their traffic (e.g.{" "}
          <code>X-HackerOne-Research: username</code>); traffic that cannot be told from an
          attacker's is treated like one.
        </p>
        <div className="row">
          <input
            type="text"
            className="query"
            placeholder="X-HackerOne-Research: your-username"
            value={headerInput}
            onChange={(e) => setHeaderInput(e.target.value)}
          />
          <button
            className="primary"
            disabled={headerInput.trim() === ""}
            onClick={() =>
              guard(
                (async () => {
                  setError(null);
                  setHeaders(await headerAdd(headerInput.trim()));
                  setHeaderInput("");
                })(),
              )
            }
          >
            Add
          </button>
        </div>
        {headers.length === 0 ? (
          <p className="muted small">No attached headers.</p>
        ) : (
          <table className="grid">
            <tbody>
              {headers.map((h) => (
                <tr key={h.name}>
                  <td>
                    <code>
                      {h.name}: {h.value}
                    </code>
                  </td>
                  <td>
                    <button
                      className="secondary"
                      onClick={() =>
                        guard(
                          (async () => {
                            setError(null);
                            setHeaders(await headerRemove(h.name));
                          })(),
                        )
                      }
                    >
                      ✕
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {error && <p className="callout danger">{error}</p>}

      <section className="card">
        <h2>Programme</h2>
        <div className="row">
          <label className="field grow">
            <span>Name (for the report header)</span>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="field grow">
            <span>Policy URL</span>
            <input type="text" value={policyUrl} onChange={(e) => setPolicyUrl(e.target.value)} />
          </label>
          <button
            className="secondary"
            onClick={() =>
              guard(
                (async () => {
                  setError(null);
                  setProgramme(await programmeSet(name.trim() || null, policyUrl.trim() || null));
                })(),
              )
            }
          >
            Save
          </button>
        </div>

        <h3 className="muted">Excluded finding classes</h3>
        <p className="muted small">
          Still looked for and listed — just not filed. Give the detector id (see the Scan tab)
          and the reason the programme states.
        </p>
        <div className="row">
          <input
            type="text"
            placeholder="detector id, e.g. disclosure.headers"
            value={exDetector}
            onChange={(e) => setExDetector(e.target.value)}
          />
          <input
            type="text"
            className="query"
            placeholder="reason (required)"
            value={exReason}
            onChange={(e) => setExReason(e.target.value)}
          />
          <button
            className="primary"
            disabled={exDetector.trim() === "" || exReason.trim() === ""}
            onClick={() =>
              guard(
                (async () => {
                  setError(null);
                  setProgramme(await programmeExclude(exDetector.trim(), exReason.trim()));
                  setExDetector("");
                  setExReason("");
                })(),
              )
            }
          >
            Exclude
          </button>
        </div>
        {programme && programme.exclusions.length === 0 ? (
          <p className="muted small">No exclusions — every finding class is reported.</p>
        ) : (
          <table className="grid">
            <tbody>
              {programme?.exclusions.map((ex) => (
                <tr key={ex.detector}>
                  <td>
                    <code>{ex.detector}</code>
                    <div className="muted small">{ex.reason}</div>
                  </td>
                  <td>
                    <button
                      className="secondary"
                      onClick={() =>
                        guard(
                          (async () => {
                            setError(null);
                            setProgramme(await programmeAllow(ex.detector));
                          })(),
                        )
                      }
                    >
                      allow
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

import { useEffect, useState } from "react";

import { MessagePane } from "../components/MessagePane";
import {
  branchesOf,
  describeError,
  loadDraft,
  sendDraft,
  type DiffView,
  type HistoryRow,
  type RequestMode,
  type SendResult,
} from "../ipc";

/**
 * Edit a captured request and send it again.
 *
 * The editor is a plain textarea holding the request as text. A structured form would
 * have to decide what a header "should" look like, and the value of this panel is
 * that it decides as little as possible.
 *
 * # Structured and raw are not the same promise
 *
 * In **structured** mode the text is parsed into a message and that message is sent.
 * Almost everything survives — header order, casing, duplicates, a `Content-Length`
 * that disagrees with the body — but the message is *serialized*, so bare LF line
 * endings go out as CRLF and framing headers may be added where they were missing.
 * The warning list says so when it applies.
 *
 * In **raw** mode the bytes are sent exactly as typed. Nothing is parsed on the way
 * out, nothing is added, nothing is corrected.
 *
 * The difference is small and it is the whole reason this panel exists, so it is a
 * switch a person operates rather than something the editor infers.
 */
export function RepeaterView({
  requestId,
  onCaptured,
}: {
  requestId: string | null;
  /** Called after a send, so history can pick up the new exchange. */
  onCaptured: () => void;
}) {
  const [raw, setRaw] = useState("");
  const [url, setUrl] = useState("");
  const [warnings, setWarnings] = useState<string[]>([]);
  const [result, setResult] = useState<SendResult | null>(null);
  const [branches, setBranches] = useState<HistoryRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [insecure, setInsecure] = useState(false);
  const [mode, setMode] = useState<RequestMode>("structured");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (requestId === null) return;
    let cancelled = false;

    setResult(null);
    setError(null);
    loadDraft(requestId)
      .then((draft) => {
        if (cancelled) return;
        setRaw(draft.raw);
        setUrl(draft.url);
        setWarnings(draft.warnings);
        // A request that was captured raw comes back raw. Loading it as structured
        // would offer to send something else under the same name.
        setMode(draft.mode);
      })
      .catch((e) => {
        if (!cancelled) setError(describeError(e));
      });

    branchesOf(requestId)
      .then((rows) => {
        if (!cancelled) setBranches(rows);
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
    };
  }, [requestId]);

  async function send() {
    if (requestId === null) return;
    setBusy(true);
    setError(null);
    try {
      const sent = await sendDraft(raw, requestId, insecure, mode);
      setResult(sent);
      setWarnings(sent.warnings);
      setBranches(await branchesOf(requestId));
      onCaptured();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (requestId === null) {
    return (
      <p className="placeholder">
        Select an exchange in History and choose “Send to repeater”.
      </p>
    );
  }

  return (
    <div className="repeater">
      <div className="repeater-editor">
        <header className="detail-header">
          <span className="mono">{url}</span>
          <div className="modes">
            {(["structured", "raw"] as const).map((option) => (
              <button
                key={option}
                className={mode === option ? "tab active" : "tab"}
                onClick={() => setMode(option)}
              >
                {option === "structured" ? "Structured" : "Raw"}
              </button>
            ))}
          </div>
          <label className="checkbox inline">
            <input
              type="checkbox"
              checked={insecure}
              onChange={(e) => setInsecure(e.target.checked)}
            />
            <span>Ignore certificate errors</span>
          </label>
          <button onClick={() => void send()} disabled={busy}>
            {busy ? "Sending…" : "Send"}
          </button>
        </header>

        {/* Said above the editor rather than in the warning list, because it changes
            what every other line of that list means. */}
        <p className={mode === "raw" ? "notice warn" : "muted small"}>
          {mode === "raw"
            ? "Raw: these bytes are sent exactly as typed. Nothing is parsed, added or corrected — including the line endings."
            : "Structured: the text is parsed and the message re-serialized, so bare LF becomes CRLF and missing framing may be added. Switch to Raw to send bytes untouched."}
        </p>

        <textarea
          className="editor"
          value={raw}
          spellCheck={false}
          onChange={(e) => setRaw(e.target.value)}
        />

        {warnings.length > 0 && (
          // Reported, never corrected. Several of these are the point of the
          // request — a tool that silently fixed them would turn a smuggling test
          // into a test of the tool.
          <div className="warnings">
            <strong>
              {mode === "raw"
                ? "Sent exactly as written:"
                : "Reported, not corrected:"}
            </strong>
            <ul>
              {warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </div>
        )}

        {branches.length > 0 && (
          <div className="branches">
            <strong>{branches.length} variant{branches.length === 1 ? "" : "s"} of this request</strong>
            <ul>
              {branches.map((branch) => (
                <li key={branch.id}>
                  <span className="mono">{branch.method}</span>{" "}
                  <span className="mono">{branch.status ?? "—"}</span>{" "}
                  {branch.url}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div className="repeater-result">
        {error && <p className="error-text">{error}</p>}

        {result && (
          <>
            {result.out_of_scope && (
              <p className="notice">This target is not in the project scope.</p>
            )}
            {result.diff && <DiffSummary diff={result.diff} />}
            <MessagePane
              title={`Response · ${result.status} · ${result.duration_ms}ms`}
              head={result.response_head}
              body={result.response_body}
            />
          </>
        )}

        {!result && !error && (
          <p className="placeholder">Send the request to see the response here.</p>
        )}
      </div>
    </div>
  );
}

function DiffSummary({ diff }: { diff: DiffView }) {
  return (
    <section className={diff.interesting ? "diff interesting" : "diff"}>
      <header>
        <h3>Compared with the request it came from</h3>
        <span className={diff.interesting ? "tag interesting" : "tag"}>
          {diff.interesting ? "worth a look" : "nothing notable"}
        </span>
      </header>
      <p className="summary">{diff.summary}</p>

      <ul className="changes">
        {diff.status && (
          <li>
            status {diff.status[0]} → {diff.status[1]}
          </li>
        )}
        {diff.changed_headers.map(([name, before, after]) => (
          <li key={name}>
            <span className="mono">{name}</span>: {before} → {after}
          </li>
        ))}
        {diff.added_headers.map((name) => (
          <li key={`+${name}`}>
            + <span className="mono">{name}</span>
          </li>
        ))}
        {diff.removed_headers.map((name) => (
          <li key={`-${name}`}>
            − <span className="mono">{name}</span>
          </li>
        ))}
        {diff.first_difference_at !== null && (
          <li>body first differs at byte {diff.first_difference_at}</li>
        )}
        {/* Called out on its own: an identical response that arrived seconds later
            is the entire signal in a time-based blind injection, and burying it in
            the summary line would hide the finding. */}
        {diff.timing_significant && (
          <li className="timing">
            timing moved {diff.timing_delta_ms > 0 ? "+" : ""}
            {diff.timing_delta_ms}ms — worth checking against a time-based payload
          </li>
        )}
      </ul>
    </section>
  );
}

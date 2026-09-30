import { useEffect, useState } from "react";

import { MessagePane } from "../components/MessagePane";
import {
  branchesOf,
  describeError,
  loadDraft,
  newDraft,
  sendDraft,
  sendRawH2,
  type DiffView,
  type HistoryRow,
  type RequestMode,
  type SendResult,
} from "../ipc";

/** The repeater's three editing modes: h1 structured, h1 raw, and frame-level h2. */
type EditMode = RequestMode | "h2";

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
  seed,
  onCaptured,
}: {
  requestId: string | null;
  /** A URL to open as a fresh draft, e.g. from the site map. The nonce re-triggers it
      when the same URL is opened twice. */
  seed: { url: string; n: number } | null;
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
  const [mode, setMode] = useState<EditMode>("structured");
  const [busy, setBusy] = useState(false);

  // What a send derives from. `parent` is a stored request — a captured one, or the
  // first send of a request crafted from scratch, adopted so resends chain off it and
  // the diff has something to compare against. `target` is the URL a from-scratch draft
  // connects to until it has been sent once. Exactly one of them drives any given send.
  const [parent, setParent] = useState<string | null>(null);
  const [target, setTarget] = useState<string | null>(null);
  // Whether an editor is open. False shows the "new request" form.
  const [ready, setReady] = useState(false);
  const [newUrl, setNewUrl] = useState("");
  const [newMethod, setNewMethod] = useState("GET");

  useEffect(() => {
    if (requestId === null) return;
    let cancelled = false;

    setResult(null);
    setError(null);
    setTarget(null);
    setParent(requestId);
    loadDraft(requestId)
      .then((draft) => {
        if (cancelled) return;
        setRaw(draft.raw);
        setUrl(draft.url);
        setWarnings(draft.warnings);
        // A request that was captured raw comes back raw. Loading it as structured
        // would offer to send something else under the same name.
        setMode(draft.mode);
        setReady(true);
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

  // Seeded from elsewhere (the site map): open the given URL as a fresh draft, the same
  // way the "new request" form's Create does.
  useEffect(() => {
    if (!seed) return;
    let cancelled = false;
    setError(null);
    setNewUrl(seed.url);
    newDraft(seed.url, "GET")
      .then((draft) => {
        if (cancelled) return;
        setRaw(draft.raw);
        setUrl(draft.url);
        setWarnings(draft.warnings);
        setMode(draft.mode);
        setParent(null);
        setTarget(seed.url);
        setResult(null);
        setBranches([]);
        setReady(true);
      })
      .catch((e) => {
        if (!cancelled) setError(describeError(e));
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seed?.n]);

  async function create() {
    setError(null);
    try {
      const draft = await newDraft(newUrl, newMethod);
      setRaw(draft.raw);
      setUrl(draft.url);
      setWarnings(draft.warnings);
      setMode(draft.mode);
      // No stored request yet: the first send connects to the typed URL, and adopts
      // the request it produces as the parent for everything after.
      setParent(null);
      setTarget(newUrl);
      setResult(null);
      setBranches([]);
      setReady(true);
    } catch (e) {
      setError(describeError(e));
    }
  }

  /// Seeds the h2 editor with a template built from the current target, unless the text is
  /// already an h2 header list — so switching to h2 does not clobber edits already in it.
  function seedH2IfNeeded() {
    const firstField = raw.split("\n").find((line) => line.trim() !== "");
    if (firstField?.startsWith(":")) return;
    try {
      const parsed = new URL(url);
      const scheme = parsed.protocol.replace(":", "");
      const authority = parsed.host;
      const path = (parsed.pathname || "/") + (parsed.search || "");
      setRaw(
        `:method: GET\n:path: ${path}\n:scheme: ${scheme}\n:authority: ${authority}\n\n`,
      );
    } catch {
      // Leave the editor as-is if the URL cannot be parsed; the tester can write the list.
    }
  }

  async function send() {
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      if (mode === "h2") {
        // Frame-level h2 goes to its own path: the header list is sent as written, and
        // there is no diff or lineage — the request is not derived from another.
        const sent = await sendRawH2(raw, url, insecure);
        setResult(sent);
        setWarnings([]);
        onCaptured();
        return;
      }
      const sent = await sendDraft(raw, parent, target, insecure, mode);
      setResult(sent);
      setWarnings(sent.warnings);
      // The request to hang variants and the diff off: the existing parent, or — on the
      // first send of a from-scratch draft — the request that send just created.
      const root = parent ?? sent.id;
      if (parent === null) setParent(sent.id);
      setBranches(await branchesOf(root));
      onCaptured();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (!ready) {
    return (
      <div className="new-request">
        <h2>New request</h2>
        <p className="muted small">
          Craft a request to an endpoint you have not captured. The URL sets where it
          connects and the request line; every other byte is yours to edit before it is
          sent. Or select an exchange in History and choose “Send to repeater”.
        </p>
        <form
          className="new-request-form"
          onSubmit={(e) => {
            e.preventDefault();
            void create();
          }}
        >
          <select value={newMethod} onChange={(e) => setNewMethod(e.target.value)}>
            {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <input
            className="url-input"
            type="text"
            value={newUrl}
            placeholder="https://api.example.com/v1/users?id=1"
            onChange={(e) => setNewUrl(e.target.value)}
            autoFocus
          />
          <button type="submit" disabled={newUrl.trim() === ""}>
            Create
          </button>
        </form>
        {error && <p className="error-text">{error}</p>}
      </div>
    );
  }

  return (
    <div className="repeater">
      <div className="repeater-editor">
        <header className="detail-header">
          <span className="mono">{url}</span>
          <button
            className="tab"
            onClick={() => {
              setReady(false);
              setResult(null);
              setError(null);
            }}
            title="Start a request from scratch"
          >
            New
          </button>
          <div className="modes">
            {(["structured", "raw", "h2"] as const).map((option) => (
              <button
                key={option}
                className={mode === option ? "tab active" : "tab"}
                onClick={() => {
                  setMode(option);
                  if (option === "h2") seedH2IfNeeded();
                }}
              >
                {option === "structured"
                  ? "Structured"
                  : option === "raw"
                    ? "Raw"
                    : "H2 raw"}
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
          <button
            onClick={() => void send()}
            disabled={busy}
            title="Ctrl+Enter (⌘+Enter on macOS)"
          >
            {busy ? "Sending…" : "Send"}
          </button>
        </header>

        {/* Said above the editor rather than in the warning list, because it changes
            what every other line of that list means. */}
        <p className={mode === "raw" || mode === "h2" ? "notice warn" : "muted small"}>
          {mode === "raw"
            ? "Raw: these bytes are sent exactly as typed. Nothing is parsed, added or corrected — including the line endings."
            : mode === "h2"
              ? "H2 raw: one `name: value` per line (pseudo-headers included), a blank line, then the body. Each field is framed exactly as written — an uppercase name, a duplicate :path or a value with control bytes all go out unchanged, which is how you test what a conforming client refuses to send."
              : "Structured: the text is parsed and the message re-serialized, so bare LF becomes CRLF and missing framing may be added. Switch to Raw to send bytes untouched."}
        </p>

        <textarea
          className="editor"
          value={raw}
          spellCheck={false}
          onChange={(e) => setRaw(e.target.value)}
          // Ctrl+Enter (⌘+Enter on macOS) sends, the way every repeater a tester has
          // used already works. A plain Enter still inserts a newline, because editing
          // the request is most of what happens in this box.
          onKeyDown={(e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
              e.preventDefault();
              if (!busy) void send();
            }
          }}
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

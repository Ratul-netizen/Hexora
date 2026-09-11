import { useCallback, useEffect, useState } from "react";

import {
  addObject,
  describeError,
  listIdentities,
  listObjects,
  listScope,
  removeObject,
  runAuthz,
  type AttemptView,
  type CellView,
  type IdentityView,
  type MatrixView,
  type ObjectView,
  type ScopeView,
} from "../ipc";

/**
 * The authorization matrix: one captured request, replayed as everybody.
 *
 * The question is a table — identities down the side, what each of them got across
 * it — so the view is a table, and everything around it exists to keep the table
 * honest: the scope the run will be held to, the confirmation before a
 * state-changing replay, and the demotion notice when an anonymous control shows the
 * resource was public all along.
 */
export function AuthzView({
  requestId,
  onFindings,
  onOpenExchange,
}: {
  /** The request to replay, chosen in History. */
  requestId: string | null;
  /** Called after a run that wrote findings, so the findings tab can reload. */
  onFindings: () => void;
  /** Opens one of the recorded replays back in History. */
  onOpenExchange: (id: string) => void;
}) {
  const [identities, setIdentities] = useState<IdentityView[]>([]);
  const [objects, setObjects] = useState<ObjectView[]>([]);
  const [scope, setScope] = useState<ScopeView | null>(null);
  const [owner, setOwner] = useState("");
  const [anonymous, setAnonymous] = useState(true);
  const [verify, setVerify] = useState(false);
  const [insecure, setInsecure] = useState(false);
  const [save, setSave] = useState(true);
  const [construct, setConstruct] = useState(false);
  const [maxAttempts, setMaxAttempts] = useState(12);
  const [confirmed, setConfirmed] = useState(false);
  const [matrix, setMatrix] = useState<MatrixView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      const [people, declared, declaredObjects] = await Promise.all([
        listIdentities(),
        listScope(),
        listObjects(),
      ]);
      setIdentities(people);
      setScope(declared);
      setObjects(declaredObjects);
      setOwner((current) => current || (people[0]?.label ?? ""));
    } catch (e) {
      setError(describeError(e));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function run() {
    if (requestId === null) return;
    setBusy(true);
    setError(null);
    try {
      const result = await runAuthz({
        id: requestId,
        owner,
        identities: [],
        anonymous,
        verify,
        insecure,
        confirm_state_changing: confirmed,
        save,
        construct,
        max_attempts: maxAttempts,
      });
      setMatrix(result);
      if (result.saved + result.updated > 0) onFindings();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (requestId === null) {
    return (
      <p className="placeholder">
        Choose a request in History and press “Test authorization”. The matrix
        replays one captured request as every identity in the project, so it needs
        a request to start from.
      </p>
    );
  }

  const tooFew = identities.length < 2;
  const noScope = scope !== null && scope.included.length === 0;

  return (
    <div className="authz">
      <section className="card">
        <h2>Replay as everybody</h2>
        <p className="muted">
          The baseline is replayed, never reused: comparing a fresh response against
          a stored one produces differences that belong to time, not to
          authorization.
        </p>

        <label className="field">
          <span>The request belongs to</span>
          <select value={owner} onChange={(e) => setOwner(e.target.value)}>
            {identities.map((identity) => (
              <option key={identity.id} value={identity.label}>
                {identity.label} ({identity.privilege})
              </option>
            ))}
          </select>
          <span className="muted small">
            Everyone else in the project is replayed against it.
          </span>
        </label>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={anonymous}
            onChange={(e) => setAnonymous(e.target.checked)}
          />
          <span>
            Add an unauthenticated control
            <span className="muted small">
              {" "}
              — one extra request, and the difference between “User B can read User
              A’s data” and “that URL is public”.
            </span>
          </span>
        </label>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={verify}
            onChange={(e) => setVerify(e.target.checked)}
          />
          <span>
            Reproduce each violation before reporting it
            <span className="muted small">
              {" "}
              — the difference between a Tentative finding and a Confirmed one.
            </span>
          </span>
        </label>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={save}
            onChange={(e) => setSave(e.target.checked)}
          />
          <span>
            Write the findings into the project
            <span className="muted small">
              {" "}
              — a conclusion that lives only on screen cannot be cited later.
            </span>
          </span>
        </label>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={construct}
            onChange={(e) => setConstruct(e.target.checked)}
          />
          <span>
            Also construct cross-identity requests
            <span className="muted small">
              {" "}
              — a replay asks whether an identity can reach this URL. Substituting an
              identifier somebody else owns asks whether it can reach{" "}
              <em>their object</em>, which is the question a captured request usually
              cannot answer.
            </span>
          </span>
        </label>

        {construct && (
          <label className="field">
            <span>At most this many constructed requests</span>
            <input
              type="text"
              value={String(maxAttempts)}
              spellCheck={false}
              onChange={(e) =>
                setMaxAttempts(Math.max(1, Number(e.target.value) || 1))
              }
            />
            <span className="muted small">
              Every attempt is a real request at a real application.
            </span>
          </label>
        )}

        <label className="checkbox">
          <input
            type="checkbox"
            checked={insecure}
            onChange={(e) => setInsecure(e.target.checked)}
          />
          <span>
            Do not verify the target’s TLS certificate
            <span className="muted small"> — for staging targets.</span>
          </span>
        </label>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
          />
          <span>
            This request may change data, and I want it replayed anyway
            <span className="muted small">
              {" "}
              — a matrix over <span className="mono">DELETE /accounts/42</span> will
              delete account 42 once per identity. Hexora will do it if told; it
              will not do it by accident.
            </span>
          </span>
        </label>

        {construct && objects.length === 0 && (
          <p className="notice">
            No objects are declared, so there is nothing to construct a request for.
            Declare one below.
          </p>
        )}
        {noScope && (
          <p className="notice">
            This project has no scope. A matrix is automated traffic, and the guard
            refuses automated traffic to hosts nobody has declared — add the target
            under Setup first.
          </p>
        )}
        {tooFew && (
          <p className="notice">
            There is nobody to compare against. Add a second identity under Setup.
          </p>
        )}

        <div className="row">
          <button
            onClick={() => void run()}
            disabled={busy || tooFew || owner === ""}
          >
            {busy ? "Replaying…" : "Run the matrix"}
          </button>
          <span className="muted mono small">{requestId}</span>
        </div>

        {error && <p className="error-text">{error}</p>}
      </section>

      <ObjectsCard
        requestId={requestId}
        identities={identities}
        objects={objects}
        onChange={setObjects}
      />

      {matrix && <Result matrix={matrix} onOpenExchange={onOpenExchange} />}
      {matrix && (
        <ConstructedAttempts
          attempts={matrix.constructed}
          notConstructed={matrix.not_constructed}
          onOpenExchange={onOpenExchange}
        />
      )}
    </div>
  );
}
/**
 * The objects a tester has declared, and who owns them.
 *
 * Declaring is data entry — nothing is sent — and it is what turns "can User B reach
 * this URL?" into "can User B reach *User A's* invoice?". The location is discovered
 * from the request the value appears in, so nobody has to count path segments.
 */
function ObjectsCard({
  requestId,
  identities,
  objects,
  onChange,
}: {
  /** The request currently selected in History, offered as the place to look. */
  requestId: string;
  identities: IdentityView[];
  objects: ObjectView[];
  onChange: (objects: ObjectView[]) => void;
}) {
  const [value, setValue] = useState("");
  const [name, setName] = useState("object");
  const [owner, setOwner] = useState("");
  const [fromRequest, setFromRequest] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function add() {
    setBusy(true);
    setError(null);
    try {
      onChange(
        await addObject({
          value,
          owner: owner || (identities[0]?.label ?? ""),
          name,
          inRequest: fromRequest ? requestId : null,
        }),
      );
      setValue("");
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Declared objects</h2>
      <p className="muted">
        Which identifiers are objects, and whose they are. Hexora never guesses this:
        a value that looks like an id is not one, and a tool that assumed otherwise
        would send traffic at an endpoint on the strength of a guess. Declaring sends
        nothing.
      </p>

      <div className="row">
        <input
          type="text"
          value={value}
          placeholder="acct-1000"
          spellCheck={false}
          onChange={(e) => setValue(e.target.value)}
        />
        <input
          type="text"
          value={name}
          placeholder="account"
          spellCheck={false}
          onChange={(e) => setName(e.target.value)}
        />
        <select value={owner} onChange={(e) => setOwner(e.target.value)}>
          {identities.map((identity) => (
            <option key={identity.id} value={identity.label}>
              owned by {identity.label}
            </option>
          ))}
        </select>
        <button onClick={() => void add()} disabled={busy || value.trim() === ""}>
          {busy ? "…" : "Declare"}
        </button>
      </div>

      <label className="checkbox">
        <input
          type="checkbox"
          checked={fromRequest}
          onChange={(e) => setFromRequest(e.target.checked)}
        />
        <span>
          Find it in the selected request
          <span className="muted small">
            {" "}
            — records where the value actually sits. Without it the declaration keeps
            the value alone, and a run substitutes it wherever the sender’s own object
            is.
          </span>
        </span>
      </label>

      {error && <p className="error-text">{error}</p>}

      {objects.length === 0 ? (
        <p className="notice">
          Nothing declared, so there is nothing to construct a request for.
        </p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Object</th>
                <th>Value</th>
                <th>Owner</th>
                <th>Where</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {objects.map((object) => (
                <tr key={object.id}>
                  <td>{object.name}</td>
                  <td className="mono">{object.value}</td>
                  <td>{object.owner}</td>
                  <td className="muted small">{object.location}</td>
                  <td>
                    <button
                      className="link"
                      onClick={() =>
                        void removeObject(object.id)
                          .then(onChange)
                          .catch((e) => setError(describeError(e)))
                      }
                    >
                      remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/**
 * The requests that were built rather than replayed.
 *
 * Every row says what was substituted, because that is the whole claim: this request
 * never existed until Hexora made it, and a reader who cannot see the substitution
 * cannot check it.
 */
function ConstructedAttempts({
  attempts,
  notConstructed,
  onOpenExchange,
}: {
  attempts: AttemptView[];
  notConstructed: string[];
  onOpenExchange: (id: string) => void;
}) {
  if (attempts.length === 0 && notConstructed.length === 0) return null;

  return (
    <section className="card">
      <h2>Constructed attempts</h2>
      <p className="muted">
        These requests were not captured. Each one takes the object identifier out of
        the request and puts somebody else’s in its place.
      </p>

      {attempts.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Sender</th>
                <th>Asked for</th>
                <th>Substitution</th>
                <th>Status</th>
                <th className="numeric">Similarity</th>
                <th>Verdict</th>
              </tr>
            </thead>
            <tbody>
              {attempts.map((attempt, index) => (
                <tr
                  key={index}
                  className={attempt.violation ? "violation" : ""}
                  onClick={() => attempt.request && onOpenExchange(attempt.request)}
                >
                  <td>{attempt.sender}</td>
                  <td>
                    <span className="mono">{attempt.object_value}</span>
                    <span className="muted small"> ({attempt.owner}’s)</span>
                  </td>
                  <td className="mono small">{attempt.substitution}</td>
                  <td>{attempt.status ?? "—"}</td>
                  <td className="numeric">
                    {attempt.outcome === "denied"
                      ? "—"
                      : attempt.similarity.toFixed(2)}
                  </td>
                  <td>
                    <span
                      className={
                        attempt.violation ? "status client-error" : "status ok"
                      }
                    >
                      {attempt.verdict}
                    </span>
                    {attempt.reproduced && (
                      <span className="tag" title="a second attempt reproduced this">
                        reproduced
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {attempts
        .filter((a) => a.disclosed_object_ids.length > 0 || a.note !== null)
        .map((attempt, index) => (
          <p key={`note-${index}`} className="muted small">
            <strong>
              {attempt.sender} → {attempt.object_value}:
            </strong>{" "}
            {attempt.disclosed_object_ids.length > 0
              ? `the response carried ${attempt.disclosed_object_ids.join(", ")}, which ${attempt.sender} never sent`
              : attempt.note}
          </p>
        ))}

      {notConstructed.map((reason, index) => (
        <p key={`skip-${index}`} className="muted small">
          not constructed — {reason}
        </p>
      ))}
    </section>
  );
}


function Result({
  matrix,
  onOpenExchange,
}: {
  matrix: MatrixView;
  onOpenExchange: (id: string) => void;
}) {
  return (
    <section className="card">
      <h2>
        <span className="mono">
          {matrix.method} {matrix.url}
        </span>
      </h2>
      <p className="muted">
        Baseline: {matrix.owner.label} → {matrix.owner.status ?? "no response"}
      </p>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Identity</th>
              <th>Privilege</th>
              <th>Status</th>
              <th>Outcome</th>
              <th className="numeric">Similarity</th>
              <th>Verdict</th>
            </tr>
          </thead>
          <tbody>
            {matrix.cells.map((cell) => (
              <tr
                key={cell.identity}
                className={cell.violation ? "violation" : ""}
                onClick={() => cell.request && onOpenExchange(cell.request)}
              >
                <td>{cell.label}</td>
                <td className="muted">{cell.privilege}</td>
                <td>{cell.status ?? "—"}</td>
                <td>{cell.outcome}</td>
                <td className="numeric">{cell.similarity.toFixed(2)}</td>
                <td>
                  <span className={verdictClass(cell)}>{cell.verdict}</span>
                  {cell.verification && (
                    /* What the second experiment established, in its own words.
                       "reproduced" and "nothing re-ran this" used to look the same
                       here, because both were a missing tag. */
                    <span
                      className="tag"
                      title={cell.verification_note ?? undefined}
                    >
                      {cell.verification}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {matrix.appears_public && (
        <p className="notice">
          An unauthenticated request received the same resource, so this endpoint
          appears to be public. Per-identity results are inconclusive as a result —
          the finding, if there is one, is that it needs no session at all.
        </p>
      )}

      {matrix.cells
        .filter((cell) => cell.note !== null || cell.error !== null)
        .map((cell) => (
          <p key={`${cell.identity}-note`} className="muted small">
            <strong>{cell.label}:</strong> {cell.note ?? cell.error}
          </p>
        ))}

      <h3>
        {matrix.findings.length === 0
          ? "No authorization violations"
          : `${matrix.findings.length} candidate finding${matrix.findings.length === 1 ? "" : "s"}`}
      </h3>
      {matrix.findings.length === 0 ? (
        <p className="muted">
          Every identity got what it should have. That is a result about this
          request, not about the application.
        </p>
      ) : (
        <ul className="findings-brief">
          {matrix.findings.map((finding) => (
            <li key={finding.id}>
              <span className={`badge sev-${finding.severity}`}>
                {finding.severity}
              </span>{" "}
              <span className="muted small">{finding.confidence}</span>{" "}
              {finding.title}
            </li>
          ))}
        </ul>
      )}

      <p className="muted small">
        {matrix.saved + matrix.updated === 0
          ? "Nothing was written into the project."
          : `${matrix.saved} new, ${matrix.updated} updated in the project. Re-running a test refreshes a claim and leaves its triage decision alone.`}
      </p>
    </section>
  );
}

function verdictClass(cell: CellView): string {
  if (cell.violation) return "status client-error";
  if (cell.verdict === "inconclusive") return "muted";
  return "status ok";
}

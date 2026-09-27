import { useState } from "react";

import {
  describeError,
  graphqlParse,
  graphqlSend,
  importParse,
  importSend,
  type GraphqlOp,
  type ImportPreview,
  type ImportResult,
  type LicenseStatus,
} from "../ipc";

/**
 * Import an API description and turn it into traffic the scanner can work over. An API has no
 * HTML links for the crawler to follow; its spec is the map.
 *
 * - **OpenAPI 3.x / Swagger 2.0** (JSON or YAML): each operation becomes a request, path params
 *   filled and required query params appended.
 * - **GraphQL introspection** (JSON): each root field becomes a sendable query, required
 *   arguments filled and a `{ __typename }` selection where it returns an object.
 *
 * Preview first; nothing is sent until you press Send. Writes/mutations go only when included.
 */
type Kind = "openapi" | "graphql";

export function ImportView({
  hasProject,
  license,
}: {
  hasProject: boolean;
  license: LicenseStatus | null;
}) {
  const [kind, setKind] = useState<Kind>("openapi");
  const [spec, setSpec] = useState("");
  const [base, setBase] = useState("");
  const [includeWrites, setIncludeWrites] = useState(false);
  const [insecure, setInsecure] = useState(false);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [gqlOps, setGqlOps] = useState<GraphqlOp[] | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const free = (license?.tier ?? "Free") === "Free";
  const graphql = kind === "graphql";

  if (!hasProject) {
    return <p className="placeholder">Open a project to import an API spec into it.</p>;
  }

  function reset() {
    setPreview(null);
    setGqlOps(null);
    setResult(null);
    setError(null);
  }

  async function parse() {
    reset();
    try {
      if (graphql) {
        setGqlOps(await graphqlParse(spec));
      } else {
        setPreview(await importParse(spec, base.trim() === "" ? null : base.trim()));
      }
    } catch (e) {
      setError(describeError(e));
    }
  }

  async function send() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = graphql
        ? await graphqlSend({
            spec,
            url: base.trim(),
            includeMutations: includeWrites,
            insecure,
          })
        : await importSend({
            spec,
            base: base.trim() === "" ? null : base.trim(),
            includeWrites,
            insecure,
          });
      setResult(r);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  const openApiWrites = preview?.operations.filter((o) => !o.safe).length ?? 0;
  const gqlMutations = gqlOps?.filter((o) => o.mutation).length ?? 0;

  return (
    <div className="import">
      <section className="card">
        <h2>Import an API spec</h2>
        <p className="muted">
          Preview the operations, then send the safe ones through the scope guard and record them
          for scanning. Writes/mutations are sent only when included.
        </p>

        <div className="row">
          <label className="field">
            <span>Kind</span>
            <select
              value={kind}
              onChange={(e) => {
                setKind(e.target.value as Kind);
                reset();
              }}
            >
              <option value="openapi">OpenAPI / Swagger</option>
              <option value="graphql">GraphQL introspection</option>
            </select>
          </label>
          <label className="field grow">
            <span>{graphql ? "GraphQL endpoint URL" : "Base URL — override, or supply one the spec omits"}</span>
            <input
              type="text"
              placeholder={graphql ? "https://api.target.com/graphql" : "https://api.target.com"}
              value={base}
              onChange={(e) => setBase(e.target.value)}
            />
          </label>
        </div>

        <label className="field">
          <span>
            {graphql
              ? "Introspection result — paste the JSON from the introspection query"
              : "Spec — paste the JSON or YAML"}
          </span>
          <textarea
            rows={8}
            className="query"
            placeholder={graphql ? '{ "data": { "__schema": { ... } } }' : '{ "openapi": "3.0.0", ... }'}
            value={spec}
            onChange={(e) => setSpec(e.target.value)}
          />
        </label>

        <div className="toggles">
          <label className="check">
            <input
              type="checkbox"
              checked={includeWrites}
              onChange={(e) => setIncludeWrites(e.target.checked)}
            />
            {graphql ? "Include mutations" : "Include writes (POST/PUT/PATCH/DELETE)"}
          </label>
          <label className="check">
            <input type="checkbox" checked={insecure} onChange={(e) => setInsecure(e.target.checked)} />
            Do not verify TLS
          </label>
        </div>

        {free && (
          <p className="callout warn">
            Sending an import needs the Pro tier (it is automated traffic). Previewing is free.
          </p>
        )}

        <div className="row">
          <button className="secondary" disabled={spec.trim() === ""} onClick={parse}>
            Preview
          </button>
          <button
            className="primary"
            disabled={busy || free || spec.trim() === "" || (graphql && base.trim() === "")}
            onClick={send}
          >
            {busy ? "Sending…" : "Send (records traffic)"}
          </button>
        </div>
      </section>

      {error && <p className="callout danger">{error}</p>}

      {result && (
        <p className="callout ok">
          Recorded {result.recorded} operation(s) from {result.base} into the project
          {result.failed > 0 && ` (${result.failed} did not complete)`}. Scan the new traffic on
          the Scan tab.
        </p>
      )}

      {preview && (
        <section className="card">
          <h2>{preview.title ?? "Operations"}</h2>
          <p className="muted small">
            Base {preview.base} — {preview.operations.length} operation(s), {openApiWrites} write(s).
          </p>
          <table className="grid">
            <thead>
              <tr>
                <th>Method</th>
                <th>URL</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {preview.operations.map((op, i) => (
                <tr key={i} className={op.safe ? "" : "muted"}>
                  <td>
                    {op.method}
                    {!op.safe && <span className="tag">write</span>}
                  </td>
                  <td>
                    <code>{op.url}</code>
                  </td>
                  <td>{op.summary ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {gqlOps && (
        <section className="card">
          <h2>GraphQL operations</h2>
          <p className="muted small">
            {gqlOps.length} operation(s), {gqlMutations} mutation(s).
          </p>
          <table className="grid">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Document</th>
              </tr>
            </thead>
            <tbody>
              {gqlOps.map((op, i) => (
                <tr key={i} className={op.mutation ? "muted" : ""}>
                  <td>
                    {op.kind}
                    {op.mutation && <span className="tag">mutation</span>}
                  </td>
                  <td>
                    <code>{op.document}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}

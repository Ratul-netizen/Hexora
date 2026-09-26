import { useCallback, useEffect, useState } from "react";

import {
  buildSitemap,
  describeError,
  type SitemapView as SitemapData,
} from "../ipc";

/**
 * The coverage answer, made visible: a host → path tree of what the project has reached.
 *
 * Read-only. It maps the traffic already captured — what was fetched, under which methods
 * and statuses, and which identity reached each path — and lists what is out of scope.
 * With "read forms" it also shows the forms discovered but never submitted. This is the
 * payoff of a crawl: the pages it fetched show up here.
 */
export function SitemapView({ hasProject }: { hasProject: boolean }) {
  const [data, setData] = useState<SitemapData | null>(null);
  const [forms, setForms] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async (withForms: boolean) => {
    setBusy(true);
    setError(null);
    try {
      setData(await buildSitemap(null, withForms));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (hasProject) void load(false);
  }, [hasProject, load]);

  if (!hasProject) {
    return <p className="placeholder">Open a project to see what it has reached.</p>;
  }

  const formTotal = data?.hosts.reduce((n, h) => n + h.forms.length, 0) ?? 0;

  return (
    <div className="sitemap">
      <div className="toolbar">
        <label className="check">
          <input
            type="checkbox"
            checked={forms}
            onChange={(e) => {
              setForms(e.target.checked);
              void load(e.target.checked);
            }}
          />
          Read forms
        </label>
        <button disabled={busy} onClick={() => load(forms)}>
          {busy ? "Building…" : "Rebuild"}
        </button>
        {data && (
          <span className="muted small">
            {data.host_count} host(s), {data.path_count} path(s)
            {forms ? `, ${formTotal} form(s)` : ""}
          </span>
        )}
      </div>

      {error && <p className="callout danger">{error}</p>}

      {data && data.hosts.length === 0 && data.out_of_scope.length === 0 && (
        <p className="placeholder">
          Nothing captured yet — proxy some traffic or run a crawl, then rebuild.
        </p>
      )}

      {data?.hosts.map((host) => (
        <section className="card sitemap-host" key={`${host.secure}:${host.host}`}>
          <h2>
            <span className="scheme">{host.secure ? "https" : "http"}://</span>
            {host.host}
          </h2>
          <table className="tree">
            <tbody>
              {host.paths.map((p) => (
                <tr key={p.path}>
                  <td className="mono path">{p.path}</td>
                  <td className="methods">{p.methods.join(", ")}</td>
                  <td className="statuses">
                    {p.statuses.map((s) => (
                      <span key={s} className={`status s${Math.floor(s / 100)}`}>
                        {s}
                      </span>
                    ))}
                  </td>
                  <td className="identities muted">
                    {p.identities.length > 0 ? `as ${p.identities.join(", ")}` : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {forms && host.forms.length > 0 && (
            <div className="forms">
              <h3>Forms — discovered, never submitted</h3>
              {host.forms.map((f) => (
                <div className="form-row mono" key={`${f.method} ${f.action}`}>
                  <span className="method">{f.method}</span> {f.action}
                </div>
              ))}
            </div>
          )}
        </section>
      ))}

      {data && data.out_of_scope.length > 0 && (
        <section className="card out-of-scope">
          <h2>Out of scope ({data.out_of_scope.length})</h2>
          <p className="muted small">Seen, never part of the map.</p>
          {data.out_of_scope.map((u) => (
            <div className="mono small" key={u}>
              {u}
            </div>
          ))}
        </section>
      )}
    </div>
  );
}

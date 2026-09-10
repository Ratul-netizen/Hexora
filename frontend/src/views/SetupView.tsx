import { useCallback, useEffect, useState } from "react";

import {
  addIdentity,
  addScope,
  caStatus,
  describeError,
  installCa,
  listIdentities,
  listScope,
  openProject,
  proxyStatus,
  removeIdentity,
  removeScope,
  startProxy,
  stopProxy,
  untrustCa,
  type CaStatus,
  type IdentityView,
  type ProjectSummary,
  type ProxyStatus,
  type ScopeView,
} from "../ipc";

/**
 * Getting a machine ready: a project, the certificate authority, the proxy, and
 * then what the engagement is allowed to touch and who it can be.
 *
 * The things that have to be true before anything else works, in the order they have
 * to be true in. Each says what state it is in rather than presenting a button and
 * leaving the result to be inferred.
 */
export function SetupView({
  project,
  onProjectChange,
  proxy,
  onProxyChange,
}: {
  project: ProjectSummary | null;
  onProjectChange: (project: ProjectSummary) => void;
  proxy: ProxyStatus;
  onProxyChange: (status: ProxyStatus) => void;
}) {
  return (
    <div className="setup">
      <ProjectCard project={project} onChange={onProjectChange} />
      <CaCard />
      <ProxyCard project={project} proxy={proxy} onChange={onProxyChange} />
      <ScopeCard project={project} />
      <IdentityCard project={project} />
    </div>
  );
}

function ProjectCard({
  project,
  onChange,
}: {
  project: ProjectSummary | null;
  onChange: (project: ProjectSummary) => void;
}) {
  const [path, setPath] = useState(project?.path ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function open() {
    setBusy(true);
    setError(null);
    try {
      onChange(await openProject(path));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>1 · Project</h2>
      <p className="muted">
        Captured traffic, findings and repeater history live in a project
        directory. It is the evidence behind a report, so it is a directory you
        keep rather than a scratch file.
      </p>

      <div className="row">
        <input
          type="text"
          value={path}
          placeholder="C:\engagements\acme"
          spellCheck={false}
          onChange={(e) => setPath(e.target.value)}
        />
        <button onClick={open} disabled={busy || path.trim() === ""}>
          {busy ? "Opening…" : "Open or create"}
        </button>
      </div>

      {error && <p className="error-text">{error}</p>}

      {project && (
        <dl className="facts">
          <dt>Open</dt>
          <dd>{project.name}</dd>
          <dt>Path</dt>
          <dd className="mono">{project.path}</dd>
          <dt>Captured</dt>
          <dd>
            {project.requests.toLocaleString()} requests across{" "}
            {project.targets.toLocaleString()} targets
          </dd>
        </dl>
      )}
    </section>
  );
}

function CaCard() {
  const [status, setStatus] = useState<CaStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    caStatus().then(setStatus).catch((e) => setError(describeError(e)));
  }, []);

  async function act(action: () => Promise<CaStatus>) {
    setBusy(true);
    setError(null);
    try {
      setStatus(await action());
      setConfirming(false);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>2 · Certificate authority</h2>
      <p className="muted">
        Reading HTTPS requires a certificate authority this machine trusts.
        Hexora generates one per installation and never ships it.
      </p>

      {error && <p className="error-text">{error}</p>}

      {status && (
        <>
          <dl className="facts">
            <dt>Fingerprint</dt>
            <dd className="mono small">{status.fingerprint}</dd>
            <dt>Trust</dt>
            <dd className={status.trusted ? "ok" : "warn"}>{status.state}</dd>
          </dl>

          {status.trusted ? (
            <div className="row">
              <button onClick={() => act(untrustCa)} disabled={busy}>
                Remove from trust store
              </button>
            </div>
          ) : confirming ? (
            // The consequences are stated at the moment of the decision rather than
            // in documentation nobody reads. Installing a root CA is the most
            // consequential thing this application asks anyone to do.
            <div className="confirm">
              <p>
                <strong>This lets Hexora decrypt HTTPS on this machine.</strong>{" "}
                Anyone who obtains the private key in {status.directory} could
                impersonate any site to you. Install it only on a machine you
                control, and remove it when you are done.
              </p>
              <div className="row">
                <button
                  className="danger"
                  onClick={() => act(installCa)}
                  disabled={busy}
                >
                  {busy ? "Installing…" : "I understand — install it"}
                </button>
                <button onClick={() => setConfirming(false)} disabled={busy}>
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <div className="row">
              <button onClick={() => setConfirming(true)}>
                Install into my trust store
              </button>
            </div>
          )}

          <p className="muted small">
            Firefox keeps its own certificate store and ignores this one. If you
            use Firefox, import{" "}
            <span className="mono">{status.directory}\hexora-ca.crt</span> under
            Settings → Privacy &amp; Security → Certificates → Authorities.
          </p>
        </>
      )}
    </section>
  );
}

function ProxyCard({
  project,
  proxy,
  onChange,
}: {
  project: ProjectSummary | null;
  proxy: ProxyStatus;
  onChange: (status: ProxyStatus) => void;
}) {
  const [listen, setListen] = useState("127.0.0.1:8080");
  const [only, setOnly] = useState("");
  const [insecure, setInsecure] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    proxyStatus().then(onChange).catch(() => undefined);
  }, [onChange]);

  async function toggle() {
    setBusy(true);
    setError(null);
    try {
      if (proxy.running) {
        onChange(await stopProxy());
      } else {
        const hosts = only
          .split(",")
          .map((h) => h.trim())
          .filter((h) => h !== "");
        onChange(await startProxy(listen, hosts, insecure));
      }
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>3 · Proxy</h2>
      <p className="muted">
        Point a browser at this address as its HTTP and HTTPS proxy. Everything
        it sees is recorded into the open project.
      </p>

      <div className="row">
        <input
          type="text"
          value={listen}
          spellCheck={false}
          disabled={proxy.running}
          onChange={(e) => setListen(e.target.value)}
        />
        <button
          onClick={toggle}
          disabled={busy || project === null}
          className={proxy.running ? "danger" : ""}
        >
          {busy ? "…" : proxy.running ? "Stop" : "Start"}
        </button>
      </div>

      <label className="field">
        <span>Decrypt only these hosts (comma separated)</span>
        <input
          type="text"
          value={only}
          placeholder="leave empty to decrypt everything"
          spellCheck={false}
          disabled={proxy.running}
          onChange={(e) => setOnly(e.target.value)}
        />
        <span className="muted small">
          The safer posture: your own browsing stays encrypted while you work.
        </span>
      </label>

      <label className="checkbox">
        <input
          type="checkbox"
          checked={insecure}
          disabled={proxy.running}
          onChange={(e) => setInsecure(e.target.checked)}
        />
        <span>
          Do not verify upstream certificates
          <span className="muted small">
            {" "}
            — for staging targets with self-signed certificates. Connections to
            the target stay encrypted but are not authenticated.
          </span>
        </span>
      </label>

      {project === null && (
        <p className="notice">Open a project before starting the proxy.</p>
      )}
      {error && <p className="error-text">{error}</p>}
    </section>
  );
}

/**
 * What this engagement is authorized to touch.
 *
 * Not a filter for tidiness: the guard refuses automated traffic to hosts nobody has
 * declared, so an empty scope is why an authorization matrix will not run. Adding a
 * host shows the whole list back, because widening scope is a decision somebody may
 * have to justify later.
 */
function ScopeCard({ project }: { project: ProjectSummary | null }) {
  const [scope, setScope] = useState<ScopeView | null>(null);
  const [host, setHost] = useState("");
  const [prefix, setPrefix] = useState("");
  const [exclude, setExclude] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (project === null) return;
    listScope()
      .then(setScope)
      .catch((e) => setError(describeError(e)));
  }, [project]);

  async function act(action: () => Promise<ScopeView>) {
    setError(null);
    try {
      setScope(await action());
    } catch (e) {
      setError(describeError(e));
    }
  }

  if (project === null) {
    return (
      <section className="card">
        <h2>4 · Scope</h2>
        <p className="notice">Open a project to declare what is in scope.</p>
      </section>
    );
  }

  return (
    <section className="card">
      <h2>4 · Scope</h2>
      <p className="muted">
        Automated components refuse to send traffic to hosts nobody has declared
        here. The proxy is exempt — it has to see a host before you can decide it is
        in bounds.
      </p>

      <div className="row">
        <input
          type="text"
          value={host}
          placeholder="api.example.com or *.example.com"
          spellCheck={false}
          onChange={(e) => setHost(e.target.value)}
        />
        <input
          type="text"
          value={prefix}
          placeholder="/api (optional)"
          spellCheck={false}
          onChange={(e) => setPrefix(e.target.value)}
        />
        <button
          onClick={() =>
            void act(async () => {
              const next = await addScope(
                host,
                prefix.trim() === "" ? null : prefix,
                exclude,
              );
              setHost("");
              setPrefix("");
              return next;
            })
          }
          disabled={host.trim() === ""}
        >
          Add
        </button>
      </div>

      <label className="checkbox">
        <input
          type="checkbox"
          checked={exclude}
          onChange={(e) => setExclude(e.target.checked)}
        />
        <span>
          Add as an exclusion
          <span className="muted small"> — exclusions win over inclusions.</span>
        </span>
      </label>

      {error && <p className="error-text">{error}</p>}

      {scope && scope.included.length === 0 && scope.excluded.length === 0 ? (
        <p className="notice">
          Scope is empty, so no automated component will send anything.
        </p>
      ) : (
        scope && (
          <ul className="rules">
            {scope.included.map((rule) => (
              <li key={`in-${rule}`}>
                <span className="mono">{rule}</span>
                <button
                  className="link"
                  onClick={() => void act(() => removeScope(hostOf(rule)))}
                >
                  remove
                </button>
              </li>
            ))}
            {scope.excluded.map((rule) => (
              <li key={`ex-${rule}`}>
                <span className="tag">excluded</span>
                <span className="mono">{rule}</span>
                <button
                  className="link"
                  onClick={() => void act(() => removeScope(hostOf(rule)))}
                >
                  remove
                </button>
              </li>
            ))}
          </ul>
        )
      )}
    </section>
  );
}

/** The host part of a rendered rule, which is what removal keys on. */
function hostOf(rule: string): string {
  const withoutScheme = rule.replace(/^https?:\/\//, "");
  const slash = withoutScheme.indexOf("/");
  return slash === -1 ? withoutScheme : withoutScheme.slice(0, slash);
}

/**
 * The principals a project can test as.
 *
 * The credential is read from an environment variable where possible. Typing one
 * here sends it across the IPC boundary — a smaller exposure than a command line
 * that `ps` and shell history can read, but not none, and the form says so rather
 * than leaving it to be discovered.
 */
function IdentityCard({ project }: { project: ProjectSummary | null }) {
  const [identities, setIdentities] = useState<IdentityView[]>([]);
  const [label, setLabel] = useState("");
  const [privilege, setPrivilege] = useState("user");
  const [kind, setKind] = useState("bearer");
  const [fromEnv, setFromEnv] = useState("");
  const [secret, setSecret] = useState("");
  const [owns, setOwns] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(() => {
    if (project === null) return;
    listIdentities()
      .then(setIdentities)
      .catch((e) => setError(describeError(e)));
  }, [project]);

  useEffect(reload, [reload]);

  async function add() {
    setBusy(true);
    setError(null);
    try {
      await addIdentity({
        label,
        privilege,
        kind,
        secret: secret === "" ? null : secret,
        fromEnv: fromEnv.trim() === "" ? null : fromEnv,
        owns: owns
          .split(",")
          .map((id) => id.trim())
          .filter((id) => id !== ""),
      });
      setLabel("");
      setSecret("");
      setFromEnv("");
      setOwns("");
      reload();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (project === null) {
    return (
      <section className="card">
        <h2>5 · Identities</h2>
        <p className="notice">Open a project to add the identities it tests as.</p>
      </section>
    );
  }

  return (
    <section className="card">
      <h2>5 · Identities</h2>
      <p className="muted">
        Two or more principals, so a captured request can be replayed as somebody
        else. Credential values are never read back — the list shows the kind only.
      </p>

      <div className="row">
        <input
          type="text"
          value={label}
          placeholder="User B"
          onChange={(e) => setLabel(e.target.value)}
        />
        <select value={privilege} onChange={(e) => setPrivilege(e.target.value)}>
          <option value="anonymous">anonymous</option>
          <option value="user">user</option>
          <option value="elevated">elevated</option>
          <option value="administrator">administrator</option>
        </select>
        <input
          type="text"
          value={kind}
          placeholder="bearer, cookie, basic, or a header name"
          spellCheck={false}
          onChange={(e) => setKind(e.target.value)}
        />
      </div>

      <label className="field">
        <span>Credential from an environment variable</span>
        <input
          type="text"
          value={fromEnv}
          placeholder="TOKEN_B"
          spellCheck={false}
          onChange={(e) => setFromEnv(e.target.value)}
        />
        <span className="muted small">
          Read by this process at the moment you press Add. Preferred: the value
          never travels through the interface.
        </span>
      </label>

      <label className="field">
        <span>…or enter it here</span>
        <input
          type="password"
          value={secret}
          placeholder="only if it is not in the environment"
          spellCheck={false}
          disabled={fromEnv.trim() !== ""}
          onChange={(e) => setSecret(e.target.value)}
        />
        <span className="muted small">
          Stored in the project as written. It crosses the IPC boundary to get there.
        </span>
      </label>

      <label className="field">
        <span>Object identifiers this identity owns (comma separated)</span>
        <input
          type="text"
          value={owns}
          placeholder="acct-2000, inv-77"
          spellCheck={false}
          onChange={(e) => setOwns(e.target.value)}
        />
        <span className="muted small">
          This is what turns a similarity score into evidence: an id declared here,
          found in somebody else’s response, is a disclosure rather than a guess.
        </span>
      </label>

      <div className="row">
        <button onClick={() => void add()} disabled={busy || label.trim() === ""}>
          {busy ? "Adding…" : "Add identity"}
        </button>
      </div>

      {error && <p className="error-text">{error}</p>}

      {identities.length === 0 ? (
        <p className="notice">
          No identities yet. An authorization matrix needs at least two.
        </p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Identity</th>
                <th>Privilege</th>
                <th>Credential</th>
                <th>Owns</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {identities.map((identity) => (
                <tr key={identity.id}>
                  <td>{identity.label}</td>
                  <td className="muted">{identity.privilege}</td>
                  <td className="muted">{identity.credential}</td>
                  <td className="mono small">
                    {identity.owns.length === 0 ? "—" : identity.owns.join(", ")}
                  </td>
                  <td>
                    <button
                      className="link"
                      onClick={() =>
                        void removeIdentity(identity.id)
                          .then(reload)
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

import { useEffect, useState } from "react";

import {
  caStatus,
  describeError,
  installCa,
  openProject,
  proxyStatus,
  startProxy,
  stopProxy,
  untrustCa,
  type CaStatus,
  type ProjectSummary,
  type ProxyStatus,
} from "../ipc";

/**
 * Getting a machine ready: a project, the certificate authority, the proxy.
 *
 * The three things that have to be true before anything else works, in the order
 * they have to be true in. Each says what state it is in rather than presenting a
 * button and leaving the result to be inferred.
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

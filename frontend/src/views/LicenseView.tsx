import { useState } from "react";

import {
  activateLicense,
  describeError,
  startTrial,
  type LicenseStatus,
} from "../ipc";

/**
 * The licence panel: what tier this install runs at, and how to change it.
 *
 * Offline by design — a licence is a signed file verified against a key embedded in the
 * build, never a call home. A bad or missing licence is never an error that stops the
 * tool; it runs at the free tier, which still reads and reports. Activation is refused,
 * loudly, only when a file does not verify — never installed silently.
 */
export function LicenseView({
  license,
  onChange,
}: {
  license: LicenseStatus | null;
  onChange: (next: LicenseStatus) => void;
}) {
  const [file, setFile] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(work: () => Promise<LicenseStatus>, done: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const next = await work();
      onChange(next);
      setNotice(done);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  const tier = license?.tier ?? "Free";
  const paid = tier !== "Free";
  const expiringSoon =
    license?.days_until_expiry != null && license.days_until_expiry <= 7;

  return (
    <div className="license-view">
      <section className="card">
        <h2>Licence</h2>
        <div className="license-tier">
          <span className={`badge-tier ${paid ? "paid" : "free"}`}>{tier}</span>
          {license?.trial && <span className="chip">trial</span>}
        </div>

        <dl className="kv">
          {license?.licensee && (
            <>
              <dt>Licensed to</dt>
              <dd>{license.licensee}</dd>
            </>
          )}
          <dt>Expires</dt>
          <dd>
            {license?.expires ? (
              <>
                {license.expires}
                {license.days_until_expiry != null && (
                  <span className={expiringSoon ? "warn" : "muted"}>
                    {" "}
                    ({license.days_until_expiry} days)
                  </span>
                )}
              </>
            ) : paid ? (
              "never"
            ) : (
              "—"
            )}
          </dd>
        </dl>

        {!paid && (
          <p className="muted small">
            The free tier includes interception, the repeater and reporting. The active
            scanner, intruder, crawler, SARIF export and retest snapshots need Pro.
          </p>
        )}
        {expiringSoon && (
          <p className="callout warn">
            This {license?.trial ? "trial" : "licence"} expires soon. It will fall back to
            the free tier — your evidence is never locked.
          </p>
        )}
      </section>

      <section className="card">
        <h2>Activate a licence</h2>
        <p className="muted">
          Point at a licence file you were sent. It is verified against this build's
          embedded key and installed for later runs; a file that does not verify is
          refused, not stored.
        </p>
        <div className="row">
          <input
            type="text"
            placeholder="path to your .hexlic file"
            value={file}
            onChange={(e) => setFile(e.target.value)}
          />
          <button
            className="primary"
            disabled={busy || file.trim() === ""}
            onClick={() => run(() => activateLicense(file.trim()), "Licence activated.")}
          >
            Activate
          </button>
        </div>
      </section>

      <section className="card">
        <h2>Start a trial</h2>
        <p className="muted">
          A 14-day Pro trial, once per machine. It grants every paid feature and never
          locks your work when it lapses.
        </p>
        <button
          disabled={busy || (paid && !license?.trial)}
          onClick={() => run(() => startTrial(), "Trial started.")}
        >
          Start 14-day Pro trial
        </button>
      </section>

      {notice && <p className="callout ok">{notice}</p>}
      {error && <p className="callout danger">{error}</p>}
    </div>
  );
}

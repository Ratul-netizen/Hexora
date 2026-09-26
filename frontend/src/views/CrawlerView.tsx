import { useState } from "react";

import {
  describeError,
  runCrawl,
  type CrawlSummary,
  type LicenseStatus,
} from "../ipc";

/**
 * The crawler: widen coverage by following in-scope links, feeding fetched pages to the
 * project so the scanner has more to work over.
 *
 * This sends requests, so it is spelled out and gated like the active scanner. The button
 * is the tester's consent — nothing goes out before it is pressed. Out-of-scope links are
 * recorded, not followed; forms are discovered, never submitted; destructive-looking links
 * and robots.txt are respected by default.
 */
export function CrawlerView({
  hasProject,
  license,
}: {
  hasProject: boolean;
  license: LicenseStatus | null;
}) {
  const [seeds, setSeeds] = useState("");
  const [maxRequests, setMaxRequests] = useState("500");
  const [maxDepth, setMaxDepth] = useState("8");
  const [identity, setIdentity] = useState("");
  const [followDestructive, setFollowDestructive] = useState(false);
  const [ignoreRobots, setIgnoreRobots] = useState(false);
  const [insecure, setInsecure] = useState(false);
  const [summary, setSummary] = useState<CrawlSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const free = (license?.tier ?? "Free") === "Free";

  if (!hasProject) {
    return <p className="placeholder">Open a project to crawl in-scope targets.</p>;
  }

  async function crawl() {
    setBusy(true);
    setError(null);
    setSummary(null);
    try {
      const result = await runCrawl({
        seeds: seeds
          .split("\n")
          .map((s) => s.trim())
          .filter((s) => s !== ""),
        maxRequests: Number(maxRequests) || null,
        maxDepth: maxDepth === "" ? null : Number(maxDepth),
        followDestructive,
        ignoreRobots,
        insecure,
        identity: identity.trim() === "" ? null : identity.trim(),
      });
      setSummary(result);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="crawler">
      <section className="card">
        <h2>Crawl</h2>
        <p className="muted">
          Follows in-scope links to widen coverage, recording each fetched page for the
          scanner. Out-of-scope links are recorded, not followed; forms are discovered,
          never submitted.
        </p>

        <label className="field">
          <span>Seeds — one URL per line, or leave empty to seed from captured traffic</span>
          <textarea
            rows={3}
            placeholder="https://target.example/"
            value={seeds}
            onChange={(e) => setSeeds(e.target.value)}
          />
        </label>

        <div className="row">
          <label className="field">
            <span>Max requests</span>
            <input
              type="text"
              value={maxRequests}
              onChange={(e) => setMaxRequests(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Max depth</span>
            <input
              type="text"
              value={maxDepth}
              onChange={(e) => setMaxDepth(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Crawl as identity (optional)</span>
            <input
              type="text"
              placeholder="label or id"
              value={identity}
              onChange={(e) => setIdentity(e.target.value)}
            />
          </label>
        </div>

        <div className="toggles">
          <label className="check">
            <input
              type="checkbox"
              checked={followDestructive}
              onChange={(e) => setFollowDestructive(e.target.checked)}
            />
            Follow destructive-looking links
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={ignoreRobots}
              onChange={(e) => setIgnoreRobots(e.target.checked)}
            />
            Ignore robots.txt
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={insecure}
              onChange={(e) => setInsecure(e.target.checked)}
            />
            Do not verify TLS
          </label>
        </div>

        {free && (
          <p className="callout warn">
            The crawler needs the Pro tier. Start a trial or activate a licence on the
            Licence tab.
          </p>
        )}

        <p className="callout warn">
          This sends requests to in-scope hosts. Only crawl systems you are authorized to
          test.
        </p>

        <button className="primary" disabled={busy || free} onClick={crawl}>
          {busy ? "Crawling…" : "Crawl (sends traffic)"}
        </button>
      </section>

      {error && <p className="callout danger">{error}</p>}

      {summary && (
        <section className="card">
          <h2>Result</h2>
          <dl className="kv">
            <dt>Seeds</dt>
            <dd>{summary.seeds}</dd>
            <dt>Fetched</dt>
            <dd>{summary.fetched} page(s)</dd>
            <dt>Recorded</dt>
            <dd>{summary.recorded} into the project</dd>
            <dt>Stopped</dt>
            <dd>{stopReason(summary.stopped)}</dd>
          </dl>

          {summary.skipped > 0 && (
            <>
              <h3 className="muted">Not followed ({summary.skipped})</h3>
              <ul className="reasons">
                {Object.entries(summary.skipped_by_reason).map(([why, count]) => (
                  <li key={why}>
                    <span className="count">{count}</span> {why}
                  </li>
                ))}
              </ul>
            </>
          )}
          <p className="muted small">
            The fetched pages are in the project now — see the Site map for coverage, or run
            a scan over the new traffic.
          </p>
        </section>
      )}
    </div>
  );
}

function stopReason(stopped: string): string {
  switch (stopped) {
    case "frontier_empty":
      return "the frontier drained — everything reachable was visited";
    case "request_ceiling":
      return "the request ceiling was reached — more may remain";
    case "cancelled":
      return "cancelled before it finished";
    default:
      return stopped;
  }
}

import { useEffect, useMemo, useState } from "react";

import {
  buildSitemap,
  exchangeDetail,
  listFindings,
  listHistory,
  listScope,
  type HistoryRow,
  type LicenseStatus,
  type ProjectSummary,
  type ProxyStatus,
  type SitemapHost,
} from "../ipc";
import {
  TopologyGraph,
  type DeviceType,
  type TopoLink,
  type TopoNode,
} from "../components/TopologyGraph";
import {
  APP_LEGEND,
  buildAppGraph,
  classifyDevice,
  parseSignals,
  type HostSignals,
} from "../lib/appgraph";

/**
 * The opening screen: where the engagement stands at a glance, and a rotating map of
 * the hosts and devices it has reached.
 *
 * Everything here is a read of what the engine already holds — captured traffic, the
 * site map, the findings list — never a new claim. When a project is empty the map
 * shows a clearly-labelled sample so the shape of the view is legible before the first
 * request is sent; the moment real hosts exist, they replace it.
 */

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEVERITY_COLOR: Record<string, string> = {
  critical: "#e0917a",
  high: "#e07a7a",
  medium: "#d9b061",
  low: "#7fa8c9",
  info: "#8a93a3",
};

const DEVICE_LEGEND: { type: DeviceType; label: string }[] = [
  { type: "server", label: "Server" },
  { type: "database", label: "Database" },
  { type: "router", label: "Gateway / router" },
  { type: "endpoint", label: "Endpoint" },
  { type: "cloud", label: "Cloud / edge" },
  { type: "firewall", label: "Firewall / WAF" },
];

interface DashboardData {
  hosts: SitemapHost[];
  severities: Record<string, number>;
  findingsTotal: number;
  recent: HistoryRow[];
  requestsTotal: number;
  signals: Map<string, HostSignals>;
  scope: { included: number; excluded: number };
}

const EMPTY: DashboardData = {
  hosts: [],
  severities: {},
  findingsTotal: 0,
  recent: [],
  requestsTotal: 0,
  signals: new Map(),
  scope: { included: 0, excluded: 0 },
};

export function DashboardView({
  project,
  proxy,
  license,
  captureCount,
  findingCount,
  onNavigate,
}: {
  project: ProjectSummary | null;
  proxy: ProxyStatus;
  license: LicenseStatus | null;
  captureCount: number;
  findingCount: number;
  onNavigate: (tab: string) => void;
}) {
  const [data, setData] = useState<DashboardData>(EMPTY);
  const [graphMode, setGraphMode] = useState<"infra" | "app">("infra");

  useEffect(() => {
    if (!project) {
      setData(EMPTY);
      return;
    }
    let live = true;
    (async () => {
      const [sitemap, findings, history, scope] = await Promise.allSettled([
        buildSitemap(null, false),
        listFindings({
          severity: null,
          status: null,
          actionable: false,
          after: null,
          limit: 200,
        }),
        listHistory(null, 200),
        listScope(),
      ]);
      if (!live) return;

      const severities: Record<string, number> = {};
      let findingsTotal = 0;
      if (findings.status === "fulfilled") {
        findingsTotal = findings.value.total;
        for (const row of findings.value.rows) {
          const key = row.severity.toLowerCase();
          severities[key] = (severities[key] ?? 0) + 1;
        }
      }

      const rows = history.status === "fulfilled" ? history.value.rows : [];
      const signals = await fetchHostSignals(rows);
      if (!live) return;

      setData({
        hosts: sitemap.status === "fulfilled" ? sitemap.value.hosts : [],
        severities,
        findingsTotal,
        recent: rows.slice(0, 6),
        signals,
        // The live captured count, re-read on every refresh — the project summary's
        // request count is a snapshot from when the project was opened and goes stale
        // the moment traffic is captured.
        requestsTotal: history.status === "fulfilled" ? history.value.total : 0,
        scope:
          scope.status === "fulfilled"
            ? {
                included: scope.value.included.length,
                excluded: scope.value.excluded.length,
              }
            : { included: 0, excluded: 0 },
      });
    })().catch(() => undefined);
    return () => {
      live = false;
    };
  }, [project, captureCount, findingCount]);

  const isSample = data.hosts.length === 0;
  const { nodes, links } = useMemo(() => {
    if (isSample) return SAMPLE_TOPOLOGY;
    return graphMode === "app"
      ? buildAppGraph(data.hosts, data.signals)
      : topologyFromHosts(data.hosts, data.signals);
  }, [isSample, data.hosts, data.signals, graphMode]);

  // Detected backend tech per host, for the "Backend" panel.
  const backends = useMemo(
    () =>
      data.hosts
        .map((h) => ({ host: h.host, tech: classifyDevice(h.host, data.signals.get(h.host)).tech }))
        .filter((b) => b.tech),
    [data.hosts, data.signals],
  );

  const zones = useMemo(() => {
    const counts = new Map<string, number>();
    // Count devices (hosts), not the endpoint leaves fanned out around them, so the
    // number matches the Hosts tile.
    for (const n of nodes) {
      if (n.type === "endpoint" && n.id.includes("#")) continue;
      counts.set(n.zone, (counts.get(n.zone) ?? 0) + 1);
    }
    return Array.from(counts.entries());
  }, [nodes]);

  const requests = Math.max(data.requestsTotal, project?.requests ?? 0);
  const hostCount = isSample ? 0 : data.hosts.length;

  return (
    <div className="dashboard">
      <header className="dash-head">
        <div>
          <h1>{project ? project.name : "No project open"}</h1>
          <p className="muted">
            {project
              ? "Live overview of the engagement — captured traffic, discovered hosts and findings."
              : "Open a project on the Setup tab to begin capturing traffic."}
          </p>
        </div>
        <div className="dash-head-actions">
          {!project && (
            <button className="primary" onClick={() => onNavigate("setup")}>
              Go to Setup
            </button>
          )}
          <button onClick={() => onNavigate("history")}>Open History</button>
        </div>
      </header>

      <section className="stat-row">
        <StatTile
          label="Proxy"
          value={proxy.running ? "Live" : "Stopped"}
          tone={proxy.running ? "ok" : "muted"}
          sub={proxy.running ? (proxy.address ?? "") : "not intercepting"}
        />
        <StatTile label="Requests" value={requests.toLocaleString()} sub="captured" />
        <StatTile
          label="Hosts"
          value={hostCount.toLocaleString()}
          sub={isSample ? "none yet" : "in site map"}
        />
        <StatTile
          label="Findings"
          value={data.findingsTotal.toLocaleString()}
          tone={data.findingsTotal > 0 ? "warn" : "muted"}
          sub={`${data.scope.included} in scope · ${data.scope.excluded} out`}
        />
        <StatTile
          label="Licence"
          value={license?.tier ?? "—"}
          tone={license && license.tier !== "Free" ? "accent" : "muted"}
          sub={license?.trial ? "trial" : license ? "active" : ""}
        />
      </section>

      <div className="dash-grid">
        <section className="card topo-card">
          <div className="card-title-row">
            <h2>
              {graphMode === "app" ? "Application structure" : "Network & system topology"}
            </h2>
            <div className="topo-head-right">
              <div className="seg topo-mode">
                <button
                  className={graphMode === "infra" ? "seg-btn on" : "seg-btn"}
                  onClick={() => setGraphMode("infra")}
                >
                  Infrastructure
                </button>
                <button
                  className={graphMode === "app" ? "seg-btn on" : "seg-btn"}
                  onClick={() => setGraphMode("app")}
                >
                  Application
                </button>
              </div>
              <span className="muted small">
                {isSample ? "sample" : "drag to orbit · scroll to zoom"}
              </span>
            </div>
          </div>
          <TopologyGraph nodes={nodes} links={links} height={430} />
          <div className="topo-legend">
            {(graphMode === "app" ? APP_LEGEND : DEVICE_LEGEND).map((d) => (
              <span key={d.type} className="legend-item">
                <LegendShape type={d.type} />
                {d.label}
              </span>
            ))}
          </div>
        </section>

        <div className="dash-side">
          <section className="card">
            <h2>Findings by severity</h2>
            {data.findingsTotal === 0 ? (
              <p className="muted">No findings recorded yet.</p>
            ) : (
              <ul className="sev-list">
                {SEVERITY_ORDER.filter((s) => data.severities[s]).map((s) => {
                  const n = data.severities[s] ?? 0;
                  const pct = Math.round((n / data.findingsTotal) * 100);
                  return (
                    <li key={s}>
                      <span className="sev-label">
                        <i
                          className="sev-dot"
                          style={{ background: SEVERITY_COLOR[s] }}
                        />
                        {s}
                      </span>
                      <span className="sev-bar">
                        <span
                          className="sev-bar-fill"
                          style={{ width: `${pct}%`, background: SEVERITY_COLOR[s] }}
                        />
                      </span>
                      <span className="sev-count">{n}</span>
                    </li>
                  );
                })}
              </ul>
            )}
            <button className="linkish" onClick={() => onNavigate("findings")}>
              View all findings →
            </button>
          </section>

          <section className="card">
            <h2>Zones</h2>
            <ul className="zone-list">
              {zones.map(([zone, count]) => (
                <li key={zone}>
                  <span>{zone}</span>
                  <span className="muted">{count} devices</span>
                </li>
              ))}
            </ul>
          </section>

          {backends.length > 0 && (
            <section className="card">
              <h2>Backend</h2>
              <ul className="backend-list">
                {backends.map((b) => (
                  <li key={b.host}>
                    <span className="backend-host mono">{b.host}</span>
                    <span className="backend-tech">{b.tech}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section className="card">
            <h2>Recent traffic</h2>
            {data.recent.length === 0 ? (
              <p className="muted">Nothing captured yet.</p>
            ) : (
              <ul className="recent-list">
                {data.recent.slice(0, 6).map((r) => (
                  <li key={r.id}>
                    <span className={`method m-${r.method.toLowerCase()}`}>
                      {r.method}
                    </span>
                    <span className="recent-url" title={r.url}>
                      {shortUrl(r.url)}
                    </span>
                    <span className={statusClass(r.status)}>{r.status ?? "—"}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

function StatTile({
  label,
  value,
  sub,
  tone = "default",
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: "default" | "ok" | "warn" | "accent" | "muted";
}) {
  return (
    <div className={`stat-tile tone-${tone}`}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {sub ? <span className="stat-sub muted">{sub}</span> : null}
    </div>
  );
}

/** A small shape matching the topology's device glyphs, coloured by type. */
function LegendShape({ type }: { type: DeviceType }) {
  const shapes: Record<DeviceType, JSX.Element> = {
    server: <circle cx="8" cy="8" r="5" />,
    database: (
      <path d="M3 4.5c0-1.4 2.2-2.5 5-2.5s5 1.1 5 2.5v7c0 1.4-2.2 2.5-5 2.5s-5-1.1-5-2.5zM3 4.5c0 1.4 2.2 2.5 5 2.5s5-1.1 5-2.5" fill="none" stroke="currentColor" strokeWidth="1.4" />
    ),
    router: <path d="M8 2l6 6-6 6-6-6z" />,
    endpoint: <rect x="3" y="3" width="10" height="10" rx="2.5" />,
    cloud: <path d="M8 1.5l5.2 3v6.5L8 14.5 2.8 11V4.5z" />,
    firewall: <path d="M8 2l6 11H2z" />,
    unknown: <circle cx="8" cy="8" r="5" />,
    page: <circle cx="8" cy="8" r="5" />,
    api: <path d="M8 1.5l5.2 3v6.5L8 14.5 2.8 11V4.5z" />,
    asset: <rect x="3" y="3" width="10" height="10" rx="2.5" />,
    form: <path d="M8 2l6 11H2z" />,
    redirect: <path d="M8 2l6 6-6 6-6-6z" />,
  };
  return (
    <svg
      className={`legend-shape dev-${type}`}
      width="13"
      height="13"
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
    >
      {shapes[type]}
    </svg>
  );
}

// ------------------------------------------------------------------ derivation

/**
 * Read a representative response per host and parse its signals. One exchange per host is
 * enough to see the Server banner and framework; capped so a large capture stays cheap.
 */
async function fetchHostSignals(rows: HistoryRow[]): Promise<Map<string, HostSignals>> {
  const firstByHost = new Map<string, { id: string; secure: boolean }>();
  for (const row of rows) {
    const host = hostOf(row.url);
    if (host && !firstByHost.has(host)) {
      firstByHost.set(host, { id: row.id, secure: row.secure });
    }
  }
  const out = new Map<string, HostSignals>();
  const entries = Array.from(firstByHost.entries()).slice(0, 16);
  await Promise.all(
    entries.map(async ([host, { id, secure }]) => {
      try {
        const detail = await exchangeDetail(id);
        out.set(host, { ...parseSignals(detail.response_head), secure });
      } catch {
        /* a host we could not fingerprint stays on hostname heuristics */
      }
    }),
  );
  return out;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

function topologyFromHosts(
  hosts: SitemapHost[],
  signals: Map<string, HostSignals>,
): { nodes: TopoNode[]; links: TopoLink[] } {
  const maxPaths = Math.max(1, ...hosts.map((h) => h.paths.length));
  const nodes: TopoNode[] = hosts.map((h) => {
    const { type, zone } = classifyDevice(h.host, signals.get(h.host));
    return {
      id: h.host,
      label: h.host,
      type,
      zone,
      weight: 0.35 + (h.paths.length / maxPaths) * 0.65,
    };
  });
  const links = starLinks(nodes);

  // With only a few hosts the graph is a lonely dot or two, so fan each host's endpoints
  // out around it — the paths it actually served, as small child nodes. Capped, and only
  // when there is room, so a hundred-host engagement is not buried in leaves.
  if (hosts.length <= 4) {
    const perHost = Math.max(4, Math.floor(28 / Math.max(1, hosts.length)));
    for (const h of hosts) {
      const { zone } = classifyDevice(h.host, signals.get(h.host));
      h.paths.slice(0, perHost).forEach((p, i) => {
        const id = `${h.host}${p.path}#${i}`;
        nodes.push({
          id,
          label: p.path.length > 20 ? p.path.slice(0, 19) + "…" : p.path,
          type: "endpoint",
          zone,
          weight: 0.18,
        });
        links.push({ source: id, target: h.host });
      });
    }
  }

  return { nodes, links };
}

/** A star per zone to a zone anchor, then the anchors interlinked — a connected shape. */
function starLinks(nodes: TopoNode[]): TopoLink[] {
  const links: TopoLink[] = [];
  const anchors = new Map<string, string>();
  for (const n of nodes) if (!anchors.has(n.zone)) anchors.set(n.zone, n.id);
  for (const n of nodes) {
    const anchor = anchors.get(n.zone)!;
    if (n.id !== anchor) links.push({ source: n.id, target: anchor });
  }
  const anchorIds = Array.from(anchors.values());
  const hub = anchors.get("Edge") ?? anchors.get("External") ?? anchorIds[0];
  if (hub) {
    for (const a of anchorIds) if (a !== hub) links.push({ source: a, target: hub });
  }
  return links;
}

const SAMPLE_TOPOLOGY: { nodes: TopoNode[]; links: TopoLink[] } = (() => {
  const defs: [string, DeviceType, string, number][] = [
    ["fw-01", "firewall", "Edge", 0.6],
    ["gw-01", "router", "Edge", 0.7],
    ["lb-01", "router", "Edge", 0.5],
    ["web-01", "server", "External", 0.9],
    ["web-02", "server", "External", 0.7],
    ["api-01", "server", "External", 0.8],
    ["api-02", "server", "External", 0.6],
    ["app-01", "server", "Internal", 0.7],
    ["app-02", "server", "Internal", 0.6],
    ["db-01", "database", "Internal", 0.8],
    ["db-02", "database", "Internal", 0.5],
    ["ws-01", "endpoint", "Internal", 0.3],
    ["ws-02", "endpoint", "Internal", 0.3],
    ["ws-03", "endpoint", "Internal", 0.3],
    ["s3-assets", "cloud", "Cloud", 0.5],
    ["cdn-edge", "cloud", "Cloud", 0.6],
  ];
  const nodes: TopoNode[] = defs.map(([id, type, zone, weight]) => ({
    id,
    label: id,
    type,
    zone,
    weight,
  }));
  return { nodes, links: starLinks(nodes) };
})();

// ------------------------------------------------------------------ small helpers

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    const path = u.pathname.length > 24 ? u.pathname.slice(0, 23) + "…" : u.pathname;
    return u.host + path;
  } catch {
    return url.length > 40 ? url.slice(0, 39) + "…" : url;
  }
}

function statusClass(status: number | null): string {
  if (status === null) return "status muted";
  if (status >= 500) return "status s5";
  if (status >= 400) return "status s4";
  if (status >= 300) return "status s3";
  return "status s2";
}

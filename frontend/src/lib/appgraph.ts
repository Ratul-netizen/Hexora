/**
 * Two derivations the dashboard graphs stand on.
 *
 * `classifyDevice` reads a host's response signals — the Server banner, X-Powered-By, a
 * Via or CDN header, the content type — to decide what kind of thing answered, rather
 * than guessing from the hostname alone. A `cloudflare` Server is a WAF, an `AmazonS3`
 * one is storage, `nginx` with a `PHP` X-Powered-By is an app server, and so on.
 *
 * `buildAppGraph` turns the site map into the application's shape: a tree of the paths
 * that were reached, each typed as a page, an API, an asset, a form or a redirect. It is
 * the "what does this app look like" view that sits beside the infrastructure one.
 *
 * Both are best-effort reads of captured traffic, never active probes.
 */

import type { DeviceType, TopoLink, TopoNode } from "../components/TopologyGraph";
import type { SitemapHost, SitemapPath } from "../ipc";

export interface HostSignals {
  server: string;
  poweredBy: string;
  via: string;
  contentType: string;
  secure: boolean;
}

/** Pull the signals we classify on out of a raw response head. */
export function parseSignals(responseHead: string): Omit<HostSignals, "secure"> {
  const header = (name: string): string => {
    const re = new RegExp(`^${name}\\s*:\\s*(.+)$`, "im");
    const m = responseHead.match(re);
    return m && m[1] ? m[1].trim() : "";
  };
  return {
    server: header("server"),
    poweredBy: header("x-powered-by"),
    via: header("via"),
    contentType: header("content-type"),
  };
}

const WAF_VENDORS = /cloudflare|sucuri|incapsula|imperva|barracuda|f5|big-?ip|awselb|mod_security|akamaighost/i;
const CDN_VENDORS = /cloudfront|akamai|fastly|amazons3|amazon s3|google frontend|gws|azure|vercel|netlify|cdn/i;
const PROXY_VENDORS = /kong|envoy|traefik|haproxy|varnish|squid|nginx.*proxy/i;
const WEB_SERVERS = /nginx|apache|microsoft-iis|iis|litespeed|openresty|caddy|jetty|tomcat|gunicorn|kestrel/i;
const FRAMEWORKS = /asp\.?net|php|express|next\.?js|django|rails|laravel|spring|flask|node\.?js/i;

/**
 * Classify a host into a device kind and zone, and name the backend tech when we can see
 * it. Signals win over the hostname; the hostname is the fallback.
 */
export function classifyDevice(
  host: string,
  signals?: HostSignals,
): { type: DeviceType; zone: string; tech: string } {
  const h = host.toLowerCase();
  const server = signals?.server ?? "";
  const powered = signals?.poweredBy ?? "";
  const via = signals?.via ?? "";
  const banner = `${server} ${via}`;

  const isPrivate =
    /^127\./.test(h) ||
    h.startsWith("localhost") ||
    h.startsWith("::1") ||
    /^10\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
    /\b(internal|intranet|corp|local|lan)\b/.test(h);

  const tech = [server, powered].filter(Boolean).join(" · ");

  // 1) Signal-driven — most specific first.
  if (WAF_VENDORS.test(banner)) return { type: "firewall", zone: "Edge", tech: tech || "WAF" };
  if (CDN_VENDORS.test(banner)) return { type: "cloud", zone: "Cloud", tech: tech || "CDN" };
  if (PROXY_VENDORS.test(banner) || via) return { type: "router", zone: "Edge", tech: tech || "proxy" };
  if (FRAMEWORKS.test(powered) || FRAMEWORKS.test(server))
    return { type: "server", zone: isPrivate ? "Internal" : "External", tech };
  if (WEB_SERVERS.test(server))
    return { type: "server", zone: isPrivate ? "Internal" : "External", tech };

  // 2) Hostname fallback.
  if (/\b(fw|firewall|waf)\b/.test(h)) return { type: "firewall", zone: "Edge", tech };
  if (/\b(gw|gateway|proxy|router|edge|ingress|lb|balancer)\b/.test(h))
    return { type: "router", zone: "Edge", tech };
  if (/\b(db|sql|postgres|mysql|mongo|redis|oracle|mariadb)\b/.test(h))
    return { type: "database", zone: "Internal", tech };
  if (/\b(cdn|s3|storage|blob|bucket|cloud|aws|azure|gcp|fastly|akamai)\b/.test(h))
    return { type: "cloud", zone: "Cloud", tech };
  if (isPrivate) return { type: "endpoint", zone: "Internal", tech };
  return { type: "server", zone: "External", tech };
}

// ------------------------------------------------------------------ app graph

const ASSET_RE = /\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|pdf)(?:$|\?)/i;
const API_RE = /(?:^|\/)(?:api|graphql|rest|v\d+|oauth|token|\.json)(?:$|\/|\?)/i;

/** What kind of endpoint a path is, from its shape, the methods it took and its statuses. */
export function endpointKind(p: SitemapPath): DeviceType {
  const path = p.path;
  const changing = p.methods.some((m) => /^(POST|PUT|PATCH|DELETE)$/i.test(m));
  const allRedirect = p.statuses.length > 0 && p.statuses.every((s) => s >= 300 && s < 400);
  if (allRedirect) return "redirect";
  if (ASSET_RE.test(path)) return "asset";
  if (changing) return "form";
  if (API_RE.test(path)) return "api";
  return "page";
}

function shortPath(path: string): string {
  const clean = path.split("?")[0] ?? path;
  const label = clean === "/" ? "/" : clean.replace(/\/$/, "");
  return label.length > 22 ? "…" + label.slice(-21) : label;
}

/** The longest captured path that is a proper ancestor of `p`, if any. */
function ancestorOf(p: string, all: string[]): string | null {
  const base = (p.split("?")[0] ?? p).replace(/\/$/, "");
  let best: string | null = null;
  for (const q of all) {
    if (q === p) continue;
    const qb = (q.split("?")[0] ?? q).replace(/\/$/, "");
    if (qb === "") continue;
    if (base.startsWith(qb + "/") && (best === null || qb.length > best.length)) best = q;
  }
  return best;
}

/**
 * Build the application structure as a graph: a root per host, then its paths as a tree
 * by URL prefix, each node typed as a page / API / asset / form / redirect.
 */
export function buildAppGraph(
  hosts: SitemapHost[],
  signalsByHost: Map<string, HostSignals>,
): { nodes: TopoNode[]; links: TopoLink[] } {
  const nodes: TopoNode[] = [];
  const links: TopoLink[] = [];

  for (const host of hosts) {
    const rootId = `host:${host.host}`;
    const dev = classifyDevice(host.host, signalsByHost.get(host.host));
    nodes.push({
      id: rootId,
      label: host.host,
      type: dev.type,
      zone: host.host,
      weight: 1,
    });

    const paths = host.paths.map((p) => p.path);
    for (const p of host.paths) {
      const id = `${host.host}${p.path}`;
      nodes.push({
        id,
        label: shortPath(p.path),
        type: endpointKind(p),
        zone: host.host,
        weight: 0.3 + Math.min(0.5, (p.methods.length + p.statuses.length) * 0.08),
      });
      const anc = ancestorOf(p.path, paths);
      links.push({ source: id, target: anc ? `${host.host}${anc}` : rootId });
    }
  }

  return { nodes, links };
}

export const APP_LEGEND: { type: DeviceType; label: string }[] = [
  { type: "page", label: "Page" },
  { type: "api", label: "API / JSON" },
  { type: "form", label: "Form / write" },
  { type: "asset", label: "Static asset" },
  { type: "redirect", label: "Redirect" },
  { type: "server", label: "Host" },
];

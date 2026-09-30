/**
 * "Copy as …" — turn a captured request into a runnable snippet.
 *
 * The snippet is meant to reproduce the request outside Nullhawk, in a report or a
 * terminal, so it is built from the head exactly as it was sent. Two headers the client
 * must recompute — Content-Length and the hop-by-hop Transfer-Encoding — are dropped, so
 * the snippet does not send a stale length; nothing else is reordered or rewritten.
 */

export interface ParsedRequest {
  method: string;
  target: string;
  headers: [string, string][];
}

const DROP_HEADERS = new Set(["content-length", "transfer-encoding"]);

export function parseRequestHead(head: string): ParsedRequest {
  const lines = head.split(/\r?\n/);
  const first = lines[0] ?? "";
  const [method = "GET", target = "/"] = first.split(/\s+/);
  const headers: [string, string][] = [];
  for (const line of lines.slice(1)) {
    if (line.trim() === "") continue;
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (DROP_HEADERS.has(name.toLowerCase())) continue;
    headers.push([name, value]);
  }
  return { method, target, headers };
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

export function toCurl(url: string, head: string, body: string): string {
  const req = parseRequestHead(head);
  const parts = [`curl -i -X ${req.method} ${shellQuote(url)}`];
  for (const [name, value] of req.headers) {
    parts.push(`  -H ${shellQuote(`${name}: ${value}`)}`);
  }
  if (body) parts.push(`  --data-raw ${shellQuote(body)}`);
  return parts.join(" \\\n");
}

export function toPython(url: string, head: string, body: string): string {
  const req = parseRequestHead(head);
  const headerLines = req.headers
    .map(([name, value]) => `    ${JSON.stringify(name)}: ${JSON.stringify(value)},`)
    .join("\n");
  const dataArg = body ? `, data=${JSON.stringify(body)}` : "";
  return [
    "import requests",
    "",
    "headers = {",
    headerLines,
    "}",
    "",
    `resp = requests.request(${JSON.stringify(req.method)}, ${JSON.stringify(url)}, headers=headers${dataArg})`,
    "print(resp.status_code)",
    "print(resp.text)",
  ].join("\n");
}

export function toFetch(url: string, head: string, body: string): string {
  const req = parseRequestHead(head);
  const headerLines = req.headers
    .map(([name, value]) => `    ${JSON.stringify(name)}: ${JSON.stringify(value)},`)
    .join("\n");
  const bodyLine = body ? `\n  body: ${JSON.stringify(body)},` : "";
  return [
    `fetch(${JSON.stringify(url)}, {`,
    `  method: ${JSON.stringify(req.method)},`,
    "  headers: {",
    headerLines,
    "  }," + bodyLine,
    "})",
    "  .then((r) => r.text())",
    "  .then(console.log);",
  ].join("\n");
}

export type CopyFormat = "curl" | "python" | "fetch";

export function formatRequest(
  format: CopyFormat,
  url: string,
  head: string,
  body: string,
): string {
  if (format === "curl") return toCurl(url, head, body);
  if (format === "python") return toPython(url, head, body);
  return toFetch(url, head, body);
}

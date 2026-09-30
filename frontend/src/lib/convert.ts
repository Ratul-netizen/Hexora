/**
 * Convert a request body between JSON, XML and form-urlencoded.
 *
 * The reason this earns a place is parser-differential bugs: an endpoint that authorizes
 * a JSON body but parses an XML one, or a filter that inspects form fields but waves JSON
 * through. Handing you the same data in another content type is how you find the mismatch.
 *
 * Conversions are best-effort and lossy by nature (form values have no types; XML has no
 * arrays). The point is a body you can send and observe, not a round-trip guarantee.
 */

export type BodyFormat = "json" | "xml" | "form";

export function detectFormat(text: string): BodyFormat | null {
  const t = text.trim();
  if (t === "") return null;
  if (t.startsWith("{") || t.startsWith("[")) {
    try {
      JSON.parse(t);
      return "json";
    } catch {
      return null;
    }
  }
  if (t.startsWith("<")) return "xml";
  if (/^[^=&\s]+=[^=&]*(&[^=&\s]+=[^=&]*)*$/.test(t)) return "form";
  return null;
}

// ---- parse any format to a JS value ----

function parseForm(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of text.trim().split("&")) {
    if (pair === "") continue;
    const idx = pair.indexOf("=");
    const k = decodeURIComponent(idx < 0 ? pair : pair.slice(0, idx)).replace(/\+/g, " ");
    const v = idx < 0 ? "" : decodeURIComponent(pair.slice(idx + 1).replace(/\+/g, " "));
    out[k] = v;
  }
  return out;
}

function parseXml(text: string): unknown {
  if (typeof DOMParser === "undefined") throw new Error("XML parsing is unavailable here.");
  const doc = new DOMParser().parseFromString(text, "application/xml");
  if (doc.querySelector("parsererror")) throw new Error("Malformed XML.");
  const root = doc.documentElement;
  return { [root.nodeName]: xmlNodeToValue(root) };
}

function xmlNodeToValue(node: Element): unknown {
  const children = Array.from(node.children);
  if (children.length === 0) return node.textContent ?? "";
  const obj: Record<string, unknown> = {};
  for (const child of children) {
    const value = xmlNodeToValue(child);
    const existing = obj[child.nodeName];
    if (existing === undefined) obj[child.nodeName] = value;
    else if (Array.isArray(existing)) existing.push(value);
    else obj[child.nodeName] = [existing, value];
  }
  return obj;
}

export function toValue(text: string, from: BodyFormat): unknown {
  if (from === "json") return JSON.parse(text);
  if (from === "form") return parseForm(text);
  return parseXml(text);
}

// ---- serialise a JS value to any format ----

function toForm(value: unknown): string {
  const pairs: string[] = [];
  const walk = (prefix: string, v: unknown) => {
    if (v === null || typeof v !== "object") {
      pairs.push(`${encodeURIComponent(prefix)}=${encodeURIComponent(String(v ?? ""))}`);
      return;
    }
    if (Array.isArray(v)) {
      v.forEach((item, i) => walk(`${prefix}[${i}]`, item));
      return;
    }
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      walk(prefix === "" ? k : `${prefix}[${k}]`, val);
    }
  };
  walk("", value);
  return pairs.join("&");
}

function esc(s: string): string {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c] ?? c);
}

function toXml(value: unknown, tag = "root", indent = ""): string {
  if (value === null || typeof value !== "object") {
    return `${indent}<${tag}>${esc(String(value ?? ""))}</${tag}>`;
  }
  if (Array.isArray(value)) {
    return value.map((v) => toXml(v, tag, indent)).join("\n");
  }
  const inner = Object.entries(value as Record<string, unknown>)
    .map(([k, v]) => toXml(v, k.replace(/[^\w.-]/g, "_"), indent + "  "))
    .join("\n");
  return `${indent}<${tag}>\n${inner}\n${indent}</${tag}>`;
}

export function fromValue(value: unknown, to: BodyFormat): string {
  if (to === "json") return JSON.stringify(value, null, 2);
  if (to === "form") return toForm(value);
  // A JSON object with a single root key serialises cleanly; otherwise wrap it.
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const keys = Object.keys(value as Record<string, unknown>);
    const k = keys[0];
    if (keys.length === 1 && k) {
      return `<?xml version="1.0"?>\n${toXml((value as Record<string, unknown>)[k], k)}`;
    }
  }
  return `<?xml version="1.0"?>\n${toXml(value, "root")}`;
}

/** Convert text from its detected (or given) format into `to`. */
export function convert(text: string, to: BodyFormat, from?: BodyFormat): string {
  const source = from ?? detectFormat(text);
  if (!source) throw new Error("Could not tell what format this is.");
  if (source === to) return text;
  return fromValue(toValue(text, source), to);
}

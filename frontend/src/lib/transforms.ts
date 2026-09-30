/**
 * A chainable transform pipeline — decode, encode, hash — of the kind Hackvertor and
 * Decoder Improved give you. You stack steps and watch the value change at each one, so
 * a triple-encoded payload comes apart one layer at a time instead of in a guess.
 *
 * Every step is pure and total: an input that cannot be decoded comes back with a short
 * "(cannot decode …)" marker rather than throwing, so one bad step never empties the
 * whole chain. Hashes go through Web Crypto and are therefore async, so the runner is.
 */

export interface Transform {
  id: string;
  label: string;
  group: "decode" | "encode" | "hash" | "text";
  fn: (input: string) => string | Promise<string>;
}

// ---- helpers ----

const enc = new TextEncoder();

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function digest(algo: string, input: string): Promise<string> {
  const buf = await crypto.subtle.digest(algo, enc.encode(input));
  return toHex(buf);
}

function b64encode(s: string): string {
  const bytes = enc.encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64decode(s: string): string {
  try {
    const bin = atob(s.trim());
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return "(cannot decode base64)";
  }
}

function htmlEncode(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c,
  );
}

function htmlDecode(s: string): string {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;|&apos;/g, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)));
}

function toHexString(s: string): string {
  return [...enc.encode(s)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHexString(s: string): string {
  const clean = s.replace(/0x|[\s,]/gi, "");
  if (!/^[0-9a-f]*$/i.test(clean) || clean.length % 2 !== 0) return "(cannot decode hex)";
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return new TextDecoder().decode(bytes);
}

export const TRANSFORMS: Transform[] = [
  { id: "b64.decode", label: "Base64 decode", group: "decode", fn: b64decode },
  { id: "b64.encode", label: "Base64 encode", group: "encode", fn: b64encode },
  {
    id: "b64url.decode",
    label: "Base64URL decode",
    group: "decode",
    fn: (s) => b64decode(s.replace(/-/g, "+").replace(/_/g, "/")),
  },
  {
    id: "url.decode",
    label: "URL decode",
    group: "decode",
    fn: (s) => {
      try {
        return decodeURIComponent(s.replace(/\+/g, "%20"));
      } catch {
        return "(cannot url-decode)";
      }
    },
  },
  { id: "url.encode", label: "URL encode", group: "encode", fn: (s) => encodeURIComponent(s) },
  {
    id: "url.encodeAll",
    label: "URL encode (all bytes)",
    group: "encode",
    fn: (s) => [...enc.encode(s)].map((b) => "%" + b.toString(16).padStart(2, "0")).join(""),
  },
  { id: "html.decode", label: "HTML decode", group: "decode", fn: htmlDecode },
  { id: "html.encode", label: "HTML encode", group: "encode", fn: htmlEncode },
  { id: "hex.decode", label: "Hex decode", group: "decode", fn: fromHexString },
  { id: "hex.encode", label: "Hex encode", group: "encode", fn: toHexString },
  {
    id: "unicode.escape",
    label: "Unicode escape (\\uXXXX)",
    group: "encode",
    fn: (s) => [...s].map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join(""),
  },
  {
    id: "jwt.decode",
    label: "JWT decode (header.payload)",
    group: "decode",
    fn: (s) => {
      const [h, p] = s.trim().split(".");
      if (!h || !p) return "(not a JWT)";
      const url = (x: string) => x.replace(/-/g, "+").replace(/_/g, "/");
      return `${b64decode(url(h))}\n${b64decode(url(p))}`;
    },
  },
  { id: "hash.sha1", label: "SHA-1", group: "hash", fn: (s) => digest("SHA-1", s) },
  { id: "hash.sha256", label: "SHA-256", group: "hash", fn: (s) => digest("SHA-256", s) },
  { id: "hash.sha384", label: "SHA-384", group: "hash", fn: (s) => digest("SHA-384", s) },
  { id: "hash.sha512", label: "SHA-512", group: "hash", fn: (s) => digest("SHA-512", s) },
  { id: "text.upper", label: "Uppercase", group: "text", fn: (s) => s.toUpperCase() },
  { id: "text.lower", label: "Lowercase", group: "text", fn: (s) => s.toLowerCase() },
  { id: "text.reverse", label: "Reverse", group: "text", fn: (s) => [...s].reverse().join("") },
  {
    id: "text.rot13",
    label: "ROT13",
    group: "text",
    fn: (s) =>
      s.replace(/[a-z]/gi, (c) => {
        const base = c <= "Z" ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      }),
  },
];

export function transformById(id: string): Transform | undefined {
  return TRANSFORMS.find((t) => t.id === id);
}

/** Run a pipeline of transform ids, returning the value after each step. */
export async function runPipeline(input: string, ids: string[]): Promise<string[]> {
  const steps: string[] = [];
  let current = input;
  for (const id of ids) {
    const t = transformById(id);
    if (!t) continue;
    current = await t.fn(current);
    steps.push(current);
  }
  return steps;
}

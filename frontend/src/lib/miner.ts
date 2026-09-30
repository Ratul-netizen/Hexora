/**
 * Pull attack surface out of a body: endpoints hidden in JavaScript, secrets left in
 * source, and hints of vulnerable libraries.
 *
 * This is the job a handful of well-loved Burp extensions do (JS link finders, secret
 * scanners, retire.js). It reads text and reports matches — it never fetches, decodes a
 * live token, or decides that a match is exploitable. A "secret" here is a string that
 * looks like one; whether it still works is for you to check.
 */

export interface Endpoint {
  value: string;
  kind: "absolute" | "path";
}

export interface SecretHit {
  type: string;
  match: string;
  line: number;
}

export interface LibraryHit {
  name: string;
  version: string;
}

export interface MineResult {
  endpoints: Endpoint[];
  secrets: SecretHit[];
  libraries: LibraryHit[];
}

const SECRET_PATTERNS: { type: string; re: RegExp }[] = [
  { type: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: "AWS secret access key", re: /\baws_secret_access_key["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})\b/gi },
  { type: "Google API key", re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { type: "Google OAuth token", re: /\bya29\.[0-9A-Za-z\-_]+/g },
  { type: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { type: "Slack webhook", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g },
  { type: "GitHub token", re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g },
  { type: "Stripe key", re: /\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
  { type: "Private key block", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type: "JWT", re: /\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/g },
  { type: "Bearer token", re: /\b[Bb]earer\s+[A-Za-z0-9\-._~+/]{16,}=*/g },
  { type: "Generic secret assignment", re: /\b(?:api[_-]?key|apikey|secret|passwd|password|token|access[_-]?token)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/gi },
];

const ENDPOINT_IN_STRING = /["'`](\/[A-Za-z0-9_\-./?=&%:@]*|https?:\/\/[A-Za-z0-9_\-./?=&%:@]+)["'`]/g;

// A pragmatic slice of retire.js: library markers that carry a version in the source.
const LIBRARY_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "jQuery", re: /jquery[.-]?v?(\d+\.\d+(?:\.\d+)?)/i },
  { name: "AngularJS", re: /angular[.-]?v?(\d+\.\d+(?:\.\d+)?)/i },
  { name: "React", re: /react(?:-dom)?[.@-]v?(\d+\.\d+(?:\.\d+)?)/i },
  { name: "Vue", re: /vue[.@-]v?(\d+\.\d+(?:\.\d+)?)/i },
  { name: "Lodash", re: /lodash[.@-]v?(\d+\.\d+(?:\.\d+)?)/i },
  { name: "Bootstrap", re: /bootstrap[.@-]v?(\d+\.\d+(?:\.\d+)?)/i },
  { name: "Moment.js", re: /moment[.@-]v?(\d+\.\d+(?:\.\d+)?)/i },
];

/** Redact the middle of a long match so the report does not leak the whole secret. */
function redact(s: string): string {
  const trimmed = s.trim();
  if (trimmed.length <= 12) return trimmed;
  return `${trimmed.slice(0, 6)}…${trimmed.slice(-4)}`;
}

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

export function mine(text: string): MineResult {
  // Endpoints
  const endpointSet = new Map<string, Endpoint>();
  for (const m of text.matchAll(ENDPOINT_IN_STRING)) {
    const value = m[1];
    if (!value) continue;
    // Skip noise: pure "/", mime types, obvious asset dirs are still kept but junk like
    // single characters or protocol-relative fragments are dropped.
    if (value.length < 2) continue;
    const kind: Endpoint["kind"] = value.startsWith("http") ? "absolute" : "path";
    if (!endpointSet.has(value)) endpointSet.set(value, { value, kind });
  }

  // Secrets
  const secrets: SecretHit[] = [];
  const seenSecret = new Set<string>();
  for (const { type, re } of SECRET_PATTERNS) {
    for (const m of text.matchAll(re)) {
      const whole = m[1] ?? m[0];
      const key = `${type}:${whole}`;
      if (seenSecret.has(key)) continue;
      seenSecret.add(key);
      secrets.push({ type, match: redact(whole), line: lineOf(text, m.index ?? 0) });
    }
  }

  // Libraries
  const libraries: LibraryHit[] = [];
  const seenLib = new Set<string>();
  for (const { name, re } of LIBRARY_PATTERNS) {
    const m = re.exec(text);
    if (m && m[1] && !seenLib.has(name)) {
      seenLib.add(name);
      libraries.push({ name, version: m[1] });
    }
  }

  return {
    endpoints: [...endpointSet.values()].sort((a, b) => a.value.localeCompare(b.value)),
    secrets,
    libraries,
  };
}

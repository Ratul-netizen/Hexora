import { useMemo, useState } from "react";

/**
 * The decoder — transform a value the way a manual tester does a hundred times a day.
 *
 * Every other view is about traffic the engine sent or stored. This one sends nothing
 * and stores nothing: it is a bench for turning a value into another value, so a tester
 * can read a base64 cookie, url-encode a payload before pasting it into the repeater, or
 * see what a JWT actually claims without leaving the window for an untrusted website.
 *
 * That last point is the reason it is built in rather than left to a browser tab. The
 * values a pentester decodes are session tokens and live payloads; pasting them into
 * jwt.io or an online base64 decoder hands someone else the credential. Every transform
 * here runs locally, in this process, on data that never leaves the machine.
 *
 * The transforms are deliberately total: a decode that cannot make sense of its input
 * says so on the line rather than throwing, because a tester chaining transforms wants
 * to see where the chain broke, not lose the whole pipeline to one bad step.
 */

type Direction = "encode" | "decode";

interface Transform {
  id: string;
  label: string;
  /** Absent for transforms that only go one way (a hash cannot be un-hashed). */
  encode?: (input: string) => string;
  decode?: (input: string) => string;
  /** A one-line note shown under the picker, for the transform that needs a caveat. */
  note?: string;
}

/** UTF-8 aware base64, so a multibyte payload survives a round trip. */
function toBase64(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromBase64(input: string): string {
  // Accept both standard and URL-safe alphabets, and tolerate missing padding, because
  // a token lifted off the wire is often URL-safe and unpadded.
  let normalized = input.trim().replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4 !== 0) normalized += "=";
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function toHex(input: string): string {
  const bytes = new TextEncoder().encode(input);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(input: string): string {
  const clean = input.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2 !== 0) throw new Error("odd number of hex digits");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

const HTML_ENTITIES: [RegExp, string][] = [
  [/&/g, "&amp;"],
  [/</g, "&lt;"],
  [/>/g, "&gt;"],
  [/"/g, "&quot;"],
  [/'/g, "&#39;"],
];

function encodeHtml(input: string): string {
  return HTML_ENTITIES.reduce((acc, [re, ent]) => acc.replace(re, ent), input);
}

function decodeHtml(input: string): string {
  return input
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => String.fromCodePoint(parseInt(code, 16)))
    .replace(/&amp;/g, "&");
}

/** Pretty-print a JWT's header and payload. Never verifies — that needs the key. */
function decodeJwt(input: string): string {
  const parts = input.trim().split(".");
  if (parts.length < 2) throw new Error("not a JWT (expected header.payload.signature)");
  const header = parts[0];
  const payload = parts[1];
  if (header === undefined || payload === undefined) throw new Error("malformed JWT");
  const decodePart = (segment: string) => {
    const json = fromBase64(segment);
    return JSON.stringify(JSON.parse(json), null, 2);
  };
  const out = [`// header\n${decodePart(header)}`, `// payload\n${decodePart(payload)}`];
  if (parts[2]) {
    out.push(
      "// signature present but NOT verified — verifying needs the signing key, which " +
        "this bench does not have and would not send anywhere if it did.",
    );
  }
  return out.join("\n\n");
}

const TRANSFORMS: [Transform, ...Transform[]] = [
  {
    id: "base64",
    label: "Base64",
    encode: toBase64,
    decode: fromBase64,
    note: "Decodes both standard and URL-safe alphabets, padded or not.",
  },
  {
    id: "url",
    label: "URL",
    encode: (s) => encodeURIComponent(s),
    decode: (s) => decodeURIComponent(s),
  },
  {
    id: "url-all",
    label: "URL (every byte)",
    encode: (s) =>
      Array.from(new TextEncoder().encode(s))
        .map((b) => `%${b.toString(16).padStart(2, "0").toUpperCase()}`)
        .join(""),
    decode: (s) => decodeURIComponent(s),
    note: "Percent-encodes every byte, not only the reserved ones — for a filter that only inspects unencoded characters.",
  },
  { id: "html", label: "HTML entities", encode: encodeHtml, decode: decodeHtml },
  { id: "hex", label: "Hex", encode: toHex, decode: fromHex },
  {
    id: "jwt",
    label: "JWT (decode)",
    decode: decodeJwt,
    note: "Reads the claims. Does not — and cannot — verify the signature.",
  },
];

export function DecoderView() {
  const [input, setInput] = useState("");
  const [transformId, setTransformId] = useState("base64");
  const [direction, setDirection] = useState<Direction>("decode");

  const transform = TRANSFORMS.find((t) => t.id === transformId) ?? TRANSFORMS[0];
  const canEncode = transform.encode !== undefined;
  const canDecode = transform.decode !== undefined;

  // A one-way transform (JWT) forces its only direction, so the buttons never offer an
  // action that does nothing.
  const effectiveDirection: Direction = canEncode && canDecode
    ? direction
    : canEncode
      ? "encode"
      : "decode";

  const output = useMemo(() => {
    if (input === "") return { text: "", error: null as string | null };
    try {
      const fn = effectiveDirection === "encode" ? transform.encode : transform.decode;
      if (!fn) return { text: "", error: "this transform does not go that way" };
      return { text: fn(input), error: null };
    } catch (e) {
      return { text: "", error: e instanceof Error ? e.message : String(e) };
    }
  }, [input, transform, effectiveDirection]);

  return (
    <div className="decoder">
      <header className="detail-header">
        <div className="modes">
          {TRANSFORMS.map((t) => (
            <button
              key={t.id}
              className={t.id === transformId ? "tab active" : "tab"}
              onClick={() => setTransformId(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>

        {canEncode && canDecode && (
          <div className="modes">
            {(["decode", "encode"] as const).map((d) => (
              <button
                key={d}
                className={effectiveDirection === d ? "tab active" : "tab"}
                onClick={() => setDirection(d)}
              >
                {d === "decode" ? "Decode" : "Encode"}
              </button>
            ))}
          </div>
        )}

        <button
          onClick={() => {
            if (output.text) setInput(output.text);
          }}
          disabled={!output.text}
          title="Feed the output back in, to chain transforms"
        >
          Output → Input
        </button>
      </header>

      {transform.note && <p className="muted small">{transform.note}</p>}

      <div className="decoder-panes">
        <section>
          <label className="muted small">Input</label>
          <textarea
            className="editor"
            value={input}
            spellCheck={false}
            placeholder="Paste a cookie, a token, a payload…"
            onChange={(e) => setInput(e.target.value)}
          />
        </section>

        <section>
          <label className="muted small">
            Output · {transform.label} · {effectiveDirection}
          </label>
          {output.error ? (
            <p className="error-text">{output.error}</p>
          ) : (
            <textarea
              className="editor"
              value={output.text}
              readOnly
              spellCheck={false}
              placeholder="Result appears here."
            />
          )}
        </section>
      </div>

      <p className="muted small">
        Everything here runs locally. Nothing you paste is sent anywhere — that is the
        point of not using an online decoder for a live session token.
      </p>
    </div>
  );
}

/**
 * Body pretty-printing for the message panes.
 *
 * The aim is only to make a captured body legible — indent JSON, break markup onto its
 * own lines — never to change what it says. Every function is pure and total: if the
 * content will not parse, it returns null and the caller shows the bytes as they came,
 * because a body we cannot format is exactly the case where guessing would mislead.
 */

export type BodyLang = "json" | "xml" | "html" | null;

/** HTML elements that never have a closing tag, so they must not open an indent level. */
const VOID_ELEMENTS = new Set([
  "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
  "param", "source", "track", "wbr",
]);

/** Guess the body's language from a Content-Type hint first, then the content itself. */
export function detectLang(content: string, contentType?: string | null): BodyLang {
  const ct = (contentType ?? "").toLowerCase();
  if (ct.includes("json")) return "json";
  if (ct.includes("html")) return "html";
  if (ct.includes("xml")) return "xml";

  const trimmed = content.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return tryJson(content) !== null ? "json" : null;
  }
  if (trimmed.startsWith("<")) {
    const head = trimmed.slice(0, 200).toLowerCase();
    return head.includes("<!doctype html") || head.includes("<html") ? "html" : "xml";
  }
  return null;
}

/** Pretty-print for the detected language, or null if it cannot be formatted. */
export function prettify(content: string, lang: BodyLang): string | null {
  if (lang === "json") return prettyJson(content);
  if (lang === "xml" || lang === "html") return prettyMarkup(content);
  return null;
}

function tryJson(content: string): unknown | null {
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

function prettyJson(content: string): string | null {
  const parsed = tryJson(content);
  if (parsed === null && content.trim() !== "null") return null;
  try {
    return JSON.stringify(parsed, null, 2);
  } catch {
    return null;
  }
}

/**
 * Indent markup by putting each tag on its own line and tracking nesting depth. It is a
 * viewer's formatter, not a parser: it leaves text content intact and treats void and
 * self-closing tags as level-neutral, which is enough to read a response by eye.
 */
function prettyMarkup(input: string): string | null {
  const source = input.trim();
  if (!source.startsWith("<")) return null;

  // Break between adjacent tags so each lands on its own line.
  const withBreaks = source.replace(/>\s*</g, ">\n<");
  const lines = withBreaks.split("\n");
  const pad = "  ";
  let depth = 0;
  const out: string[] = [];

  for (const raw of lines) {
    const node = raw.trim();
    if (!node) continue;

    const isClosing = /^<\//.test(node);
    const isComment = /^<!--/.test(node);
    const isDecl = /^<[!?]/.test(node); // <!doctype ...>, <?xml ...?>
    const tagName = node.match(/^<\/?\s*([a-zA-Z0-9-]+)/)?.[1]?.toLowerCase() ?? "";
    const isVoid = VOID_ELEMENTS.has(tagName);
    const isSelfClosing = /\/>$/.test(node);
    // A one-line element that opens and closes on the same node, e.g. <title>x</title>.
    const opensAndCloses = /^<[^/!?][^>]*>.*<\/[^>]+>$/.test(node);

    if (isClosing) depth = Math.max(depth - 1, 0);

    out.push(pad.repeat(depth) + node);

    const opensLevel =
      !isClosing &&
      !isComment &&
      !isDecl &&
      !isVoid &&
      !isSelfClosing &&
      !opensAndCloses &&
      /^<[a-zA-Z]/.test(node);
    if (opensLevel) depth += 1;
  }

  return out.join("\n");
}

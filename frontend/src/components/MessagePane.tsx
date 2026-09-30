import { useMemo, useState } from "react";

import type { BodyPreview } from "../ipc";
import { detectLang, prettify, type BodyLang } from "./beautify";

/**
 * Renders one HTTP message: the head as written, then the body.
 *
 * The head is shown verbatim — original casing, duplicate fields and all — because
 * that is the entire point of the message model underneath. Nothing here re-orders,
 * re-cases or de-duplicates anything.
 *
 * The body may be beautified for reading. When it parses as JSON or markup the pane
 * offers a Pretty view beside the Raw bytes, but the two are the same content: Pretty
 * only re-indents, and Raw is always one click away, so nothing the formatter does can
 * hide what was actually on the wire.
 */
export function MessagePane({
  title,
  head,
  body,
}: {
  title: string;
  head: string;
  body: BodyPreview;
}) {
  const contentType = useMemo(() => extractContentType(head), [head]);
  return (
    <section className="message">
      <header className="message-header">
        <h3>{title}</h3>
        <span className="muted">{describeBody(body)}</span>
      </header>
      <pre className="head">{head}</pre>
      <BodyView body={body} contentType={contentType} />
    </section>
  );
}

function BodyView({
  body,
  contentType,
}: {
  body: BodyPreview;
  contentType: string | null;
}) {
  const lang: BodyLang = useMemo(
    () => (body.rendering === "text" ? detectLang(body.content, contentType) : null),
    [body.rendering, body.content, contentType],
  );
  const pretty = useMemo(
    () => (lang ? prettify(body.content, lang) : null),
    [lang, body.content],
  );

  const [mode, setMode] = useState<"pretty" | "raw">(pretty ? "pretty" : "raw");
  const [wrap, setWrap] = useState(false);
  const [copied, setCopied] = useState(false);

  if (body.rendering === "empty") {
    return <p className="muted empty-body">No body.</p>;
  }

  const shown = mode === "pretty" && pretty ? pretty : body.content;
  const isHex = body.rendering === "binary";

  const copy = () => {
    navigator.clipboard?.writeText(shown).then(
      () => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1200);
      },
      () => undefined,
    );
  };

  return (
    <div className="body-view">
      <div className="body-toolbar">
        {pretty && (
          <div className="seg">
            <button
              className={mode === "pretty" ? "seg-btn on" : "seg-btn"}
              onClick={() => setMode("pretty")}
            >
              Pretty
            </button>
            <button
              className={mode === "raw" ? "seg-btn on" : "seg-btn"}
              onClick={() => setMode("raw")}
            >
              Raw
            </button>
          </div>
        )}
        {lang && <span className="lang-badge">{lang.toUpperCase()}</span>}
        <div className="body-toolbar-right">
          {!isHex && (
            <button
              className={wrap ? "chip-btn on" : "chip-btn"}
              onClick={() => setWrap((w) => !w)}
              title="Toggle word wrap"
            >
              Wrap
            </button>
          )}
          <button className="chip-btn" onClick={copy}>
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </div>

      {body.truncated && (
        <p className="notice">
          Showing the first {body.content.length.toLocaleString()} of{" "}
          {body.total_bytes.toLocaleString()} bytes.
        </p>
      )}

      {isHex ? (
        <pre className="body hex">{shown}</pre>
      ) : (
        <CodeBlock text={shown} wrap={wrap} />
      )}
    </div>
  );
}

/** A body with a line-number gutter, the way a request pane is read line by line. */
function CodeBlock({ text, wrap }: { text: string; wrap: boolean }) {
  const lineCount = useMemo(() => text.split("\n").length, [text]);
  const gutter = useMemo(
    () => Array.from({ length: lineCount }, (_, i) => i + 1).join("\n"),
    [lineCount],
  );
  return (
    <div className={wrap ? "code-block wrap" : "code-block"}>
      <pre className="code-gutter" aria-hidden="true">
        {gutter}
      </pre>
      <pre className="code-body">{text}</pre>
    </div>
  );
}

/** Pull the Content-Type value out of a raw head, case-insensitively. */
function extractContentType(head: string): string | null {
  for (const line of head.split(/\r?\n/)) {
    const m = line.match(/^content-type\s*:\s*(.+)$/i);
    if (m && m[1]) return m[1].trim();
  }
  return null;
}

function describeBody(body: BodyPreview): string {
  if (body.rendering === "empty") return "no body";
  const size = `${body.total_bytes.toLocaleString()} bytes`;
  // "binary" is said out loud rather than implied by the hex, so nobody reads a hex
  // dump as the tool having failed to decode something it should have.
  return body.rendering === "binary" ? `${size}, binary` : size;
}

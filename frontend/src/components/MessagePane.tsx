import type { BodyPreview } from "../ipc";

/**
 * Renders one HTTP message: the head as written, then the body.
 *
 * The head is shown verbatim — original casing, duplicate fields and all — because
 * that is the entire point of the message model underneath. Nothing here re-orders,
 * re-cases or de-duplicates anything.
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
  return (
    <section className="message">
      <header className="message-header">
        <h3>{title}</h3>
        <span className="muted">{describeBody(body)}</span>
      </header>
      <pre className="head">{head}</pre>
      <BodyView body={body} />
    </section>
  );
}

function BodyView({ body }: { body: BodyPreview }) {
  if (body.rendering === "empty") {
    return <p className="muted empty-body">No body.</p>;
  }

  return (
    <>
      {body.truncated && (
        <p className="notice">
          Showing the first {body.content.length.toLocaleString()} of{" "}
          {body.total_bytes.toLocaleString()} bytes.
        </p>
      )}
      <pre className={body.rendering === "binary" ? "body hex" : "body"}>
        {body.content}
      </pre>
    </>
  );
}

function describeBody(body: BodyPreview): string {
  if (body.rendering === "empty") return "no body";
  const size = `${body.total_bytes.toLocaleString()} bytes`;
  // "binary" is said out loud rather than implied by the hex, so nobody reads a hex
  // dump as the tool having failed to decode something it should have.
  return body.rendering === "binary" ? `${size}, binary` : size;
}

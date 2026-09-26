import { useEffect, useState } from "react";

import {
  describeError,
  websocketMessages,
  websocketSessions,
  type WsMessageView,
  type WsSessionView,
} from "../ipc";

/**
 * Captured WebSocket sessions, and the message timeline of one.
 *
 * A WebSocket is not request/response, so it never appears in History as a single row: it
 * is a session of frames going both ways. This lists the sessions the proxy captured and
 * opens one as an ordered, both-directions timeline — the read side of WS.a.
 */
export function WebSocketsView({ hasProject }: { hasProject: boolean }) {
  const [sessions, setSessions] = useState<WsSessionView[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [messages, setMessages] = useState<WsMessageView[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!hasProject) return;
    websocketSessions()
      .then(setSessions)
      .catch((e) => setError(describeError(e)));
  }, [hasProject]);

  useEffect(() => {
    if (selected === null) return;
    websocketMessages(selected)
      .then(setMessages)
      .catch((e) => setError(describeError(e)));
  }, [selected]);

  if (!hasProject) {
    return <p className="placeholder">Open a project to see its WebSocket sessions.</p>;
  }

  return (
    <div className="websockets">
      <div className="ws-sessions">
        <h2>Sessions</h2>
        {error && <p className="error-text">{error}</p>}
        {sessions.length === 0 ? (
          <p className="muted small">No WebSocket sessions captured yet.</p>
        ) : (
          <ul>
            {sessions.map((session) => (
              <li key={session.id}>
                <button
                  className={selected === session.id ? "tab active" : "tab"}
                  onClick={() => setSelected(session.id)}
                >
                  <span className="mono">{session.url}</span>
                  <span className="muted small"> · {session.messages} messages</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="ws-timeline">
        {selected === null ? (
          <p className="placeholder">Select a session to see its messages.</p>
        ) : (
          <ul>
            {messages.map((message) => {
              const outbound = message.direction === "client_to_server";
              return (
                <li key={message.id} className={outbound ? "ws-out" : "ws-in"}>
                  <span className="ws-arrow">{outbound ? "→" : "←"}</span>
                  <span className="ws-op">{opcodeName(message.opcode)}</span>
                  <span className="muted small">{message.size}B</span>
                  <span className="mono ws-preview">{message.preview}</span>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

function opcodeName(opcode: number): string {
  switch (opcode) {
    case 0x0:
      return "cont";
    case 0x1:
      return "text";
    case 0x2:
      return "binary";
    case 0x8:
      return "close";
    case 0x9:
      return "ping";
    case 0xa:
      return "pong";
    default:
      return "other";
  }
}

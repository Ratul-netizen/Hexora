import { useCallback, useEffect, useState } from "react";

import { MessagePane } from "../components/MessagePane";
import {
  describeError,
  exchangeDetail,
  listHistory,
  type ExchangeDetail,
  type HistoryRow,
} from "../ipc";

const PAGE_SIZE = 200;

/**
 * Captured traffic, and one exchange in full.
 *
 * The table is the index and the panes below are the evidence. Selecting a row
 * fetches it rather than keeping every body in memory: a crawl produces gigabytes,
 * and a window that held all of it would stop responding long before it ran out.
 */
export function HistoryView({
  hasProject,
  refreshToken,
  onRepeat,
}: {
  hasProject: boolean;
  /** Changes whenever the proxy captures something, prompting a reload. */
  refreshToken: number;
  onRepeat: (id: string) => void;
}) {
  const [rows, setRows] = useState<HistoryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<ExchangeDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  const reload = useCallback(async () => {
    if (!hasProject) return;
    try {
      const page = await listHistory(null, PAGE_SIZE);
      setRows(page.rows);
      setTotal(page.total);
      setError(null);
    } catch (e) {
      setError(describeError(e));
    }
  }, [hasProject]);

  useEffect(() => {
    void reload();
  }, [reload, refreshToken]);

  useEffect(() => {
    if (selected === null) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    exchangeDetail(selected)
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch((e) => {
        if (!cancelled) setError(describeError(e));
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  if (!hasProject) {
    return <p className="placeholder">Open a project to see captured traffic.</p>;
  }

  const needle = filter.trim().toLowerCase();
  const shown =
    needle === ""
      ? rows
      : rows.filter(
          (row) =>
            row.url.toLowerCase().includes(needle) ||
            row.method.toLowerCase().includes(needle) ||
            String(row.status ?? "").includes(needle),
        );

  return (
    <div className="history">
      <div className="toolbar">
        <input
          type="text"
          value={filter}
          placeholder="Filter by URL, method or status"
          spellCheck={false}
          onChange={(e) => setFilter(e.target.value)}
        />
        <span className="muted">
          {shown.length.toLocaleString()} of {total.toLocaleString()}
          {total > PAGE_SIZE && ` (newest ${PAGE_SIZE})`}
        </span>
        <button onClick={() => void reload()}>Reload</button>
      </div>

      {error && <p className="error-text">{error}</p>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Method</th>
              <th>Status</th>
              <th>URL</th>
              <th className="numeric">Bytes</th>
              <th className="numeric">Time</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((row) => (
              <tr
                key={row.id}
                className={row.id === selected ? "selected" : ""}
                onClick={() => setSelected(row.id)}
              >
                <td className="mono">{row.method}</td>
                <td className={statusClass(row.status)}>{row.status ?? "—"}</td>
                <td className="url">
                  {!row.secure && <span className="tag insecure">http</span>}
                  {row.url}
                  {/* Framing anomalies are surfaced in the index, not buried in a
                      detail pane: a smuggling signal is worth noticing while
                      scrolling, which is the only time anyone would see it. */}
                  {row.quirks.length > 0 && (
                    <span className="tag quirk" title={row.quirks.join(", ")}>
                      {row.quirks.length} quirk
                      {row.quirks.length === 1 ? "" : "s"}
                    </span>
                  )}
                </td>
                <td className="numeric">{row.response_bytes.toLocaleString()}</td>
                <td className="numeric">
                  {row.duration_ms === null ? "—" : `${row.duration_ms}ms`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length === 0 && (
          <p className="placeholder">
            {rows.length === 0
              ? "Nothing captured yet. Start the proxy and browse."
              : "Nothing matches that filter."}
          </p>
        )}
      </div>

      {detail && (
        <div className="detail">
          <header className="detail-header">
            <span className="mono">{detail.url}</span>
            <span className="muted">
              {detail.origin} · {detail.sent_at}
            </span>
            <button onClick={() => onRepeat(detail.id)}>Send to repeater</button>
          </header>
          <div className="panes">
            <MessagePane
              title="Request"
              head={detail.request_head}
              body={detail.request_body}
            />
            <MessagePane
              title="Response"
              head={detail.response_head}
              body={detail.response_body}
            />
          </div>
        </div>
      )}
    </div>
  );
}

function statusClass(status: number | null): string {
  if (status === null) return "muted";
  if (status >= 500) return "status server-error";
  if (status >= 400) return "status client-error";
  if (status >= 300) return "status redirect";
  return "status ok";
}

import { useMemo, useState } from "react";

import {
  analyzeJwt,
  attackVariants,
  parseJwt,
  signHs256,
  type JwtParts,
  type JwtVariant,
} from "../lib/jwt";
import { mine, type MineResult } from "../lib/miner";
import { generateBypasses, type BypassCandidate } from "../lib/bypass";

/**
 * The toolkit: the standalone power tools a tester reaches for that do not need the
 * engine — a JWT workbench, a body miner, and a 403/WAF bypass generator. Each reads
 * what you give it and reports; the forging and the sending are deliberate, separate
 * acts you take with the result.
 */

type Tool = "jwt" | "miner" | "bypass";

export function ToolkitView() {
  const [tool, setTool] = useState<Tool>("jwt");
  return (
    <div className="toolkit">
      <div className="seg toolkit-switch">
        <button
          className={tool === "jwt" ? "seg-btn on" : "seg-btn"}
          onClick={() => setTool("jwt")}
        >
          JWT workbench
        </button>
        <button
          className={tool === "miner" ? "seg-btn on" : "seg-btn"}
          onClick={() => setTool("miner")}
        >
          Secret &amp; endpoint miner
        </button>
        <button
          className={tool === "bypass" ? "seg-btn on" : "seg-btn"}
          onClick={() => setTool("bypass")}
        >
          403 / WAF bypass
        </button>
      </div>
      {tool === "jwt" && <JwtPanel />}
      {tool === "miner" && <MinerPanel />}
      {tool === "bypass" && <BypassPanel />}
    </div>
  );
}

function copy(text: string) {
  navigator.clipboard?.writeText(text).catch(() => undefined);
}

// ---------------------------------------------------------------- JWT

function JwtPanel() {
  const [token, setToken] = useState("");
  const [secret, setSecret] = useState("");
  const [signed, setSigned] = useState<string | null>(null);
  const [signError, setSignError] = useState<string | null>(null);

  const parsed = useMemo((): { parts: JwtParts } | { error: string } | null => {
    if (token.trim() === "") return null;
    try {
      return { parts: parseJwt(token) };
    } catch (e) {
      return { error: e instanceof Error ? e.message : "Could not parse token." };
    }
  }, [token]);

  const weaknesses = parsed && "parts" in parsed ? analyzeJwt(parsed.parts) : [];
  const variants: JwtVariant[] = parsed && "parts" in parsed ? attackVariants(parsed.parts) : [];

  async function reSign() {
    if (!parsed || !("parts" in parsed)) return;
    setSignError(null);
    try {
      setSigned(await signHs256(parsed.parts.header, parsed.parts.payload, secret));
    } catch (e) {
      setSignError(e instanceof Error ? e.message : "Signing failed.");
    }
  }

  return (
    <div className="jwt">
      <section className="card">
        <h2>JWT workbench</h2>
        <p className="muted">
          Paste a token to decode it and see what is weak. Nothing is sent — the forged
          variants are yours to try from the Repeater, and a token is only a finding when
          the server accepts a forged one.
        </p>
        <textarea
          className="jwt-input mono"
          value={token}
          spellCheck={false}
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.…"
          onChange={(e) => setToken(e.target.value)}
        />
      </section>

      {parsed && "error" in parsed && <p className="error-text">{parsed.error}</p>}

      {parsed && "parts" in parsed && (
        <>
          <div className="jwt-grid">
            <section className="card">
              <h3>Header</h3>
              <pre className="code-body mono">{JSON.stringify(parsed.parts.header, null, 2)}</pre>
            </section>
            <section className="card">
              <h3>Payload</h3>
              <pre className="code-body mono">{JSON.stringify(parsed.parts.payload, null, 2)}</pre>
            </section>
          </div>

          {weaknesses.length > 0 && (
            <section className="card">
              <h3>What's weak</h3>
              <ul className="weakness-list">
                {weaknesses.map((w, i) => (
                  <li key={i}>
                    <span className={`badge sev-${w.severity}`}>{w.severity}</span>
                    <span>
                      <strong>{w.title}</strong>
                      <div className="muted small">{w.detail}</div>
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section className="card">
            <h3>Forged variants to try</h3>
            <ul className="variant-list">
              {variants.map((v) => (
                <li key={v.name}>
                  <div className="variant-head">
                    <strong>{v.name}</strong>
                    <button className="chip-btn" onClick={() => copy(v.token)}>
                      Copy
                    </button>
                  </div>
                  <pre className="code-body mono variant-token">{v.token}</pre>
                  <div className="muted small">{v.note}</div>
                </li>
              ))}
            </ul>
          </section>

          <section className="card">
            <h3>Re-sign (HS256)</h3>
            <p className="muted small">
              If the signature is HMAC and the secret is guessable, re-sign the current
              payload under a candidate secret and see if the server trusts it.
            </p>
            <div className="row">
              <input
                type="text"
                value={secret}
                placeholder="candidate secret, e.g. secret / changeme / a wordlist entry"
                onChange={(e) => setSecret(e.target.value)}
              />
              <button className="primary" onClick={() => void reSign()}>
                Sign
              </button>
            </div>
            {signError && <p className="error-text">{signError}</p>}
            {signed && (
              <>
                <pre className="code-body mono variant-token">{signed}</pre>
                <button className="chip-btn" onClick={() => copy(signed)}>
                  Copy signed token
                </button>
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- 403 / WAF bypass

function BypassPanel() {
  const [url, setUrl] = useState("");
  const [method, setMethod] = useState("GET");
  const [candidates, setCandidates] = useState<BypassCandidate[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  function generate() {
    setError(null);
    try {
      setCandidates(generateBypasses(url, method));
    } catch (e) {
      setCandidates(null);
      setError(e instanceof Error ? e.message : "Could not parse the URL.");
    }
  }

  const groups: BypassCandidate["group"][] = ["path", "header", "method"];
  const label: Record<BypassCandidate["group"], string> = {
    path: "Path mutations",
    header: "Header spoofing",
    method: "Method changes",
  };

  return (
    <div className="bypass">
      <section className="card">
        <h2>403 / WAF bypass</h2>
        <p className="muted">
          Give a forbidden URL and get the known mutations to try — path rewriting,
          header-driven auth spoofing, method changes. For authorized testing only.
          Nothing is sent: copy a candidate as curl, or paste it into the Repeater, and a
          bypass counts only when the server returns what the 403 withheld.
        </p>
        <div className="row">
          <select value={method} onChange={(e) => setMethod(e.target.value)}>
            {["GET", "POST", "PUT", "DELETE", "PATCH"].map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <input
            type="text"
            className="grow"
            value={url}
            placeholder="https://host/admin"
            spellCheck={false}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") generate();
            }}
          />
          <button className="primary" onClick={generate}>
            Generate
          </button>
        </div>
        {error && <p className="error-text">{error}</p>}
      </section>

      {candidates && (
        <>
          <div className="toolbar">
            <span className="muted">
              {candidates.length} candidate{candidates.length === 1 ? "" : "s"}
            </span>
            <button
              className="chip-btn"
              onClick={() => copy(candidates.map((c) => c.curl).join("\n\n"))}
            >
              Copy all as curl
            </button>
          </div>
          {groups.map((g) => {
            const rows = candidates.filter((c) => c.group === g);
            if (rows.length === 0) return null;
            return (
              <section className="card" key={g}>
                <h3>
                  {label[g]} ({rows.length})
                </h3>
                <ul className="bypass-list">
                  {rows.map((c, i) => (
                    <li key={`${g}-${i}`}>
                      <div className="bypass-head">
                        <span className="tag">{c.technique}</span>
                        <span className="mono small bypass-target">
                          {c.method} {displayTarget(c)}
                        </span>
                        <button className="chip-btn" onClick={() => copy(c.curl)}>
                          Copy curl
                        </button>
                      </div>
                      {c.headers.length > 0 && (
                        <div className="mono small muted">
                          {c.headers.map(([n, v]) => `${n}: ${v}`).join("  ·  ")}
                        </div>
                      )}
                      <div className="muted small">{c.note}</div>
                    </li>
                  ))}
                </ul>
              </section>
            );
          })}
        </>
      )}
    </div>
  );
}

function displayTarget(c: BypassCandidate): string {
  try {
    const u = new URL(c.url);
    return u.pathname + u.search;
  } catch {
    return c.url;
  }
}

// ---------------------------------------------------------------- Miner

function MinerPanel() {
  const [text, setText] = useState("");
  const result: MineResult = useMemo(() => mine(text), [text]);
  const empty = text.trim() === "";

  return (
    <div className="miner">
      <section className="card">
        <h2>Secret &amp; endpoint miner</h2>
        <p className="muted">
          Paste a JavaScript file or a response body. Endpoints hidden in strings,
          secrets left in source, and versioned libraries are pulled out. A match is a
          lead, not proof — a key here may already be revoked.
        </p>
        <textarea
          className="miner-input mono"
          value={text}
          spellCheck={false}
          placeholder="Paste JS or a response body here…"
          onChange={(e) => setText(e.target.value)}
        />
      </section>

      {!empty && (
        <div className="miner-grid">
          <section className="card">
            <h3>Secrets ({result.secrets.length})</h3>
            {result.secrets.length === 0 ? (
              <p className="muted">None matched.</p>
            ) : (
              <ul className="mine-list">
                {result.secrets.map((s, i) => (
                  <li key={i}>
                    <span className="tag insecure">{s.type}</span>
                    <code>{s.match}</code>
                    <span className="muted small">line {s.line}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card">
            <h3>Endpoints ({result.endpoints.length})</h3>
            {result.endpoints.length === 0 ? (
              <p className="muted">None matched.</p>
            ) : (
              <ul className="mine-list endpoints">
                {result.endpoints.map((e) => (
                  <li key={e.value}>
                    <span className={`tag ${e.kind === "absolute" ? "" : "path"}`}>
                      {e.kind}
                    </span>
                    <code>{e.value}</code>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card">
            <h3>Libraries ({result.libraries.length})</h3>
            {result.libraries.length === 0 ? (
              <p className="muted">None detected.</p>
            ) : (
              <ul className="mine-list">
                {result.libraries.map((l) => (
                  <li key={l.name}>
                    <strong>{l.name}</strong>
                    <code>{l.version}</code>
                    <span className="muted small">
                      cross-check against known CVEs for this version
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

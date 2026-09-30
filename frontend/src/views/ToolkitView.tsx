import { useEffect, useMemo, useState } from "react";

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
import { TRANSFORMS, runPipeline, transformById } from "../lib/transforms";
import { convert, detectFormat, type BodyFormat } from "../lib/convert";
import {
  CHARSETS,
  bruteForce,
  casePermutations,
  mutateWordlist,
  numberRange,
  type Generated,
} from "../lib/payloads";

/**
 * The toolkit: the standalone power tools a tester reaches for that do not need the
 * engine — a JWT workbench, a body miner, a transform pipeline, a content-type
 * converter and a 403/WAF bypass generator. Each reads what you give it and reports;
 * the forging and the sending are deliberate, separate acts you take with the result.
 */

type Tool = "jwt" | "miner" | "transforms" | "convert" | "payloads" | "bypass";

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
          className={tool === "transforms" ? "seg-btn on" : "seg-btn"}
          onClick={() => setTool("transforms")}
        >
          Transforms
        </button>
        <button
          className={tool === "convert" ? "seg-btn on" : "seg-btn"}
          onClick={() => setTool("convert")}
        >
          Content-type
        </button>
        <button
          className={tool === "payloads" ? "seg-btn on" : "seg-btn"}
          onClick={() => setTool("payloads")}
        >
          Payloads
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
      {tool === "transforms" && <TransformsPanel />}
      {tool === "convert" && <ConvertPanel />}
      {tool === "payloads" && <PayloadsPanel />}
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

// ---------------------------------------------------------------- Transforms

function TransformsPanel() {
  const [input, setInput] = useState("");
  const [pipeline, setPipeline] = useState<string[]>([]);
  const [steps, setSteps] = useState<string[]>([]);
  const [pick, setPick] = useState(TRANSFORMS[0]?.id ?? "");

  // Re-run the whole chain whenever the input or the pipeline changes.
  useEffect(() => {
    let live = true;
    void runPipeline(input, pipeline).then((s) => {
      if (live) setSteps(s);
    });
    return () => {
      live = false;
    };
  }, [input, pipeline]);

  const output = steps[steps.length - 1] ?? input;

  return (
    <div className="transforms">
      <section className="card">
        <h2>Transforms</h2>
        <p className="muted">
          Stack decode, encode and hash steps and watch the value change at each one —
          the way a triple-encoded payload comes apart one layer at a time.
        </p>
        <textarea
          className="jwt-input mono"
          value={input}
          spellCheck={false}
          placeholder="Paste a value to transform…"
          onChange={(e) => setInput(e.target.value)}
        />
        <div className="row">
          <select value={pick} onChange={(e) => setPick(e.target.value)}>
            {(["decode", "encode", "hash", "text"] as const).map((g) => (
              <optgroup key={g} label={g}>
                {TRANSFORMS.filter((t) => t.group === g).map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.label}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
          <button onClick={() => pick && setPipeline((p) => [...p, pick])}>Add step</button>
          {pipeline.length > 0 && (
            <button className="secondary" onClick={() => setPipeline([])}>
              Clear
            </button>
          )}
        </div>
      </section>

      {pipeline.length > 0 && (
        <section className="card">
          <h3>Pipeline</h3>
          <ol className="pipeline">
            {pipeline.map((id, i) => (
              <li key={i}>
                <span className="tag">{transformById(id)?.label ?? id}</span>
                <pre className="code-body mono step-out">{steps[i] ?? ""}</pre>
                <button
                  className="chip-btn"
                  onClick={() => setPipeline((p) => p.filter((_, j) => j !== i))}
                >
                  Remove
                </button>
              </li>
            ))}
          </ol>
        </section>
      )}

      <section className="card">
        <div className="card-title-row">
          <h3>Output</h3>
          <button className="chip-btn" onClick={() => copy(output)}>
            Copy
          </button>
        </div>
        <pre className="code-body mono variant-token">{output}</pre>
      </section>
    </div>
  );
}

// ---------------------------------------------------------------- Content-type

function ConvertPanel() {
  const [input, setInput] = useState("");
  const [to, setTo] = useState<BodyFormat>("json");
  const detected = useMemo(() => detectFormat(input), [input]);
  const result = useMemo(() => {
    if (input.trim() === "") return null;
    try {
      return { text: convert(input, to) };
    } catch (e) {
      return { error: e instanceof Error ? e.message : "Could not convert." };
    }
  }, [input, to]);
  const converted = result && "text" in result ? result.text : null;
  const convertError = result && "error" in result ? result.error : null;

  return (
    <div className="convert">
      <section className="card">
        <h2>Content-type converter</h2>
        <p className="muted">
          Re-express a body as JSON, XML or form-urlencoded to find parser-differential
          bugs — an endpoint that authorizes one content type but parses another.
        </p>
        <textarea
          className="miner-input mono"
          value={input}
          spellCheck={false}
          placeholder='{"user":"admin","roles":["a","b"]}'
          onChange={(e) => setInput(e.target.value)}
        />
        <div className="row">
          <span className="muted small">
            Detected: {detected ?? "—"} → convert to
          </span>
          <select value={to} onChange={(e) => setTo(e.target.value as BodyFormat)}>
            <option value="json">JSON</option>
            <option value="xml">XML</option>
            <option value="form">form-urlencoded</option>
          </select>
        </div>
      </section>

      {convertError && <p className="error-text">{convertError}</p>}
      {converted !== null && (
        <section className="card">
          <div className="card-title-row">
            <h3>Result</h3>
            <button className="chip-btn" onClick={() => copy(converted)}>
              Copy
            </button>
          </div>
          <pre className="code-body mono variant-token">{converted}</pre>
        </section>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Payloads

type PayloadMode = "own" | "numbers" | "brute" | "case" | "mutate";

function PayloadsPanel() {
  const [mode, setMode] = useState<PayloadMode>("own");

  // own list
  const [own, setOwn] = useState("");
  // numbers
  const [from, setFrom] = useState("0");
  const [to, setTo] = useState("100");
  const [step, setStep] = useState("1");
  const [pad, setPad] = useState("0");
  // brute
  const [charsetKey, setCharsetKey] = useState("lowercase");
  const [customCharset, setCustomCharset] = useState("");
  const [minLen, setMinLen] = useState("1");
  const [maxLen, setMaxLen] = useState("3");
  // case + mutate share a base word/list
  const [word, setWord] = useState("");
  const [mutOpts, setMutOpts] = useState({
    capitalize: true,
    leet: true,
    appendYears: true,
    appendCommon: true,
  });

  const result: Generated = useMemo(() => {
    const num = (s: string, d = 0) => {
      const n = parseInt(s, 10);
      return Number.isFinite(n) ? n : d;
    };
    switch (mode) {
      case "own": {
        const items = own.split(/\r?\n/).map((s) => s.trim()).filter((s) => s !== "");
        const dedup = [...new Set(items)];
        return { items: dedup, total: dedup.length, truncated: false };
      }
      case "numbers":
        return numberRange(num(from), num(to, 100), num(step, 1), num(pad));
      case "brute":
        return bruteForce(customCharset || CHARSETS[charsetKey] || "", num(minLen, 1), num(maxLen, 1));
      case "case":
        return casePermutations(word);
      case "mutate":
        return mutateWordlist(
          word.split(/\r?\n/).map((s) => s.trim()).filter(Boolean),
          mutOpts,
        );
    }
  }, [mode, own, from, to, step, pad, charsetKey, customCharset, minLen, maxLen, word, mutOpts]);

  const modes: { id: PayloadMode; label: string }[] = [
    { id: "own", label: "Own list" },
    { id: "numbers", label: "Numbers" },
    { id: "brute", label: "Brute force" },
    { id: "case", label: "Case" },
    { id: "mutate", label: "Mutate wordlist" },
  ];

  return (
    <div className="payloads">
      <section className="card">
        <h2>Payload generator</h2>
        <p className="muted">
          Build a list to paste into the Fuzzer. Bring your own, or generate one — number
          ranges, charset brute-force, case permutations, or password-spray mutations of a
          wordlist.
        </p>
        <div className="seg payload-modes">
          {modes.map((m) => (
            <button
              key={m.id}
              className={mode === m.id ? "seg-btn on" : "seg-btn"}
              onClick={() => setMode(m.id)}
            >
              {m.label}
            </button>
          ))}
        </div>

        {mode === "own" && (
          <textarea
            className="miner-input mono"
            value={own}
            spellCheck={false}
            placeholder={"one payload per line\nadmin\npassword\nletmein"}
            onChange={(e) => setOwn(e.target.value)}
          />
        )}

        {mode === "numbers" && (
          <div className="payload-fields">
            <label>From <input type="text" className="narrow" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
            <label>To <input type="text" className="narrow" value={to} onChange={(e) => setTo(e.target.value)} /></label>
            <label>Step <input type="text" className="narrow" value={step} onChange={(e) => setStep(e.target.value)} /></label>
            <label>Zero-pad <input type="text" className="narrow" value={pad} onChange={(e) => setPad(e.target.value)} /></label>
          </div>
        )}

        {mode === "brute" && (
          <div className="payload-fields">
            <label>
              Charset{" "}
              <select value={charsetKey} onChange={(e) => setCharsetKey(e.target.value)}>
                {Object.keys(CHARSETS).map((k) => (
                  <option key={k} value={k}>{k}</option>
                ))}
              </select>
            </label>
            <label>Custom <input type="text" value={customCharset} placeholder="overrides preset" onChange={(e) => setCustomCharset(e.target.value)} /></label>
            <label>Min len <input type="text" className="narrow" value={minLen} onChange={(e) => setMinLen(e.target.value)} /></label>
            <label>Max len <input type="text" className="narrow" value={maxLen} onChange={(e) => setMaxLen(e.target.value)} /></label>
          </div>
        )}

        {mode === "case" && (
          <input
            type="text"
            className="grow"
            value={word}
            placeholder="a word — every upper/lower combination"
            onChange={(e) => setWord(e.target.value)}
          />
        )}

        {mode === "mutate" && (
          <>
            <textarea
              className="miner-input mono"
              value={word}
              spellCheck={false}
              placeholder={"base words, one per line\nadmin\ncompanyname"}
              onChange={(e) => setWord(e.target.value)}
            />
            <div className="payload-fields">
              {(["capitalize", "leet", "appendYears", "appendCommon"] as const).map((k) => (
                <label key={k} className="checkbox">
                  <input
                    type="checkbox"
                    checked={mutOpts[k]}
                    onChange={(e) => setMutOpts((o) => ({ ...o, [k]: e.target.checked }))}
                  />
                  <span>{k}</span>
                </label>
              ))}
            </div>
          </>
        )}
      </section>

      <section className="card">
        <div className="card-title-row">
          <h3>
            {result.total.toLocaleString()} payload{result.total === 1 ? "" : "s"}
            {result.truncated && (
              <span className="muted small"> — showing first {result.items.length.toLocaleString()}</span>
            )}
          </h3>
          <button
            className="chip-btn"
            disabled={result.items.length === 0}
            onClick={() => copy(result.items.join("\n"))}
          >
            Copy list
          </button>
        </div>
        <pre className="code-body mono variant-token payload-out">
          {result.items.slice(0, 500).join("\n")}
          {result.items.length > 500 ? `\n… ${result.items.length - 500} more` : ""}
        </pre>
      </section>
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
                    {l.advisory && <span className="tag insecure">vuln</span>}
                    <strong>{l.name}</strong>
                    <code>{l.version}</code>
                    <span className="muted small">
                      {l.advisory ?? "cross-check against known CVEs for this version"}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card">
            <div className="card-title-row">
              <h3>Parameters ({result.parameters.length})</h3>
              {result.parameters.length > 0 && (
                <button className="chip-btn" onClick={() => copy(result.parameters.join("\n"))}>
                  Copy as wordlist
                </button>
              )}
            </div>
            {result.parameters.length === 0 ? (
              <p className="muted">None found.</p>
            ) : (
              <div className="param-chips">
                {result.parameters.map((p) => (
                  <code key={p} className="param-chip">
                    {p}
                  </code>
                ))}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

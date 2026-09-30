import { useCallback, useEffect, useState } from "react";

import { AuthzView } from "./views/AuthzView";
import { DashboardView } from "./views/DashboardView";
import { DecoderView } from "./views/DecoderView";
import { FindingsView } from "./views/FindingsView";
import { ChecksView } from "./views/ChecksView";
import { CrawlerView } from "./views/CrawlerView";
import { DomXssView } from "./views/DomXssView";
import { FuzzerView } from "./views/FuzzerView";
import { RaceView } from "./views/RaceView";
import { HistoryView } from "./views/HistoryView";
import { IdentifiersView } from "./views/IdentifiersView";
import { ImportView } from "./views/ImportView";
import { LicenseView } from "./views/LicenseView";
import { LlmView } from "./views/LlmView";
import { MatchReplaceView } from "./views/MatchReplaceView";
import { OobView } from "./views/OobView";
import { ProgrammeView } from "./views/ProgrammeView";
import { SequencerView } from "./views/SequencerView";
import { SitemapView } from "./views/SitemapView";
import { RepeaterView } from "./views/RepeaterView";
import { ReportView } from "./views/ReportView";
import { ScanView } from "./views/ScanView";
import { SetupView } from "./views/SetupView";
import { SnapshotsView } from "./views/SnapshotsView";
import { ToolkitView } from "./views/ToolkitView";
import { WebSocketsView } from "./views/WebSocketsView";
import { TabIcon } from "./components/TabIcon";
import logoUrl from "./assets/nullhawk.jpg";
import {
  currentProject,
  describeError,
  EXPECTED_RPC_CONTRACT_VERSION,
  fetchEngineInfo,
  isContractCompatible,
  licenseStatus,
  onTraffic,
  type EngineInfo,
  type LicenseStatus,
  type ProjectSummary,
  type ProxyStatus,
} from "./ipc";

type Boot =
  | { status: "loading" }
  | { status: "ready"; info: EngineInfo }
  | { status: "incompatible"; info: EngineInfo }
  | { status: "error"; message: string };

type Tab =
  | "dashboard"
  | "setup"
  | "history"
  | "repeater"
  | "decoder"
  | "websockets"
  | "matchreplace"
  | "import"
  | "identifiers"
  | "scan"
  | "checks"
  | "fuzzer"
  | "race"
  | "sequencer"
  | "domxss"
  | "authz"
  | "llm"
  | "oob"
  | "toolkit"
  | "findings"
  | "crawler"
  | "report"
  | "sitemap"
  | "snapshots"
  | "programme"
  | "license";

/**
 * The nav, grouped by the stage of the work rather than run together as one long
 * list. The order inside a group is the order the work tends to happen in.
 */
const GROUPS: { label: string; items: { id: Tab; label: string }[] }[] = [
  {
    label: "Overview",
    items: [
      { id: "dashboard", label: "Dashboard" },
      { id: "setup", label: "Setup" },
    ],
  },
  {
    label: "Traffic",
    items: [
      { id: "history", label: "History" },
      { id: "repeater", label: "Repeater" },
      { id: "websockets", label: "WebSocket" },
      { id: "matchreplace", label: "Match & Replace" },
      { id: "decoder", label: "Decoder" },
    ],
  },
  {
    label: "Discovery",
    items: [
      { id: "crawler", label: "Crawler" },
      { id: "sitemap", label: "Site map" },
      { id: "import", label: "Import API" },
      { id: "identifiers", label: "Identifiers" },
      { id: "toolkit", label: "Toolkit" },
    ],
  },
  {
    label: "Testing",
    items: [
      { id: "scan", label: "Scan" },
      { id: "checks", label: "Custom Checks" },
      { id: "fuzzer", label: "Fuzzer" },
      { id: "race", label: "Race" },
      { id: "sequencer", label: "Sequencer" },
      { id: "domxss", label: "DOM XSS" },
      { id: "authz", label: "Authorization" },
      { id: "llm", label: "LLM" },
      { id: "oob", label: "Collaborator" },
    ],
  },
  {
    label: "Results",
    items: [
      { id: "findings", label: "Findings" },
      { id: "report", label: "Report" },
      { id: "snapshots", label: "Snapshots" },
      { id: "programme", label: "Programme" },
      { id: "license", label: "Licence" },
    ],
  },
];

export default function App() {
  const [boot, setBoot] = useState<Boot>({ status: "loading" });
  const [tab, setTab] = useState<Tab>("dashboard");
  const [project, setProject] = useState<ProjectSummary | null>(null);
  const [proxy, setProxy] = useState<ProxyStatus>({
    running: false,
    address: null,
  });
  const [repeating, setRepeating] = useState<string | null>(null);
  const [repeaterSeed, setRepeaterSeed] = useState<{ url: string; n: number } | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [openExchange, setOpenExchange] = useState<string | null>(null);
  const [license, setLicense] = useState<LicenseStatus | null>(null);

  // Bumped when a run files something, which is what tells the findings list to
  // re-read. The engine remains the source of truth for what the project holds.
  const [findingCount, setFindingCount] = useState(0);

  // Bumped whenever something new is captured, which is what tells the history view
  // to re-read. A counter rather than the traffic itself: the engine is the source
  // of truth for what a project contains, and a row assembled in the browser could
  // disagree with what was actually stored.
  const [captureCount, setCaptureCount] = useState(0);

  useEffect(() => {
    fetchEngineInfo()
      .then((info) =>
        setBoot(
          isContractCompatible(info)
            ? { status: "ready", info }
            : { status: "incompatible", info },
        ),
      )
      .catch((error: unknown) =>
        setBoot({ status: "error", message: describeError(error) }),
      );

    currentProject()
      .then(setProject)
      .catch(() => undefined);

    licenseStatus()
      .then(setLicense)
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    const subscription = onTraffic(() => setCaptureCount((n) => n + 1));
    return () => {
      void subscription.then((unlisten) => unlisten());
    };
  }, []);

  const openRepeater = useCallback((id: string) => {
    setRepeating(id);
    setTab("repeater");
  }, []);

  const openAuthz = useCallback((id: string) => {
    setTesting(id);
    setTab("authz");
  }, []);

  // Send a captured request on to a tool that takes one as its base. All three read
  // the same `testing` request id, so this is one setter and a destination tab —
  // exactly the "send to…" plumbing that otherwise means hand-copying an id.
  const openFuzzer = useCallback((id: string) => {
    setTesting(id);
    setTab("fuzzer");
  }, []);

  const openRace = useCallback((id: string) => {
    setTesting(id);
    setTab("race");
  }, []);

  // Open a URL (from the site map) as a fresh Repeater draft. The nonce makes a repeat
  // click on the same path re-seed the editor.
  const openRepeaterUrl = useCallback((url: string) => {
    setRepeaterSeed((s) => ({ url, n: (s?.n ?? 0) + 1 }));
    setTab("repeater");
  }, []);

  // Following a citation out of a finding, or out of a matrix cell, lands in
  // History with that exchange selected. A claim whose evidence cannot be opened is
  // a claim nobody can check.
  const showExchange = useCallback((id: string) => {
    setOpenExchange(id);
    setTab("history");
  }, []);

  if (boot.status !== "ready") {
    return <Blocked boot={boot} />;
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            <img src={logoUrl} alt="" className="brand-logo" />
          </span>
          <span className="brand-text">
            <strong>Nullhawk</strong>
            <span className="muted small">
              {boot.info.milestone} · v{boot.info.version}
            </span>
          </span>
        </div>

        <nav>
          {GROUPS.map((group) => (
            <div key={group.label} className="nav-group">
              <div className="nav-group-label">{group.label}</div>
              {group.items.map(({ id, label }) => (
                <button
                  key={id}
                  className={tab === id ? "tab active" : "tab"}
                  onClick={() => setTab(id)}
                >
                  <TabIcon id={id} />
                  <span className="tab-label">{label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>
      </aside>

      <div className="workspace">
        <header className="top">
        <div className="indicators">
          {license && (
            <span
              className="chip"
              title={
                license.tier === "Free"
                  ? "Free tier — the active scanner, intruder, SARIF export and retest snapshots need Pro"
                  : license.days_until_expiry !== null && license.days_until_expiry <= 7
                    ? `Expires in ${license.days_until_expiry} days — falls back to the free tier`
                    : license.licensee
                      ? `Licensed to ${license.licensee}`
                      : `${license.tier} tier`
              }
            >
              {license.tier}
              {license.trial ? " · trial" : ""}
            </span>
          )}
          {project && <span className="chip">{project.name}</span>}
          <span className={proxy.running ? "chip live" : "chip"}>
            {proxy.running ? `proxy ${proxy.address}` : "proxy stopped"}
          </span>
        </div>
      </header>

      <main>
        {tab === "dashboard" && (
          <DashboardView
            project={project}
            proxy={proxy}
            license={license}
            captureCount={captureCount}
            findingCount={findingCount}
            onNavigate={(t) => setTab(t as Tab)}
          />
        )}
        {tab === "setup" && (
          <SetupView
            project={project}
            onProjectChange={setProject}
            proxy={proxy}
            onProxyChange={setProxy}
          />
        )}
        {tab === "history" && (
          <HistoryView
            hasProject={project !== null}
            refreshToken={captureCount}
            onRepeat={openRepeater}
            onTestAuthorization={openAuthz}
            onSendToFuzzer={openFuzzer}
            onSendToRace={openRace}
            select={openExchange}
          />
        )}
        {tab === "repeater" && (
          <RepeaterView
            requestId={repeating}
            seed={repeaterSeed}
            onCaptured={() => setCaptureCount((n) => n + 1)}
          />
        )}
        {tab === "decoder" && <DecoderView />}
        {tab === "websockets" && <WebSocketsView hasProject={project !== null} />}
        {tab === "identifiers" && (
          <IdentifiersView hasProject={project !== null} />
        )}
        {tab === "scan" && (
          <ScanView
            hasProject={project !== null}
            onOpenExchange={showExchange}
          />
        )}
        {tab === "checks" && <ChecksView hasProject={project !== null} />}
        {tab === "fuzzer" && (
          <FuzzerView
            hasProject={project !== null}
            requestId={testing}
            license={license}
          />
        )}
        {tab === "authz" && (
          <AuthzView
            requestId={testing}
            onFindings={() => {
              setFindingCount((n) => n + 1);
              setCaptureCount((n) => n + 1);
            }}
            onOpenExchange={showExchange}
          />
        )}
        {tab === "race" && (
          <RaceView hasProject={project !== null} requestId={testing} license={license} />
        )}
        {tab === "sequencer" && <SequencerView hasProject={project !== null} />}
        {tab === "domxss" && <DomXssView license={license} />}
        {tab === "llm" && <LlmView license={license} />}
        {tab === "oob" && <OobView license={license} />}
        {tab === "matchreplace" && <MatchReplaceView hasProject={project !== null} />}
        {tab === "import" && (
          <ImportView hasProject={project !== null} license={license} />
        )}
        {tab === "findings" && (
          <FindingsView
            hasProject={project !== null}
            refreshToken={findingCount}
            onOpenExchange={showExchange}
          />
        )}
        {tab === "crawler" && (
          <CrawlerView hasProject={project !== null} license={license} />
        )}
        {tab === "sitemap" && (
          <SitemapView
            hasProject={project !== null}
            onOpenInRepeater={openRepeaterUrl}
          />
        )}
        {tab === "report" && <ReportView hasProject={project !== null} />}
        {tab === "snapshots" && (
          <SnapshotsView hasProject={project !== null} />
        )}
        {tab === "toolkit" && <ToolkitView hasProject={project !== null} />}
        {tab === "programme" && <ProgrammeView hasProject={project !== null} />}
        {tab === "license" && (
          <LicenseView license={license} onChange={setLicense} />
        )}
      </main>

        <footer>
          For authorized security testing only. Do not use Nullhawk against systems
          you do not own or have written permission to test.
        </footer>
      </div>
    </div>
  );
}

/** Everything that stops the window from being usable at all. */
function Blocked({ boot }: { boot: Boot }) {
  return (
    <main className="shell">
      <h1>Nullhawk</h1>
      {boot.status === "loading" && (
        <p className="status">Connecting to the engine…</p>
      )}

      {boot.status === "error" && (
        <section className="panel error">
          <h2>The engine is not reachable</h2>
          <p>{boot.message}</p>
        </section>
      )}

      {boot.status === "incompatible" && (
        <section className="panel error">
          <h2>Incompatible engine</h2>
          <p>
            This interface speaks IPC contract v{EXPECTED_RPC_CONTRACT_VERSION},
            but the engine reports v{boot.info.rpc_contract_version}. Update
            Nullhawk so the two halves match — showing you a request decoded under
            the wrong contract would be worse than showing you nothing.
          </p>
        </section>
      )}
    </main>
  );
}

import { useCallback, useEffect, useState } from "react";

import { HistoryView } from "./views/HistoryView";
import { RepeaterView } from "./views/RepeaterView";
import { SetupView } from "./views/SetupView";
import {
  currentProject,
  describeError,
  EXPECTED_RPC_CONTRACT_VERSION,
  fetchEngineInfo,
  isContractCompatible,
  onTraffic,
  type EngineInfo,
  type ProjectSummary,
  type ProxyStatus,
} from "./ipc";

type Boot =
  | { status: "loading" }
  | { status: "ready"; info: EngineInfo }
  | { status: "incompatible"; info: EngineInfo }
  | { status: "error"; message: string };

type Tab = "setup" | "history" | "repeater";

export default function App() {
  const [boot, setBoot] = useState<Boot>({ status: "loading" });
  const [tab, setTab] = useState<Tab>("setup");
  const [project, setProject] = useState<ProjectSummary | null>(null);
  const [proxy, setProxy] = useState<ProxyStatus>({
    running: false,
    address: null,
  });
  const [repeating, setRepeating] = useState<string | null>(null);

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

  if (boot.status !== "ready") {
    return <Blocked boot={boot} />;
  }

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <strong>Hexora</strong>
          <span className="muted small">
            {boot.info.milestone} · v{boot.info.version}
          </span>
        </div>

        <nav>
          {(["setup", "history", "repeater"] as const).map((name) => (
            <button
              key={name}
              className={tab === name ? "tab active" : "tab"}
              onClick={() => setTab(name)}
            >
              {name === "setup"
                ? "Setup"
                : name === "history"
                  ? "History"
                  : "Repeater"}
            </button>
          ))}
        </nav>

        <div className="indicators">
          {project && <span className="chip">{project.name}</span>}
          <span className={proxy.running ? "chip live" : "chip"}>
            {proxy.running ? `proxy ${proxy.address}` : "proxy stopped"}
          </span>
        </div>
      </header>

      <main>
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
          />
        )}
        {tab === "repeater" && (
          <RepeaterView
            requestId={repeating}
            onCaptured={() => setCaptureCount((n) => n + 1)}
          />
        )}
      </main>

      <footer>
        For authorized security testing only. Do not use Hexora against systems
        you do not own or have written permission to test.
      </footer>
    </div>
  );
}

/** Everything that stops the window from being usable at all. */
function Blocked({ boot }: { boot: Boot }) {
  return (
    <main className="shell">
      <h1>Hexora</h1>
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
            Hexora so the two halves match — showing you a request decoded under
            the wrong contract would be worse than showing you nothing.
          </p>
        </section>
      )}
    </main>
  );
}

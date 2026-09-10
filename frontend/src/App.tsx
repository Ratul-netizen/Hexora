import { useEffect, useState } from "react";
import {
  EXPECTED_RPC_CONTRACT_VERSION,
  fetchEngineInfo,
  isContractCompatible,
  type EngineInfo,
} from "./ipc";

type State =
  | { status: "loading" }
  | { status: "ready"; info: EngineInfo }
  | { status: "incompatible"; info: EngineInfo }
  | { status: "error"; message: string };

export default function App() {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    fetchEngineInfo()
      .then((info) =>
        setState(
          isContractCompatible(info)
            ? { status: "ready", info }
            : { status: "incompatible", info },
        ),
      )
      .catch((error: unknown) =>
        setState({ status: "error", message: String(error) }),
      );
  }, []);

  return (
    <main className="shell">
      <h1>Hexora</h1>
      <p className="tagline">The Modern Offensive Security Workbench</p>
      {render(state)}
      <footer>
        <p>
          For authorized security testing only. Do not use Hexora against systems
          you do not own or have written permission to test.
        </p>
      </footer>
    </main>
  );
}

function render(state: State) {
  switch (state.status) {
    case "loading":
      return <p className="status">Connecting to the engine…</p>;

    case "error":
      return (
        <section className="panel error">
          <h2>The engine is not reachable</h2>
          <p>{state.message}</p>
        </section>
      );

    case "incompatible":
      return (
        <section className="panel error">
          <h2>Incompatible engine</h2>
          <p>
            This interface speaks IPC contract v
            {EXPECTED_RPC_CONTRACT_VERSION}, but the engine reports v
            {state.info.rpc_contract_version}. Update Hexora so the two halves
            match.
          </p>
        </section>
      );

    case "ready":
      return (
        <section className="panel">
          <h2>Milestone {state.info.milestone} — architecture foundation</h2>
          <p>
            The engine is running and the project store is ready. The proxy,
            repeater, scanner and fuzzer are not implemented yet, so this window
            deliberately shows no interface for them.
          </p>
          <dl>
            <dt>Engine version</dt>
            <dd>{state.info.version}</dd>
            <dt>IPC contract</dt>
            <dd>v{state.info.rpc_contract_version}</dd>
            <dt>Project schema</dt>
            <dd>revision {state.info.schema_version}</dd>
          </dl>
        </section>
      );
  }
}

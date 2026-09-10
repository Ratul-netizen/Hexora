import { invoke } from "@tauri-apps/api/core";

/**
 * Version and contract information reported by the Rust core.
 */
export interface EngineInfo {
  version: string;
  rpc_contract_version: number;
  schema_version: number;
  milestone: string;
}

/**
 * The IPC contract version this frontend was written against.
 *
 * The UI refuses to operate against an engine reporting a different value rather
 * than misinterpreting its messages. A security tool that quietly shows the wrong
 * request would be worse than one that refuses to start.
 */
export const EXPECTED_RPC_CONTRACT_VERSION = 1;

export async function fetchEngineInfo(): Promise<EngineInfo> {
  return invoke<EngineInfo>("engine_info");
}

export function isContractCompatible(info: EngineInfo): boolean {
  return info.rpc_contract_version === EXPECTED_RPC_CONTRACT_VERSION;
}

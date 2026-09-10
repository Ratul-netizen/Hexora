/**
 * The typed edge of the IPC boundary.
 *
 * Every call into the Rust core goes through this file, and these types mirror the
 * `Serialize` structs in `apps/desktop/src-tauri/src/commands.rs` exactly. They are
 * hand-written rather than generated because the surface is small and a review of it
 * is meant to be a review of one file on each side.
 *
 * Nothing here holds state. The engine is the single source of truth for what a
 * project contains, and a React store that believed something different would
 * eventually render a request that was never sent.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

/** Version and contract information reported by the Rust core. */
export interface EngineInfo {
  version: string;
  rpc_contract_version: number;
  schema_version: number;
  milestone: string;
}

/** A project, as the window shows it. */
export interface ProjectSummary {
  path: string;
  name: string;
  targets: number;
  requests: number;
  schema_version: number;
}

/** Where the proxy is, or that it is not running. */
export interface ProxyStatus {
  running: boolean;
  address: string | null;
}

/** One row of the history table. */
export interface HistoryRow {
  id: string;
  method: string;
  url: string;
  status: number | null;
  response_bytes: number;
  duration_ms: number | null;
  sent_at: string;
  secure: boolean;
  quirks: string[];
  /** The identity the request was sent as, for rows an authorization run produced. */
  identity: string | null;
}

export interface HistoryPage {
  rows: HistoryRow[];
  next: string | null;
  total: number;
}

/**
 * How a body should be shown.
 *
 * `binary` means the bytes are not valid UTF-8, or contain a NUL. The content is a
 * hex dump in that case — never lossy text, because characters that were not on the
 * wire have no business on screen in a security tool.
 */
export type Rendering = "text" | "binary" | "empty";

export interface BodyPreview {
  rendering: Rendering;
  content: string;
  total_bytes: number;
  truncated: boolean;
}

export interface ExchangeDetail {
  id: string;
  parent: string | null;
  origin: string;
  url: string;
  request_head: string;
  request_body: BodyPreview;
  response_head: string;
  response_body: BodyPreview;
  sent_at: string;
}

export interface DraftView {
  raw: string;
  url: string;
  parent: string | null;
  warnings: string[];
}

export interface DiffView {
  summary: string;
  interesting: boolean;
  identical: boolean;
  status: [number, number] | null;
  changed_headers: [string, string, string][];
  added_headers: string[];
  removed_headers: string[];
  first_difference_at: number | null;
  timing_delta_ms: number;
  timing_significant: boolean;
}

export interface SendResult {
  id: string;
  parent: string | null;
  status: number;
  duration_ms: number;
  out_of_scope: boolean;
  response_head: string;
  response_body: BodyPreview;
  warnings: string[];
  diff: DiffView | null;
}

export interface CaStatus {
  directory: string;
  fingerprint: string;
  state: string;
  trusted: boolean;
}

/** A summary of an exchange, pushed as the proxy captures it. */
export interface TrafficEvent {
  method: string;
  url: string;
  status: number;
  duration_ms: number;
  out_of_scope: boolean;
}

/**
 * The IPC contract version this frontend was written against.
 *
 * The UI refuses to operate against an engine reporting a different value rather
 * than misinterpreting its messages. A security tool that quietly shows the wrong
 * request would be worse than one that refuses to start.
 */
export const EXPECTED_RPC_CONTRACT_VERSION = 2;

export function isContractCompatible(info: EngineInfo): boolean {
  return info.rpc_contract_version === EXPECTED_RPC_CONTRACT_VERSION;
}

export const fetchEngineInfo = (): Promise<EngineInfo> =>
  invoke<EngineInfo>("engine_info");

export const openProject = (path: string): Promise<ProjectSummary> =>
  invoke<ProjectSummary>("project_open", { path });

export const currentProject = (): Promise<ProjectSummary | null> =>
  invoke<ProjectSummary | null>("project_current");

export const startProxy = (
  listen: string,
  interceptOnly: string[],
  insecureUpstream: boolean,
): Promise<ProxyStatus> =>
  invoke<ProxyStatus>("proxy_start", {
    listen,
    interceptOnly,
    insecureUpstream,
  });

export const stopProxy = (): Promise<ProxyStatus> =>
  invoke<ProxyStatus>("proxy_stop");

export const proxyStatus = (): Promise<ProxyStatus> =>
  invoke<ProxyStatus>("proxy_status");

export const listHistory = (
  after: string | null,
  limit: number,
): Promise<HistoryPage> => invoke<HistoryPage>("history_list", { after, limit });

export const exchangeDetail = (id: string): Promise<ExchangeDetail> =>
  invoke<ExchangeDetail>("history_detail", { id });

export const loadDraft = (id: string): Promise<DraftView> =>
  invoke<DraftView>("repeater_draft", { id });

export const sendDraft = (
  raw: string,
  parent: string | null,
  insecure: boolean,
): Promise<SendResult> =>
  invoke<SendResult>("repeater_send", { raw, parent, insecure });

export const branchesOf = (id: string): Promise<HistoryRow[]> =>
  invoke<HistoryRow[]>("repeater_tree", { id });

export const caStatus = (): Promise<CaStatus> => invoke<CaStatus>("ca_status");

export const installCa = (): Promise<CaStatus> => invoke<CaStatus>("ca_install");

export const untrustCa = (): Promise<CaStatus> => invoke<CaStatus>("ca_untrust");

/** Subscribes to exchanges as the proxy captures them. */
export const onTraffic = (
  handler: (event: TrafficEvent) => void,
): Promise<UnlistenFn> =>
  listen<TrafficEvent>("hexora://traffic", (event) => handler(event.payload));

/**
 * Turns whatever a rejected `invoke` produced into a sentence.
 *
 * Commands reject with the engine's own message, which already names the field or
 * file at fault. Anything else is unexpected and is shown verbatim rather than
 * replaced with a generic apology that hides it.
 */
export function describeError(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return String(error);
}

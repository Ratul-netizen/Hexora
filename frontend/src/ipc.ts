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
  /** How it reached the socket. A raw row was sent byte for byte. */
  mode: RequestMode;
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
  mode: RequestMode;
  url: string;
  request_head: string;
  request_body: BodyPreview;
  response_head: string;
  response_body: BodyPreview;
  sent_at: string;
}

/**
 * How a request reaches the socket.
 *
 * `structured` serializes a message model: header order, casing and duplicates
 * survive, but bare LF line endings become CRLF and missing framing may be added.
 * `raw` writes the bytes exactly as they are. Nothing switches between them on its
 * own — the difference is the point.
 */
export type RequestMode = "structured" | "raw";

export interface DraftView {
  raw: string;
  url: string;
  parent: string | null;
  warnings: string[];
  mode: RequestMode;
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
  mode: RequestMode;
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
export const EXPECTED_RPC_CONTRACT_VERSION = 11;

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
  requestMode: RequestMode,
): Promise<SendResult> =>
  invoke<SendResult>("repeater_send", { raw, parent, insecure, requestMode });

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

/* ------------------------------------------------------------------ *
 * Scope
 * ------------------------------------------------------------------ */

/** The project's scope, as two lists of readable rules. */
export interface ScopeView {
  included: string[];
  excluded: string[];
}

export const listScope = (): Promise<ScopeView> => invoke<ScopeView>("scope_list");

export const addScope = (
  host: string,
  pathPrefix: string | null,
  exclude: boolean,
): Promise<ScopeView> =>
  invoke<ScopeView>("scope_add", { host, pathPrefix, exclude });

export const removeScope = (host: string): Promise<ScopeView> =>
  invoke<ScopeView>("scope_remove", { host });

/* ------------------------------------------------------------------ *
 * Identities
 * ------------------------------------------------------------------ */

/**
 * An identity, as the window shows it.
 *
 * There is no credential field, deliberately. `credential` is the *kind* — bearer,
 * cookie, none — because the value has no business in a renderer process, a devtools
 * console or a screenshot of the window.
 */
export interface IdentityView {
  id: string;
  label: string;
  privilege: string;
  credential: string;
  owns: string[];
}

export const listIdentities = (): Promise<IdentityView[]> =>
  invoke<IdentityView[]>("identities_list");

export const addIdentity = (identity: {
  label: string;
  privilege: string;
  kind: string;
  secret: string | null;
  fromEnv: string | null;
  owns: string[];
}): Promise<IdentityView> => invoke<IdentityView>("identity_add", identity);

export const removeIdentity = (id: string): Promise<void> =>
  invoke<void>("identity_remove", { id });

/* ------------------------------------------------------------------ *
 * Authorization matrix
 * ------------------------------------------------------------------ */

/** One identity's row in the matrix. */
export interface CellView {
  identity: string;
  label: string;
  privilege: string;
  request: string | null;
  status: number | null;
  similarity: number;
  outcome: string;
  verdict: string;
  violation: boolean;
  leaked_object_ids: string[];
  own_object_ids: string[];
  /**
   * What a second experiment established: `reproduced`, `supported`, `refuted` or
   * `inconclusive`. `null` means nothing re-examined this cell, which is not the
   * same as "it did not reproduce".
   */
  verification: string | null;
  /** The verification in a sentence. */
  verification_note: string | null;
  error: string | null;
  note: string | null;
  /**
   * Where this response differs from the owner's, field by field. `null` when
   * nothing was sent, so there was nothing to compare.
   */
  structure: StructureView | null;
}

/** One field where two responses disagree. */
export interface DifferenceView {
  /** `$.account.email`. */
  path: string;
  /** `appeared`, `disappeared`, `changed` or `type changed`. */
  change: string;
  /** The whole thing in one line, naming both identities. */
  detail: string;
  /** Whether the field's name suggests it carries something personal. */
  notable: boolean;
}

/** A structural comparison of two responses. */
export interface StructureView {
  /** `structurally`, `not_structured` or `only_one_side`. */
  comparable: string;
  /** Whether the two responses are the same document everywhere that counts. */
  same_document: boolean;
  /** Whether every shared value differs, which is what a scoped endpoint looks like. */
  every_value_differs: boolean;
  shared_paths: number;
  total_paths: number;
  /** What the comparison was allowed to ignore, in words. */
  policy: string;
  /** The differences that count, most notable first. */
  differences: DifferenceView[];
  /** The ones the policy set aside — listed, never dropped. */
  set_aside: DifferenceView[];
  /** Anything about the bodies a reader should know first. */
  quirks: string[];
}

/** One constructed cross-identity attempt. */
export interface AttemptView {
  sender: string;
  object_name: string;
  object_value: string;
  owner: string;
  /** What was replaced, and where — the whole substitution in one line. */
  substitution: string;
  location: string;
  original_value: string;
  request: string | null;
  control: string | null;
  status: number | null;
  similarity: number;
  outcome: string;
  verdict: string;
  violation: boolean;
  disclosed_object_ids: string[];
  echoed: boolean;
  own_object_ids: string[];
  reproduced: boolean;
  error: string | null;
  note: string | null;
}

export interface MatrixView {
  base: string;
  method: string;
  url: string;
  owner: CellView;
  cells: CellView[];
  appears_public: boolean;
  constructed: AttemptView[];
  not_constructed: string[];
  findings: FindingRow[];
  saved: number;
  updated: number;
}

/**
 * Everything one run needs, named at the call site.
 *
 * Field names are snake_case because this object is deserialized as a single command
 * argument: Tauri's camelCase conversion applies to a command's own parameters, not
 * to the fields inside one.
 */
export interface AuthzRequest {
  id: string;
  owner: string;
  identities: string[];
  anonymous: boolean;
  verify: boolean;
  insecure: boolean;
  confirm_state_changing: boolean;
  save: boolean;
  construct: boolean;
  max_attempts: number;
}

export const runAuthz = (request: AuthzRequest): Promise<MatrixView> =>
  invoke<MatrixView>("authz_run", { request });

/* ------------------------------------------------------------------ *
 * Declared objects
 * ------------------------------------------------------------------ */

/**
 * An identifier a tester declared, and who owns it.
 *
 * Declaring is data entry: it sends nothing. It is also not evidence of ownership —
 * it is the tester's assertion, which is why a constructed attempt that cannot show
 * the returned object really is the declared one produces a lead rather than a
 * finding.
 */
export interface ObjectView {
  id: string;
  name: string;
  value: string;
  owner: string;
  owner_id: string;
  location: string;
  source_request: string | null;
}

export const listObjects = (): Promise<ObjectView[]> =>
  invoke<ObjectView[]>("objects_list");

export const addObject = (declaration: {
  value: string;
  owner: string;
  name: string;
  inRequest: string | null;
}): Promise<ObjectView[]> => invoke<ObjectView[]>("object_add", declaration);

export const removeObject = (id: string): Promise<ObjectView[]> =>
  invoke<ObjectView[]>("object_remove", { id });

/* ------------------------------------------------------------------ *
 * Proof of concept
 * ------------------------------------------------------------------ */

/** One step of a reproduction. */
export interface StepView {
  number: number;
  /** What to do, and who to do it as. */
  heading: string;
  /** The exchange it came from. */
  request: string;
  /** The request as bytes, with credentials replaced. */
  raw: string | null;
  /** A shell command, when one can express the request. */
  curl: string | null;
  /** Why there is no command, when there is not. */
  curl_refused: string | null;
  expect: string | null;
}

/** A value the reader supplies before running the steps. */
export interface PlaceholderView {
  token: string;
  header: string;
  identity: string | null;
  bytes: number;
}

/**
 * A reproduction compiled from a finding's evidence.
 *
 * Carries no credential. Every one was replaced by a placeholder when the
 * reproduction was compiled, not when it was rendered — so nothing downstream,
 * including this payload, can carry one.
 */
export interface ReproductionView {
  finding: string;
  title: string;
  confidence: string;
  /** Whether any step can actually be run. */
  runnable: boolean;
  summary: string;
  steps: StepView[];
  placeholders: PlaceholderView[];
  caveats: string[];
}

export const findingReproduction = (id: string): Promise<ReproductionView> =>
  invoke<ReproductionView>("finding_reproduction", { id });

/* ------------------------------------------------------------------ *
 * Passive scanning
 * ------------------------------------------------------------------ */

/** A check this build has. */
export interface DetectorView {
  id: string;
  name: string;
  version: string;
  about: string;
  /** `passive` or `active`. */
  mode: string;
  /** Whether running it puts traffic on the wire. */
  sends: boolean;
  observes: boolean;
  hypothesizes: boolean;
  /** The check whose suspicions this one settles, when that is its job. */
  settles: string | null;
}

/** What one detector did during a pass. */
export interface DetectorRunView {
  detector: string;
  version: string;
  mode: string;
  observations: number;
  hypotheses: number;
}

/**
 * A fact about captured traffic.
 *
 * Carries no credential: the scanner redacts when it assembles an exchange, so there
 * is nothing here to leak.
 */
export interface ObservationView {
  detector: string;
  version: string;
  about: string;
  expected: string;
  observed: string;
  rationale: string;
  severity: string;
  /** Whether it became a finding, or is context that never will. */
  reportable: boolean;
  host: string;
  occurrences: number;
  exchanges: string[];
}

/** A suspicion the pass raised and did not settle. */
export interface HypothesisView {
  detector: string;
  claim: string;
  source_request: string;
  provisional_severity: string;
}

export interface ScanView {
  exchanges_read: number;
  exchanges_skipped: number;
  detectors: DetectorRunView[];
  observations: ObservationView[];
  hypotheses: HypothesisView[];
  findings: number;
  recorded_new: number;
  recorded_refreshed: number;
}

export const listDetectors = (): Promise<DetectorView[]> =>
  invoke<DetectorView[]>("detectors_list");

/** Reads captured traffic. Sends nothing — the engine has no transport to do it with. */
export const scanPassive = (
  detector: string | null,
  everything: boolean,
): Promise<ScanView> =>
  invoke<ScanView>("scan_passive", { host: null, detector, everything });

/* ------------------------------------------------------------------ *
 * Active scanning
 * ------------------------------------------------------------------ */

/** One experiment a run would perform. */
export interface PlannedView {
  host: string;
  detector: string;
  claim: string;
  /** The exchange it was raised from, for opening in History. */
  source_request: string;
}

/** A hypothesis nothing will be sent for, and why. */
export interface SkippedView {
  detector: string;
  claim: string;
  why: string;
}

/** What a run would do. Produced without sending anything. */
export interface PlanView {
  experiments: PlannedView[];
  skipped: SkippedView[];
  /** Each host, with how many experiments and how many requests at most. */
  hosts: [string, number, number][];
  requests_at_most: number;
  /** What the run may do to the systems it tests, in words. */
  budget: string;
  /** Whether the request ceiling would cut this run short. */
  exceeds_ceiling: boolean;
  /**
   * Suspicions standing on traffic that is no longer in scope.
   *
   * So an empty plan can say *why* it is empty. "Nothing to test" and "everything
   * that could be tested is out of bounds" are different sentences, and only one of
   * them is about the application.
   */
  out_of_scope: number;
}

/** One experiment and what it established. */
export interface SettledView {
  detector: string;
  claim: string;
  /** `reproduced`, `supported`, `refuted` or `inconclusive`. */
  verification: string;
  note: string;
  finding: string | null;
  severity: string | null;
  confidence: string | null;
  title: string | null;
}

/** What an active run did. */
export interface ActiveRunView {
  requests_sent: number;
  settled: SettledView[];
  skipped: SkippedView[];
  detectors: DetectorRunView[];
  /**
   * Whether the run worked through everything it planned.
   *
   * The field every reader has to look at: a truncated run whose reader concludes
   * "clean" is the worst thing this can produce.
   */
  complete: boolean;
  /** Why it ended early, in a sentence. */
  unfinished_note: string | null;
  recorded_new: number;
  recorded_refreshed: number;
}

/** Works out what an active run would send. Sends nothing. */
export const scanActivePlan = (
  maxRequests: number | null,
): Promise<PlanView> =>
  invoke<PlanView>("scan_active_plan", { host: null, maxRequests });

/** Performs the experiments. The only call in this file that generates traffic. */
export const scanActiveRun = (
  maxRequests: number | null,
): Promise<ActiveRunView> =>
  invoke<ActiveRunView>("scan_active_run", { host: null, maxRequests });

/**
 * Stops a running scan before its next request.
 *
 * Promises exactly that. A request already on the wire completes, because nothing can
 * recall one. Resolves to whether there was a run to stop.
 */
export const scanActiveStop = (): Promise<boolean> =>
  invoke<boolean>("scan_active_stop");

/* ------------------------------------------------------------------ *
 * Engagement snapshots
 * ------------------------------------------------------------------ */

/** A snapshot's header, as the list shows it. */
export interface SnapshotView {
  id: string;
  label: string;
  note: string | null;
  taken_at: string;
  tool_version: string;
  exchanges: number;
  candidates: number;
  findings: number;
  identities: number;
  objects: number;
}

/** How a claim stood at a moment. */
export interface FindingState {
  severity: string;
  confidence: string;
  status: string;
  evidence: number;
}

/**
 * Why a claim present earlier is absent later.
 *
 * None of these means "fixed". A finding is what a test produced; its absence is the
 * absence of a result, and only `not_reproduced` is evidence about the application at
 * all — even that one says only that it did not come back.
 */
export type WhyGone =
  | { kind: "not_reproduced" }
  | { kind: "source_silent" }
  | { kind: "tool_changed"; from: string; to: string };

/** What became of a claim between two snapshots. */
export type Change =
  | { kind: "appeared"; state: FindingState }
  | { kind: "unchanged"; state: FindingState; restated: boolean }
  | { kind: "changed"; before: FindingState; after: FindingState }
  | { kind: "gone"; before: FindingState; because: WhyGone };

export interface ClaimChange {
  claim: { target: string; title: string; location: unknown };
  source: { kind: string };
  change: Change;
}

export interface ScopeLine {
  rule: {
    host: string;
    ports: number[];
    scheme: string;
    path: { kind?: string; value?: string };
  };
  excluded: boolean;
}

export interface Count {
  before: number;
  after: number;
}

export interface Comparison {
  from: { id: string; label: string; taken_at: string; tool_version: string };
  to: { id: string; label: string; taken_at: string; tool_version: string };
  /** False means every disappearance below is inconclusive. */
  same_tool: boolean;
  findings: ClaimChange[];
  scope: { added: ScopeLine[]; removed: ScopeLine[] };
  identities: { added: string[]; removed: string[] };
  objects: { added: string[]; removed: string[] };
  counts: { exchanges: Count; candidates: Count; findings: Count };
}

export const listSnapshots = (): Promise<SnapshotView[]> =>
  invoke<SnapshotView[]>("snapshots_list");

/** Reads the project and writes one row. Sends nothing, copies no traffic. */
export const takeSnapshot = (
  label: string | null,
  note: string | null,
): Promise<SnapshotView[]> =>
  invoke<SnapshotView[]>("snapshot_take", { label, note });

export const deleteSnapshot = (id: string): Promise<SnapshotView[]> =>
  invoke<SnapshotView[]>("snapshot_delete", { id });

/** `to` of null compares against the project as it stands. */
export const compareSnapshots = (
  from: string,
  to: string | null,
): Promise<Comparison> => invoke<Comparison>("snapshot_compare", { from, to });

/* ------------------------------------------------------------------ *
 * Identifier suggestions
 * ------------------------------------------------------------------ */

/** One reason a value was suggested, and what it counted for. */
export interface SignalView {
  kind: string;
  weight: number;
  detail: string;
}

/**
 * A value that *might* be an object identifier.
 *
 * Note what is not here: an owner. A suggestion is Hexora saying "this looks like
 * an identifier"; who it belongs to is an assertion only a tester can make, and it
 * is made by declaring an {@link ObjectView}. Accepting a suggestion does not
 * declare anything.
 */
export interface CandidateView {
  id: string;
  value: string;
  location: string;
  status: string;
  score: number;
  strength: string;
  occurrences: number;
  live_observations: number;
  signals: SignalView[];
  source_request: string | null;
}

export const listCandidates = (): Promise<CandidateView[]> =>
  invoke<CandidateView[]>("candidates_list");

/** Reads the project's own traffic. Sends nothing, changes nothing captured. */
export const analyzeCandidates = (): Promise<CandidateView[]> =>
  invoke<CandidateView[]>("candidates_analyze");

export const decideCandidate = (
  id: string,
  status: "accepted" | "rejected",
): Promise<CandidateView[]> =>
  invoke<CandidateView[]>("candidate_decide", { id, status });

/* ------------------------------------------------------------------ *
 * Findings
 * ------------------------------------------------------------------ */

export interface FindingRow {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  status: string;
  /** Whether this may be presented as an issue rather than a lead. */
  actionable: boolean;
  evidence_count: number;
  updated_at: string;
}

export interface FindingsPage {
  rows: FindingRow[];
  next: string | null;
  total: number;
}

/** One piece of evidence, and the exchanges behind it. */
export interface EvidenceView {
  summary: string;
  requests: string[];
}

export interface FindingDetail {
  row: FindingRow;
  description: string;
  impact: string;
  remediation: string;
  reproduction: string;
  location: string | null;
  cwe: string | null;
  owasp: string | null;
  cvss: string | null;
  created_at: string;
  evidence: EvidenceView[];
}

export const listFindings = (query: {
  severity: string | null;
  status: string | null;
  actionable: boolean;
  after: string | null;
  limit: number;
}): Promise<FindingsPage> => invoke<FindingsPage>("findings_list", query);

export const findingDetail = (id: string): Promise<FindingDetail> =>
  invoke<FindingDetail>("findings_detail", { id });

export const triageFinding = (
  id: string,
  status: string,
): Promise<FindingRow> => invoke<FindingRow>("findings_triage", { id, status });

/* ------------------------------------------------------------------ *
 * Report
 * ------------------------------------------------------------------ */

export interface ReportView {
  format: string;
  headline: string;
  content: string;
  findings: number;
  leads: number;
  caveats: string[];
  path: string | null;
  bytes: number;
}

export const renderReport = (options: {
  format: string;
  title: string | null;
  severity: string | null;
  actionable: boolean;
  showSecrets: boolean;
  saveTo: string | null;
}): Promise<ReportView> => invoke<ReportView>("report_render", options);

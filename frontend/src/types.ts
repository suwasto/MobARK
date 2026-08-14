/**
 * M5 typed API layer - mirrors of the backend Pydantic schemas
 * (backend/app/schemas.py) and model enums (backend/app/models.py).
 */

export interface HealthResponse {
  status: 'ok' | 'degraded'
  version: string
  redis_ok: boolean
  db_ok: boolean
}

// ---- M9.1 auth (login/register + OAuth) ----

/** The session's user (boot check + the TopBar chip). */
export interface UserRead {
  id: number
  username: string
  email: string | null
  /** First registered user = admin (drives claim affordances, Phase C/E). */
  is_admin: boolean
  created_at: string
  /** M9.1 vault: true when this session cannot access the vault (OAuth-only
   * account without an unlocked session). Local users unlock at login, so
   * it is always false for them; only /auth/me sets it. */
  vault_locked: boolean
}

/** register/login/me payload - the user; the session cookie travels in
 * Set-Cookie, never the body. */
export interface AuthResponse {
  user: UserRead
}

export interface LoginRequest {
  username: string
  password: string
}

export interface RegisterRequest {
  username: string
  email?: string | null
  password: string
}

/** What the login page renders: whether auth is on at all (dev/CI parity
 * mode skips the login screen entirely) + which sign-in methods are
 * configured (buttons render only for configured providers). */
export interface ProvidersResponse {
  auth_enabled: boolean
  providers: string[]
}

export type ScanStatus = 'queued' | 'running' | 'done' | 'failed'
export type Platform = 'android' | 'ios'
// No critical band (owner decision, Aug 8 2026) - high is the top severity.
export type Severity = 'high' | 'medium' | 'low' | 'info'

export interface ScanRead {
  id: number
  filename: string
  platform: Platform | null
  status: ScanStatus
  /** Internal severity-weighted risk (higher = worse); the UI reads security_score. */
  risk_score: number | null
  /** Public-facing 0-100 score - higher is better (100 - risk). */
  security_score: number | null
  error: string | null
  stage: string | null
  /** M7: per-scan web research opt-in (privacy gate) - the agent's web tools
   * are offered only when this is on AND an Active search engine exists. */
  web_research_enabled: boolean
  /** M8: on-demand apktool decode state (Android only). The Smali chip uses
   * the dedicated smali-status endpoint (filesystem-derived `ready`); these
   * columns carry the in-flight states + failure reason. */
  apktool_status: ApktoolStatus
  apktool_error: string | null
  created_at: string
}

/** M8 Phase A: on-demand apktool decode lifecycle (the Smali chip).
 * `stalled` (Aug 12): the decode was enqueued but no RQ worker consumed
 * it in time - a missing worker, not a slow apktool. The chip renders it
 * like a failure with the backend's start-the-worker hint. */
export type ApktoolStatus =
  | 'not_started'
  | 'queued'
  | 'decoding'
  | 'ready'
  | 'failed'
  | 'stalled'

export interface SmaliStatus {
  status: ApktoolStatus
  error: string | null
}

/** M8 Phase B: one edit row (the edits table - DB-diff source of truth). */
export interface EditRead {
  id: number
  scan_id: number
  /** apktool-root-relative: smali/..., res/..., AndroidManifest.xml */
  file_path: string
  source: 'manual' | 'agent'
  instruction: string | null
  /** proposed | applied | rejected | reverted */
  status: 'proposed' | 'applied' | 'rejected' | 'reverted'
  build_id: number | null
  created_at: string
  applied_at: string | null
}

export interface EditCreate {
  file_path: string
  content: string
}

export interface EditDiff {
  file_path: string
  diff: string
}

/** Java⇄Smali sibling mapping for the Decompiler view toggle. */
export interface SmaliSibling {
  path: string
  /** Counterpart tree path, or null when the file has none (res/manifest). */
  sibling: string | null
}

/** Java→Smali tree-path mapping for a scan's findings - Smali-mode dots +
 * the annotation rail re-key jadx findings onto their apktool smali
 * siblings (keys = jadx tree paths like `sources/com/foo/A.java`, values =
 * smali tree paths like `smali/com/foo/A.smali`; scoped to finding-bearing
 * paths so the payload stays bounded).
 *
 * `anchors` (Aug 11): smali-mode LINE anchors for line-bearing findings -
 * `{smaliTreePath: {str(jadxLine): smaliLine}}`, each jadx line mapped to
 * its containing method's `.method` line in the smali sibling (jadx
 * renumbers, so only method granularity is honest). The smali rail notes
 * pin there so they align with the smali editor's own line numbers. */
export interface SmaliMapping {
  mapping: Record<string, string>
  anchors: Record<string, Record<string, number>>
  total: number
}

/** M8 Phase C: rebuild lifecycle (the builds table - full history, D8). */
export type BuildStatus = 'queued' | 'running' | 'done' | 'failed'
export type BuildStage =
  | 'queued'
  | 'applying'
  | 'rebuilding'
  | 'zipping'
  | 'signing'
  | 'done'

/** One recompile attempt - the recompile modal's poll target. */
export interface BuildRead {
  id: number
  scan_id: number
  status: BuildStatus
  /** The failing stage is kept on a failed build so the error reads in
   * context; a done build is at 'done'. */
  stage: BuildStage
  error: string | null
  /** Applied edit ids snapshot at job start. */
  edit_ids: number[]
  artifact_name: string | null
  artifact_sha256: string | null
  created_at: string
  finished_at: string | null
}

export interface FindingRead {
  id: number
  scan_id: number
  title: string
  severity: Severity
  file_path: string | null
  line_number: number | null
  category: string | null
  mastg_test_id: string | null
  tool: string
  detail: Record<string, unknown> | null
  static_only: boolean
  /** M5 (Aug 8): false-positive suppression - hidden by default, excluded
   * from risk/summary/agent context; restorable via the review toggle. */
  suppressed: boolean
  suppressed_at: string | null
  created_at: string
}

// ---- M3 model backends (consumed by the Settings modal) ----

export interface ModelBackendHealth {
  reachable: boolean
  status: 'ok' | 'unreachable' | 'unknown'
  latency_ms: number | null
  models: string[]
  model_source: 'live' | 'suggested' | 'unavailable' | 'none'
  probe_model: string | null
  probe_ok: boolean | null
  error: string | null
  checked_at: string | null
}

export interface ModelBackendRead {
  id: string
  provider_id: string
  name: string
  kind: 'local' | 'byok' | 'custom'
  base_url: string
  model: string
  enabled: boolean
  local: boolean
  has_api_key: boolean
  /** Provider's curated model list - Settings shows these by default with a
   * "see all" reveal for the full served list (owner UX request, Aug 8). */
  suggested_models: string[]
  health: ModelBackendHealth | null
}

export interface ModelBackendUpsert {
  base_url?: string | null
  model?: string | null
  api_key?: string | null
  enabled?: boolean | null
}

export interface ModelBackendCreate {
  provider_id: string
  base_url?: string | null
  api_key?: string | null
  model?: string | null
}

export interface ModelBackendModels {
  models: string[]
  source: 'live' | 'suggested' | 'unavailable'
  error: string | null
}

// ---- M7 search backends (web research engines) ----

export interface SearchBackendHealth {
  reachable: boolean
  status: 'ok' | 'unreachable' | 'unknown'
  latency_ms: number | null
  error: string | null
  checked_at: string | null
  /** Full-probe extras: how many normalized results a real query returned. */
  result_count: number | null
  sample_title: string | null
}

export interface SearchBackendRead {
  id: string
  provider_id: string
  name: string
  kind: 'bundled' | 'custom' | 'keyed'
  base_url: string
  /** Active/Inactive radio: exactly one engine enabled at a time. */
  enabled: boolean
  order: number
  /** The key itself is never returned - only whether one is set. */
  has_api_key: boolean
  health: SearchBackendHealth | null
}

export interface SearchBackendUpsert {
  base_url?: string | null
  /** An empty string clears the stored key. */
  api_key?: string | null
  /** `true` triggers the one-Active radio semantics server-side. */
  enabled?: boolean | null
}

export interface SearchBackendCreate {
  provider_id: string
  base_url?: string | null
  api_key?: string | null
}

/** One addable search engine - drives the Settings add-form picker. */
export interface SearchProviderRead {
  id: string
  name: string
  kind: 'custom' | 'keyed'
  base_url_required: boolean
  key_required: boolean
  default_base_url: string
}

// ---- M4 agent layer ----

/** One prior user/assistant turn re-sent with a follow-up (M9 follow-up):
 * the backend never persists chat, so a "continue the edit task" follow-up
 * needs the recent thread to keep the original request in context. */
export interface ChatHistoryTurn {
  role: 'user' | 'assistant'
  content: string
}

export interface ChatRequest {
  question: string
  timeout_seconds?: number | null
  /** M6 Phase C: max tool-calling rounds before the context-only fallback. */
  max_tool_rounds?: number | null
  /** M8 follow-up: tree paths the user @mentioned in the dock - the agent
   * gets their content attached (no search round needed). */
  mentioned_files?: string[]
  /** M9 follow-up: recent turns from the client-side thread, injected before
   * the current question so follow-ups keep the original ask (the buffered
   * fallback; sessions replace it with server-side history). */
  history?: ChatHistoryTurn[]
  /** M9 follow-up: the chat session this turn runs in - the route loads the
   * session's persisted thread and stores the turn back. */
  session_id?: number | null
}

/** M9 follow-up: one chat session in the per-scan switcher. */
export interface ChatSession {
  id: number
  scan_id: number
  title: string
  created_at: string
  updated_at: string
  message_count: number
  last_content: string | null
}

/** M9 follow-up: one persisted turn of a session's thread. */
export interface ChatMessageRead {
  id: number
  role: 'user' | 'assistant'
  content: string
  created_at: string
  tool_runs: ToolRunRead[]
  /** Assistant turns only - reloaded history re-renders the clickable
   * source chips exactly like the live ChatResponse. */
  citations: Citation[]
}

export interface Citation {
  file: string
  line: number | null
  snippet: string
}

/** One executed tool call - the persistent trace on a chat response. */
export interface ToolRunRead {
  id: string
  name: string
  args: Record<string, unknown>
  status: 'ok' | 'error'
  duration_ms: number
  result_preview: string
  error: string | null
  count: number | null
}

export interface ChatResponse {
  answer: string
  citations: Citation[]
  sources: string[]
  /** M6 Phase B: 'tools' when the agent ran tool calls this turn. */
  tool_mode: 'tools' | 'context-only'
  tools_used: string[]
  /** M6 follow-up: the per-tool trace (the live SSE events, finalized). */
  tool_runs: ToolRunRead[]
}

export interface ScanGraphState {
  built: boolean
  nodes: number | null
  edges: number | null
  graph_path: string | null
  reason: string | null
}

// ---- Code maps tab (graphify explorer, Android only) ----

export interface GraphNodeRow {
  id: string
  label: string
  file_type: string | null
  file: string | null
  line: number | null
}

export interface GraphSearchResponse {
  query: string
  /** Pre-limit match count - the UI shows "n of m". */
  total: number
  nodes: GraphNodeRow[]
}

export interface GraphNeighbor {
  node: GraphNodeRow
  relation: string | null
  direction: 'in' | 'out'
}

export interface GraphNodeDetail {
  node: GraphNodeRow
  degree: number
  neighbors: GraphNeighbor[]
}

export interface GraphHubRow {
  node: GraphNodeRow
  degree: number
}

export interface GraphHubsResponse {
  hubs: GraphHubRow[]
}

// ---- M5 dashboard: insights, decompiler tree ----

export interface ExplainResponse {
  explanation: string
  cached: boolean
  model: string | null
  generated_at: string | null
  /** Deterministic no-AI explanation (no model configured) - the same text
   * the report renders, never the cached AI row. */
  fallback?: boolean
}

export interface SummaryResponse {
  summary: string
  cached: boolean
  model: string | null
  generated_at: string | null
}

// ---- M9 report tab (deterministic assembly + cached AI commentary) ----

export interface ReportResponse {
  /** The assembled markdown body (cache-first, identity-validated
   * server-side - a suppress/regenerate/rebuild/web-capture recomputes). */
  markdown: string
  generated_at: string
}


export interface FileNode {
  name: string
  path: string
  type: 'dir' | 'file'
  /** iOS: hidden binary blob listed under the 'Binary (Mach-O)' folder. */
  binary?: boolean
  children: FileNode[]
}

export interface FileTreeRoot {
  name: string
  total_nodes: number
  truncated: boolean
  /** iOS: count of raw binary files hidden from the curated bundle walk. */
  filtered_binaries?: number
  tree: FileNode[]
}

export interface FileTreeResponse {
  platform: Platform
  roots: FileTreeRoot[]
}

export interface FileContentResponse {
  path: string
  content: string
  language: string
  truncated: boolean
  size: number
}

// ---- Dependencies tab (local-first inventory) ----

/** package (Android Java/Kotlin group) · native (Android lib/*.so) ·
 * dylib (iOS Mach-O link) · framework (iOS embedded bundle). */
export type DependencyKind = 'package' | 'native' | 'dylib' | 'framework'

export interface DependencyApp {
  /** Android */
  package: string | null
  min_sdk: number | null
  target_sdk: number | null
  /** iOS */
  bundle_id: string | null
  version: string | null
}

export interface DependencyItem {
  name: string
  /** Human name for well-known libraries (Android packages only). */
  label: string | null
  kind: DependencyKind
  evidence: string
  file_count: number | null
  /** Non-suppressed semgrep findings inside the package (Android only). */
  finding_count: number
  high_count: number
  medium_count: number
  /** Native libs: the ABIs the .so ships for. */
  abis: string[]
  /** iOS dylibs: true = Apple's own runtime, false = third-party. */
  system: boolean | null
}

export interface DependenciesResponse {
  platform: Platform
  app: DependencyApp
  /** Cross-platform engines embedded in the app (Flutter, React Native…). */
  runtime_markers: string[]
  dependencies: DependencyItem[]
  total: number
  truncated: boolean
  generated_at: string
}

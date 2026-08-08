/**
 * M5 typed API layer — mirrors of the backend Pydantic schemas
 * (backend/app/schemas.py) and model enums (backend/app/models.py).
 */

export interface HealthResponse {
  status: 'ok' | 'degraded'
  version: string
  redis_ok: boolean
  db_ok: boolean
}

export type ScanStatus = 'queued' | 'running' | 'done' | 'failed'
export type Platform = 'android' | 'ios'
// No critical band (owner decision, Aug 8 2026) — high is the top severity.
export type Severity = 'high' | 'medium' | 'low' | 'info'

export interface ScanRead {
  id: number
  filename: string
  platform: Platform | null
  status: ScanStatus
  /** Internal severity-weighted risk (higher = worse); the UI reads security_score. */
  risk_score: number | null
  /** Public-facing 0-100 score — higher is better (100 - risk). */
  security_score: number | null
  error: string | null
  stage: string | null
  created_at: string
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
  /** M5 (Aug 8): false-positive suppression — hidden by default, excluded
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
  /** Provider's curated model list — Settings shows these by default with a
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

// ---- M4 agent layer ----

export interface ChatRequest {
  question: string
  timeout_seconds?: number | null
}

export interface Citation {
  file: string
  line: number | null
  snippet: string
}

export interface ChatResponse {
  answer: string
  citations: Citation[]
  sources: string[]
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
  /** Pre-limit match count — the UI shows "n of m". */
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
}

export interface SummaryResponse {
  summary: string
  cached: boolean
  model: string | null
  generated_at: string | null
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

/**
 * M5 typed API client - thin fetch wrapper over the FastAPI surface.
 *
 * All endpoints hang off the same-origin `/api/v1` base (Vite dev proxy in
 * dev, FastAPI static mount in production). Errors are normalized to
 * `ApiError` with the FastAPI `detail` message so the UI can render them.
 */
import type {
  AuthResponse,
  BuildRead,
  ChatHistoryTurn,
  ChatMessageRead,
  ChatRequest,
  ChatResponse,
  ChatSession,
  EditCreate,
  EditDiff,
  EditRead,
  ExplainResponse,
  FileContentResponse,
  FileTreeResponse,
  FindingRead,
  GraphHubsResponse,
  GraphNodeDetail,
  GraphSearchResponse,
  HealthResponse,
  LoginRequest,
  ModelBackendCreate,
  ModelBackendModels,
  ModelBackendRead,
  ModelBackendUpsert,
  ProvidersResponse,
  RegisterRequest,
  ScanGraphState,
  ScanRead,
  DependenciesResponse,
  ReportResponse,
  SearchBackendCreate,
  SearchBackendRead,
  SearchBackendUpsert,
  SearchProviderRead,
  Severity,
  SmaliMapping,
  SmaliSibling,
  SmaliStatus,
  SummaryResponse,
  UserRead,
} from '../types'

const API_BASE = '/api/v1'

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, detail: string) {
    super(detail)
    this.name = 'ApiError'
    this.status = status
  }
}

/** M9.1: the app-wide "session died" hook - AppContext registers it (via
 * `setOnUnauthorized`) and any guarded request that comes back 401 calls
 * it, dropping the UI to the login screen. Auth routes (login/register/me)
 * throw their own 401s to the caller instead - a wrong password is a form
 * error, not a session expiry. */
let onUnauthorized: (() => void) | null = null

export function setOnUnauthorized(fn: (() => void) | null) {
  onUnauthorized = fn
}

async function toApiError(res: Response): Promise<ApiError> {
  let detail = `${res.status} ${res.statusText}`
  try {
    const body = (await res.json()) as { detail?: unknown }
    if (typeof body.detail === 'string') {
      detail = body.detail
    } else if (body.detail != null) {
      detail = JSON.stringify(body.detail)
    }
  } catch {
    // Non-JSON error body - fall back to the status text above.
  }
  return new ApiError(res.status, detail)
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  const hasBody = init.body != null
  if (hasBody && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers }).catch((err: unknown) => {
    // User-initiated aborts (the agent Stop button) reach the caller
    // untouched so it can tell "stopped" apart from a real network failure.
    // Check by name, not instanceof - some fetch polyfills reject with a
    // plain Error named 'AbortError' rather than a DOMException.
    if ((err as { name?: string } | null)?.name === 'AbortError') throw err
    // Network-level failures (backend down, proxy unreachable) become
    // ApiError(0) so callers get one consistent error type to render.
    const msg = err instanceof Error ? err.message : String(err)
    throw new ApiError(0, `Network error: ${msg}`)
  })
  if (!res.ok) {
    const err = await toApiError(res)
    // A 401 from any GUARDED route means the session died mid-use (expired,
    // revoked, or logged out elsewhere) - the AppContext hook clears state
    // and drops to login. Auth routes are excluded: their 401s are form
    // errors (bad password) the caller renders inline.
    if (err.status === 401 && !path.startsWith('/auth/')) onUnauthorized?.()
    throw err
  }
  if (res.status === 204) {
    return undefined as T
  }
  return (await res.json()) as T
}

export interface FindingsQuery {
  severity?: Severity
  limit?: number
  offset?: number
  /** M5 (Aug 8): show suppressed (false-positive) findings too - the review
   * toggle. Defaults to false (suppressed findings are hidden). */
  includeSuppressed?: boolean
}

/** Result of a batch suppress/restore. `finding_ids` lists exactly which
 * rows THIS call toggled, so an Undo toast can restore them precisely. */
export interface BatchFindingsResponse {
  suppressed: number
  restored: number
  finding_ids: number[]
}

export const api = {
  // ---- M9.1 auth ----
  /** The session cookie's user, or null (auth-off parity mode). 401 without
   * a session - the boot flow treats that as "not logged in". */
  me: () => request<UserRead | null>('/auth/me'),
  login: (payload: LoginRequest) =>
    request<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  register: (payload: RegisterRequest) =>
    request<AuthResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  logout: () => request<void>('/auth/logout', { method: 'POST' }),
  /** Which sign-in methods are configured (login page buttons). */
  providers: () => request<ProvidersResponse>('/auth/providers'),
  /** M9.1 vault: unlock the vault with the vault passphrase (OAuth-only
   * accounts - first use creates it). Local users unlock at login. */
  unlockVault: (passphrase: string) =>
    request<{ unlocked: boolean }>('/auth/vault/unlock', {
      method: 'POST',
      body: JSON.stringify({ passphrase }),
    }),
  /** M9.1 vault: forgot the passphrase? Destroys the vault and clears the
   * stored keys (the recovery path - keys are unrecoverable by design). */
  resetVault: () =>
    request<{ reset: boolean }>('/auth/vault/reset', { method: 'POST' }),
  /** OAuth entry: the 302 to the provider. Plain-anchor target (a fetch
   * would follow the redirect into the provider's consent page). */
  oauthStartUrl: (provider: string) => `${API_BASE}/auth/oauth/${provider}/start`,

  // ---- M0/M5 scans ----
  health: () => request<HealthResponse>('/health'),
  listScans: () => request<ScanRead[]>('/scans'),
  getScan: (scanId: number) => request<ScanRead>(`/scans/${scanId}`),
  createScan: (file: File) => {
    const form = new FormData()
    form.append('file', file, file.name)
    return request<ScanRead>('/scans', { method: 'POST', body: form })
  },
  listFindings: (scanId: number, q: FindingsQuery = {}) => {
    const params = new URLSearchParams()
    if (q.severity) params.set('severity', q.severity)
    if (q.limit != null) params.set('limit', String(q.limit))
    if (q.offset != null) params.set('offset', String(q.offset))
    if (q.includeSuppressed) params.set('include_suppressed', 'true')
    const qs = params.toString()
    return request<FindingRead[]>(`/scans/${scanId}/findings${qs ? `?${qs}` : ''}`)
  },
  /** M5 (Aug 8): mark a finding as a suppressed false positive (risk
   * recomputed server-side). */
  suppressFinding: (scanId: number, findingId: number) =>
    request<FindingRead>(`/scans/${scanId}/findings/${findingId}/suppress`, {
      method: 'POST',
    }),
  /** M5 (Aug 8): restore a suppressed finding (review toggle). */
  unsuppressFinding: (scanId: number, findingId: number) =>
    request<FindingRead>(`/scans/${scanId}/findings/${findingId}/unsuppress`, {
      method: 'POST',
    }),
  /** M5 follow-up: batch-suppress every finding with this title (MASTG rules
   * emit one row per occurrence - e.g. dozens of "up-to-date OS version"
   * checks). `category` optionally narrows the match. Risk recomputed once
   * server-side; returns how many were toggled + their ids (for Undo). */
  suppressFindingsByTitle: (scanId: number, title: string, category?: string) =>
    request<BatchFindingsResponse>(
      `/scans/${scanId}/findings/suppress-batch`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, category: category ?? null }),
      },
    ),
  /** M5 follow-up: batch-restore the suppressed findings with this title
   * (the review side's mirror of suppressFindingsByTitle). */
  unsuppressFindingsByTitle: (scanId: number, title: string, category?: string) =>
    request<BatchFindingsResponse>(
      `/scans/${scanId}/findings/unsuppress-batch`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, category: category ?? null }),
      },
    ),
  /** M5 follow-up: bulk-suppress a whole severity band (the Findings group
   * header action) - every non-suppressed finding of that severity. */
  suppressFindingsBySeverity: (scanId: number, severity: Severity) =>
    request<BatchFindingsResponse>(
      `/scans/${scanId}/findings/suppress-batch`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity }),
      },
    ),
  /** M5 follow-up: bulk-restore a whole severity band (the review side's
   * mirror of suppressFindingsBySeverity). */
  unsuppressFindingsBySeverity: (scanId: number, severity: Severity) =>
    request<BatchFindingsResponse>(
      `/scans/${scanId}/findings/unsuppress-batch`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity }),
      },
    ),
  /** M5 follow-up: restore exactly these finding ids - the Undo toast's
   * precise counterpart to a batch suppress (match-based restores would
   * also flip earlier, separately-suppressed rows). */
  unsuppressFindingsByIds: (scanId: number, findingIds: number[]) =>
    request<BatchFindingsResponse>(
      `/scans/${scanId}/findings/unsuppress-batch`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_ids: findingIds }),
      },
    ),
  /** M5 follow-up: suppress exactly these finding ids - the Undo of a batch
   * restore (review-side mirror of unsuppressFindingsByIds). */
  suppressFindingsByIds: (scanId: number, findingIds: number[]) =>
    request<BatchFindingsResponse>(
      `/scans/${scanId}/findings/suppress-batch`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_ids: findingIds }),
      },
    ),
  /** Cached server-side (scans.ai_summary) - repeat calls return it with no
   * LLM spend. `regenerate` explicitly bypasses the cache (Regenerate button). */
  scanSummary: (scanId: number, regenerate = false) =>
    request<SummaryResponse>(
      `/scans/${scanId}/summary${regenerate ? '?regenerate=true' : ''}`,
      { method: 'POST' },
    ),
  /** Cached server-side (findings.explanation) - repeat calls are free.
   * `regenerate` explicitly bypasses the cache (Regenerate button). */
  explainFinding: (scanId: number, findingId: number, regenerate = false) =>
    request<ExplainResponse>(
      `/scans/${scanId}/findings/${findingId}/explain${regenerate ? '?regenerate=true' : ''}`,
      { method: 'POST' },
    ),
  /** M7: per-scan web research opt-in (the dock 🌐 toggle / Settings). */
  setWebResearch: (scanId: number, enabled: boolean) =>
    request<ScanRead>(`/scans/${scanId}/web-research`, {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    }),
  getFiles: (scanId: number) => request<FileTreeResponse>(`/scans/${scanId}/files`),
  getFileContent: (scanId: number, path: string) =>
    request<FileContentResponse>(
      `/scans/${scanId}/files/content?path=${encodeURIComponent(path)}`,
    ),
  /** Dependencies tab inventory - derived on demand, nothing leaves the
   * machine. Known-CVE research is the agent's web-research use case (the
   * panel's "Check known CVEs" button pre-fills the dock question). */
  listDependencies: (scanId: number) =>
    request<DependenciesResponse>(`/scans/${scanId}/dependencies`),

  // ---- M9 report tab (assembly + export) ----
  /** The assembled report body (cached server-side; never 400s on a missing
   * model - the AI sections render their cached rows or the explicit no-AI
   * note). */
  getReport: (scanId: number) => request<ReportResponse>(`/scans/${scanId}/report`),
  /** M9 Phase C: the export download URL. Same-origin, so a plain anchor
   * with the `download` attribute works - the backend's Content-Disposition
   * sets the `{stem}-report.md|pdf` attachment name anyway. */
  reportExportUrl: (scanId: number, format: 'md' | 'pdf') =>
    `${API_BASE}/scans/${scanId}/report/export?format=${format}`,
  /** The Report tab's live PDF preview URL - the backend serves it with
   * `Content-Disposition: inline` so an <iframe> renders it (attachment
   * would trigger a download instead). The optional `nonce` cache-busts so
   * a Regenerate / tab re-activation reloads the freshly assembled body. */
  reportPdfUrl: (scanId: number, nonce?: number) =>
    `${API_BASE}/scans/${scanId}/report/export?format=pdf&inline=1${
      nonce ? `&t=${nonce}` : ''
    }`,

  // ---- M8 Phase A: on-demand apktool decode (Smali view) ----

  // ---- M8 Phase A: on-demand apktool decode (Smali view) ----
  /** Trigger the on-demand apktool decode (202 queued; 409 already
   * decoding/ready, non-Android, or not analyzed). */
  triggerSmali: (scanId: number) =>
    request<SmaliStatus>(`/scans/${scanId}/smali`, { method: 'POST' }),
  /** Current decode state - `ready` is filesystem-derived server-side, so a
   * worker crash mid-decode can never report a phantom ready. */
  smaliStatus: (scanId: number) =>
    request<SmaliStatus>(`/scans/${scanId}/smali-status`),

  // ---- M8 Phase B: edits (DB-diff source of truth) ----
  /** All edit rows for a scan, newest first (full history). */
  listEdits: (scanId: number) => request<EditRead[]>(`/scans/${scanId}/edits`),
  /** Manual edit from the editor (Ctrl/Cmd+S) - created as `applied`. */
  createEdit: (scanId: number, payload: EditCreate) =>
    request<EditRead>(`/scans/${scanId}/edits`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  /** The stored unified diff for one edit (the review surface). */
  editDiff: (scanId: number, editId: number) =>
    request<EditDiff>(`/scans/${scanId}/edits/${editId}/diff`),
  /** proposed -> applied (agent proposals; human-owned). */
  applyEdit: (scanId: number, editId: number) =>
    request<EditRead>(`/scans/${scanId}/edits/${editId}/apply`, { method: 'POST' }),
  /** proposed -> rejected. */
  rejectEdit: (scanId: number, editId: number) =>
    request<EditRead>(`/scans/${scanId}/edits/${editId}/reject`, { method: 'POST' }),
  /** applied -> reverted (restore-original: pops to the prior state). */
  revertEdit: (scanId: number, editId: number) =>
    request<EditRead>(`/scans/${scanId}/edits/${editId}/revert`, { method: 'POST' }),
  /** Java⇄Smali counterpart of a tree path (the view-toggle jump). */
  smaliSibling: (scanId: number, path: string) =>
    request<SmaliSibling>(
      `/scans/${scanId}/files/smali-sibling?path=${encodeURIComponent(path)}`,
    ),
  /** Java→Smali tree-path mapping for the scan's findings - Smali-mode
   * dots + the annotation rail re-key jadx findings onto their apktool
   * smali siblings (Android only; empty mapping before the decode). */
  smaliMapping: (scanId: number) =>
    request<SmaliMapping>(`/scans/${scanId}/smali-mapping`),

  // ---- M8 Phase C: rebuild pipeline (recompile + resign) ----
  /** Enqueue a recompile (202 queued; 409 not analyzed / iOS / decode not
   * ready / another build in flight). */
  triggerRebuild: (scanId: number) =>
    request<BuildRead>(`/scans/${scanId}/rebuild`, { method: 'POST' }),
  /** Full rebuild history, newest first. */
  listBuilds: (scanId: number) => request<BuildRead[]>(`/scans/${scanId}/builds`),
  /** One build - the recompile modal's poll target for live stages. */
  getBuild: (scanId: number, buildId: number) =>
    request<BuildRead>(`/scans/${scanId}/builds/${buildId}`),
  /** Download URL of a done build's resigned TEST APK. Same-origin, so a
   * plain anchor works - the backend sets the attachment name (which carries
   * the `-resigned-test-` label) + the X-Resigned-Test-Build header. */
  buildDownloadUrl: (scanId: number, buildId: number) =>
    `${API_BASE}/scans/${scanId}/builds/${buildId}/download`,

  // ---- M4 agent layer ----
  chat: (
    scanId: number,
    question: string,
    timeoutSeconds?: number,
    /** AbortSignal from the Stop button - aborting makes the fetch reject
     * with AbortError (re-thrown untouched by `request`). */
    signal?: AbortSignal,
    /** M8 follow-up: tree paths the user @mentioned in the dock. */
    mentionedFiles?: string[],
    /** M9 follow-up: recent turns from the client-side thread so follow-ups
     * ("continue the edit task") keep the original request (buffered-only
     * fallback; sessions use server-side history). */
    history?: ChatHistoryTurn[],
    /** M9 follow-up: run the turn in this chat session (persisted thread). */
    sessionId?: number | null,
  ) => {
    const body: ChatRequest = { question }
    if (timeoutSeconds != null) body.timeout_seconds = timeoutSeconds
    if (mentionedFiles && mentionedFiles.length > 0) body.mentioned_files = mentionedFiles
    if (history && history.length > 0) body.history = history
    if (sessionId != null) body.session_id = sessionId
    return request<ChatResponse>(`/scans/${scanId}/chat`, {
      method: 'POST',
      body: JSON.stringify(body),
      signal,
    })
  },
  // ---- M9 follow-up: multi-session agent chat ----
  listChatSessions: (scanId: number) =>
    request<ChatSession[]>(`/scans/${scanId}/chat/sessions`),
  createChatSession: (scanId: number) =>
    request<ChatSession>(`/scans/${scanId}/chat/sessions`, { method: 'POST' }),
  renameChatSession: (scanId: number, sessionId: number, title: string) =>
    request<ChatSession>(`/scans/${scanId}/chat/sessions/${sessionId}/rename`, {
      method: 'POST',
      body: JSON.stringify({ title }),
    }),
  deleteChatSession: (scanId: number, sessionId: number) =>
    request<{ deleted: boolean }>(`/scans/${scanId}/chat/sessions/${sessionId}`, {
      method: 'DELETE',
    }),
  chatSessionMessages: (scanId: number, sessionId: number) =>
    request<ChatMessageRead[]>(`/scans/${scanId}/chat/sessions/${sessionId}/messages`),
  /** M6 follow-up: SSE stream of one agent turn (live token + tool events).
   * Returns the raw Response - the caller reads the body as a stream and
   * decodes events (pre-stream HTTP errors - 400 no-model, 409 not analyzed -
   * still surface as ApiError here; in-stream failures arrive as SSE
   * `error` frames). */
  chatStream: (
    scanId: number,
    question: string,
    signal?: AbortSignal,
    /** M8 follow-up: tree paths the user @mentioned in the dock. */
    mentionedFiles?: string[],
    /** M9 follow-up: recent turns from the client-side thread so follow-ups
     * ("continue the edit task") keep the original request (fallback;
     * sessions use server-side history). */
    history?: ChatHistoryTurn[],
    /** M9 follow-up: run the turn in this chat session (persisted thread). */
    sessionId?: number | null,
  ) =>
    fetch(`${API_BASE}/scans/${scanId}/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        question,
        ...(mentionedFiles && mentionedFiles.length > 0
          ? { mentioned_files: mentionedFiles }
          : {}),
        ...(history && history.length > 0 ? { history } : {}),
        ...(sessionId != null ? { session_id: sessionId } : {}),
      }),
      signal,
    }).then(async (res) => {
      if (!res.ok) throw await toApiError(res)
      return res
    }),
  /** Stop an in-flight agent chat (the Stop button) - fire-and-forget; the
   * server polls this flag between agent rounds and halts the LLM loop so it
   * stops burning tokens instead of running to the end of the budget. */
  cancelChat: (scanId: number) =>
    request<{ cancelled: boolean }>(`/scans/${scanId}/chat/cancel`, {
      method: 'POST',
    }),
  getGraph: (scanId: number) => request<ScanGraphState>(`/scans/${scanId}/graph`),
  /** Code maps (Android only): substring search over graph node labels/ids. */
  graphSearch: (scanId: number, q: string, limit = 25) =>
    request<GraphSearchResponse>(
      `/scans/${scanId}/graph/search?q=${encodeURIComponent(q)}&limit=${limit}`,
    ),
  /** Code maps: most-connected nodes (initial view before any search). */
  graphHubs: (scanId: number, limit = 25) =>
    request<GraphHubsResponse>(`/scans/${scanId}/graph/hubs?limit=${limit}`),
  /** Code maps: one node + its in/out neighbors (relation-tagged). */
  graphNode: (scanId: number, nodeId: string) =>
    request<GraphNodeDetail>(
      `/scans/${scanId}/graph/node/${encodeURIComponent(nodeId)}`,
    ),

  // ---- M3/M5 model backends ----
  listBackends: () => request<ModelBackendRead[]>('/model/backends'),
  createBackend: (payload: ModelBackendCreate) =>
    request<ModelBackendRead>('/model/backends', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateBackend: (backendId: string, payload: ModelBackendUpsert) =>
    request<ModelBackendRead>(`/model/backends/${backendId}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteBackend: (backendId: string) =>
    request<void>(`/model/backends/${backendId}`, { method: 'DELETE' }),
  testBackend: (backendId: string) =>
    request<ModelBackendRead>(`/model/backends/${backendId}/test`, { method: 'POST' }),
  backendModels: (backendId: string) =>
    request<ModelBackendModels>(`/model/backends/${backendId}/models`),

  // ---- M7 search backends (web research engines) ----
  listSearchBackends: () => request<SearchBackendRead[]>('/search/backends'),
  /** The addable engine set (Settings add-form picker) - everything except
   * the bundled SearXNG. */
  listSearchProviders: () => request<SearchProviderRead[]>('/search/providers'),
  createSearchBackend: (payload: SearchBackendCreate) =>
    request<SearchBackendRead>('/search/backends', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  /** `enabled: true` triggers the one-Active radio semantics server-side. */
  updateSearchBackend: (id: string, payload: SearchBackendUpsert) =>
    request<SearchBackendRead>(`/search/backends/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteSearchBackend: (id: string) =>
    request<void>(`/search/backends/${id}`, { method: 'DELETE' }),
  /** Full probe: a real search query against the engine. */
  testSearchBackend: (id: string) =>
    request<SearchBackendRead>(`/search/backends/${id}/test`, { method: 'POST' }),
  /** One-click start for the bundled engine - runs `docker compose up -d
   * searxng` server-side and waits for it to answer (the Settings
   * "Start engine" button, the recovery path now that searxng starts with
   * the stack; custom instances 400). */
  startSearchBackend: (id: string) =>
    request<SearchBackendRead>(`/search/backends/${id}/start`, { method: 'POST' }),
}

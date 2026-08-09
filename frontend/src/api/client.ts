/**
 * M5 typed API client — thin fetch wrapper over the FastAPI surface.
 *
 * All endpoints hang off the same-origin `/api/v1` base (Vite dev proxy in
 * dev, FastAPI static mount in production). Errors are normalized to
 * `ApiError` with the FastAPI `detail` message so the UI can render them.
 */
import type {
  ChatRequest,
  ChatResponse,
  ExplainResponse,
  FileContentResponse,
  FileTreeResponse,
  FindingRead,
  GraphHubsResponse,
  GraphNodeDetail,
  GraphSearchResponse,
  HealthResponse,
  ModelBackendCreate,
  ModelBackendModels,
  ModelBackendRead,
  ModelBackendUpsert,
  ScanGraphState,
  ScanRead,
  Severity,
  SummaryResponse,
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
    // Non-JSON error body — fall back to the status text above.
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
    // Check by name, not instanceof — some fetch polyfills reject with a
    // plain Error named 'AbortError' rather than a DOMException.
    if ((err as { name?: string } | null)?.name === 'AbortError') throw err
    // Network-level failures (backend down, proxy unreachable) become
    // ApiError(0) so callers get one consistent error type to render.
    const msg = err instanceof Error ? err.message : String(err)
    throw new ApiError(0, `Network error: ${msg}`)
  })
  if (!res.ok) {
    throw await toApiError(res)
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
  /** M5 (Aug 8): show suppressed (false-positive) findings too — the review
   * toggle. Defaults to false (suppressed findings are hidden). */
  includeSuppressed?: boolean
}

export const api = {
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
  /** Cached server-side (scans.ai_summary) — repeat calls return it with no
   * LLM spend. `regenerate` explicitly bypasses the cache (Regenerate button). */
  scanSummary: (scanId: number, regenerate = false) =>
    request<SummaryResponse>(
      `/scans/${scanId}/summary${regenerate ? '?regenerate=true' : ''}`,
      { method: 'POST' },
    ),
  /** Cached server-side (findings.explanation) — repeat calls are free.
   * `regenerate` explicitly bypasses the cache (Regenerate button). */
  explainFinding: (scanId: number, findingId: number, regenerate = false) =>
    request<ExplainResponse>(
      `/scans/${scanId}/findings/${findingId}/explain${regenerate ? '?regenerate=true' : ''}`,
      { method: 'POST' },
    ),
  getFiles: (scanId: number) => request<FileTreeResponse>(`/scans/${scanId}/files`),
  getFileContent: (scanId: number, path: string) =>
    request<FileContentResponse>(
      `/scans/${scanId}/files/content?path=${encodeURIComponent(path)}`,
    ),

  // ---- M4 agent layer ----
  chat: (
    scanId: number,
    question: string,
    timeoutSeconds?: number,
    /** AbortSignal from the Stop button — aborting makes the fetch reject
     * with AbortError (re-thrown untouched by `request`). */
    signal?: AbortSignal,
  ) => {
    const body: ChatRequest = { question }
    if (timeoutSeconds != null) body.timeout_seconds = timeoutSeconds
    return request<ChatResponse>(`/scans/${scanId}/chat`, {
      method: 'POST',
      body: JSON.stringify(body),
      signal,
    })
  },
  /** M6 follow-up: SSE stream of one agent turn (live token + tool events).
   * Returns the raw Response — the caller reads the body as a stream and
   * decodes events (pre-stream HTTP errors — 400 no-model, 409 not analyzed —
   * still surface as ApiError here; in-stream failures arrive as SSE
   * `error` frames). */
  chatStream: (scanId: number, question: string, signal?: AbortSignal) =>
    fetch(`${API_BASE}/scans/${scanId}/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
      signal,
    }).then(async (res) => {
      if (!res.ok) throw await toApiError(res)
      return res
    }),
  /** Stop an in-flight agent chat (the Stop button) — fire-and-forget; the
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
}

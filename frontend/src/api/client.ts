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

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  const hasBody = init.body != null
  if (hasBody && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers }).catch((err: unknown) => {
    // Network-level failures (backend down, proxy unreachable) become
    // ApiError(0) so callers get one consistent error type to render.
    const msg = err instanceof Error ? err.message : String(err)
    throw new ApiError(0, `Network error: ${msg}`)
  })
  if (!res.ok) {
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
    throw new ApiError(res.status, detail)
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
    const qs = params.toString()
    return request<FindingRead[]>(`/scans/${scanId}/findings${qs ? `?${qs}` : ''}`)
  },
  scanSummary: (scanId: number) =>
    request<SummaryResponse>(`/scans/${scanId}/summary`, { method: 'POST' }),
  explainFinding: (scanId: number, findingId: number) =>
    request<ExplainResponse>(`/scans/${scanId}/findings/${findingId}/explain`, {
      method: 'POST',
    }),
  getFiles: (scanId: number) => request<FileTreeResponse>(`/scans/${scanId}/files`),
  getFileContent: (scanId: number, path: string) =>
    request<FileContentResponse>(
      `/scans/${scanId}/files/content?path=${encodeURIComponent(path)}`,
    ),

  // ---- M4 agent layer ----
  chat: (scanId: number, question: string, timeoutSeconds?: number) => {
    const body: ChatRequest = { question }
    if (timeoutSeconds != null) body.timeout_seconds = timeoutSeconds
    return request<ChatResponse>(`/scans/${scanId}/chat`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  },
  getGraph: (scanId: number) => request<ScanGraphState>(`/scans/${scanId}/graph`),

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

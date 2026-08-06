import { useCallback, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import type { ExplainResponse } from '../types'

export type ExplainState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'ok'; data: ExplainResponse }
  | { kind: 'no-model' }
  | { kind: 'error'; message: string }

/**
 * Per-finding AI explanation (POST /scans/{id}/findings/{fid}/explain),
 * shared by the Findings tab rows and the Decompiler annotation rail.
 * The backend caches in findings.explanation, so repeat calls are free.
 */
export function useExplain(scanId: number, findingId: number) {
  const [state, setState] = useState<ExplainState>({ kind: 'idle' })
  const requestIdRef = useRef(0)

  const fetchExplain = useCallback(() => {
    const id = ++requestIdRef.current
    setState({ kind: 'loading' })
    api
      .explainFinding(scanId, findingId)
      .then((data) => {
        if (requestIdRef.current === id) setState({ kind: 'ok', data })
      })
      .catch((err: unknown) => {
        if (requestIdRef.current !== id) return
        if (err instanceof ApiError && err.status === 400) {
          setState({ kind: 'no-model' })
        } else {
          setState({
            kind: 'error',
            message: err instanceof Error ? err.message : String(err),
          })
        }
      })
  }, [scanId, findingId])

  return { state, fetchExplain }
}

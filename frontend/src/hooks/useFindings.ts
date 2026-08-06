import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/client'
import type { FindingRead, Severity } from '../types'

export type SeverityCounts = Record<Severity, number>

export interface UseFindingsResult {
  findings: FindingRead[]
  counts: SeverityCounts
  total: number
  loading: boolean
  error: string | null
  refetch: () => void
}

const EMPTY_COUNTS: SeverityCounts = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
}

/**
 * All findings for one scan (API default limit of 1000 covers the flagship
 * InsecureBankv2 523-finding scan) plus severity counts for the Overview
 * stat boxes. Re-fetches when the scan id changes or `refetch` is called.
 */
export function useFindings(scanId: number | null): UseFindingsResult {
  // Start loading when there is a scan to load, so the Overview never
  // flashes the empty-state before the effect kicks in.
  const [findings, setFindings] = useState<FindingRead[]>([])
  const [loading, setLoading] = useState(scanId != null)
  const [error, setError] = useState<string | null>(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (scanId == null) {
      setFindings([])
      setError(null)
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    setError(null)
    // v1 cap: the API's max page size is 1000 (covers the flagship
    // InsecureBankv2 523-finding scan); larger scans would truncate the
    // stat boxes / tab count — revisit with pagination in a later pass.
    api
      .listFindings(scanId, { limit: 1000 })
      .then((list) => {
        if (!cancelled) setFindings(list)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setFindings([])
        setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId, tick])

  const counts = useMemo<SeverityCounts>(() => {
    const c = { ...EMPTY_COUNTS }
    for (const f of findings) c[f.severity] += 1
    return c
  }, [findings])

  return {
    findings,
    counts,
    total: findings.length,
    loading,
    error,
    refetch: () => setTick((t) => t + 1),
  }
}

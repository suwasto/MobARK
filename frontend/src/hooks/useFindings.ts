import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/client'
import type { FindingRead, Severity } from '../types'

export type SeverityCounts = Record<Severity, number>

export interface UseFindingsResult {
  /** Non-suppressed findings (the real posture) - what Overview / Decompiler
   * / Findings render by default. */
  findings: FindingRead[]
  /** Suppressed (false-positive) findings - shown by the review toggle. */
  suppressed: FindingRead[]
  counts: SeverityCounts
  total: number
  suppressedCount: number
  loading: boolean
  error: string | null
  refetch: () => void
}

const EMPTY_COUNTS: SeverityCounts = {
  high: 0,
  warning: 0,
  info: 0,
}

/**
 * All findings for one scan (API limit of 5000 covers large APKs with
 * thousands of findings) plus severity counts for the Overview
 * stat boxes. Fetches suppressed findings too (single call) and splits them
 * out: `findings` = active, `suppressed` = the review queue. Counts are over
 * the ACTIVE set - suppressed false positives don't drive the posture or the
 * chips (matching the server-side risk score). Re-fetches when the scan id
 * changes or `refetch` is called.
 */
export function useFindings(scanId: number | null): UseFindingsResult {
  // Start loading when there is a scan to load, so the Overview never
  // flashes the empty-state before the effect kicks in.
  const [all, setAll] = useState<FindingRead[]>([])
  const [loading, setLoading] = useState(scanId != null)
  const [error, setError] = useState<string | null>(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (scanId == null) {
      setAll([])
      setError(null)
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    setError(null)
    // v2: limit raised to 5000 to support large APKs (150 MB+) with
    // thousands of findings. The virtual list in FindingsPanel handles
    // rendering. include_suppressed=true so the review toggle needs no
    // extra fetch.
    api
      .listFindings(scanId, { limit: 5000, includeSuppressed: true })
      .then((list) => {
        if (!cancelled) setAll(list)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setAll([])
        setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId, tick])

  const { findings, suppressed } = useMemo(() => {
    const active: FindingRead[] = []
    const hidden: FindingRead[] = []
    for (const f of all) {
      if (f.suppressed) hidden.push(f)
      else active.push(f)
    }
    return { findings: active, suppressed: hidden }
  }, [all])

  const counts = useMemo<SeverityCounts>(() => {
    const c = { ...EMPTY_COUNTS }
    for (const f of findings) c[f.severity] += 1
    return c
  }, [findings])

  return {
    findings,
    suppressed,
    counts,
    total: findings.length,
    suppressedCount: suppressed.length,
    loading,
    error,
    refetch: () => setTick((t) => t + 1),
  }
}

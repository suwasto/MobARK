import { useEffect, useState } from 'react'
import { api } from '../api/client'
import type { FileContentResponse } from '../types'

interface UseFileContentResult {
  data: FileContentResponse | null
  loading: boolean
  error: string | null
}

/** Fetch one decompiled file (GET /scans/{id}/files/content?path=). */
export function useFileContent(
  scanId: number | null,
  contentPath: string | null,
): UseFileContentResult {
  const [data, setData] = useState<FileContentResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (scanId == null || contentPath == null) {
      setData(null)
      setError(null)
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    setError(null)
    setData(null)
    api
      .getFileContent(scanId, contentPath)
      .then((d) => {
        if (!cancelled) setData(d)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId, contentPath])

  return { data, loading, error }
}

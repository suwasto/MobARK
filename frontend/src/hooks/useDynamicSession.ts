import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import type { DynamicScriptRead, DynamicSessionRead } from '../types'

/**
 * M18: the LIVE dynamic-session state for the current scan. Polls
 * `GET /dynamic/session` every 3s while the dashboard is loaded (the backend
 * holds ONE process-local active session, scan-scoped; this hook surfaces
 * whether it belongs to `scanId` and what's running). Also owns the connect/
 * disconnect actions and the running-script count shown in the sidebar's
 * Dynamic section.
 *
 * The poll interval is deliberately short (3s) like the scan-progress poll:
 * dynamic state (connect/disconnect, run/stop) changes on human timescale,
 * and the whole point of the panel is live response.
 */
export interface DynamicSessionState {
  /** The active session row, or null when none is live / it's another scan's. */
  session: DynamicSessionRead | null
  /** True when a session is live AND its scan_id matches the current scan. */
  connected: boolean
  /** How many scripts are currently running (from the live list). */
  runningScripts: number
  /** True while the very first GET is in flight (the panel shows nothing yet). */
  loading: boolean
  /** Transient poll/action error - rendered as a banner, cleared on success. */
  error: string | null
  connect: (payload: {
    platform: string
    device_id: string
    target_app: string
  }) => Promise<void>
  disconnect: () => Promise<void>
  refresh: () => Promise<void>
}

const POLL_MS = 3000

export function useDynamicSession(scanId: number | null): DynamicSessionState {
  const [session, setSession] = useState<DynamicSessionRead | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [runningScripts, setRunningScripts] = useState(0)
  const scanRef = useRef(scanId)

  const fetchSession = useCallback(async () => {
    try {
      const s = await api.dynamicSession()
      setSession(s)
      setError(null)
    } catch {
      // A dead/never-connected backend is the designed no-session state - a
      // poll failure keeps the last state rather than flashing an error
      // every 3s. The connect action surfaces real failures.
    } finally {
      setLoading(false)
    }
  }, [])

  // Poll while a scan is loaded. On scan switch the stale session is cleared
  // immediately (the refetch lands a moment later) so the previous scan's
  // "connected" state can never flash against the new scan.
  useEffect(() => {
    setSession(null)
    setRunningScripts(0)
    setError(null)
    setLoading(true)
    scanRef.current = scanId
    if (scanId == null) {
      setLoading(false)
      return
    }
    let stopped = false
    void fetchSession()
    const t = setInterval(() => {
      if (!stopped) void fetchSession()
    }, POLL_MS)
    return () => {
      stopped = true
      clearInterval(t)
    }
  }, [scanId, fetchSession])

  // The running-script count is part of the sidebar badge. Refresh it when
  // the session identity or the session lifecycle changes (connect/disconnect
  // or a run/stop from the scripts panel bumps this via refresh()).
  const refreshScripts = useCallback(async (s: DynamicSessionRead | null) => {
    if (!s || s.scan_id !== scanRef.current) {
      setRunningScripts(0)
      return
    }
    try {
      const list: DynamicScriptRead[] = await api.dynamicScripts()
      setRunningScripts(list.filter((x) => x.running).length)
    } catch {
      // Non-critical badge; the scripts panel does its own error surfacing.
    }
  }, [])

  useEffect(() => {
    void refreshScripts(session)
  }, [session, refreshScripts])

  const isOwn = session != null && scanId != null && session.scan_id === scanId

  const connect = useCallback(
    async (payload: { platform: string; device_id: string; target_app: string }) => {
      if (scanId == null) return
      setError(null)
      try {
        const s = await api.dynamicConnect({
          scan_id: scanId,
          platform: payload.platform,
          device_id: payload.device_id,
          target_app: payload.target_app,
        })
        setSession(s)
      } catch (err) {
        const msg = err instanceof ApiError ? err.message : String(err)
        setError(msg)
        throw err
      }
    },
    [scanId],
  )

  const disconnect = useCallback(async () => {
    setError(null)
    try {
      const s = await api.dynamicDisconnect()
      setSession(s)
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : String(err)
      setError(msg)
      throw err
    }
  }, [])

  const refresh = useCallback(async () => {
    await fetchSession()
  }, [fetchSession])

  return {
    session,
    connected: isOwn,
    runningScripts,
    loading,
    error,
    connect,
    disconnect,
    refresh,
  }
}
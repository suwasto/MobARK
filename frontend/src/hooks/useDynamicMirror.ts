import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import type { DynamicMirrorState } from '../types'

/**
 * M18: the device mirror (FR-D6/D7/D8). The relay is a WebSocket - the
 * codebase's first - carrying a JSON CONTROL ENVELOPE first (fidelity +
 * codec + latency), then BINARY frames (H.264 NAL for Android's continuous
 * scrcpy relay, JPEG for iOS's polled screenshotr). View-only: the ONLY
 * client message is the latency ping.
 *
 * Rendering honesty (the PRD's `continuous|polled` fidelity surfacing): JPEG
 * frames (polled/iOS) render as `<img>` blob URLs; raw H.264 NAL has no
 * browser decoder, so continuous/android frames surface the live badge +
 * latency + frame count on the mockup's "continuous · view only" phone
 * placeholder instead of pretending to decode them.
 *
 * State + start/stop go over HTTP (`GET/POST /session/mirror`); the WS is
 * strictly the frame pipe. Tolerates a dead/closed socket cleanly - the
 * panel shows the state + Retry, never an unhandled throw.
 */
export interface DynamicMirrorState2 extends DynamicMirrorState {
  /** Latest JPEG frame as an object URL (polled/iOS only; null otherwise). */
  frameUrl: string | null
  /** True while the WS is open and receiving frames. */
  streaming: boolean
}

export interface DynamicMirrorHook {
  mirror: DynamicMirrorState2 | null
  loading: boolean
  error: string | null
  start: () => Promise<void>
  stop: () => Promise<void>
  refresh: () => Promise<void>
}

const POLL_MS = 3000

export function useDynamicMirror(
  scanId: number | null,
  sessionLive: boolean,
): DynamicMirrorHook {
  const [mirror, setMirror] = useState<DynamicMirrorState2 | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const frameUrlRef = useRef<string | null>(null)
  // A dropped WS while the session is still live re-opens after the next
  // poll (the relay is torn down on session end, so a closed socket against
  // a LIVE session is always transient).
  const [reopenTick, setReopenTick] = useState(0)

  const closeWs = useCallback(() => {
    wsRef.current?.close()
    wsRef.current = null
    if (frameUrlRef.current) {
      URL.revokeObjectURL(frameUrlRef.current)
      frameUrlRef.current = null
    }
  }, [])

  const fetchState = useCallback(async (silent = false) => {
    try {
      const s = await api.dynamicMirrorState()
      setMirror((prev) => ({
        ...s,
        frameUrl: prev?.frameUrl ?? null,
        streaming: prev?.streaming ?? false,
      }))
      setError(null)
    } catch (err) {
      if (!silent && err instanceof ApiError && err.status === 404) {
        // No live session - the designed no-mirror state, not an error.
        setMirror(null)
      } else if (!silent) {
        setError(err instanceof Error ? err.message : String(err))
      }
    }
  }, [])

  // Open the WS when a session is live; close + clear on scan/session change.
  useEffect(() => {
    if (scanId == null || !sessionLive) {
      closeWs()
      setMirror(null)
      setLoading(false)
      return
    }
    setLoading(true)
    let cancelled = false
    const ws = new WebSocket(api.dynamicMirrorWsUrl())
    wsRef.current = ws
    ws.binaryType = 'arraybuffer'

    ws.onopen = () => {
      if (cancelled) return
      setError(null)
    }
    ws.onmessage = (ev) => {
      if (cancelled) return
      if (typeof ev.data === 'string') {
        // Control envelope: the FIRST message (mirror stats) + latency pings
        // come back as JSON text; everything after is binary.
        try {
          const stats = JSON.parse(ev.data) as DynamicMirrorState
          setMirror((prev) => ({
            ...stats,
            frameUrl: prev?.frameUrl ?? null,
            streaming: prev?.streaming ?? false,
          }))
        } catch {
          // ignore - a stray text frame shouldn't corrupt state
        }
        return
      }
      // Binary frame. Only JPEG (polled) frames are renderable; continuous
      // H.264 is surfaced via the state (live + latency + frame count).
      const bytes = ev.data as ArrayBuffer
      setMirror((prev) => {
        if (!prev) return prev
        if (prev.polled) {
          const url = frameUrlRef.current
          if (url) URL.revokeObjectURL(url)
          const blob = new Blob([bytes], { type: 'image/jpeg' })
          frameUrlRef.current = URL.createObjectURL(blob)
          return { ...prev, frame_count: prev.frame_count + 1, streaming: true, frameUrl: frameUrlRef.current }
        }
        return { ...prev, frame_count: prev.frame_count + 1, streaming: true }
      })
    }
    ws.onclose = () => {
      if (frameUrlRef.current) {
        URL.revokeObjectURL(frameUrlRef.current)
        frameUrlRef.current = null
      }
      if (!cancelled) {
        setMirror((prev) => (prev ? { ...prev, streaming: false, frameUrl: null } : prev))
      }
    }
    ws.onerror = () => {
      if (!cancelled) {
        setError('Mirror stream failed - is the device connected?')
      }
    }

    // HTTP state refresh keeps latency/subscribers/frame-count current even
    // when the WS is idle; and re-syncs after a start/stop. A WS that closed
    // while the session is still live (transient drop) bumps reopenTick so
    // the effect re-runs and reopens it.
    void fetchState()
    const t = setInterval(() => {
      void fetchState(true)
      if (wsRef.current && wsRef.current.readyState >= WebSocket.CLOSING) {
        setReopenTick((v) => v + 1)
      }
    }, POLL_MS)
    return () => {
      cancelled = true
      closeWs()
      clearInterval(t)
    }
  }, [scanId, sessionLive, fetchState, closeWs, reopenTick])

  // Never leave the panel mounting spinner forever - a session that exists
  // but has no mirror relay yet still resolves to a state quickly.
  useEffect(() => {
    if (mirror != null || error != null) setLoading(false)
  }, [mirror, error])

  const start = useCallback(async () => {
    setError(null)
    try {
      const s = await api.dynamicMirrorStart()
      setMirror((prev) => ({ ...s, frameUrl: prev?.frameUrl ?? null, streaming: prev?.streaming ?? false }))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      throw err
    }
  }, [])

  const stop = useCallback(async () => {
    setError(null)
    try {
      const s = await api.dynamicMirrorStop()
      setMirror((prev) => ({ ...s, frameUrl: prev?.frameUrl ?? null, streaming: prev?.streaming ?? false }))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      throw err
    }
  }, [])

  const refresh = useCallback(async () => {
    await fetchState()
  }, [fetchState])

  return { mirror, loading, error, start, stop, refresh }
}
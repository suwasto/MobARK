import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import { StreamDecoder } from '../lib/sse'
import type { DynamicEvent } from '../types'

/**
 * M18: the FR-D10 live event feed. Opens the SSE stream
 * (`GET /dynamic/session/events/stream`, the chat-streaming pattern) while a
 * session is live, seeds from the HTTP catch-up snapshot on (re)connect, and
 * exposes a bounded local ring (the backend ring is bounded; the client caps
 * the DOM copy too). Also owns the "Add note" observation push (the
 * fake-posture HTTP fallback).
 *
 * The stream lives as long as the session does; the backend ends it cleanly
 * when the session disconnects (swap) or the client goes away.
 */
const MAX_CLIENT_EVENTS = 200

export interface DynamicEventsState {
  events: DynamicEvent[]
  connected: boolean
  error: string | null
  pushNote: (text: string) => Promise<void>
  retry: () => void
}

export function useDynamicEvents(
  scanId: number | null,
  sessionLive: boolean,
  onDisconnect?: () => void,
): DynamicEventsState {
  const [events, setEvents] = useState<DynamicEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  // Guard against the 404 no-session storm: the stream only starts once a
  // session is live, and a mid-flight session death ends it cleanly.
  const activeRef = useRef(false)

  const stop = useCallback(() => {
    activeRef.current = false
    abortRef.current?.abort()
    abortRef.current = null
  }, [])

  const start = useCallback(async () => {
    stop()
    if (scanId == null || !sessionLive) return
    setError(null)
    activeRef.current = true
    setEvents([]) // fresh session - don't carry the previous scan's feed
    // Catch-up snapshot first (the HTTP fallback a reconnect uses).
    try {
      const snap = await api.dynamicEvents()
      if (!activeRef.current) return
      setEvents(snap.slice(-MAX_CLIENT_EVENTS))
      setConnected(true)
    } catch (err) {
      if (!activeRef.current) return
      // 404 = the session died between the poll and here - a clean end.
      if (err instanceof ApiError && err.status === 404) {
        setConnected(false)
        onDisconnect?.()
        return
      }
      setError(err instanceof Error ? err.message : String(err))
      setConnected(false)
      return
    }

    // Live stream. The backend keeps the connection open with `: ping`
    // keepalives; the decoder ignores comments and emits `event: hook`
    // frames with the JSON event in `data:`.
    const controller = new AbortController()
    abortRef.current = controller
    const dec = new StreamDecoder()
    try {
      const res = await fetch(api.dynamicEventsStreamUrl(), {
        signal: controller.signal,
        headers: { Accept: 'text/event-stream' },
      })
      if (!res.ok) {
        throw new ApiError(res.status, res.statusText)
      }
      if (!res.body) throw new Error('No response body in events stream')
      const reader = res.body.getReader()
      const push = (event: DynamicEvent) =>
        setEvents((prev) => [...prev.slice(-(MAX_CLIENT_EVENTS - 1)), event])
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        if (!activeRef.current) break
        const text = new TextDecoder().decode(value)
        for (const ev of dec.push(text)) {
          try {
            push(JSON.parse(ev.data) as DynamicEvent)
          } catch {
            // Non-JSON frame - ignore, never crash the feed.
          }
        }
      }
      if (activeRef.current) onDisconnect?.()
    } catch (err) {
      // Abort = our own stop() (clean teardown). Anything else mid-stream is
      // a lost connection - the backend ends the stream on session death.
      if ((err as { name?: string } | null)?.name === 'AbortError') return
      if (activeRef.current) {
        setConnected(false)
        setError(err instanceof Error ? err.message : String(err))
        onDisconnect?.()
      }
    } finally {
      if (abortRef.current === controller) abortRef.current = null
    }
  }, [scanId, sessionLive, onDisconnect, stop])

  // (Re)start when the session flips live or the scan changes. The stream
  // itself is long-lived; retry() below re-runs the same path.
  useEffect(() => {
    if (scanId == null || !sessionLive) {
      stop()
      setEvents([])
      setConnected(false)
      return
    }
    void start()
    return stop
  }, [scanId, sessionLive, start, stop])

  const pushNote = useCallback(
    async (text: string) => {
      try {
        const ev = await api.dynamicPostEvent({ source: 'note', tag: 'note', text })
        setEvents((prev) => [...prev.slice(-(MAX_CLIENT_EVENTS - 1)), ev])
        setError(null)
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err))
        throw err
      }
    },
    [],
  )

  const retry = useCallback(() => {
    void start()
  }, [start])

  return { events, connected, error, pushNote, retry }
}
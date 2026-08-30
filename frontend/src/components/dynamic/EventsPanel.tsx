import { useEffect, useRef, useState } from 'react'
import type { DynamicEventsState } from '../../hooks/useDynamicEvents'
import type { DynamicEvent } from '../../types'

/**
 * M18: the FR-D10 live hooks & events feed. Reads the SSE stream (see
 * useDynamicEvents) and renders the timestamped, tag-colored rows: hook=steel,
 * bypass=amber, net=moss, note=bone-faint. The "Add note" input is the
 * observation push (the fake-posture HTTP fallback that proves the feed
 * end-to-end). The list auto-scrolls to the newest event.
 */
interface EventsPanelProps {
  events: DynamicEventsState
}

function tagClass(source: string): string {
  switch (source) {
    case 'bypass':
      return 'bypass'
    case 'net':
      return 'net'
    case 'note':
      return 'note'
    default:
      return 'hook'
  }
}

function formatTs(ts: string): string {
  // Server-stamped UTC ISO; render as local HH:MM:SS.
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ts
  return d.toLocaleTimeString([], { hour12: false })
}

function EventRow({ ev }: { ev: DynamicEvent }) {
  return (
    <div className="event-row">
      <span className="event-time">{formatTs(ev.ts)}</span>
      <span className={`event-tag ${tagClass(ev.source)}`}>{ev.source}</span>
      <span className="event-text">
        {ev.text}
        {ev.code ? <span className="event-code">{ev.code}</span> : null}
      </span>
    </div>
  )
}

export function EventsPanel({ events }: EventsPanelProps) {
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const listRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to the newest event - the feed is live.
  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight })
  }, [events.events])

  const submitNote = async () => {
    const text = note.trim()
    if (!text || busy) return
    setBusy(true)
    setErr(null)
    try {
      await events.pushNote(text)
      setNote('')
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="dyn-panel">
      <div className="dyn-panel-head">
        <span>Live hooks &amp; events</span>
        {events.connected ? (
          <span style={{ color: 'var(--color-moss)' }}>● streaming</span>
        ) : (
          <span style={{ color: 'var(--color-bone-faint)' }}>— idle</span>
        )}
      </div>
      <div className="dyn-panel-body" ref={listRef}>
        {events.events.length === 0 && (
          <div className="event-empty">
            No events yet — connect and run a hook script to watch calls live.
          </div>
        )}
        {events.events.map((ev, i) => (
          <EventRow key={`${ev.ts}-${i}`} ev={ev} />
        ))}
      </div>
      {events.error && (
        <div className="dyn-panel-foot-error">
          {events.error}
          <button type="button" className="link-btn" onClick={events.retry}>
            Retry
          </button>
        </div>
      )}
      <div className="dyn-panel-foot">
        <input
          className="field-input flex-1"
          placeholder="Add a note to the feed…"
          value={note}
          disabled={!events.connected || busy}
          onChange={(e) => setNote(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') void submitNote()
          }}
        />
        <button
          type="button"
          className="btn"
          disabled={!events.connected || busy || !note.trim()}
          onClick={() => void submitNote()}
        >
          {busy ? 'Adding…' : 'Add note'}
        </button>
      </div>
      {err && <div className="dyn-panel-foot-error">{err}</div>}
    </div>
  )
}
import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../../api/client'
import type { DynamicTrafficLog, DynamicCaStatus } from '../../types'

/**
 * M18: the network traffic capture panel (FR-D12/D13/D14/D14a). Reads the
 * active session's traffic log (bounded rows + running total + capture flag),
 * Start/Stop the capture, and the FR-D14a CA-trust gate: iOS needs the
 * mitmproxy CA config profile installed (the .mobileconfig download); Android
 * trusts via device settings (no profile step). Flagged rows render the
 * bounded FR-D13 snippets in crimson - never a raw body.
 */
interface TrafficPanelProps {
  scanId: number | null
  sessionLive: boolean
  platform: string
}

const POLL_MS = 2500

export function TrafficPanel({ scanId, sessionLive, platform }: TrafficPanelProps) {
  const [log, setLog] = useState<DynamicTrafficLog | null>(null)
  const [ca, setCa] = useState<DynamicCaStatus | null>(null)
  const [busy, setBusy] = useState<'start' | 'stop' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<number | null>(null)

  const load = useCallback(async () => {
    if (!sessionLive) {
      setLog(null)
      setCa(null)
      return
    }
    try {
      const t = await api.dynamicTraffic()
      setLog(t)
      setError(null)
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setLog(null)
        return
      }
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [sessionLive])

  const loadCa = useCallback(async () => {
    if (!sessionLive) return
    try {
      setCa(await api.dynamicCaStatus())
    } catch {
      // CA status is a per-session nicety; a failure shouldn't block traffic.
    }
  }, [sessionLive])

  // Poll while a session is live (traffic rows land continuously). Reset the
  // stale view immediately on session/scan change.
  useEffect(() => {
    setLog(null)
    setError(null)
    setExpanded(null)
    if (!sessionLive) return
    void load()
    void loadCa()
    const t = setInterval(() => void load(), POLL_MS)
    return () => clearInterval(t)
  }, [scanId, sessionLive, load, loadCa])

  const toggle = async (which: 'start' | 'stop') => {
    setBusy(which)
    setError(null)
    try {
      const t = which === 'start' ? await api.dynamicTrafficStart() : await api.dynamicTrafficStop()
      setLog(t)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const flagsFor = (id: number) => {
    const row = log?.rows.find((r) => r.id === id)
    return row?.flags ?? []
  }

  return (
    <div className="dyn-panel">
      <div className="dyn-panel-head">
        <span>Network traffic{platform === 'ios' ? ' (via pinning bypass)' : ''}</span>
        <span style={{ color: log?.capture_active ? 'var(--color-moss)' : 'var(--color-bone-faint)' }}>
          {log?.capture_active ? `● capturing · ${log.total ?? 0} requests` : `— idle · ${log?.total ?? 0} captured`}
        </span>
      </div>

      <div className="traffic-controls">
        {!log?.capture_active && (
          <button type="button" className="btn btn-primary" disabled={!sessionLive || busy === 'start'} onClick={() => void toggle('start')}>
            {busy === 'start' ? 'Starting…' : 'Start capture'}
          </button>
        )}
        {log?.capture_active && (
          <button type="button" className="btn" disabled={busy === 'stop'} onClick={() => void toggle('stop')}>
            {busy === 'stop' ? 'Stopping…' : 'Stop capture'}
          </button>
        )}
      </div>

      {ca?.required && (
        <div className="ca-row">
          <span>
            CA trust: {ca.trusted ? '✓ profile installed + trusted' : '✗ install the mitmproxy CA config profile'}
          </span>
          {ca.profile_available && (
            <a className="link-btn" href={api.dynamicCaProfileUrl()} download>
              Download .mobileconfig
            </a>
          )}
        </div>
      )}

      <div className="dyn-panel-body">
        {!log || log.rows.length === 0 ? (
          <div className="event-empty">
            No traffic yet — start capture and exercise the app to watch requests.
          </div>
        ) : (
          log.rows.map((row) => {
            const flags = flagsFor(row.id)
            const open = expanded === row.id
            return (
              <div key={row.id} className="traffic-row">
                <div className="traffic-row-line">
                  <span className="traffic-method">{row.method}</span>
                  <span className="traffic-url">{row.path}</span>
                  {row.host ? <span className="traffic-host">{row.host}</span> : null}
                </div>
                <div className="traffic-meta">
                  {row.status != null ? `${row.status} · ` : ''}
                  {row.size_bytes > 0 ? `${row.size_bytes}b · ` : ''}
                  {row.flagged ? (
                    <span className="flag">
                      flagged data detected
                      <button type="button" className="link-btn" onClick={() => setExpanded(open ? null : row.id)}>
                        {open ? 'hide' : 'show'}
                      </button>
                    </span>
                  ) : (
                    'clean'
                  )}
                </div>
                {open && flags.length > 0 && (
                  <div className="traffic-flags">
                    {flags.map((f, i) => (
                      <div key={i} className="traffic-flag">
                        <span className="sev-tag high">{f.category}</span>
                        <span className="traffic-flag-snippet">{f.snippet}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>

      {error && (
        <div className="dyn-panel-foot-error">
          {error}
          <button type="button" className="link-btn" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}
    </div>
  )
}
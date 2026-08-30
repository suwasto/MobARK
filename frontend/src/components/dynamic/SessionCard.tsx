import { useState } from 'react'
import type { DynamicSessionRead } from '../../types'
import type { DynamicSessionState } from '../../hooks/useDynamicSession'

/**
 * M18: the connected device card (FR-D3/D4). Shows the live session's
 * connection type, frida-server version, target PID, root/jailbreak status
 * and the platform indicator, with the Disconnect action. Clean teardown is
 * the backend's job (FR-D4: hooks, scripts, mirror + traffic all torn down);
 * this card just drives it.
 */
interface SessionCardProps {
  session: DynamicSessionRead
  state: DynamicSessionState
}

export function SessionCard({ session, state }: SessionCardProps) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const disconnect = async () => {
    setBusy(true)
    setError(null)
    try {
      await state.disconnect()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const connected = session.state === 'attached'
  const rootVal = session.root_status
  const platformLabel = session.platform === 'ios' ? 'iOS' : 'Android'

  return (
    <div className="device-card">
      <div className="device-card-head">
        <div className={`device-status ${connected ? 'connected' : 'disconnected'}`}>
          <span className="dot" />
          <span>
            {session.device_name ?? session.device_id ?? 'Device'} —{' '}
            {connected ? 'connected' : session.state}
          </span>
        </div>
        <button
          type="button"
          className="btn"
          disabled={busy}
          onClick={() => void disconnect()}
        >
          {busy ? 'Disconnecting…' : 'Disconnect'}
        </button>
      </div>

      {error && (
        <div className="mb-3 rounded-[4px] border border-crimson/30 bg-crimson/10 p-3 font-mono text-[11.5px] leading-relaxed text-bone-dim">
          {error}
        </div>
      )}

      <div className="device-detail-row">
        <span className="ddr-key">Platform</span>
        <span className="ddr-val ok">{platformLabel}</span>
      </div>
      <div className="device-detail-row">
        <span className="ddr-key">Connection</span>
        <span className="ddr-val ok">{session.connection_type ?? '—'}</span>
      </div>
      <div className="device-detail-row">
        <span className="ddr-key">frida-server</span>
        <span className={`ddr-val ${session.frida_version ? 'ok' : ''}`}>
          {session.frida_version ? `✓ running · ${session.frida_version}` : '—'}
        </span>
      </div>
      <div className="device-detail-row">
        <span className="ddr-key">Target process</span>
        <span className="ddr-val">
          {session.target_pid != null ? `PID ${session.target_pid}` : '—'}
        </span>
      </div>
      {session.platform === 'android' ? (
        <div className="device-detail-row">
          <span className="ddr-key">Root status</span>
          <span className={`ddr-val ${rootVal ? 'ok' : ''}`}>
            {rootVal == null ? '—' : rootVal ? '✓ rooted' : 'not rooted'}
          </span>
        </div>
      ) : (
        <div className="device-detail-row">
          <span className="ddr-key">Jailbreak</span>
          <span className="ddr-val">{session.jailbreak_method ?? '—'}</span>
        </div>
      )}
      {session.corellium_enabled && (
        <div className="device-detail-row">
          <span className="ddr-key">Backend</span>
          <span className="ddr-val ok">Corellium virtual device</span>
        </div>
      )}
    </div>
  )
}
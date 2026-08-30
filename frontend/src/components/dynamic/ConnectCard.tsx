import { useEffect, useState } from 'react'
import { api, ApiError } from '../../api/client'
import type { DynamicSessionState } from '../../hooks/useDynamicSession'
import type { DynamicDevice, DynamicPreflight } from '../../types'

/**
 * M18: the "no session / connect" state of the Dynamic Analysis panel
 * (FR-D1/D2/D3). Real preflight flow, not a jump-in: pick a platform
 * (defaults to the scan's) -> scan for devices -> pick a device -> target-app
 * field (prefilled from the scan's package/bundle id, editable) -> check
 * prerequisites (the per-check booleans, never one opaque failure) ->
 * Connect.
 *
 * Every backend failure surfaces as an inline bubble (the per-panel error
 * convention) - a missing adb/frida renders a clean message, never a raw 500.
 */
interface ConnectCardProps {
  scanId: number
  platform: string
  /** The shared session hook - its `connect` action owns the API call so the
   * session state flips in one place. */
  state: DynamicSessionState
}

function PreflightChecks({ preflight }: { preflight: DynamicPreflight }) {
  const entries = Object.entries(preflight.checks)
  return (
    <div className="dyn-connect-checklist">
      {entries.map(([name, ok]) => (
        <div key={name} className="check-row">
          <span>{name.replace(/_/g, ' ')}</span>
          <span className={`check-mark ${ok ? 'pass' : 'fail'}`}>{ok ? '✓ ok' : '✗'}</span>
        </div>
      ))}
    </div>
  )
}

/**
 * M19: the platform's RUNTIME prerequisites surfaced before the connect flow
 * (the PRD: "root/jailbreak requirement surfaced clearly in-app - pre-flight
 * is the first exposure, not the only"). Also carries the dual-use framing
 * consistent with v1's recompile warning.
 */
function PrereqNotice({ platform }: { platform: string }) {
  const isIos = platform === 'ios'
  return (
    <div className="dyn-prereq-box">
      <div className="dyn-prereq-title">Runtime prerequisites</div>
      <ul className="dyn-prereq-list">
        {isIos ? (
          <li>
            <strong>Jailbroken physical iOS device</strong> — jailbreak is a hard
            prerequisite (checkra1n / palera1n / …) with <code>frida-server</code>{' '}
            running over SSH on the device.
          </li>
        ) : (
          <li>
            <strong>Rooted Android device</strong> — or a non-Google-play AVD /
            emulator with <code>frida-server</code> under <code>adb root</code>{' '}
            (no physical root required on the emulator path).
          </li>
        )}
        {isIos && (
          <li>
            No jailbroken device? Configure the opt-in{' '}
            <strong>Corellium</strong> virtual device in Settings → Corellium.
          </li>
        )}
        <li>
          <code>frida-server</code> runs on the target device (never
          containerized); this install reaches it over adb (Android) or SSH
          (iOS).
        </li>
      </ul>
      <div className="dyn-prereq-warn">
        Authorized testing only — pinning/ATS bypass, root/jailbreak-detection
        bypass, and decrypted traffic capture are standard techniques for tests
        you have permission to run.
      </div>
    </div>
  )
}

export function ConnectCard({ scanId, platform, state }: ConnectCardProps) {
  const [devices, setDevices] = useState<DynamicDevice[] | null>(null)
  const [deviceId, setDeviceId] = useState('')
  const [targetApp, setTargetApp] = useState('')
  const [preflight, setPreflight] = useState<DynamicPreflight | null>(null)
  const [busy, setBusy] = useState<'devices' | 'preflight' | 'connect' | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Prefill the target app from the scan's dependencies (package / bundle id)
  // - best-effort, never blocking: a failed fetch leaves the field editable.
  useEffect(() => {
    let stopped = false
    api
      .listDependencies(scanId)
      .then((d) => {
        if (stopped) return
        const app = d.app.package ?? d.app.bundle_id
        if (app) setTargetApp(app)
      })
      .catch(() => {
        // Transient - the field stays empty and the tester types it.
      })
    return () => {
      stopped = true
    }
  }, [scanId])

  const scanDevices = async () => {
    setBusy('devices')
    setError(null)
    setDevices(null)
    setPreflight(null)
    try {
      const list = await api.dynamicDevices(platform)
      setDevices(list)
      if (list.length > 0) setDeviceId(list[0].id)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const checkPreflight = async () => {
    if (!deviceId || !targetApp.trim()) {
      setError('Pick a device and enter the target app to check prerequisites.')
      return
    }
    setBusy('preflight')
    setError(null)
    try {
      const p = await api.dynamicPreflight(platform, deviceId, targetApp.trim())
      setPreflight(p)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const connect = async () => {
    if (!deviceId || !targetApp.trim()) {
      setError('Pick a device and enter the target app to connect.')
      return
    }
    setBusy('connect')
    setError(null)
    try {
      // The shared hook's connect owns the API call + state flip; a failure
      // lands on both the hook's banner and this card's inline bubble.
      await state.connect({ platform, device_id: deviceId, target_app: targetApp.trim() })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const prReady = preflight != null && preflight.ok && deviceId && targetApp.trim()

  return (
    <div className="dyn-connect-card">
      <div className="dyn-connect-icon">📵</div>
      <div className="dyn-connect-title">No active session</div>
      <div className="dyn-connect-sub">
        Connect a rooted Android device / emulator (with <code>frida-server</code>
        running) or a jailbroken iOS device to begin a live dynamic analysis
        session against this app.
      </div>

      <PrereqNotice platform={platform} />

      {error && (
        <div className="mb-4 rounded-[4px] border border-crimson/30 bg-crimson/10 p-3 text-left font-mono text-[11.5px] leading-relaxed text-bone-dim">
          {error}
        </div>
      )}

      <div className="mb-4 flex flex-col gap-3 text-left">
        <div className="field-row" style={{ gap: 8 }}>
          <label className="field-label" style={{ minWidth: 90 }}>
            Target app
          </label>
          <input
            className="field-input flex-1"
            placeholder={platform === 'ios' ? 'com.example.app' : 'com.example.app'}
            value={targetApp}
            onChange={(e) => {
              setTargetApp(e.target.value)
              setPreflight(null)
            }}
            spellCheck={false}
          />
        </div>

        <button
          type="button"
          className="btn btn-primary"
          disabled={busy === 'devices'}
          onClick={() => void scanDevices()}
        >
          {busy === 'devices' ? 'Scanning…' : 'Scan for devices'}
        </button>

        {devices && (
          <div className="field-row" style={{ gap: 8 }}>
            <label className="field-label" style={{ minWidth: 90 }}>
              Device
            </label>
            <select
              className="field-input flex-1"
              value={deviceId}
              disabled={devices.length === 0}
              onChange={(e) => {
                setDeviceId(e.target.value)
                setPreflight(null)
              }}
            >
              {devices.length === 0 && <option value="">No devices found</option>}
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name}
                  {d.detail ? ` · ${d.detail}` : ''}
                </option>
              ))}
            </select>
          </div>
        )}

        {devices && deviceId && (
          <button
            type="button"
            className="btn"
            disabled={busy === 'preflight' || !targetApp.trim()}
            onClick={() => void checkPreflight()}
          >
            {busy === 'preflight' ? 'Checking…' : 'Check prerequisites'}
          </button>
        )}

        {preflight && <PreflightChecks preflight={preflight} />}
      </div>

      <button
        type="button"
        className="btn btn-primary"
        disabled={!prReady || busy === 'connect'}
        title={prReady ? undefined : 'Check prerequisites and ensure they all pass first'}
        onClick={() => void connect()}
      >
        {busy === 'connect' ? 'Connecting…' : 'Connect'}
      </button>
    </div>
  )
}
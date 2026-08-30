import { useState } from 'react'
import type { DynamicMirrorHook } from '../../hooks/useDynamicMirror'

/**
 * M18: the device mirror (FR-D6/D7/D8) - view-only, live. Renders the
 * honest fidelity story: polled/iOS frames come through as JPEG `<img>` blobs;
 * continuous/Android frames are H.264 NAL (no browser decoder for raw NAL), so
 * the mockup's "continuous · view only" phone placeholder carries the live
 * badge + latency + frame count instead of pretending to decode. Start/Stop
 * drive the HTTP control surface; the WS is strictly the frame pipe.
 */
interface MirrorPanelProps {
  mirror: DynamicMirrorHook
}

export function MirrorPanel({ mirror }: MirrorPanelProps) {
  const [busy, setBusy] = useState<'start' | 'stop' | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const m = mirror.mirror
  const live = m?.live && m?.streaming
  const continuous = m?.continuous ?? false
  const renderable = m?.frameUrl != null

  const run = async (which: 'start' | 'stop') => {
    setBusy(which)
    setErr(null)
    try {
      if (which === 'start') await mirror.start()
      else await mirror.stop()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="mirror-frame">
      <div className="mirror-frame-head">
        <span>Device mirror</span>
        {live ? (
          <span className="mirror-live-badge">
            <span className="mirror-live-dot" />
            LIVE
          </span>
        ) : (
          <span style={{ color: 'var(--color-bone-faint)' }}>idle</span>
        )}
      </div>

      <div className="mirror-phone">
        {renderable ? (
          <img
            src={m?.frameUrl ?? undefined}
            alt="Device screen"
            className="mirror-screen-img"
          />
        ) : (
          <div className="mirror-phone-placeholder">
            <div className="mirror-statusbar">
              <span>MobARK</span>
              <span>{continuous ? '●' : '◐'}</span>
            </div>
            <div className="mirror-app-header">{continuous ? 'continuous' : 'polled'}</div>
            <div className="mirror-app-body">
              <div className="mirror-field label">{continuous ? 'scrcpy relay · H.264' : 'screenshotr · JPEG'}</div>
              <div className="mirror-field" />
              <div className="mirror-field" />
              <div className="mirror-field" />
              <div className="mirror-field mirror-btn" />
            </div>
          </div>
        )}
      </div>

      <div className="mirror-frame-foot">
        {continuous ? 'continuous · view only' : 'polled · view only'}
        {m?.latency_ms != null ? ` · ~${m.latency_ms}ms latency` : ''}
        {m?.frame_count != null ? ` · ${m.frame_count} frames` : ''}
      </div>

      <div className="mirror-controls">
        {!m?.live && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy === 'start'}
            onClick={() => void run('start')}
          >
            {busy === 'start' ? 'Starting…' : 'Start mirror'}
          </button>
        )}
        {m?.live && (
          <button
            type="button"
            className="btn"
            disabled={busy === 'stop'}
            onClick={() => void run('stop')}
          >
            {busy === 'stop' ? 'Stopping…' : 'Stop mirror'}
          </button>
        )}
        <span className="mirror-footnote">
          view-only — no input forwarding
        </span>
      </div>

      {err && (
        <div className="mt-3 rounded-[4px] border border-crimson/30 bg-crimson/10 p-3 font-mono text-[11.5px] text-bone-dim">
          {err}
        </div>
      )}
      {mirror.error && !err && (
        <div className="mt-3 rounded-[4px] border border-crimson/30 bg-crimson/10 p-3 font-mono text-[11.5px] text-bone-dim">
          {mirror.error}
        </div>
      )}
    </div>
  )
}
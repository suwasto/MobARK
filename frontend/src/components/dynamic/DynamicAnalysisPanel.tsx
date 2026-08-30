import { useMemo } from 'react'
import { useDynamicEvents } from '../../hooks/useDynamicEvents'
import { useDynamicMirror } from '../../hooks/useDynamicMirror'
import type { DynamicSessionState } from '../../hooks/useDynamicSession'
import type { Platform } from '../../types'
import { ConnectCard } from './ConnectCard'
import { EventsPanel } from './EventsPanel'
import { MirrorPanel } from './MirrorPanel'
import { ScriptsPanel } from './ScriptsPanel'
import { SessionCard } from './SessionCard'
import { TrafficPanel } from './TrafficPanel'

/**
 * M18: the Dynamic Analysis panel (the V2 dashboard contract). Consumes ONE
 * shared dynamic-session hook (the backend holds a single process-local
 * active session) and mounts the sub-panels that use it:
 *
 *   no session   -> ConnectCard (device scan + preflight + connect)
 *   connected    -> SessionCard + MirrorPanel + EventsPanel + TrafficPanel
 *                   + ScriptsPanel, all keyed to the same session
 *
 * Live transport matches the backend (owner decision): SSE for events, WS
 * for mirror frames, HTTP refresh for traffic/scripts. Platform comes from
 * the scan (the connect payload targets the scan's package/bundle).
 */
interface DynamicAnalysisPanelProps {
  scanId: number
  platform: Platform | null
  session: DynamicSessionState
}

export function DynamicAnalysisPanel({ scanId, platform, session: sessionState }: DynamicAnalysisPanelProps) {
  const connected = sessionState.connected
  const sessionLive = connected

  // When the session dies mid-stream (disconnect from this tab or a foreign
  // teardown), the events feed ends and the hook re-derives state from the
  // next poll. The event hook's onDisconnect is a no-op here - the session
  // poll is the source of truth.
  const eventsState = useDynamicEvents(scanId, sessionLive)
  const mirrorState = useDynamicMirror(scanId, sessionLive)

  // Keyed by scan id so a scan switch never leaks the previous scan's feed
  // or mirror; the panels reset themselves on key change.
  const panelKey = useMemo(() => `dyn-${scanId}`, [scanId])

  return (
    <div>
      <div className="dyn-view-header">
        <div className="dyn-view-title">
          Dynamic Analysis <span className="v2-badge">v2</span>
        </div>
      </div>

      {sessionState.error && (
        <div className="mb-4 rounded-[4px] border border-crimson/30 bg-crimson/10 p-3 font-mono text-[11.5px] text-bone-dim">
          {sessionState.error}
        </div>
      )}

      {sessionLive && sessionState.session ? (
        <div key={panelKey}>
          <SessionCard session={sessionState.session} state={sessionState} />

          <div className="dyn-section-row">
            <MirrorPanel mirror={mirrorState} />
            <EventsPanel events={eventsState} />
          </div>

          <div className="dyn-section-row">
            <TrafficPanel scanId={scanId} sessionLive={sessionLive} platform={platform ?? 'android'} />
            <div>
              <ScriptsPanel
                scanId={scanId}
                sessionLive={sessionLive}
                platform={platform ?? 'android'}
                onScriptsChanged={() => void sessionState.refresh()}
              />
            </div>
          </div>
        </div>
      ) : (
        <ConnectCard scanId={scanId} platform={platform ?? 'android'} state={sessionState} />
      )}
    </div>
  )
}
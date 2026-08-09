import { useCallback, useEffect, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { api } from '../../api/client'
import { useFindings } from '../../hooks/useFindings'
import { formatRelative, platformLabel } from '../../lib/format'
import { useApp } from '../../state/AppContext'
import type { ScanRead } from '../../types'
import { Splitter } from '../Splitter'
import { TargetBar } from '../TargetBar'
import { AgentDock } from '../agent/AgentDock'
import { CodeMapsPanel } from '../panels/CodeMapsPanel'
import { DecompilerPanel } from '../panels/DecompilerPanel'
import { FindingsPanel } from '../panels/FindingsPanel'
import { OverviewPanel } from '../panels/OverviewPanel'

type Tab =
  | 'overview'
  | 'findings'
  | 'dependencies'
  | 'decompiler'
  | 'codemaps'
  | 'report'

// Resizable Agent dock (owner follow-up, Aug 9): dragged width persisted per
// browser like the decompiler splitters. The 45vw CSS cap keeps a wide drag
// from swallowing the dashboard on narrow windows. DOCK_MIN is sized so the
// dock header ("Agent · this scan" + 🌐 Web toggle + collapse button) fits
// without the title overlapping the toggle (owner report, Aug 9).
const DOCK_KEY = 'masa.dockW'
const DOCK_DEFAULT = 340
const DOCK_MIN = 320
const DOCK_MAX = 560

/** Live ceiling for the dock — the CSS renders `clamp(320px, dockW, 45vw)`, so
 * mirroring the 45vw cap in JS keeps a drag (and the persisted width) from
 * diverging from what's actually visible on this viewport (review catch,
 * Aug 9). Never below DOCK_MIN: on sub-~711px windows the CSS resolves the
 * clamp to its min, and the state must match. */
function dockLiveCap(): number {
  return Math.max(
    DOCK_MIN,
    Math.min(DOCK_MAX, Math.floor(window.innerWidth * 0.45)),
  )
}

function readDockWidth(): number {
  try {
    const n = Number(localStorage.getItem(DOCK_KEY))
    if (Number.isFinite(n)) return Math.min(dockLiveCap(), Math.max(DOCK_MIN, n))
  } catch {
    // Storage unavailable (private mode) — session default is fine.
  }
  return Math.min(DOCK_DEFAULT, dockLiveCap())
}

interface DashboardViewProps {
  onPickFile: () => void
  uploading: boolean
  /** Render a different scan than the active one — the progress-dialog
   * backdrop shows the last completed scan's dashboard while a new scan
   * runs, and flips to the finished scan automatically when it completes. */
  scanOverride?: ScanRead | null
}

/** Loaded-state dashboard: TargetBar + tabbed main area (Overview live). */
export function DashboardView({ onPickFile, uploading, scanOverride }: DashboardViewProps) {
  const { activeScan } = useApp()
  const [tab, setTab] = useState<Tab>('overview')
  const [dockCollapsed, setDockCollapsed] = useState(false)
  // Dragged dock width — same readWidth/clamp/persist pattern as the
  // decompiler panes, so the splitter behavior is identical everywhere.
  const [dockW, setDockW] = useState(readDockWidth)
  const dockWRef = useRef(dockW)
  const setDockWClamped = (w: number) => {
    const next = Math.min(dockLiveCap(), Math.max(DOCK_MIN, w))
    dockWRef.current = next
    setDockW(next)
  }
  const commitDockW = () => {
    try {
      localStorage.setItem(DOCK_KEY, String(dockWRef.current))
    } catch {
      // ignore
    }
  }
  // Scroll target for tab switches — panels stay mounted (see below) but a
  // reopened tab should start at its top, not wherever the previous tab
  // left off. Refs the shared scroll container on <main>.
  const mainRef = useRef<HTMLElement>(null)
  // Citation-click -> decompiler: agent cites `file:line` paths relative to
  // the platform tree root; the Decompiler tab resolves them against the
  // loaded tree and reports back via onRequestConsumed.
  const [fileRequest, setFileRequest] = useState<{
    file: string
    nonce: number
  } | null>(null)
  // Legacy scans get risk_score backfilled on GET /scans/{id} (security_score
  // derives from it) — fetch the single scan so the gauge is real even for
  // pre-Phase-A rows.
  const [scan, setScan] = useState<ScanRead | null>(null)

  const openInDecompiler = useCallback((file: string) => {
    setFileRequest((prev) => ({ file, nonce: (prev?.nonce ?? 0) + 1 }))
    setTab('decompiler')
  }, [])

  const consumeFileRequest = useCallback(() => setFileRequest(null), [])

  const current = scan ?? scanOverride ?? activeScan

  // Tabs keep their panels mounted (hidden, not unmounted) so switching
  // never refetches the file tree / code graph — see the panels block.
  useEffect(() => {
    mainRef.current?.scrollTo(0, 0)
  }, [tab, current?.id])

  // Keyed on the id (not the object) so the backdrop's scan rows refreshing
  // during background polling never triggers a backfill storm.
  useEffect(() => {
    if (!current) return
    setScan(current)
    void api
      .getScan(current.id)
      .then(setScan)
      .catch(() => {
        // List data is already enough to render; backfill is best-effort.
      })
  }, [current?.id])
  const {
    findings,
    suppressed,
    counts,
    total,
    suppressedCount,
    loading,
    error,
    refetch: refetchFindings,
  } = useFindings(current?.id ?? null)

  // After a suppress/restore the backend recomputes the risk score — refresh
  // both the findings list and the scan row so the gauge stays honest.
  const onFindingsChanged = useCallback(() => {
    refetchFindings()
    const id = current?.id
    if (id != null) {
      void api
        .getScan(id)
        .then(setScan)
        .catch(() => {
          // Gauge refresh is best-effort; the list refetch already happened.
        })
    }
  }, [refetchFindings, current?.id])

  if (!current) return null
  const failed = current.status === 'failed'

  const tabs: { key: Tab; label: string }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'findings', label: `Findings (${total})` },
    { key: 'dependencies', label: 'Dependencies' },
    { key: 'decompiler', label: 'Decompiler' },
    { key: 'codemaps', label: 'Code maps' },
    { key: 'report', label: 'Report' },
  ]

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TargetBar onPickFile={onPickFile} uploading={uploading} scan={current} />

      <div
        className="grid min-h-0 flex-1"
        style={
          {
            gridTemplateColumns: dockCollapsed
              ? 'minmax(0, 1fr) 44px'
              : `minmax(0, 1fr) 6px clamp(${DOCK_MIN}px, ${dockW}px, 45vw)`,
          } as CSSProperties
        }
      >
        <main ref={mainRef} className="min-w-0 overflow-y-auto">
          {/* Header (scrolls away with the content) */}
          <div className="px-7 pt-5">
            <div className="flex items-baseline gap-2.5">
              <h1 className="font-mono text-[17px] font-semibold">
                {current.filename}
              </h1>
              {failed && <span className="status-badge failed">Failed</span>}
            </div>
            <p className="mt-1 text-xs text-bone-faint">
              {current.platform ? `${platformLabel(current.platform)} · ` : ''}
              scanned {formatRelative(current.created_at)} · {total} findings
            </p>
          </div>

          {/* Sticky tab bar — stays put while the panel content scrolls. */}
          <div className="sticky top-0 z-20 bg-graphite px-7 pt-4">
            <div className="tabs">
              {tabs.map((t) => (
                <button
                  key={t.key}
                  type="button"
                  className={`tab ${tab === t.key ? 'active' : ''}`}
                  onClick={() => setTab(t.key)}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          {/* Panels — kept MOUNTED once first visited: visibility is toggled
              instead of unmounting, so reopening a tab is instant and never
              refetches the file tree / code graph (the wait was the remount
              refetch, not the data). Per-scan state still resets when the
              active scan changes (DecompilerPanel keys its fetches on
              scanId; CodeMapsPanel is keyed below). */}
          <div className="px-7 pb-16 pt-6">
            {failed && current.error && (
              <div className="mb-6 rounded-md border border-crimson/30 bg-crimson/10 p-4 font-mono text-[11.5px] leading-relaxed text-bone-dim">
                Scan failed: {current.error}
              </div>
            )}

            <div className={tab !== 'overview' ? 'hidden' : undefined}>
              <OverviewPanel
                scan={current}
                findings={findings}
                counts={counts}
                findingsLoading={loading}
                findingsError={error}
                onOpenFindings={() => setTab('findings')}
              />
            </div>
            <div className={tab !== 'findings' ? 'hidden' : undefined}>
              <FindingsPanel
                scanId={current.id}
                findings={findings}
                suppressed={suppressed}
                counts={counts}
                total={total}
                suppressedCount={suppressedCount}
                loading={loading}
                error={error}
                onChanged={onFindingsChanged}
              />
            </div>
            <div className={tab !== 'dependencies' ? 'hidden' : undefined}>
              <PlaceholderPanel
                title="Dependencies"
                note="Dependency CVE research ships in M7. The tab is shown here as a placeholder only."
              />
            </div>
            <div className={tab !== 'decompiler' ? 'hidden' : undefined}>
              <DecompilerPanel
                scanId={current.id}
                findings={findings}
                findingsLoading={loading}
                requestFile={fileRequest}
                onRequestConsumed={consumeFileRequest}
              />
            </div>
            <div className={tab !== 'codemaps' ? 'hidden' : undefined}>
              {/* Keyed per scan so search/hubs/selection never leak from the
                 previous scan (same remount pattern as AgentDock). */}
              <CodeMapsPanel
                key={current.id}
                scanId={current.id}
                platform={current.platform}
                onOpenFile={openInDecompiler}
              />
            </div>
            <div className={tab !== 'report' ? 'hidden' : undefined}>
              <PlaceholderPanel
                title="Report"
                note="AI-drafted report generation and export ship in M9. The tab is shown here as a placeholder only."
              />
            </div>
          </div>
        </main>

        {!dockCollapsed && (
          <Splitter
            title="Drag to resize the agent dock (double-click to reset)"
            /* The dock is the RIGHT-edge pane, so its divider follows the
               decompiler rail-splitter convention (owner report, Aug 9 —
               "extend and shrink … like in decompiler view"): dragging the
               divider right NARROWS the dock, dragging it left EXTENDS it.
               The old `+ d` grew the dock when the divider was pulled right
               — the opposite of every other divider in the app. */
            onDelta={(d) => setDockWClamped(dockWRef.current - d)}
            onCommit={commitDockW}
            onReset={() => {
              setDockWClamped(DOCK_DEFAULT)
              commitDockW() // a reset should persist too, like a drag
            }}
          />
        )}

        <AgentDock
          key={current.id}
          scan={current}
          greeting={{ total, high: counts.high }}
          collapsed={dockCollapsed}
          onToggleCollapsed={() => setDockCollapsed((c) => !c)}
          onOpenFile={openInDecompiler}
        />
      </div>
    </div>
  )
}

function PlaceholderPanel({ title, note }: { title: string; note: string }) {
  return (
    <div className="rounded-md border border-line-soft bg-panel p-5">
      <div className="mb-1 font-mono text-[11px] uppercase tracking-[0.08em] text-bone-faint">
        {title}
      </div>
      <p className="text-xs leading-relaxed text-bone-dim">{note}</p>
    </div>
  )
}

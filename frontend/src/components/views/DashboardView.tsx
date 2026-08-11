import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { api } from '../../api/client'
import { useFindings } from '../../hooks/useFindings'
import { formatRelative, platformLabel } from '../../lib/format'
import { useApp } from '../../state/AppContext'
import type { EditRead, ScanRead } from '../../types'
import { ProposalsModal } from '../ProposalsModal'
import { Splitter } from '../Splitter'
import { TargetBar } from '../TargetBar'
import { AgentDock } from '../agent/AgentDock'
import { CodeMapsPanel } from '../panels/CodeMapsPanel'
import { DecompilerPanel } from '../panels/DecompilerPanel'
import { DependenciesPanel } from '../panels/DependenciesPanel'
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
  // Dependencies tab -> Agent dock: the per-dependency "Check known CVEs"
  // button pre-fills the dock draft (nonce-guarded so repeat clicks always
  // land) — known-CVE research is the M7 web-research surface, not a column.
  const [dockPreset, setDockPreset] = useState<{
    text: string
    nonce: number
  } | null>(null)
  const askAgent = useCallback((text: string) => {
    setDockPreset((prev) => ({ text, nonce: (prev?.nonce ?? 0) + 1 }))
    // Expand a collapsed dock — a preset landing in a 44px rail would be
    // invisible (review catch, Dependencies tab wiring).
    setDockCollapsed(false)
  }, [])
  // Legacy scans get risk_score backfilled on GET /scans/{id} (security_score
  // derives from it) — fetch the single scan so the gauge is real even for
  // pre-Phase-A rows.
  const [scan, setScan] = useState<ScanRead | null>(null)

  const openInDecompiler = useCallback((file: string) => {
    setFileRequest((prev) => ({ file, nonce: (prev?.nonce ?? 0) + 1 }))
    setTab('decompiler')
  }, [])

  const consumeFileRequest = useCallback(() => setFileRequest(null), [])

  // The scan identity ALWAYS follows the selection (override or active
  // scan) — never the backfill cache. `scan` is keyed to the selection's id,
  // so the moment the selection changes it must not pin the dashboard to the
  // previous scan (reported bug: switching scans did not refresh until a
  // manual reload — the old `scan ?? activeScan` chain kept evaluating to
  // the cached object because current?.id never changed, so the backfill
  // effect never re-ran). The cache only wins while it matches the selection.
  const selected = scanOverride ?? activeScan
  const current = scan?.id === selected?.id ? scan : selected

  // M8 Phase D (moved here Aug 11 — the dock chat is the agent edit surface
  // now): the shared agent-edit-proposal surface. The edits list powers both
  // the dock's "Review edits (n)" pill and the Decompiler toolbar badge; the
  // modal is a single instance rendered at the dashboard level; `editVersion`
  // remounts an open CodeEditor after an Apply/Reject so a manual save never
  // overwrites a just-applied agent edit.
  const [proposalsOpen, setProposalsOpen] = useState(false)
  const closeProposals = useCallback(() => setProposalsOpen(false), [])
  const [edits, setEdits] = useState<EditRead[]>([])
  const [editVersion, setEditVersion] = useState(0)
  // Fetch the per-scan edits list — on scan change AND after every
  // Apply/Reject (the modal's onChanged). Best-effort: a failed fetch keeps
  // the last list; the pill/badge are non-critical and the next refresh
  // retries. The dock's proposal landing also triggers a refresh (see
  // onReviewProposals).
  const refreshEdits = useCallback(async () => {
    if (current?.id == null) return
    try {
      setEdits(await api.listEdits(current.id))
    } catch {
      // Transient — keep the last list.
    }
  }, [current?.id])
  // On scan switch: clear the previous scan's edits so the pill/badge can
  // never show the OLD scan's count against the new scan (the refetch lands
  // a moment later), and close any open review modal — the proposals belong
  // to the previous scan. The dock preset is cleared too: AgentDock is
  // keyed per scan, so a stale preset from scan A would otherwise pre-fill
  // scan B's fresh dock on mount (review catch).
  useEffect(() => {
    setEdits([])
    setProposalsOpen(false)
    setDockPreset(null)
    void refreshEdits()
  }, [current?.id, refreshEdits])
  const proposedCount = useMemo(
    () => edits.filter((e) => e.status === 'proposed').length,
    [edits],
  )
  // Auto-close the review modal once the last proposal is resolved — the
  // apply/reject refresh lands with zero proposed and the empty state would
  // otherwise linger.
  useEffect(() => {
    if (proposalsOpen && proposedCount === 0) setProposalsOpen(false)
  }, [proposalsOpen, proposedCount])
  // Open the review modal AFTER a fresh edits fetch so the just-landed
  // proposal is already listed (the dock calls this the moment a
  // propose_smali_edit step succeeds — the plan's "the returned proposal
  // opens the diff review panel").
  const onReviewProposals = useCallback(() => {
    void refreshEdits().then(() => setProposalsOpen(true))
  }, [refreshEdits])
  // Remount an open editor after an Apply/Reject (passed down to
  // DecompilerPanel as the CodeEditor key).
  const onProposalsChanged = useCallback(() => {
    void refreshEdits()
    setEditVersion((v) => v + 1)
  }, [refreshEdits])

  // Tabs keep their panels mounted (hidden, not unmounted) so switching
  // never refetches the file tree / code graph — see the panels block.
  useEffect(() => {
    mainRef.current?.scrollTo(0, 0)
  }, [tab, current?.id])

  // Keyed on the SELECTION's id (not the object) so the backdrop's scan rows
  // refreshing during background polling never triggers a backfill storm.
  // `setScan(selected)` first: the fresh selection object must land in the
  // cache so `current` re-derives to it — the null-coalescing pin is gone.
  useEffect(() => {
    if (!selected) return
    setScan(selected)
    const id = selected.id
    void api
      .getScan(id)
      .then((fresh) => {
        // Guard the mid-flight race: a quick switch must never land the
        // previous scan's backfill on the new selection.
        setScan((prev) => (prev?.id === id ? fresh : prev))
      })
      .catch(() => {
        // List data is already enough to render; backfill is best-effort.
      })
  }, [selected?.id])

  // Code maps is Android-only: if the active tab is the hidden one (the user
  // switched scans while on Code maps, or the tab was removed), fall back to
  // Overview instead of rendering a blank main area with no active tab.
  useEffect(() => {
    if (tab === 'codemaps' && current?.platform === 'ios') setTab('overview')
  }, [tab, current?.platform])
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
    // Code maps is Android-only in v1 (the graph builds the decompiled Java
    // tree; iOS has no source-like files and the backend 409s non-Android) —
    // hide the tab on iOS scans entirely. The panel stays guarded below.
    ...(current.platform !== 'ios'
      ? [{ key: 'codemaps' as Tab, label: 'Code maps' }]
      : []),
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
              refetch, not the data). Per-scan state resets when the active
              scan changes: DecompilerPanel, CodeMapsPanel and AgentDock are
              all keyed by id below. */}
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
              <DependenciesPanel
                key={current.id}
                scanId={current.id}
                onAskAgent={askAgent}
              />
            </div>
            <div className={tab !== 'decompiler' ? 'hidden' : undefined}>
              {/* Keyed per scan so the M8 per-scan state resets on switch:
                 the ask-agent chat thread (useChat never sees scanId), the
                 Smali decode status, and the edits list all belong to one
                 scan. Stays mounted across TAB switches, so reopening the
                 tab is still instant (the key only changes with the scan). */}
              <DecompilerPanel
                key={current.id}
                scanId={current.id}
                findings={findings}
                findingsLoading={loading}
                requestFile={fileRequest}
                onRequestConsumed={consumeFileRequest}
                proposedCount={proposedCount}
                editVersion={editVersion}
                onOpenProposals={onReviewProposals}
              />
            </div>
            {current.platform !== 'ios' && (
              <div className={tab !== 'codemaps' ? 'hidden' : undefined}>
                {/* Keyed per scan so search/hubs/selection never leak from
                   the previous scan (same remount pattern as AgentDock). */}
                <CodeMapsPanel
                  key={current.id}
                  scanId={current.id}
                  platform={current.platform}
                  onOpenFile={openInDecompiler}
                />
              </div>
            )}
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
          proposedCount={proposedCount}
          onReviewProposals={onReviewProposals}
          presetDraft={dockPreset}
        />
      </div>

      {/* M8 Phase D: the shared agent-edit-proposal review modal — opened by
          the dock's Review pill (and auto-opened when a propose step lands)
          AND the Decompiler toolbar badge. Single instance, one edits list. */}
      {proposalsOpen && (
        <ProposalsModal
          scanId={current.id}
          proposals={edits.filter((e) => e.status === 'proposed')}
          onClose={closeProposals}
          onChanged={onProposalsChanged}
        />
      )}
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

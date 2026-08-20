import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { api } from '../../api/client'
import type { SeverityCounts } from '../../hooks/useFindings'
import { useExplain } from '../../hooks/useExplain'
import { findingLocation } from '../../lib/findings'
import type { FindingRead, Severity } from '../../types'
import { ExplainBox } from '../ExplainBox'

type SeverityFilter = Severity | 'all'

/** What a batch suppress/restore just did - the Undo toast flips it. */
type BatchAction = 'suppressed' | 'restored'

interface UndoToast {
  key: number
  message: string
  findingIds: number[]
  action: BatchAction
  /** Undo in flight (the toast's button shows Undoing…). */
  busy?: boolean
}

interface FindingsPanelProps {
  scanId: number
  /** Non-suppressed findings (the real posture). */
  findings: FindingRead[]
  /** Suppressed (false-positive) findings - shown by the review toggle. */
  suppressed: FindingRead[]
  counts: SeverityCounts
  total: number
  suppressedCount: number
  loading: boolean
  error: string | null
  /** Refetch findings after a suppress/restore (parent owns the hook). */
  onChanged: () => void
  /** Jump the Decompiler tab to this finding's file+line (rail note
   * highlighted). Called by the View code button (Aug 14: the row
   * container itself is no longer clickable). */
  onJumpToCode: (finding: FindingRead) => void
}

const FILTER_ORDER: Severity[] = ['high', 'warning', 'info']

const SEVERITY_CAP: Record<Severity, string> = {
  high: 'High',
  warning: 'Warning',
  info: 'Info',
}

// ---------------------------------------------------------------------------
// Virtual list item types
// ---------------------------------------------------------------------------

interface HeaderItem {
  type: 'header'
  sev: Severity
  count: number
}

interface FindingItem {
  type: 'finding'
  finding: FindingRead
  groupCount: number
}

type VirtualItem = HeaderItem | FindingItem

// Estimated pixel heights for the virtualizer.  Headers are compact;
// findings vary (collapsed ~96px, expanded ~300px) but the virtualizer
// measures actuals after first paint.
const HEADER_H = 48
const FINDING_H = 96

// ---------------------------------------------------------------------------
// FindingRow — memoized to skip re-renders when props haven't changed.
// Expanded state is owned by the parent (FindingsPanel) so it survives
// virtualizer unmount/remount cycles.
// ---------------------------------------------------------------------------

const FindingRow = memo(function FindingRow({
  scanId,
  finding,
  onChanged,
  onJumpToCode,
  groupCount,
  onBatchResult,
  isOpen,
  onToggleOpen,
}: {
  scanId: number
  finding: FindingRead
  onChanged: () => void
  onJumpToCode: (finding: FindingRead) => void
  groupCount: number
  onBatchResult: (action: BatchAction, findingIds: number[]) => void
  isOpen: boolean
  onToggleOpen: (id: number) => void
}) {
  const [busy, setBusy] = useState(false)
  const [batchBusy, setBatchBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const { state: explain, fetchExplain } = useExplain(scanId, finding.id)

  // Fetch lazily the first time the row is expanded; the backend caches, so
  // the row keeps its own state for instant collapse/re-expand.
  useEffect(() => {
    if (isOpen && explain.kind === 'idle') void fetchExplain()
  }, [isOpen, explain.kind, fetchExplain])

  const meta = findingLocation(finding)
  const jumpable = finding.file_path != null && finding.file_path.length > 0

  const toggleSuppressed = async () => {
    if (busy) return
    setBusy(true)
    setActionError(null)
    try {
      if (finding.suppressed) {
        await api.unsuppressFinding(scanId, finding.id)
      } else {
        await api.suppressFinding(scanId, finding.id)
      }
      onChanged()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const toggleBatch = async () => {
    if (batchBusy || busy) return
    setBatchBusy(true)
    setActionError(null)
    try {
      const res = finding.suppressed
        ? await api.unsuppressFindingsByTitle(scanId, finding.title)
        : await api.suppressFindingsByTitle(scanId, finding.title)
      if (res.finding_ids.length > 0) {
        onBatchResult(finding.suppressed ? 'restored' : 'suppressed', res.finding_ids)
      }
      onChanged()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err))
    } finally {
      setBatchBusy(false)
    }
  }

  return (
    <div className={`finding ${isOpen ? 'open' : ''} ${finding.suppressed ? 'suppressed' : ''}`}>
      <div className={`spine ${finding.suppressed ? 'suppressed' : finding.severity}`} />
      <div className="min-w-0 flex-1 px-[18px] py-3.5">
        <div className="block w-full text-left">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-[13.5px] font-semibold leading-snug">
                {finding.title}
              </div>
              <div className="mt-1 font-mono text-[11px] text-bone-faint">
                {meta}
                {finding.category && (
                  <span className="text-bone-faint/70">
                    {' '}
                    · {finding.category}
                  </span>
                )}
                {finding.mastg_test_id && (
                  <span className="text-bone-faint/70">
                    {' '}
                    · {finding.mastg_test_id}
                  </span>
                )}
                {finding.suppressed && (
                  <span className="suppressed-tag"> · suppressed</span>
                )}
              </div>
            </div>
            <span className={`sev-tag ${finding.severity}`}>
              {finding.severity}
            </span>
          </div>
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-4">
          <button
            type="button"
            className="explain-btn"
            aria-expanded={isOpen}
            onClick={() => onToggleOpen(finding.id)}
          >
            <span className="arrow">▸</span> AI explanation
          </button>
          {jumpable && (
            <button
              type="button"
              className="link-btn"
              title="Open this finding's code in the Decompiler"
              onClick={() => onJumpToCode(finding)}
            >
              View code ↗
            </button>
          )}
          {groupCount > 1 && (
            <button
              type="button"
              className="link-btn suppress-btn"
              disabled={busy || batchBusy}
              title={
                finding.suppressed
                  ? `Restore all ${groupCount} suppressed findings with this title`
                  : `Suppress all ${groupCount} findings with this title as false positives - they stop driving the score`
              }
              onClick={() => void toggleBatch()}
            >
              {batchBusy
                ? finding.suppressed
                  ? 'Restoring all…'
                  : 'Suppressing all…'
                : finding.suppressed
                  ? `Restore all (${groupCount})`
                  : `Suppress all (${groupCount})`}
            </button>
          )}
          <button
            type="button"
            className="link-btn suppress-btn"
            disabled={busy || batchBusy}
            title={
              finding.suppressed
                ? 'Restore this finding (it was reviewed out as a false positive)'
                : 'Suppress this finding as a false positive - it stops driving the score'
            }
            onClick={() => void toggleSuppressed()}
          >
            {busy
              ? finding.suppressed
                ? 'Restoring…'
                : 'Suppressing…'
              : finding.suppressed
                ? 'Restore'
                : 'Suppress'}
          </button>
        </div>
        {actionError && (
          <div className="mt-2 font-mono text-[10.5px] text-crimson">
            {actionError}
          </div>
        )}

        {isOpen && (
          <ExplainBox state={explain} onRetry={() => void fetchExplain(true)} />
        )}
      </div>
    </div>
  )
})

/** Findings tab: severity filter chips + virtualized findings list + a review
 * toggle that swaps in suppressed (false-positive) findings for restore. */
export const FindingsPanel = memo(function FindingsPanel({
  scanId,
  findings,
  suppressed,
  counts,
  total,
  suppressedCount,
  loading,
  error,
  onChanged,
  onJumpToCode,
}: FindingsPanelProps) {
  const [filter, setFilter] = useState<SeverityFilter>('all')
  const [review, setReview] = useState(false)
  const [bandBusy, setBandBusy] = useState<Severity | null>(null)
  const [bandError, setBandError] = useState<{ sev: Severity; msg: string } | null>(null)
  const [toast, setToast] = useState<UndoToast | null>(null)
  // Lift expanded-state into the parent so it survives virtualizer unmount
  // (when a row scrolls out of the viewport the virtualizer removes it from
  // the DOM; the next scroll-in recreates it — the Set preserves the open
  // flag across that cycle).
  const [openIds, setOpenIds] = useState<Set<number>>(() => new Set())

  const source = review ? suppressed : findings
  const visible = useMemo(
    () => (filter === 'all' ? source : source.filter((f) => f.severity === filter)),
    [source, filter],
  )

  // --- Undo toast ---
  const showBatchToast = useCallback(
    (action: BatchAction, findingIds: number[], scope: string) => {
      setToast((prev) => ({
        key: (prev?.key ?? 0) + 1,
        message:
          action === 'suppressed'
            ? `Suppressed ${findingIds.length} ${scope}`
            : `Restored ${findingIds.length} ${scope}`,
        findingIds,
        action,
      }))
    },
    [],
  )
  useEffect(() => {
    if (!toast) return
    const t = window.setTimeout(() => setToast(null), 6000)
    return () => window.clearTimeout(t)
  }, [toast?.key])

  const undoToast = async () => {
    if (!toast || toast.busy) return
    setToast((t) => (t ? { ...t, busy: true } : t))
    try {
      if (toast.action === 'suppressed') {
        await api.unsuppressFindingsByIds(scanId, toast.findingIds)
      } else {
        await api.suppressFindingsByIds(scanId, toast.findingIds)
      }
      setToast(null)
      onChanged()
    } catch (err) {
      setToast((t) =>
        t
          ? { ...t, busy: false, message: `Undo failed: ${err instanceof Error ? err.message : String(err)}` }
          : t,
      )
    }
  }

  // --- Severity band bulk toggle ---
  const toggleSeverityBand = async (sev: Severity) => {
    if (bandBusy != null) return
    setBandBusy(sev)
    setBandError(null)
    try {
      const res = review
        ? await api.unsuppressFindingsBySeverity(scanId, sev)
        : await api.suppressFindingsBySeverity(scanId, sev)
      if (res.finding_ids.length > 0) {
        showBatchToast(review ? 'restored' : 'suppressed', res.finding_ids, `${SEVERITY_CAP[sev]} findings`)
      }
      onChanged()
    } catch (err) {
      setBandError({ sev, msg: err instanceof Error ? err.message : String(err) })
    } finally {
      setBandBusy(null)
    }
  }

  // Per-title group sizes — O(n) single pass, used by FindingRow buttons.
  const groupCounts = useMemo(() => {
    const m = new Map<string, number>()
    for (const f of source) m.set(f.title, (m.get(f.title) ?? 0) + 1)
    return m
  }, [source])

  // --- Flatten severity groups into a single virtual list ---
  const flatItems = useMemo(() => {
    const bySev = new Map<Severity, FindingRead[]>()
    for (const f of visible) {
      const sev = (f.severity in SEVERITY_CAP ? f.severity : 'info') as Severity
      const list = bySev.get(sev)
      if (list) list.push(f)
      else bySev.set(sev, [f])
    }
    const items: VirtualItem[] = []
    for (const sev of FILTER_ORDER) {
      const items_in = bySev.get(sev)
      if (!items_in || items_in.length === 0) continue
      items.push({ type: 'header', sev, count: items_in.length })
      for (const f of items_in) {
        items.push({ type: 'finding', finding: f, groupCount: groupCounts.get(f.title) ?? 1 })
      }
    }
    return items
  }, [visible, groupCounts])

  // Stable estimateSize — avoids re-creating on every render.
  const estimateSize = useCallback(
    (i: number) => (flatItems[i]?.type === 'header' ? HEADER_H : FINDING_H),
    [flatItems],
  )

  // --- Virtualizer ---
  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: flatItems.length,
    getScrollElement: () => parentRef.current,
    estimateSize,
    overscan: 3,
  })

  const toggleOpen = useCallback(
    (id: number) => setOpenIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    }),
    [],
  )

  // Stable callback for batch results passed to each row — avoids a new
  // function reference per row per render which would defeat React.memo.
  const handleBatchResult = useCallback(
    (action: BatchAction, ids: number[]) => showBatchToast(action, ids, 'findings'),
    [showBatchToast],
  )

  const chips: { key: SeverityFilter; label: string; count: number }[] = [
    { key: 'all', label: 'All', count: review ? suppressed.length : total },
    ...FILTER_ORDER.map((sev) => ({
      key: sev as SeverityFilter,
      label: SEVERITY_CAP[sev],
      count: counts[sev],
    })),
  ]

  return (
    <div>
      <div className="flex items-center justify-between gap-4">
        <div className="section-label">
          {review
            ? `Suppressed findings (${suppressed.length})`
            : filter === 'all'
              ? `All findings (${visible.length})`
              : `${SEVERITY_CAP[filter]} findings (${visible.length})`}
        </div>
        {suppressedCount > 0 && (
          <button
            type="button"
            className="link-btn"
            onClick={() => {
              setReview((r) => !r)
              setFilter('all')
            }}
          >
            {review
              ? '← Back to active findings'
              : `Review suppressed (${suppressedCount})`}
          </button>
        )}
      </div>

      {/* Severity filter chips */}
      <div className="mb-4 flex flex-wrap gap-2">
        {chips.map((chip) => {
          const active = filter === chip.key
          return (
            <button
              key={chip.key}
              type="button"
              className={`rounded-full border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                active
                  ? 'border-steel bg-steel/10 text-steel'
                  : 'border-line text-bone-faint hover:border-steel-dim hover:text-bone-dim'
              }`}
              onClick={() => setFilter(chip.key)}
            >
              {chip.label}
              <span className={active ? 'text-steel/70' : 'text-bone-faint/70'}>
                {' '}
                ({chip.count})
              </span>
            </button>
          )
        })}
      </div>

      {/* List */}
      {loading && (
        <div className="text-[12px] text-bone-faint">Loading findings…</div>
      )}
      {!loading && error && (
        <div className="rounded border border-crimson/30 bg-crimson/10 p-4 font-mono text-[11.5px] text-bone-dim">
          {error}
        </div>
      )}
      {!loading && !error && visible.length === 0 && (
        <div className="text-[12px] italic text-bone-faint">
          {review
            ? 'Nothing suppressed - every finding is active.'
            : 'No findings match this severity.'}
        </div>
      )}

      {/* Virtualized list */}
      {!loading && !error && visible.length > 0 && (
        <div
          ref={parentRef}
          className="findings-virtual-list"
          style={{ height: 'calc(100vh - 280px)', overflow: 'auto' }}
        >
          <div
            style={{
              height: `${virtualizer.getTotalSize()}px`,
              width: '100%',
              position: 'relative',
            }}
          >
            {virtualizer.getVirtualItems().map((virt) => {
              const item = flatItems[virt.index]
              return (
                <div
                  key={virt.index}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: `${virt.size}px`,
                    transform: `translateY(${virt.start}px)`,
                  }}
                >
                  {item.type === 'header' ? (
                    <div>
                      <div className={`sev-group-head ${item.sev}`}>
                        {SEVERITY_CAP[item.sev]}
                        <span className="sev-group-count">({item.count})</span>
                        <button
                          type="button"
                          className="link-btn suppress-btn sev-band-btn"
                          disabled={bandBusy != null}
                          title={
                            review
                              ? `Restore all ${item.count} suppressed ${SEVERITY_CAP[item.sev]} findings - they drive the score again`
                              : `Suppress all ${item.count} ${SEVERITY_CAP[item.sev]} findings as false positives - they stop driving the score`
                          }
                          onClick={() => void toggleSeverityBand(item.sev)}
                        >
                          {bandBusy === item.sev
                            ? review
                              ? 'Restoring…'
                              : 'Suppressing…'
                            : review
                              ? `Restore all (${item.count})`
                              : `Suppress all (${item.count})`}
                        </button>
                      </div>
                      {bandError?.sev === item.sev && (
                        <div className="mb-3 font-mono text-[10.5px] text-crimson">
                          {bandError.msg}
                        </div>
                      )}
                    </div>
                  ) : (
                    <FindingRow
                      scanId={scanId}
                      finding={item.finding}
                      onChanged={onChanged}
                      onJumpToCode={onJumpToCode}
                      groupCount={item.groupCount}
                      onBatchResult={handleBatchResult}
                      isOpen={openIds.has(item.finding.id)}
                      onToggleOpen={toggleOpen}
                    />
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Undo toast after a band / group batch toggle */}
      {toast && (
        <div className="undo-toast" role="status">
          <span className="undo-toast-msg">{toast.message}</span>
          <button
            type="button"
            className="link-btn undo-toast-btn"
            disabled={toast.busy}
            onClick={() => void undoToast()}
          >
            {toast.busy ? 'Undoing…' : 'Undo'}
          </button>
          <button
            type="button"
            className="undo-toast-x"
            aria-label="Dismiss"
            onClick={() => setToast(null)}
          >
            ×
          </button>
        </div>
      )}
    </div>
  )
})

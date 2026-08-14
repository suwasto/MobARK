import { useCallback, useEffect, useMemo, useState } from 'react'
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

const FILTER_ORDER: Severity[] = ['high', 'medium', 'low', 'info']

const SEVERITY_CAP: Record<Severity, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

/** One finding row: severity spine + title/meta + expandable AI explanation
 * + suppress/restore + jump-to-code + batch actions. */
function FindingRow({
  scanId,
  finding,
  onChanged,
  onJumpToCode,
  groupCount,
  onBatchResult,
}: {
  scanId: number
  finding: FindingRead
  onChanged: () => void
  onJumpToCode: (finding: FindingRead) => void
  /** How many rows in the CURRENT list share this finding's title (active
   * list -> the suppress-all size; review list -> restore-all). */
  groupCount: number
  /** A batch (title-group) toggle succeeded - the panel shows the Undo
   * toast with the exact finding ids it toggled. */
  onBatchResult: (action: BatchAction, findingIds: number[]) => void
}) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [batchBusy, setBatchBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const { state: explain, fetchExplain } = useExplain(scanId, finding.id)

  // Fetch lazily the first time the row is expanded; the backend caches, so
  // the row keeps its own state for instant collapse/re-expand.
  useEffect(() => {
    if (open && explain.kind === 'idle') void fetchExplain()
  }, [open, explain.kind, fetchExplain])

  const meta = findingLocation(finding)
  // Aug 14 owner follow-up: the finding CONTAINER is not clickable - the
  // dedicated "View code" button jumps to the code and the "▸ AI
  // explanation" button expands the explanation. A clickable title was
  // redundant (and confusing - two affordances for the same jump).
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
      // Never leave a silent failure - the row shows why the toggle didn't
      // apply (network down, backend error, scan no longer analyzed).
      setActionError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  // Batch toggle: suppress/restore every finding with this title at once
  // (e.g. dozens of "up-to-date OS version" rows). Shown only when the group
  // has more than this row - a lone finding would duplicate its own
  // Suppress/Restore button. Risk is recomputed once server-side.
  const toggleBatch = async () => {
    if (batchBusy || busy) return
    setBatchBusy(true)
    setActionError(null)
    try {
      // Title-only match (no category): the button label counts the WHOLE
      // title group in the current list, so the batch must cover the same
      // set - a category narrowing could suppress fewer than the label says.
      const res = finding.suppressed
        ? await api.unsuppressFindingsByTitle(scanId, finding.title)
        : await api.suppressFindingsByTitle(scanId, finding.title)
      // Only toast when something actually toggled (a no-op batch - e.g. the
      // group was already cleared from another row - gets no Undo offer).
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
    <div className={`finding ${open ? 'open' : ''} ${finding.suppressed ? 'suppressed' : ''}`}>
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
            aria-expanded={open}
            onClick={() => setOpen((o) => !o)}
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

        {open && (
          // Regenerate explicitly bypasses the server cache (costs one
          // generation); the row's first expand stays cache-first.
          <ExplainBox state={explain} onRetry={() => void fetchExplain(true)} />
        )}
      </div>
    </div>
  )
}

/** Findings tab: severity filter chips + full findings list + a review
 * toggle that swaps in suppressed (false-positive) findings for restore. */
export function FindingsPanel({
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
  // Group-header bulk toggle: which severity band is mid-toggle + the last
  // failure (band-scoped so one error can't obscure the whole list).
  const [bandBusy, setBandBusy] = useState<Severity | null>(null)
  const [bandError, setBandError] = useState<{ sev: Severity; msg: string } | null>(null)
  // The Undo toast after a band / title-group batch toggle. ``findingIds``
  // are EXACTLY the rows this call flipped (server returns them), so Undo
  // restores precisely - never touching earlier, separately-suppressed rows.
  const [toast, setToast] = useState<UndoToast | null>(null)

  const source = review ? suppressed : findings
  const visible = useMemo(
    () =>
      filter === 'all' ? source : source.filter((f) => f.severity === filter),
    [source, filter],
  )

  // Show the Undo toast for a finished batch toggle (band or title group).
  // Auto-dismisses after a few seconds - the key drives the timer, so an
  // Undo failure message (same key) doesn't reset it.
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
      // Undo flips the action: a suppress's undo restores, a restore's undo
      // suppresses - both by the exact ids the original call returned.
      if (toast.action === 'suppressed') {
        await api.unsuppressFindingsByIds(scanId, toast.findingIds)
      } else {
        await api.suppressFindingsByIds(scanId, toast.findingIds)
      }
      setToast(null)
      onChanged()
    } catch (err) {
      // Keep the toast so the user sees the failure and can retry - it still
      // auto-dismisses on the original timer.
      setToast((t) =>
        t
          ? { ...t, busy: false, message: `Undo failed: ${err instanceof Error ? err.message : String(err)}` }
          : t,
      )
    }
  }

  // Group header "Suppress all (n)" / "Restore all (n)": bulk-clear the
  // whole severity band in one call (risk recomputed once server-side). The
  // header count equals the band size in the CURRENT list (active or
  // review), and the severity-only match toggles exactly that set.
  const toggleSeverityBand = async (sev: Severity) => {
    if (bandBusy != null) return
    setBandBusy(sev)
    setBandError(null)
    try {
      const res = review
        ? await api.unsuppressFindingsBySeverity(scanId, sev)
        : await api.suppressFindingsBySeverity(scanId, sev)
      if (res.finding_ids.length > 0) {
        showBatchToast(
          review ? 'restored' : 'suppressed',
          res.finding_ids,
          `${SEVERITY_CAP[sev]} findings`,
        )
      }
      onChanged()
    } catch (err) {
      setBandError({ sev, msg: err instanceof Error ? err.message : String(err) })
    } finally {
      setBandBusy(null)
    }
  }
  // Per-title group sizes over the CURRENT list (active or review) - powers
  // the per-row "Suppress all (n)" / "Restore all (n)" batch action. One
  // pass instead of a per-row filter over a 1000-row scan.
  const groupCounts = useMemo(() => {
    const m = new Map<string, number>()
    for (const f of source) m.set(f.title, (m.get(f.title) ?? 0) + 1)
    return m
  }, [source])

  // Findings grouped by severity (mirroring the report body's structure -
  // ``### High (7)`` etc.): the 'all' view renders one section per severity
  // with a colored header instead of one flat list.
  const groups = useMemo(() => {
    const grouped: { sev: Severity; items: FindingRead[] }[] = []
    const bySev = new Map<Severity, FindingRead[]>()
    for (const f of visible) {
      const sev = (f.severity in SEVERITY_CAP ? f.severity : 'info') as Severity
      const list = bySev.get(sev)
      if (list) list.push(f)
      else bySev.set(sev, [f])
    }
    for (const sev of FILTER_ORDER) {
      const items = bySev.get(sev)
      if (items && items.length) grouped.push({ sev, items })
    }
    return grouped
  }, [visible])

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
      {!loading &&
        !error &&
        groups.map(({ sev, items }) => (
          <div key={sev} className="mb-5">
            {/* Severity group header - colored like the report's h3 (the
                same conventional palette as the sev-tag chips), with the
                bulk band action on the right. */}
            <div className={`sev-group-head ${sev}`}>
              {SEVERITY_CAP[sev]}
              <span className="sev-group-count">({items.length})</span>
              <button
                type="button"
                className="link-btn suppress-btn sev-band-btn"
                disabled={bandBusy != null}
                title={
                  review
                    ? `Restore all ${items.length} suppressed ${SEVERITY_CAP[sev]} findings - they drive the score again`
                    : `Suppress all ${items.length} ${SEVERITY_CAP[sev]} findings as false positives - they stop driving the score`
                }
                onClick={() => void toggleSeverityBand(sev)}
              >
                {bandBusy === sev
                  ? review
                    ? 'Restoring…'
                    : 'Suppressing…'
                  : review
                    ? `Restore all (${items.length})`
                    : `Suppress all (${items.length})`}
              </button>
            </div>
            {bandError?.sev === sev && (
              <div className="mb-3 font-mono text-[10.5px] text-crimson">
                {bandError.msg}
              </div>
            )}
            {items.map((f) => (
              <FindingRow
                key={f.id}
                scanId={scanId}
                finding={f}
                onChanged={onChanged}
                onJumpToCode={onJumpToCode}
                groupCount={groupCounts.get(f.title) ?? 1}
                onBatchResult={(action, ids) =>
                  showBatchToast(action, ids, 'findings')
                }
              />
            ))}
          </div>
        ))}

      {/* Undo toast after a band / group batch toggle - fixed bottom-center
          so it survives the list refetch (the panel stays mounted). */}
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
}

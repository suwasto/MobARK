import { useEffect, useMemo, useState } from 'react'
import { api } from '../../api/client'
import type { SeverityCounts } from '../../hooks/useFindings'
import { useExplain } from '../../hooks/useExplain'
import { findingLocation } from '../../lib/findings'
import type { FindingRead, Severity } from '../../types'
import { ExplainBox } from '../ExplainBox'

type SeverityFilter = Severity | 'all'

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
}

const FILTER_ORDER: Severity[] = ['high', 'medium', 'low', 'info']

const SEVERITY_CAP: Record<Severity, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

/** One finding row: severity spine + title/meta + expandable AI explanation
 * + suppress/restore action. */
function FindingRow({
  scanId,
  finding,
  onChanged,
}: {
  scanId: number
  finding: FindingRead
  onChanged: () => void
}) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const { state: explain, fetchExplain } = useExplain(scanId, finding.id)

  // Fetch lazily the first time the row is expanded; the backend caches, so
  // the row keeps its own state for instant collapse/re-expand.
  useEffect(() => {
    if (open && explain.kind === 'idle') void fetchExplain()
  }, [open, explain.kind, fetchExplain])

  const meta = findingLocation(finding)

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

  return (
    <div className={`finding ${open ? 'open' : ''} ${finding.suppressed ? 'suppressed' : ''}`}>
      <div className={`spine ${finding.suppressed ? 'suppressed' : finding.severity}`} />
      <div className="min-w-0 flex-1 px-[18px] py-3.5">
        <button
          type="button"
          className="block w-full text-left"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
        >
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
        </button>

        <div className="mt-2 flex items-center gap-4">
          <button
            type="button"
            className="explain-btn"
            aria-expanded={open}
            onClick={() => setOpen((o) => !o)}
          >
            <span className="arrow">▸</span> AI explanation
          </button>
          <button
            type="button"
            className="link-btn suppress-btn"
            disabled={busy}
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
}: FindingsPanelProps) {
  const [filter, setFilter] = useState<SeverityFilter>('all')
  const [review, setReview] = useState(false)

  const source = review ? suppressed : findings
  const visible = useMemo(
    () =>
      filter === 'all' ? source : source.filter((f) => f.severity === filter),
    [source, filter],
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
      {!loading &&
        !error &&
        visible.map((f) => (
          <FindingRow
            key={f.id}
            scanId={scanId}
            finding={f}
            onChanged={onChanged}
          />
        ))}
    </div>
  )
}

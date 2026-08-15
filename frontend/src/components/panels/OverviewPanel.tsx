import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, ApiError } from '../../api/client'
import type { SeverityCounts } from '../../hooks/useFindings'
import { findingLocation } from '../../lib/findings'
import { formatRelative } from '../../lib/format'
import type { FindingRead, ScanRead, SummaryResponse } from '../../types'
import { Markdown } from '../Markdown'
import { SecurityGauge } from '../SecurityGauge'

interface OverviewPanelProps {
  scan: ScanRead
  findings: FindingRead[]
  counts: SeverityCounts
  findingsLoading: boolean
  findingsError: string | null
  onOpenFindings: () => void
}

type SummaryState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'ok'; data: SummaryResponse }
  | { kind: 'no-model' }
  | { kind: 'error'; message: string }

function StatBox({ n, label, cls }: { n: number; label: string; cls: string }) {
  return (
    // Stretches to fill the gauge card's height (the row's tallest cell) so
    // the stat column stays full even without the suppressed-count pill.
    <div className="flex flex-col justify-center rounded-[5px] border border-line bg-panel px-4 py-3.5">
      <div className={`font-mono text-[22px] font-semibold leading-none ${cls}`}>
        {n}
      </div>
      <div className="mt-1.5 text-[11px] uppercase tracking-[0.05em] text-bone-faint">
        {label}
      </div>
    </div>
  )
}

/** Overview tab: risk gauge + severity counts + AI summary + top findings. */
export function OverviewPanel({
  scan,
  findings,
  counts,
  findingsLoading,
  findingsError,
  onOpenFindings,
}: OverviewPanelProps) {
  // ---- AI summary (POST /scans/{id}/summary, cached backend-side) ----
  // Cached in scans.ai_summary: the auto-fetch on mount hits the cache (no
  // LLM cost); `regenerate` is the explicit Regenerate-button opt-in that
  // bypasses it. No model configured → 400 → a quiet "connect a model" state,
  // not an error.
  const [summary, setSummary] = useState<SummaryState>({ kind: 'idle' })
  const requestIdRef = useRef(0)

  const fetchSummary = useCallback(
    (regenerate = false) => {
      const id = ++requestIdRef.current
      setSummary({ kind: 'loading' })
      api
        .scanSummary(scan.id, regenerate)
        .then((data) => {
          if (requestIdRef.current === id) setSummary({ kind: 'ok', data })
        })
        .catch((err: unknown) => {
          if (requestIdRef.current !== id) return
          if (err instanceof ApiError && err.status === 400) {
            setSummary({ kind: 'no-model' })
          } else {
            setSummary({
              kind: 'error',
              message: err instanceof Error ? err.message : String(err),
            })
          }
        })
    },
    [scan.id],
  )

  useEffect(() => {
    void fetchSummary()
  }, [fetchSummary])

  const top = useMemo(
    () => findings.filter((f) => f.severity !== 'info').slice(0, 5),
    [findings],
  )

  return (
    <div>
      {/* Security gauge (higher = better) + severity stat boxes */}
      <div className="mb-7 grid grid-cols-[220px_1fr] gap-6">
        <div className="flex flex-col items-center rounded-[5px] border border-line bg-panel p-5">
          <SecurityGauge score={scan.security_score} />
        </div>
        <div className="grid h-full grid-cols-3 gap-3.5">
          <StatBox n={counts.high} label="High" cls="text-sev-red" />
          <StatBox n={counts.warning} label="Warning" cls="text-amber" />
          <StatBox n={counts.info} label="Info" cls="text-sev-slate" />
        </div>
      </div>

      {/* AI summary */}
      <div className="section-label">AI summary</div>
      {summary.kind === 'loading' && (
        <div className="mb-6 flex items-center gap-2 rounded border border-line-soft bg-panel-raised p-4 font-mono text-[10px] uppercase tracking-[0.06em] text-steel">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-steel" />
          Generating AI summary…
        </div>
      )}
      {summary.kind === 'ok' && (
        <div className="ai-explain mt-0 mb-6">
          <div className="ai-tag">
            Agent{summary.data.model ? ` · ${summary.data.model}` : ''}
          </div>
          <Markdown text={summary.data.summary} />
          <div className="mt-3 flex items-center justify-between gap-3 border-t border-line-soft pt-2.5">
            <span className="font-mono text-[10px] text-bone-faint">
              {summary.data.cached ? 'cached · ' : ''}
              {summary.data.generated_at
                ? `generated ${formatRelative(summary.data.generated_at)}`
                : 'generated on demand'}
            </span>
            <button
              type="button"
              className="link-btn"
              title="Re-run the model - bypasses the cached summary (costs one generation)"
              onClick={() => void fetchSummary(true)}
            >
              Regenerate
            </button>
          </div>
        </div>
      )}
      {summary.kind === 'no-model' && (
        <div className="mb-6 flex items-start justify-between gap-4 rounded border border-dashed border-line bg-panel p-4 text-[12.5px] leading-relaxed text-bone-dim">
          <p>
            No model connected yet - pick a backend and model in Settings
            (top-right ⚙) and the AI overview will appear here. Everything else
            on this page is fully local.
          </p>
          <button
            type="button"
            className="link-btn shrink-0"
            onClick={() => void fetchSummary()}
          >
            Retry
          </button>
        </div>
      )}
      {summary.kind === 'error' && (
        <div className="mb-6 flex items-start justify-between gap-4 rounded border border-crimson/30 bg-crimson/10 p-4 text-[12.5px] leading-relaxed text-bone-dim">
          <p className="font-mono text-[11.5px]">{summary.message}</p>
          <button
            type="button"
            className="link-btn shrink-0"
            onClick={() => void fetchSummary()}
          >
            Retry
          </button>
        </div>
      )}

      {/* Top findings */}
      <div className="section-label">Top findings</div>
      {findingsLoading && (
        <div className="mb-6 text-[12px] text-bone-faint">Loading findings…</div>
      )}
      {!findingsLoading && findingsError && (
        <div className="mb-6 rounded border border-crimson/30 bg-crimson/10 p-4 font-mono text-[11.5px] text-bone-dim">
          {findingsError}
        </div>
      )}
      {!findingsLoading && !findingsError && top.length === 0 && (
        <div className="mb-6 text-[12px] italic text-bone-faint">
          No findings above info level.
        </div>
      )}
      {!findingsLoading &&
        !findingsError &&
        top.map((f) => (
          <div key={f.id} className="finding">
            <div className={`spine ${f.severity}`} />
            <div className="min-w-0 flex-1 px-[18px] py-3.5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-[13.5px] font-semibold leading-snug">
                    {f.title}
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-bone-faint">
                    {findingLocation(f)}
                    {f.category && (
                      <span className="text-bone-faint/70"> · {f.category}</span>
                    )}
                  </div>
                </div>
                <span className={`sev-tag ${f.severity}`}>{f.severity}</span>
              </div>
            </div>
          </div>
        ))}
      {!findingsLoading && !findingsError && top.length > 0 && (
        <button
          type="button"
          className="link-btn mt-1"
          onClick={onOpenFindings}
        >
          View all findings →
        </button>
      )}
    </div>
  )
}

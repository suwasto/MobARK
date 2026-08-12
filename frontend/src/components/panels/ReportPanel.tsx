import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../../api/client'
import { formatRelative } from '../../lib/format'

interface ReportPanelProps {
  scanId: number
  /** True while the Report tab is the visible tab (the panels stay MOUNTED
   *  once visited, so the body is re-fetched on later activations - a
   *  suppress/restore on another tab invalidates the server-side cache
   *  identity, M9 decision 7, and must not leave the stale document up). */
  active: boolean
}

type BodyState =
  | { kind: 'loading' }
  | { kind: 'ok'; markdown: string; generatedAt: string }
  | { kind: 'error'; message: string }

type RegenState =
  | { kind: 'idle' }
  | { kind: 'running' }
  | { kind: 'done'; note: string }
  | { kind: 'no-model' }
  | { kind: 'error'; message: string }

/**
 * M9 Report tab: the assembled report body (deterministic assembly + cached
 * AI commentary - decision 2) with a LIVE PDF PREVIEW (owner follow-up: the
 * tab used to render markdown; it now embeds the branded PDF itself via the
 * inline-disposition export route), plus the export surface.
 *
 * The body NEVER 400s on a missing model (decision 10) - the AI sections
 * render their cached rows or the explicit no-AI note inside the document;
 * only the Regenerate POST is an AI route (400 no-model → an inline note
 * near the button, mirroring the Overview summary's quiet state). Export is
 * a same-origin anchor download (`{stem}-report.md|pdf` attachments).
 */
export function ReportPanel({ scanId, active }: ReportPanelProps) {
  // ---- body (cache-first server-side) ----
  const [body, setBody] = useState<BodyState>({ kind: 'loading' })
  const requestIdRef = useRef(0)
  // The PDF iframe (src = inline export) is remounted/refetched whenever
  // the body is re-fetched - Regenerate and tab re-activation change the
  // server cache identity and must not leave a stale document up.
  const [pdfNonce, setPdfNonce] = useState(0)
  const [pdfLoaded, setPdfLoaded] = useState(false)

  const fetchReport = useCallback(() => {
    const id = ++requestIdRef.current
    setBody({ kind: 'loading' })
    setPdfLoaded(false)
    setPdfNonce((n) => n + 1)
    api
      .getReport(scanId)
      .then((data) => {
        if (requestIdRef.current === id) {
          setBody({ kind: 'ok', markdown: data.markdown, generatedAt: data.generated_at })
        }
      })
      .catch((err: unknown) => {
        if (requestIdRef.current !== id) return
        setBody({
          kind: 'error',
          message: err instanceof Error ? err.message : String(err),
        })
      })
  }, [scanId])

  useEffect(() => {
    void fetchReport()
  }, [fetchReport])

  // The first activation needs no re-fetch (the mount effect above ran);
  // LATER activations re-fetch so findings changes on other tabs (which
  // invalidate the server cache identity) show up without a scan remount.
  const activatedRef = useRef(false)
  useEffect(() => {
    if (active) {
      if (activatedRef.current) void fetchReport()
      activatedRef.current = true
    }
  }, [active, fetchReport])

  // ---- regenerate (explicit cost-spending opt-in, decision 7) ----
  const [regen, setRegen] = useState<RegenState>({ kind: 'idle' })

  const regenerate = useCallback(async () => {
    setRegen({ kind: 'running' })
    try {
      const res = await api.regenerateReport(scanId)
      const note =
        res.explanations_generated > 0
          ? `Summary regenerated · ${res.explanations_generated} missing explanation${
              res.explanations_generated === 1 ? '' : 's'
            } filled`
          : 'Summary regenerated (explanations were already cached)'
      setRegen({ kind: 'done', note })
      // The body's cache identity changed (ai_summary + explanations) -
      // refetch so the document shows the fresh commentary.
      void fetchReport()
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) {
        setRegen({ kind: 'no-model' })
      } else {
        setRegen({
          kind: 'error',
          message: err instanceof Error ? err.message : String(err),
        })
      }
    }
  }, [scanId, fetchReport])

  return (
    <div>
      <div className="section-label">Report</div>

      {/* Toolbar: export + the explicit Regenerate opt-in */}
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-[560px] text-[11.5px] leading-relaxed text-bone-faint">
          Assembled from the scan's persisted findings and the cached AI
          commentary. Export as Markdown or the branded PDF; Regenerate
          re-runs the executive summary and fills missing per-finding
          explanations (spends model tokens).
        </p>
        <div className="flex shrink-0 items-center gap-2">
          <a
            className="btn"
            href={api.reportExportUrl(scanId, 'md')}
            download
            title="Download the assembled body as Markdown"
          >
            Export .md
          </a>
          <a
            className="btn"
            href={api.reportExportUrl(scanId, 'pdf')}
            download
            title="Download the branded PDF report"
          >
            Export PDF
          </a>
          <button
            type="button"
            className="btn btn-primary"
            disabled={regen.kind === 'running'}
            title="Re-run the AI surfaces - bypasses the cached summary and fills missing explanations (explicit cost opt-in)"
            onClick={() => void regenerate()}
          >
            {regen.kind === 'running' ? 'Regenerating…' : 'Regenerate'}
          </button>
        </div>
      </div>

      {/* Regenerate status line */}
      {regen.kind === 'running' && (
        <div className="mb-3 flex items-center gap-2 rounded border border-line-soft bg-panel-raised px-3 py-2 font-mono text-[10.5px] uppercase tracking-[0.06em] text-steel">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-steel" />
          Regenerating summary…
        </div>
      )}
      {regen.kind === 'done' && (
        <div className="mb-3 rounded border border-moss/30 bg-moss/10 px-3 py-2 font-mono text-[11px] text-moss">
          {regen.note}
        </div>
      )}
      {regen.kind === 'no-model' && (
        <div className="mb-3 rounded border border-dashed border-line bg-panel px-3 py-2 text-[12px] leading-relaxed text-bone-dim">
          No chat model connected - pick a backend and model in Settings (top
          right ⚙) to regenerate the AI summary. The report body is fully
          local and renders regardless.
        </div>
      )}
      {regen.kind === 'error' && (
        <div className="mb-3 flex items-start justify-between gap-3 rounded border border-crimson/30 bg-crimson/10 px-3 py-2">
          <p className="font-mono text-[11px] text-bone-dim">{regen.message}</p>
          <button type="button" className="link-btn shrink-0" onClick={() => void regenerate()}>
            Retry
          </button>
        </div>
      )}

      {/* The document: the branded PDF itself, embedded inline */}
      {body.kind === 'loading' && (
        <div className="flex items-center gap-2 rounded border border-line-soft bg-panel-raised p-4 font-mono text-[10px] uppercase tracking-[0.06em] text-steel">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-steel" />
          Assembling report…
        </div>
      )}
      {body.kind === 'error' && (
        <div className="flex items-start justify-between gap-4 rounded border border-crimson/30 bg-crimson/10 p-4">
          <p className="font-mono text-[11.5px] leading-relaxed text-bone-dim">
            {body.message}
          </p>
          <button type="button" className="link-btn shrink-0" onClick={() => void fetchReport()}>
            Retry
          </button>
        </div>
      )}
      {body.kind === 'ok' && (
        <div className="report-preview">
          <iframe
            key={pdfNonce}
            className="report-pdf-frame"
            src={api.reportPdfUrl(scanId, pdfNonce)}
            title="Report PDF preview"
            onLoad={() => setPdfLoaded(true)}
          />
          {!pdfLoaded && (
            <div className="report-pdf-loading">
              <span className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.06em] text-bone-faint">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-steel" />
                Rendering PDF…
              </span>
            </div>
          )}
          <div className="mt-3 border-t border-line-soft pt-2.5 font-mono text-[10px] text-bone-faint">
            Assembled {formatRelative(body.generatedAt)} · MASA security report
          </div>
        </div>
      )}
    </div>
  )
}

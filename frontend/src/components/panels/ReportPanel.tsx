import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../../api/client'
import { formatRelative } from '../../lib/format'
import { Markdown } from '../Markdown'

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

/**
 * M9 Report tab: the assembled report body - DETERMINISTIC (no model
 * required; the cached AI commentary renders when present, and every
 * finding carries a factual fallback explanation without one - the MobSF
 * pattern). The Markdown view RENDERS the body via react-markdown (Aug 14
 * owner follow-up: "the report tab in markdown currently shows raw
 * markdown - fix it"); a toggle swaps in the LIVE PDF PREVIEW (the branded
 * PDF itself via the inline-disposition export route).
 *
 * The body NEVER 400s on a missing model (decision 10) - the AI surfaces
 * degrade to deterministic text inside the document; there is no
 * Regenerate button (Aug 14 owner follow-up: the report does not depend on
 * AI, so the AI-only regenerate affordance is gone). Export is a
 * same-origin anchor download (`{stem}-report.md|pdf` attachments).
 */
export function ReportPanel({ scanId, active }: ReportPanelProps) {
  // ---- body (cache-first server-side) ----
  const [body, setBody] = useState<BodyState>({ kind: 'loading' })
  const requestIdRef = useRef(0)
  // Markdown source (default) vs the branded PDF preview.
  const [view, setView] = useState<'md' | 'pdf'>('md')
  const [copied, setCopied] = useState(false)
  // The PDF iframe (src = inline export) is remounted/refetched whenever
  // the body is re-fetched - tab re-activation (or a suppress/restore on
  // another tab) changes the server cache identity and must not leave a
  // stale document up.
  const [pdfNonce, setPdfNonce] = useState(0)
  const [pdfLoaded, setPdfLoaded] = useState(false)

  const copyMarkdown = useCallback(() => {
    if (body.kind !== 'ok') return
    void navigator.clipboard
      ?.writeText(body.markdown)
      .then(() => setCopied(true))
      .catch(() => setCopied(false))
    window.setTimeout(() => setCopied(false), 1500)
  }, [body])

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

  return (
    <div>
      <div className="section-label">Report</div>

      {/* Toolbar: export (no Regenerate - the report is deterministic and
          does not depend on AI, Aug 14 owner follow-up) */}
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-[560px] text-[11.5px] leading-relaxed text-bone-faint">
          Assembled deterministically from the scan's persisted findings - no
          AI required (the cached AI commentary replaces the factual
          fallbacks when a model has generated it). Export as Markdown or the
          branded PDF.
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
        </div>
      </div>

      {/* View toggle: rendered Markdown (default) ↔ the branded PDF preview */}
      {body.kind === 'ok' && (
        <div className="report-view-toggle">
          <button
            type="button"
            className={`vt-chip ${view === 'md' ? 'active' : ''}`}
            aria-pressed={view === 'md'}
            onClick={() => setView('md')}
          >
            Markdown
          </button>
          <button
            type="button"
            className={`vt-chip ${view === 'pdf' ? 'active' : ''}`}
            aria-pressed={view === 'pdf'}
            onClick={() => setView('pdf')}
          >
            PDF preview
          </button>
          {view === 'md' && (
            <button type="button" className="link-btn" onClick={copyMarkdown}>
              {copied ? 'Copied ✓' : 'Copy markdown'}
            </button>
          )}
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
      {body.kind === 'ok' && view === 'md' && (
        <div className="report-md-view">
          {/* Rendered markdown (react-markdown + GFM) - the same body Export
              .md downloads, presented as a document instead of raw source
              (Aug 14 owner follow-up). */}
          <div className="report-md-body">
            <Markdown text={body.markdown} />
          </div>
          <div className="mt-3 border-t border-line-soft pt-2.5 font-mono text-[10px] text-bone-faint">
            Assembled {formatRelative(body.generatedAt)} · MobARK security
            report · what Export .md downloads
          </div>
        </div>
      )}
      {body.kind === 'ok' && view === 'pdf' && (
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
            Assembled {formatRelative(body.generatedAt)} · MobARK security report
          </div>
        </div>
      )}
    </div>
  )
}

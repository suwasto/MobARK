import { useEffect, useRef, useState } from 'react'
import { Document, Page, pdfjs } from 'react-pdf'

// react-pdf (pdf.js) renders the branded PDF client-side so the browser's
// NATIVE PDF viewer - and its toolbar (page split / zoom / print / save ...)
// - never appears in the preview (owner request, Aug 17: "view the pdf docs
// only without that pdf toolbar"). The worker is bundled locally via Vite's
// asset-URL handling (no CDN, matching the local-first posture) and MUST be
// configured in this module - the same one that renders <Document>/<Page> -
// because react-pdf overwrites workerSrc on import (a setup in the parent
// module would be clobbered by module execution order).
//
// This module is LAZY-loaded by ReportPanel (React.lazy) so the ~1 MB pdf.js
// library stays out of the initial bundle and loads only when the PDF
// preview is actually opened.
pdfjs.GlobalWorkerOptions.workerSrc = new URL(
  'pdfjs-dist/build/pdf.worker.min.mjs',
  import.meta.url,
).toString()

/** M9 follow-up (Aug 17): the PDF preview renders the BRANDED PDF with
 * react-pdf (pdf.js) instead of an <iframe> - the browser's native PDF
 * viewer chrome (the toolbar with page split / zoom / print) never appears;
 * the document itself is all that's shown. Pages render as crisp canvases
 * (text/annotation layers off - it's a preview; Export PDF downloads the
 * real artifact), fit to the container width and stacked vertically.
 * `withCredentials` is REQUIRED: the export route is cookie-guarded when
 * auth is on, and react-pdf's default fetch omits credentials (the old
 * iframe got them from the browser automatically). */
export function ReportPdfView({
  url,
  onLoaded,
  onError,
}: {
  url: string
  onLoaded: () => void
  onError: (message: string) => void
}) {
  const wrapRef = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(0)
  const [numPages, setNumPages] = useState(0)
  // Fit pages to the container's content width (the dashboard splitter can
  // resize the panel while the preview is open - pages re-fit live).
  useEffect(() => {
    const el = wrapRef.current
    if (!el) return
    const measure = () => setWidth(el.clientWidth)
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return (
    <div className="report-pdf-doc" ref={wrapRef}>
      <Document
        file={url}
        options={{ withCredentials: true }}
        loading={null}
        error={null}
        onLoadSuccess={({ numPages: n }) => {
          setNumPages(n)
          onLoaded()
        }}
        onLoadError={(e) => onError(e instanceof Error ? e.message : String(e))}
      >
        {numPages > 0 &&
          Array.from({ length: numPages }, (_, i) => (
            <Page
              key={i + 1}
              pageNumber={i + 1}
              width={Math.max(320, width - 32)}
              renderTextLayer={false}
              renderAnnotationLayer={false}
            />
          ))}
      </Document>
    </div>
  )
}

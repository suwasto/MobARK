import { useMemo } from 'react'
import { useFileContent } from '../../hooks/useFileContent'
import { highlightCode, splitHtmlLines } from '../../lib/highlight'

interface CodeViewerProps {
  scanId: number
  /** Tree path (root-relative) of the open file, or null when none selected. */
  rootName: string | null
  path: string | null
  flaggedLines: Set<number>
  onLineClick: (line: number) => void
}

/** Empty prompt when no file is selected. */
function EmptyPrompt() {
  return (
    <div className="flex h-full items-center justify-center bg-[#111417] p-6 text-center">
      <p className="text-[12px] leading-relaxed text-bone-faint">
        Select a file in the tree to view the decompiled source.
      </p>
    </div>
  )
}

/** Code viewer: highlight.js tokenization, numbered lines, flagged lines. */
export function CodeViewer({
  scanId,
  rootName,
  path,
  flaggedLines,
  onLineClick,
}: CodeViewerProps) {
  const contentPath = rootName && path ? `${rootName}/${path}` : null
  const { data, loading, error } = useFileContent(scanId, contentPath)

  const lines = useMemo(() => {
    if (!data) return []
    const html = highlightCode(data.content, data.language)
    return splitHtmlLines(html)
  }, [data])

  if (!path) return <EmptyPrompt />

  return (
    <div className="code-pane">
      {/* The sticky title is defined in CSS (.code-file-path): position,
          z-index, and the opaque pane background live there so it always
          paints ABOVE the scrolling lines (they are position:relative and
          would otherwise draw over the title — owner report, Aug 10). */}
      <div className="code-file-path">
        {contentPath}
        {data?.truncated && (
          <span className="text-amber"> · truncated at 200 KB</span>
        )}
      </div>

      {loading && (
        <div className="px-[18px] font-mono text-[11px] text-bone-faint">
          Loading file…
        </div>
      )}
      {!loading && error && (
        <div className="mx-[18px] rounded border border-crimson/30 bg-crimson/10 p-3 font-mono text-[11px] text-bone-dim">
          {error}
        </div>
      )}
      {!loading && !error && data && (
        <div>
          {lines.map((lineHtml, i) => {
            const lineNo = i + 1
            const flagged = flaggedLines.has(lineNo)
            return (
              <div
                key={lineNo}
                className={`code-line ${flagged ? 'flagged' : ''}`}
                title={flagged ? `Finding on line ${lineNo}` : undefined}
                onClick={flagged ? () => onLineClick(lineNo) : undefined}
              >
                <span className="ln">{lineNo}</span>
                <span
                  className="code-text"
                  dangerouslySetInnerHTML={{ __html: lineHtml || ' ' }}
                />
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

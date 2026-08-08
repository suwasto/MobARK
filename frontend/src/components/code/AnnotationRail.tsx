import { useEffect, useRef } from 'react'
import { useExplain } from '../../hooks/useExplain'
import type { FindingRead } from '../../types'
import { ExplainBox } from '../ExplainBox'

interface AnnotationRailProps {
  scanId: number
  /** Findings for the open file, already ordered by line. */
  findings: FindingRead[]
  /** Finding id to scroll into view (clicked a flagged line in the code). */
  activeNoteId: number | null
}

const SEV_LABEL: Record<string, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

function RailNote({
  scanId,
  finding,
  active,
}: {
  scanId: number
  finding: FindingRead
  active: boolean
}) {
  const { state, fetchExplain } = useExplain(scanId, finding.id)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (active) ref.current?.scrollIntoView({ block: 'nearest' })
  }, [active])

  return (
    <div ref={ref} className={`note ${active ? 'active' : ''}`}>
      <span className="note-tag">
        {SEV_LABEL[finding.severity] ?? finding.severity}
        {finding.line_number != null ? ` · line ${finding.line_number}` : ''}
      </span>
      <div className="mb-2 text-[11.5px] leading-snug text-bone">
        {finding.title}
      </div>
      {state.kind === 'idle' ? (
        <button
          type="button"
          className="link-btn"
          onClick={() => void fetchExplain()}
        >
          AI explanation ▸
        </button>
      ) : (
        // Regenerate bypasses the server cache (explicit cost spend); the
        // initial "AI explanation ▸" click stays cache-first.
        <ExplainBox
          state={state}
          onRetry={() => void fetchExplain(true)}
          className="mt-2 mb-0"
        />
      )}
    </div>
  )
}

/** Right rail: findings on the open file, ordered by line (mockup notes). */
export function AnnotationRail({
  scanId,
  findings,
  activeNoteId,
}: AnnotationRailProps) {
  return (
    <div className="annot-rail">
      <div className="annot-rail-label">
        Annotations ({findings.length})
      </div>
      {findings.length === 0 && (
        <p className="no-notes">
          No findings in this file. Notes for flagged lines land here.
        </p>
      )}
      {findings.map((f) => (
        <RailNote
          key={f.id}
          scanId={scanId}
          finding={f}
          active={f.id === activeNoteId}
        />
      ))}
    </div>
  )
}

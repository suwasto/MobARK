import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { Ref } from 'react'
import { useExplain } from '../../hooks/useExplain'
import type { FindingRead } from '../../types'
import { ExplainBox } from '../ExplainBox'

interface AnnotationRailProps {
  scanId: number
  /** Findings for the open file, already ordered by line. */
  findings: FindingRead[]
  /** Finding id to highlight (clicked a flagged line in the code). */
  activeNoteId: number | null
  /** M8 follow-up: collapse the rail to a slim restore strip (space
   * control; the parent owns the state + persistence). */
  onMinimize?: () => void
  /** One-scroll mirror (Aug 11): the rail shares the code pane's vertical
   * scroll - each note is placed at its finding's line offset and the notes
   * column translates by the code's scrollTop (a ``--rail-scroll`` CSS var
   * the parent sets directly on the DOM, so scrolling never re-renders the
   * panel). ``lineHeight`` = px per code line, ``compensation`` = code-title
   * height minus rail-head height - together they pin every note exactly
   * beside its line; ``contentHeight`` = the code pane's full scroll height
   * (the reachability bound: when the note stack is taller than it, the
   * rail switches to its own scrollbar - see onOverflowChange). All
   * measured by the parent (0 until measured). */
  lineHeight: number
  compensation: number
  contentHeight: number
  /** Attaches to the rail root (the parent measures the head and forwards
   * wheel events to the code scroll source). */
  railRef?: Ref<HTMLDivElement>
  /** M8 follow-up (owner request, Aug 11): reports whether the note stack is
   * TALLER than the code's content (dense findings on a short file). In that
   * case the rail cannot mirror the code scroll (bottom notes would be
   * clipped) - the parent freezes the code mirror at ``--rail-scroll: 0``
   * and stops forwarding wheel events, and this rail scrolls on its own.
   * Called only when the value changes. */
  onOverflowChange?: (overflow: boolean) => void
}

const SEV_LABEL: Record<string, string> = {
  high: 'High',
  warning: 'Warning',
  info: 'Info',
}

function RailNote({
  scanId,
  finding,
  active,
  top,
  noteRef,
}: {
  scanId: number
  finding: FindingRead
  active: boolean
  top: number
  noteRef: (el: HTMLDivElement | null) => void
}) {
  const { state, fetchExplain } = useExplain(scanId, finding.id)

  return (
    <div
      ref={noteRef}
      className={`note ${active ? 'active' : ''}`}
      style={{ top }}
    >
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

/** Vertical gap kept between clustered notes (cards are taller than a code
 * line, so notes whose lines are close together stack below each other). */
const NOTE_GAP = 10

/**
 * Right rail: findings on the open file, ordered by line (mockup notes).
 *
 * One-scroll mirror (Aug 11): the rail has NO scrollbar of its own - the
 * notes are positioned absolutely at their finding's line offset (clustered
 * so overlapping cards stack below each other) inside a column that
 * translates by the code pane's ``scrollTop`` (``--rail-scroll``). Scrolling
 * the code scrolls the annotations with it; wheeling over the rail is
 * forwarded to the code by the parent.
 */
export function AnnotationRail({
  scanId,
  findings,
  activeNoteId,
  onMinimize,
  lineHeight,
  compensation,
  contentHeight,
  railRef,
  onOverflowChange,
}: AnnotationRailProps) {
  const notesWrapRef = useRef<HTMLDivElement | null>(null)
  const noteRefs = useRef(new Map<number, HTMLDivElement>())
  // Per-note vertical offset (px, relative to the rail's top). Computed by
  // measuring the rendered cards and clustering: each note sits AT its
  // finding's line (plus the compensation offset), or below the previous
  // card when the card is taller than the gap. Notes without a line (smali
  // aliases, res) simply stack after the last line-anchored note.
  const [tops, setTops] = useState<number[]>([])
  // Whether the note stack exceeds the code's content height - the rail
  // then scrolls on its own (see onOverflowChange). Ref-guarded so the
  // parent is only notified on an actual change, never per layout pass.
  const [overflow, setOverflow] = useState(false)
  const lastOverflowRef = useRef(false)

  useLayoutEffect(() => {
    const apply = () => {
      const heights = findings.map(
        (f) => noteRefs.current.get(f.id)?.offsetHeight ?? 56,
      )
      let cursor = 0
      const out: number[] = []
      findings.forEach((f, i) => {
        const desired =
          f.line_number != null && lineHeight > 0
            ? (f.line_number - 1) * lineHeight + compensation
            : cursor
        const top = Math.max(desired, cursor)
        out.push(top)
        cursor = top + heights[i] + NOTE_GAP
      })
      // One-scroll reachability (owner report, Aug 11): the rail can only
      // translate as far as the code can scroll (contentHeight) - notes
      // beyond that bound were clipped and unreachable. When the note stack
      // is TALLER than the code, the rail switches to its own scrollbar
      // (.rail-overflow - the parent freezes the code mirror at 0 and stops
      // forwarding wheel events), so every note is reachable. The old
      // last-note clamp is obsolete: in the fits case it was a no-op, and in
      // the dense case the scrollbar replaces it.
      const lastBottom =
        out.length > 0 ? out[out.length - 1] + heights[heights.length - 1] : 0
      // Reachability bound: contentHeight when measured (the code's scroll
      // range ≈ the rail's reachable note range). If the geometry never
      // measured (contentHeight 0), fall back to the rail's own viewport so
      // dense notes still become scrollable instead of clipping (review
      // catch, Aug 11 - a failed measurement must not re-introduce the bug).
      const railH = notesWrapRef.current?.clientHeight ?? 0
      const nextOverflow =
        contentHeight > 0 ? lastBottom > contentHeight : lastBottom > railH
      if (nextOverflow !== lastOverflowRef.current) {
        lastOverflowRef.current = nextOverflow
        setOverflow(nextOverflow)
        onOverflowChange?.(nextOverflow)
      }
      setTops(out)
    }
    // First pass measures the DOM just committed (heights are independent of
    // the vertical offset); the setTops flush happens before paint, so the
    // user never sees the un-positioned frame.
    apply()
    const wrap = notesWrapRef.current
    if (!wrap || typeof ResizeObserver === 'undefined') return
    // Re-cluster when a card's height changes (e.g. an AI explanation
    // expands) so a taller card never overlaps the next one.
    const ro = new ResizeObserver(apply)
    for (const child of wrap.children) ro.observe(child)
    return () => ro.disconnect()
  }, [findings, lineHeight, compensation, contentHeight])

  // A flagged code line was clicked - bring its note into view in the rail's
  // OWN scroll (overflow mode only; in normal mode the parent already
  // scrolls the code pane and the mirror follows). Notes are absolutely
  // positioned inside the notes wrap, so offsetTop is the wrap-relative
  // top; centering keeps the note fully visible. No-op when the wrap is not
  // scrollable (scrollHeight <= clientHeight).
  useEffect(() => {
    if (activeNoteId == null) return
    const wrap = notesWrapRef.current
    const el = noteRefs.current.get(activeNoteId)
    if (!wrap || !el) return
    if (wrap.scrollHeight <= wrap.clientHeight) return
    wrap.scrollTop = Math.max(
      0,
      el.offsetTop - wrap.clientHeight / 2 + el.clientHeight / 2,
    )
  }, [activeNoteId])

  return (
    <div className="annot-rail" ref={railRef}>
      {/* Fixed head - the notes translate beneath it (it has an opaque
          background + z-index so scrolled cards never paint over it). */}
      <div className="annot-rail-label">
        <span>Annotations ({findings.length})</span>
        {onMinimize && (
          <button
            type="button"
            className="rail-min-btn"
            onClick={onMinimize}
            title="Minimize annotations rail"
            aria-label="Minimize annotations rail"
          >
            <span aria-hidden="true">−</span>
          </button>
        )}
      </div>
      {findings.length === 0 ? (
        <p className="no-notes">
          No findings in this file. Notes for flagged lines land here.
        </p>
      ) : (
        <div
          className={`annot-rail-notes${overflow ? ' rail-overflow' : ''}`}
          ref={notesWrapRef}
        >
          {findings.map((f, i) => (
            <RailNote
              key={f.id}
              scanId={scanId}
              finding={f}
              active={f.id === activeNoteId}
              top={tops[i] ?? 0}
              noteRef={(el) => {
                if (el) noteRefs.current.set(f.id, el)
                else noteRefs.current.delete(f.id)
              }}
            />
          ))}
        </div>
      )}
    </div>
  )
}

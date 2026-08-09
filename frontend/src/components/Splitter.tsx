import { useRef } from 'react'
import type { PointerEvent as ReactPointerEvent } from 'react'

/**
 * IntelliJ-style drag divider between two panes. Dragging reports
 * horizontal pixel deltas; the parent clamps + applies them to the pane
 * width and persists on pointer-up. Double-click resets to the default.
 *
 * Shared by the Decompiler tab (tree/annotation-rail splitters) and the
 * Agent dock (right-rail width, owner follow-up Aug 9 2026).
 */
export function Splitter({
  onDelta,
  onCommit,
  onReset,
  title,
}: {
  onDelta: (delta: number) => void
  onCommit: () => void
  onReset: () => void
  title: string
}) {
  const dragging = useRef(false)

  const handleDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    dragging.current = true
    e.currentTarget.setPointerCapture(e.pointerId)
    e.preventDefault() // don't start a text selection while dragging
  }
  const end = () => {
    if (!dragging.current) return
    dragging.current = false
    onCommit()
  }

  return (
    <div
      className="splitter"
      role="separator"
      aria-orientation="vertical"
      title={title}
      onPointerDown={handleDown}
      onPointerMove={(e) => {
        if (dragging.current) onDelta(e.movementX)
      }}
      onPointerUp={end}
      onPointerCancel={end}
      onDoubleClick={onReset}
    />
  )
}

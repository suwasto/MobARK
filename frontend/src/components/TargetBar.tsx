import { useEffect, useMemo, useRef, useState } from 'react'
import { formatRelative, platformLabel } from '../lib/format'
import { useApp } from '../state/AppContext'
import type { ScanRead } from '../types'

interface TargetBarProps {
  onPickFile: () => void
  uploading: boolean
  /** Override the identity shown - the progress-dialog backdrop renders the
   * last completed scan while the active one runs. Defaults to the active
   * scan. */
  scan?: ScanRead | null
}

/**
 * Target bar - the active scan's identity plus the "Open a different scan"
 * switch dropdown (upload new artifact or jump to any recent scan). One scan
 * at a time, matching the mockup.
 */
export function TargetBar({ onPickFile, uploading, scan }: TargetBarProps) {
  const { activeScan: active, scans, actions } = useApp()
  const activeScan = scan ?? active
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)

  // Close on outside click / Escape while the dropdown is open.
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const sorted = useMemo(
    () => [...scans].sort((a, b) => b.id - a.id),
    [scans],
  )

  if (!activeScan) return null

  return (
    <div
      ref={rootRef}
      className="flex h-12 shrink-0 items-center justify-between gap-4 border-b border-line bg-panel px-5"
    >
      {/* Active scan identity */}
      <div className="flex min-w-0 items-center gap-2.5">
        <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded border border-line bg-panel-raised text-xs">
          📦
        </div>
        <div className="truncate font-mono text-[13px] text-bone">
          {activeScan.filename}
        </div>
        {activeScan.platform && (
          <span className="plat-tag">{platformLabel(activeScan.platform)}</span>
        )}
        <span className={`status-badge ${activeScan.status}`}>
          {activeScan.status}
        </span>
        <div
          className="hidden whitespace-nowrap text-[11.5px] text-bone-faint md:block"
          title={`Created ${new Date(activeScan.created_at).toLocaleString()}`}
        >
          scanned {formatRelative(activeScan.created_at)}
        </div>
      </div>

      {/* Switch scan */}
      <div className="relative shrink-0">
        <button
          type="button"
          className="switch-pill"
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-controls={open ? 'targetbar-scan-list' : undefined}
          onClick={() => setOpen((o) => !o)}
        >
          <span>Open a different scan</span>
          <span className="chev">▾</span>
        </button>

        {open && (
          <div
            id="targetbar-scan-list"
            className="absolute right-0 top-full z-50 mt-1.5 w-[280px] rounded border border-line bg-panel-raised p-1.5 shadow-[0_12px_24px_rgba(0,0,0,0.4)]"
            role="listbox"
          >
            <button
              type="button"
              className="switch-opt-upload"
              disabled={uploading}
              onClick={() => {
                setOpen(false)
                onPickFile()
              }}
            >
              <span>⬆</span>
              {uploading ? 'Uploading…' : 'Upload new APK / IPA'}
            </button>
            <div className="mx-1 my-1.5 h-px bg-line" />
            <div className="px-2.5 pb-1 pt-1.5 font-mono text-[9.5px] uppercase tracking-[0.08em] text-bone-faint">
              Recent scans
            </div>
            <div className="max-h-[280px] overflow-y-auto">
              {sorted.length === 0 && (
                <div className="px-2.5 py-2 text-[11px] text-bone-faint">
                  No other scans yet
                </div>
              )}
              {sorted.map((scan) => {
                const active = scan.id === activeScan.id
                return (
                  <button
                    key={scan.id}
                    type="button"
                    role="option"
                    aria-selected={active}
                    className="switch-opt"
                    onClick={() => {
                      setOpen(false)
                      actions.selectScan(scan.id)
                    }}
                  >
                    <span className="sname">
                      <span className="truncate">{scan.filename}</span>
                      {scan.platform && (
                        <span className="plat-tag">
                          {platformLabel(scan.platform)}
                        </span>
                      )}
                      {active && <span className="text-steel">✓</span>}
                    </span>
                    <span className="sdate">
                      {formatRelative(scan.created_at)}
                    </span>
                  </button>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client'
import { useApp } from '../state/AppContext'
import type { ScanRead } from '../types'
import wordmarkUrl from '../assets/mobark-wordmark.svg'
import { ModelPicker } from './ModelPicker'

interface TopBarProps {
  onPickFile: () => void
  uploading: boolean
  onOpenSettings: () => void
  /** The scan currently on screen - the Export button targets it and stays
   *  disabled until it's a completed (done) scan. */
  scan: ScanRead | null
}

/** App shell top bar: brand, provider+model pickers, actions. */
export function TopBar({ onPickFile, uploading, onOpenSettings, scan }: TopBarProps) {
  // M9 Phase D: Export report is a dropdown of two download anchors (the
  // same {stem}-report.md|pdf attachments the Report tab offers). Same
  // outside-click + Escape close as the model pickers.
  const [exportOpen, setExportOpen] = useState(false)
  const exportRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!exportOpen) return
    const onDown = (e: MouseEvent) => {
      if (exportRef.current && !exportRef.current.contains(e.target as Node)) {
        setExportOpen(false)
      }
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setExportOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [exportOpen])

  // M9.1: the user chip + logout dropdown (auth-on mode; hidden in the
  // auth-off parity mode where there is no user).
  const { user, actions } = useApp()
  const [userOpen, setUserOpen] = useState(false)
  const userRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!userOpen) return
    const onDown = (e: MouseEvent) => {
      if (userRef.current && !userRef.current.contains(e.target as Node)) {
        setUserOpen(false)
      }
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setUserOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [userOpen])

  const exportable = scan?.status === 'done'

  return (
    <header className="flex items-center justify-between gap-4 border-b border-line bg-panel px-5">
      {/* Brand */}
      <div className="flex min-w-0 items-center gap-3">
        <img src={wordmarkUrl} alt="MobARK" className="h-[22px] w-auto shrink-0" draggable={false} />
        <span className="brand-tag hidden lg:inline">Mobile Application Reverse Kit</span>
      </div>

      {/* Actions */}
      <div className="flex shrink-0 items-center gap-3">
        <ModelPicker />

        <div ref={exportRef} className="relative">
          <button
            type="button"
            className="btn export-trigger"
            disabled={!exportable}
            aria-haspopup="menu"
            aria-expanded={exportOpen}
            title={
              exportable
                ? 'Download the assembled report as Markdown or PDF'
                : 'Export report - needs a completed scan'
            }
            onClick={() => setExportOpen((o) => !o)}
          >
            Export report <span className="chev">▾</span>
          </button>
          {exportOpen && exportable && scan && (
            <div className="export-menu" role="menu" aria-label="Export report">
              <div className="model-group-label">Export report</div>
              <a
                className="model-opt"
                role="menuitem"
                href={api.reportExportUrl(scan.id, 'md')}
                download
                title="Download the assembled body as Markdown"
              >
                <span className="mname">Markdown</span>
                <span className="via">.md</span>
              </a>
              <a
                className="model-opt"
                role="menuitem"
                href={api.reportExportUrl(scan.id, 'pdf')}
                download
                title="Download the branded PDF report"
              >
                <span className="mname">PDF</span>
                <span className="via">.pdf</span>
              </a>
            </div>
          )}
        </div>
        <button className="btn btn-primary" onClick={onPickFile} disabled={uploading}>
          {uploading ? 'Uploading…' : '+ New scan'}
        </button>
        {user ? (
          <div ref={userRef} className="relative">
            <button
              type="button"
              className="user-chip"
              aria-haspopup="menu"
              aria-expanded={userOpen}
              title={user.email ?? user.username}
              onClick={() => setUserOpen((o) => !o)}
            >
              <span className="user-chip-avatar">{user.username.slice(0, 1).toUpperCase()}</span>
              <span className="user-chip-name">{user.username}</span>
              <span className="chev">▾</span>
            </button>
            {userOpen && (
              <div className="user-menu" role="menu" aria-label="Account">
                <div className="model-group-label">Signed in as</div>
                <div className="user-menu-name">{user.username}</div>
                {user.email && <div className="user-menu-email">{user.email}</div>}
                <div className="model-group-label user-menu-role">
                  {user.is_admin ? 'Administrator' : 'User'}
                </div>
                {/* Settings lives in the profile menu (owner request) - close
                    the menu before opening the modal so the outside-click
                    handler doesn't immediately close it again. */}
                <button
                  type="button"
                  className="model-opt user-menu-settings"
                  role="menuitem"
                  onClick={() => {
                    setUserOpen(false)
                    onOpenSettings()
                  }}
                >
                  Settings
                </button>
                <button
                  type="button"
                  className="model-opt user-menu-logout"
                  role="menuitem"
                  onClick={() => void actions.logout()}
                >
                  Sign out
                </button>
              </div>
            )}
          </div>
        ) : (
          // Auth-off parity mode: no user chip, so the settings gear stays
          // in the top bar (the only way to reach Settings without a user).
          <button
            className="icon-btn"
            onClick={onOpenSettings}
            title="Settings"
            aria-label="Settings"
          >
            ⚙
          </button>
        )}
      </div>
    </header>
  )
}

import { useEffect, useState } from 'react'
import { useApp } from '../../state/AppContext'
import { BackendsTab } from './BackendsTab'
import { BYOKTab } from './BYOKTab'

interface SettingsModalProps {
  open: boolean
  onClose: () => void
}

type TabKey = 'backends' | 'byok' | 'search'

/**
 * Settings modal (mockup 1:1): Model backends + Bring your own key tabs are
 * live; Search & research is an M7 placeholder (SearXNG + agent-browser).
 * Field edits persist as they happen (blur / actions) — "Save changes"
 * closes and refreshes so the top-bar provider/model pickers are current.
 */
export function SettingsModal({ open, onClose }: SettingsModalProps) {
  const { actions } = useApp()
  const [tab, setTab] = useState<TabKey>('backends')

  // Escape closes; body scroll is locked while the modal is open.
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prev
    }
  }, [open, onClose])

  if (!open) return null

  const tabs: { key: TabKey; label: string; disabled?: boolean }[] = [
    { key: 'backends', label: 'Model backends' },
    { key: 'byok', label: 'Bring your own key' },
    { key: 'search', label: 'Search & research', disabled: true },
  ]

  return (
    <div
      className="modal-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="modal" role="dialog" aria-modal="true" aria-label="Settings">
        <div className="modal-head">
          <div className="modal-title">Settings</div>
          <button type="button" className="modal-close" aria-label="Close settings" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="modal-tabs" role="tablist">
          {tabs.map((t) => (
            <button
              key={t.key}
              type="button"
              role="tab"
              aria-selected={tab === t.key}
              className={`modal-tab ${tab === t.key ? 'active' : ''} ${t.disabled ? 'disabled' : ''}`}
              disabled={t.disabled}
              title={t.disabled ? 'Search & research ships in M7' : undefined}
              onClick={() => setTab(t.key)}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="modal-body">
          <div className={`modal-pane ${tab === 'backends' ? 'active' : ''}`}>
            <BackendsTab />
          </div>
          <div className={`modal-pane ${tab === 'byok' ? 'active' : ''}`}>
            <BYOKTab />
          </div>
          <div className={`modal-pane ${tab === 'search' ? 'active' : ''}`}>
            <SearchPane />
          </div>
        </div>

        <div className="save-row">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              void actions.refreshAll()
              onClose()
            }}
          >
            Save changes
          </button>
        </div>
      </div>
    </div>
  )
}

/** M7 placeholder — same privacy framing the mockup ships, no controls yet. */
function SearchPane() {
  return (
    <div>
      <div className="warn-box">
        <span className="mark2">⚠</span>
        <span>
          Even self-hosted, search queries leave this machine to reach public
          search engines — a different privacy boundary than local model
          inference. Browser automation shares that boundary.
        </span>
      </div>

      <div className="toggle-row">
        <div>
          <div className="label">Enable web research for this scan</div>
          <div className="sub">
            Lets the agent search, read, and drive a browser for things like CVE
            lookups — off by default.
          </div>
        </div>
        <span className="switch" aria-disabled="true" />
      </div>

      <p className="field-hint" style={{ marginTop: 4 }}>
        Ships in <strong style={{ color: 'var(--color-steel)' }}>M7</strong>:
        self-hosted SearXNG search plus interactive browser automation
        (agent-browser, CDP-driven Chrome) for reading and verifying JS-rendered
        pages — gated behind the same per-scan opt-in shown here.
      </p>
    </div>
  )
}

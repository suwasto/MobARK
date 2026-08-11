import { useEffect, useState } from 'react'
import { useApp } from '../../state/AppContext'
import { BackendsTab } from './BackendsTab'
import { BYOKTab } from './BYOKTab'
import { SearchTab } from './SearchTab'

interface SettingsModalProps {
  open: boolean
  onClose: () => void
}

type TabKey = 'backends' | 'byok' | 'search'

/**
 * Settings modal (mockup 1:1): Model backends + Bring your own key + Search
 * & research (M7, live) tabs. Field edits persist as they happen (blur /
 * actions) - "Save changes" closes and refreshes so the top-bar
 * provider/model pickers are current.
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
    { key: 'search', label: 'Search & research' },
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
            <SearchTab />
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

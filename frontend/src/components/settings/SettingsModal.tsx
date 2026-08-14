import { useEffect, useState } from 'react'
import { ApiError } from '../../api/client'
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
/** M9.1 vault unlock form (shown while the session can't access the vault).
 * First use creates the vault passphrase; later uses verify it. "Reset
 * vault" is the forgot-passphrase recovery (destroys the vault + clears
 * stored keys). */
function VaultForm() {
  const { actions } = useApp()
  const [passphrase, setPassphrase] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [confirming, setConfirming] = useState(false)

  const unlock = async (e: React.FormEvent) => {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      await actions.unlockVault(passphrase)
      setPassphrase('')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const reset = async () => {
    if (busy || !confirming) return
    setBusy(true)
    setError(null)
    try {
      await actions.resetVault()
      setConfirming(false)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="warn-box" style={{ marginBottom: 12 }}>
      <span className="mark2">🔐</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <p className="field-hint" style={{ marginBottom: 8 }}>
          Your API keys are encrypted at rest and protected by a vault
          passphrase. Enter it to unlock this session (the first time
          creates it). Without unlocking, keys cannot be added or used.
        </p>
        <form onSubmit={(e) => void unlock(e)} className="field-row" style={{ gap: 8 }}>
          <input
            className="field-input"
            type="password"
            placeholder="Vault passphrase (min 8 chars)"
            value={passphrase}
            disabled={busy}
            autoComplete="new-password"
            minLength={8}
            onChange={(e) => setPassphrase(e.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={busy || passphrase.length < 8}>
            {busy ? 'Unlocking…' : 'Unlock vault'}
          </button>
          {!confirming ? (
            <button
              type="button"
              className="link-btn"
              style={{ marginLeft: 'auto', alignSelf: 'center' }}
              onClick={() => setConfirming(true)}
            >
              Forgot it? Reset vault
            </button>
          ) : (
            <button
              type="button"
              className="link-btn"
              style={{ marginLeft: 'auto', alignSelf: 'center', color: 'var(--color-crimson)' }}
              onClick={() => void reset()}
            >
              {busy ? 'Resetting…' : 'Confirm reset (clears stored keys)'}
            </button>
          )}
        </form>
        {error && <p className="field-error" style={{ marginTop: 6 }}>{error}</p>}
      </div>
    </div>
  )
}

export function SettingsModal({ open, onClose }: SettingsModalProps) {
  const { user, actions } = useApp()
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

        {/* M9.1 vault: OAuth-only accounts with a locked session get the
            passphrase form here - local users unlock at login and never
            see it. Without it, every key-write would 400. */}
        {user?.vault_locked && <VaultForm />}

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

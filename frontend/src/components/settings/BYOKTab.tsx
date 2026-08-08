import { useState } from 'react'
import { useApp } from '../../state/AppContext'
import type { ModelBackendRead } from '../../types'

/**
 * Settings -> "Bring your own key" tab (mockup 1:1, scoped to the v1
 * provider set). A master cloud-fallback toggle, one row per configured
 * cloud backend (Active / Remove), and an add-provider form for the four
 * seeded BYOK providers plus a base-URL-only custom endpoint. Cloud
 * backends surface as pickable providers in the top-bar provider dropdown.
 */
const ADDABLE_PROVIDERS: { id: string; name: string; needsBaseUrl: boolean }[] = [
  { id: 'openai', name: 'OpenAI', needsBaseUrl: false },
  { id: 'anthropic', name: 'Anthropic', needsBaseUrl: false },
  { id: 'deepseek', name: 'DeepSeek', needsBaseUrl: false },
  { id: 'openrouter', name: 'OpenRouter', needsBaseUrl: false },
  { id: 'custom', name: 'Custom endpoint…', needsBaseUrl: true },
]

export function BYOKTab() {
  const { backends, actions } = useApp()
  const cloud = backends.filter((b) => !b.local)
  // A cloud route exists when an enabled backend is keyed (BYOK) or is a
  // custom endpoint (counts even without a key, per the M5 owner decision).
  const usable = (b: ModelBackendRead) => b.has_api_key || b.kind === 'custom'
  const cloudActive = cloud.some((b) => b.enabled && usable(b))

  const [selected, setSelected] = useState(ADDABLE_PROVIDERS[0].id)
  const [apiKey, setApiKey] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const sel = ADDABLE_PROVIDERS.find((p) => p.id === selected) ?? ADDABLE_PROVIDERS[0]

  const canAdd =
    !busy && (sel.needsBaseUrl ? baseUrl.trim().length > 0 : apiKey.trim().length > 0)

  const toggleCloud = async () => {
    if (busy) return
    setBusy(true)
    setFormError(null)
    try {
      // Master switch, batched into one PUT round + one refresh: disable
      // every cloud backend, or enable every one that can actually send
      // (keyed BYOK, or a custom endpoint regardless of key).
      const entries = cloud
        .filter((b) => (cloudActive ? b.enabled : usable(b)))
        .map((b) => ({ id: b.id, payload: { enabled: !cloudActive } as const }))
      if (entries.length > 0) {
        await actions.updateBackends(entries)
      }
    } catch (err) {
      setFormError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const addProvider = async () => {
    if (!canAdd) return
    setBusy(true)
    setFormError(null)
    setSuccess(null)
    try {
      await actions.createBackend({
        provider_id: sel.id,
        api_key: sel.needsBaseUrl ? apiKey.trim() || null : apiKey.trim(),
        base_url: sel.needsBaseUrl ? baseUrl.trim() : null,
      })
      setApiKey('')
      setBaseUrl('')
      setSuccess(`${sel.name} added — you can now pick its models from the top bar.`)
    } catch (err) {
      setFormError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const remove = async (b: ModelBackendRead) => {
    setBusy(true)
    setFormError(null)
    setSuccess(null)
    try {
      await actions.deleteBackend(b.id)
      setSuccess(`${b.name} removed. You can re-add it any time.`)
    } catch (err) {
      setFormError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <div className="warn-box">
        <span className="mark2">⚠</span>
        <span>
          Enabling a cloud key sends prompts (findings, code snippets, chat) to
          that provider. Keep this off for confidential client engagements —
          local backends stay fully on-device.
        </span>
      </div>

      <div className="toggle-row">
        <div>
          <div className="label">Enable cloud fallback</div>
          <div className="sub">
            Off by default. Only used if you explicitly select a cloud model.
          </div>
        </div>
        <span
          role="switch"
          aria-checked={cloudActive}
          className={`switch ${cloudActive ? 'on' : ''}`}
          onClick={() => void toggleCloud()}
        />
      </div>

      <label className="field-label" style={{ marginBottom: 4, display: 'block' }}>
        Connected providers
      </label>

      {cloud.length === 0 && (
        <p className="field-hint" style={{ marginTop: 8 }}>
          No cloud providers configured yet — add one below.
        </p>
      )}

      {cloud.map((b) => (
        <div key={b.id} className="mcp-item">
          <div style={{ minWidth: 0 }}>
            <div className="name">
              <span className={`dot ${b.enabled && b.has_api_key ? 'online' : 'off'}`} />
              <span className="truncate">{b.name}</span>
              <span className="kind-tag">{b.kind}</span>
            </div>
            <div className="desc">
              {b.kind === 'custom' ? b.base_url : b.has_api_key ? 'Key set' : 'Not configured'}
            </div>
          </div>
          <div className="mcp-actions">
            <span className={`conn-status ${b.enabled && b.has_api_key ? 'ok' : 'off'}`}>
              {b.enabled && b.has_api_key ? 'Active' : 'Inactive'}
            </span>
            <span
              role="switch"
              aria-checked={b.enabled}
              aria-label={`${b.name} enabled`}
              className={`switch ${b.enabled ? 'on' : ''}`}
              onClick={() => {
                if (busy) return
                setBusy(true)
                void actions
                  .updateBackend(b.id, { enabled: !b.enabled })
                  .catch((err: unknown) => {
                    setFormError(err instanceof Error ? err.message : String(err))
                  })
                  .finally(() => setBusy(false))
              }}
            />
            <button
              type="button"
              className="link-btn danger"
              disabled={busy}
              onClick={() => void remove(b)}
            >
              Remove
            </button>
          </div>
        </div>
      ))}

      <div className="add-mcp-form">
        <label className="field-label">Add a provider</label>
        <div className="provider-chip-row">
          {ADDABLE_PROVIDERS.map((p) => (
            <button
              key={p.id}
              type="button"
              className={`provider-chip ${selected === p.id ? 'active' : ''}`}
              disabled={busy}
              onClick={() => {
                setSelected(p.id)
                setFormError(null)
                setSuccess(null)
              }}
            >
              {p.name}
            </button>
          ))}
        </div>

        {sel.needsBaseUrl && (
          <div className="field-group" style={{ marginBottom: 10 }}>
            <input
              className="field-input"
              placeholder="Base URL, e.g. https://api.your-provider.com/v1"
              value={baseUrl}
              disabled={busy}
              spellCheck={false}
              onChange={(e) => setBaseUrl(e.target.value)}
            />
          </div>
        )}

        {!sel.needsBaseUrl && (
          <div className="field-group" style={{ marginBottom: 10 }}>
            <input
              className="field-input"
              type="password"
              placeholder="API key"
              value={apiKey}
              disabled={busy}
              autoComplete="off"
              onChange={(e) => setApiKey(e.target.value)}
            />
          </div>
        )}

        <p className="field-hint" style={{ marginBottom: 10 }}>
          Any provider exposing an OpenAI-compatible{' '}
          <code>/v1/chat/completions</code> endpoint works via{' '}
          &ldquo;Custom endpoint…&rdquo; — the base URL field appears when
          selected.
        </p>

        {formError && <p className="field-error">{formError}</p>}
        {success && <p className="field-hint" style={{ color: 'var(--color-moss)' }}>{success}</p>}

        <button
          type="button"
          className="btn btn-primary"
          disabled={!canAdd}
          onClick={() => void addProvider()}
        >
          {busy ? 'Saving…' : 'Add provider'}
        </button>
      </div>
    </div>
  )
}

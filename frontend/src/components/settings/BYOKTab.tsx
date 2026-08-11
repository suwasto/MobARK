import { useState } from 'react'
import { useApp } from '../../state/AppContext'
import type { ModelBackendRead } from '../../types'

/**
 * Settings -> "Bring your own key" tab (mockup 1:1, scoped to the v1
 * provider set). Pure add/remove: one row per configured cloud backend
 * (read-only Active/Inactive status + Remove - per-backend enable/disable
 * lives entirely in the Model backends tab, owner review Aug 8), and an
 * add-provider form for the BYOK providers plus a custom endpoint (base
 * URL + optional API key). BYOK backends are NOT seeded keyless (owner
 * decision, Aug 8 2026) - this menu is the only way to add a cloud
 * provider. Cloud backends surface as pickable providers in the top-bar
 * provider dropdown.
 */
const ADDABLE_PROVIDERS: {
  id: string
  name: string
  needsBaseUrl: boolean
  needsApiKey: boolean
}[] = [
  { id: 'openai', name: 'OpenAI', needsBaseUrl: false, needsApiKey: true },
  { id: 'anthropic', name: 'Anthropic', needsBaseUrl: false, needsApiKey: true },
  { id: 'gemini', name: 'Google Gemini', needsBaseUrl: false, needsApiKey: true },
  { id: 'deepseek', name: 'DeepSeek', needsBaseUrl: false, needsApiKey: true },
  { id: 'openrouter', name: 'OpenRouter', needsBaseUrl: false, needsApiKey: true },
  { id: 'custom', name: 'Custom endpoint…', needsBaseUrl: true, needsApiKey: true },
]

export function BYOKTab() {
  const { backends, actions } = useApp()
  const cloud = backends.filter((b) => !b.local)

  const [selected, setSelected] = useState(ADDABLE_PROVIDERS[0].id)
  const [apiKey, setApiKey] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const sel = ADDABLE_PROVIDERS.find((p) => p.id === selected) ?? ADDABLE_PROVIDERS[0]

  // BYOK providers need a key; custom endpoints need a base URL (its key is
  // optional - some OpenAI-compatible endpoints are keyless).
  const canAdd =
    !busy &&
    (sel.needsBaseUrl ? baseUrl.trim().length > 0 : apiKey.trim().length > 0)

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
      setSuccess(`${sel.name} added - you can now pick its models from the top bar.`)
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
          that provider. Keep this off for confidential client engagements -
          local backends stay fully on-device.
        </span>
      </div>

      <label className="field-label" style={{ marginBottom: 4, display: 'block' }}>
        Connected providers
      </label>

      {cloud.length === 0 && (
        <p className="field-hint" style={{ marginTop: 8 }}>
          No cloud providers configured yet - add one below.
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
            {/* Read-only status: enable/disable lives in the Model backends
                tab (the master and per-row switches were removed, owner
                review Aug 8) - this tab is pure add/remove. */}
            <span className={`conn-status ${b.enabled && b.has_api_key ? 'ok' : 'off'}`}>
              {b.enabled && b.has_api_key ? 'Active' : 'Inactive'}
            </span>
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

        {sel.needsApiKey && (
          <div className="field-group" style={{ marginBottom: 10 }}>
            <input
              className="field-input"
              type="password"
              placeholder={sel.needsBaseUrl ? 'API key (optional)' : 'API key'}
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
          &ldquo;Custom endpoint…&rdquo; - the base URL field appears when
          selected; its API key is optional for keyless endpoints.
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

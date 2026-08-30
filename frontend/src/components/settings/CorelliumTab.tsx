import { useEffect, useState } from 'react'
import { api, ApiError } from '../../api/client'
import type { CorelliumConfigRead, CorelliumHealth } from '../../types'

/**
 * Settings -> "Corellium" tab (M17 deferral, landed in M18). The OPT-IN,
 * paid, third-party iOS virtual-device backend for testers without a
 * jailbroken physical device. Off by default (FR-D5a); the key is
 * vault-encrypted and never returned (only `has_api_key` - same honesty rule
 * as model/search BYOK). Base URL + API key + Test probe + Clear. Clearly
 * separated from the default self-hosted device path.
 */
export function CorelliumTab() {
  const [config, setConfig] = useState<CorelliumConfigRead | null>(null)
  const [baseUrl, setBaseUrl] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [enabled, setEnabled] = useState(false)
  const [busy, setBusy] = useState<'load' | 'save' | 'test' | 'clear' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [health, setHealth] = useState<CorelliumHealth | null>(null)

  const load = async () => {
    setBusy('load')
    setError(null)
    try {
      const c = await api.corelliumConfig()
      setConfig(c)
      setBaseUrl(c.base_url)
      setEnabled(c.enabled)
      setApiKey('')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const save = async () => {
    if (busy) return
    setBusy('save')
    setError(null)
    setHealth(null)
    try {
      const c = await api.corelliumUpsert({
        base_url: baseUrl.trim() || null,
        // Empty string clears the stored key; null leaves it unchanged. The
        // field only sends a value when the user typed one (never a masked
        // placeholder back - we only ever hold `has_api_key`).
        api_key: apiKey.trim() === '' ? null : apiKey.trim(),
        enabled: enabled || null,
      })
      setConfig(c)
      setBaseUrl(c.base_url)
      setApiKey('')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const test = async () => {
    if (busy) return
    setBusy('test')
    setError(null)
    setHealth(null)
    try {
      setHealth(await api.corelliumTest())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const clear = async () => {
    if (busy) return
    setBusy('clear')
    setError(null)
    setHealth(null)
    try {
      await api.corelliumClear()
      setConfig(null)
      setBaseUrl('')
      setApiKey('')
      setEnabled(false)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const configured = config?.configured ?? false
  const dirty = baseUrl.trim() !== (config?.base_url ?? '') || apiKey.trim() !== '' || enabled !== (config?.enabled ?? false)

  return (
    <div>
      <div className="warn-box">
        <span className="mark2">⚠</span>
        <span>
          Corellium is a <strong>paid, third-party virtual-device service</strong> —
          traffic leaves your infrastructure, unlike the default self-hosted
          iOS path. Off by default; only enable it if you have Corellium
          credentials and want a virtual iOS device instead of a jailbroken
          physical one.
        </span>
      </div>

      <p className="field-hint" style={{ marginBottom: 16 }}>
        Base URL + API key pair. The key is encrypted at rest (your vault) and
        never shown again — only whether one is set.
      </p>

      {error && (
        <div className="rounded-[4px] border border-crimson/30 bg-crimson/10 p-3 font-mono text-[11.5px] text-bone-dim" style={{ marginBottom: 12 }}>
          {error}
        </div>
      )}

      <div className="field-group">
        <label className="field-label">Base URL</label>
        <input
          className="field-input"
          placeholder="https://app.corellium.com"
          value={baseUrl}
          disabled={busy === 'load'}
          onChange={(e) => setBaseUrl(e.target.value)}
          spellCheck={false}
        />
      </div>

      <div className="field-group">
        <label className="field-label">API key</label>
        <input
          className="field-input"
          type="password"
          placeholder={config?.has_api_key ? '•••••••• (key set — leave blank to keep)' : 'Corellium API key'}
          value={apiKey}
          disabled={busy === 'load'}
          onChange={(e) => setApiKey(e.target.value)}
          autoComplete="new-password"
        />
      </div>

      <div className="field-row" style={{ gap: 8, marginBottom: 16 }}>
        <label className="field-label">Enabled</label>
        <input
          type="checkbox"
          className="toggle-checkbox"
          checked={enabled}
          disabled={busy === 'load'}
          onChange={(e) => setEnabled(e.target.checked)}
        />
        <span className="field-hint">{enabled ? 'Corellium instances appear in iOS device discovery' : 'off — the default self-hosted device path'}</span>
      </div>

      {health && (
        <div className={`rounded-[4px] border p-3 font-mono text-[11.5px] ${health.reachable ? 'border-moss/30 bg-moss/10 text-bone-dim' : 'border-crimson/30 bg-crimson/10 text-bone-dim'}`} style={{ marginBottom: 12 }}>
          {health.reachable
            ? `✓ reachable — ${health.instance_count} virtual iOS instance${health.instance_count === 1 ? '' : 's'} visible`
            : health.error
              ? `✗ unreachable — ${health.error}`
              : '✗ not configured'}
        </div>
      )}

      <div className="field-row" style={{ gap: 8 }}>
        <button type="button" className="btn btn-primary" disabled={busy !== null || !dirty} onClick={() => void save()}>
          {busy === 'save' ? 'Saving…' : configured ? 'Save changes' : 'Save'}
        </button>
        <button type="button" className="btn" disabled={busy !== null || !configured} onClick={() => void test()}>
          {busy === 'test' ? 'Testing…' : 'Test connection'}
        </button>
        {configured && (
          <button type="button" className="btn" disabled={busy !== null} onClick={() => void clear()} title="Clear the config (back to off by default)">
            {busy === 'clear' ? 'Clearing…' : 'Clear'}
          </button>
        )}
      </div>
    </div>
  )
}
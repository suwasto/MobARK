import { useEffect, useState } from 'react'
import { api } from '../../api/client'
import { useApp } from '../../state/AppContext'
import type { SearchBackendRead, SearchProviderRead } from '../../types'

/**
 * Settings -> "Search & research" tab (M7, live). This tab owns the ENGINE
 * layer only — the per-scan opt-in lives EXCLUSIVELY on the Agent dock 🌐
 * toggle (owner decision, Aug 9: a Settings copy of the same switch was
 * redundant with the dock and was removed).
 *
 * One card per configured search backend carrying an Active/Inactive toggle
 * — exactly ONE Active at a time (enabling one disables the others; the
 * server enforces it via `enable_only`) — plus editable base URL + Test (a
 * real search-query probe). Addable engines (Aug 9 follow-up): a custom
 * SearXNG-compatible instance (base URL, no key) or a keyed provider —
 * Brave / Serper / Mojeek (API key, base URL optional with a per-provider
 * default). The add-form's provider picker comes from `GET /search/providers`
 * so the UI can never drift from the provider table.
 *
 * The Active toggle never auto-starts the SearXNG container — Active means
 * "the configured engine"; reachability is probed separately (a failing
 * probe carries the `docker compose --profile web up -d searxng` hint).
 */
export function SearchTab() {
  const { searchBackends } = useApp()
  return (
    <div>
      <div className="warn-box">
        <span className="mark2">⚠</span>
        <span>
          Even self-hosted, search queries leave this machine to reach public
          search engines — a different privacy boundary than local model
          inference. Web research is opt-in per scan, and the dock toggle
          stays greyed until an engine here is Active.
        </span>
      </div>

      <p className="field-hint" style={{ marginBottom: 16 }}>
        Pick the search engine the agent uses when web research is enabled.
        Only one engine can be Active at a time — enabling one turns the
        others off. SearXNG ships bundled; start it with{' '}
        <code>docker compose --profile web up -d searxng</code>.
      </p>

      {searchBackends.map((b) => (
        <SearchBackendCard key={b.id} backend={b} />
      ))}

      {searchBackends.length === 0 && (
        <p className="field-hint" style={{ marginTop: 8 }}>
          No search engines configured — the bundled SearXNG entry was
          removed. Add one below (or delete the store file to reseed).
        </p>
      )}

      <SearchAddForm />
    </div>
  )
}

function SearchBackendCard({ backend }: { backend: SearchBackendRead }) {
  const { actions } = useApp()
  const [baseUrl, setBaseUrl] = useState(backend.base_url)
  const [busy, setBusy] = useState<'url' | 'test' | 'enable' | 'start' | null>(null)
  const [error, setError] = useState<string | null>(null)

  const h = backend.health

  useEffect(() => {
    setBaseUrl(backend.base_url)
  }, [backend.base_url])

  const commitUrl = async () => {
    if (baseUrl === backend.base_url) return
    setBusy('url')
    setError(null)
    try {
      await actions.updateSearchBackend(backend.id, { base_url: baseUrl })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const test = async () => {
    setBusy('test')
    setError(null)
    try {
      await commitUrl()
      await actions.testSearchBackend(backend.id)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  // The radio: enabling one engine disables all others (server-side
  // `enable_only` keeps the invariant even for raw API clients).
  const toggleActive = async () => {
    setBusy('enable')
    setError(null)
    try {
      await actions.updateSearchBackend(backend.id, { enabled: !backend.enabled })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const remove = async () => {
    setBusy('enable')
    setError(null)
    try {
      await actions.deleteSearchBackend(backend.id)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  // One-click start for the bundled engine: the server runs the documented
  // compose command and waits for the engine to answer, then merges the fresh
  // health back into the card (owner request, Aug 9 — no more copy-pasting
  // the compose command when the probe fails).
  const startEngine = async () => {
    // Guard against a fast double-click: compose can hold the request for a
    // while (image pull), and two concurrent starts are pointless even though
    // `compose up` is idempotent.
    if (busy != null) return
    setBusy('start')
    setError(null)
    try {
      await actions.startSearchBackend(backend.id)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className={`backend-card ${backend.enabled ? '' : 'opacity-70'}`}>
      <div className="backend-card-head">
        <div className="name">
          <span className={`dot ${backend.enabled ? (h?.reachable ? 'online' : 'off') : 'off'}`} />
          <span className="truncate">{backend.name}</span>
          <span className="kind-tag">{backend.kind}</span>
        </div>
        <div className="right">
          <span className={`conn-status ${backend.enabled ? (h?.reachable ? 'ok' : 'off') : 'off'}`}>
            {backend.enabled ? 'Active' : 'Inactive'}
          </span>
          {/* The Active/Inactive radio — one engine Active at a time. */}
          <span
            role="radio"
            aria-checked={backend.enabled}
            aria-label={`${backend.name} active`}
            title={
              backend.enabled
                ? 'Active — the agent searches with this engine'
                : 'Set as the Active search engine (turns others off)'
            }
            className={`switch ${backend.enabled ? 'on' : ''}`}
            onClick={() => void toggleActive()}
          />
        </div>
      </div>

      <div className="field-row">
        <input
          className="field-input"
          value={baseUrl}
          disabled={busy != null}
          spellCheck={false}
          aria-label={`${backend.name} base URL`}
          onChange={(e) => setBaseUrl(e.target.value)}
          onBlur={() => void commitUrl()}
        />
        <button
          type="button"
          className="btn"
          style={{ flexShrink: 0 }}
          disabled={busy != null}
          onClick={() => void test()}
        >
          Test
        </button>
        {backend.kind === 'custom' && (
          <button
            type="button"
            className="btn"
            style={{ flexShrink: 0 }}
            disabled={busy != null}
            onClick={() => void remove()}
          >
            Remove
          </button>
        )}
      </div>

      {h?.status === 'ok' && h?.result_count != null && (
        <p className="field-hint">
          Probe OK — a test query returned {h.result_count} result
          {h.result_count === 1 ? '' : 's'}
          {h.sample_title ? ` (first: ${h.sample_title})` : ''}.
        </p>
      )}
      {!backend.enabled && (
        <p className="field-hint">Inactive — the agent will not search with this engine.</p>
      )}
      {/* Keyed engines never expose the key — only whether one is set
          (same honesty rule as model backends). Change it: remove + re-add. */}
      {backend.kind === 'keyed' && (
        <p className="field-hint">
          {backend.has_api_key ? 'API key set.' : 'No API key set — the agent cannot search with this engine yet.'}
        </p>
      )}
      {error && <p className="field-error">{error}</p>}
      {/* Probe diagnostics: surface *why* the test failed, including the
          compose first-use hint for the bundled engine. */}
      {h?.error && <p className="field-error">{h.error}</p>}
      {/* One-click start (bundled engine only, and only while unreachable):
          run the documented compose command from the UI instead of just
          showing its text — the card flips to "Probe OK" once the engine
          answers. Inside the app container (no Docker on its host) the
          server 502s with the manual command, shown as the field error. */}
      {backend.kind === 'bundled' && h != null && !h.reachable && (
        <div className="field-row" style={{ marginTop: 10 }}>
          <button
            type="button"
            className="btn btn-primary"
            style={{ flexShrink: 0 }}
            disabled={busy != null}
            onClick={() => void startEngine()}
          >
            {busy === 'start' ? 'Starting…' : '▶ Start engine'}
          </button>
          <span className="field-hint" style={{ margin: 'auto 0' }}>
            Runs <code>docker compose --profile web up -d searxng</code> and
            waits for the engine to answer.
          </span>
        </div>
      )}
    </div>
  )
}

function SearchAddForm() {
  const { actions } = useApp()
  // The addable engine set comes from the provider table — never hardcoded
  // here, so the UI can't drift from the backend (keyed providers are just
  // future table rows + a client branch).
  const [providers, setProviders] = useState<SearchProviderRead[] | null>(null)
  const [selected, setSelected] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    api
      .listSearchProviders()
      .then((p) => {
        if (cancelled) return
        setProviders(p)
        if (p.length > 0) {
          setSelected(p[0].id)
          setBaseUrl(p[0].default_base_url)
        }
      })
      .catch(() => {
        if (!cancelled) setProviders([])
      })
    return () => {
      cancelled = true
    }
  }, [])

  const sel = providers?.find((p) => p.id === selected) ?? null

  // Custom instances need a base URL; keyed providers need a key. Keyed base
  // URLs are optional — the provider default is used when left blank.
  const canAdd =
    !busy &&
    sel != null &&
    (sel.base_url_required ? baseUrl.trim().length > 0 : true) &&
    (sel.key_required ? apiKey.trim().length > 0 : true)

  const add = async () => {
    if (!canAdd || !sel) return
    setBusy(true)
    setError(null)
    setSuccess(null)
    try {
      await actions.createSearchBackend({
        provider_id: sel.id,
        base_url: sel.base_url_required ? baseUrl.trim() : baseUrl.trim() || null,
        api_key: sel.key_required ? apiKey.trim() : null,
      })
      setApiKey('')
      setSuccess(`${sel.name} added — it is now the Active engine.`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="add-mcp-form" style={{ marginTop: 18 }}>
      <label className="field-label">Add a search provider</label>
      <p className="field-hint" style={{ marginBottom: 10 }}>
        A custom SearXNG instance (self-hosted or public, JSON format
        enabled) needs only a base URL; Brave / Serper / Mojeek need an API
        key and use their default endpoint unless you override it.
      </p>

      {providers == null && (
        <p className="field-hint">Loading providers…</p>
      )}
      {providers != null && (
        <div className="provider-chip-row">
          {providers.map((p) => (
            <button
              key={p.id}
              type="button"
              className={`provider-chip ${selected === p.id ? 'active' : ''}`}
              disabled={busy}
              onClick={() => {
                setSelected(p.id)
                setBaseUrl(p.default_base_url)
                setApiKey('')
                setError(null)
                setSuccess(null)
              }}
            >
              {p.name}
            </button>
          ))}
        </div>
      )}

      {sel != null && (
        <>
          {sel.base_url_required ? (
            <div className="field-group" style={{ marginBottom: 10, marginTop: 10 }}>
              <input
                className="field-input"
                placeholder="Base URL, e.g. http://localhost:8888"
                value={baseUrl}
                disabled={busy}
                spellCheck={false}
                onChange={(e) => setBaseUrl(e.target.value)}
              />
            </div>
          ) : (
            <div className="field-group" style={{ marginBottom: 10, marginTop: 10 }}>
              <input
                className="field-input"
                placeholder={`Base URL (optional — defaults to ${sel.default_base_url})`}
                value={baseUrl}
                disabled={busy}
                spellCheck={false}
                onChange={(e) => setBaseUrl(e.target.value)}
              />
            </div>
          )}

          {sel.key_required && (
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
        </>
      )}

      {error && <p className="field-error">{error}</p>}
      {success && <p className="field-hint" style={{ color: 'var(--color-moss)' }}>{success}</p>}

      <button
        type="button"
        className="btn btn-primary"
        disabled={!canAdd}
        onClick={() => void add()}
      >
        {busy ? 'Adding…' : 'Add provider'}
      </button>
    </div>
  )
}



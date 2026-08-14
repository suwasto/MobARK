import { useEffect, useState } from 'react'
import { api } from '../../api/client'
import { useApp } from '../../state/AppContext'
import type { SearchBackendRead, SearchProviderRead } from '../../types'

/**
 * Settings -> "Search & research" tab (M7, live). This tab owns the ENGINE
 * layer only - the per-scan opt-in lives EXCLUSIVELY on the Agent dock 🌐
 * toggle (owner decision, Aug 9: a Settings copy of the same switch was
 * redundant with the dock and was removed).
 *
 * One card per configured search backend carrying an Active/Inactive toggle
 * - exactly ONE Active at a time (enabling one disables the others; the
 * server enforces it via `enable_only`) - plus editable base URL + Test (a
 * real search-query probe). Addable engines (Aug 9 follow-up): a custom
 * SearXNG-compatible instance (base URL, no key) or a keyed provider -
 * Brave / Serper / Mojeek (API key, base URL optional with a per-provider
 * default). The add-form's provider picker comes from `GET /search/providers`
 * so the UI can never drift from the provider table.
 *
 * The Active toggle only picks the configured engine - it does not start
 * or stop containers. SearXNG is always-on since the Aug 14 change (it
 * starts with `docker compose up`); reachability is probed separately (a
 * failing probe carries the `docker compose up -d searxng` hint).
 */
export function SearchTab() {
  const { searchBackends } = useApp()
  return (
    <div>
      <div className="warn-box">
        <span className="mark2">⚠</span>
        <span>
          Even self-hosted, search queries leave this machine to reach public
          search engines - a different privacy boundary than local model
          inference. Web research is opt-in per scan, and the dock toggle
          stays greyed until an engine here is Active <strong>and
          reachable</strong>.
        </span>
      </div>

      <p className="field-hint" style={{ marginBottom: 16 }}>
        Pick the search engine the agent uses when web research is enabled.
        Only one engine can be Active at a time - enabling one turns the
        others off. SearXNG is bundled and starts automatically with{' '}
        <code>docker compose up</code>.
      </p>

      {searchBackends.map((b) => (
        <SearchBackendCard key={b.id} backend={b} />
      ))}

      {searchBackends.length === 0 && (
        <p className="field-hint" style={{ marginTop: 8 }}>
          No search engines configured - the bundled SearXNG entry was
          removed. Add one below (or delete the store file to reseed).
        </p>
      )}

      <SearchAddForm />
    </div>
  )
}

/**
 * Guided-start state for the bundled engine when the app container has no
 * Docker (the compose case): the start endpoint 502s carrying the manual
 * command, and the card turns into a copy-the-command + auto-detect flow
 * instead of just an error line (owner decision, Aug 10: guided start +
 * auto-detect - no Docker socket is mounted into the app container).
 */
type GuideState =
  | { mode: 'waiting'; command: string }
  | { mode: 'up'; command: string }
  | { mode: 'stopped'; command: string }

/** Pull the manual command out of the start endpoint's failure message
 * (``start it manually: `docker compose up -d searxng```). The
 * message shape is pinned by backend tests, so the parse can't drift
 * silently. Anchored on `docker compose` (not the first backticked segment)
 * because the compose-failure format embeds the stderr tail BEFORE the
 * command - a backticked tail would otherwise win the parse. Returns null
 * when the failure carries no command (genuine errors - 404 etc. - keep the
 * plain field-error surface). */
function extractStartCommand(err: unknown): string | null {
  const msg = err instanceof Error ? err.message : String(err)
  const m = msg.match(/`(docker compose[^`]*)`/)
  return m ? m[1] : null
}

function SearchBackendCard({ backend }: { backend: SearchBackendRead }) {
  const { actions } = useApp()
  // The polling effect depends on these two STABLE callbacks directly (not
  // the whole `actions` object): AppContext rebuilds `actions` whenever its
  // state changes (e.g. App.tsx polls scan progress while any scan runs), so
  // depending on it would restart the interval and reset the 120s cap on
  // every unrelated update (review catch, Aug 10).
  const { refreshSearchBackends, testSearchBackend } = actions
  const [baseUrl, setBaseUrl] = useState(backend.base_url)
  const [busy, setBusy] = useState<'url' | 'test' | 'enable' | 'start' | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Guided-start flow (see GuideState) + the raw server message it explains.
  const [guided, setGuided] = useState<GuideState | null>(null)
  const [guideNote, setGuideNote] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const h = backend.health

  // M7 follow-up (Aug 11): the Active radio must not activate an engine that
  // can't search. SearXNG-style engines (bundled/custom) get a cheap
  // reachability probe on EVERY list (even inactive - the list route now
  // probes them regardless), so a dead engine's radio is disabled until it
  // answers. Keyed engines can't be probed cheaply - their honest check is a
  // real query - so their gate is the API key (the existing "No API key
  // set" hint explains).
  // Owner report (Aug 12): the bundled engine showed "Active" while the
  // container was down and its radio stayed toggleable. A SearXNG-style
  // engine now reads as Active ONLY while it actually answers - the stored
  // `enabled` flag is user intent, and an unreachable engine renders as
  // Inactive with its switch disabled (both on AND off) until it comes up
  // again; the recovery path is ▶ Start engine / Test, not flipping the
  // switch.
  const searxngStyle = backend.kind !== 'keyed'
  const engineLive = searxngStyle
    ? (h?.reachable ?? false)
    : backend.has_api_key
  const effectiveEnabled = searxngStyle
    ? backend.enabled && engineLive
    : backend.enabled
  const radioDisabled = !engineLive

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
    // Inert while disabled - a dead engine (or a keyless keyed engine) can't
    // be activated, even by a stray click on the dimmed switch.
    if (radioDisabled) return
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
  // health back into the card (owner request, Aug 9 - no more copy-pasting
  // the compose command when the probe fails). Inside the app container (no
  // Docker on its host) the server 502s carrying the manual command - the
  // card then switches to the guided flow: copy the command for the host
  // terminal + auto-detect when the engine comes up (owner decision, Aug 10).
  const startEngine = async () => {
    // Guard against a fast double-click: compose can hold the request for a
    // while (image pull), and two concurrent starts are pointless even though
    // `compose up` is idempotent.
    if (busy != null) return
    setBusy('start')
    setError(null)
    setGuideNote(null)
    try {
      await actions.startSearchBackend(backend.id)
    } catch (err) {
      const command = extractStartCommand(err)
      if (command) {
        // The compose-container case: the start can't run inside the app, so
        // guide the user to the host terminal and watch for the engine.
        setGuideNote(err instanceof Error ? err.message : String(err))
        setGuided({ mode: 'waiting', command })
      } else {
        setError(err instanceof Error ? err.message : String(err))
      }
    } finally {
      setBusy(null)
    }
  }

  // Auto-detect: while the guided flow waits, poll the lightweight
  // reachability check every 4s; when the engine answers, merge the fresh
  // card (plus a best-effort real probe for the "Probe OK" line - a fresh
  // boot can 503 the first real query, so failures are fine) and flip the
  // panel to its success state. Stops at ~2 min or on unmount - the engine
  // keeps booting regardless and the user can re-click Start / Test.
  const guideMode = guided?.mode ?? null
  useEffect(() => {
    if (guideMode !== 'waiting') return
    let cancelled = false
    const startedAt = Date.now()
    const tick = async () => {
      try {
        const list = await api.listSearchBackends()
        if (cancelled) return
        const b = list.find((x) => x.id === backend.id)
        if (b?.health?.reachable) {
          await refreshSearchBackends()
          try {
            await testSearchBackend(backend.id)
          } catch {
            // Lightweight reachability already merged - good enough.
          }
          if (cancelled) return
          setGuided((g) => (g ? { ...g, mode: 'up' } : g))
          return
        }
      } catch {
        // Transient list/probe failure - keep polling.
      }
      if (!cancelled && Date.now() - startedAt > 120_000) {
        setGuided((g) => (g ? { ...g, mode: 'stopped' } : g))
      }
    }
    void tick()
    const t = window.setInterval(() => void tick(), 4000)
    return () => {
      cancelled = true
      window.clearInterval(t)
    }
  }, [guideMode, backend.id, refreshSearchBackends, testSearchBackend])

  // Success transient: once the engine is detected the card already shows
  // the reachable dot (Start row gone), so clear the panel shortly after.
  useEffect(() => {
    if (guideMode !== 'up') return
    const t = window.setTimeout(() => setGuided(null), 4000)
    return () => window.clearTimeout(t)
  }, [guideMode])

  const copyCommand = async () => {
    if (!guided) return
    try {
      await navigator.clipboard.writeText(guided.command)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard blocked (non-secure context) - the code block is
      // selectable; the note below covers it.
    }
  }

  return (
    <div className={`backend-card ${effectiveEnabled ? '' : 'opacity-70'}`}>
      <div className="backend-card-head">
        <div className="name">
          <span className={`dot ${effectiveEnabled ? (engineLive ? 'online' : 'off') : 'off'}`} />
          <span className="truncate">{backend.name}</span>
          <span className="kind-tag">{backend.kind}</span>
        </div>
        <div className="right">
          <span className={`conn-status ${effectiveEnabled ? (engineLive ? 'ok' : 'off') : 'off'}`}>
            {effectiveEnabled ? 'Active' : 'Inactive'}
          </span>
          {/* The Active/Inactive radio - one engine Active at a time. It is
              disabled (dimmed, click-inert) while the engine can't search:
              a SearXNG-style engine that the probe reports unreachable (even
              if it was Active before going down), or a keyed engine with no
              API key. The recovery for a dead bundled engine is ▶ Start
              engine / Test, not flipping the switch. */}
          <span
            role="radio"
            aria-checked={effectiveEnabled}
            aria-disabled={radioDisabled}
            aria-label={`${backend.name} active`}
            title={
              radioDisabled
                ? searxngStyle
                  ? 'Engine unreachable - start it (▶ Start engine), then activate'
                  : 'No API key set - add a key to use this engine'
                : effectiveEnabled
                  ? 'Active - the agent searches with this engine'
                  : 'Set as the Active search engine (turns others off)'
            }
            className={`switch ${effectiveEnabled ? 'on' : ''}${radioDisabled ? ' disabled' : ''}`}
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
          Probe OK - a test query returned {h.result_count} result
          {h.result_count === 1 ? '' : 's'}
          {h.sample_title ? ` (first: ${h.sample_title})` : ''}.
        </p>
      )}
      {!effectiveEnabled && (
        <p className="field-hint">
          Inactive - the agent will not search with this engine.
          {searxngStyle && backend.enabled && (
            <> The engine is unreachable right now - start it or Test it to
            reactivate.</>
          )}
        </p>
      )}
      {/* Keyed engines never expose the key - only whether one is set
          (same honesty rule as model backends). Change it: remove + re-add. */}
      {backend.kind === 'keyed' && (
        <p className="field-hint">
          {backend.has_api_key ? 'API key set.' : 'No API key set - the agent cannot search with this engine yet.'}
        </p>
      )}
      {error && <p className="field-error">{error}</p>}
      {/* Probe diagnostics: surface *why* the test failed, including the
          compose first-use hint for the bundled engine. */}
      {h?.error && <p className="field-error">{h.error}</p>}
      {/* One-click start (bundled engine only, and only while unreachable):
          run the documented compose command from the UI instead of just
          showing its text - the card flips to "Probe OK" once the engine
          answers. Inside the app container (no Docker on its host) the
          server 502s with the manual command and the card switches to the
          guided flow below (copy + auto-detect). */}
      {backend.kind === 'bundled' && h != null && !h.reachable && guided == null && (
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
            Runs <code>docker compose up -d searxng</code> and waits for the
            engine to answer (the recovery path - the engine already starts
            with the stack).
          </span>
        </div>
      )}
      {/* Guided start (the compose-container case): the command to run on the
          HOST terminal, a Copy button, and live auto-detect - the app polls
          reachability and flips to "Engine is up" on its own (Aug 10). */}
      {/* aria-live so the detecting→up flip is announced (review catch). */}
      {guided != null && (
        <div className="engine-guide" role="status" aria-live="polite">
          {guided.mode === 'waiting' && (
            <>
              <div className="eg-command">
                <code>{guided.command}</code>
                <button
                  type="button"
                  className="btn"
                  style={{ flexShrink: 0 }}
                  disabled={copied}
                  onClick={() => void copyCommand()}
                >
                  {copied ? 'Copied ✓' : 'Copy'}
                </button>
              </div>
              <p className="eg-note">
                The app runs in a container without Docker - run this command
                once in a <strong>terminal on this machine</strong> (the host
                running Docker). The app checks every few seconds and picks
                the engine up automatically.
              </p>
              {guideNote && <p className="eg-note eg-raw">{guideNote}</p>}
              <div className="eg-row">
                <span className="eg-status">◌ Detecting - checking every 4s…</span>
                <button
                  type="button"
                  className="link-btn"
                  onClick={() =>
                    setGuided({ mode: 'stopped', command: guided.command })
                  }
                >
                  Stop waiting
                </button>
              </div>
            </>
          )}
          {guided.mode === 'up' && (
            <p className="eg-note eg-ok">
              ✓ Engine is up - SearXNG is reachable. Web research is ready to
              use; enable it per scan with the 🌐 toggle in the Agent dock.
            </p>
          )}
          {guided.mode === 'stopped' && (
            <>
              <div className="eg-command">
                <code>{guided.command}</code>
                <button
                  type="button"
                  className="btn"
                  style={{ flexShrink: 0 }}
                  disabled={copied}
                  onClick={() => void copyCommand()}
                >
                  {copied ? 'Copied ✓' : 'Copy'}
                </button>
              </div>
              <p className="eg-note">
                Still unreachable. Run the command in a terminal on this
                machine and wait for it to finish, then click{' '}
                <strong>Test</strong> above.
              </p>
              <div className="eg-row">
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setGuided(null)}
                >
                  Dismiss
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

function SearchAddForm() {
  const { actions } = useApp()
  // The addable engine set comes from the provider table - never hardcoded
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
  // URLs are optional - the provider default is used when left blank.
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
      setSuccess(`${sel.name} added - it is now the Active engine.`)
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
                placeholder={`Base URL (optional - defaults to ${sel.default_base_url})`}
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



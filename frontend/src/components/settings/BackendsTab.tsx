import { useEffect, useState } from 'react'
import { useApp } from '../../state/AppContext'
import type { ModelBackendRead } from '../../types'

/**
 * Settings -> "Model backends" tab (mockup 1:1). One card per configured
 * backend: connection state, editable base URL, Test (full health probe),
 * model chips (set default), and an enable switch. Edits persist on
 * blur / action - the footer "Save changes" is a close that refreshes.
 *
 * Model chips are CURATED by default (owner UX request, Aug 8): the
 * provider's suggested models that the backend actually serves - a
 * "See all (N more)" chip reveals the full served list. The configured
 * default model is never hidden behind the fold.
 */
export function BackendsTab() {
  const { backends } = useApp()
  return (
    <div>
      <p className="field-hint" style={{ marginBottom: 16 }}>
        MASA talks to any locally-served, OpenAI-compatible endpoint. Point it
        at Ollama or LM Studio - no cloud calls unless you enable one in
        &ldquo;Bring your own key&rdquo;.
      </p>
      {backends.map((b) => (
        <BackendCard key={b.id} backend={b} />
      ))}
    </div>
  )
}

// How many served models are shown by default for providers without a
// curated list (local/custom) - the rest sit behind the "see all" reveal.
const CURATED_LIMIT = 6

function BackendCard({ backend }: { backend: ModelBackendRead }) {
  const { actions } = useApp()
  const [baseUrl, setBaseUrl] = useState(backend.base_url)
  const [busy, setBusy] = useState<'url' | 'test' | 'enable' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState(false)

  const h = backend.health

  // Follow external updates (e.g. a fresh probe merged a newer base_url).
  useEffect(() => {
    setBaseUrl(backend.base_url)
  }, [backend.base_url])

  // A fresh probe can shrink/grow the served list - collapse the "see all"
  // reveal so the curated view is never left showing a stale count.
  const served = h?.models ?? []
  useEffect(() => {
    setExpanded(false)
  }, [served])

  const conn = busy === 'test'
    ? { cls: 'testing', text: 'Testing…' }
    : h?.probe_ok === true
      ? { cls: 'ok', text: '● Connected' }
      : h?.probe_ok === false
        ? { cls: 'err', text: '● Probe failed' }
        : h?.reachable
          ? { cls: 'ok', text: '● Connected' }
          : { cls: 'off', text: '○ Not connected' }

  // Green only when the probe (or a reachable pre-probe state) says so - a
  // failed completion probe stays a red/dim dot, never a green one.
  const dotOnline =
    h?.probe_ok === true || (h?.reachable === true && h?.probe_ok == null)

  const commitUrl = async () => {
    if (baseUrl === backend.base_url) return
    setBusy('url')
    setError(null)
    try {
      await actions.updateBackend(backend.id, { base_url: baseUrl })
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
      await actions.testBackend(backend.id)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const toggleEnabled = async () => {
    setBusy('enable')
    setError(null)
    try {
      await actions.updateBackend(backend.id, { enabled: !backend.enabled })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const setDefault = async (model: string) => {
    if (busy) return
    setBusy('url')
    setError(null)
    try {
      await actions.updateBackend(backend.id, { model, enabled: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const kindLabel = backend.kind === 'local' ? 'local' : backend.kind === 'custom' ? 'custom' : 'cloud'

  // Curated default view (owner UX request, Aug 8): show the provider's
  // suggested models that the backend actually serves; local/custom backends
  // have no curated list, so fall back to the first few served models. The
  // configured default is never hidden behind the fold. "See all" reveals
  // the complete served list.
  const curatedServed = (backend.suggested_models ?? []).filter((m) =>
    served.includes(m),
  )
  let defaultVisible =
    curatedServed.length > 0 ? curatedServed : served.slice(0, CURATED_LIMIT)
  if (
    backend.model &&
    served.includes(backend.model) &&
    !defaultVisible.includes(backend.model)
  ) {
    defaultVisible = [backend.model, ...defaultVisible]
  }
  const visible = expanded ? served : defaultVisible
  const hiddenCount = served.length - defaultVisible.length

  return (
    <div className={`backend-card ${backend.enabled ? '' : 'opacity-70'}`}>
      <div className="backend-card-head">
        <div className="name">
          <span className={`dot ${dotOnline ? 'online' : 'off'}`} />
          <span className="truncate">{backend.name}</span>
          <span className="kind-tag">{kindLabel}</span>
        </div>
        <div className="right">
          <span className={`conn-status ${conn.cls}`}>{conn.text}</span>
          <span
            role="switch"
            aria-checked={backend.enabled}
            aria-label={`${backend.name} enabled`}
            className={`switch ${backend.enabled ? 'on' : ''}`}
            onClick={() => void toggleEnabled()}
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
      </div>

      {served.length > 0 && (
        <div className="model-chip-row">
          <span className="model-chip-label">Models</span>
          {visible.map((m) => {
            const isDefault = backend.enabled && backend.model === m
            return (
              <button
                key={m}
                type="button"
                className={`model-chip ${isDefault ? 'default' : ''}`}
                title={isDefault ? 'Default chat model' : 'Set as default chat model'}
                disabled={busy != null}
                onClick={() => void setDefault(m)}
              >
                {isDefault ? '★ ' : ''}
                {m}
              </button>
            )
          })}
          {hiddenCount > 0 && (
            <button
              type="button"
              className="model-chip see-all"
              title={expanded ? 'Collapse to curated models' : 'Show every model this backend serves'}
              disabled={busy != null}
              onClick={() => setExpanded((e) => !e)}
            >
              {expanded ? '▲ Show fewer' : `▼ See all (${hiddenCount} more)`}
            </button>
          )}
        </div>
      )}

      {served.length === 0 && backend.enabled && (
        <p className="field-hint">
          {backend.local
            ? 'No models listed - start the local server (or confirm the URL), '
              + 'then Test to populate the model list.'
            : 'No models listed - confirm the provider key (or the URL for '
              + 'custom endpoints), then Test.'}
        </p>
      )}
      {!backend.enabled && (
        <p className="field-hint">Disabled - the agent will not use this backend.</p>
      )}
      {error && <p className="field-error">{error}</p>}
      {/* Probe diagnostics: the backend health carries *why* the test
          failed (e.g. the model server can't load the model) - surface it
          instead of leaving the failure at a bare red dot. */}
      {h?.error && <p className="field-error">{h.error}</p>}
    </div>
  )
}

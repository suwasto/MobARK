import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { useApp } from '../state/AppContext'
import type { ModelBackendRead, ModelBackendUpsert } from '../types'

/**
 * Top-bar model selection (owner redesign, Aug 8 2026) — TWO searchable
 * dropdowns instead of the single model pill:
 *
 *   1. **Provider** — every configured backend (local + cloud) plus
 *      **None (no AI)**. Picking a provider loads its served models into the
 *      model dropdown.
 *   2. **Model** — the models the selected provider actually serves (from the
 *      lightweight reachability check already attached to each backend,
 *      `health.models`) plus **None**. Picking a model makes it the default
 *      (PUT model + enabled).
 *
 * **None linkage:** selecting None on the provider clears the selection
 * (every enabled-with-model backend is disabled + cleared), which auto-sets
 * the model to None; selecting None on the model does the same on the active
 * provider, which auto-sets the provider to None. Either way the result is
 * "no AI at all" — matching `pick_chat_backend`'s contract (needs an enabled
 * backend WITH a model).
 *
 * Served models come from `health.models`, so opening the dropdowns costs
 * zero extra calls. Per-kind empty copy: local backends suggest starting the
 * server; cloud-opt backends never claim "is the server running?" (owner
 * review, Aug 7).
 */
export function ModelPicker() {
  const { backends, actions } = useApp()
  const [openMenu, setOpenMenu] = useState<'provider' | 'model' | null>(null)
  const [busy, setBusy] = useState(false)
  const [pQuery, setPQuery] = useState('')
  const [mQuery, setMQuery] = useState('')
  const [providerSel, setProviderSel] = useState<string | null>(null)
  const rootRef = useRef<HTMLDivElement>(null)
  const queryRef = useRef('')

  // Active chat model = first enabled backend with a model (mirror of
  // backend `pick_chat_backend` — one rule everywhere).
  const active = useMemo(
    () => backends.find((b) => b.enabled && b.model) ?? null,
    [backends],
  )

  // The provider the model dropdown is bound to. User picks persist; when
  // nothing is chosen (or the chosen provider vanished) it follows `active`.
  useEffect(() => {
    setProviderSel((prev) => {
      if (prev != null && backends.some((b) => b.id === prev)) return prev
      return active?.id ?? null
    })
  }, [backends, active])

  // Close on outside click / Escape while a dropdown is open. Escape clears
  // a running search first, then closes.
  useEffect(() => {
    if (!openMenu) return
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpenMenu(null)
      }
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (queryRef.current) {
          if (openMenu === 'provider') setPQuery('')
          else setMQuery('')
        } else {
          setOpenMenu(null)
        }
      }
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [openMenu])

  // Track the currently-open menu's query for Escape-first-clear semantics.
  useEffect(() => {
    queryRef.current = openMenu === 'provider' ? pQuery : mQuery
  }, [openMenu, pQuery, mQuery])

  const providerBackend = backends.find((b) => b.id === providerSel) ?? null

  /** Disable + clear every backend that currently has an active model. */
  const clearAll = async () => {
    const entries: { id: string; payload: ModelBackendUpsert }[] = backends
      .filter((b) => b.enabled && b.model)
      .map((b) => ({ id: b.id, payload: { model: '', enabled: false } }))
    if (entries.length > 0) await actions.updateBackends(entries)
  }

  const pickProvider = async (id: string | null) => {
    if (busy) return
    setBusy(true)
    try {
      if (id === null) {
        // None provider -> auto None model (clear everything active).
        await clearAll()
        setProviderSel(null)
      } else {
        const backend = backends.find((b) => b.id === id)
        if (backend) {
          // Activate this provider deterministically (same batch-clear as
          // pickModel): keep its configured model if it has one, and clear
          // every OTHER enabled-with-model backend so `pick_chat_backend`
          // resolves to the picked provider — the pill label and the actual
          // chat provider must never diverge.
          const entries: { id: string; payload: ModelBackendUpsert }[] = backends
            .filter((b) => b.id !== id && b.enabled && b.model)
            .map((b) => ({ id: b.id, payload: { model: '', enabled: false } }))
          entries.push({ id, payload: { enabled: true } })
          await actions.updateBackends(entries)
          setProviderSel(id)
          setPQuery('')
        }
      }
    } finally {
      setBusy(false)
      setOpenMenu(null)
    }
  }

  const pickModel = async (backend: ModelBackendRead, model: string | null) => {
    if (busy) return
    setBusy(true)
    try {
      if (model === null) {
        // None model -> auto None provider on this backend.
        await actions.updateBackend(backend.id, { model: '', enabled: false })
        if (providerSel === backend.id) setProviderSel(null)
      } else {
        // Activate this backend + model; clear other enabled-with-model
        // backends so `pick_chat_backend` deterministically returns it.
        const entries: { id: string; payload: ModelBackendUpsert }[] = backends
          .filter((b) => b.id !== backend.id && b.enabled && b.model)
          .map((b) => ({ id: b.id, payload: { model: '', enabled: false } }))
        entries.push({ id: backend.id, payload: { model, enabled: true } })
        await actions.updateBackends(entries)
      }
    } finally {
      setBusy(false)
      setOpenMenu(null)
    }
  }

  const servedModels = (b: ModelBackendRead): string[] => {
    const listed = b.health?.models ?? []
    // Always surface the configured model even if the live listing is empty
    // or hasn't reported it yet (server briefly down, etc.).
    if (b.model && !listed.includes(b.model)) return [b.model, ...listed]
    return listed
  }

  // ---- provider dropdown content ----
  const pq = pQuery.trim().toLowerCase()
  const providerBlocks = backends
    .filter((b) => !pq || b.name.toLowerCase().includes(pq) || b.id.includes(pq))
    .map((b) => (
      <button
        key={b.id}
        type="button"
        className={`model-opt ${providerSel === b.id ? 'active' : ''}`}
        disabled={busy}
        onClick={() => void pickProvider(b.id)}
      >
        <span className="mname">{b.name}</span>
        <span className="via">{b.local ? 'local' : 'cloud'}</span>
      </button>
    ))

  // ---- model dropdown content ----
  const mq = mQuery.trim().toLowerCase()
  const modelOptions = providerBackend ? servedModels(providerBackend) : []
  const visibleModels = modelOptions.filter(
    (m) => !mq || m.toLowerCase().includes(mq),
  )
  // An enabled backend with an EMPTY model string (e.g. the seed default
  // when no MASA_DEFAULT_CHAT_MODEL is set) is the same as None — the
  // `?? 'Model: None'` label and the None-row active state must treat it as
  // no model.
  const currentModel =
    providerBackend && providerBackend.enabled && providerBackend.model
      ? providerBackend.model
      : null

  return (
    <div ref={rootRef} className="flex shrink-0 items-center gap-2">
      {/* Provider dropdown */}
      <div className="relative">
        <button
          type="button"
          className="model-pill"
          aria-haspopup="listbox"
          aria-expanded={openMenu === 'provider'}
          title="Choose a model provider, or None to disable AI"
          onClick={() => setOpenMenu((m) => (m === 'provider' ? null : 'provider'))}
        >
          <span className={`dot ${active ? 'online' : 'off'}`} />
          <span className="truncate">{providerBackend?.name ?? 'Provider: None'}</span>
          <span className="chev">▾</span>
        </button>

        {openMenu === 'provider' && (
          <div className="model-dropdown" role="listbox">
            <div className="model-group-label">Provider</div>
            <input
              className="model-search"
              placeholder="Search providers…"
              value={pQuery}
              autoFocus
              aria-label="Search providers"
              onChange={(e) => setPQuery(e.target.value)}
            />
            <button
              type="button"
              className={`model-opt ${providerSel === null ? 'active' : ''}`}
              disabled={busy}
              onClick={() => void pickProvider(null)}
            >
              <span className="mname">None (no AI)</span>
              <span className="via">disabled</span>
            </button>
            {providerBlocks.length === 0 && (
              <div className="model-opt-empty">No providers match your search.</div>
            )}
            {providerBlocks.length > 0 && <div className="model-divider" />}
            {providerBlocks}
            {backends.length === 0 && (
              <div className="model-opt-empty">
                No providers configured — add one in Settings.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Model dropdown */}
      <div className="relative">
        {/* The closed pill truncates by necessity — the hover title always
            carries the full id so the active model is never unreadable
            (owner follow-up, Aug 9). */}
        <button
          type="button"
          className="model-pill"
          aria-haspopup="listbox"
          aria-expanded={openMenu === 'model'}
          title={
            currentModel
              ? `Model: ${currentModel}`
              : 'Choose a model for the selected provider, or None to disable AI'
          }
          onClick={() => setOpenMenu((m) => (m === 'model' ? null : 'model'))}
        >
          <span className={`dot ${active ? 'online' : 'off'}`} />
          <span className="truncate">
            {currentModel ?? 'Model: None'}
          </span>
          <span className="chev">▾</span>
        </button>

        {openMenu === 'model' && (
          <div className="model-dropdown" role="listbox">
            <div className="model-group-label">
              Model{providerBackend ? ` · ${providerBackend.name}` : ''}
            </div>
            {providerBackend ? (
              <Fragment>
                {modelOptions.length > 0 && (
                  <input
                    className="model-search"
                    placeholder="Search models…"
                    value={mQuery}
                    autoFocus
                    aria-label="Search models"
                    onChange={(e) => setMQuery(e.target.value)}
                  />
                )}
                <button
                  type="button"
                  className={`model-opt ${currentModel == null ? 'active' : ''}`}
                  disabled={busy}
                  onClick={() => void pickModel(providerBackend, null)}
                >
                  <span className="mname">None</span>
                  <span className="via">no AI</span>
                </button>
                {visibleModels.length === 0 ? (
                  <div className="model-opt-empty">
                    {mq && modelOptions.length > 0
                      ? 'No models match your search.'
                      : providerBackend.enabled
                        ? providerBackend.local
                          ? 'No models listed (is the server running?)'
                          : 'No models listed — check the provider key in Settings.'
                        : 'This provider is disabled.'}
                  </div>
                ) : (
                  <Fragment>
                    <div className="model-divider" />
                    {/* Model rows are name-only (owner follow-up, Aug 9): the
                        local-vs-opt-in signal already lives on the provider
                        dropdown, and the right-aligned via column was what
                        truncated long model ids. The name wraps instead of
                        ellipsizing; the title guarantees the full id on
                        hover regardless. */}
                    {visibleModels.map((m) => (
                      <button
                        key={m}
                        type="button"
                        className={`model-opt ${
                          currentModel === m ? 'active' : ''
                        }`}
                        disabled={busy}
                        title={m}
                        onClick={() => void pickModel(providerBackend, m)}
                      >
                        <span className="mname">{m}</span>
                      </button>
                    ))}
                  </Fragment>
                )}
              </Fragment>
            ) : (
              <div className="model-opt-empty">
                Pick a provider first — or leave both at None to run without AI.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

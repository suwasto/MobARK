import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../../api/client'
import type { DynamicScriptRead } from '../../types'

/**
 * M18: the frida scripts panel (FR-D15/D16/D17 + the M16 approval gate).
 * Lists the per-scan script library (built-in + manual + agent, live
 * `running` flags), Run/Stop per row, "Add script manually" (name + JS body +
 * description), and the M16 deferral — PROPOSED agent-authored drafts render
 * an Approve/Reject card (Approve -> ready + read-only + runnable; Reject ->
 * DELETE). Built-in / approved-agent rows are read-only. The body expands
 * inline per script.
 */
interface ScriptsPanelProps {
  scanId: number | null
  sessionLive: boolean
  platform: string
  /** The shared session hook - running counts sync to the sidebar badge. */
  onScriptsChanged?: () => void
}

const ORIGIN_LABEL: Record<string, string> = {
  builtin: 'built-in',
  manual: 'manual',
  agent: 'agent',
}

function formatError(err: unknown): string {
  return err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err)
}

export function ScriptsPanel({ scanId, sessionLive, platform, onScriptsChanged }: ScriptsPanelProps) {
  const [scripts, setScripts] = useState<DynamicScriptRead[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<number | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [form, setForm] = useState({ name: '', body: '', description: '' })
  const [formBusy, setFormBusy] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<number | null>(null)

  const load = useCallback(async () => {
    if (!sessionLive) {
      setScripts([])
      setLoading(false)
      return
    }
    setLoading(true)
    try {
      setScripts(await api.dynamicScripts())
      setError(null)
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setScripts([])
      } else {
        setError(formatError(err))
      }
    } finally {
      setLoading(false)
    }
  }, [sessionLive])

  // Refresh on session change AND after every run/stop/create (the live
  // `running` flags are process-local, not persisted).
  useEffect(() => {
    setScripts([])
    setError(null)
    if (!sessionLive) return
    void load()
  }, [scanId, sessionLive, load])

  const act = useCallback(
    async (id: number, fn: () => Promise<DynamicScriptRead>) => {
      setBusyId(id)
      setError(null)
      try {
        await fn()
        await load()
        onScriptsChanged?.()
      } catch (err) {
        setError(formatError(err))
      } finally {
        setBusyId(null)
      }
    },
    [load, onScriptsChanged],
  )

  const createScript = async () => {
    const name = form.name.trim()
    const body = form.body.trim()
    if (!name || !body) {
      setFormError('Name and Frida JS body are required.')
      return
    }
    setFormBusy(true)
    setFormError(null)
    try {
      await api.dynamicCreateScript({
        name,
        body,
        description: form.description.trim() || null,
      })
      setForm({ name: '', body: '', description: '' })
      setFormOpen(false)
      await load()
      onScriptsChanged?.()
    } catch (err) {
      setFormError(formatError(err))
    } finally {
      setFormBusy(false)
    }
  }

  const proposed = scripts.filter((s) => s.origin === 'agent' && s.status === 'proposed')
  const active = scripts.filter((s) => !(s.origin === 'agent' && s.status === 'proposed'))

  return (
    <div>
      <div className="script-section-head">
        <div className="section-label" style={{ marginBottom: 0, flex: 1 }}>
          Frida scripts · {scripts.filter((s) => s.running).length} running
        </div>
        <button type="button" className="btn" onClick={() => setFormOpen((v) => !v)}>
          {formOpen ? 'Cancel' : '+ Add script manually'}
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-[4px] border border-crimson/30 bg-crimson/10 p-3 font-mono text-[11.5px] text-bone-dim">
          {error}
        </div>
      )}

      {formOpen && (
        <div className="manual-script-form open">
          <div className="field-group">
            <label className="field-label">Script name</label>
            <input
              className="field-input"
              placeholder="e.g. log-crypto-calls.js"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            />
          </div>
          <div className="field-group">
            <label className="field-label">Frida JS</label>
            <textarea
              className="field-input script-textarea"
              placeholder={'Java.perform(function () {\n  // your hook here\n});'}
              value={form.body}
              onChange={(e) => setForm((f) => ({ ...f, body: e.target.value }))}
              spellCheck={false}
            />
          </div>
          <div className="field-group">
            <label className="field-label">Description (optional)</label>
            <input
              className="field-input"
              placeholder="What this script hooks, and why"
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </div>
          {formError && <div className="field-error">{formError}</div>}
          <div className="manual-script-actions">
            <button type="button" className="btn" disabled={formBusy} onClick={() => setFormOpen(false)}>
              Cancel
            </button>
            <button type="button" className="btn btn-primary" disabled={formBusy} onClick={() => void createScript()}>
              {formBusy ? 'Saving…' : 'Save script'}
            </button>
          </div>
        </div>
      )}

      {/* M16 approval gate: proposed agent drafts are the ONLY scripts that
          never run/stop until approved. */}
      {proposed.length > 0 && (
        <>
          <div className="section-label" style={{ fontSize: 10 }}>
            Agent-authored drafts · awaiting approval
          </div>
          {proposed.map((s) => (
            <div key={s.id} className="script-card agent-draft">
              <div className="script-card-head">
                <span className="script-name">{s.name}</span>
                <span className="dep-status-tag unchecked">● proposed</span>
              </div>
              <div className="script-desc">
                {s.description || 'Agent-authored frida script — review the body, then approve to make it runnable or reject to discard.'}
              </div>
              <div className="script-actions">
                <button type="button" className="btn" onClick={() => setExpandedId(expandedId === s.id ? null : s.id)}>
                  {expandedId === s.id ? 'Hide script' : 'View script'}
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={busyId === s.id}
                  onClick={() =>
                    void act(s.id, () => api.dynamicApproveScript(s.id))
                  }
                >
                  {busyId === s.id ? '…' : 'Approve'}
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={busyId === s.id}
                  onClick={() => void act(s.id, () => api.dynamicDeleteScript(s.id).then(() => s))}
                >
                  {busyId === s.id ? '…' : 'Reject'}
                </button>
              </div>
              {expandedId === s.id && (
                <pre className="script-body">{s.script}</pre>
              )}
            </div>
          ))}
        </>
      )}

      {loading ? (
        <div className="event-empty">Loading scripts…</div>
      ) : active.length === 0 && proposed.length === 0 ? (
        <div className="event-empty">
          No scripts yet — add one manually, or ask the agent in the dock.
        </div>
      ) : (
        active.map((s) => {
          const readOnly = s.origin !== 'manual'
          const expanded = expandedId === s.id
          return (
            <div key={s.id} className="script-card">
              <div className="script-card-head">
                <span className="script-name">{s.name}</span>
                <span className={`dep-status-tag ${s.running ? 'safe' : ''}`}>
                  {s.running ? '● active' : `${ORIGIN_LABEL[s.origin] ?? s.origin}`}
                </span>
              </div>
              <div className="script-desc">
                {s.description ?? `Targets ${platform === 'ios' ? 'iOS' : 'Android'} (${ORIGIN_LABEL[s.origin] ?? s.origin}).`}
              </div>
              <div className="script-actions">
                <button type="button" className="btn" onClick={() => setExpandedId(expanded ? null : s.id)}>
                  {expanded ? 'Hide script' : 'View script'}
                </button>
                {s.running ? (
                  <button type="button" className="btn" disabled={busyId === s.id} onClick={() => void act(s.id, () => api.dynamicStopScript(s.id))}>
                    {busyId === s.id ? '…' : 'Stop'}
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={busyId === s.id}
                    title={readOnly ? 'Built-in and agent scripts run as-is' : undefined}
                    onClick={() => void act(s.id, () => api.dynamicRunScript(s.id))}
                  >
                    {busyId === s.id ? '…' : 'Run'}
                  </button>
                )}
              </div>
              {expanded && (
                <pre className="script-body">{s.script}</pre>
              )}
            </div>
          )
        })
      )}

      {!sessionLive && (
        <div className="agent-script-hint">
          <span className="mark2">✨</span>
          <span>
            Connect a device to manage scripts. Want the agent to write one?
            Ask in the dock — e.g. "generate a script that hooks the token
            refresh call and logs every request" — and it will appear above
            once you approve it.
          </span>
        </div>
      )}
    </div>
  )
}
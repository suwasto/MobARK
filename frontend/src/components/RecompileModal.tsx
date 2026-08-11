import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { formatRelative } from '../lib/format'
import type { BuildRead, BuildStage, EditRead } from '../types'

const STAGE_LABELS: Record<string, string> = {
  queued: 'Queued',
  applying: 'Applying edits',
  rebuilding: 'Rebuilding (apktool b)',
  zipping: 'Zipaligning',
  signing: 'Signing + verifying',
  done: 'Done',
}

// The live-progress pipeline (queued shows nothing active yet).
const STAGE_ORDER: BuildStage[] = [
  'applying',
  'rebuilding',
  'zipping',
  'signing',
  'done',
]

interface RecompileModalProps {
  scanId: number
  onClose: () => void
}

/**
 * M8 Phase C: Edit & recompile — the rebuild history modal.
 *
 * The persistent, un-dismissable "resigned test build" warning (decision 10)
 * is always rendered; the artifact filename + download header carry the same
 * `-resigned-test-` label (decision 9). While a build runs, the modal polls
 * its live stage; done builds stay re-downloadable (decision 8). The edits
 * list is the full history with per-applied-edit "Restore original" (revert
 * to the prior state — human-owned, never an agent action).
 */
export function RecompileModal({ scanId, onClose }: RecompileModalProps) {
  const [builds, setBuilds] = useState<BuildRead[]>([])
  const [edits, setEdits] = useState<EditRead[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)

  const activeBuild =
    builds.find((b) => b.status === 'queued' || b.status === 'running') ?? null
  const newest = builds[0] ?? null

  // Escape dismisses + body scroll lock (same contract as Settings/Progress).
  useEffect(() => {
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
  }, [onClose])

  // Initial load of both histories.
  useEffect(() => {
    let cancelled = false
    setLoading(true)
    Promise.all([api.listBuilds(scanId), api.listEdits(scanId)])
      .then(([bs, es]) => {
        if (!cancelled) {
          setBuilds(bs)
          setEdits(es)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId])

  // Poll the active build's live stage; on settle, refresh both lists so the
  // history (and each consumed edit's build_id stamp) is current.
  const activeId = activeBuild?.id ?? null
  const activeStatus = activeBuild?.status ?? null
  useEffect(() => {
    if (!activeId) return
    let cancelled = false
    const tick = async () => {
      try {
        const next = await api.getBuild(scanId, activeId)
        if (cancelled) return
        setBuilds((prev) => prev.map((b) => (b.id === next.id ? next : b)))
        if (next.status === 'done' || next.status === 'failed') {
          const [bs, es] = await Promise.all([
            api.listBuilds(scanId),
            api.listEdits(scanId),
          ])
          if (!cancelled) {
            setBuilds(bs)
            setEdits(es)
          }
        }
      } catch {
        // Transient poll failure — the next tick retries.
      }
    }
    const id = window.setInterval(tick, 2000)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [scanId, activeId, activeStatus])

  const startRebuild = async () => {
    setStarting(true)
    setError(null)
    try {
      const b = await api.triggerRebuild(scanId)
      setBuilds((prev) => [b, ...prev])
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setStarting(false)
    }
  }

  const restoreEdit = async (edit: EditRead) => {
    setError(null)
    try {
      const updated = await api.revertEdit(scanId, edit.id)
      setEdits((prev) => prev.map((e) => (e.id === updated.id ? updated : e)))
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const appliedCount = edits.filter((e) => e.status === 'applied').length
  const activeStageIdx = activeBuild
    ? STAGE_ORDER.indexOf(activeBuild.stage as BuildStage)
    : -1

  return (
    <div
      className="modal-overlay"
      onMouseDown={(e) => {
        // Backdrop click dismisses — the build keeps running server-side and
        // the modal resumes live when reopened.
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        className="modal recompile-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Edit & recompile"
      >
        <div className="modal-head">
          <div className="modal-title">Edit &amp; recompile</div>
          <button
            type="button"
            className="modal-close"
            aria-label="Close"
            title="Close (a running build keeps going in the background)"
            onClick={onClose}
          >
            ×
          </button>
        </div>

        <div className="modal-body">
          {/* Persistent, un-dismissable test-build label (decision 10). */}
          <div className="recompile-warn" role="note">
            <strong>⚠ Resigned test build.</strong> The rebuilt APK is signed
            with MASA&rsquo;s install-scoped test keystore — not the app&rsquo;s
            original certificate. Install only on a test device. The artifact
            filename always carries the <code>-resigned-test-</code> label.
          </div>

          {error && (
            <div className="recompile-error">
              <strong>Something went wrong.</strong> {error}
            </div>
          )}

          {/* Build action */}
          <div className="recompile-action">
            <div className="min-w-0">
              <div className="recompile-action-title">Build a new APK</div>
              <div className="recompile-action-sub">
                {appliedCount === 0
                  ? 'No applied edits — this rebuilds the pristine decoded tree.'
                  : `${appliedCount} applied edit${appliedCount === 1 ? '' : 's'} are overlaid onto a fresh copy of the decoded tree.`}{' '}
                The baseline never changes.
              </div>
            </div>
            <button
              type="button"
              className="btn btn-primary recompile-go"
              disabled={!!activeBuild || starting}
              onClick={startRebuild}
              title={
                activeBuild
                  ? `Build #${activeBuild.id} is running — one build at a time`
                  : 'Recompile with the current applied edits'
              }
            >
              {starting ? 'Starting…' : activeBuild ? 'Building…' : 'Recompile'}
            </button>
          </div>

          {/* Live build */}
          {activeBuild && (
            <div className="recompile-live">
              <div className="recompile-live-head">
                <span className="build-chip running">build #{activeBuild.id}</span>
                <span className="recompile-stage">
                  {STAGE_LABELS[activeBuild.stage] ?? activeBuild.stage}
                </span>
                <span className="smali-spin" aria-hidden="true" />
              </div>
              <div className="recompile-stages">
                {STAGE_ORDER.map((s, i) => (
                  <div
                    key={s}
                    className={`recompile-stage-dot${
                      activeStageIdx >= i ? ' on' : ''
                    }${activeStageIdx === i ? ' active' : ''}`}
                    title={STAGE_LABELS[s]}
                  />
                ))}
                <span className="recompile-stage-note">
                  {STAGE_LABELS[activeBuild.stage] ?? activeBuild.stage}
                </span>
              </div>
            </div>
          )}

          {/* Newest finished build result */}
          {!activeBuild && newest?.status === 'failed' && (
            <div className="recompile-live failed">
              <div className="recompile-live-head">
                <span className="build-chip failed">build #{newest.id} failed</span>
                <span className="recompile-stage">
                  at {STAGE_LABELS[newest.stage] ?? newest.stage}
                </span>
              </div>
              <pre className="recompile-error-detail">
                {newest.error ?? 'no error detail recorded'}
              </pre>
              <button
                type="button"
                className="btn"
                onClick={startRebuild}
                disabled={starting}
              >
                ↻ Retry rebuild
              </button>
            </div>
          )}
          {!activeBuild && newest?.status === 'done' && (
            <div className="recompile-live done">
              <div className="recompile-live-head">
                <span className="build-chip done">build #{newest.id} done</span>
                <a
                  className="recompile-download"
                  href={api.buildDownloadUrl(scanId, newest.id)}
                  download={newest.artifact_name ?? undefined}
                >
                  ⬇ Download {newest.artifact_name}
                </a>
              </div>
              {newest.artifact_sha256 && (
                <div className="recompile-sha">
                  sha256{' '}
                  <code>
                    {newest.artifact_sha256.slice(0, 16)}…{newest.artifact_sha256.slice(-8)}
                  </code>
                </div>
              )}
            </div>
          )}

          {/* Builds history */}
          <div className="recompile-section">
            <div className="section-label">Builds</div>
            {loading ? (
              <div className="recompile-empty">Loading build history…</div>
            ) : builds.length === 0 ? (
              <div className="recompile-empty">
                No rebuilds yet — every attempt stays here, and a done
                artifact can be re-downloaded at any time.
              </div>
            ) : (
              <div className="recompile-rows">
                {builds.map((b) => (
                  <div key={b.id} className={`recompile-row ${b.status}`}>
                    <span className={`build-chip ${b.status}`}>{b.status}</span>
                    <div className="recompile-row-main">
                      <div className="recompile-row-title">
                        Build #{b.id} · {STAGE_LABELS[b.stage] ?? b.stage} ·{' '}
                        {b.edit_ids.length} edit
                        {b.edit_ids.length === 1 ? '' : 's'}
                      </div>
                      {b.status === 'done' && b.artifact_name && (
                        <a
                          className="recompile-download small"
                          href={api.buildDownloadUrl(scanId, b.id)}
                          download={b.artifact_name}
                        >
                          ⬇ {b.artifact_name}
                        </a>
                      )}
                    </div>
                    <span className="recompile-row-date">
                      {formatRelative(b.created_at)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Edits history */}
          <div className="recompile-section">
            <div className="section-label">Edits</div>
            {loading ? (
              <div className="recompile-empty">Loading edit history…</div>
            ) : edits.length === 0 ? (
              <div className="recompile-empty">
                No edits yet — open a smali / res / manifest file in the
                decompiler and save with Ctrl/Cmd+S.
              </div>
            ) : (
              <div className="recompile-rows">
                {edits.map((e) => (
                  <div key={e.id} className={`recompile-row ${e.status}`}>
                    <span className={`edit-chip ${e.status}`}>{e.status}</span>
                    <div className="recompile-row-main">
                      <div className="recompile-row-title mono">{e.file_path}</div>
                      <div className="recompile-row-sub">
                        {e.source === 'agent' ? 'agent proposal' : 'manual'}
                        {e.instruction ? ` · “${e.instruction}”` : ''}
                        {e.build_id ? ` · built in #${e.build_id}` : ''}
                      </div>
                    </div>
                    {e.status === 'applied' && (
                      <button
                        type="button"
                        className="link-btn"
                        title="Revert this edit — the effective content falls back to the previous applied edit (or the baseline)"
                        onClick={() => restoreEdit(e)}
                      >
                        Restore original
                      </button>
                    )}
                    <span className="recompile-row-date">
                      {formatRelative(e.created_at)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

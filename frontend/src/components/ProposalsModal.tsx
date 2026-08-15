import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { formatRelative } from '../lib/format'
import type { EditRead } from '../types'

interface ProposalsModalProps {
  scanId: number
  /** The agent edit proposals (status === 'proposed') awaiting review. */
  proposals: EditRead[]
  onClose: () => void
  /** Called after an Apply/Reject lands so the parent refetches + re-counts. */
  onChanged: () => void
}

/** One unified-diff line -> a colored class (git-style diff coloring). */
function diffLineClass(line: string): string {
  if (line.startsWith('@@')) return 'pr-line hunk'
  if (line.startsWith('+')) return 'pr-line add'
  if (line.startsWith('-')) return 'pr-line del'
  return 'pr-line ctx'
}

/** Per-proposal review card: instruction + lazy diff + Apply/Reject. */
function ProposalCard({
  scanId,
  proposal,
  onChanged,
  onError,
}: {
  scanId: number
  proposal: EditRead
  onChanged: () => void
  onError: (msg: string) => void
}) {
  const [diff, setDiff] = useState<string | null>(null)
  const [diffError, setDiffError] = useState<string | null>(null)
  const [busy, setBusy] = useState<'apply' | 'reject' | null>(null)

  // Lazy diff fetch on first mount of the card (the review surface, D7).
  useEffect(() => {
    let cancelled = false
    api
      .editDiff(scanId, proposal.id)
      .then((d) => {
        if (!cancelled) setDiff(d.diff)
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setDiffError(err instanceof Error ? err.message : String(err))
      })
    return () => {
      cancelled = true
    }
  }, [scanId, proposal.id])

  const act = async (kind: 'apply' | 'reject') => {
    setBusy(kind)
    try {
      if (kind === 'apply') {
        await api.applyEdit(scanId, proposal.id)
      } else {
        await api.rejectEdit(scanId, proposal.id)
      }
      onChanged()
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  const lines = diff ? diff.split('\n') : []

  return (
    <div className="proposal-card">
      <div className="proposal-head">
        <span className={`edit-chip ${proposal.status}`}>{proposal.status}</span>
        <span className="proposal-file">{proposal.file_path}</span>
        <span className="proposal-date">{formatRelative(proposal.created_at)}</span>
      </div>
      {proposal.instruction && (
        <div className="proposal-instruction">“{proposal.instruction}”</div>
      )}
      <div className="proposal-diff" role="region" aria-label={`Diff for ${proposal.file_path}`}>
        {diffError ? (
          <div className="proposal-diff-error">{diffError}</div>
        ) : diff === null ? (
          <div className="proposal-diff-loading">Loading diff…</div>
        ) : lines.length === 0 ? (
          <div className="proposal-diff-empty">(no diff recorded)</div>
        ) : (
          lines.map((line, i) => (
            <div key={i} className={diffLineClass(line)}>
              {line || ' '}
            </div>
          ))
        )}
      </div>
      <div className="proposal-actions">
        <span className="proposal-hint">
          The agent never applies edits - you own this decision per file.
        </span>
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy != null}
          onClick={() => void act('apply')}
          title="Apply this edit - it becomes part of the effective content (and of the next rebuild)"
        >
          {busy === 'apply' ? 'Applying…' : '✓ Apply'}
        </button>
        <button
          type="button"
          className="btn"
          disabled={busy != null}
          onClick={() => void act('reject')}
          title="Reject this proposal - it is discarded"
        >
          {busy === 'reject' ? 'Rejecting…' : '✗ Reject'}
        </button>
      </div>
    </div>
  )
}

/**
 * M8 Phase D: diff-review modal - the human review surface for agent edit
 * proposals (decision 7: apply/reject/revert are human API calls, never
 * agent tools). One agent turn may propose several files; each is reviewed
 * file-by-file (D7) with its own unified diff and Apply/Reject. Applying an
 * edit stacks it on the effective content (the decompiler editor picks it up
 * on next open); rejecting discards the proposal.
 */
export function ProposalsModal({
  scanId,
  proposals,
  onClose,
  onChanged,
}: ProposalsModalProps) {
  const [error, setError] = useState<string | null>(null)

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

  return (
    <div
      className="modal-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        className="modal proposals-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Review agent edit proposals"
      >
        <div className="modal-head">
          <div className="modal-title">
            Review edits ({proposals.length})
          </div>
          <button
            type="button"
            className="modal-close"
            aria-label="Close"
            onClick={onClose}
          >
            ×
          </button>
        </div>

        <div className="modal-body">
          {error && (
            <div className="recompile-error">
              <strong>Something went wrong.</strong> {error}
            </div>
          )}
          <p className="proposals-intro">
            These are <strong>agent proposals</strong> - stored as diffs, never
            applied automatically. Review each file and Apply or Reject it.
            Applied edits join the effective content and are compiled by the
            next <strong>Edit &amp; recompile</strong> (signed with MobARK&rsquo;s
            test keystore).
          </p>
          {proposals.length === 0 ? (
            <div className="recompile-empty">
              No pending proposals - the agent&rsquo;s edit suggestions have all
              been reviewed.
            </div>
          ) : (
            proposals.map((p) => (
              <ProposalCard
                key={p.id}
                scanId={scanId}
                proposal={p}
                onChanged={() => {
                  setError(null)
                  onChanged()
                }}
                onError={setError}
              />
            ))
          )}
        </div>
      </div>
    </div>
  )
}

import { useEffect, useRef, useState } from 'react'
import { api } from '../../api/client'
import type { EditRead } from '../../types'

interface CodeEditorProps {
  scanId: number
  /** Full tree path (content fetch - returns the effective content with the
   * newest applied edit overlaid). */
  contentPath: string
  /** apktool-root-relative path (POST /edits). */
  editPath: string
  onSaved?: (edit: EditRead) => void
}

/** Empty prompt while no content is loaded. */
function EditorLoading() {
  return (
    <div className="code-pane code-editor">
      <div className="editor-body">
        <div className="px-[18px] py-3 font-mono text-[11px] text-bone-faint">
          Loading editable file…
        </div>
      </div>
    </div>
  )
}

/**
 * M8 Phase B plaintext editor for editable paths (smali, res/, the decoded
 * AndroidManifest.xml). No editor dependency - a line-numbered textarea (hljs
 * lacks a smali grammar anyway). Dirty tracking, Ctrl/Cmd+S -> POST /edits
 * (stored as a reviewable DB diff; the on-disk apktool tree never changes),
 * and a save-status row. The gutter follows the textarea's scroll exactly
 * (same line-height/metrics), so line numbers stay aligned.
 */
export function CodeEditor({ scanId, contentPath, editPath, onSaved }: CodeEditorProps) {
  // Effective content straight from the server (baseline + applied edits).
  const [loaded, setLoaded] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [justSaved, setJustSaved] = useState(false)
  const [scrollTop, setScrollTop] = useState(0)
  const areaRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    setSaveError(null)
    setJustSaved(false)
    setScrollTop(0)
    // NOTE: switching files discards any unsaved draft (the dirty indicator
    // + Ctrl/Cmd+S are the affordance - a confirm dialog is Phase D polish).
    api
      .getFileContent(scanId, contentPath)
      .then((d) => {
        if (cancelled) return
        setLoaded(d.content)
        setDraft(d.content)
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
  }, [scanId, contentPath])

  const dirty = loaded != null && draft !== loaded

  const save = async () => {
    if (!dirty || saving) return
    setSaving(true)
    setSaveError(null)
    try {
      const edit = await api.createEdit(scanId, {
        file_path: editPath,
        content: draft,
      })
      setLoaded(draft) // the effective baseline is now what we saved
      setJustSaved(true)
      window.setTimeout(() => setJustSaved(false), 1800)
      onSaved?.(edit)
    } catch (err: unknown) {
      setSaveError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }
  // The keydown handler is registered once; the ref always holds the latest
  // save closure so Ctrl/Cmd+S never saves stale content.
  const saveRef = useRef(save)
  saveRef.current = save
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== 's') return
      // Only when the editor itself has focus: the dashboard keeps every
      // tab's panel mounted (hidden, not unmounted), so a global Cmd+S would
      // otherwise save a background editor and block the browser's native
      // Save-page dialog while the user is on any other tab (review catch).
      if (document.activeElement !== areaRef.current) return
      e.preventDefault()
      void saveRef.current()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const lineCount = (draft || loaded || '').split('\n').length
  const gutterLines = Array.from({ length: lineCount }, (_, i) => i + 1).join('\n')

  if (loading) return <EditorLoading />

  return (
    <div className="code-pane code-editor">
      <div className="code-file-path editor-path">
        {contentPath}
        <span className="edit-badge">editable</span>
      </div>

      {error && (
        <div className="mx-[18px] my-3 rounded border border-crimson/30 bg-crimson/10 p-3 font-mono text-[11px] text-bone-dim">
          {error}
        </div>
      )}
      {!error && (
        <div className="editor-body">
          <div className="editor-gutter" aria-hidden="true">
            <pre style={{ transform: `translateY(${-scrollTop}px)` }}>
              {gutterLines}
            </pre>
          </div>
          <textarea
            ref={areaRef}
            className="editor-textarea"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
            spellCheck={false}
            wrap="off"
            aria-label={`Edit ${contentPath}`}
          />
        </div>
      )}

      <div className="editor-status">
        {saveError ? (
          <span className="editor-save-error">{saveError}</span>
        ) : justSaved ? (
          <span className="editor-saved-flash">Saved ✓</span>
        ) : dirty ? (
          <span className="editor-dirty">Unsaved changes</span>
        ) : (
          <span className="editor-clean">Up to date</span>
        )}
        <span className="editor-save-hint">
          {saving ? 'Saving…' : 'Ctrl/Cmd+S to save · stored as a reviewable diff'}
        </span>
      </div>
    </div>
  )
}

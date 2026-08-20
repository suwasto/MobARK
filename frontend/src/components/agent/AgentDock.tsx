import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../../api/client'
import type {
  ChatSession,
  EditReviewResult,
  FileNode,
  FileTreeRoot,
  ScanRead,
} from '../../types'
import { useChat, type ChatMessage, type ToolStep } from '../../hooks/useChat'
import { useApp } from '../../state/AppContext'
import { Markdown } from '../Markdown'

/** M8 follow-up: @-mention of a file in the dock. The user types `@` to
 * open a picker over the scan's decompiler tree; selecting inserts a
 * `@path` token (tree path, e.g. `@sources/com/foo/AuthManager.java`) into
 * the draft. On send the tokens are extracted into `mentioned_files` - the
 * backend attaches the files' current content to the agent context, so the
 * model answers / proposes edits about them directly (no search round).
 * Mentions render as removable chips above the input and clickable chips in
 * the sent bubble (open in Decompiler).
 *
 * Every real tree path is `<root>/<rel>` - it ALWAYS contains a `/` - so
 * requiring one here keeps ordinary prose like `user@example.com` from
 * becoming a bogus chip (review catch). */
const MENTION_RE = /@([A-Za-z0-9_./-]+\/[A-Za-z0-9_./-]+\.[a-z0-9]+)/g

/** Flatten the decompiler tree into full tree paths (root-prefixed) for the
 * mention picker - files only, binary blobs (iOS) excluded (they can't be
 * read anyway). */
function flattenFilePaths(roots: FileTreeRoot[]): string[] {
  const out: string[] = []
  const walk = (nodes: FileNode[], root: string) => {
    for (const n of nodes) {
      if (n.type === 'file' && !n.binary) out.push(`${root}/${n.path}`)
      if (n.children && n.children.length > 0) walk(n.children, root)
    }
  }
  for (const r of roots) walk(r.tree, r.name)
  return out
}

/** Extract the @-mentioned tree paths from a draft/message (deduped). */
function mentionedFrom(text: string): string[] {
  const out: string[] = []
  for (const m of text.matchAll(MENTION_RE)) {
    if (!out.includes(m[1])) out.push(m[1])
  }
  return out
}

interface AgentDockProps {
  scan: ScanRead
  /** Static greeting numbers (total findings + high-severity count). */
  greeting: { total: number; high: number }
  collapsed: boolean
  onToggleCollapsed: () => void
  /** A citation was clicked - jump the Decompiler tab to that file. */
  onOpenFile: (file: string) => void
  /** M8 Phase D (moved here Aug 11 - the dock chat is the agent edit
   * surface): the agent can propose edits (search_code ->
   * find_smali_sibling -> read_editable_file -> propose_smali_edit). The
   * shared review modal lives in DashboardView; this dock shows a
   * "Review edits (n)" pill when proposals await, and auto-opens the modal
   * the moment a propose_smali_edit step succeeds (the plan's "the returned
   * proposal opens the diff review panel"). */
  proposedCount: number
  onReviewProposals: () => void
  /** Dependencies tab "Check known CVEs" -> pre-fill the draft (nonce so
   * every click lands, even for the same dependency twice). Known-CVE
   * research is the M7 web-research surface - the agent searches when the
   * scan's 🌐 Web toggle is on, else it answers from local context. */
  presetDraft?: { text: string; nonce: number } | null
  /** M8 follow-up (Aug 16): bumped by the dashboard with the apply/reject
   * response the moment the user resolves a proposal. The BACKEND owns what
   * happens next (from the scan's task-list artifact): `paused` -> the
   * rejection stops the loop (the pause message is appended as an agent
   * note); `next_task_pending` -> the next task's proposal turn starts
   * itself (advance stream, no fake "continue" text); `task_complete` ->
   * the task list is exhausted, one wrap-up summary closes the task. */
  reviewSignal?: { nonce: number; result: EditReviewResult } | null
}

/** Compact args summary for a step row (first 2 keys, values truncated). */
function summarizeArgs(args: Record<string, unknown>): string {
  const entries = Object.entries(args)
  if (entries.length === 0) return ''
  const parts = entries.slice(0, 2).map(([k, v]) => {
    const s = typeof v === 'string' ? v : JSON.stringify(v)
    return `${k}: ${s.length > 40 ? `${s.slice(0, 40)}…` : s}`
  })
  return parts.join(', ')
}

/** file:line references inside a tool result - clickable Decompiler jumps. */
const FILE_REF_RE =
  /([A-Za-z0-9_./-]+\.(?:java|xml|kt|kts|smali|swift|m|h|plist|json|txt|properties|yml|yaml|html|strings|entitlements))(?::(\d+))?/g

/**
 * Shorten a long file path for a chip while keeping the part that matters -
 * the tail (filename:line, what you click to jump) - visible. Middle-ellipsis
 * like the file tree: a trimmed head + `…` + the kept tail. The full path
 * stays in the chip's tooltip. Belt-and-braces with the CSS floor on
 * `.src-chip` (max-width + ellipsis): nothing can ever escape the bubble.
 */
function shortenPath(path: string, max = 38): string {
  if (path.length <= max) return path
  const tailLen = Math.max(16, Math.floor(max * 0.6))
  const headLen = Math.max(2, max - tailLen - 1)
  return `${path.slice(0, headLen)}…${path.slice(-tailLen)}`
}

function ResultFileChips({
  text,
  onOpenFile,
}: {
  text: string
  onOpenFile: (file: string) => void
}) {
  const refs = useMemo(() => {
    const out: Array<{ file: string; line: number | null }> = []
    for (const m of text.matchAll(FILE_REF_RE)) {
      const file = m[1]
      if (!out.some((r) => r.file === file && r.line === (m[2] ? Number(m[2]) : null))) {
        out.push({ file, line: m[2] ? Number(m[2]) : null })
      }
      if (out.length >= 4) break
    }
    return out
  }, [text])
  if (refs.length === 0) return null
  return (
    <div className="src-row" style={{ marginTop: 6 }}>
      {refs.map((r) => {
        const full = `${r.file}${r.line != null ? `:${r.line}` : ''}`
        return (
          <button
            key={full}
            type="button"
            className="src-chip"
            title={`${full} - open in Decompiler`}
            onClick={() => onOpenFile(r.file)}
          >
            {shortenPath(full)}
          </button>
        )
      })}
    </div>
  )
}

const StepRow = memo(function StepRow({
  step,
  onOpenFile,
}: {
  step: ToolStep
  onOpenFile: (file: string) => void
}) {
  const [open, setOpen] = useState(false)
  const done = step.status !== 'running'
  // Errors auto-expand so the message is visible without a click.
  const expanded = open || step.status === 'error'
  const statusIcon = step.status === 'running' ? '◌' : step.status === 'ok' ? '✓' : '✗'
  // M8 follow-up: the expanded result preview is its own height-capped
  // scroll box (140px) - pin it to the bottom when the result lands/grows
  // or the row expands, so the newest content is visible without the user
  // scrolling. Running rows are never expanded (heads ignore clicks until
  // done), so there is no fight with a live stream here.
  const resultRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!expanded) return
    const el = resultRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [expanded, step.resultPreview])
  return (
    <div className={`step-row ${step.status}`}>
      <button
        type="button"
        className="step-head"
        onClick={() => done && setOpen((v) => !v)}
        aria-expanded={expanded}
      >
        <span className={`step-status ${step.status}`}>{statusIcon}</span>
        <span className="step-name">{step.name}</span>
        <span className="step-args">{summarizeArgs(step.args)}</span>
        {done && (
          <span className="step-meta">
            {step.count != null && `${step.count} result${step.count === 1 ? '' : 's'}`}
            {step.count != null && step.durationMs != null && ' · '}
            {step.durationMs != null && `${step.durationMs}ms`}
          </span>
        )}
      </button>
      {expanded && (
        <div className="step-detail">
          {Object.keys(step.args).length > 0 && (
            <pre className="step-json">{JSON.stringify(step.args, null, 2)}</pre>
          )}
          {step.error && <div className="step-error">{step.error}</div>}
          {step.resultPreview && (
            <>
              <ResultFileChips text={step.resultPreview} onOpenFile={onOpenFile} />
              <div className="step-result" ref={resultRef}>
                <pre>{step.resultPreview}</pre>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
})

function Steps({ steps, onOpenFile }: { steps: ToolStep[]; onOpenFile: (file: string) => void }) {
  if (steps.length === 0) return null
  return (
    <details className="tools-trace">
      <summary>Tools ({steps.length})</summary>
      <div className="tools-trace-body">
        {steps.map((s) => (
          <StepRow key={s.id} step={s} onOpenFile={onOpenFile} />
        ))}
      </div>
    </details>
  )
}

/** M8 follow-up: the specialized thinking box - reasoning/thinking tokens
 * stream into a muted, inset block ABOVE the answer (the standard AI-agent
 * thinking display: the model thinks first, then answers). No blinking
 * caret inside - the caret belongs to the final answer only; the animated
 * dots run while thinking is in progress but no token has landed yet.
 *
 * While streaming the box stays open (live tokens) - ENFORCED, not just
 * defaulted: the summary stops the browser's native details toggle
 * (preventDefault) while the turn is live, because the box must keep
 * scrolling to the newest reasoning as tool calls start and the answer
 * streams. A FINALIZED message is collapsed by default to the
 * ChatGPT/Claude "Thinking" summary with a Show reasoning / Hide reasoning
 * affordance on the right - the full text is one click away instead of
 * crowding the answer. State (not the DOM default) drives the toggle so the
 * click sticks across re-renders. */
function ThinkingBox({
  text,
  active,
  finalized = false,
  note = false,
}: {
  text: string
  active: boolean
  finalized?: boolean
  /** M8 follow-up: a model that appeared to think (dots shown) but exposed
   * no readable reasoning (Gemini 3.x etc.) - render the quiet fallback
   * note instead of the show/hide affordance, since there is nothing to
   * reveal. Ignored when text exists (the real box wins). */
  note?: boolean
}) {
  const [open, setOpen] = useState(!finalized)
  const hasText = text.length > 0
  // M8 follow-up: the box is height-capped and scrolls internally - pin the
  // reasoning text to the bottom whenever NEW tokens land (streaming, even
  // after the answer text has started - the box may outlive `active`) so
  // the newest reasoning is always visible without the user scrolling.
  const textRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = textRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [text])
  // Collapse/expand: re-pin on (re)open so the latest reasoning is in view
  // instead of the top of the reasoning text.
  useEffect(() => {
    if (!open) return
    const el = textRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [open])
  if (!hasText && !active && !note) return null
  if (note && !hasText && !active) {
    return (
      <div className="thinking-box thinking-note-box">
        <span className="thinking-head thinking-note-head">
          Thinking
          <span className="thinking-note-copy">
            this model didn&rsquo;t expose its reasoning
          </span>
        </span>
      </div>
    )
  }
  return (
    <details
      className="thinking-box"
      // While the turn is live the box is ALWAYS open - `active` (the dots
      // flag) goes false the moment tool calls or the answer start, and the
      // reasoning may still be streaming into the box. Only a FINALIZED box
      // is collapsed by default (state-driven expand/collapse).
      open={!finalized || (open && hasText)}
      onToggle={(e) => {
        if (finalized) setOpen((e.currentTarget as HTMLDetailsElement).open)
      }}
    >
      <summary
        className="thinking-head"
        onClick={(e) => {
          // Stop the browser's native details toggle while the turn is
          // live - the box must stay open so the reasoning stream stays
          // visible and pinned. (A click collapsing it here used to leave
          // the details closed with the `open` prop still true - React
          // never re-writes an unchanged prop - so the rest of the turn's
          // reasoning streamed into an invisible box and the box appeared
          // to stop scrolling.)
          if (!finalized) e.preventDefault()
        }}
      >
        <span className={`thinking-label${active && !hasText ? ' thinking-dots' : ''}`}>
          Thinking
        </span>
        {finalized && (
          <span className="thinking-reveal">
            <span
              className={`thinking-chev${open ? ' open' : ''}`}
              aria-hidden="true"
            >
              ▸
            </span>
            {open ? 'Hide reasoning' : 'Show reasoning'}
          </span>
        )}
      </summary>
      {hasText && (
        <div className="thinking-text" ref={textRef}>
          {text}
        </div>
      )}
    </details>
  )
}

/** M8 follow-up: render a user message with @-mentions as clickable chips
 * (jump the Decompiler), splitting the content around each mention token. */
function UserBubble({
  message,
  onOpenFile,
}: {
  message: ChatMessage
  onOpenFile: (file: string) => void
}) {
  const parts = useMemo(() => {
    const text = message.content
    const out: Array<{ kind: 'text' | 'mention'; value: string }> = []
    let last = 0
    for (const m of text.matchAll(MENTION_RE)) {
      const idx = m.index ?? 0
      if (idx > last) out.push({ kind: 'text', value: text.slice(last, idx) })
      out.push({ kind: 'mention', value: m[1] })
      last = idx + m[0].length
    }
    if (last < text.length) out.push({ kind: 'text', value: text.slice(last) })
    return out
  }, [message.content])
  return (
    <div className="msg user">
      {parts.map((p, i) =>
        p.kind === 'mention' ? (
          <button
            key={i}
            type="button"
            className="src-chip mention-chip-inline"
            title={`${p.value} - open in Decompiler`}
            onClick={() => onOpenFile(p.value)}
          >
            @{shortenPath(p.value)}
          </button>
        ) : (
          <span key={i}>{p.value}</span>
        ),
      )}
    </div>
  )
}

const AgentMessage = memo(function AgentMessage({
  message,
  send,
  onOpenFile,
}: {
  message: ChatMessage
  send: (q: string, mentionedFiles?: string[]) => void
  onOpenFile: (file: string) => void
}) {
  const handleRetry = useCallback(() => {
    if (message.retryQuestion) send(message.retryQuestion, message.mentionedFiles)
  }, [message.retryQuestion, message.mentionedFiles, send])
  if (message.role === 'user') {
    return <UserBubble message={message} onOpenFile={onOpenFile} />
  }
  return (
    <div className={`msg ai${message.errorKind ? ' error' : ''}`}>
      <span className="msg-tag">
        {message.errorKind ? 'Agent · failed' : 'Agent'}
      </span>
      {message.thinking ? (
        <ThinkingBox text={message.thinking} active={false} finalized />
      ) : message.thinkingAttempted ? (
        <ThinkingBox text="" active={false} finalized note />
      ) : null}
      <Markdown text={message.content} />

      {message.toolMode === 'context-only' && (
        <span className="tool-mode-tag">answered from findings context</span>
      )}

      {message.citations && message.citations.length > 0 && (
        <div className="src-row" aria-label="Sources cited by the agent">
          {message.citations.map((c, i) => {
            const full = `${c.file}${c.line != null ? `:${c.line}` : ''}`
            return (
              <button
                key={`${c.file}:${c.line ?? ''}:${i}`}
                type="button"
                className="src-chip"
                title={c.snippet ? `${full} - ${c.snippet}` : `${full} - open in Decompiler`}
                onClick={() => onOpenFile(c.file)}
              >
                {shortenPath(full)}
              </button>
            )
          })}
        </div>
      )}

      {message.steps && message.steps.length > 0 && (
        <Steps steps={message.steps} onOpenFile={onOpenFile} />
      )}

      {message.errorKind && message.retryQuestion && (
        <div className="mt-3 border-t border-line-soft pt-2.5">
          <button type="button" className="link-btn" onClick={handleRetry}>
            Retry
          </button>
        </div>
      )}
    </div>
  )
})

/**
 * Agent dock (Phase G + M6 follow-up): right-hand chat rail over the SSE
 * stream `POST /scans/{id}/chat/stream`. While a turn runs, token text
 * streams live with a blinking caret and tool steps appear as they execute;
 * on completion the steps collapse into a persistent "Tools (n)" trace.
 * Collapsible to a 44px rail (mockup `.body` grid); web research toggle is a
 * disabled M7 placeholder. Citation + result file chips jump the Decompiler
 * tab via `onOpenFile`.
 */
export function AgentDock({
  scan,
  greeting,
  collapsed,
  onToggleCollapsed,
  onOpenFile,
  proposedCount,
  onReviewProposals,
  presetDraft,
  reviewSignal,
}: AgentDockProps) {
  const {
    messages,
    pending,
    sending,
    sessions,
    activeSessionId,
    sessionsLoading,
    send,
    stop,
    switchSession,
    newSession,
    deleteSession,
    renameSession,
    advance,
    completeTask,
    appendNote,
  } = useChat(scan.id)
  const { backends, searchBackends, actions } = useApp()
  const [draft, setDraft] = useState('')
  const bodyRef = useRef<HTMLDivElement>(null)
  // M8 follow-up: the live tool trace is its own height-capped scroll
  // container (240px) - pin it to the bottom as steps land so the newest
  // step is always visible without the user scrolling.
  const stepsTraceRef = useRef<HTMLDivElement>(null)
  // M8 follow-up: the @-mention file picker. Typing `@` opens a dropdown
  // over the scan's decompiler tree (flattened once, lazily - the payload is
  // the full multi-MB tree, so it's fetched only on the first mention);
  // selecting inserts a `@path` token at the `@` position.
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const [mentionOpen, setMentionOpen] = useState(false)
  const [mentionQuery, setMentionQuery] = useState('')
  const [mentionIdx, setMentionIdx] = useState(0)
  const mentionStartRef = useRef(0) // draft index of the '@' being typed
  const [filePaths, setFilePaths] = useState<string[] | null>(null)
  const filePathsLoaded = useRef(false)
  // M8 Phase D: the edit tools are only offered once the on-demand apktool
  // decode is ready (edit_tools_allowed) - on a fresh Android scan the dock
  // shows a small hint pointing at the Decompiler's Smali chip, so the
  // headline "disable password validation in authentication" flow is
  // discoverable. Best-effort fetch; a failure just hides the hint. The
  // status is RE-CHECKED on a timer while the hint is visible: the decode is
  // triggered from the Decompiler's Smali chip and completes on its own
  // timeline, so the hint must disappear the moment the tree is ready
  // WITHOUT a page refresh (the old one-shot fetch kept the stale warning
  // until the dock remounted - the bug report: "warning not gone when smali
  // ready, need refresh to dismiss").
  const [decodeReady, setDecodeReady] = useState<boolean | null>(null)
  useEffect(() => {
    // The dock is keyed per scan (DashboardView), so `null` here always
    // means "fresh scan, status unknown" - the hint stays hidden until the
    // first check lands. Stop entirely once ready (or collapsed): nothing
    // left to dismiss.
    if (scan.platform !== 'android' || collapsed || decodeReady === true) return
    let cancelled = false
    const check = () =>
      api
        .smaliStatus(scan.id)
        .then((s) => {
          if (!cancelled) setDecodeReady(s.status === 'ready')
        })
        .catch(() => {
          // Transient - keep polling; the hint hides once a status lands.
        })
    check()
    const t = window.setInterval(check, 2000)
    return () => {
      cancelled = true
      window.clearInterval(t)
    }
  }, [scan.id, scan.platform, collapsed, decodeReady])
  // M8 follow-up: lazily load the flattened file tree on the first mention
  // (the full tree payload is heavy - never fetched at mount).
  useEffect(() => {
    if (!mentionOpen || filePathsLoaded.current) return
    filePathsLoaded.current = true
    let cancelled = false
    api
      .getFiles(scan.id)
      .then((res) => {
        if (!cancelled) setFilePaths(flattenFilePaths(res.roots))
      })
      .catch(() => {
        if (!cancelled) setFilePaths([]) // picker just finds nothing
      })
    return () => {
      cancelled = true
    }
  }, [mentionOpen, scan.id])

  // Filtered mention candidates (substring, capped for the dropdown).
  const mentionMatches = useMemo(() => {
    if (!filePaths) return []
    const q = mentionQuery.toLowerCase()
    const hits = q ? filePaths.filter((p) => p.toLowerCase().includes(q)) : filePaths
    return hits.slice(0, 40)
  }, [filePaths, mentionQuery])

  // Selection resets when the query changes (keeps the arrow keys sane).
  useEffect(() => {
    setMentionIdx(0)
  }, [mentionQuery])

  // The mention tokens currently in the draft - the removable chip row above
  // the input + the `mentioned_files` sent with the question.
  const draftMentions = useMemo(() => mentionedFrom(draft), [draft])

  // M8 Phase D: auto-open the shared review modal the moment a turn lands a
  // successful propose_smali_edit step (guarded per message id so a re-render
  // never re-opens - the dashboard's onReviewProposals already refreshes the
  // edits list before opening, so the fresh proposal is listed).
  const handledProposalMsg = useRef<number | null>(null)
  // M9 follow-up: whether the last agent message proposed an edit - gates
  // both the auto-open (a landed proposal opens the review modal) and the
  // auto-continue (a reviewed proposal resumes the task).
  const lastProposed = useMemo(() => {
    const last = messages[messages.length - 1]
    return !!(
      last &&
      last.role === 'agent' &&
      last.steps?.some((s) => s.name === 'propose_smali_edit' && s.status === 'ok')
    )
  }, [messages])
  useEffect(() => {
    const last = messages[messages.length - 1]
    if (!last || last.role !== 'agent' || last.id === handledProposalMsg.current) return
    if (!lastProposed) return
    handledProposalMsg.current = last.id
    onReviewProposals()
  }, [messages, lastProposed, onReviewProposals])

  // M8 follow-up (Aug 16): the human resolved a proposal (Apply/Reject) -
  // the dashboard bumps `reviewSignal` with the apply/reject response, and
  // the BACKEND owns what happens next (from the scan's task-list.md
  // artifact): a rejection with tasks still pending pauses the loop (the
  // pause message is appended as an agent note - the human owns whether the
  // rest of the task is still wanted); `next_task_pending` starts the next
  // task's proposal turn itself via the advance stream (no fake "continue"
  // user message, no history replay); `task_complete` runs the one-call
  // wrap-up summary. Each signal is consumed exactly once (seen ref), so
  // the follow-up turn - which may itself propose, re-arming lastProposed -
  // can never re-trigger a second advance for the same review resolution.
  const seenReviewNonce = useRef(0)
  useEffect(() => {
    const sig = reviewSignal ?? null
    if (!sig || sig.nonce === seenReviewNonce.current) return
    seenReviewNonce.current = sig.nonce
    if (sending) return
    const r = sig.result
    if (!r) return
    // Only auto-react after the user reviewed a LIVE proposal of THIS thread
    // (live messages have negative ids; a loaded history message with a
    // positive id can re-arm lastProposed when switching sessions, and its
    // review must not trigger an unsolicited continuation).
    const last = messages[messages.length - 1]
    if (!last || last.id > 0 || !lastProposed) return
    if (r.paused && r.pause_message) {
      appendNote(r.pause_message)
      return
    }
    if (r.task_complete) {
      void completeTask()
      return
    }
    if (r.next_task_pending) {
      advance()
    }
  }, [reviewSignal, sending, lastProposed, advance, completeTask, appendNote, messages])

  // M9 follow-up: the session switcher dropdown (the model-picker pattern -
  // outside-click + Escape close). Inline rename (an input in the row,
  // Enter saves / Escape cancels) and a two-step inline delete confirm - no
  // browser prompt/confirm dialogs.
  const [sessionMenuOpen, setSessionMenuOpen] = useState(false)
  const [renamingId, setRenamingId] = useState<number | null>(null)
  const [renameDraft, setRenameDraft] = useState('')
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null)
  const sessionMenuRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!sessionMenuOpen) return
    const onDown = (e: MouseEvent) => {
      if (sessionMenuRef.current && !sessionMenuRef.current.contains(e.target as Node)) {
        setSessionMenuOpen(false)
      }
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSessionMenuOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [sessionMenuOpen])

  const activeSession = sessions.find((s) => s.id === activeSessionId) ?? null
  const closeSessionMenu = () => {
    setSessionMenuOpen(false)
    setConfirmDeleteId(null)
    setRenamingId(null)
  }
  const pickSession = (id: number) => {
    closeSessionMenu()
    if (id !== activeSessionId) void switchSession(id)
  }
  const startRename = (s: ChatSession) => {
    setRenamingId(s.id)
    setRenameDraft(s.title)
    setConfirmDeleteId(null)
  }
  const saveRename = () => {
    if (renamingId == null) return
    const title = renameDraft.trim()
    if (title) void renameSession(renamingId, title)
    setRenamingId(null)
  }
  const cancelRename = () => setRenamingId(null)
  // Two-step inline delete: first click arms the confirm, second deletes.
  const handleDelete = (s: ChatSession) => {
    if (confirmDeleteId === s.id) {
      setConfirmDeleteId(null)
      setSessionMenuOpen(false)
      void deleteSession(s.id)
    } else {
      setConfirmDeleteId(s.id)
    }
  }

  // M7 web research - two layers, per the plan: an Active search engine in
  // Settings (the radio list; the dock toggle NEVER selects an engine) AND
  // the per-scan opt-in this toggle controls. The toggle is disabled until
  // an engine is Active AND a chat model is connected (owner follow-up,
  // Aug 9) - the mirror of the send button's no-model gate.
  const activeEngine = useMemo(
    () => searchBackends.some((b) => b.enabled),
    [searchBackends],
  )
  // M7 follow-up (Aug 11 + Aug 13): the toggle also needs the Active engine
  // to be LIVE - the list route probes enabled backends on every list, so an
  // enabled-but-dead engine (e.g. the SearXNG container stopped) reports
  // health.reachable=false and must not enable web research (every search
  // would fail). The exact mirror of the Settings radio gate (SearchTab): a
  // SearXNG-style engine is live only while it answers its probe; a KEYED
  // engine's gate is the API key (its honest check is a real query - a
  // rejected key locks the toggle too).
  const liveEngine = useMemo(
    () =>
      searchBackends.some(
        (b) =>
          b.enabled &&
          (b.kind === 'keyed'
            ? b.has_api_key
            : (b.health?.reachable ?? false)),
      ),
    [searchBackends],
  )
  // A chat is only possible when some backend is enabled WITH a model - the
  // exact mirror of backend `pick_chat_backend` (and the ModelPicker's
  // active lookup). Without one the send button is disabled and the hint
  // says why (owner follow-up, Aug 8).
  const modelConnected = useMemo(
    () => backends.some((b) => b.enabled && b.model),
    [backends],
  )
  const [webResearch, setWebResearch] = useState(scan.web_research_enabled)
  const [webBusy, setWebBusy] = useState(false)
  // Reset per scan - the prop may be stale until the next scan-list refresh.
  useEffect(() => {
    setWebResearch(scan.web_research_enabled)
  }, [scan.id, scan.web_research_enabled])
  // The engine health above is a boot-time snapshot in AppContext - refresh
  // it whenever the dock opens so the web toggle's lock reflects CURRENT
  // reachability (SearXNG started/stopped since the app booted), not a stale
  // probe. Cheap: the list route only probes SearXNG-style engines.
  useEffect(() => {
    if (collapsed) return
    void actions.refreshSearchBackends()
  }, [collapsed, actions.refreshSearchBackends])

  // Web 🌐 toggle lock (owner request, Aug 13): when no live engine holds,
  // the toggle is disabled BOTH ways - the exact mirror of the Settings
  // radio, where an unreachable SearXNG-style engine renders as Inactive
  // with its switch disabled (on AND off) until it answers again. (The
  // earlier Aug 11 design kept the off-direction available when an opt-in
  // was already on; the recovery path is now Settings → ▶ Start engine /
  // Test, and a stale opt-in stays on harmlessly - the agent's web tools are
  // only offered while a live engine actually holds.) Without a chat model
  // the toggle stays fully inert (pre-existing no-model gate).
  const webLocked = !modelConnected || !liveEngine

  const toggleWebResearch = async () => {
    // Inert while locked (no chat model, OR no live search engine - the
    // switch is disabled both ways until an engine answers) - it must not be
    // flippable in that state, even by a stray click.
    if (webLocked || webBusy) return
    setWebBusy(true)
    try {
      await actions.setWebResearch(scan.id, !webResearch)
      setWebResearch((v) => !v)
    } catch {
      // Keep the switch where it was - the API call is the source of truth.
    } finally {
      setWebBusy(false)
    }
  }

  // Per-scan welcome message. Rebuilt on every render so the counts update
  // once findings finish loading (they start at 0); cheap string work. M8
  // Phase D: on Android scans with the smali decode ready, the agent can
  // PROPOSE EDITS - say "disable password validation in authentication"
  // and it searches the code, maps the class to its editable smali, reads
  // the current content, and stores a proposal for review (never applied
  // automatically). Proposals may exist from earlier turns in this dock.
  const welcome: ChatMessage = useMemo(() => ({
    id: -1,
    role: 'agent' as const,
    content: `Scan complete for ${scan.filename}. ${greeting.total} findings, ${
      greeting.high
    } high. Ask me anything, or @mention a file to work on it.${
      proposedCount > 0
        ? ` ${proposedCount} edit proposal${proposedCount === 1 ? '' : 's'} pending review.`
        : ''
    }`,
  }), [scan.filename, greeting.total, greeting.high, proposedCount])

  // Keep the newest message in view. While a turn is live with a streaming
  // thinking box, pin the BOX to the bottom of the chat instead of the
  // absolute bottom: tool steps land BELOW the reasoning, so scrolling to the
  // very bottom pushes the newest thinking out of view (the reported "thinking
  // box not pinned on tool calls"). The box keeps its own internal bottom-pin
  // (M8), so the newest reasoning stays visible. Once the answer text starts
  // (or the turn ends), the normal absolute-bottom pin takes over.
  useEffect(() => {
    const el = bodyRef.current
    if (!el) return
    const box = el.querySelector('.msg.streaming .thinking-box')
    if (sending && box && !pending?.text) {
      const bodyRect = el.getBoundingClientRect()
      const boxRect = box.getBoundingClientRect()
      // Scroll down only when the box bottom has fallen below the visible
      // bottom edge - keeps the box pinned at the bottom while reasoning
      // streams and tool steps pile up below it.
      const below = boxRect.bottom - (bodyRect.bottom - 8)
      if (below > 0) el.scrollTop += below
    } else {
      el.scrollTop = el.scrollHeight
    }
  }, [messages, pending, sending])

  // The live tool trace scrolls internally (height-capped); keep it pinned
  // to the bottom while the turn runs so the newest step stays in view.
  // `pending` re-arms on every streamed step/token flush, so this follows
  // the trace as it grows.
  useEffect(() => {
    const el = stepsTraceRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [pending])

  // Dependencies tab -> pre-fill the draft with a prepared question (the
  // per-dependency "Check known CVEs" button). Nonce-guarded: the same text
  // with a new nonce still lands (repeat clicks), and the picker is closed
  // so a half-typed @mention can't swallow the preset.
  useEffect(() => {
    if (!presetDraft) return
    setDraft(presetDraft.text)
    setMentionOpen(false)
    requestAnimationFrame(() => textareaRef.current?.focus())
  }, [presetDraft?.nonce])

  // Insert a picked file into the draft at the '@' position (replacing the
  // partial query the user typed), then refocus + place the caret after it.
  const insertMention = (path: string) => {
    const start = mentionStartRef.current
    const before = draft.slice(0, start)
    const after = draft.slice(start + 1 + mentionQuery.length)
    const next = `${before}@${path} ${after}`
    setDraft(next)
    setMentionOpen(false)
    requestAnimationFrame(() => {
      const el = textareaRef.current
      if (el) {
        el.focus()
        const caret = before.length + path.length + 2
        el.setSelectionRange(caret, caret)
      }
    })
  }

  // Remove a mention token from the draft (its × chip).
  const removeMention = (path: string) => {
    setDraft((v) => v.replace(`@${path}`, '').replace(/\s{2,}/g, ' ').trimStart())
    setMentionOpen(false)
  }

  const submit = () => {
    if (!draft.trim() || sending || !modelConnected) return
    const mentions = mentionedFrom(draft)
    send(draft, mentions.length > 0 ? mentions : undefined)
    setDraft('')
    setMentionOpen(false)
  }

  // The in-flight turn: the specialized thinking box (streamed reasoning
  // tokens, or the animated dots before the first token/step lands), then
  // the streamed answer text + live steps.
  const streamingMessage = pending && (
    <div className="msg ai streaming">
      <span className="msg-tag">Agent</span>
      {(pending.thinking || (!pending.text && pending.steps.length === 0)) && (
        <ThinkingBox
          text={pending.thinking}
          active={!pending.text && pending.steps.length === 0}
        />
      )}
      {pending.text ? (
        <>
          <div className="stream-text">{pending.text}</div>
          <span className="stream-caret" aria-hidden="true" />
        </>
      ) : null}
      {pending.steps.length > 0 && (
        <div className="tools-trace-body" style={{ marginTop: 8 }} ref={stepsTraceRef}>
          {pending.steps.map((s) => (
            <StepRow key={s.id} step={s} onOpenFile={onOpenFile} />
          ))}
        </div>
      )}
    </div>
  )

  return (
    <aside className={`agent${collapsed ? ' agent-collapsed' : ''}`} aria-label="Agent chat">
      <div className="agent-header">
        <div className="title">
          <span className="dot" style={{ background: 'var(--color-steel)', boxShadow: '0 0 6px var(--color-steel)' }} />
          <span>Agent · this scan</span>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {/* M8 follow-up (Aug 16): the header's pending-edit badge - the
              count is ALWAYS in view (even collapsed to the 44px rail, where
              the Review pill below the header is hidden) so a proposal the
              agent stored can never be invisible: the reported apply/revert
              case where a second auto-continue proposal lingered unseen and
              blocked the human's next ask. Compact clickable chip - opens
              the same review modal as the pill. */}
          {proposedCount > 0 && (
            <button
              type="button"
              className="dock-review-badge"
              onClick={onReviewProposals}
              title={`${proposedCount} agent edit proposal${proposedCount === 1 ? '' : 's'} awaiting your review - apply or reject per file`}
              aria-label={`Review ${proposedCount} edit proposal${proposedCount === 1 ? '' : 's'}`}
            >
              <span className="dock-review-badge-emoji" aria-hidden="true">
                📝
              </span>
              <span className="dock-review-badge-count">{proposedCount}</span>
            </button>
          )}
          <div
            role="switch"
            aria-checked={webResearch}
            aria-disabled={webLocked}
            className={`research-toggle${webLocked ? ' disabled' : ''}${webResearch ? ' on' : ''}`}
            title={
              !modelConnected
                ? 'No model connected - pick one in the top bar or Settings'
                : !activeEngine
                  ? 'Web research needs an Active search engine - enable one in Settings → Search & research'
                  : !liveEngine
                    ? 'The Active search engine is unreachable - start or Test it in Settings → Search & research'
                    : 'Allow the agent to search the web for this scan (per-scan opt-in - queries leave this machine)'
            }
            onClick={() => void toggleWebResearch()}
          >
            <span>🌐 Web</span>
            <span className={`switch${webResearch ? ' on' : ''}`} aria-hidden="true" />
          </div>
          <button
            type="button"
            className="collapse-btn"
            title={collapsed ? 'Expand agent' : 'Collapse agent'}
            onClick={onToggleCollapsed}
          >
            {collapsed ? '⤡' : '⤢'}
          </button>
        </div>
      </div>

      {/* M8 Phase D: two dock strips under the header. (1) On Android scans
          where the smali decode is NOT ready yet, a hint that the agent can
          propose edits once it is (the Decompiler's Smali chip triggers the
          on-demand decode) - makes the headline "disable password
          validation in authentication" flow discoverable. (2) A persistent
          Review edits (n) pill when proposals await - also auto-opened the
          moment a proposal lands. Hidden when there is nothing to show. */}
      {!collapsed && scan.platform === 'android' && decodeReady === false && (
        <div className="dock-edit-hint" role="status">
          <span aria-hidden="true">✏️</span>
          <span>
            Edit tools are off until the smali decode is ready - open{' '}
            <strong>Decompiler → Smali</strong> to trigger it, then ask me to
            change code (e.g. “disable password validation”).
          </span>
        </div>
      )}
      {proposedCount > 0 && !collapsed && (
        <button
          type="button"
          className="dock-review-pill"
          onClick={onReviewProposals}
          title={`${proposedCount} agent edit proposal${proposedCount === 1 ? '' : 's'} awaiting your review - apply or reject per file`}
        >
          <span aria-hidden="true">📝</span>
          Review edits ({proposedCount})
        </button>
      )}

      {/* M9 follow-up: the multi-session switcher - a trigger + custom
          dropdown (one chat thread per session, persisted server-side per
          scan). Rows switch sessions, ✎ renames INLINE (input in the row),
          🗑 deletes with a two-step inline confirm - no browser dialogs.
          Disabled while a turn runs - switching mid-turn would orphan it. */}
      {!collapsed && (
        <div className="session-bar" ref={sessionMenuRef}>
          <button
            type="button"
            className="session-trigger"
            disabled={sending || sessionsLoading}
            title="Switch chat session"
            onClick={() => setSessionMenuOpen((v) => !v)}
          >
            <span className="session-trigger-title">
              {sessionsLoading ? 'Loading…' : activeSession?.title ?? 'New chat'}
            </span>
            <span className="session-chev" aria-hidden="true">
              ▾
            </span>
          </button>

          {sessionMenuOpen && (
            <div className="session-pop" role="menu" aria-label="Chat sessions">
              {sessions.length === 0 && (
                <div className="session-pop-empty">No sessions yet</div>
              )}
              {sessions.map((s) => (
                <div
                  key={s.id}
                  className={`session-pop-row${s.id === activeSessionId ? ' active' : ''}`}
                  role="menuitem"
                >
                  {renamingId === s.id ? (
                    <input
                      className="session-rename-input"
                      aria-label="Session name"
                      value={renameDraft}
                      autoFocus
                      onChange={(e) => setRenameDraft(e.target.value)}
                      onFocus={(e) => e.target.select()}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') saveRename()
                        if (e.key === 'Escape') cancelRename()
                      }}
                      onBlur={cancelRename}
                    />
                  ) : (
                    <>
                      <button
                        type="button"
                        className="session-pop-name"
                        title={`Switch to this session${s.message_count > 0 ? ` (${s.message_count} messages)` : ''}`}
                        onClick={() => pickSession(s.id)}
                      >
                        <span className="session-pop-title">{s.title}</span>
                        {s.message_count > 0 && (
                          <span className="session-pop-count">{s.message_count}</span>
                        )}
                      </button>
                      <button
                        type="button"
                        className="session-pop-act"
                        title="Rename session"
                        onClick={() => startRename(s)}
                      >
                        ✎
                      </button>
                      <button
                        type="button"
                        className={`session-pop-act session-pop-del${confirmDeleteId === s.id ? ' confirming' : ''}`}
                        title={
                          confirmDeleteId === s.id
                            ? 'Click again to delete this session'
                            : 'Delete session'
                        }
                        onClick={() => handleDelete(s)}
                      >
                        {confirmDeleteId === s.id ? 'Delete?' : '🗑'}
                      </button>
                    </>
                  )}
                </div>
              ))}
              <div className="session-pop-divider" />
              <button
                type="button"
                className="session-pop-new"
                disabled={sending}
                onClick={() => {
                  closeSessionMenu()
                  void newSession()
                }}
              >
                ＋ New session
              </button>
            </div>
          )}
        </div>
      )}

      <div className="agent-body" ref={bodyRef}>
        <AgentMessage
          message={welcome}
          send={send}
          onOpenFile={onOpenFile}
        />
        {messages.map((m) => (
          <AgentMessage
            key={m.id}
            message={m}
            send={send}
            onOpenFile={onOpenFile}
          />
        ))}
        {streamingMessage}
      </div>

      <div className="agent-input">
        {/* M8 follow-up: the @-mention dropdown - floats above the input,
            listing files from the scan's decompiler tree (lazily fetched).
            Arrow keys navigate, Enter/Tab selects, Escape closes. */}
        {mentionOpen && mentionMatches.length > 0 && (
          <div className="mention-pop" role="listbox" aria-label="Mention a file">
            <div className="mention-pop-head">
              @ mention a file{mentionQuery ? ` - “${mentionQuery}”` : ''}
            </div>
            {mentionMatches.map((p, i) => (
              <button
                key={p}
                type="button"
                role="option"
                aria-selected={i === mentionIdx}
                className={`mention-opt${i === mentionIdx ? ' active' : ''}`}
                onMouseEnter={() => setMentionIdx(i)}
                onClick={() => insertMention(p)}
              >
                <span className="mention-at" aria-hidden="true">@</span>
                {shortenPath(p, 64)}
              </button>
            ))}
          </div>
        )}
        {/* M8 follow-up: the removable mention-chip row (the draft's @paths). */}
        {draftMentions.length > 0 && !sending && (
          <div className="mention-chips">
            {draftMentions.map((p) => (
              <span key={p} className="mention-chip">
                <button
                  type="button"
                  className="mention-chip-open"
                  title={`${p} - open in Decompiler`}
                  onClick={() => onOpenFile(p)}
                >
                  @{shortenPath(p, 44)}
                </button>
                <button
                  type="button"
                  className="mention-chip-x"
                  title="Remove mention"
                  aria-label={`Remove mention ${p}`}
                  onClick={() => removeMention(p)}
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        )}
        <textarea
          ref={textareaRef}
          aria-label="Ask about this scan"
          placeholder='Ask about this scan, or @mention a file'
          value={draft}
          disabled={sending}
          onChange={(e) => {
            const v = e.target.value
            const caret = e.target.selectionStart ?? v.length
            setDraft(v)
            // Detect a `@query` token being typed at the caret: open the
            // picker when the last `@` has no whitespace before it.
            const before = v.slice(0, caret)
            const at = before.lastIndexOf('@')
            const ws = Math.max(
              before.lastIndexOf(' '),
              before.lastIndexOf('\n'),
              before.lastIndexOf('\t'),
            )
            if (at > ws) {
              mentionStartRef.current = at
              setMentionQuery(before.slice(at + 1))
              setMentionOpen(true)
            } else {
              setMentionOpen(false)
            }
          }}
          onKeyDown={(e) => {
            if (mentionOpen && mentionMatches.length > 0) {
              if (e.key === 'ArrowDown') {
                e.preventDefault()
                setMentionIdx((i) => (i + 1) % mentionMatches.length)
                return
              }
              if (e.key === 'ArrowUp') {
                e.preventDefault()
                setMentionIdx(
                  (i) => (i - 1 + mentionMatches.length) % mentionMatches.length,
                )
                return
              }
              if (e.key === 'Enter' || e.key === 'Tab') {
                e.preventDefault()
                insertMention(mentionMatches[mentionIdx])
                return
              }
              if (e.key === 'Escape') {
                e.preventDefault()
                setMentionOpen(false)
                return
              }
            }
            // Ignore Enter while an IME composition is in flight so
            // CJK input isn't submitted mid-composition.
            if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
              e.preventDefault()
              submit()
            }
          }}
        />
        <div className="row">
          <span className={`hint${modelConnected ? '' : ' warn'}`}>
            {modelConnected
              ? !liveEngine
                ? webResearch
                  ? '⏎ to send · 🌐 on - engine unreachable (Settings → Search & research)'
                  : '⏎ to send · 🌐 off - no live search engine (Settings → Search & research)'
                : webResearch
                  ? '⏎ to send · 🌐 web on · @ to mention a file'
                  : '⏎ to send · @ to mention a file'
              : 'No model connected - pick one in the top bar or Settings'}
          </span>
          {sending ? (
            <button
              type="button"
              className="stop-btn stop-icon"
              onClick={stop}
              aria-label="Stop the agent"
              title="Stop the agent - it stops at the next round"
            >
              ■
            </button>
          ) : (
            <button
              type="button"
              className="send-btn"
              disabled={!draft.trim() || !modelConnected}
              title={
                modelConnected
                  ? undefined
                  : 'No chat model connected - pick one in the top bar or Settings'
              }
              onClick={submit}
            >
              Send
            </button>
          )}
        </div>
      </div>
    </aside>
  )
}

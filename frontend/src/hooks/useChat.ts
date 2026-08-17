import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import { StreamDecoder } from '../lib/sse'
import type { ChatMessageRead, ChatResponse, ChatSession, Citation } from '../types'

export type ChatErrorKind =
  | 'no-model'
  | 'not-analyzed'
  | 'upstream'
  | 'timeout'
  | 'network'
  | 'error'

/** One tool call the agent executed (live steps + the persistent trace). */
export interface ToolStep {
  id: string
  name: string
  args: Record<string, unknown>
  status: 'running' | 'ok' | 'error'
  durationMs?: number
  resultPreview?: string
  error?: string
  count?: number
}

export interface ChatMessage {
  id: number
  role: 'user' | 'agent'
  content: string
  citations?: Citation[]
  sources?: string[]
  /** M6 Phase B: whether the agent ran tools this turn + which ones. */
  toolMode?: 'tools' | 'context-only'
  toolsUsed?: string[]
  /** M6 follow-up: the per-tool trace (live steps collapse into this). */
  steps?: ToolStep[]
  /** Non-empty for failed agent turns - renders as a distinct bubble with
   * a Retry affordance that re-sends the original question. */
  errorKind?: ChatErrorKind
  retryQuestion?: string
  /** M8 follow-up: tree paths the user @mentioned in this message - kept
   * so a Retry re-sends them and the bubble can render clickable chips. */
  mentionedFiles?: string[]
  /** M8 follow-up: reasoning/thinking tokens the model emitted before its
   * answer - rendered in the specialized thinking box above the answer. */
  thinking?: string
  /** M8 follow-up: the streaming thinking box was shown (dots while the
   * model computed) but NO readable reasoning ever landed - e.g. Gemini
   * 3.x exposes only encrypted thought signatures. Renders the box's
   * fallback note instead of letting the box vanish unexplained. */
  thinkingAttempted?: boolean
}

/** The in-flight streamed turn (not yet a finalized ChatMessage). */
interface PendingTurn {
  text: string
  steps: ToolStep[]
  /** M8 follow-up: streamed reasoning/thinking tokens (own SSE event). */
  thinking: string
}

// M9 follow-up: locally-created messages use NEGATIVE ids so they can never
// collide with server-persisted message ids (positive) when a session's
// thread is loaded from the API. The dock's welcome bubble is -1.
let nextLocalId = -2
const localId = () => nextLocalId--

/** Map a persisted turn back to the thread shape (steps from the trace,
 * citations from the persisted chips - reloaded history keeps the
 * clickable source chips like the live turn). */
function toChatMessage(m: ChatMessageRead): ChatMessage {
  return {
    id: m.id,
    role: m.role === 'user' ? 'user' : 'agent',
    content: m.content,
    ...(m.tool_runs.length > 0
      ? {
          steps: m.tool_runs.map((r) => ({
            id: r.id,
            name: r.name,
            args: r.args,
            status: r.status,
            durationMs: r.duration_ms,
            resultPreview: r.result_preview,
            error: r.error ?? undefined,
            count: r.count ?? undefined,
          })),
        }
      : {}),
    ...(m.citations.length > 0
      ? {
          citations: m.citations,
          sources: [...new Set(m.citations.map((c) => c.file))],
        }
      : {}),
  }
}

/** Human copy for the graceful chat error states (400/409/504/network). */
export function chatErrorMessage(kind: ChatErrorKind, detail: string): string {
  switch (kind) {
    case 'no-model':
      return 'No chat model is connected yet. Open Settings (top-right ⚙), point MobARK at a local backend such as Ollama and pick a model - then I can answer questions about this scan.'
    case 'not-analyzed':
      return 'This scan has not finished analyzing yet - the agent becomes available once the pipeline is done.'
    case 'upstream':
      return `The model backend failed to answer - it may not be able to load the selected model. ${detail}`
    case 'timeout':
      return 'The agent ran out of time answering that one. The question may be too broad - narrow it to a specific file or finding, then retry.'
    case 'network':
      return `Could not reach the backend: ${detail}`
    default:
      return detail || 'Something went wrong while asking the agent.'
  }
}

function classifyError(err: unknown): ChatErrorKind {
  if (err instanceof ApiError) {
    if (err.status === 400) return 'no-model'
    // 409 is 'not analyzed' from the API's perspective. The Stop-button
    // interrupt also returns 409 (ChatInterrupted), but that response is
    // unreachable here: stop() aborts the fetch first, so the only 409 a
    // non-aborted call can see is the not-analyzed case.
    if (err.status === 409) return 'not-analyzed'
    if (err.status === 502) return 'upstream'
    if (err.status === 504) return 'timeout'
    if (err.status === 0) return 'network'
  }
  return 'error'
}

/** Map the SSE error-frame kind to the existing bubble copy. */
function sseErrorKind(kind: string | undefined): ChatErrorKind {
  switch (kind) {
    case 'no-model':
      return 'no-model'
    case 'upstream':
      return 'upstream'
    case 'timeout':
      return 'timeout'
    case 'interrupted':
      return 'error' // Stop is handled client-side via abort; this is a fallback
    default:
      return 'error'
  }
}

function isAbort(err: unknown): boolean {
  // Name check, not instanceof: some fetch polyfills reject with a plain
  // Error named 'AbortError' instead of a DOMException.
  return (err as { name?: string } | null)?.name === 'AbortError'
}

function parseData<T>(raw: string): T | null {
  try {
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

// Throttle token-event state updates: a long answer streams one delta per
// token, which would be a render per token without a flush window.
const TOKEN_FLUSH_MS = 50

// M8 follow-up: a compute window this long (no content at all) means the
// model was visibly "thinking" - the streaming box's dots were actually
// shown. Below it, the box never perceptibly rendered, so the finalized
// message gets no fallback note.
const DOTS_VISIBLE_MS = 300

/**
 * Agent dock conversation (Phase G + M6 follow-up) - messages + send over
 * `POST /scans/{id}/chat/stream` (SSE: live tokens + tool steps), plus
 * interrupt: `stop()` aborts the in-flight fetch (immediate UI) and fires the
 * cancel endpoint so the server halts the agent loop at the next round (no
 * more LLM tokens burned).
 *
 * M9 follow-up: multi-session chat. The thread now persists SERVER-SIDE per
 * session (chat_sessions/chat_messages), so the whole history survives
 * reloads and reaches the model on every turn. This hook holds the per-scan
 * session list + the ACTIVE session's thread: on mount it loads the most
 * recent session (creating nothing - the first send creates one on demand),
 * the switcher calls `switchSession`/`newSession`/`deleteSession`/
 * `renameSession`, and every send runs inside the active session. Mount
 * per-scan (React `key`) to reset.
 */
export function useChat(scanId: number) {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [pending, setPending] = useState<PendingTurn | null>(null)
  const [sending, setSending] = useState(false)
  // M9 follow-up: the per-scan session list + the active session.
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [activeSessionId, setActiveSessionId] = useState<number | null>(null)
  const [sessionsLoading, setSessionsLoading] = useState(true)
  const requestIdRef = useRef(0)
  const controllerRef = useRef<AbortController | null>(null)
  // Guards a quick session switch: only the LATEST load applies its result.
  const loadSeqRef = useRef(0)
  // Ref mirror of `pending` - the stream handlers (abort path especially)
  // need the latest turn without reading stale closure state.
  const pendingRef = useRef<PendingTurn | null>(null)

  const mutatePending = useCallback((fn: (p: PendingTurn) => PendingTurn) => {
    const cur = pendingRef.current
    if (!cur) return
    const next = fn(cur)
    pendingRef.current = next
    setPending(next)
  }, [])

  const clearPending = useCallback(() => {
    pendingRef.current = null
    setPending(null)
  }, [])

  // M9 follow-up: reload the session list (metadata changes after a turn
  // lands, a rename, a delete, or a create). Best-effort.
  const refreshSessions = useCallback(async () => {
    try {
      setSessions(await api.listChatSessions(scanId))
    } catch {
      // Transient - keep the last list.
    }
  }, [scanId])

  // Load one session's full thread and make it active.
  const switchSession = useCallback(
    async (sessionId: number) => {
      const seq = ++loadSeqRef.current
      try {
        const msgs = await api.chatSessionMessages(scanId, sessionId)
        if (seq !== loadSeqRef.current) return // superseded by a newer switch
        setMessages(msgs.map(toChatMessage))
        setActiveSessionId(sessionId)
        // The thread changed sessions - a dangling in-flight render (e.g.
        // from a stop) must never leak into the newly shown session.
        clearPending()
      } catch {
        // Transient - keep the current thread.
      }
    },
    [scanId, clearPending],
  )

  // M9 follow-up: on mount (per scan) load the session list and the most
  // recently used session's thread - the dock resumes where it left off.
  // Nothing is auto-created: a scan with no sessions starts empty and the
  // first send creates one on demand (no junk sessions for mere browsing).
  useEffect(() => {
    let cancelled = false
    loadSeqRef.current += 1
    setSessionsLoading(true)
    setSessions([])
    setMessages([])
    setActiveSessionId(null)
    void api
      .listChatSessions(scanId)
      .then(async (list) => {
        if (cancelled) return
        setSessions(list)
        if (list.length > 0) {
          const first = list[0] // most recently used
          const msgs = await api.chatSessionMessages(scanId, first.id)
          if (cancelled) return
          setMessages(msgs.map(toChatMessage))
          setActiveSessionId(first.id)
        }
      })
      .catch(() => {
        // No sessions / transient - the dock starts fresh.
      })
      .finally(() => {
        if (!cancelled) setSessionsLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId])

  const newSession = useCallback(async () => {
    if (sending) return
    try {
      const s = await api.createChatSession(scanId)
      loadSeqRef.current += 1
      setSessions((prev) => [s, ...prev.filter((x) => x.id !== s.id)])
      setActiveSessionId(s.id)
      setMessages([])
      // A fresh session must never inherit an in-flight render (e.g. a
      // dangling pending turn from a stop) - clear it with the thread.
      clearPending()
    } catch {
      // Transient - the switcher keeps the current session.
    }
  }, [scanId, sending, clearPending])

  const deleteSession = useCallback(
    async (sessionId: number) => {
      if (sending) return
      try {
        await api.deleteChatSession(scanId, sessionId)
        const remaining = await api.listChatSessions(scanId)
        setSessions(remaining)
        if (sessionId === activeSessionId) {
          loadSeqRef.current += 1
          if (remaining.length > 0) {
            const msgs = await api.chatSessionMessages(scanId, remaining[0].id)
            setMessages(msgs.map(toChatMessage))
            setActiveSessionId(remaining[0].id)
          } else {
            setMessages([])
            setActiveSessionId(null)
          }
          // Deleting the active session swapped the thread to another
          // session (or nothing) - a dangling pending render must not leak
          // into whatever is shown now (the switchSession rule).
          clearPending()
        }
      } catch {
        // Transient - keep the current state.
      }
    },
    [scanId, sending, activeSessionId, clearPending],
  )

  const renameSession = useCallback(
    async (sessionId: number, title: string) => {
      try {
        const s = await api.renameChatSession(scanId, sessionId, title)
        setSessions((prev) => prev.map((x) => (x.id === s.id ? s : x)))
      } catch {
        // Transient - the switcher keeps the old title.
      }
    },
    [scanId],
  )

  const stop = useCallback(() => {
    controllerRef.current?.abort()
    controllerRef.current = null
    // The in-flight promise is now aborted; bump the guard so its
    // then/catch/finally all bail - no error bubble, no stale state.
    requestIdRef.current += 1
    setSending(false)
    // Keep whatever streamed so far as a finalized partial message (the
    // "Stopped" note below it says why the turn ended), then clear the
    // dangling pending turn. The old abort path that did this was DEAD
    // CODE: stop() bumps the request id BEFORE the fetch rejection lands,
    // so the catch bailed at `requestIdRef.current !== id` and
    // `clearPending()` never ran. The leftover `pending` kept rendering the
    // interrupted turn (live caret + steps) AND survived a "New session" -
    // `newSession` only resets `messages`, not the in-flight pending turn -
    // so the history appeared stuck in the fresh chat until a page refresh
    // remounted the hook (the reported bug).
    const partial = pendingRef.current
    clearPending()
    const stoppedNote: ChatMessage = {
      id: localId(),
      role: 'agent',
      content: '⏹ Stopped - the agent\u2019s turn was interrupted.',
    }
    if (partial && (partial.text || partial.steps.length > 0)) {
      setMessages((prev) => [
        ...prev,
        {
          id: localId(),
          role: 'agent',
          content: partial.text || '…',
          steps: partial.steps,
        },
        stoppedNote,
      ])
    } else {
      setMessages((prev) => [...prev, stoppedNote])
    }
    // Fire-and-forget: tell the server to stop. If it fails, the abort above
    // already stopped the UI; the server just finishes its current round.
    void api.cancelChat(scanId).catch(() => {
      // No UI - the stop already happened client-side.
    })
    void refreshSessions() // the user turn was persisted server-side
  }, [scanId, refreshSessions, clearPending])

  const send = useCallback(
    (
      question: string,
      mentionedFiles?: string[],
      opts?: { advance?: boolean },
    ) => {
      const trimmed = question.trim()
      if (sending) return
      if (!opts?.advance && !trimmed) return
      const advance = opts?.advance ?? false
      const id = ++requestIdRef.current
      controllerRef.current?.abort() // never two in flight
      const controller = new AbortController()
      controllerRef.current = controller
      // M8 follow-up (Aug 16): an ADVANCE turn has no user message - the
      // backend builds the continuation from the task-list artifact (no
      // fake "continue" text is ever sent).
      if (!advance) {
        const userMsg: ChatMessage = {
          id: localId(),
          role: 'user',
          content: trimmed,
          mentionedFiles,
        }
        setMessages((prev) => [...prev, userMsg])
      }
      // M8 follow-up: turn start time - the thinking dots are shown from
      // here until the first content (token/step) lands; that window is
      // what decides the fallback note on finalized turns.
      const pendingStartedAt = Date.now()
      pendingRef.current = { text: '', steps: [], thinking: '' }
      setPending({ text: '', steps: [], thinking: '' })
      setSending(true)

      const finalizeMessage = (msg: ChatMessage) => {
        clearPending()
        setMessages((prev) => [...prev, msg])
      }

      const pushErrorMessage = (kind: ChatErrorKind, detail: string) => {
        finalizeMessage({
          id: localId(),
          role: 'agent',
          content: chatErrorMessage(kind, detail),
          errorKind: kind,
          // An advance turn has no user question to retry.
          ...(advance ? {} : { retryQuestion: trimmed }),
        })
      }

      // The turn body: stream + persist. The SERVER loads the session's
      // history (full thread) and stores the user/assistant turns back.
      const runTurn = (sessionId: number) => {
        api
          .chatStream(
            scanId,
            advance ? '' : trimmed,
            controller.signal,
            mentionedFiles,
            undefined,
            sessionId,
            advance || undefined,
          )
          .then(async (res) => {
            const reader = res.body?.getReader()
            if (!reader) throw new Error('No response body in chat stream')
            const textDecoder = new TextDecoder()
            const sse = new StreamDecoder()
            let answer: ChatResponse | null = null
            let streamError: { kind: ChatErrorKind; detail: string } | null = null
            // Token text + thinking text are buffered and flushed on a timer
            // so a long answer doesn't render once per token.
            let tokenBuf = ''
            let thinkBuf = ''
            let lastFlush = 0
            // M8 follow-up: the fallback thinking note is only meaningful when
            // the dots were ACTUALLY shown - i.e. the model computed with no
            // content for a perceptible window before the first token/step.
            // An instant answer never lets the box render, so it gets no note.
            let firstContentAt: number | null = null
            const noteFirstContent = () => {
              if (firstContentAt == null) firstContentAt = Date.now()
            }
            const flushTokens = () => {
              if (!tokenBuf && !thinkBuf) return
              const delta = tokenBuf
              const thinkDelta = thinkBuf
              tokenBuf = ''
              thinkBuf = ''
              mutatePending((p) => ({
                ...p,
                text: p.text + delta,
                thinking: p.thinking + thinkDelta,
              }))
            }

            for (;;) {
              const { done, value } = await reader.read()
              if (done) break
              for (const ev of sse.push(textDecoder.decode(value, { stream: true }))) {
                if (requestIdRef.current !== id) return
                if (ev.event === 'token') {
                  const d = parseData<{ delta?: string }>(ev.data)
                  if (d?.delta) {
                    noteFirstContent()
                    tokenBuf += d.delta
                    const now = Date.now()
                    if (now - lastFlush >= TOKEN_FLUSH_MS) {
                      lastFlush = now
                      flushTokens()
                    }
                  }
                } else if (ev.event === 'thinking') {
                  const d = parseData<{ delta?: string }>(ev.data)
                  if (d?.delta) {
                    noteFirstContent()
                    thinkBuf += d.delta
                    const now = Date.now()
                    if (now - lastFlush >= TOKEN_FLUSH_MS) {
                      lastFlush = now
                      flushTokens()
                    }
                  }
                } else if (ev.event === 'tool_start') {
                  noteFirstContent()
                  flushTokens()
                  const d = parseData<{ id: string; name: string; args: Record<string, unknown> }>(ev.data)
                  if (d) {
                    mutatePending((p) => ({
                      ...p,
                      steps: [...p.steps, { id: d.id, name: d.name, args: d.args, status: 'running' }],
                    }))
                  }
                } else if (ev.event === 'tool_end') {
                  flushTokens()
                  const d = parseData<{
                    id: string
                    status: 'ok' | 'error'
                    duration_ms?: number
                    result_preview?: string
                    error?: string | null
                    count?: number | null
                  }>(ev.data)
                  if (d) {
                    mutatePending((p) => ({
                      ...p,
                      steps: p.steps.map((s) =>
                        s.id === d.id
                          ? {
                              ...s,
                              status: d.status,
                              durationMs: d.duration_ms,
                              resultPreview: d.result_preview,
                              error: d.error ?? undefined,
                              count: d.count ?? undefined,
                            }
                          : s,
                      ),
                    }))
                  }
                } else if (ev.event === 'answer') {
                  answer = parseData<ChatResponse>(ev.data)
                } else if (ev.event === 'error') {
                  const d = parseData<{ kind?: string; detail?: string }>(ev.data)
                  streamError = { kind: sseErrorKind(d?.kind), detail: d?.detail ?? '' }
                }
              }
            }
            if (requestIdRef.current !== id) return
            flushTokens()
            if (streamError) {
              pushErrorMessage(streamError.kind, streamError.detail)
            } else if (answer) {
              const thinking = answer.thinking ?? ''
              // The dots were shown only if the model computed for a
              // perceptible window before ANY content (token/step) landed.
              const dotsShown =
                firstContentAt != null &&
                firstContentAt - pendingStartedAt >= DOTS_VISIBLE_MS
              finalizeMessage({
                id: localId(),
                role: 'agent',
                content: answer.answer,
                citations: answer.citations,
                sources: answer.sources,
                toolMode: answer.tool_mode,
                toolsUsed: answer.tools_used,
                thinking,
                thinkingAttempted: !thinking && dotsShown,
                steps: answer.tool_runs.map((r) => ({
                  id: r.id,
                  name: r.name,
                  args: r.args,
                  status: r.status,
                  durationMs: r.duration_ms,
                  resultPreview: r.result_preview,
                  error: r.error ?? undefined,
                  count: r.count ?? undefined,
                })),
              })
            } else {
              pushErrorMessage(
                'error',
                'The agent stream ended without an answer - please retry.',
              )
            }
            setSending(false)
          })
          .catch((err: unknown) => {
            if (isAbort(err)) {
              // Stopped via the Stop button: keep whatever streamed so far as a
              // partial message (the dock already appended the "Stopped" note),
              // so live text/steps are not silently dropped. The abort is only
              // meaningful for the CURRENT request - an older request aborted
              // by a superseding send already had its ref bumped and must bail.
              if (requestIdRef.current !== id) return
              const partial = pendingRef.current
              if (partial && (partial.text || partial.steps.length > 0)) {
                setMessages((prev) => [
                  ...prev,
                  {
                    id: localId(),
                    role: 'agent',
                    content: partial.text || '…',
                    steps: partial.steps,
                  },
                ])
              }
              clearPending()
              setSending(false)
              return
            }
            if (requestIdRef.current !== id) return
            const kind = classifyError(err)
            pushErrorMessage(kind, err instanceof Error ? err.message : String(err))
            setSending(false)
          })
          .finally(() => {
            if (requestIdRef.current === id) {
              controllerRef.current = null
            }
            // The turn persisted server-side - refresh the switcher's
            // counts/previews/order.
            void refreshSessions()
          })
      }

      // M9 follow-up: every turn runs inside a session. The dock starts
      // with no session on a fresh scan - the first send creates one (the
      // question becomes its auto-title), then the turn proceeds.
      if (activeSessionId != null) {
        runTurn(activeSessionId)
      } else {
        api
          .createChatSession(scanId)
          .then((s) => {
            if (requestIdRef.current !== id) return // stopped while creating
            setActiveSessionId(s.id)
            setSessions((prev) => [s, ...prev.filter((x) => x.id !== s.id)])
            runTurn(s.id)
          })
          .catch(() => {
            if (requestIdRef.current !== id) return
            pushErrorMessage(
              'error',
              'Could not start a chat session - please retry.',
            )
            setSending(false)
          })
      }
    },
    [scanId, sending, activeSessionId, clearPending, mutatePending, refreshSessions],
  )

  /** M8 follow-up (Aug 16): AUTO-ADVANCE - the backend starts the next
   * task's proposal turn itself after the human applied a proposal. No user
   * message (there is no user question - the continuation prompt is built
   * server-side from the task-list artifact), no fake "continue" text.
   * The turn streams live and persists like any other. */
  const advance = useCallback(() => {
    send('', undefined, { advance: true })
  }, [send])

  /** Append a plain agent note locally (e.g. the rejection-pause message
   * from the apply/reject response) - informational, not a streamed turn.
   * Local id (negative): never collides with persisted turns. */
  const appendNote = useCallback((content: string) => {
    setMessages((prev) => [...prev, { id: localId(), role: 'agent', content }])
  }, [])

  /** M8 follow-up (Aug 16): the task-complete wrap-up - the task list is
   * exhausted (every proposal applied/rejected), so ONE small LLM summary
   * closes the task (buffered; the deterministic fallback is server-side,
   * so this never errors the thread). */
  const completeTask = useCallback(async () => {
    if (sending || activeSessionId == null) return
    try {
      const res = await api.completeTask(scanId, activeSessionId)
      setMessages((prev) => [
        ...prev,
        {
          id: localId(),
          role: 'agent',
          content: res.answer,
          citations: res.citations,
          sources: res.sources,
          toolMode: res.tool_mode,
          toolsUsed: res.tools_used,
          thinking: res.thinking ?? '',
          steps: res.tool_runs.map((r) => ({
            id: r.id,
            name: r.name,
            args: r.args,
            status: r.status,
            durationMs: r.duration_ms,
            resultPreview: r.result_preview,
            error: r.error ?? undefined,
            count: r.count ?? undefined,
          })),
        },
      ])
    } catch {
      // Transient - a wrap-up must never break the thread.
    } finally {
      void refreshSessions() // the wrap-up was persisted server-side
    }
  }, [scanId, sending, activeSessionId, refreshSessions])

  return {
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
  }
}

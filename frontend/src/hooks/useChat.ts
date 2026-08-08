import { useCallback, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import type { Citation } from '../types'

export type ChatErrorKind =
  | 'no-model'
  | 'not-analyzed'
  | 'upstream'
  | 'timeout'
  | 'network'
  | 'error'

export interface ChatMessage {
  id: number
  role: 'user' | 'agent'
  content: string
  citations?: Citation[]
  sources?: string[]
  /** Non-empty for failed agent turns — renders as a distinct bubble with
   * a Retry affordance that re-sends the original question. */
  errorKind?: ChatErrorKind
  retryQuestion?: string
}

let nextMessageId = 1

/** Human copy for the graceful chat error states (400/409/504/network). */
export function chatErrorMessage(kind: ChatErrorKind, detail: string): string {
  switch (kind) {
    case 'no-model':
      return 'No chat model is connected yet. Open Settings (top-right ⚙), point MASA at a local backend such as Ollama and pick a model — then I can answer questions about this scan.'
    case 'not-analyzed':
      return 'This scan has not finished analyzing yet — the agent becomes available once the pipeline is done.'
    case 'upstream':
      return `The model backend failed to answer — it may not be able to load the selected model. ${detail}`
    case 'timeout':
      return 'The agent ran out of time answering that one. The question may be too broad — narrow it to a specific file or finding, then retry.'
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

function isAbort(err: unknown): boolean {
  // Name check, not instanceof: some fetch polyfills reject with a plain
  // Error named 'AbortError' instead of a DOMException.
  return (err as { name?: string } | null)?.name === 'AbortError'
}

/**
 * Agent dock conversation (Phase G) — messages + send over
 * `POST /scans/{id}/chat`, plus interrupt: `stop()` aborts the in-flight
 * fetch (immediate UI) and fires the cancel endpoint so the server halts the
 * agent loop at the next round (no more LLM tokens burned). The backend never
 * persists chat, so the whole thread lives in this hook's state; mount
 * per-scan (React `key`) to reset.
 */
export function useChat(scanId: number) {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [sending, setSending] = useState(false)
  const requestIdRef = useRef(0)
  const controllerRef = useRef<AbortController | null>(null)

  const stop = useCallback(() => {
    controllerRef.current?.abort()
    controllerRef.current = null
    // The in-flight promise is now aborted; bump the guard so its
    // then/catch/finally all bail — no error bubble, no stale state.
    requestIdRef.current += 1
    setSending(false)
    setMessages((prev) => [
      ...prev,
      {
        id: nextMessageId++,
        role: 'agent',
        content: '⏹ Stopped — the agent\u2019s turn was interrupted.',
      },
    ])
    // Fire-and-forget: tell the server to stop. If it fails, the abort above
    // already stopped the UI; the server just finishes its current round.
    void api.cancelChat(scanId).catch(() => {
      // No UI — the stop already happened client-side.
    })
  }, [scanId])

  const send = useCallback(
    (question: string) => {
      const trimmed = question.trim()
      if (!trimmed || sending) return
      const id = ++requestIdRef.current
      controllerRef.current?.abort() // never two in flight
      const controller = new AbortController()
      controllerRef.current = controller
      const userMsg: ChatMessage = {
        id: nextMessageId++,
        role: 'user',
        content: trimmed,
      }
      setMessages((prev) => [...prev, userMsg])
      setSending(true)
      api
        .chat(scanId, trimmed, undefined, controller.signal)
        .then((res) => {
          if (requestIdRef.current !== id) return
          setMessages((prev) => [
            ...prev,
            {
              id: nextMessageId++,
              role: 'agent',
              content: res.answer,
              citations: res.citations,
              sources: res.sources,
            },
          ])
        })
        .catch((err: unknown) => {
          if (requestIdRef.current !== id) return
          if (isAbort(err)) return // stopped via Stop button — not an error
          const kind = classifyError(err)
          setMessages((prev) => [
            ...prev,
            {
              id: nextMessageId++,
              role: 'agent',
              content: chatErrorMessage(
                kind,
                err instanceof Error ? err.message : String(err),
              ),
              errorKind: kind,
              retryQuestion: trimmed,
            },
          ])
        })
        .finally(() => {
          if (requestIdRef.current === id) setSending(false)
        })
    },
    [scanId, sending],
  )

  return { messages, sending, send, stop }
}

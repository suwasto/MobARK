import { useCallback, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import type { Citation } from '../types'

export type ChatErrorKind =
  | 'no-model'
  | 'not-analyzed'
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
    if (err.status === 409) return 'not-analyzed'
    if (err.status === 504) return 'timeout'
    if (err.status === 0) return 'network'
  }
  return 'error'
}

/**
 * Agent dock conversation (Phase G) — messages + send over
 * `POST /scans/{id}/chat`. The backend never persists chat, so the whole
 * thread lives in this hook's state; mount per-scan (React `key`) to reset.
 */
export function useChat(scanId: number) {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [sending, setSending] = useState(false)
  const requestIdRef = useRef(0)

  const send = useCallback(
    (question: string) => {
      const trimmed = question.trim()
      if (!trimmed || sending) return
      const id = ++requestIdRef.current
      const userMsg: ChatMessage = {
        id: nextMessageId++,
        role: 'user',
        content: trimmed,
      }
      setMessages((prev) => [...prev, userMsg])
      setSending(true)
      api
        .chat(scanId, trimmed)
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

  return { messages, sending, send }
}

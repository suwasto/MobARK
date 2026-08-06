import { useEffect, useRef, useState } from 'react'
import type { ScanRead } from '../../types'
import { useChat, type ChatMessage } from '../../hooks/useChat'

interface AgentDockProps {
  scan: ScanRead
  /** Static greeting numbers (total findings + critical count). */
  greeting: { total: number; critical: number }
  collapsed: boolean
  onToggleCollapsed: () => void
  /** A citation was clicked — jump the Decompiler tab to that file. */
  onOpenFile: (file: string) => void
}

/** Backticks → `<code>` spans so agent answers render like the mockup. */
function renderCodeSpans(text: string) {
  return text.split('`').map((part, i) =>
    i % 2 === 1 ? (
      <code key={i}>{part}</code>
    ) : (
      <span key={i}>{part}</span>
    ),
  )
}

function AgentMessage({
  message,
  onRetry,
  onOpenFile,
}: {
  message: ChatMessage
  onRetry: () => void
  onOpenFile: (file: string) => void
}) {
  if (message.role === 'user') {
    return <div className="msg user">{message.content}</div>
  }
  return (
    <div className={`msg ai${message.errorKind ? ' error' : ''}`}>
      <span className="msg-tag">
        {message.errorKind ? 'Agent · failed' : 'Agent'}
      </span>
      <div className="whitespace-pre-wrap">{renderCodeSpans(message.content)}</div>

      {message.citations && message.citations.length > 0 && (
        <div className="src-row" aria-label="Sources cited by the agent">
          {message.citations.map((c, i) => (
            <button
              key={`${c.file}:${c.line ?? ''}:${i}`}
              type="button"
              className="src-chip"
              title={c.snippet ? `${c.snippet} — click to open in Decompiler` : 'Click to open in Decompiler'}
              onClick={() => onOpenFile(c.file)}
            >
              {c.file}
              {c.line != null ? `:${c.line}` : ''}
            </button>
          ))}
        </div>
      )}

      {message.errorKind && message.retryQuestion && (
        <div className="mt-3 border-t border-line-soft pt-2.5">
          <button type="button" className="link-btn" onClick={onRetry}>
            Retry
          </button>
        </div>
      )}
    </div>
  )
}

/**
 * Agent dock (Phase G): right-hand chat rail over `POST /scans/{id}/chat`
 * (M4 Layers 1–3). Collapsible to a 44px rail (mockup `.body` grid); web
 * research toggle is a disabled M7 placeholder. Citation chips jump the
 * Decompiler tab to the cited file.
 */
export function AgentDock({
  scan,
  greeting,
  collapsed,
  onToggleCollapsed,
  onOpenFile,
}: AgentDockProps) {
  const { messages, sending, send } = useChat(scan.id)
  const [draft, setDraft] = useState('')
  const bodyRef = useRef<HTMLDivElement>(null)

  // Per-scan welcome message. Rebuilt on every render so the counts update
  // once findings finish loading (they start at 0); cheap string work.
  const welcome: ChatMessage = {
    id: -1,
    role: 'agent',
    content: `Scan complete for ${scan.filename}. ${greeting.total} findings, ${
      greeting.critical
    } critical. Ask me anything about the decompiled code — try "where is certificate pinning handled?"`,
  }

  // Keep the newest message in view.
  useEffect(() => {
    const el = bodyRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages, sending])

  const submit = () => {
    if (!draft.trim() || sending) return
    send(draft)
    setDraft('')
  }

  return (
    <aside className={`agent${collapsed ? ' agent-collapsed' : ''}`} aria-label="Agent chat">
      <div className="agent-header">
        <div className="title">
          <span className="dot" style={{ background: 'var(--color-steel)', boxShadow: '0 0 6px var(--color-steel)' }} />
          <span>Agent · this scan</span>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <div
            className="research-toggle disabled"
            title="Web research ships in M7 — prompts stay fully local until then"
          >
            <span>🌐 Web</span>
            <span className="switch" aria-hidden="true" />
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

      <div className="agent-body" ref={bodyRef}>
        <AgentMessage
          message={welcome}
          onRetry={() => undefined}
          onOpenFile={onOpenFile}
        />
        {messages.map((m) => (
          <AgentMessage
            key={m.id}
            message={m}
            onRetry={() => m.retryQuestion && send(m.retryQuestion)}
            onOpenFile={onOpenFile}
          />
        ))}
        {sending && (
          <div className="msg ai">
            <span className="msg-tag">Agent</span>
            <span className="text-bone-faint">Thinking…</span>
          </div>
        )}
      </div>

      <div className="agent-input">
        <textarea
          aria-label="Ask about this scan"
          placeholder='Ask about this scan, e.g. "explain the WebView bridge risk"'
          value={draft}
          disabled={sending}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            // Ignore Enter while an IME composition is in flight so
            // CJK input isn't submitted mid-composition.
            if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
              e.preventDefault()
              submit()
            }
          }}
        />
        <div className="row">
          <span className="hint">⏎ to send</span>
          <button
            type="button"
            className="send-btn"
            disabled={sending || !draft.trim()}
            onClick={submit}
          >
            {sending ? 'Thinking…' : 'Send'}
          </button>
        </div>
      </div>
    </aside>
  )
}

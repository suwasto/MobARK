import { useEffect, useMemo, useRef, useState } from 'react'
import type { ScanRead } from '../../types'
import { useChat, type ChatMessage, type ToolStep } from '../../hooks/useChat'
import { useApp } from '../../state/AppContext'
import { Markdown } from '../Markdown'

interface AgentDockProps {
  scan: ScanRead
  /** Static greeting numbers (total findings + high-severity count). */
  greeting: { total: number; high: number }
  collapsed: boolean
  onToggleCollapsed: () => void
  /** A citation was clicked — jump the Decompiler tab to that file. */
  onOpenFile: (file: string) => void
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

/** file:line references inside a tool result — clickable Decompiler jumps. */
const FILE_REF_RE =
  /([A-Za-z0-9_./-]+\.(?:java|xml|kt|kts|smali|swift|m|h|plist|json|txt|properties|yml|yaml|html|strings|entitlements))(?::(\d+))?/g

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
      {refs.map((r, i) => (
        <button
          key={`${r.file}:${r.line ?? ''}:${i}`}
          type="button"
          className="src-chip"
          title="Open in Decompiler"
          onClick={() => onOpenFile(r.file)}
        >
          {r.file}
          {r.line != null ? `:${r.line}` : ''}
        </button>
      ))}
    </div>
  )
}

function StepRow({
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
              <div className="step-result">
                <pre>{step.resultPreview}</pre>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

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
      <Markdown text={message.content} />

      {message.toolMode === 'context-only' && (
        <span className="tool-mode-tag">answered from findings context</span>
      )}

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

      {message.steps && message.steps.length > 0 && (
        <Steps steps={message.steps} onOpenFile={onOpenFile} />
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
}: AgentDockProps) {
  const { messages, pending, sending, send, stop } = useChat(scan.id)
  const { backends } = useApp()
  const [draft, setDraft] = useState('')
  const bodyRef = useRef<HTMLDivElement>(null)

  // A chat is only possible when some backend is enabled WITH a model — the
  // exact mirror of backend `pick_chat_backend` (and the ModelPicker's
  // active lookup). Without one the send button is disabled and the hint
  // says why (owner follow-up, Aug 8).
  const modelConnected = useMemo(
    () => backends.some((b) => b.enabled && b.model),
    [backends],
  )

  // Per-scan welcome message. Rebuilt on every render so the counts update
  // once findings finish loading (they start at 0); cheap string work.
  const welcome: ChatMessage = {
    id: -1,
    role: 'agent',
    content: `Scan complete for ${scan.filename}. ${greeting.total} findings, ${
      greeting.high
    } high-severity. Ask me anything about the decompiled code — try "where is certificate pinning handled?"`,
  }

  // Keep the newest message in view.
  useEffect(() => {
    const el = bodyRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages, pending, sending])

  const submit = () => {
    if (!draft.trim() || sending || !modelConnected) return
    send(draft)
    setDraft('')
  }

  // The in-flight turn: streamed text + live steps, or the thinking dots
  // before the first token/step lands.
  const streamingMessage = pending && (
    <div className="msg ai streaming">
      <span className="msg-tag">Agent</span>
      {pending.text ? (
        <>
          <div className="stream-text">{pending.text}</div>
          <span className="stream-caret" aria-hidden="true" />
        </>
      ) : pending.steps.length === 0 ? (
        <div className="thinking-row">
          <span className="thinking-dots text-bone-faint">Thinking</span>
        </div>
      ) : null}
      {pending.steps.length > 0 && (
        <div className="tools-trace-body" style={{ marginTop: 8 }}>
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
        {streamingMessage}
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
          <span className={`hint${modelConnected ? '' : ' warn'}`}>
            {modelConnected
              ? '⏎ to send'
              : 'No model connected — pick one in the top bar or Settings'}
          </span>
          {sending ? (
            <button
              type="button"
              className="stop-btn stop-icon"
              onClick={stop}
              aria-label="Stop the agent"
              title="Stop the agent — it stops at the next round"
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
                  : 'No chat model connected — pick one in the top bar or Settings'
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

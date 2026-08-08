import type { ExplainState } from '../hooks/useExplain'
import { Markdown } from './Markdown'

interface ExplainBoxProps {
  state: ExplainState
  onRetry: () => void
  className?: string
}

/** Renders the current AI-explanation state inside a `.ai-explain` box:
 * loading spinner, full explanation with Regenerate, or quiet no-model /
 * error states with Retry. Shared by the Findings tab rows and the
 * Decompiler annotation rail. */
export function ExplainBox({ state, onRetry, className }: ExplainBoxProps) {
  return (
    <div className={`ai-explain ${className ?? ''}`.trim()}>
      <div className="ai-tag">Agent explains</div>
      {state.kind === 'loading' && (
        <div className="font-mono text-[11px] text-bone-faint">
          Generating explanation…
        </div>
      )}
      {state.kind === 'ok' && (
        <>
          <Markdown text={state.data.explanation} />
          <div className="mt-3 flex items-center justify-between gap-3 border-t border-line-soft pt-2.5">
            <span className="font-mono text-[10px] text-bone-faint">
              {state.data.model ? `via ${state.data.model} · ` : ''}
              {state.data.cached ? 'cached' : 'generated on demand'}
            </span>
            <button type="button" className="link-btn" onClick={onRetry}>
              Regenerate
            </button>
          </div>
        </>
      )}
      {state.kind === 'no-model' && (
        <div className="flex items-start justify-between gap-4">
          <p>
            No model connected yet — pick a backend and model in Settings
            (top-right ⚙) and the explanation will appear here.
          </p>
          <button type="button" className="link-btn shrink-0" onClick={onRetry}>
            Retry
          </button>
        </div>
      )}
      {state.kind === 'error' && (
        <div className="flex items-start justify-between gap-4">
          <span className="font-mono text-[11px] text-crimson">
            {state.message}
          </span>
          <button type="button" className="link-btn shrink-0" onClick={onRetry}>
            Retry
          </button>
        </div>
      )}
    </div>
  )
}

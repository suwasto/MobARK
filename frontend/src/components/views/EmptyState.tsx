import { useRef, useState } from 'react'
import { BrandMark } from '../BrandMark'
import { ACCEPT_ARTIFACTS } from '../../constants'
import { useApp } from '../../state/AppContext'
import type { HealthResponse, ModelBackendRead } from '../../types'

interface EmptyStateProps {
  /** Called with the picked/dropped file (the shell runs the upload). */
  onFile: (file: File) => void
  error: string | null
}

type CheckState = 'ok' | 'warn'

interface CheckRow {
  state: CheckState
  label: string
  sub: string
}

function servicesRow(health: HealthResponse | null): CheckRow {
  if (health == null) {
    return {
      state: 'warn',
      label: 'Backend services unreachable',
      sub: 'Start the API server so uploads and analysis work',
    }
  }
  if (health.status === 'ok' && health.redis_ok && health.db_ok) {
    return { state: 'ok', label: 'Backend services running', sub: 'app · redis · worker' }
  }
  return {
    state: 'warn',
    label: 'Backend services degraded',
    sub: `redis ${health.redis_ok ? 'ok' : 'down'} · db ${health.db_ok ? 'ok' : 'down'}`,
  }
}

function modelRow(backends: ModelBackendRead[]): CheckRow {
  const connected = backends.some((b) => b.enabled && b.model && b.health?.reachable)
  if (connected) {
    return { state: 'ok', label: 'Model connected', sub: 'Agent can explain findings and chat' }
  }
  const configured = backends.some((b) => b.enabled && b.model)
  if (configured) {
    return {
      state: 'warn',
      label: 'Model configured but unreachable',
      sub: 'Start the local model server, then test the connection',
    }
  }
  return {
    state: 'warn',
    label: 'No model connected yet',
    sub: 'Needed before the agent can explain findings or chat',
  }
}

/** Empty / first-run state (mockup contract). */
export function EmptyState({ onFile, error }: EmptyStateProps) {
  const { health, backends, actions } = useApp()
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragOver, setDragOver] = useState(false)
  // Depth counter: dragleave fires when the cursor moves onto child elements
  // of the dropzone - only drop the highlight once the whole zone is exited.
  const dragDepthRef = useRef(0)

  const services = servicesRow(health)
  const model = modelRow(backends)

  const pickFile = (file: File | undefined) => {
    if (inputRef.current) inputRef.current.value = ''
    if (file) onFile(file)
  }

  return (
    <div className="flex h-full items-center justify-center overflow-y-auto p-6">
      <div className="flex w-full max-w-[520px] flex-col items-center py-6 text-center">
        <BrandMark className="mb-6 h-14 w-auto opacity-90" />

        <h1 className="font-mono text-[19px] font-semibold">No scan loaded yet</h1>
        <p className="mb-8 mt-2 max-w-[400px] text-[13px] leading-relaxed text-bone-faint">
          Upload an APK or IPA to get started. MASA decompiles it locally, runs
          static analysis, and lets you chat with an AI agent about what it
          finds.
        </p>

        <div
          role="button"
          tabIndex={0}
          className={`dropzone ${dragOver ? 'drag' : ''}`}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              inputRef.current?.click()
            }
          }}
          onDragEnter={(e) => {
            e.preventDefault()
            dragDepthRef.current += 1
            setDragOver(true)
          }}
          onDragOver={(e) => {
            e.preventDefault()
          }}
          onDragLeave={() => {
            dragDepthRef.current = Math.max(0, dragDepthRef.current - 1)
            if (dragDepthRef.current === 0) setDragOver(false)
          }}
          onDrop={(e) => {
            e.preventDefault()
            dragDepthRef.current = 0
            setDragOver(false)
            pickFile(e.dataTransfer.files?.[0])
          }}
        >
          <div className="mb-3 text-[26px] text-bone-faint">⬆</div>
          <div className="font-mono text-[13.5px]">Drop an APK or IPA here</div>
          <div className="mt-1 text-[11.5px] text-bone-faint">or click to browse</div>
          <div className="mt-3.5 font-mono text-[10.5px] tracking-[0.03em] text-bone-faint">
            .apk · .ipa
          </div>
          <input
            ref={inputRef}
            type="file"
            accept={ACCEPT_ARTIFACTS}
            className="hidden"
            onChange={(e) => pickFile(e.target.files?.[0])}
          />
        </div>

        {error && (
          <p className="mt-4 max-w-full truncate font-mono text-[11px] text-crimson" title={error}>
            {error}
          </p>
        )}

        <div className="setup-checklist mt-5">
          <div className="setup-item">
            <div className="setup-item-left">
              <div className={`setup-status ${services.state}`}>
                {services.state === 'ok' ? '✓' : '!'}
              </div>
              <div>
                <div className="setup-label">{services.label}</div>
                <div className="setup-sub">{services.sub}</div>
              </div>
            </div>
            {health == null && (
              <button
                type="button"
                className="setup-action"
                onClick={() => void actions.refreshAll()}
              >
                Retry
              </button>
            )}
          </div>
          <div className="setup-item">
            <div className="setup-item-left">
              <div className={`setup-status ${model.state}`}>
                {model.state === 'ok' ? '✓' : '!'}
              </div>
              <div>
                <div className="setup-label">{model.label}</div>
                <div className="setup-sub">{model.sub}</div>
              </div>
            </div>
          </div>
        </div>

        <p className="mt-5 text-[11px] text-bone-faint">
          Analysis stays on this machine by default - nothing uploads anywhere
          unless you turn on web research.
        </p>
      </div>
    </div>
  )
}

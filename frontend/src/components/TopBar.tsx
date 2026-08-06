import { useMemo } from 'react'
import wordmarkUrl from '../assets/masa-wordmark.svg'
import { useApp } from '../state/AppContext'

interface TopBarProps {
  onPickFile: () => void
  uploading: boolean
}

/** App shell top bar: brand, local-only indicator, model pill, actions. */
export function TopBar({ onPickFile, uploading }: TopBarProps) {
  const { backends, localOnly } = useApp()

  const modelLabel = useMemo(() => {
    const configured = backends.find((b) => b.enabled && b.model)
    if (!configured) return 'No model connected'
    return `${configured.model} · ${configured.name}`
  }, [backends])

  return (
    <header className="flex items-center justify-between gap-4 border-b border-line bg-panel px-5">
      {/* Brand */}
      <div className="flex min-w-0 items-center gap-3">
        <img src={wordmarkUrl} alt="MASA" className="h-[22px] w-auto shrink-0" draggable={false} />
        <span className="brand-tag hidden lg:inline">Mobile Application Security Assistant</span>
      </div>

      {/* Actions */}
      <div className="flex shrink-0 items-center gap-3">
        <div
          className="local-badge"
          title={
            localOnly
              ? 'No scan data or chat content leaves this machine'
              : 'A cloud backend is enabled — prompts leave this machine'
          }
        >
          <span className={`dot ${localOnly ? 'online' : 'cloud'}`} />
          <span className="hidden sm:inline">{localOnly ? 'Local-only' : 'Cloud enabled'}</span>
        </div>

        <div className="model-pill" title="Choose a model in Settings">
          <span className={`dot ${modelLabel === 'No model connected' ? 'off' : 'online'}`} />
          <span>{modelLabel}</span>
        </div>

        <button className="btn" disabled title="Export report — coming soon">
          Export report
        </button>
        <button className="btn btn-primary" onClick={onPickFile} disabled={uploading}>
          {uploading ? 'Uploading…' : '+ New scan'}
        </button>
        <button className="icon-btn" disabled title="Settings — coming soon">
          ⚙
        </button>
      </div>
    </header>
  )
}

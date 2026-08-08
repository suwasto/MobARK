import wordmarkUrl from '../assets/masa-wordmark.svg'
import { ModelPicker } from './ModelPicker'

interface TopBarProps {
  onPickFile: () => void
  uploading: boolean
  onOpenSettings: () => void
}

/** App shell top bar: brand, provider+model pickers, actions. */
export function TopBar({ onPickFile, uploading, onOpenSettings }: TopBarProps) {
  return (
    <header className="flex items-center justify-between gap-4 border-b border-line bg-panel px-5">
      {/* Brand */}
      <div className="flex min-w-0 items-center gap-3">
        <img src={wordmarkUrl} alt="MASA" className="h-[22px] w-auto shrink-0" draggable={false} />
        <span className="brand-tag hidden lg:inline">Mobile Application Security Assistant</span>
      </div>

      {/* Actions */}
      <div className="flex shrink-0 items-center gap-3">
        <ModelPicker />

        <button className="btn" disabled title="Export report — ships in M9">
          Export report
        </button>
        <button className="btn btn-primary" onClick={onPickFile} disabled={uploading}>
          {uploading ? 'Uploading…' : '+ New scan'}
        </button>
        <button className="icon-btn" onClick={onOpenSettings} title="Settings" aria-label="Settings">
          ⚙
        </button>
      </div>
    </header>
  )
}

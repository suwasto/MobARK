import { useEffect, useRef, useState } from 'react'
import { useApp } from '../../state/AppContext'
import { TargetBar } from '../TargetBar'

interface StageDef {
  key: string
  label: string
  sub: string
}

// The real orchestrator stage strings (orchestrator.on_stage + jobs.py),
// mapped to display rows. Platform is only knowable from the stage strings
// themselves (the scan row's platform is set when analysis finishes).
const ANDROID_STAGES: StageDef[] = [
  { key: 'queued', label: 'Queued', sub: 'Waiting for a worker to pick it up' },
  { key: 'starting', label: 'Started', sub: 'Pipeline initialized' },
  { key: 'decompiling', label: 'Decompiling', sub: 'jadx · source + resources' },
  { key: 'analyzing', label: 'Manifest & certificate', sub: 'androguard' },
  { key: 'code analysis', label: 'Code analysis', sub: 'Semgrep rules' },
  { key: 'secrets', label: 'Secrets scanning', sub: 'Gitleaks' },
  { key: 'done', label: 'Done', sub: 'Findings, decompiler, and agent chat ready' },
]

const IOS_STAGES: StageDef[] = [
  { key: 'queued', label: 'Queued', sub: 'Waiting for a worker to pick it up' },
  { key: 'starting', label: 'Started', sub: 'Pipeline initialized' },
  { key: 'unpacking', label: 'Unpacking', sub: 'IPA → Payload/*.app' },
  { key: 'analyzing', label: 'Binary analysis', sub: 'Info.plist + Mach-O (LIEF)' },
  { key: 'entitlements', label: 'Entitlements', sub: 'Code-signature carve' },
  { key: 'symbols', label: 'Import-table scan', sub: 'Known-insecure APIs' },
  { key: 'secrets', label: 'Secrets scanning', sub: 'Gitleaks' },
  { key: 'done', label: 'Done', sub: 'Findings, decompiler, and agent chat ready' },
]

const IOS_ONLY = new Set(['unpacking', 'entitlements', 'symbols'])
const ANDROID_ONLY = new Set(['decompiling', 'code analysis'])

function formatElapsed(totalSeconds: number): string {
  const m = Math.floor(totalSeconds / 60)
  const s = totalSeconds % 60
  return `${m}m ${String(s).padStart(2, '0')}s`
}

interface ProgressScreenProps {
  onPickFile: () => void
  uploading: boolean
}

/** Scan-in-progress screen: live stage pipeline driven by Scan.stage. */
export function ProgressScreen({ onPickFile, uploading }: ProgressScreenProps) {
  const { activeScan } = useApp()
  const stage = activeScan?.stage ?? 'queued'
  const [elapsed, setElapsed] = useState(0)
  const startAtRef = useRef(Date.now())
  // The platform is remembered once a stage reveals it, so an iOS scan that
  // has already passed 'unpacking' keeps its iOS pipeline while at 'secrets'.
  const platformRef = useRef<'android' | 'ios' | null>(null)

  useEffect(() => {
    startAtRef.current = Date.now()
    setElapsed(0)
    const id = window.setInterval(() => {
      setElapsed(Math.floor((Date.now() - startAtRef.current) / 1000))
    }, 1000)
    return () => window.clearInterval(id)
  }, [activeScan?.id])

  useEffect(() => {
    if (IOS_ONLY.has(stage)) platformRef.current = 'ios'
    else if (ANDROID_ONLY.has(stage)) platformRef.current = 'android'
  }, [stage])

  // Both stage lists are module constants — a plain per-render pick is
  // always correct (a useMemo with a missing dep would freeze the platform
  // flip that happens when a stage string first reveals the platform).
  const stages = platformRef.current === 'ios' ? IOS_STAGES : ANDROID_STAGES
  const activeIdx = Math.max(0, stages.findIndex((s) => s.key === stage))
  const active = stages[activeIdx]

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TargetBar onPickFile={onPickFile} uploading={uploading} />
        <div className="flex min-h-0 flex-1 items-center justify-center overflow-y-auto p-6">
          <div className="w-full max-w-[480px] rounded-lg border border-line bg-panel px-7 py-6">
        {/* Head */}
        <div className="mb-1.5 flex items-center gap-2.5">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded border border-line bg-panel-raised text-xs">
            📦
          </span>
          <span className="truncate font-mono text-sm text-bone">
            {activeScan?.filename ?? 'Scan'}
          </span>
          {platformRef.current && (
            <span className="rounded-[2px] border border-line px-1 py-0.5 font-mono text-[9px] tracking-wider text-bone-faint">
              {platformRef.current === 'ios' ? 'iOS' : 'Android'}
            </span>
          )}
        </div>
        <p className="mb-5 text-[11.5px] text-bone-faint">
          {activeScan?.status === 'queued'
            ? 'Queued — waiting for a worker…'
            : `${active.label} — ${active.sub}`}
        </p>

        {/* Bar */}
        <div className="mb-1 h-[5px] w-full overflow-hidden rounded-[3px] bg-line-soft">
          <div className="animate-indeterminate h-full w-1/3 rounded-[3px] bg-steel" />
        </div>
        <div className="mb-5 flex justify-between font-mono text-[10.5px] text-bone-faint">
          <span>
            Step {activeIdx + 1} of {stages.length}
          </span>
          <span>{formatElapsed(elapsed)} elapsed</span>
        </div>

        {/* Pipeline */}
        <div className="border-t border-line-soft pt-2">
          {stages.map((s, i) => {
            const state = i < activeIdx ? 'done' : i === activeIdx ? 'active' : 'pending'
            return (
              <div key={s.key} className={`pipeline-step ${state}`}>
                <div className={`pipeline-icon ${state === 'active' ? 'active' : ''}`}>
                  {state === 'done' ? '✓' : state === 'active' ? '●' : String(i + 1)}
                </div>
                <div className="min-w-0">
                  <div className="pstep-name">{s.label}</div>
                  <div className="pstep-sub">{s.sub}</div>
                </div>
              </div>
            )
          })}
        </div>

        <div className="mt-4 flex justify-end border-t border-line-soft pt-4">
          <button className="btn" disabled title="Scans always complete in the background in v1">
            Cancel scan
          </button>
        </div>
          <p className="mt-4 text-[11px] leading-relaxed text-bone-faint">
            You can switch to any other scan or start a new one — MASA keeps
            analyzing in the background and this scan will show up in “Open a
            different scan” when it’s done.
          </p>
          </div>
        </div>
    </div>
  )
}

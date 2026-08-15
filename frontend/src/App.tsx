import { useEffect, useMemo, useRef, useState } from 'react'
import { BrandMark } from './components/BrandMark'
import { LoginView } from './components/auth/LoginView'
import { SettingsModal } from './components/settings/SettingsModal'
import { TopBar } from './components/TopBar'
import { DashboardView } from './components/views/DashboardView'
import { EmptyState } from './components/views/EmptyState'
import { ProgressScreen } from './components/views/ProgressScreen'
import { ACCEPT_ARTIFACTS } from './constants'
import { useScanPolling } from './hooks/useScanPolling'
import { AppProvider, useApp } from './state/AppContext'

function BootSplash() {
  return (
    <div className="flex h-screen items-center justify-center bg-graphite">
      <BrandMark className="animate-pulse-ring h-12 w-auto opacity-80" />
    </div>
  )
}

function Shell() {
  const { booting, auth, view, scans, activeScan, actions } = useApp()
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  // Progress is a dismissible dialog now - the scan keeps running in the
  // background, and the dashboard flips to it automatically when it finishes.
  const [progressDismissed, setProgressDismissed] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Poll every 2.5s while the active scan is queued/running, or while ANY
  // background scan is still going (the progress-dialog copy: "MobARK keeps
  // analyzing in the background") so completion always lands on the list.
  const anyScanRunning = useMemo(
    () => scans.some((s) => s.status === 'queued' || s.status === 'running'),
    [scans],
  )
  useScanPolling(view === 'progress' || anyScanRunning, actions.refreshScans)

  // A newly active scan (new upload, or selecting another running scan)
  // brings the dialog back - the dismiss flag is per-scan.
  useEffect(() => setProgressDismissed(false), [activeScan?.id])

  // Backdrop for the progress dialog: the newest non-running scan's
  // dashboard, or the empty state on a fresh install.
  const backdropScan = useMemo(() => {
    if (view !== 'progress') return null
    return (
      [...scans]
        .sort((a, b) => b.id - a.id)
        .find((s) => s.id !== activeScan?.id && (s.status === 'done' || s.status === 'failed')) ??
      null
    )
  }, [view, scans, activeScan?.id])

  const handleFile = async (file: File) => {
    setUploadError(null)
    if (!file.name.toLowerCase().endsWith('.apk') && !file.name.toLowerCase().endsWith('.ipa')) {
      setUploadError('Unsupported file - expected .apk or .ipa')
      return
    }
    setUploading(true)
    try {
      await actions.uploadScan(file)
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : String(err))
    } finally {
      setUploading(false)
    }
  }

  if (booting) return <BootSplash />
  // M9.1: the auth gate - no session (and auth is ON) renders the login
  // screen instead of the app shell. Auth-off parity mode never gets here.
  if (auth === 'anon') return <LoginView />

  // The scan currently on screen - the TopBar Export button targets it. The
  // progress backdrop shows the last completed scan (NOT the running one),
  // so `scanOverride ?? activeScan` is the same selection DashboardView
  // renders; exporting the running scan would 409 anyway.
  const visibleScan = view === 'progress' ? backdropScan ?? activeScan : activeScan

  return (
    <div className="grid h-screen grid-rows-[52px_1fr]">
      <TopBar
        onPickFile={() => fileInputRef.current?.click()}
        uploading={uploading}
        onOpenSettings={() => setSettingsOpen(true)}
        scan={visibleScan}
      />

      {/* `relative` scopes the progress-dialog overlay to the main area so
          the top bar stays visible while a scan runs (the old full-view
          progress screen could push header/footer off-screen). */}
      <main className="relative min-h-0 overflow-hidden">
        {view === 'empty' && <EmptyState onFile={(f) => void handleFile(f)} error={uploadError} />}
        {view === 'loaded' && (
          <DashboardView
            onPickFile={() => fileInputRef.current?.click()}
            uploading={uploading}
          />
        )}
        {/* The progress backdrop: the last completed scan's dashboard (or the
            empty state) stays interactive behind the dialog. */}
        {view === 'progress' && backdropScan && (
          <DashboardView
            onPickFile={() => fileInputRef.current?.click()}
            uploading={uploading}
            scanOverride={backdropScan}
          />
        )}
        {view === 'progress' && !backdropScan && (
          <EmptyState onFile={(f) => void handleFile(f)} error={uploadError} />
        )}
        {view === 'progress' && !progressDismissed && (
          <ProgressScreen onClose={() => setProgressDismissed(true)} />
        )}
      </main>

      {/* Single hidden file input powers both the top-bar and dropzone triggers. */}
      <input
        ref={fileInputRef}
        type="file"
        accept={ACCEPT_ARTIFACTS}
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0]
          // Reset immediately so re-selecting the same file still fires change.
          if (fileInputRef.current) fileInputRef.current.value = ''
          if (file) void handleFile(file)
        }}
      />

      <SettingsModal open={settingsOpen} onClose={() => setSettingsOpen(false)} />
    </div>
  )
}

export default function App() {
  return (
    <AppProvider>
      <Shell />
    </AppProvider>
  )
}

import { useRef, useState } from 'react'
import { BrandMark } from './components/BrandMark'
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
  const { booting, view, actions } = useApp()
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // M5 progress contract: poll every 2.5s while a scan is queued/running.
  useScanPolling(view === 'progress', actions.refreshScans)

  const handleFile = async (file: File) => {
    setUploadError(null)
    if (!file.name.toLowerCase().endsWith('.apk') && !file.name.toLowerCase().endsWith('.ipa')) {
      setUploadError('Unsupported file — expected .apk or .ipa')
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

  return (
    <div className="grid h-screen grid-rows-[52px_1fr]">
      <TopBar onPickFile={() => fileInputRef.current?.click()} uploading={uploading} />

      <main className="min-h-0 overflow-hidden">
        {view === 'empty' && <EmptyState onFile={(f) => void handleFile(f)} error={uploadError} />}
        {view === 'progress' && (
          <ProgressScreen
            onPickFile={() => fileInputRef.current?.click()}
            uploading={uploading}
          />
        )}
        {view === 'loaded' && (
          <DashboardView
            onPickFile={() => fileInputRef.current?.click()}
            uploading={uploading}
          />
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

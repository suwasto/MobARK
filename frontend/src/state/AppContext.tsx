import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'
import type { ReactNode } from 'react'
import { api } from '../api/client'
import type { HealthResponse, ModelBackendRead, ScanRead } from '../types'

/**
 * M5 view machine — derives purely from the active scan's status:
 *   no scans                -> 'empty'
 *   active queued/running   -> 'progress'
 *   active done/failed      -> 'loaded'
 *
 * The active scan id persists to localStorage; on boot the most recent scan
 * is auto-selected when nothing valid is stored.
 */
export type View = 'empty' | 'progress' | 'loaded'

const ACTIVE_SCAN_KEY = 'masa.activeScanId'

interface AppContextValue {
  /** First load in flight — shell shows the boot splash. */
  booting: boolean
  view: View
  scans: ScanRead[]
  activeScan: ScanRead | null
  health: HealthResponse | null
  backends: ModelBackendRead[]
  /** Green "Local-only" while no *usable* cloud route exists. */
  localOnly: boolean
  actions: {
    refreshScans: () => Promise<void>
    refreshHealth: () => Promise<void>
    refreshBackends: () => Promise<void>
    refreshAll: () => Promise<void>
    selectScan: (id: number | null) => void
    uploadScan: (file: File) => Promise<ScanRead>
  }
}

const AppContext = createContext<AppContextValue | null>(null)

function readStoredScanId(): number | null {
  try {
    const raw = localStorage.getItem(ACTIVE_SCAN_KEY)
    if (raw == null) return null
    const n = Number(raw)
    return Number.isFinite(n) ? n : null
  } catch {
    return null
  }
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [scans, setScans] = useState<ScanRead[]>([])
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [backends, setBackends] = useState<ModelBackendRead[]>([])
  const [activeScanId, setActiveScanId] = useState<number | null>(readStoredScanId)
  const [booting, setBooting] = useState(true)

  const refreshScans = useCallback(async () => {
    try {
      const list = await api.listScans()
      setScans(list)
      setActiveScanId((prev) => {
        if (prev != null && list.some((s) => s.id === prev)) return prev
        return list[0]?.id ?? null
      })
    } catch {
      // Backend unreachable — keep whatever state we already had.
    }
  }, [])

  const refreshHealth = useCallback(async () => {
    try {
      setHealth(await api.health())
    } catch {
      setHealth(null)
    }
  }, [])

  const refreshBackends = useCallback(async () => {
    try {
      setBackends(await api.listBackends())
    } catch {
      setBackends([])
    }
  }, [])

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshScans(), refreshHealth(), refreshBackends()])
    setBooting(false)
  }, [refreshScans, refreshHealth, refreshBackends])

  useEffect(() => {
    void refreshAll()
  }, [refreshAll])

  const selectScan = useCallback((id: number | null) => {
    setActiveScanId(id)
    try {
      if (id == null) {
        localStorage.removeItem(ACTIVE_SCAN_KEY)
      } else {
        localStorage.setItem(ACTIVE_SCAN_KEY, String(id))
      }
    } catch {
      // Storage unavailable (private mode) — session-only selection is fine.
    }
  }, [])

  const uploadScan = useCallback(
    async (file: File) => {
      const scan = await api.createScan(file)
      await refreshScans()
      selectScan(scan.id)
      return scan
    },
    [refreshScans, selectScan],
  )

  const activeScan = useMemo(() => {
    if (activeScanId != null) {
      const byId = scans.find((s) => s.id === activeScanId)
      if (byId) return byId
    }
    return scans[0] ?? null
  }, [scans, activeScanId])

  const view: View = useMemo(() => {
    if (!activeScan) return 'empty'
    if (activeScan.status === 'queued' || activeScan.status === 'running') {
      return 'progress'
    }
    return 'loaded'
  }, [activeScan])

  // A BYOK provider only counts as a cloud route once it has an API key
  // (a keyless seeded card cannot send anything); custom endpoints count
  // the moment they are added. Local backends never count.
  const localOnly = useMemo(
    () =>
      !backends.some(
        (b) => b.enabled && !b.local && (b.has_api_key || b.kind === 'custom'),
      ),
    [backends],
  )

  const value = useMemo<AppContextValue>(
    () => ({
      booting,
      view,
      scans,
      activeScan,
      health,
      backends,
      localOnly,
      actions: {
        refreshScans,
        refreshHealth,
        refreshBackends,
        refreshAll,
        selectScan,
        uploadScan,
      },
    }),
    [
      booting,
      view,
      scans,
      activeScan,
      health,
      backends,
      localOnly,
      refreshScans,
      refreshHealth,
      refreshBackends,
      refreshAll,
      selectScan,
      uploadScan,
    ],
  )

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>
}

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext)
  if (ctx == null) {
    throw new Error('useApp must be used within <AppProvider>')
  }
  return ctx
}

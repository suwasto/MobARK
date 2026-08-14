import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'
import type { ReactNode } from 'react'
import { api, setOnUnauthorized } from '../api/client'
import type {
  HealthResponse,
  ModelBackendCreate,
  ModelBackendRead,
  ModelBackendUpsert,
  ProvidersResponse,
  ScanRead,
  SearchBackendCreate,
  SearchBackendRead,
  SearchBackendUpsert,
  UserRead,
} from '../types'

/**
 * M5 view machine - derives purely from the active scan's status:
 *   no scans                -> 'empty'
 *   active queued/running   -> 'progress'
 *   active done/failed      -> 'loaded'
 *
 * The active scan id persists to localStorage; on boot the most recent scan
 * is auto-selected when nothing valid is stored.
 */
export type View = 'empty' | 'progress' | 'loaded'

/** M9.1: the auth gate. `booting` = providers+me boot in flight (the shell
 * shows the boot splash); `anon` = auth is ON and there's no session (the
 * shell renders LoginView); `authed` = a session exists OR auth is OFF
 * (dev/CI parity - the login screen never appears). */
export type AuthState = 'booting' | 'anon' | 'authed'

const ACTIVE_SCAN_KEY = 'masa.activeScanId'

interface AppContextValue {
  /** First load in flight - shell shows the boot splash. */
  booting: boolean
  /** M9.1: the auth gate (login screen vs app shell). */
  auth: AuthState
  /** M9.1: the session's user (null in auth-off mode) - the TopBar chip. */
  user: UserRead | null
  /** M9.1: configured sign-in methods + auth-on/off flag (login page). */
  providers: ProvidersResponse | null
  view: View
  scans: ScanRead[]
  activeScan: ScanRead | null
  health: HealthResponse | null
  backends: ModelBackendRead[]
  /** M7: configured search engines (the web-research radio list). */
  searchBackends: SearchBackendRead[]
  actions: {
    /** M9.1: username/password login (register/login view). */
    login: (username: string, password: string) => Promise<UserRead>
    /** M9.1: create the first/admin account or a new user. */
    register: (username: string, password: string, email?: string) => Promise<UserRead>
    /** M9.1: revoke the session + drop to the login screen. */
    logout: () => Promise<void>
    /** M9.1: clear the session locally after a 401 (no network call). */
    clearSession: () => void
    /** M9.1 vault: unlock with the vault passphrase (OAuth accounts; first
     * use creates it). Refreshes the backend lists so key states re-read. */
    unlockVault: (passphrase: string) => Promise<void>
    /** M9.1 vault: forgot the passphrase - destroy the vault + clear keys. */
    resetVault: () => Promise<void>
    refreshScans: () => Promise<void>
    refreshHealth: () => Promise<void>
    refreshBackends: () => Promise<void>
    refreshSearchBackends: () => Promise<void>
    refreshAll: () => Promise<void>
    selectScan: (id: number | null) => void
    uploadScan: (file: File) => Promise<ScanRead>
    /** M5 Phase H - model backend mutations (Settings modal + ModelPicker). */
    updateBackend: (id: string, payload: ModelBackendUpsert) => Promise<void>
    /** Batch PUTs with a single refresh - avoids N full backend re-probes. */
    updateBackends: (entries: { id: string; payload: ModelBackendUpsert }[]) => Promise<void>
    createBackend: (payload: ModelBackendCreate) => Promise<void>
    deleteBackend: (id: string) => Promise<void>
    /** Full health probe; the probed backend is merged into state in place. */
    testBackend: (id: string) => Promise<ModelBackendRead>
    /** M7 - search engine mutations (Settings -> Search & research). */
    updateSearchBackend: (id: string, payload: SearchBackendUpsert) => Promise<void>
    createSearchBackend: (payload: SearchBackendCreate) => Promise<void>
    deleteSearchBackend: (id: string) => Promise<void>
    /** Full probe; the probed engine is merged into state in place. */
    testSearchBackend: (id: string) => Promise<SearchBackendRead>
    /** One-click start for the bundled engine (compose up + wait, server-
     * side); the returned card carries the fresh health, merged in place. */
    startSearchBackend: (id: string) => Promise<SearchBackendRead>
    /** M7 - per-scan web research opt-in (the dock 🌐 toggle). Refreshes the
     * scan list so ScanRead.web_research_enabled stays honest. */
    setWebResearch: (scanId: number, enabled: boolean) => Promise<void>
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
  const [searchBackends, setSearchBackends] = useState<SearchBackendRead[]>([])
  const [activeScanId, setActiveScanId] = useState<number | null>(readStoredScanId)
  const [booting, setBooting] = useState(true)
  // M9.1 auth state.
  const [auth, setAuth] = useState<AuthState>('booting')
  const [user, setUser] = useState<UserRead | null>(null)
  const [providers, setProviders] = useState<ProvidersResponse | null>(null)

  const refreshScans = useCallback(async () => {
    try {
      const list = await api.listScans()
      setScans(list)
      setActiveScanId((prev) => {
        if (prev != null && list.some((s) => s.id === prev)) return prev
        return list[0]?.id ?? null
      })
    } catch {
      // Backend unreachable - keep whatever state we already had.
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

  const refreshSearchBackends = useCallback(async () => {
    try {
      setSearchBackends(await api.listSearchBackends())
    } catch {
      setSearchBackends([])
    }
  }, [])

  const refreshAll = useCallback(async () => {
    await Promise.all([
      refreshScans(),
      refreshHealth(),
      refreshBackends(),
      refreshSearchBackends(),
    ])
  }, [refreshScans, refreshHealth, refreshBackends, refreshSearchBackends])

  const selectScan = useCallback((id: number | null) => {
    setActiveScanId(id)
    try {
      if (id == null) {
        localStorage.removeItem(ACTIVE_SCAN_KEY)
      } else {
        localStorage.setItem(ACTIVE_SCAN_KEY, String(id))
      }
    } catch {
      // Storage unavailable (private mode) - session-only selection is fine.
    }
  }, [])

  /** M9.1: drop to the login screen + clear the active scan (audit gap 3:
   * the stored activeScanId must not survive into another user's session -
   * refreshScans' fallback would re-derive it, but explicit is safer). */
  const clearSession = useCallback(() => {
    setUser(null)
    setAuth('anon')
    selectScan(null)
  }, [selectScan])

  // M9.1: any guarded request that 401s (session expired/revoked mid-use)
  // drops the UI to login. Auth-route 401s (bad password) never reach here.
  useEffect(() => {
    setOnUnauthorized(clearSession)
    return () => setOnUnauthorized(null)
  }, [clearSession])

  // M9.1 boot: providers tells us whether auth is even on; me resolves the
  // session. Auth-off (dev/CI parity) skips login entirely. Data refreshes
  // only run when the gate opened - an anon boot would 401 every guarded
  // call (each firing the onUnauthorized hook) for no reason.
  useEffect(() => {
    const boot = async () => {
      let p: ProvidersResponse | null = null
      try {
        p = await api.providers()
      } catch {
        // Backend unreachable - stay open (pre-auth behavior) so the shell
        // can show its own degraded-state messaging.
        setAuth('authed')
      }
      setProviders(p)
      let authed = false
      if (p == null) {
        // providers fetch failed - open mode (the EmptyState shows the
        // unreachable-backend warning).
        authed = true
      } else if (!p.auth_enabled) {
        // Auth is OFF: no login screen, no user - today's open behavior.
        authed = true
      } else {
        try {
          const me = await api.me()
          if (me) {
            setUser(me)
            authed = true
          }
        } catch {
          // No/invalid session - the login screen.
        }
      }
      setAuth(authed ? 'authed' : 'anon')
      setBooting(false)
      if (authed) await refreshAll()
    }
    void boot()
    // Boot once on mount; refreshAll is stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const login = useCallback(
    async (username: string, password: string) => {
      const { user: u } = await api.login({ username, password })
      setUser(u)
      setAuth('authed')
      selectScan(null)
      await refreshAll()
      return u
    },
    [refreshAll, selectScan],
  )

  const register = useCallback(
    async (username: string, password: string, email?: string) => {
      const { user: u } = await api.register({ username, password, email: email || null })
      setUser(u)
      setAuth('authed')
      selectScan(null)
      await refreshAll()
      return u
    },
    [refreshAll, selectScan],
  )

  /** M9.1 vault: after a successful unlock the session can access the vault
   * - clear the flag locally and refresh the key-bearing lists. */
  const unlockVault = useCallback(
    async (passphrase: string) => {
      await api.unlockVault(passphrase)
      setUser((u) => (u ? { ...u, vault_locked: false } : u))
      await refreshBackends()
      await refreshSearchBackends()
    },
    [refreshBackends, refreshSearchBackends],
  )

  /** M9.1 vault: reset destroys the vault and clears stored keys; a fresh
   * passphrase (via unlockVault) re-creates it. */
  const resetVault = useCallback(async () => {
    await api.resetVault()
    await refreshBackends()
    await refreshSearchBackends()
  }, [refreshBackends, refreshSearchBackends])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } catch {
      // Idempotent server-side - even a network failure still drops the UI.
    }
    selectScan(null)
    setUser(null)
    setScans([])
    setAuth('anon')
  }, [selectScan])

  const uploadScan = useCallback(
    async (file: File) => {
      const scan = await api.createScan(file)
      await refreshScans()
      selectScan(scan.id)
      return scan
    },
    [refreshScans, selectScan],
  )

  const updateBackend = useCallback(
    async (id: string, payload: ModelBackendUpsert) => {
      await api.updateBackend(id, payload)
      await refreshBackends()
    },
    [refreshBackends],
  )

  const updateBackends = useCallback(
    async (entries: { id: string; payload: ModelBackendUpsert }[]) => {
      await Promise.all(entries.map((e) => api.updateBackend(e.id, e.payload)))
      await refreshBackends()
    },
    [refreshBackends],
  )

  const createBackend = useCallback(
    async (payload: ModelBackendCreate) => {
      await api.createBackend(payload)
      await refreshBackends()
    },
    [refreshBackends],
  )

  const deleteBackend = useCallback(
    async (id: string) => {
      await api.deleteBackend(id)
      await refreshBackends()
    },
    [refreshBackends],
  )

  const testBackend = useCallback(async (id: string) => {
    const probed = await api.testBackend(id)
    // Merge the probe result in place - a full refresh would downgrade the
    // probe to the lightweight reachability check this result already carries.
    setBackends((prev) => prev.map((b) => (b.id === probed.id ? probed : b)))
    return probed
  }, [])

  const updateSearchBackend = useCallback(
    async (id: string, payload: SearchBackendUpsert) => {
      await api.updateSearchBackend(id, payload)
      await refreshSearchBackends()
    },
    [refreshSearchBackends],
  )

  const createSearchBackend = useCallback(
    async (payload: SearchBackendCreate) => {
      await api.createSearchBackend(payload)
      await refreshSearchBackends()
    },
    [refreshSearchBackends],
  )

  const deleteSearchBackend = useCallback(
    async (id: string) => {
      await api.deleteSearchBackend(id)
      await refreshSearchBackends()
    },
    [refreshSearchBackends],
  )

  const testSearchBackend = useCallback(async (id: string) => {
    const probed = await api.testSearchBackend(id)
    // Merge the probe result in place (same as the model-backend probe).
    setSearchBackends((prev) => prev.map((b) => (b.id === probed.id ? probed : b)))
    return probed
  }, [])

  /** One-click start for the bundled engine - the returned card carries the
   * fresh health, merged in place so a full list refresh never downgrades it
   * to the lightweight reachability check. */
  const startSearchBackend = useCallback(async (id: string) => {
    const started = await api.startSearchBackend(id)
    setSearchBackends((prev) => prev.map((b) => (b.id === started.id ? started : b)))
    return started
  }, [])

  const setWebResearch = useCallback(
    async (scanId: number, enabled: boolean) => {
      await api.setWebResearch(scanId, enabled)
      await refreshScans()
    },
    [refreshScans],
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

  const value = useMemo<AppContextValue>(
    () => ({
      booting,
      auth,
      user,
      providers,
      view,
      scans,
      activeScan,
      health,
      backends,
      searchBackends,
      actions: {
        login,
        register,
        logout,
        clearSession,
        unlockVault,
        resetVault,
        refreshScans,
        refreshHealth,
        refreshBackends,
        refreshSearchBackends,
        refreshAll,
        selectScan,
        uploadScan,
        updateBackend,
        updateBackends,
        createBackend,
        deleteBackend,
        testBackend,
        updateSearchBackend,
        createSearchBackend,
        deleteSearchBackend,
        testSearchBackend,
        startSearchBackend,
        setWebResearch,
      },
    }),
    [
      booting,
      auth,
      user,
      providers,
      view,
      scans,
      activeScan,
      health,
      backends,
      searchBackends,
      login,
      register,
      logout,
      clearSession,
      unlockVault,
      resetVault,
      refreshScans,
      refreshHealth,
      refreshBackends,
      refreshSearchBackends,
      refreshAll,
      selectScan,
      uploadScan,
      updateBackend,
      updateBackends,
      createBackend,
      deleteBackend,
      testBackend,
      updateSearchBackend,
      createSearchBackend,
      deleteSearchBackend,
      testSearchBackend,
      startSearchBackend,
      setWebResearch,
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

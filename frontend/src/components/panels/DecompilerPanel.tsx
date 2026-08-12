import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { api } from '../../api/client'
import type { FileNode, FileTreeResponse, FindingRead, SmaliStatus } from '../../types'
import { RecompileModal } from '../RecompileModal'
import { Splitter } from '../Splitter'
import { AnnotationRail } from '../code/AnnotationRail'
import { CodeEditor } from '../code/CodeEditor'
import { CodeViewer } from '../code/CodeViewer'
import { FileTree } from '../code/FileTree'

const TREE_KEY = 'masa.decomp.treeW'
const RAIL_KEY = 'masa.decomp.railW'
const TREE_DEFAULT = 210
const RAIL_DEFAULT = 220
const TREE_MIN = 140
const TREE_MAX = 460
const RAIL_MIN = 160
const RAIL_MAX = 460
// M8 follow-up: the annotations rail's minimized flag - persisted like the
// splitter widths so a collapsed rail stays collapsed across sessions.
const RAIL_MIN_KEY = 'masa.decomp.railMin'

function readWidth(key: string, fallback: number, min: number, max: number): number {
  try {
    const n = Number(localStorage.getItem(key))
    if (Number.isFinite(n)) return Math.min(max, Math.max(min, n))
  } catch {
    // Storage unavailable (private mode) - session defaults are fine.
  }
  return fallback
}

function readFlag(key: string, fallback = false): boolean {
  try {
    const v = localStorage.getItem(key)
    if (v != null) return v === '1'
  } catch {
    // Storage unavailable (private mode) - session default.
  }
  return fallback
}

function clampWidth(v: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, v))
}

interface DecompilerPanelProps {
  scanId: number
  findings: FindingRead[]
  /** Findings are fetched async by the dashboard - skip the default file
   * pick until they are loaded so app-code-with-findings wins. */
  findingsLoading: boolean
  /** Agent-citation click: open a file. `file` is relative to the platform
   * tree root (e.g. `com/app/MyWebViewClient.java`); resolved against the
   * loaded tree, then reported back via `onRequestConsumed`. */
  requestFile?: { file: string; nonce: number } | null
  onRequestConsumed?: () => void
  /** M8 Phase D (moved to the dashboard after the Aug 11 owner request):
   * the agent edit-proposal review is a shared surface - the dock chat
   * proposes edits (search_code -> find_smali_sibling -> read_editable_file
   * -> propose_smali_edit) and BOTH the dock's "Review edits (n)" pill and
   * this toolbar badge open the same ProposalsModal. The edits list, the
   * modal, and the editor-remount version all live in DashboardView. */
  proposedCount: number
  editVersion: number
  onOpenProposals: () => void
}

const SEV_RANK: Record<string, number> = {
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
}

// M8 Phase B: the editable tree roots - apktool's rebuildable surface only.
// jadx `sources/` (and everything else) stays read-only, server-enforced.
function isEditableRoot(rootName: string): boolean {
  return (
    rootName === 'AndroidManifest.xml' ||
    rootName === 'res' ||
    rootName === 'smali' ||
    rootName.startsWith('smali_classes')
  )
}

/** Which side of the Java/Smali toggle a tree root belongs to. The tree is
 * filtered by the active view (owner decision, Aug 10): jadx `sources` +
 * `resources` are the read-only Java analysis surface; the apktool roots
 * (`smali`, `smali_classesN`, `res`, `AndroidManifest.xml`) are the
 * editable Smali surface. */
function isJavaRoot(rootName: string): boolean {
  return rootName === 'sources' || rootName === 'resources'
}

/** Tree selection -> apktool-root-relative edit path (POST /edits). */
function editPathFor(rootName: string, path: string): string {
  // The manifest synthetic root's tree path is `AndroidManifest.xml/AndroidManifest.xml`;
  // its edit path is just `AndroidManifest.xml` (the tree path already is the
  // edit path for the real smali/res roots).
  return rootName === 'AndroidManifest.xml' ? 'AndroidManifest.xml' : `${rootName}/${path}`
}

function collectFiles(
  rootName: string,
  nodes: FileNode[],
  out: { rootName: string; path: string }[],
): void {
  for (const n of nodes) {
    if (n.type === 'file') out.push({ rootName, path: n.path })
    else collectFiles(rootName, n.children, out)
  }
}

/** Default open: first app-code file with findings, else first with findings. */
function findDefaultFile(
  files: FileTreeResponse | null,
  findingFiles: Set<string>,
): { rootName: string; path: string } | null {
  if (!files) return null
  const all: { rootName: string; path: string }[] = []
  for (const root of files.roots) collectFiles(root.name, root.tree, all)
  return (
    all.find((f) => f.path.startsWith('com/') && findingFiles.has(f.path)) ??
    all.find((f) => findingFiles.has(f.path)) ??
    all[0] ??
    null
  )
}

/**
 * Resolve an agent citation / @-mention path against the bounded tree.
 * Two shapes arrive:
 * - Agent citations + graph nodes are ROOT-RELATIVE: Android `com/...` under
 *   the `sources` root, iOS relative to the `Payload/*.app` root (whose name
 *   IS the root name). Try `<root>/<file>` for each root, then a suffix
 *   match as a last resort.
 * - @-mention chips pass FULL tree paths (`<root>/<rel>`, e.g.
 *   `smali/com/foo/A.smali` - what the mention picker inserts) - split the
 *   root off and look up the remaining relative path directly (review
 *   catch, Aug 11: without this a smali mention fell back to the auto-open
 *   default instead of opening the mentioned file).
 */
function resolveTreePath(
  files: FileTreeResponse,
  file: string,
): { rootName: string; path: string } | null {
  const all: { rootName: string; path: string }[] = []
  for (const root of files.roots) collectFiles(root.name, root.tree, all)
  const byPath = new Set(all.map((f) => f.path))
  const exact = all.find((f) => f.path === file)
  if (exact) return exact
  for (const root of files.roots) {
    const candidate = `${root.name}/${file}`
    if (byPath.has(candidate)) return { rootName: root.name, path: candidate }
  }
  // M8 follow-up: full tree paths from the @-mention picker - strip the
  // leading root (e.g. `smali/com/foo/A.smali` -> root `smali`, rel
  // `com/foo/A.smali`) and match that root's node directly.
  const slash = file.indexOf('/')
  if (slash > 0) {
    const rootName = file.slice(0, slash)
    const rel = file.slice(slash + 1)
    const direct = all.find((f) => f.rootName === rootName && f.path === rel)
    if (direct) return direct
  }
  // Graph node files are normalized to root-relative in the backend
  // (graphify._normalize_source_file), so this resolver only ever sees
  // root-relative paths - no root-prefix handling needed here.
  return all.find((f) => f.path.endsWith(`/${file}`)) ?? null
}

/** Decompiler tab: bounded file tree + highlighted viewer + annotation rail. */
export function DecompilerPanel({
  scanId,
  findings,
  findingsLoading,
  requestFile,
  onRequestConsumed,
  proposedCount,
  editVersion,
  onOpenProposals,
}: DecompilerPanelProps) {
  const [files, setFiles] = useState<FileTreeResponse | null>(null)
  const [filesLoading, setFilesLoading] = useState(true)
  const [filesError, setFilesError] = useState<string | null>(null)
  const [selected, setSelected] = useState<{
    rootName: string
    path: string
  } | null>(null)
  const [activeNoteId, setActiveNoteId] = useState<number | null>(null)

  // M8: on-demand apktool decode (the live Smali chip) + the Java/Smali
  // view toggle. `smali` is null until the first status fetch lands.
  const [smali, setSmali] = useState<SmaliStatus | null>(null)
  const [view, setView] = useState<'java' | 'smali'>('java')
  // Smali-mode analysis (owner request, Aug 10): the Java→Smali mapping for
  // the scan's findings - fetched once the decode is ready so Smali mode
  // shows the same tree dots + rail notes as Java mode (findings live on
  // jadx `sources/...` paths; their apktool smali siblings annotate too).
  // Null = not fetched yet (or non-Android); {} = fetched, nothing mapped.
  const [smaliMap, setSmaliMap] = useState<Record<string, string> | null>(null)
  // Aug 11 one-scroll follow-up: smali-mode LINE anchors for the rail notes.
  // jadx renumbers source lines, so the smali notes can't pin statement-to-
  // statement - instead each finding's jadx line maps to its containing
  // method's `.method` line in the smali sibling (computed server-side,
  // cached with the mapping). The aliased smali notes use these as their
  // line_number so they align with the smali editor's own line numbers.
  // Keyed by full smali tree path, then str(jadx line) -> smali line.
  const [smaliAnchors, setSmaliAnchors] = useState<Record<
    string,
    Record<string, number>
  > | null>(null)

  // The tree follows the active view (owner decision, Aug 10): Java mode
  // shows only the jadx analysis surface (sources + resources), Smali mode
  // only the editable rebuild surface (smali*/res/AndroidManifest.xml).
  // iOS keeps the full bundle tree - the toggle is hidden there anyway.
  const visibleRoots = useMemo(() => {
    if (!files) return []
    if (files.platform !== 'android') return files.roots
    return files.roots.filter((r) =>
      view === 'java' ? isJavaRoot(r.name) : !isJavaRoot(r.name),
    )
  }, [files, view])
  // M8 Phase C: the Edit & recompile modal (rebuild history + live stages).
  // The close callback is stable so the modal's Escape/scroll-lock effect
  // doesn't re-subscribe on every parent render (review catch).
  const [recompileOpen, setRecompileOpen] = useState(false)
  const closeRecompile = useCallback(() => setRecompileOpen(false), [])

  // M8 Phase D (moved to the dashboard Aug 11 - the dock chat is the agent
  // edit surface now, and its proposals share this review modal):
  // `proposedCount` powers the toolbar badge, `editVersion` remounts an open
  // editor after an Apply/Reject so a manual save never overwrites a
  // just-applied agent edit, and `onOpenProposals` opens the shared modal.
  // View-toggle fix (Aug 10): the last-open file per side of the Java/Smali
  // toggle. When a file has no counterpart (res/manifest, classes jadx
  // didn't decompile - the sibling API returns null), clicking the other
  // chip still switches the view and shows that side's last-open file (or
  // its default), so the toggle is never a dead click.
  const lastSideFile = useRef<{
    java: { rootName: string; path: string } | null
    smali: { rootName: string; path: string } | null
  }>({ java: null, smali: null })

  // Resizable pane widths (IntelliJ-style) - persisted per browser.
  const [treeW, setTreeW] = useState(() =>
    readWidth(TREE_KEY, TREE_DEFAULT, TREE_MIN, TREE_MAX),
  )
  const [railW, setRailW] = useState(() =>
    readWidth(RAIL_KEY, RAIL_DEFAULT, RAIL_MIN, RAIL_MAX),
  )
  // M8 follow-up: the annotations rail's minimized flag - persisted like the
  // splitter widths so a collapsed rail stays collapsed across sessions.
  const [railMin, setRailMin] = useState(() => readFlag(RAIL_MIN_KEY))
  // M8 follow-up (owner report, Aug 11): when the note stack is TALLER than
  // the code's content, the rail scrolls on its own - the code mirror is
  // frozen at 0 and wheel events over the rail are left to its native
  // scrollbar (reported by AnnotationRail via onOverflowChange).
  const [railOverflow, setRailOverflow] = useState(false)
  const treeWRef = useRef(treeW)
  const railWRef = useRef(railW)
  const setTreeWClamped = (w: number) => {
    const next = clampWidth(w, TREE_MIN, TREE_MAX)
    treeWRef.current = next
    setTreeW(next)
  }
  const setRailWClamped = (w: number) => {
    const next = clampWidth(w, RAIL_MIN, RAIL_MAX)
    railWRef.current = next
    setRailW(next)
  }
  const commitTreeW = () => {
    try {
      localStorage.setItem(TREE_KEY, String(treeWRef.current))
    } catch {
      // ignore
    }
  }
  const commitRailW = () => {
    try {
      localStorage.setItem(RAIL_KEY, String(railWRef.current))
    } catch {
      // ignore
    }
  }
  const toggleRailMin = (next: boolean) => {
    setRailMin(next)
    try {
      localStorage.setItem(RAIL_MIN_KEY, next ? '1' : '0')
    } catch {
      // ignore
    }
  }

  // Fetch the bounded file tree per scan; reset the open file with it.
  useEffect(() => {
    let cancelled = false
    setFilesLoading(true)
    setFilesError(null)
    setFiles(null)
    setSelected(null)
    setActiveNoteId(null)
    api
      .getFiles(scanId)
      .then((d) => {
        if (!cancelled) setFiles(d)
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setFilesError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setFilesLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId])

  // M8: fetch the on-demand decode state per scan; reset the view toggle.
  useEffect(() => {
    let cancelled = false
    setSmali(null)
    setView('java')
    api
      .smaliStatus(scanId)
      .then((s) => {
        if (!cancelled) setSmali(s)
      })
      .catch(() => {
        // Transient (e.g. backend just restarted) - leave smali null; the
        // chip renders disabled until a status actually lands.
      })
    return () => {
      cancelled = true
    }
  }, [scanId])

  // Poll while a decode is queued/running until it settles (ready/failed).
  const smaliBusy = smali?.status === 'queued' || smali?.status === 'decoding'
  // `stalled` (Aug 12) keeps polling SLOWLY: the queued job completes on its
  // own the moment a worker comes up, so the chip recovers without a click -
  // fast while actively decoding, slow so a dead worker isn't hammered.
  const smaliPolling = smaliBusy || smali?.status === 'stalled'
  useEffect(() => {
    if (!smaliPolling) return
    let cancelled = false
    const t = window.setInterval(async () => {
      try {
        const next = await api.smaliStatus(scanId)
        if (!cancelled) setSmali(next)
      } catch {
        // Transient poll failure - keep polling; the next tick retries.
      }
    }, smali?.status === 'stalled' ? 15000 : 2000)
    return () => {
      cancelled = true
      window.clearInterval(t)
    }
  }, [scanId, smaliPolling, smali?.status])

  // Phase B: the moment a decode turns ready, refetch the file tree so the
  // apktool roots (smali, res, AndroidManifest.xml) appear - the tree was
  // fetched before the decode existed. Only fires on the transition, and the
  // existing selection (rootName/path) is preserved.
  const prevSmaliStatus = useRef<SmaliStatus['status'] | null>(null)
  useEffect(() => {
    const prev = prevSmaliStatus.current
    prevSmaliStatus.current = smali?.status ?? null
    if (smali?.status === 'ready' && prev !== 'ready' && files) {
      api
        .getFiles(scanId)
        .then((d) => setFiles(d))
        .catch(() => {
          // Tree refresh is best-effort; the next tab visit refetches.
        })
    }
  }, [smali?.status, files, scanId])

  // M8: trigger the on-demand decode, or resync with the server when the
  // POST 409s (already decoding / already ready / enqueue failure).
  const triggerDecode = async () => {
    try {
      await api.triggerSmali(scanId)
      setSmali({ status: 'queued', error: null })
    } catch {
      try {
        setSmali(await api.smaliStatus(scanId))
      } catch {
        // Keep the current state; the chip stays where it was.
      }
    }
  }

  // M8 Phase D: fetch the findings→smali mapping when the decode is ready
  // (Android only). The tree was fetched with the smali roots by then, so the
  // aliases power Smali-mode dots + rail immediately; iOS/undecoded scans get
  // null (the memos below stay jadx-only). Best-effort: a failed fetch
  // degrades to an empty map rather than breaking the panel.
  const decodeReady = smali?.status === 'ready'
  useEffect(() => {
    let cancelled = false
    setSmaliMap(null)
    setSmaliAnchors(null)
    if (!decodeReady || files?.platform !== 'android') return
    api
      .smaliMapping(scanId)
      .then((d) => {
        if (!cancelled) {
          setSmaliMap(d.mapping)
          setSmaliAnchors(d.anchors ?? {})
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSmaliMap({})
          setSmaliAnchors({})
        }
      })
    return () => {
      cancelled = true
    }
  }, [scanId, decodeReady, files?.platform])

  // jadx root-relative path -> smali root-relative path, prefixes stripped
  // from the mapping's full tree paths (`sources/com/foo/A.java` ->
  // `smali/com/foo/A.smali` become `com/foo/A.java` -> `com/foo/A.smali`;
  // `res/values/strings.xml` -> `values/strings.xml` - the apktool res root
  // serves the same relative paths). Declared above the auto-select effect
  // (it consumes it); the dots/rail memos reuse it. Identity pairs (e.g.
  // the manifest: `AndroidManifest.xml` -> its own root's file) are skipped
  // - the finding already lands on that key, so aliasing would double it.
  const smaliAlias = useMemo(() => {
    const m = new Map<string, string>()
    if (!smaliMap) return m
    for (const [javaTreePath, smaliTreePath] of Object.entries(smaliMap)) {
      const javaRel = javaTreePath.startsWith('sources/')
        ? javaTreePath.slice('sources/'.length)
        : javaTreePath
      const idx = smaliTreePath.indexOf('/')
      const smaliRel = idx > 0 ? smaliTreePath.slice(idx + 1) : smaliTreePath
      if (!javaRel || !smaliRel || javaRel === smaliRel) continue
      m.set(javaRel, smaliRel)
    }
    return m
  }, [smaliMap])

  // jadx root-relative path -> FULL smali tree path (the anchors map is
  // keyed by the smali side of the mapping, e.g. `smali/com/foo/A.smali`),
  // so the alias loop can look up a finding's method-level smali line in
  // one step (Aug 11). Built alongside smaliAlias - same strip rule.
  const smaliTreePathByRel = useMemo(() => {
    const m = new Map<string, string>()
    if (!smaliMap) return m
    for (const [javaTreePath, smaliTreePath] of Object.entries(smaliMap)) {
      const javaRel = javaTreePath.startsWith('sources/')
        ? javaTreePath.slice('sources/'.length)
        : javaTreePath
      m.set(javaRel, smaliTreePath)
    }
    return m
  }, [smaliMap])

  // Default-file candidate paths: findings' file paths PLUS their smali
  // aliases, so the app-code-with-findings rule holds on both sides of the
  // toggle. Shared by the auto-open effect and the no-sibling toggle
  // fallback (kept in one place so the semantics can't drift).
  const findingPaths = useMemo(() => {
    const paths = new Set(findings.map((f) => f.file_path ?? ''))
    if (smaliAlias.size > 0) {
      for (const smaliRel of smaliAlias.values()) paths.add(smaliRel)
    }
    return paths
  }, [findings, smaliAlias])

  // Auto-open a sensible default once the tree AND findings are ready, but
  // never stomp a file the user already opened. The default is picked from
  // the CURRENT view's roots so it matches the active mode (a sources file
  // in Java mode, the first smali file in Smali mode).
  useEffect(() => {
    if (filesLoading || findingsLoading || !files || selected) return
    setSelected(findDefaultFile({ ...files, roots: visibleRoots }, findingPaths))
  }, [files, filesLoading, findingsLoading, selected, visibleRoots, findingPaths])

  // External open request (agent citation click): resolve once the tree is
  // loaded, then report back so the request clears. Unresolvable paths
  // (rare - e.g. an iOS string inside a binary) silently keep the current
  // file rather than stomping it.
  useEffect(() => {
    if (!files || !requestFile) return
    // Citations resolve against the FULL tree (a smali citation must land
    // even while the Java view is active) - then the view switches to match
    // the resolved file's side so the tree actually shows it.
    const resolved = resolveTreePath(files, requestFile.file)
    if (resolved) {
      setSelected(resolved)
      // Track the side so a later no-sibling toggle restores the cited file
      // rather than a stale one (review catch).
      lastSideFile.current[isJavaRoot(resolved.rootName) ? 'java' : 'smali'] =
        resolved
      setActiveNoteId(null)
      if (files.platform === 'android') {
        setView(isJavaRoot(resolved.rootName) ? 'java' : 'smali')
      }
    }
    onRequestConsumed?.()
  }, [files, requestFile, onRequestConsumed])

  // file path (root-relative) → findings, for flagging + the rail. Smali
  // mode: each jadx finding is ALSO listed under its smali sibling. Aug 11
  // follow-up: the aliases now carry METHOD-level line anchors - the
  // finding's jadx line maps to its containing method's `.method` line in
  // the smali file (jadx renumbers source lines, so statement-level mapping
  // is impossible; the anchor is the honest granularity). Findings without a
  // resolvable anchor keep line_number null - those notes stack from the top
  // (the pre-follow-up behaviour).
  const findingsByFile = useMemo(() => {
    const m = new Map<string, FindingRead[]>()
    for (const f of findings) {
      if (!f.file_path) continue
      const list = m.get(f.file_path)
      if (list) list.push(f)
      else m.set(f.file_path, [f])
    }
    if (smaliAlias.size > 0 && smaliAnchors) {
      for (const [javaRel, smaliRel] of smaliAlias) {
        const jadxList = m.get(javaRel)
        if (!jadxList) continue
        const smaliTreePath = smaliTreePathByRel.get(javaRel)
        const byLine = smaliTreePath ? smaliAnchors[smaliTreePath] : null
        const aliased = jadxList.map((f) => ({
          ...f,
          file_path: smaliRel,
          // Method-level smali line anchor (or null -> the note stacks).
          line_number:
            byLine && f.line_number != null
              ? (byLine[String(f.line_number)] ?? null)
              : null,
        }))
        const existing = m.get(smaliRel)
        m.set(smaliRel, existing ? [...existing, ...aliased] : aliased)
      }
    }
    return m
  }, [findings, smaliAlias, smaliAnchors, smaliTreePathByRel])

  // file path → worst severity rank, for the tree dots. Same aliasing: a
  // smali file carries its jadx sibling's worst rank so Smali mode shows
  // the dots.
  const findingFiles = useMemo(() => {
    const m = new Map<string, number>()
    for (const f of findings) {
      if (!f.file_path) continue
      const rank = SEV_RANK[f.severity] ?? 0
      const prev = m.get(f.file_path) ?? 0
      if (rank > prev) m.set(f.file_path, rank)
    }
    if (smaliAlias.size > 0) {
      for (const [javaRel, smaliRel] of smaliAlias) {
        const rank = m.get(javaRel)
        if (rank != null) m.set(smaliRel, rank)
      }
    }
    return m
  }, [findings, smaliAlias])

  const openFileFindings = useMemo(() => {
    if (!selected) return []
    const list = findingsByFile.get(selected.path) ?? []
    return [...list].sort(
      (a, b) =>
        (a.line_number ?? Number.MAX_SAFE_INTEGER) -
        (b.line_number ?? Number.MAX_SAFE_INTEGER),
    )
  }, [findingsByFile, selected])

  const flaggedLines = useMemo(() => {
    const s = new Set<number>()
    for (const f of openFileFindings) {
      if (f.line_number != null) s.add(f.line_number)
    }
    return s
  }, [openFileFindings])

  const openFile = (rootName: string, node: FileNode) => {
    setSelected({ rootName, path: node.path })
    // Track the last-open file per side for the no-sibling toggle fallback.
    lastSideFile.current[isJavaRoot(rootName) ? 'java' : 'smali'] = {
      rootName,
      path: node.path,
    }
    setActiveNoteId(null)
    // The active chip follows the file's side: jadx sources/resources are
    // the Java view, everything else (smali/res/manifest) is the Smali view.
    setView(isJavaRoot(rootName) ? 'java' : 'smali')
  }

  // Phase B: the Java/Smali toggle - jump the open file to its counterpart
  // (multidex-aware server-side). When there is no counterpart (res/manifest
  // files, classes jadx didn't decompile - the API returns null) the toggle
  // STILL switches the view, showing the other side's last-open file (or its
  // default app-code file when never opened) - the toggle is never a dead
  // click (owner fix, Aug 10). A transient lookup failure degrades to the
  // same view-only switch.
  const jumpToSibling = async () => {
    if (!selected) return
    const sideOf = (rootName: string): 'java' | 'smali' =>
      isJavaRoot(rootName) ? 'java' : 'smali'
    const currentSide = sideOf(selected.rootName)
    // The file we're leaving becomes its side's last state - the other
    // side's remembered file is what we fall back to below.
    lastSideFile.current[currentSide] = selected
    try {
      const { sibling } = await api.smaliSibling(
        scanId,
        `${selected.rootName}/${selected.path}`,
      )
      if (sibling) {
        const idx = sibling.indexOf('/')
        const rootName = sibling.slice(0, idx)
        const path = sibling.slice(idx + 1)
        setSelected({ rootName, path })
        lastSideFile.current[sideOf(rootName)] = { rootName, path }
        setActiveNoteId(null)
        setView(sideOf(rootName))
        return
      }
    } catch {
      // Transient API failure - fall through to the view-only switch so the
      // toggle still works; the file reverts to the remembered/default one.
    }
    // No counterpart (or the lookup failed): switch the view anyway and
    // show the other side's last-open file - or its default when that side
    // was never opened.
    const targetView: 'java' | 'smali' = view === 'smali' ? 'java' : 'smali'
    const remembered = lastSideFile.current[targetView]
    if (remembered) {
      setSelected(remembered)
    } else if (files) {
      const roots = files.roots.filter((r) =>
        targetView === 'java' ? isJavaRoot(r.name) : !isJavaRoot(r.name),
      )
      const def = findDefaultFile({ ...files, roots }, findingPaths)
      // Clear on an empty side rather than leave a wrong-side file open
      // (the viewer would show a file absent from the filtered tree).
      setSelected(def ?? null)
    } else {
      setSelected(null)
    }
    setActiveNoteId(null)
    setView(targetView)
  }

  // A flagged code line carries a line number - resolve it to the first
  // finding on that line so the rail can scroll its note into view.
  const onFlaggedLineClick = (line: number) => {
    const finding = openFileFindings.find((f) => f.line_number === line)
    if (finding) setActiveNoteId(finding.id)
  }

  // ---- M8 Smali chip + edit-mode derived state ----------------------------
  const platform = files?.platform ?? null
  const isAndroid = platform === 'android'
  const smaliReady = smali?.status === 'ready'
  // `stalled` (Aug 12): the decode was enqueued but no RQ worker consumed
  // it - the chip renders like a failure with the backend's friendly
  // 'start the worker' hint, and the ↻ Retry decode button re-triggers it.
  const smaliFailed =
    smali?.status === 'failed' || smali?.status === 'stalled'
  // M8 toolbar gate: the WHOLE Java/Smali toggle (Java chip included) plus
  // the decode/recompile affordances are Android-only - fully hidden on iOS
  // (decision 5 - iOS keeps the read-only bundle view; no apktool/ldid in
  // v1). Unknown platform (tree still loading) keeps them, matching the
  // established `platform == null || isAndroid` convention.
  const androidToolbar = platform == null || isAndroid
  const smaliChipTitle = !smali
    ? 'Loading decode status…'
    : smaliBusy
      ? 'Decoding smali with apktool - this runs once and is cached per scan'
      : smaliReady
        ? view === 'java'
          ? 'Switch to this file\'s smali (editable)'
          : 'Smali view - edit in place, save with Ctrl/Cmd+S'
        : smaliFailed
          ? `Smali decode failed: ${smali.error ?? 'apktool could not decode this APK'}`
          : 'Decode smali with apktool (on-demand - runs once, cached per scan)'
  const javaChipTitle =
    view === 'smali' && selected
      ? "Switch to this file's jadx java (read-only)"
      : 'Java view - read-only'

  // Phase B edit mode: editable root + decode ready + a file selected.
  const contentPath = selected ? `${selected.rootName}/${selected.path}` : null
  const editPath = selected ? editPathFor(selected.rootName, selected.path) : null
  const isEditableFile =
    isAndroid && smaliReady && selected != null && isEditableRoot(selected.rootName)

  // ---- One-scroll annotation rail (owner request, Aug 11) ------------------
  // The code pane keeps its own (vertical) scrollbar - it is the scroll
  // SOURCE. The annotation rail has no scrollbar of its own (overflow
  // hidden); its notes are pinned to their finding's line offset and the
  // whole notes column translates by the code's scrollTop via a CSS var
  // (--rail-scroll) set DIRECTLY on the DOM, so scrolling never re-renders
  // the panel (the tree is huge; per-scroll React renders would be janky).
  const layoutRef = useRef<HTMLDivElement | null>(null)
  const railRef = useRef<HTMLDivElement | null>(null)
  // Measured geometry for the note alignment: px per code line + the offset
  // between the code title bar and the rail head (both fixed-height). Null
  // until the content renders (async) and the measurement lands.
  const [codeMetrics, setCodeMetrics] = useState<{
    lineHeight: number
    compensation: number
    contentHeight: number
  } | null>(null)

  // Measure the geometry once the open file's content renders. Content loads
  // async, so retry via rAF until the DOM has the pieces (or give up after
  // ~60 frames ≈ 1s - the defaults of 0/0 make notes stack from the top,
  // still one-scroll, just not line-pinned). Re-runs on file/mode/rail
  // changes.
  //
  // Aug 11 (smali one-scroll): the EDITOR path now measures real metrics
  // too - the gutter pre and the textarea share the same 12.5px/1.9 font
  // metrics (the gutter follows the textarea's scroll exactly), so its
  // computed line-height is the smali row height, and the textarea's
  // scrollHeight is the content height the rail's overflow detection uses
  // as its reachability bound.
  useEffect(() => {
    let cancelled = false
    let raf = 0
    let tries = 0
    const measure = () => {
      if (cancelled) return
      const pane = layoutRef.current?.querySelector('.code-pane') as HTMLElement | null
      const lineEl = pane?.querySelector('.code-line') as HTMLElement | null
      const titleEl = pane?.querySelector('.code-file-path') as HTMLElement | null
      const headEl = railRef.current?.querySelector('.annot-rail-label') as HTMLElement | null
      const editorArea = pane?.querySelector('.editor-textarea') as HTMLTextAreaElement | null
      const ready = titleEl && headEl && (lineEl || (isEditableFile && editorArea))
      if (ready) {
        setCodeMetrics({
          // Viewer: the rendered .code-line height. Editor: the computed
          // row height of the smali textarea (0 until it renders - notes
          // stack meanwhile, the rAF retry lands the real value).
          lineHeight: lineEl
            ? lineEl.getBoundingClientRect().height
            : editorArea
              ? parseFloat(getComputedStyle(editorArea).lineHeight) || 0
              : 0,
          compensation:
            titleEl.getBoundingClientRect().height -
            headEl.getBoundingClientRect().height,
          // The scroll source's full content height - the viewer's pane or
          // the editor's textarea - AnnotationRail clamps its last clustered
          // note inside it (review guard, Aug 11).
          contentHeight: editorArea
            ? editorArea.scrollHeight
            : pane
              ? pane.scrollHeight
              : 0,
        })
        return
      }
      if (tries++ < 60) raf = requestAnimationFrame(measure)
    }
    raf = requestAnimationFrame(measure)
    return () => {
      cancelled = true
      cancelAnimationFrame(raf)
    }
  }, [contentPath, isEditableFile, railMin])

  // The mirror itself: the scroll source differs by mode - the viewer's
  // .code-pane vs the smali editor's .editor-textarea (both exist once the
  // content renders; the codeMetrics dep re-resolves the scroller after the
  // async load lands). The rail has no scrollbar, so wheel events over it
  // are forwarded (native non-passive listener - React's onWheel is passive
  // and cannot preventDefault) to the code scroll source.
  //
  // Overflow mode (owner report, Aug 11): when the notes are taller than the
  // code, the rail scrolls on its own - the mirror is frozen at 0 and wheel
  // events are NOT forwarded (a preventDefault forwarder would block the
  // rail's native scrollbar).
  useEffect(() => {
    const pane = layoutRef.current?.querySelector('.code-pane') as HTMLElement | null
    const scroller = isEditableFile
      ? (layoutRef.current?.querySelector('.editor-textarea') as HTMLElement | null)
      : pane
    const rail = railRef.current
    if (!scroller) return
    const sync = () => {
      // Skip the write while the rail is minimized - there is nothing to
      // mirror (review nit, Aug 11): saves a style recalc per scroll frame.
      if (!railRef.current) return
      layoutRef.current?.style.setProperty(
        '--rail-scroll',
        railOverflow ? '0px' : `${-scroller.scrollTop}px`,
      )
    }
    sync() // reset on file/mode change
    if (railOverflow) return
    scroller.addEventListener('scroll', sync)
    const onRailWheel = (e: WheelEvent) => {
      if (e.deltaY === 0) return
      e.preventDefault()
      // deltaMode 1 = line-mode wheels (some mice/terminals): the code
      // pane's native scroll would move 16px per line - mirror that.
      const delta = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY
      scroller.scrollTop += delta
    }
    rail?.addEventListener('wheel', onRailWheel, { passive: false })
    return () => {
      scroller.removeEventListener('scroll', sync)
      rail?.removeEventListener('wheel', onRailWheel)
    }
  }, [contentPath, isEditableFile, railMin, codeMetrics, railOverflow])

  // A flagged-line click highlights its note - bring the (line-aligned) note
  // into view by scrolling the code so the line sits near the top (the old
  // rail scrollIntoView is gone: the rail no longer scrolls on its own). The
  // findings lookup goes through a ref so the effect only fires when the
  // ACTIVE note changes - not when the findings array identity shifts (e.g.
  // a dashboard refetch while a note is highlighted - review catch, Aug 11).
  const openFindingsRef = useRef(openFileFindings)
  openFindingsRef.current = openFileFindings
  useEffect(() => {
    if (activeNoteId == null || !codeMetrics) return
    const f = openFindingsRef.current.find((x) => x.id === activeNoteId)
    if (!f || f.line_number == null) return
    const pane = layoutRef.current?.querySelector('.code-pane') as HTMLElement | null
    if (!pane) return
    const top =
      (f.line_number - 1) * codeMetrics.lineHeight + codeMetrics.compensation
    pane.scrollTop = Math.max(0, top - 40)
  }, [activeNoteId, codeMetrics])

  return (
    <div>
      {/* Sticky header region (owner request, Aug 11): the Java/Smali toggle,
          the decode/recompile affordances and the view hint pin BELOW the
          sticky tab bar (--tabbar-h, measured by DashboardView) while the
          main area scrolls - the decode/recompile controls stay reachable.
          M8 toolbar: Java/Smali view toggle + decode/recompile affordances.
          Android-only - fully hidden on iOS (decisions 5/6 - iOS keeps the
          read-only bundle view; no apktool/ldid in v1), including the lone
          "Java" chip that means nothing without the Smali side of the
          toggle. Unknown platform (tree still loading) keeps it, matching
          the convention. */}
      <div className="decomp-sticky">
      {androidToolbar && (
        <div className="decomp-toolbar">
          <div className="view-toggle" role="tablist" aria-label="Code view">
            <button
              type="button"
              className={`vt-chip ${view === 'java' ? 'active' : ''}`}
              role="tab"
              aria-selected={view === 'java'}
              title={javaChipTitle}
              onClick={view === 'smali' ? jumpToSibling : undefined}
            >
              Java
            </button>
            <button
              type="button"
              className={`vt-chip${smaliReady && view === 'smali' ? ' active' : ''}${smaliBusy ? ' busy' : ''}${smaliFailed ? ' failed' : ''}`}
              role="tab"
              aria-selected={view === 'smali'}
              disabled={!isAndroid || smaliBusy || smaliFailed}
              title={smaliChipTitle}
              onClick={smaliReady ? jumpToSibling : triggerDecode}
            >
              {smaliBusy && <span className="smali-spin" aria-hidden="true" />}
              Smali
            </button>
          </div>
          <div className="toolbar-actions">
            {isAndroid && smaliFailed && (
              <button
                className="btn"
                onClick={triggerDecode}
                title="Retry the apktool decode"
              >
                ↻ Retry decode
              </button>
            )}
            {/* M8 Phase D: agent edit proposals awaiting review (D7) - the
                human applies/rejects each file; hidden until one exists. The
                count + modal live in DashboardView (shared with the dock's
                Review pill - the dock chat is the agent edit surface now). */}
            {proposedCount > 0 && (
              <button
                type="button"
                className="btn review-btn"
                onClick={onOpenProposals}
                title={`${proposedCount} agent edit proposal${proposedCount === 1 ? '' : 's'} awaiting your review - apply or reject per file`}
              >
                Review edits ({proposedCount})
              </button>
            )}
            {/* M8 Phase C: live - opens the recompile modal (rebuild history,
                persistent test-build warning, download). Disabled until the
                on-demand decode is ready (the Smali chip triggers it). */}
            <button
              className="btn"
              disabled={!isAndroid || !smaliReady}
              title={
                !isAndroid
                  ? 'Edit & recompile is Android-only'
                  : !smaliReady
                    ? 'Decode smali first (the Smali chip) - then you can edit & recompile'
                    : 'Rebuild the APK from your edits - signed with MASA’s test keystore'
              }
              onClick={() => setRecompileOpen(true)}
            >
              Edit &amp; recompile
            </button>
          </div>
        </div>
      )}
      {isAndroid && smaliFailed ? (
        <div className="view-hint hint-error">
          <strong>Smali decode failed.</strong>{' '}
          {smali.error ?? 'apktool could not decode this APK'} - retry above.
        </div>
      ) : isAndroid && smaliReady && selected && isEditableFile ? (
        <div className="view-hint">
          <strong>Editable</strong> - smali/res/manifest is what actually gets
          rebuilt into the APK. Edit in place and save with{' '}
          <strong>Ctrl/Cmd+S</strong>; the change is stored as a reviewable
          diff and applied at recompile.
        </div>
      ) : isAndroid && smaliReady && selected ? (
        <div className="view-hint">
          <strong>Read-only</strong> - jadx output is for understanding code,
          not rebuilding it. Switch to <strong>Smali</strong> to edit what
          actually gets rebuilt.
        </div>
      ) : isAndroid || platform == null ? (
        <div className="view-hint">
          Read-only - jadx Java + resources. The <strong>Smali</strong> chip
          triggers an on-demand apktool decode (runs once, cached), then the
          smali view is editable.
        </div>
      ) : (
        <div className="view-hint">
          Read-only - iOS scans show the unpacked bundle (plists,
          entitlements, strings) instead of source.
        </div>
      )}
      </div>

      {filesLoading && (
        <div className="text-[12px] text-bone-faint">Loading file tree…</div>
      )}
      {!filesLoading && filesError && (
        <div className="rounded border border-crimson/30 bg-crimson/10 p-4 font-mono text-[11.5px] text-bone-dim">
          {filesError}
        </div>
      )}
      {!filesLoading && !filesError && files && (
        <div
          ref={layoutRef}
          className={`decomp-layout${railMin ? ' rail-min' : ''}`}
          style={
            {
              '--tree-w': `${treeW}px`,
              '--rail-w': `${railW}px`,
              // One-scroll mirror: the code pane's scroll offset is written
              // here directly on scroll (never through React state).
              '--rail-scroll': '0px',
            } as CSSProperties
          }
        >
          <FileTree
            roots={visibleRoots}
            findingFiles={findingFiles}
            selectedPath={selected?.path ?? null}
            autoExpandDir={
              selected && selected.path.includes('/')
                ? selected.path.slice(0, selected.path.lastIndexOf('/'))
                : null
            }
            onOpenFile={openFile}
          />
          <Splitter
            title="Drag to resize the file tree (double-click to reset)"
            onDelta={(d) => setTreeWClamped(treeWRef.current + d)}
            onCommit={commitTreeW}
            onReset={() => {
              setTreeWClamped(TREE_DEFAULT)
              commitTreeW() // a reset should persist too, like a drag
            }}
          />
          {isEditableFile && contentPath && editPath ? (
            <CodeEditor
              key={editVersion}
              scanId={scanId}
              contentPath={contentPath}
              editPath={editPath}
            />
          ) : (
            <CodeViewer
              scanId={scanId}
              rootName={selected?.rootName ?? null}
              path={selected?.path ?? null}
              flaggedLines={flaggedLines}
              onLineClick={onFlaggedLineClick}
            />
          )}
          {railMin ? (
            <button
              type="button"
              className="annot-rail-collapsed"
              onClick={() => toggleRailMin(false)}
              title="Expand annotations rail"
              aria-label="Expand annotations rail"
              aria-expanded={false}
            >
              <span className="arc-label">
                Annotations ({openFileFindings.length})
              </span>
            </button>
          ) : (
            <>
              <Splitter
                title="Drag to resize the annotations rail (double-click to reset)"
                onDelta={(d) => setRailWClamped(railWRef.current - d)}
                onCommit={commitRailW}
                onReset={() => {
                  setRailWClamped(RAIL_DEFAULT)
                  commitRailW() // a reset should persist too, like a drag
                }}
              />
              <AnnotationRail
                scanId={scanId}
                findings={openFileFindings}
                activeNoteId={activeNoteId}
                onMinimize={() => toggleRailMin(true)}
                lineHeight={codeMetrics?.lineHeight ?? 0}
                compensation={codeMetrics?.compensation ?? 0}
                contentHeight={codeMetrics?.contentHeight ?? 0}
                railRef={railRef}
                onOverflowChange={setRailOverflow}
              />
            </>
          )}
        </div>
      )}

      {recompileOpen && (
        <RecompileModal scanId={scanId} onClose={closeRecompile} />
      )}
    </div>
  )
}

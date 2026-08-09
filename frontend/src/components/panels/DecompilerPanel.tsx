import { useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { api } from '../../api/client'
import type { FileNode, FileTreeResponse, FindingRead } from '../../types'
import { Splitter } from '../Splitter'
import { AnnotationRail } from '../code/AnnotationRail'
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

function readWidth(key: string, fallback: number, min: number, max: number): number {
  try {
    const n = Number(localStorage.getItem(key))
    if (Number.isFinite(n)) return Math.min(max, Math.max(min, n))
  } catch {
    // Storage unavailable (private mode) — session defaults are fine.
  }
  return fallback
}

function clampWidth(v: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, v))
}

interface DecompilerPanelProps {
  scanId: number
  findings: FindingRead[]
  /** Findings are fetched async by the dashboard — skip the default file
   * pick until they are loaded so app-code-with-findings wins. */
  findingsLoading: boolean
  /** Agent-citation click: open a file. `file` is relative to the platform
   * tree root (e.g. `com/app/MyWebViewClient.java`); resolved against the
   * loaded tree, then reported back via `onRequestConsumed`. */
  requestFile?: { file: string; nonce: number } | null
  onRequestConsumed?: () => void
}

const SEV_RANK: Record<string, number> = {
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
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
 * Resolve an agent citation path against the bounded tree. Agent paths are
 * relative to the platform tree root: Android citations are `com/...` under
 * the `sources` root, iOS citations are relative to the `Payload/*.app`
 * root (whose name IS the root name). Try `<root>/<file>` for each root,
 * then a suffix match as a last resort.
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
  // Graph node files are normalized to root-relative in the backend
  // (graphify._normalize_source_file), so this resolver only ever sees
  // root-relative paths — no root-prefix handling needed here.
  return all.find((f) => f.path.endsWith(`/${file}`)) ?? null
}

/** Decompiler tab: bounded file tree + highlighted viewer + annotation rail. */
export function DecompilerPanel({
  scanId,
  findings,
  findingsLoading,
  requestFile,
  onRequestConsumed,
}: DecompilerPanelProps) {
  const [files, setFiles] = useState<FileTreeResponse | null>(null)
  const [filesLoading, setFilesLoading] = useState(true)
  const [filesError, setFilesError] = useState<string | null>(null)
  const [selected, setSelected] = useState<{
    rootName: string
    path: string
  } | null>(null)
  const [activeNoteId, setActiveNoteId] = useState<number | null>(null)

  // Resizable pane widths (IntelliJ-style) — persisted per browser.
  const [treeW, setTreeW] = useState(() =>
    readWidth(TREE_KEY, TREE_DEFAULT, TREE_MIN, TREE_MAX),
  )
  const [railW, setRailW] = useState(() =>
    readWidth(RAIL_KEY, RAIL_DEFAULT, RAIL_MIN, RAIL_MAX),
  )
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

  // Auto-open a sensible default once the tree AND findings are ready, but
  // never stomp a file the user already opened.
  useEffect(() => {
    if (filesLoading || findingsLoading || !files || selected) return
    const paths = new Set(findings.map((f) => f.file_path ?? ''))
    setSelected(findDefaultFile(files, paths))
  }, [files, filesLoading, findings, findingsLoading, selected])

  // External open request (agent citation click): resolve once the tree is
  // loaded, then report back so the request clears. Unresolvable paths
  // (rare — e.g. an iOS string inside a binary) silently keep the current
  // file rather than stomping it.
  useEffect(() => {
    if (!files || !requestFile) return
    const resolved = resolveTreePath(files, requestFile.file)
    if (resolved) {
      setSelected(resolved)
      setActiveNoteId(null)
    }
    onRequestConsumed?.()
  }, [files, requestFile, onRequestConsumed])

  // file path (root-relative) → findings, for flagging + the rail.
  const findingsByFile = useMemo(() => {
    const m = new Map<string, FindingRead[]>()
    for (const f of findings) {
      if (!f.file_path) continue
      const list = m.get(f.file_path)
      if (list) list.push(f)
      else m.set(f.file_path, [f])
    }
    return m
  }, [findings])

  // file path → worst severity rank, for the tree dots.
  const findingFiles = useMemo(() => {
    const m = new Map<string, number>()
    for (const f of findings) {
      if (!f.file_path) continue
      const rank = SEV_RANK[f.severity] ?? 0
      const prev = m.get(f.file_path) ?? 0
      if (rank > prev) m.set(f.file_path, rank)
    }
    return m
  }, [findings])

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
    setActiveNoteId(null)
  }

  // A flagged code line carries a line number — resolve it to the first
  // finding on that line so the rail can scroll its note into view.
  const onFlaggedLineClick = (line: number) => {
    const finding = openFileFindings.find((f) => f.line_number === line)
    if (finding) setActiveNoteId(finding.id)
  }

  return (
    <div>
      {/* Toolbar: Java/Smali view toggle (M5 read-only; M8 owns Smali/edit). */}
      <div className="decomp-toolbar">
        <div className="view-toggle" role="tablist" aria-label="Code view">
          <button
            type="button"
            className="vt-chip active"
            role="tab"
            aria-selected="true"
          >
            Java
          </button>
          <button
            type="button"
            className="vt-chip"
            role="tab"
            aria-selected="false"
            disabled
            title="Smali view + edit/recompile land in M8"
          >
            Smali
          </button>
        </div>
        <div className="toolbar-actions">
          <button className="btn" disabled title="Edit & recompile — M8">
            Edit &amp; recompile
          </button>
        </div>
      </div>
      <div className="view-hint">
        Read-only in M5 — jadx Java + resources. Smali view, editing, and
        recompile arrive in <strong>M8</strong>. iOS scans show the unpacked
        bundle (plists, entitlements, strings) instead of source.
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
          className="decomp-layout"
          style={
            {
              '--tree-w': `${treeW}px`,
              '--rail-w': `${railW}px`,
            } as CSSProperties
          }
        >
          <FileTree
            roots={files.roots}
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
          <CodeViewer
            scanId={scanId}
            rootName={selected?.rootName ?? null}
            path={selected?.path ?? null}
            flaggedLines={flaggedLines}
            onLineClick={onFlaggedLineClick}
          />
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
          />
        </div>
      )}
    </div>
  )
}

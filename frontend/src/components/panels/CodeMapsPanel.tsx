import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../../api/client'
import type {
  GraphHubRow,
  GraphNodeDetail,
  GraphNodeRow,
  Platform,
  ScanGraphState,
} from '../../types'

const SEARCH_DEBOUNCE_MS = 300

interface CodeMapsPanelProps {
  scanId: number
  platform: Platform | null
  /** Jump to the Decompiler tab at a source file (neighbor/node with a file). */
  onOpenFile: (file: string) => void
}

function nodeLoc(n: GraphNodeRow): string {
  if (n.file && n.line != null) return `${n.file}:${n.line}`
  if (n.file) return n.file
  return n.id
}

/**
 * Code maps tab: searchable structural code graph (Android only).
 *
 * The 64 MB graph.json never reaches the browser — the backend compacts it
 * into a per-scan explorer index, and this panel talks to three thin
 * endpoints: search (debounced substring over labels/ids), hubs (most-
 * connected nodes for the initial view), and node detail (in/out neighbors
 * with their relation). Any row with a source file can jump to the
 * Decompiler tab via `onOpenFile`.
 */
export function CodeMapsPanel({ scanId, platform, onOpenFile }: CodeMapsPanelProps) {
  const [state, setState] = useState<ScanGraphState | null>(null)
  const [stateLoading, setStateLoading] = useState(true)
  const [stateError, setStateError] = useState<string | null>(null)

  const [query, setQuery] = useState('')
  const [searching, setSearching] = useState(false)
  const [results, setResults] = useState<GraphNodeRow[] | null>(null)
  const [resultTotal, setResultTotal] = useState(0)
  const [hubs, setHubs] = useState<GraphHubRow[] | null>(null)

  const [selected, setSelected] = useState<GraphNodeDetail | null>(null)
  const [selectedLoading, setSelectedLoading] = useState(false)
  const [selectedError, setSelectedError] = useState<string | null>(null)

  const built = state?.built ?? false
  const queryActive = query.trim().length > 0

  // Graph build state (filesystem-derived backend state).
  useEffect(() => {
    let cancelled = false
    setStateLoading(true)
    setStateError(null)
    api
      .getGraph(scanId)
      .then((s) => {
        if (!cancelled) setState(s)
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setStateError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (!cancelled) setStateLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId])

  // Hubs for the initial view — loaded once per scan.
  useEffect(() => {
    if (!built || hubs) return
    let cancelled = false
    api
      .graphHubs(scanId)
      .then((d) => {
        if (!cancelled) setHubs(d.hubs)
      })
      .catch(() => {
        // Hubs are a nicety; search still works without them.
      })
    return () => {
      cancelled = true
    }
  }, [built, hubs, scanId])

  // Debounced search. Clearing the query returns to the hubs view.
  const debounceRef = useRef<number | null>(null)
  useEffect(() => {
    if (!built) return
    const q = query.trim()
    if (debounceRef.current != null) window.clearTimeout(debounceRef.current)
    if (!q) {
      setResults(null)
      setResultTotal(0)
      setSearching(false)
      return
    }
    let cancelled = false
    setSearching(true)
    debounceRef.current = window.setTimeout(() => {
      api
        .graphSearch(scanId, q)
        .then((d) => {
          if (cancelled) return
          setResults(d.nodes)
          setResultTotal(d.total)
        })
        .catch(() => {
          if (cancelled) return
          setResults([])
          setResultTotal(0)
        })
        .finally(() => {
          if (!cancelled) setSearching(false)
        })
    }, SEARCH_DEBOUNCE_MS)
    return () => {
      cancelled = true
      if (debounceRef.current != null) window.clearTimeout(debounceRef.current)
    }
  }, [query, built, scanId])

  // RequestId race guard (same pattern as useExplain): rapid clicks on
  // different nodes must never let a slower first response overwrite the
  // newer selection.
  const detailReqId = useRef(0)
  const selectNode = useCallback(
    (node: GraphNodeRow) => {
      const reqId = ++detailReqId.current
      setSelectedError(null)
      setSelectedLoading(true)
      api
        .graphNode(scanId, node.id)
        .then((d) => {
          if (reqId !== detailReqId.current) return
          setSelected(d)
        })
        .catch((err: unknown) => {
          if (reqId !== detailReqId.current) return
          setSelectedError(err instanceof Error ? err.message : String(err))
        })
        .finally(() => {
          if (reqId === detailReqId.current) setSelectedLoading(false)
        })
    },
    [scanId],
  )

  const openNodeFile = useCallback(
    (node: GraphNodeRow) => {
      if (node.file) onOpenFile(node.file)
    },
    [onOpenFile],
  )

  const listRows: GraphNodeRow[] =
    queryActive && results != null
      ? results
      : (hubs ?? []).map((h) => h.node)

  return (
    <div>
      <div className="codemap-toolbar">
        <input
          className="codemap-search"
          type="search"
          placeholder="Search code — class, method, resource… (e.g. WebView, NetworkSecurityConfig)"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          disabled={!built}
          aria-label="Search the code graph"
        />
        {queryActive && (
          <button
            type="button"
            className="link-btn"
            onClick={() => {
              setQuery('')
              setResults(null)
            }}
          >
            Clear
          </button>
        )}
        <span className="codemap-meta">
          {stateLoading
            ? '…'
            : built
              ? `${state?.nodes?.toLocaleString() ?? '–'} nodes · ${state?.edges?.toLocaleString() ?? '–'} edges`
              : ''}
        </span>
      </div>

      {stateLoading && (
        <div className="text-[12px] text-bone-faint">Loading graph state…</div>
      )}
      {!stateLoading && stateError && (
        <div className="rounded border border-crimson/30 bg-crimson/10 p-4 font-mono text-[11.5px] text-bone-dim">
          {stateError}
        </div>
      )}
      {!stateLoading && !stateError && !built && state && (
        <div className="view-hint">
          {platform !== 'android' ? (
            <>
              Code maps are <strong>Android-only</strong> — iOS has no
              decompiled source tree to graph ({state.reason}).
            </>
          ) : (
            <>
              {state.reason} — it builds automatically after the Android
              analysis completes. Re-scan the app to generate it.
            </>
          )}
        </div>
      )}

      {!stateLoading && !stateError && built && (
        <div className="codemap-layout">
          {/* Left: results / hubs list */}
          <div className="codemap-list">
            <div className="codemap-list-label">
              {queryActive
                ? searching
                  ? 'Searching…'
                  : `${results?.length ?? 0} of ${resultTotal} matches`
                : 'Most connected'}
            </div>
            {searching && (
              <div className="codemap-empty">Searching the graph…</div>
            )}
            {!searching && listRows.length === 0 && (
              <div className="codemap-empty">
                {queryActive
                  ? `No nodes match “${query.trim()}”.`
                  : 'No graph nodes found.'}
              </div>
            )}
            {!searching &&
              listRows.map((row) => (
                <button
                  key={row.id}
                  type="button"
                  className={`codemap-node ${
                    selected?.node.id === row.id ? 'active' : ''
                  }`}
                  onClick={() => selectNode(row)}
                >
                  <span className="nlabel" title={row.label}>
                    {row.label}
                  </span>
                  <span className="nloc" title={nodeLoc(row)}>
                    {nodeLoc(row)}
                  </span>
                </button>
              ))}
          </div>

          {/* Right: selected node detail */}
          <div className="codemap-detail">
            {selectedLoading && (
              <div className="codemap-empty">Loading node…</div>
            )}
            {!selectedLoading && selectedError && (
              <div className="rounded border border-crimson/30 bg-crimson/10 p-4 font-mono text-[11.5px] text-bone-dim">
                {selectedError}
              </div>
            )}
            {!selectedLoading && !selectedError && selected && (
              <>
                <div className="codemap-detail-head">
                  <div className="dl">{selected.node.label}</div>
                  <div className="dm">
                    <span>degree {selected.degree}</span>
                    {selected.node.file_type && (
                      <span className="kind-tag">{selected.node.file_type}</span>
                    )}
                    {selected.node.file && (
                      <button
                        type="button"
                        className="link-btn"
                        onClick={() => openNodeFile(selected.node)}
                      >
                        Open in Decompiler →
                      </button>
                    )}
                  </div>
                  {selected.node.file && (
                    <div className="dm" style={{ marginTop: 2 }}>
                      {selected.node.file}
                      {selected.node.line != null ? `:${selected.node.line}` : ''}
                    </div>
                  )}
                </div>
                {selected.neighbors.length === 0 ? (
                  <div className="codemap-empty">
                    No connections in the graph.
                  </div>
                ) : (
                  <div className="codemap-neighbors">
                    <div className="codemap-group-label">
                      Outgoing ({selected.neighbors.filter((n) => n.direction === 'out').length})
                    </div>
                    {selected.neighbors
                      .filter((n) => n.direction === 'out')
                      .map((n) => (
                        <NeighborRow
                          key={n.node.id}
                          node={n.node}
                          relation={n.relation}
                          direction="out"
                          onSelect={() => selectNode(n.node)}
                          onOpenFile={() => openNodeFile(n.node)}
                        />
                      ))}
                    <div className="codemap-group-label">
                      Incoming ({selected.neighbors.filter((n) => n.direction === 'in').length})
                    </div>
                    {selected.neighbors
                      .filter((n) => n.direction === 'in')
                      .map((n) => (
                        <NeighborRow
                          key={n.node.id}
                          node={n.node}
                          relation={n.relation}
                          direction="in"
                          onSelect={() => selectNode(n.node)}
                          onOpenFile={() => openNodeFile(n.node)}
                        />
                      ))}
                  </div>
                )}
              </>
            )}
            {!selectedLoading && !selectedError && !selected && (
              <div className="codemap-empty">
                Select a node to inspect its connections in the code graph.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function NeighborRow({
  node,
  relation,
  direction,
  onSelect,
  onOpenFile,
}: {
  node: GraphNodeRow
  relation: string | null
  direction: 'in' | 'out'
  onSelect: () => void
  onOpenFile: () => void
}) {
  return (
    <div className="codemap-neighbor">
      <span className="codemap-arrow" title={direction === 'out' ? 'calls/imports' : 'called/imported by'}>
        {direction === 'out' ? '→' : '←'}
      </span>
      {relation && <span className="codemap-rel">{relation}</span>}
      <span className="nlabel" onClick={onSelect} title={node.label}>
        {node.label}
      </span>
      <span className="nloc" title={nodeLoc(node)}>
        {nodeLoc(node)}
      </span>
      {node.file && (
        <button
          type="button"
          className="link-btn"
          title="Open this file in the Decompiler tab"
          onClick={onOpenFile}
        >
          open
        </button>
      )}
    </div>
  )
}

"""Subprocess wrapper over the graphify CLI (pinned 0.9.32) - M4 Layer 3.

Per-scan code graph (FR-9i): deterministic AST extraction, zero LLM, zero
network. Build runs ``graphify update <decompiled-dir> --no-cluster`` with
cwd set to ``data/graphs/<scan_id>`` so output lands at
``data/graphs/<scan_id>/graphify-out/graph.json``; queries run
``graphify query|path|explain|affected --graph <path>`` - the exact surface
the M4 agent tools ``graph_query``/``graph_path``/``graph_explain`` call.

CLI-surface notes (validated on 0.9.32, recorded for the M4 plan):
- There is **no ``extract`` or ``export`` subcommand**; ``update`` is the
  headless code-only build (its help text: "re-extract code files and update
  the graph (no LLM needed)"). ``--no-cluster`` skips community detection and
  writes the raw ``graph.json`` - sufficient for query/path/explain; a
  ``cluster-only`` pass can add the report later (M9).
- Natural-language ``query`` finds nothing on code-only AST graphs (nodes
  carry identifier labels, not semantic text - e.g. ``query WebView`` works,
  ``query "where is certificate pinning"`` does not). ``query()`` therefore
  falls back to a deterministic label/ID substring search over ``graph.json``
  so identifier-shaped and natural-language terms both resolve.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.config import settings

_STOPWORDS = {
    "where", "what", "when", "which", "who", "how", "why", "is", "are", "was",
    "were", "the", "this", "that", "these", "those", "with", "from", "does",
    "do", "did", "located", "find", "show", "tell", "about", "there", "it",
    "its", "has", "have", "had", "can", "could", "would", "should", "will",
    "and", "or", "but", "not", "no", "any", "all", "code", "class", "file",
}

_SEARCH_LIMIT = 8

# jadx decompiles code under a `sources/` root (resources under `resources/`),
# so the graph's source_file keeps that root prefix (e.g. `sources/com/...`)
# while the Decompiler tree, agent citations, and code maps rows are all
# root-relative. The tree resolves the root at open time, so node rows
# normalize to root-relative - one path shape for every consumer.
_JADX_ROOTS = {"sources", "resources"}


def _normalize_source_file(source_file: str | None) -> str | None:
    """Strip a leading jadx root segment (``sources/``, ``resources/``).

    Applied in ``_node_row``/``_parse_query_nodes`` so ``file`` is
    root-relative everywhere (code maps rows, agent graph citations). Only
    one leading segment is stripped: a package literally named ``sources``
    yields ``sources/foo/Bar.java``, which is exactly the tree path under
    the ``sources`` root.
    """
    if not source_file:
        return source_file
    first, sep, rest = source_file.partition("/")
    if sep and first in _JADX_ROOTS:
        return rest
    return source_file


class GraphifyError(RuntimeError):
    """graphify CLI failed or produced no graph - surfaced as a clear error."""


@dataclass(frozen=True)
class GraphStats:
    nodes: int
    edges: int
    graph_path: Path


def _resolve_cmd() -> str:
    return settings.graphify_cmd or shutil.which("graphify") or "graphify"


# ---- build -------------------------------------------------------------------


def build(scan_id: int, decompiled_root: Path, graphs_dir: Path) -> GraphStats:
    """Build the per-scan code graph; returns node/edge counts + graph path.

    graphify 0.9.32 writes its output into the INPUT directory
    (``<decompiled>/graphify-out/``), not the cwd - verified empirically
    (Aug 8: rc=0 builds produced ``graph.json`` inside the decompiled tree,
    never at ``<cwd>/graphify-out/``). After a successful run the whole
    ``graphify-out`` folder is therefore MOVED into the per-scan graphs dir
    (same volume → instant rename) so the decompiler tree stays clean and
    ``graph_path_for`` keeps resolving. Raises GraphifyError when the CLI
    fails or no ``graph.json`` is produced anywhere.
    """
    graphs_dir = Path(graphs_dir)
    target = graphs_dir / str(scan_id)
    target.mkdir(parents=True, exist_ok=True)
    cmd = [_resolve_cmd(), "update", str(decompiled_root), "--no-cluster"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=target,
            capture_output=True,
            text=True,
            timeout=settings.graphify_timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise GraphifyError(
            f"graphify build timed out after {settings.graphify_timeout_seconds}s"
        ) from exc

    if proc.returncode != 0:
        stderr = (proc.stderr or "")[-2000:]
        raise GraphifyError(f"graphify build failed (rc={proc.returncode}): {stderr}")

    graph_path = target / "graphify-out" / "graph.json"
    built_in_input = decompiled_root / "graphify-out"
    if built_in_input.is_dir() and not graph_path.is_file():
        # Relocate the CLI's input-dir output into the per-scan graphs dir.
        # A pre-existing target (re-run) is replaced first.
        out_target = target / "graphify-out"
        if out_target.exists():
            shutil.rmtree(out_target)
        shutil.move(str(built_in_input), str(out_target))

    if not graph_path.is_file():
        stderr = (proc.stderr or "")[-2000:]
        raise GraphifyError(
            f"graphify build produced no graph.json (rc={proc.returncode}): {stderr}"
        )

    nodes, edges = count_graph(graph_path)
    return GraphStats(nodes=nodes, edges=edges, graph_path=graph_path)


def count_graph(graph_path: Path) -> tuple[int, int]:
    """Node/edge counts from graph.json.

    The file can be tens of MB (46k nodes ≈ 64 MB on InsecureBankv2), so this
    is a streaming count of top-level array members rather than a full
    json.load (which would build the entire object graph in memory). The
    export uses networkx node-link format: nodes under ``"nodes"``, edges
    under ``"links"`` (some versions use ``"edges"`` - accept both).
    """
    text = graph_path.read_text(encoding="utf-8")
    nodes = _count_array_members(text, "nodes")
    edges = max(_count_array_members(text, "edges"), _count_array_members(text, "links"))
    return nodes, edges


def _count_array_members(text: str, key: str) -> int:
    """Count ``{...}`` members of the array following ``"<key>": [``.

    Each top-level object (depth 0 -> 1 transition) counts as one member; the
    count is returned when the array's closing ``]`` is reached. Strings are
    not JSON-token-aware, but node/edge payloads contain no braces inside
    string values in graphify's export format, so plain brace counting is
    safe here.
    """
    marker = f'"{key}": ['
    idx = text.find(marker)
    if idx < 0:
        return 0
    idx += len(marker)
    count = 0
    depth = 0
    for ch in text[idx:]:
        if ch == "{":
            depth += 1
            if depth == 1:
                count += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
        elif ch == "]" and depth == 0:
            return count
    return count


def graph_path_for(scan_id: int) -> Path:
    """Resolve a scan's graph.json (may not exist yet)."""
    from app.config import settings

    return settings.data_dir / "graphs" / str(scan_id) / "graphify-out" / "graph.json"


# ---- Code maps explorer (search / detail / hubs) ------------------------------


@dataclass(frozen=True)
class ExplorerData:
    """Compact in-memory view of a graph for the Code maps explorer.

    ``nodes`` are public-shape rows (``id/label/file_type/file/line``),
    ``links`` are ``(source, target, relation)`` tuples, ``degree`` counts
    in+out links per node. Built once per graph and cached; the raw 64 MB
    graph.json is never parsed per request.
    """

    nodes: list[dict]
    by_id: dict[str, int]
    links: list[tuple[str, str, str]]
    degree: dict[str, int]


# graph_path -> (mtime, data). Keyed on absolute paths so distinct scans (and
# test tmp dirs) never collide; mtime check picks up a rebuilt graph. Bounded
# to the most-recently built graphs - each compact index is tens of MB in
# memory, so an unbounded cache would creep on a machine that scans many apps.
_EXPLORER_CACHE: dict[str, tuple[float, ExplorerData]] = {}
_EXPLORER_CACHE_MAX = 4
# explorer.json shape version - bump when the row shape changes (Aug 9, 2026:
# file normalized to root-relative) so a stale persisted index from an older
# build is rebuilt instead of served as-is.
_EXPLORER_INDEX_VERSION = 2


def _row_from_node(node: dict) -> dict:
    """Public-shape explorer row - the agent citation row plus file_type."""
    row = _node_row(node)
    # _node_row keeps label/file optional (agent citations); the explorer
    # schema requires a label, so fall back to the id like the old builder.
    row["label"] = row["label"] or row["id"]
    row["file_type"] = node.get("file_type") or ""
    return row


def _build_explorer(graph_path: Path, index_path: Path) -> ExplorerData:
    """One-time compaction of graph.json into the explorer index.

    Writes ``explorer.json`` next to ``graph.json`` (compact node rows +
    (source, target, relation) links) so later process starts skip the full
    parse. ``json.load`` of the raw file is a few hundred MB peak - accepted
    for the local-first tool, and only happens once per graph.
    """
    with open(graph_path, encoding="utf-8") as fh:
        data = json.load(fh)
    nodes: list[dict] = []
    by_id: dict[str, int] = {}
    for node in data.get("nodes", []):
        nid = node.get("id")
        if not nid:
            continue
        by_id[nid] = len(nodes)
        nodes.append(_row_from_node(node))
    links: list[tuple[str, str, str]] = []
    degree: dict[str, int] = {}
    for link in data.get("links", []) or data.get("edges", []):
        source, target = link.get("source"), link.get("target")
        if not source or not target:
            continue
        rel = link.get("relation") or ""
        links.append((source, target, rel))
        degree[source] = degree.get(source, 0) + 1
        degree[target] = degree.get(target, 0) + 1
    try:
        index_path.write_text(
            json.dumps(
                {"version": _EXPLORER_INDEX_VERSION, "nodes": nodes, "links": links},
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
    except OSError:
        pass  # in-memory cache alone is enough for this process
    return ExplorerData(nodes=nodes, by_id=by_id, links=links, degree=degree)


def _load_explorer_index(index_path: Path) -> ExplorerData | None:
    try:
        with open(index_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None  # missing/torn index - caller rebuilds
    if data.get("version") != _EXPLORER_INDEX_VERSION:
        return None  # stale shape from an older build - caller rebuilds
    nodes: list[dict] = []
    by_id: dict[str, int] = {}
    for row in data.get("nodes", []):
        nid = row.get("id")
        if not nid:
            continue
        by_id[nid] = len(nodes)
        nodes.append(row)
    links: list[tuple[str, str, str]] = []
    degree: dict[str, int] = {}
    for link in data.get("links", []):
        source, target, rel = link
        links.append((source, target, rel))
        degree[source] = degree.get(source, 0) + 1
        degree[target] = degree.get(target, 0) + 1
    return ExplorerData(nodes=nodes, by_id=by_id, links=links, degree=degree)


def explorer_data(graph_path: Path) -> ExplorerData:
    """Load (lazily building once) the compact explorer index for a graph.

    ``graph.json`` can be tens of MB (InsecureBankv2: 46k nodes / 116k edges
    ≈ 64 MB) - far too heavy to parse per search. The first access compacts
    it into ``explorer.json`` next to the graph and caches the result in
    memory (mtime-keyed, so a rebuilt graph re-compacts).
    """
    key = str(graph_path)
    mtime = graph_path.stat().st_mtime
    cached = _EXPLORER_CACHE.get(key)
    if cached is not None and cached[0] == mtime:
        return cached[1]
    index_path = graph_path.with_name("explorer.json")
    if index_path.is_file() and index_path.stat().st_mtime >= mtime:
        data = _load_explorer_index(index_path)
        if data is None:
            data = _build_explorer(graph_path, index_path)
    else:
        data = _build_explorer(graph_path, index_path)
    _EXPLORER_CACHE[key] = (mtime, data)
    # Evict the oldest-inserted entry when over the bound (dicts preserve
    # insertion order, so the first key is the oldest).
    while len(_EXPLORER_CACHE) > _EXPLORER_CACHE_MAX:
        _EXPLORER_CACHE.pop(next(iter(_EXPLORER_CACHE)))
    return data


def search(
    graph_path: Path, query: str, limit: int = 25
) -> tuple[list[dict], int]:
    """Substring search over node labels/ids for the Code maps explorer.

    Tokens come from the query (camelCase/snake identifiers kept whole,
    stopwords dropped - same tokenizer as ``search_labels``). A node matches
    when any token appears in its label or id; results rank label-prefix >
    label-substring > id-substring, then label asc. Returns ``(rows, total)``
    where ``total`` is the pre-limit match count.
    """
    tokens = {
        t for t in re.split(r"[^a-zA-Z0-9_]+", query.lower())
        if len(t) >= 3 and t not in _STOPWORDS
    }
    if not tokens:
        return [], 0
    data = explorer_data(graph_path)
    scored: list[tuple[int, dict]] = []
    for row in data.nodes:
        label = (row["label"] or "").lower()
        nid = (row["id"] or "").lower()
        score = 0
        for token in tokens:
            if token in label:
                score += 2 if label.startswith(token) else 1
            if token in nid:
                score += 1
        if score:
            scored.append((score, row))
    total = len(scored)
    scored.sort(key=lambda pair: (-pair[0], (pair[1]["label"] or "").lower()))
    return [dict(row) for _, row in scored[:limit]], total


def node_detail(
    graph_path: Path, node_id: str, max_neighbors: int = 40
) -> dict | None:
    """One node + its graph neighbors for the explorer detail pane.

    Neighbors are the nodes linked to/from ``node_id`` in either direction,
    each with the link's ``relation`` and its ``direction`` ("in"/"out").
    Out-neighbors come first, each group sorted by neighbor degree (the
    most-connected first), capped at ``max_neighbors``. Returns None for an
    unknown node id.
    """
    data = explorer_data(graph_path)
    idx = data.by_id.get(node_id)
    if idx is None:
        return None
    node = data.nodes[idx]
    outgoing: list[dict] = []
    incoming: list[dict] = []
    # A pair can carry several relations (a->b "calls" AND a->b "imports");
    # dedupe by neighbor id, keeping the first relation seen, so the list
    # reads as a map rather than a raw edge dump.
    seen_out: set[str] = set()
    seen_in: set[str] = set()
    for source, target, rel in data.links:
        if source == node_id:
            nidx = data.by_id.get(target)
            if nidx is not None and data.nodes[nidx]["id"] not in seen_out:
                seen_out.add(data.nodes[nidx]["id"])
                outgoing.append(
                    {"node": data.nodes[nidx], "relation": rel, "direction": "out"}
                )
        elif target == node_id:
            nidx = data.by_id.get(source)
            if nidx is not None and data.nodes[nidx]["id"] not in seen_in:
                seen_in.add(data.nodes[nidx]["id"])
                incoming.append(
                    {"node": data.nodes[nidx], "relation": rel, "direction": "in"}
                )
    outgoing.sort(key=lambda n: -data.degree.get(n["node"]["id"], 0))
    incoming.sort(key=lambda n: -data.degree.get(n["node"]["id"], 0))
    return {
        "node": node,
        "degree": data.degree.get(node_id, 0),
        "neighbors": (outgoing + incoming)[:max_neighbors],
    }


def hubs(graph_path: Path, limit: int = 25) -> list[dict]:
    """Most-connected nodes by link degree - the explorer's initial view."""
    data = explorer_data(graph_path)
    rows: list[dict] = []
    for node_id, degree in sorted(data.degree.items(), key=lambda kv: -kv[1]):
        idx = data.by_id.get(node_id)
        if idx is None:
            continue
        rows.append({"node": data.nodes[idx], "degree": degree})
        if len(rows) >= limit:
            break
    return rows

# ---- query -------------------------------------------------------------------


def _run_cli(args: list[str], graph_path: Path, timeout: float = 180.0) -> str:
    cmd = [_resolve_cmd(), *args, "--graph", str(graph_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise GraphifyError(f"graphify {' '.join(args)} timed out") from exc
    if proc.returncode != 0:
        return proc.stderr[-1000:]
    return proc.stdout


def query(graph_path: Path, question: str, *, budget: int = 1500) -> dict:
    """Structural question -> graph traversal answer.

    Tries graphify's BFS first; on no match, falls back to a deterministic
    label/ID substring search (identifier-shaped vocabulary works natively,
    natural-language terms resolve via the fallback). Returns
    ``{"found", "text", "nodes", "via"}`` where ``nodes`` are
    ``{id, label, file, line}`` rows for citation-style answers.
    """
    out = _run_cli(["query", question, "--budget", str(budget)], graph_path)
    nodes = _parse_query_nodes(out)
    if nodes:
        return {"found": True, "text": out, "nodes": nodes, "via": "graphify-query"}
    fallback = search_labels(graph_path, question, limit=_SEARCH_LIMIT)
    if fallback:
        return {
            "found": True,
            "text": _render_search(fallback),
            "nodes": fallback,
            "via": "label-search",
        }
    return {"found": False, "text": out, "nodes": [], "via": "none"}


def search_labels(graph_path: Path, question: str, limit: int = _SEARCH_LIMIT) -> list[dict]:
    """Deterministic label/ID substring search over the graph JSON.

    Tokens come from the question (camelCase/snake identifiers are kept whole
    - "NetworkSecurityConfig" stays one token). Stopwords are dropped so a
    phrase like "where is X located" reduces to its identifier terms.
    """
    tokens = {
        t for t in re.split(r"[^a-zA-Z0-9_]+", question.lower())
        if len(t) >= 3 and t not in _STOPWORDS
    }
    if not tokens:
        return []
    with open(graph_path, encoding="utf-8") as fh:
        data = json.load(fh)
    hits: list[dict] = []
    for node in data.get("nodes", []):
        label = (node.get("label") or "").lower()
        nid = (node.get("id") or "").lower()
        if any(t in label or t in nid for t in tokens):
            hits.append(_node_row(node))
            if len(hits) >= limit:
                break
    return hits


def _node_row(node: dict) -> dict:
    loc = node.get("source_location") or ""
    line = int(re.sub(r"\D", "", loc)) if re.search(r"\d", loc) else None
    return {
        "id": node.get("id"),
        "label": node.get("label"),
        "file": _normalize_source_file(node.get("source_file")),
        "line": line,
    }


def _parse_query_nodes(out: str) -> list[dict]:
    """Extract ``NODE label [src=...]`` lines from ``graphify query`` output."""
    rows: list[dict] = []
    for line in out.splitlines():
        m = re.match(r"^\s*NODE\s+(.+?)\s+\[src=([^\]]*)\s+loc=([^\]]*)\]", line)
        if not m:
            continue
        label, src, loc = m.group(1), m.group(2), m.group(3)
        line_no = int(re.sub(r"\D", "", loc)) if re.search(r"\d", loc) else None
        rows.append(
            {
                "id": None,
                "label": label,
                "file": _normalize_source_file(src) or None,
                "line": line_no,
            }
        )
    return rows


def _render_search(rows: list[dict]) -> str:
    lines = [f"{r['label']} - {r['file']}" + (f":{r['line']}" if r["line"] else "") for r in rows]
    return "Matching nodes:\n" + "\n".join(lines)


# ---- path / explain / affected (M6 tool surface) ------------------------------


def path_between(graph_path: Path, node_a: str, node_b: str) -> str:
    return _run_cli(["path", node_a, node_b], graph_path)


def explain(graph_path: Path, node: str) -> str:
    return _run_cli(["explain", node], graph_path)


def affected(graph_path: Path, node: str, *, depth: int = 2) -> str:
    return _run_cli(["affected", node, "--depth", str(depth)], graph_path)

"""Subprocess wrapper over the graphify CLI (pinned 0.9.32) — M4 Layer 3.

Per-scan code graph (FR-9i): deterministic AST extraction, zero LLM, zero
network. Build runs ``graphify update <decompiled-dir> --no-cluster`` with
cwd set to ``data/graphs/<scan_id>`` so output lands at
``data/graphs/<scan_id>/graphify-out/graph.json``; queries run
``graphify query|path|explain|affected --graph <path>`` — the exact surface
the M4 agent tools ``graph_query``/``graph_path``/``graph_explain`` call.

CLI-surface notes (validated on 0.9.32, recorded for the M4 plan):
- There is **no ``extract`` or ``export`` subcommand**; ``update`` is the
  headless code-only build (its help text: "re-extract code files and update
  the graph (no LLM needed)"). ``--no-cluster`` skips community detection and
  writes the raw ``graph.json`` — sufficient for query/path/explain; a
  ``cluster-only`` pass can add the report later (M9).
- Natural-language ``query`` finds nothing on code-only AST graphs (nodes
  carry identifier labels, not semantic text — e.g. ``query WebView`` works,
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


class GraphifyError(RuntimeError):
    """graphify CLI failed or produced no graph — surfaced as a clear error."""


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

    Raises GraphifyError when the CLI fails or ``graph.json`` isn't produced.
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

    graph_path = target / "graphify-out" / "graph.json"
    if proc.returncode != 0 or not graph_path.is_file():
        stderr = (proc.stderr or "")[-2000:]
        raise GraphifyError(f"graphify build failed (rc={proc.returncode}): {stderr}")

    nodes, edges = count_graph(graph_path)
    return GraphStats(nodes=nodes, edges=edges, graph_path=graph_path)


def count_graph(graph_path: Path) -> tuple[int, int]:
    """Node/edge counts from graph.json.

    The file can be tens of MB (46k nodes ≈ 64 MB on InsecureBankv2), so this
    is a streaming count of top-level array members rather than a full
    json.load (which would build the entire object graph in memory). The
    export uses networkx node-link format: nodes under ``"nodes"``, edges
    under ``"links"`` (some versions use ``"edges"`` — accept both).
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
    — "NetworkSecurityConfig" stays one token). Stopwords are dropped so a
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
        "file": node.get("source_file"),
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
        rows.append({"id": None, "label": label, "file": src or None, "line": line_no})
    return rows


def _render_search(rows: list[dict]) -> str:
    lines = [f"{r['label']} — {r['file']}" + (f":{r['line']}" if r["line"] else "") for r in rows]
    return "Matching nodes:\n" + "\n".join(lines)


# ---- path / explain / affected (M6 tool surface) ------------------------------


def path_between(graph_path: Path, node_a: str, node_b: str) -> str:
    return _run_cli(["path", node_a, node_b], graph_path)


def explain(graph_path: Path, node: str) -> str:
    return _run_cli(["explain", node], graph_path)


def affected(graph_path: Path, node: str, *, depth: int = 2) -> str:
    return _run_cli(["affected", node, "--depth", str(depth)], graph_path)

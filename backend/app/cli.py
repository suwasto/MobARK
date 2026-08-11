"""M1/M2/M3/M4 CLI: artifact analysis + model health + agent/graph commands.

Usage:
  python -m app.cli run <apk|ipa> [--out <results.json>]   # synchronous, no RQ
  python -m app.cli scan <apk|ipa>                         # create scan + enqueue RQ job
  python -m app.cli jobs <scan_id>                         # run an existing scan id synchronously
  python -m app.cli model health [--backend <id>]          # backend reachability + models
  python -m app.cli graph build <scan_id>                  # build the per-scan code graph
  python -m app.cli graph query <scan_id> "question"      # graph traversal (no LLM)
  python -m app.cli graph path <scan_id> <a> <b>           # shortest path between nodes
  python -m app.cli graph explain <scan_id> <node>         # explain a graph node
  python -m app.cli agent context <scan_id> [--out f]      # render Layer 1 findings context
  python -m app.cli agent chat <scan_id> "question" [--timeout N]  # Layers 1-3 answer

The synchronous ``run`` path is the fastest way to validate the pipeline
end-to-end against a real artifact without Redis running. Platform is
auto-detected from the file extension (``.apk`` -> android, ``.ipa`` -> ios).
The ``model health`` path is the UI-free way to verify Ollama/LM Studio/BYOK
connectivity (exit 0 = all requested backends reachable).

The RAG/embedding pipeline was removed from v1 by owner decision - the agent
layers are non-embedding: Layer 1 = full findings context, Layer 2 =
search/read tools, Layer 3 = Graphify graph (Android). ``agent context`` is
the LLM-free way to inspect exactly what the agent sees.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from app.config import settings


def _positive_seconds(value: str) -> float:
    """argparse type: a strictly positive number of seconds."""
    t = float(value)
    if t <= 0:
        raise argparse.ArgumentTypeError(f"timeout must be > 0, got {value!r}")
    return t


def _artifact_path(value: str) -> Path:
    p = Path(value).resolve()
    if not p.is_file():
        raise SystemExit(f"artifact not found: {p}")
    suffix = p.suffix.lower()
    if suffix not in (".apk", ".ipa"):
        raise SystemExit(f"unsupported artifact type {suffix!r} (expected .apk or .ipa)")
    return p


def cmd_run(artifact: Path, out: Path | None) -> int:
    from app.analysis.orchestrator import ScanAborted, run_analysis

    work = settings.data_dir / "work" / "cli"
    try:
        result = run_analysis(artifact, work)
    except ScanAborted as exc:
        print(f"scan aborted: {exc}", file=sys.stderr)
        return 1

    summary = {
        "platform": result.platform,
        "findings": len(result.findings),
        "warnings": result.warnings,
        "decompiled_root": str(result.decompiled_root) if result.decompiled_root else None,
    }
    print(json.dumps(summary, indent=2))
    by_tool: dict[str, int] = {}
    for f in result.findings:
        by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
    print("findings per tool:", json.dumps(by_tool))
    for f in result.findings:
        loc = f.file_path or ""
        if f.line_number:
            loc = f"{loc}:{f.line_number}"
        print(f"  [{f.severity:8}] ({f.tool}) {f.title}  {loc}")

    if out:
        payload = [
            {
                "tool": f.tool,
                "title": f.title,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "category": f.category,
                "mastg_test_id": f.mastg_test_id,
                "detail": f.detail,
                "static_only": f.static_only,
            }
            for f in result.findings
        ]
        out.write_text(json.dumps({"summary": summary, "findings": payload}, indent=2))
        print(f"results written to {out}")
    return 0


def cmd_scan(artifact: Path) -> int:
    """Create a Scan row, copy the artifact into the data dir, enqueue the job."""
    from app.db import SessionLocal
    from app.models import Scan

    platform = "ios" if artifact.suffix.lower() == ".ipa" else "android"
    db = SessionLocal()
    try:
        scan = Scan(filename=artifact.name, platform=platform, status="queued")
        db.add(scan)
        db.commit()
        scan_id = scan.id

        upload_dir = settings.data_dir / "uploads" / str(scan_id)
        upload_dir.mkdir(parents=True, exist_ok=True)
        stored = upload_dir / artifact.name
        shutil.copy2(artifact, stored)
        scan.storage_path = str(upload_dir)
        db.commit()
    finally:
        db.close()

    from app.workers.jobs import enqueue_scan

    job = enqueue_scan(scan_id)
    print(f"scan {scan_id} enqueued (job {job.id}); stored at {upload_dir}")
    return 0


def cmd_jobs(scan_id: int) -> int:
    """Run an existing scan synchronously (useful when Redis isn't up)."""
    from app.workers.jobs import run_scan

    result = run_scan(scan_id)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


def cmd_graph_build(scan_id: int) -> int:
    """Run the Layer 3 graph build synchronously (no Redis needed)."""
    from app.workers.jobs import build_graph_scan

    result = build_graph_scan(scan_id)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


def cmd_graph_query(scan_id: int, question: str, budget: int = 1500) -> int:
    """Graph traversal answer (zero LLM) against the per-scan code graph."""
    from app.graph import graphify

    graph_path = graphify.graph_path_for(scan_id)
    if not graph_path.is_file():
        print(f"no graph for scan {scan_id} at {graph_path} - run 'graph build' first")
        return 1
    result = graphify.query(graph_path, question, budget=budget)
    print(result["text"])
    if result["nodes"]:
        print(f"\n({len(result['nodes'])} nodes via {result['via']})")
    return 0 if result["found"] else 1


def cmd_graph_path(scan_id: int, node_a: str, node_b: str) -> int:
    """Shortest path between two graph nodes."""
    from app.graph import graphify

    graph_path = graphify.graph_path_for(scan_id)
    if not graph_path.is_file():
        print(f"no graph for scan {scan_id} - run 'graph build' first")
        return 1
    print(graphify.path_between(graph_path, node_a, node_b))
    return 0


def cmd_graph_explain(scan_id: int, node: str) -> int:
    """Plain-language explanation of a graph node."""
    from app.graph import graphify

    graph_path = graphify.graph_path_for(scan_id)
    if not graph_path.is_file():
        print(f"no graph for scan {scan_id} - run 'graph build' first")
        return 1
    print(graphify.explain(graph_path, node))
    return 0


def cmd_agent_context(scan_id: int, out: Path | None) -> int:
    """Render the Layer 1 findings context - LLM-free inspection of the
    exact findings set (and precision tags) the agent will see."""
    from app.agent.context import build_findings_context
    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            print(f"scan {scan_id} not found", file=sys.stderr)
            return 1
        context = build_findings_context(db, scan)
    finally:
        db.close()
    print(context.rendered)
    if out:
        out.write_text(context.rendered)
        print(f"context written to {out}")
    return 0


def cmd_agent_chat(scan_id: int, question: str, timeout: float | None) -> int:
    """Layers 1-3 grounded answer (needs a configured chat model).

    ``--timeout`` is a hard overall deadline for the whole tool loop - a hung
    LLM call exits with an error instead of blocking forever.
    """
    from app.agent.chat import AgentTimeout, ChatNotConfigured, answer_question

    try:
        result = answer_question(scan_id, question, timeout=timeout)
    except (ChatNotConfigured, AgentTimeout) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(result.answer)
    print()
    for n, c in enumerate(result.citations, 1):
        loc = f"{c.file}:{c.line}" if c.line else c.file
        print(f"  [{n}] {loc}")
    if result.tools_used:
        print(f"\n(tools used: {', '.join(result.tools_used)})")
    return 0


def cmd_model_health(backend_id: str | None) -> int:
    """Reachability + model listing per configured backend (UI-free check).

    Exit codes: 0 all requested backends reachable, 1 any unreachable,
    2 unknown backend id.
    """
    from app.model.backends import get_store
    from app.model.health import check_backend

    backends = get_store().read()
    if backend_id:
        backends = [b for b in backends if b.id == backend_id]
        if not backends:
            known = ", ".join(b.id for b in get_store().read())
            print(f"unknown backend {backend_id!r}; known: {known}", file=sys.stderr)
            return 2

    ok = True
    for b in backends:
        h = check_backend(b, probe=True)
        line = (
            f"{b.id:12} {h.status:11} reachable={h.reachable}"
            f" latency={h.latency_ms}ms models={len(h.models)}"
        )
        if h.probe_model:
            line += f" probe={h.probe_model}:{h.probe_ok}"
        print(line)
        if h.error:
            print(f"             {h.error}")
        ok = ok and h.reachable
    return 0 if ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="masa-cli", description="MASA M1 analysis CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run analysis synchronously")
    p_run.add_argument("artifact", type=_artifact_path, metavar="apk-or-ipa")
    p_run.add_argument("--out", type=Path, default=None)

    p_scan = sub.add_parser("scan", help="register + enqueue a scan")
    p_scan.add_argument("artifact", type=_artifact_path, metavar="apk-or-ipa")

    p_jobs = sub.add_parser("jobs", help="run an existing scan synchronously")
    p_jobs.add_argument("scan_id", type=int)

    p_model = sub.add_parser("model", help="model backend health checks")
    p_model_sub = p_model.add_subparsers(dest="model_command", required=True)
    p_health = p_model_sub.add_parser("health", help="check backend reachability + models")
    p_health.add_argument(
        "--backend",
        default=None,
        help="backend id (ollama, lm-studio, openai, ...); default: all",
    )

    p_graph = sub.add_parser("graph", help="Graphify code-graph commands (Layer 3, Android)")
    p_graph_sub = p_graph.add_subparsers(dest="graph_command", required=True)
    p_gb = p_graph_sub.add_parser("build", help="build the per-scan code graph")
    p_gb.add_argument("scan_id", type=int)
    p_gq = p_graph_sub.add_parser("query", help="structural question -> graph traversal")
    p_gq.add_argument("scan_id", type=int)
    p_gq.add_argument("question")
    p_gq.add_argument("--budget", type=int, default=1500)
    p_gp = p_graph_sub.add_parser("path", help="shortest path between two nodes")
    p_gp.add_argument("scan_id", type=int)
    p_gp.add_argument("node_a")
    p_gp.add_argument("node_b")
    p_ge = p_graph_sub.add_parser("explain", help="explain a graph node")
    p_ge.add_argument("scan_id", type=int)
    p_ge.add_argument("node")

    p_agent = sub.add_parser("agent", help="M4 Layers 1-3 agent commands (no embeddings)")
    p_agent_sub = p_agent.add_subparsers(dest="agent_command", required=True)
    p_ac = p_agent_sub.add_parser("context", help="render the Layer 1 findings context (no LLM)")
    p_ac.add_argument("scan_id", type=int)
    p_ac.add_argument("--out", type=Path, default=None)
    p_ach = p_agent_sub.add_parser("chat", help="Layers 1-3 answer (needs a chat model)")
    p_ach.add_argument("scan_id", type=int)
    p_ach.add_argument("question")
    p_ach.add_argument(
        "--timeout",
        type=_positive_seconds,
        default=None,
        help="overall deadline in seconds for the whole agent loop "
        "(default: settings.chat_timeout_seconds)",
    )

    args = parser.parse_args()
    if args.command == "run":
        raise SystemExit(cmd_run(args.artifact, args.out))
    if args.command == "scan":
        raise SystemExit(cmd_scan(args.artifact))
    if args.command == "jobs":
        raise SystemExit(cmd_jobs(args.scan_id))
    if args.command == "model":
        if args.model_command == "health":
            raise SystemExit(cmd_model_health(args.backend))
    if args.command == "graph":
        if args.graph_command == "build":
            raise SystemExit(cmd_graph_build(args.scan_id))
        if args.graph_command == "query":
            raise SystemExit(cmd_graph_query(args.scan_id, args.question, args.budget))
        if args.graph_command == "path":
            raise SystemExit(cmd_graph_path(args.scan_id, args.node_a, args.node_b))
        if args.graph_command == "explain":
            raise SystemExit(cmd_graph_explain(args.scan_id, args.node))
    if args.command == "agent":
        if args.agent_command == "context":
            raise SystemExit(cmd_agent_context(args.scan_id, args.out))
        if args.agent_command == "chat":
            raise SystemExit(cmd_agent_chat(args.scan_id, args.question, args.timeout))


if __name__ == "__main__":
    main()

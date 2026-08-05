"""M1/M2 CLI: register an artifact (.apk/.ipa) as a scan and run analysis.

Usage:
  python -m app.cli run <apk|ipa> [--out <results.json>]   # synchronous, no RQ
  python -m app.cli scan <apk|ipa>                         # create scan + enqueue RQ job
  python -m app.cli jobs <scan_id>                         # run an existing scan id synchronously

The synchronous ``run`` path is the fastest way to validate the pipeline
end-to-end against a real artifact without Redis running. Platform is
auto-detected from the file extension (``.apk`` -> android, ``.ipa`` -> ios).
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from app.config import settings


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

    args = parser.parse_args()
    if args.command == "run":
        raise SystemExit(cmd_run(args.artifact, args.out))
    if args.command == "scan":
        raise SystemExit(cmd_scan(args.artifact))
    if args.command == "jobs":
        raise SystemExit(cmd_jobs(args.scan_id))


if __name__ == "__main__":
    main()

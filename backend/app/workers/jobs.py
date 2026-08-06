import json
import time
from pathlib import Path

from rq import Queue

from app.workers.redis import get_redis

DEFAULT_QUEUE = "default"


def dummy_job(message: str = "hello from MASA") -> dict:
    """M0 smoke-test job: proves the Redis -> RQ -> worker -> result loop."""
    time.sleep(0.5)
    return {"echo": message, "processed": True, "status": "ok"}


def enqueue_dummy(message: str = "hello from MASA"):
    """Enqueue the dummy job and return the RQ Job handle."""
    queue = Queue(DEFAULT_QUEUE, connection=get_redis())
    return queue.enqueue(dummy_job, message)


def run_scan(scan_id: int) -> dict:
    """Run the full analysis pipeline for an existing scan row (M1/M2).

    Platform is auto-detected from the stored artifact's extension
    (``.apk`` -> android, ``.ipa`` -> ios) via the orchestrator's
    ``run_analysis`` dispatch. The scan row must already have
    ``storage_path`` pointing at a directory containing the uploaded
    artifact (``<storage_path>/<filename>``). Progress is persisted on the
    scan row (queued -> running -> done|failed).
    """
    from app.analysis.orchestrator import ScanAborted, run_analysis
    from app.analysis.risk import compute_risk_score
    from app.config import settings
    from app.db import SessionLocal
    from app.models import Finding, Scan, utcnow

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return {"ok": False, "error": f"scan {scan_id} not found"}

        scan.status = "running"
        scan.started_at = utcnow()
        scan.stage = "starting"
        db.commit()

        storage = Path(scan.storage_path) if scan.storage_path else None
        artifact_path = (
            storage / scan.filename if storage and storage.is_dir() else storage
        )
        if artifact_path is None or not artifact_path.is_file():
            raise ScanAborted(f"uploaded artifact missing at {artifact_path}")

        def _set_stage(stage: str) -> None:
            """Persist the pipeline stage for the M5 progress screen."""
            scan.stage = stage
            db.commit()

        work_dir = settings.data_dir / "work" / str(scan_id)
        result = run_analysis(artifact_path, work_dir, on_stage=_set_stage)

        # Replace findings for this scan (re-runs shouldn't accumulate).
        db.query(Finding).filter(Finding.scan_id == scan_id).delete()
        for f in result.findings:
            db.add(
                Finding(
                    scan_id=scan_id,
                    tool=f.tool,
                    title=f.title,
                    severity=f.severity,
                    file_path=f.file_path,
                    line_number=f.line_number,
                    category=f.category,
                    mastg_test_id=f.mastg_test_id,
                    detail=json.dumps(f.detail) if f.detail else None,
                    static_only=f.static_only,
                )
            )

        scan.platform = result.platform
        scan.status = "done"
        scan.stage = "done"
        scan.risk_score = compute_risk_score(result.findings)
        scan.finished_at = utcnow()
        scan.error = "\n".join(result.warnings)[:2000] if result.warnings else None
        db.commit()
        # M4 Layer 3: chain the Graphify code-graph build as a follow-up job —
        # a separate, retryable job so a graph failure never fails analysis.
        # Android only: iOS has no decompiled source tree (M4 Decision 5).
        # A failed enqueue (e.g. Redis briefly down) is a warning, never a
        # scan failure — analysis already succeeded and is committed above.
        graph_enqueued = False
        if result.platform == "android":
            try:
                enqueue_graph_build(scan_id)
                graph_enqueued = True
            except Exception as exc:  # noqa: BLE001
                result.warnings.append(
                    f"graph build enqueue failed (analysis unaffected): {exc}"
                )
                scan.error = "\n".join(result.warnings)[:2000]
                db.commit()
        return {
            "ok": True,
            "scan_id": scan_id,
            "findings": len(result.findings),
            "warnings": result.warnings,
            "graph_build_enqueued": graph_enqueued,
        }
    except Exception as exc:
        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.stage = "failed"
            scan.error = str(exc)[:2000]
            scan.finished_at = utcnow()
            db.commit()
        return {"ok": False, "scan_id": scan_id, "error": str(exc)[:2000]}
    finally:
        db.close()


def run_android_scan(scan_id: int) -> dict:
    """Compatibility shim for the M1 job name (old queued jobs may resolve it)."""
    return run_scan(scan_id)


def enqueue_scan(scan_id: int):
    """Enqueue the analysis job for a scan (platform auto-detected at run time)."""
    queue = Queue(DEFAULT_QUEUE, connection=get_redis())
    return queue.enqueue(run_scan, scan_id)


# ---- M4 Layer 3: Graphify code-graph build -----------------------------------


def build_graph_scan(scan_id: int) -> dict:
    """Build the per-scan Graphify code graph (Layer 3, Android-only).

    Runs as a follow-up job chained after ``run_scan`` in the same
    worker/queue (a failure here never fails the analysis job). iOS records
    ``built=False`` with a clear reason instead of erroring. Graph state is
    filesystem-derived (``data/graphs/<scan_id>/graphify-out/graph.json``) —
    no DB columns.
    """
    from app.config import settings
    from app.db import SessionLocal
    from app.graph.graphify import build as graphify_build
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return {"ok": False, "error": f"scan {scan_id} not found"}
        if scan.platform != "android":
            return {
                "ok": True,
                "built": False,
                "reason": "ios-no-source",
                "note": "graph is Android-only — iOS has no decompiled source tree",
            }
        decompiled_root = settings.data_dir / "work" / str(scan_id) / "decompiled"
        if not decompiled_root.is_dir():
            return {
                "ok": False,
                "built": False,
                "error": (
                    f"no decompiled source at {decompiled_root} — run the analysis "
                    "scan first"
                ),
            }
        stats = graphify_build(scan_id, decompiled_root, settings.data_dir / "graphs")
        return {
            "ok": True,
            "built": True,
            "nodes": stats.nodes,
            "edges": stats.edges,
            "graph_path": str(stats.graph_path),
        }
    except Exception as exc:
        return {"ok": False, "built": False, "error": str(exc)[:2000]}
    finally:
        db.close()


def enqueue_graph_build(scan_id: int):
    """Enqueue the graph build job for a scan (chained after analysis)."""
    queue = Queue(DEFAULT_QUEUE, connection=get_redis())
    return queue.enqueue(build_graph_scan, scan_id)

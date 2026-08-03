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


def run_android_scan(scan_id: int) -> dict:
    """Run the full M1 Android analysis pipeline for an existing scan row.

    The scan row must already have ``storage_path`` pointing at a directory
    containing the uploaded APK (``<storage_path>/<filename>``). Progress is
    persisted on the scan row (queued -> running -> done|failed).
    """
    from app.analysis.orchestrator import ScanAborted, run_android_analysis
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
        db.commit()

        storage = Path(scan.storage_path) if scan.storage_path else None
        apk_path = (storage / scan.filename) if storage and storage.is_dir() else storage
        if apk_path is None or not apk_path.is_file():
            raise ScanAborted(f"uploaded APK missing at {apk_path}")

        work_dir = settings.data_dir / "work" / str(scan_id)
        result = run_android_analysis(apk_path, work_dir)

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
                )
            )

        scan.platform = result.platform
        scan.status = "done"
        scan.finished_at = utcnow()
        scan.error = "\n".join(result.warnings)[:2000] if result.warnings else None
        db.commit()
        return {
            "ok": True,
            "scan_id": scan_id,
            "findings": len(result.findings),
            "warnings": result.warnings,
        }
    except Exception as exc:
        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.error = str(exc)[:2000]
            scan.finished_at = utcnow()
            db.commit()
        return {"ok": False, "scan_id": scan_id, "error": str(exc)[:2000]}
    finally:
        db.close()


def enqueue_scan(scan_id: int):
    """Enqueue the M1 analysis job for a scan."""
    queue = Queue(DEFAULT_QUEUE, connection=get_redis())
    return queue.enqueue(run_android_scan, scan_id)

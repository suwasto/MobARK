import json
import time
from pathlib import Path

from rq import Queue

from app.workers.redis import get_redis

DEFAULT_QUEUE = "default"


def dummy_job(message: str = "hello from MobARK") -> dict:
    """M0 smoke-test job: proves the Redis -> RQ -> worker -> result loop."""
    time.sleep(0.5)
    return {"echo": message, "processed": True, "status": "ok"}


def enqueue_dummy(message: str = "hello from MobARK"):
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
        # M4 Layer 3: chain the Graphify code-graph build as a follow-up job -
        # a separate, retryable job so a graph failure never fails analysis.
        # Android only: iOS has no decompiled source tree (M4 Decision 5).
        # A failed enqueue (e.g. Redis briefly down) is a warning, never a
        # scan failure - analysis already succeeded and is committed above.
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
        # M8 follow-up (Aug 12): WARM pre-decode. With the worker running,
        # the apktool decode starts the moment analysis lands, so the Smali
        # view is usually ALREADY ready when it is opened - the on-demand
        # first-open wait disappears (a big APK decodes while the user reads
        # the report). Config-gated; a failed enqueue rolls the queue row
        # back to ``not_started`` and is a warning, never a scan failure.
        decode_enqueued = False
        if result.platform == "android" and settings.apktool_predecode_enabled:
            from app.analysis import apktool

            if not apktool.is_ready(scan_id):
                scan.apktool_status = "queued"
                scan.apktool_queued_at = utcnow()
                scan.apktool_error = None
                db.commit()
                try:
                    enqueue_apktool_decode(scan_id)
                    decode_enqueued = True
                except Exception as exc:  # noqa: BLE001 - warning only
                    scan.apktool_status = "not_started"
                    scan.apktool_queued_at = None
                    result.warnings.append(
                        f"smali pre-decode enqueue failed (analysis unaffected): {exc}"
                    )
                    scan.error = "\n".join(result.warnings)[:2000]
                    db.commit()
        return {
            "ok": True,
            "scan_id": scan_id,
            "findings": len(result.findings),
            "warnings": result.warnings,
            "graph_build_enqueued": graph_enqueued,
            "decode_enqueued": decode_enqueued,
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
    filesystem-derived (``data/graphs/<scan_id>/graphify-out/graph.json``) -
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
                "note": "graph is Android-only - iOS has no decompiled source tree",
            }
        decompiled_root = settings.data_dir / "work" / str(scan_id) / "decompiled"
        if not decompiled_root.is_dir():
            return {
                "ok": False,
                "built": False,
                "error": (
                    f"no decompiled source at {decompiled_root} - run the analysis "
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


# ---- M8 Phase A: on-demand apktool decode (Android, Smali view) ------------


def run_apktool_decode(scan_id: int) -> dict:
    """Decode a scan's APK into smali/res/AndroidManifest (Android only).

    **On-demand** (owner decision, Aug 10 2026): this job runs only when the
    user first opens the Smali view or starts an edit - never as part of the
    scan pipeline. The decoded tree is cached per scan (one decode in v1);
    ``ready`` is filesystem-derived (``apktool/AndroidManifest.xml`` exists)
    so a crash mid-decode can never leave a phantom ``ready``. A failed
    decode records ``apktool_status=failed`` + ``apktool_error`` (the Smali
    chip disables with the specific reason + a retry affordance).
    """
    from app.analysis import apktool
    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return {"ok": False, "error": f"scan {scan_id} not found"}
        if scan.platform != "android":
            return {
                "ok": False,
                "error": "apktool decode is Android-only - iOS keeps the read-only "
                "bundle view (M8 decision 5)",
            }
        if apktool.is_ready(scan_id):
            # Crash-safe idempotency: the tree exists, so the state is ready
            # regardless of what the column says.
            scan.apktool_status = "ready"
            scan.apktool_error = None
            scan.apktool_queued_at = None
            db.commit()
            return {"ok": True, "status": "ready", "note": "already decoded"}

        scan.apktool_status = "decoding"
        scan.apktool_queued_at = None  # the job started - the stall clock stops
        db.commit()

        storage = Path(scan.storage_path) if scan.storage_path else None
        artifact_path = (
            storage / scan.filename if storage and storage.is_dir() else storage
        )
        if artifact_path is None or not artifact_path.is_file():
            raise apktool.ApktoolError(f"uploaded APK missing at {artifact_path}")

        apktool.decode(artifact_path, apktool.decoded_root(scan_id))
        scan.apktool_status = "ready"
        scan.apktool_error = None
        scan.apktool_queued_at = None
        db.commit()
        return {"ok": True, "status": "ready"}
    except Exception as exc:
        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.apktool_status = "failed"
            scan.apktool_error = str(exc)[:2000]
            db.commit()
        return {"ok": False, "status": "failed", "error": str(exc)[:2000]}
    finally:
        db.close()


def enqueue_apktool_decode(scan_id: int):
    """Enqueue the on-demand decode job (POST /scans/{id}/smali)."""
    queue = Queue(DEFAULT_QUEUE, connection=get_redis())
    return queue.enqueue(run_apktool_decode, scan_id)


# ---- M8 Phase C: rebuild pipeline (recompile + resign, Android) ------------


def run_rebuild(scan_id: int, build_id: int) -> dict:
    """Apply the scan's applied edits onto a fresh apktool decode and rebuild
    a resigned **TEST** APK: apktool b -> zipalign -> apksigner sign -> verify
    gate (owner decisions, Aug 10 2026).

    Full rebuild history per scan (decision 8): the build row snapshots the
    applied edit ids at job start (``edits_json``), so edits accepted
    mid-build never mutate the build tree; a done build's artifact stays
    re-downloadable. Every stage fails loudly (decision 8): the failing
    stage + specific reason land on ``builds.stage``/``builds.error`` -
    never a silently broken APK. Zero applied edits is allowed (default
    rebuild of the pristine tree). The artifact is signed with MobARK's
    install-scoped TEST keystore (decision 7) and the filename carries the
    ``-resigned-test-`` label (decision 9).
    """
    from sqlalchemy import select

    from app.analysis import apktool, rebuild
    from app.db import SessionLocal
    from app.models import Build, Edit, Scan, utcnow

    db = SessionLocal()
    try:
        build = db.get(Build, build_id)
        if build is None:
            return {"ok": False, "error": f"build {build_id} not found"}
        scan = db.get(Scan, scan_id)
        if scan is None:
            return {"ok": False, "error": f"scan {scan_id} not found"}
        if build.scan_id != scan_id:
            # Defensive: the job is enqueued by the API with matching ids, but
            # a direct/mis-argued enqueue must never build one scan while
            # recording the artifact under another scan's build row.
            return {
                "ok": False,
                "error": f"build {build_id} belongs to scan {build.scan_id}, "
                f"not {scan_id}",
            }
        if scan.platform != "android":
            raise rebuild.RebuildError(
                "applying",
                "rebuild is Android-only - iOS keeps the read-only bundle "
                "view (M8 decision 5)",
            )
        if not apktool.is_ready(scan_id):
            raise rebuild.RebuildError(
                "applying", "apktool decode not ready - run the decode first"
            )

        # Snapshot the applied edits at job start (decision 8): a human can
        # accept/reject proposals while the build runs - the tree never sees
        # them. ``edits_json`` is the immutable record for this build.
        applied = list(
            db.scalars(
                select(Edit)
                .where(Edit.scan_id == scan_id, Edit.status == "applied")
                .order_by(Edit.id)
            ).all()
        )
        build.edits_json = json.dumps([e.id for e in applied])
        build.status = "running"
        build.stage = "applying"
        db.commit()

        def on_stage(stage: str) -> None:
            build.stage = stage
            db.commit()

        artifact = rebuild.build_apk(scan, applied, build_id, on_stage=on_stage)
        build.status = "done"
        build.stage = "done"
        build.artifact_name = artifact.name
        build.artifact_path = str(artifact.path)
        build.artifact_sha256 = artifact.sha256
        build.finished_at = utcnow()
        db.commit()
        # Record which build consumed each snapshot edit (only on success - a
        # failed build produced no artifact to consume them).
        for edit_id in json.loads(build.edits_json):
            edit = db.get(Edit, edit_id)
            if edit is not None:
                edit.build_id = build.id
        db.commit()
        return {
            "ok": True,
            "build_id": build_id,
            "artifact": artifact.name,
            "sha256": artifact.sha256,
        }
    except rebuild.RebuildError as exc:
        build = db.get(Build, build_id)
        if build is not None:
            build.status = "failed"
            build.stage = exc.stage
            build.error = str(exc)[:2000]
            build.finished_at = utcnow()
            db.commit()
        return {
            "ok": False,
            "build_id": build_id,
            "status": "failed",
            "stage": exc.stage,
            "error": str(exc)[:2000],
        }
    except Exception as exc:  # noqa: BLE001 - fail loudly, record the reason
        build = db.get(Build, build_id)
        if build is not None:
            build.status = "failed"
            build.stage = build.stage or "applying"
            build.error = str(exc)[:2000]
            build.finished_at = utcnow()
            db.commit()
        return {"ok": False, "build_id": build_id, "error": str(exc)[:2000]}
    finally:
        db.close()


def enqueue_rebuild(scan_id: int, build_id: int):
    """Enqueue the rebuild job (POST /scans/{id}/rebuild)."""
    queue = Queue(DEFAULT_QUEUE, connection=get_redis())
    return queue.enqueue(run_rebuild, scan_id, build_id)

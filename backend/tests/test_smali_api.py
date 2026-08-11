"""M8 Phase A: on-demand apktool decode - RQ job + smali trigger/status API.

Subprocess and Redis are mocked (no network); the decode state machine and
its 409 guards are the units under test.
"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from app.analysis import apktool
from app.analysis.apktool import ApktoolError
from app.models import Scan
from app.workers import jobs

# ---- helpers ----------------------------------------------------------------


def _add_scan(
    factory, *, platform="android", status="done", apktool_status=None,
    storage_path=None,
):
    with factory() as session:
        scan = Scan(
            filename="app.apk",
            platform=platform,
            status=status,
            storage_path=storage_path or "/unused/uploads",
        )
        if apktool_status:
            scan.apktool_status = apktool_status
        session.add(scan)
        session.commit()
        return scan.id


def _make_apk_upload(scan_id, tmp_path):
    """Materialize the scan's stored APK under the patched data_dir."""
    uploads = tmp_path / "uploads" / str(scan_id)
    uploads.mkdir(parents=True)
    (uploads / "app.apk").write_bytes(b"PK")
    return str(uploads)


def _make_decoded_tree(scan_id, tmp_path, monkeypatch):
    """Point data_dir at tmp_path and materialize a decoded apktool tree."""
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    root = apktool.decoded_root(scan_id)
    root.mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text("<manifest/>")
    (root / "smali").mkdir()
    return root


# ---- job: run_apktool_decode -----------------------------------------------


def test_job_decode_success(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _add_scan(db_session_factory)
    storage = _make_apk_upload(scan_id, tmp_path)
    with db_session_factory() as session:
        session.get(Scan, scan_id).storage_path = storage
        session.commit()

    decoded = {}

    def fake_decode(apk, out_dir, timeout=None):
        decoded["apk"] = apk
        decoded["out"] = out_dir
        out_dir.mkdir(parents=True)  # the real wrapper creates the output dir
        (out_dir / "AndroidManifest.xml").write_text("<manifest/>")

    monkeypatch.setattr(apktool, "decode", fake_decode)

    result = jobs.run_apktool_decode(scan_id)
    assert result == {"ok": True, "status": "ready"}
    assert decoded["apk"].name == "app.apk"
    assert decoded["out"] == tmp_path / "work" / str(scan_id) / "apktool"
    with db_session_factory() as session:
        assert session.get(Scan, scan_id).apktool_status == "ready"


def test_job_decode_already_ready_skips_decode(
    monkeypatch, db_session_factory, tmp_path
):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _add_scan(db_session_factory, apktool_status="failed")
    _make_decoded_tree(scan_id, tmp_path, monkeypatch)  # tree exists

    called = []

    def fake_decode(*a, **k):
        called.append(True)

    monkeypatch.setattr(apktool, "decode", fake_decode)
    result = jobs.run_apktool_decode(scan_id)
    assert result["status"] == "ready"
    assert result["note"] == "already decoded"
    assert called == []  # filesystem-ready wins over the stale 'failed' column
    with db_session_factory() as session:
        assert session.get(Scan, scan_id).apktool_status == "ready"


def test_job_decode_failure_records_failed(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _add_scan(db_session_factory)
    storage = _make_apk_upload(scan_id, tmp_path)
    with db_session_factory() as session:
        session.get(Scan, scan_id).storage_path = storage
        session.commit()

    def boom(apk, out_dir, timeout=None):
        raise ApktoolError("apktool exited 1: resource clash")

    monkeypatch.setattr(apktool, "decode", boom)
    result = jobs.run_apktool_decode(scan_id)
    assert result["ok"] is False
    assert result["status"] == "failed"
    assert "resource clash" in result["error"]
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan.apktool_status == "failed"
        assert "resource clash" in scan.apktool_error


def test_job_decode_missing_apk_fails_cleanly(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _add_scan(db_session_factory)  # storage_path is a dead dir

    result = jobs.run_apktool_decode(scan_id)
    assert result["ok"] is False
    assert "APK missing" in result["error"]
    with db_session_factory() as session:
        assert session.get(Scan, scan_id).apktool_status == "failed"


def _craft_awkward_apk(path) -> None:
    """The Phase E awkward fixture: an APK-shaped ZIP that gets past upload
    but trips apktool - a TEXT AndroidManifest.xml (apktool expects binary
    AXML) + a corrupt resources.arsc. **Keep in sync with
    scripts/make_awkward_apk.py** (the container e2e runs the REAL apktool
    against the same fixture); here it proves the fail-loudly decode chain
    at the job level."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", '<?xml version="1.0"?><manifest/>\n')
        z.writestr("resources.arsc", b"\x02garbage-not-a-resource-table" + b"\x00" * 64)
        z.writestr("classes.dex", b"dex\n035\x00garbage")
    Path(path).write_bytes(buf.getvalue())


def test_job_decode_awkward_apk_fails_loudly(
    monkeypatch, db_session_factory, tmp_path
):
    """Phase E awkward-APK fail-loudly: a corrupt APK present in storage
    fails the decode with a SPECIFIC error on the scan (status=failed +
    apktool_error carries the reason apktool reported), leaves no phantom
    ready tree, and the Smali chip's retry is the user's recovery."""
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _add_scan(db_session_factory)
    storage = _make_apk_upload(scan_id, tmp_path)
    _craft_awkward_apk(tmp_path / "uploads" / str(scan_id) / "app.apk")
    with db_session_factory() as session:
        session.get(Scan, scan_id).storage_path = storage
        session.commit()

    def real_decode_behavior(apk, out_dir, timeout=None):
        # Host has no apktool - the subprocess boundary is mocked. The reason
        # is the EXACT text the real apktool reported in the containerized
        # e2e for this fixture (Unexpected chunk 0x6702 = corrupt ARSC).
        raise apktool.ApktoolError(
            "apktool exited 1: brut.androlib.exceptions.AndrolibException: "
            "Unexpected chunk: 0x6702 (expected: RES_TABLE_TYPE)"
        )

    monkeypatch.setattr(apktool, "decode", real_decode_behavior)
    result = jobs.run_apktool_decode(scan_id)
    assert result["ok"] is False
    assert result["status"] == "failed"
    assert "RES_TABLE_TYPE" in result["error"]
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan.apktool_status == "failed"
        assert "RES_TABLE_TYPE" in scan.apktool_error
    assert apktool.is_ready(scan_id) is False  # no phantom ready tree


def test_job_decode_ios_rejects(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _add_scan(db_session_factory, platform="ios")

    called = []

    def fake_decode(*a, **k):
        called.append(True)

    monkeypatch.setattr(apktool, "decode", fake_decode)
    result = jobs.run_apktool_decode(scan_id)
    assert result["ok"] is False
    assert "Android-only" in result["error"]
    assert called == []
    with db_session_factory() as session:
        assert session.get(Scan, scan_id).apktool_status == "not_started"


def test_job_decode_unknown_scan(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    result = jobs.run_apktool_decode(999999)
    assert result["ok"] is False
    assert "not found" in result["error"]


# ---- API: POST /scans/{id}/smali -------------------------------------------


def test_smali_trigger_202_enqueues(client, db_session_factory, monkeypatch, tmp_path):
    from app.api.routes import scans as routes

    scan_id = _add_scan(db_session_factory)
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    enqueued = {}

    def fake_enqueue(sid):
        enqueued["scan_id"] = sid

    monkeypatch.setattr(routes, "enqueue_apktool_decode", fake_enqueue)
    r = client.post(f"/api/v1/scans/{scan_id}/smali")
    assert r.status_code == 202
    assert r.json() == {"status": "queued", "error": None}
    assert enqueued["scan_id"] == scan_id
    with db_session_factory() as session:
        assert session.get(Scan, scan_id).apktool_status == "queued"


def test_smali_trigger_retries_after_failed(client, db_session_factory, monkeypatch, tmp_path):
    from app.api.routes import scans as routes

    scan_id = _add_scan(db_session_factory, apktool_status="failed")
    with db_session_factory() as session:
        session.get(Scan, scan_id).apktool_error = "apktool exited 1: boom"
        session.commit()
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    enqueued = {}

    def fake_enqueue(sid):
        enqueued["scan_id"] = sid

    monkeypatch.setattr(routes, "enqueue_apktool_decode", fake_enqueue)
    r = client.post(f"/api/v1/scans/{scan_id}/smali")
    assert r.status_code == 202
    assert enqueued["scan_id"] == scan_id
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan.apktool_status == "queued"
        assert scan.apktool_error is None  # retry clears the stale reason


def test_smali_trigger_409_not_analyzed(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, status="queued")
    r = client.post(f"/api/v1/scans/{scan_id}/smali")
    assert r.status_code == 409
    assert "not analyzed" in r.json()["detail"]


def test_smali_trigger_409_ios(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, platform="ios")
    r = client.post(f"/api/v1/scans/{scan_id}/smali")
    assert r.status_code == 409
    assert "Android-only" in r.json()["detail"]


def test_smali_trigger_409_while_decoding(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, apktool_status="decoding")
    r = client.post(f"/api/v1/scans/{scan_id}/smali")
    assert r.status_code == 409
    assert "in progress" in r.json()["detail"]


def test_smali_trigger_409_already_ready(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, apktool_status="failed")
    _make_decoded_tree(scan_id, tmp_path, monkeypatch)  # filesystem says ready
    r = client.post(f"/api/v1/scans/{scan_id}/smali")
    assert r.status_code == 409
    assert "already decoded" in r.json()["detail"]
    with db_session_factory() as session:
        # the stale 'failed' column was corrected to 'ready'
        assert session.get(Scan, scan_id).apktool_status == "ready"


def test_smali_trigger_500_on_enqueue_failure(client, db_session_factory, monkeypatch, tmp_path):
    from app.api.routes import scans as routes

    scan_id = _add_scan(db_session_factory)
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)

    def boom(sid):
        raise RuntimeError("redis down")

    monkeypatch.setattr(routes, "enqueue_apktool_decode", boom)
    r = client.post(f"/api/v1/scans/{scan_id}/smali")
    assert r.status_code == 500
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan.apktool_status == "failed"
        assert "redis down" in scan.apktool_error


def test_smali_trigger_unknown_scan_404(client, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    assert client.post("/api/v1/scans/999999/smali").status_code == 404


# ---- API: GET /scans/{id}/smali-status -------------------------------------


def test_smali_status_derives_ready_from_filesystem(
    client, db_session_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, apktool_status="decoding")
    # the tree exists (e.g. worker crashed after decode, column stale)
    _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    r = client.get(f"/api/v1/scans/{scan_id}/smali-status")
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "error": None}


def test_smali_status_reports_column_states(
    client, db_session_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, apktool_status="decoding")
    r = client.get(f"/api/v1/scans/{scan_id}/smali-status")
    assert r.json()["status"] == "decoding"
    with db_session_factory() as session:
        session.get(Scan, scan_id).apktool_status = "failed"
        session.get(Scan, scan_id).apktool_error = "apktool timed out"
        session.commit()
    r = client.get(f"/api/v1/scans/{scan_id}/smali-status")
    assert r.json() == {"status": "failed", "error": "apktool timed out"}


def test_smali_status_unknown_scan_404(client, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    assert client.get("/api/v1/scans/999999/smali-status").status_code == 404


# ---- API: GET /scans/{id}/smali-mapping -------------------------------------
# Java→Smali mapping for the scan's findings - Smali-mode dots + rail re-key
# jadx findings onto their apktool smali siblings.


def _add_finding(db_session_factory, scan_id, file_path, severity="high"):
    from app.models import Finding

    with db_session_factory() as session:
        session.add(
            Finding(
                scan_id=scan_id,
                tool="semgrep",
                title="webview js",
                severity=severity,
                file_path=file_path,
                line_number=42,
            )
        )
        session.commit()


def test_smali_mapping_returns_finding_siblings(
    client, db_session_factory, tmp_path, monkeypatch
):
    """Finding file_paths are ROOT-RELATIVE (``com/foo/AuthManager.java`` -
    the ``sources/`` prefix is implied, matching the tree node paths the
    frontend dots/rail key on). The mapping returns full tree paths
    (``sources/...`` -> ``smali/...``), consistent with smali-sibling, plus
    the identity entries for res/ and the manifest (their apktool roots
    serve the same files)."""
    scan_id = _add_scan(db_session_factory)
    root = _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    smali_dir = root / "smali" / "com" / "foo"
    smali_dir.mkdir(parents=True)
    (smali_dir / "AuthManager.smali").write_text(".class")
    (root / "res" / "values").mkdir(parents=True)
    (root / "res" / "values" / "strings.xml").write_text("<resources/>")
    _add_finding(db_session_factory, scan_id, "com/foo/AuthManager.java")
    # res/ findings map to THEMSELVES - the apktool res root serves the same
    # relative path as the jadx resources tree.
    _add_finding(db_session_factory, scan_id, "res/values/strings.xml")
    # The manifest maps to the synthetic root's single file (full tree path).
    _add_finding(db_session_factory, scan_id, "AndroidManifest.xml")
    # A sources finding WITHOUT a decoded smali sibling maps to nothing.
    _add_finding(db_session_factory, scan_id, "com/foo/NoSmali.java")
    # An asset path is neither source, res, nor manifest - never mapped.
    _add_finding(db_session_factory, scan_id, "assets/config.json")

    r = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert body["mapping"] == {
        "sources/com/foo/AuthManager.java": "smali/com/foo/AuthManager.smali",
        "res/values/strings.xml": "res/values/strings.xml",
        "AndroidManifest.xml": "AndroidManifest.xml/AndroidManifest.xml",
    }


def test_smali_mapping_multidex_and_dedupe(
    client, db_session_factory, tmp_path, monkeypatch
):
    """Multidex: the map points at the FIRST-FOUND smali root (smali wins
    over smali_classes2), and duplicate file_paths (suppressed + active
    findings on the same file) dedupe via the distinct query."""
    scan_id = _add_scan(db_session_factory)
    root = _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    (root / "smali_classes2").mkdir()
    s1 = root / "smali" / "com" / "foo"
    s2 = root / "smali_classes2" / "com" / "foo"
    s1.mkdir(parents=True)
    s2.mkdir(parents=True)
    (s1 / "A.smali").write_text(".class")
    (s2 / "A.smali").write_text(".class")
    _add_finding(db_session_factory, scan_id, "com/foo/A.java")
    _add_finding(db_session_factory, scan_id, "com/foo/A.java", severity="low")

    r = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r.status_code == 200
    assert r.json()["mapping"] == {
        "sources/com/foo/A.java": "smali/com/foo/A.smali"
    }


def test_smali_mapping_empty_when_undecoded(
    client, db_session_factory, tmp_path, monkeypatch
):
    """No apktool tree = no mapping at all - including the res/manifest
    identity entries, which must not leak before the decode exists (the
    explicit is_ready gate). And no cache file is written."""
    from app.analysis import smali_map

    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, apktool_status="not_started")
    _add_finding(db_session_factory, scan_id, "com/foo/A.java")
    _add_finding(db_session_factory, scan_id, "res/values/strings.xml")
    _add_finding(db_session_factory, scan_id, "AndroidManifest.xml")
    r = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r.status_code == 200
    assert r.json() == {"mapping": {}, "anchors": {}, "total": 0}
    assert not smali_map.mapping_cache_path(scan_id).exists()


def test_smali_mapping_second_call_served_from_cache(
    client, db_session_factory, tmp_path, monkeypatch
):
    """The mapping is computed once per scan: a second request is served from
    the cache (no re-walk of the filesystem per finding path) and the
    persistent cache file exists with the decoded tree's mtime."""
    from app.analysis import smali_map

    scan_id = _add_scan(db_session_factory)
    root = _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    smali_dir = root / "smali" / "com" / "foo"
    smali_dir.mkdir(parents=True)
    (smali_dir / "A.smali").write_text(".class")
    _add_finding(db_session_factory, scan_id, "com/foo/A.java")
    _add_finding(db_session_factory, scan_id, "AndroidManifest.xml")

    computes = []
    real = smali_map.compute_mapping

    def counting_compute(scan, paths):
        computes.append(list(paths))
        return real(scan, paths)

    monkeypatch.setattr(smali_map, "compute_mapping", counting_compute)

    r1 = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r1.status_code == 200
    assert len(computes) == 1  # first call computes
    r2 = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r2.status_code == 200
    assert r2.json() == r1.json()
    assert len(computes) == 1  # second call served from cache - no re-walk

    cache = smali_map.mapping_cache_path(scan_id)
    assert cache.is_file()
    data = json.loads(cache.read_text())
    assert data["version"] == 2
    assert data["tree_mtime"] == (root / "AndroidManifest.xml").stat().st_mtime
    assert data["mapping"] == {
        "sources/com/foo/A.java": "smali/com/foo/A.smali",
        "AndroidManifest.xml": "AndroidManifest.xml/AndroidManifest.xml",
    }
    assert data["anchors"] == {}  # .class-only smali -> no method anchors


def test_smali_mapping_stale_cache_rebuilds(
    client, db_session_factory, tmp_path, monkeypatch
):
    """A cache file from an OLDER decode (stale tree mtime) or a torn write
    is never served - the endpoint recomputes and rewrites the file."""
    from app.analysis import smali_map

    scan_id = _add_scan(db_session_factory)
    root = _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    smali_dir = root / "smali" / "com" / "foo"
    smali_dir.mkdir(parents=True)
    (smali_dir / "A.smali").write_text(".class")
    _add_finding(db_session_factory, scan_id, "com/foo/A.java")

    cache = smali_map.mapping_cache_path(scan_id)
    cache.write_text(
        json.dumps({"version": 1, "tree_mtime": 1.0, "mapping": {"stale": "stale"}})
    )
    r = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r.status_code == 200
    assert r.json()["mapping"] == {
        "sources/com/foo/A.java": "smali/com/foo/A.smali"
    }
    # The file was rewritten with the live tree mtime (not served as-is).
    data = json.loads(cache.read_text())
    assert data["tree_mtime"] == (root / "AndroidManifest.xml").stat().st_mtime
    assert data["mapping"] == {"sources/com/foo/A.java": "smali/com/foo/A.smali"}

    # A torn cache file (invalid JSON) also degrades to a recompute - with
    # the module cache cleared (a fresh process, where only the disk file
    # exists): the request recomputes AND rewrites the file.
    smali_map._MAPPING_CACHE.clear()
    cache.write_text("{not valid json")
    r2 = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r2.status_code == 200
    assert r2.json()["mapping"] == {
        "sources/com/foo/A.java": "smali/com/foo/A.smali"
    }
    assert json.loads(cache.read_text())["mapping"] == {
        "sources/com/foo/A.java": "smali/com/foo/A.smali"
    }


def test_smali_mapping_disk_cache_served_on_fresh_process(
    client, db_session_factory, tmp_path, monkeypatch
):
    """A VALID persisted cache file (matching version + tree mtime) is served
    without recompute - the fresh-process path, where only the disk file
    exists (module cache empty)."""
    from app.analysis import smali_map

    scan_id = _add_scan(db_session_factory)
    root = _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    smali_dir = root / "smali" / "com" / "foo"
    smali_dir.mkdir(parents=True)
    (smali_dir / "A.smali").write_text(".class")
    _add_finding(db_session_factory, scan_id, "com/foo/A.java")

    # Prime the cache (compute + write) via the endpoint, then simulate a
    # fresh process: clear the module cache so only the disk file remains.
    assert client.get(f"/api/v1/scans/{scan_id}/smali-mapping").status_code == 200
    smali_map._MAPPING_CACHE.clear()

    computes = []
    real = smali_map.compute_mapping

    def counting_compute(scan, paths):
        computes.append(list(paths))
        return real(scan, paths)

    monkeypatch.setattr(smali_map, "compute_mapping", counting_compute)
    r = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r.status_code == 200
    assert r.json()["mapping"] == {"sources/com/foo/A.java": "smali/com/foo/A.smali"}
    assert computes == []  # served from the disk file - no re-walk


def test_smali_mapping_409_ios(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, platform="ios")
    r = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r.status_code == 409
    assert "Android-only" in r.json()["detail"]


def test_smali_mapping_409_not_analyzed(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, status="queued")
    r = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r.status_code == 409
    assert "not analyzed" in r.json()["detail"]


def test_smali_mapping_unknown_scan_404(client, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    assert client.get("/api/v1/scans/999999/smali-mapping").status_code == 404


# ---- method-level line anchors (Aug 11) -------------------------------------
# jadx renumbers source lines, so findings can't map statement-to-statement
# onto smali. The honest anchor is METHOD granularity: a finding's jadx line
# sits inside a jadx method; that method's name maps to a ``.method`` line in
# the apktool smali sibling, and the smali rail notes pin there.

_JADX_SAMPLE = """\
package com.foo;

public class AuthManager {
    public static String login(String user, String pass) {
        String secret = "hardcoded";
        return secret;
    }

    public AuthManager() {
        this.token = "abc";
    }

    private void doThing() throws Exception {
        if (user != null) {
            call();
        }
    }
}
"""

_SMALI_SAMPLE = """\
.class public Lcom/foo/AuthManager;
.super Ljava/lang/Object;

.method public static login(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    return-object v0
.end method

.method public constructor <init>()V
    return-void
.end method

.method private doThing()V
    return-void
.end method
"""


def _make_sources_tree(scan_id, tmp_path, monkeypatch):
    """Add a jadx ``work/<id>/decompiled/sources`` tree to the patched data
    dir (the smali-mapping route reads the jadx side for anchors)."""
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    src_dir = tmp_path / "work" / str(scan_id) / "decompiled" / "sources" / "com" / "foo"
    src_dir.mkdir(parents=True)
    (src_dir / "AuthManager.java").write_text(_JADX_SAMPLE)
    return src_dir


def test_anchors_map_finding_lines_to_methods(
    client, db_session_factory, tmp_path, monkeypatch
):
    """A finding's jadx line maps to its containing method's ``.method`` line
    in the smali sibling (by name; constructors map to ``<init>``)."""
    scan_id = _add_scan(db_session_factory)
    root = _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    smali_dir = root / "smali" / "com" / "foo"
    smali_dir.mkdir(parents=True)
    (smali_dir / "AuthManager.smali").write_text(_SMALI_SAMPLE)
    _make_sources_tree(scan_id, tmp_path, monkeypatch)

    from app.models import Finding

    with db_session_factory() as session:
        # login body line 5 -> .method login (smali line 4)
        session.add(Finding(scan_id=scan_id, tool="semgrep", title="hardcoded",
                            severity="high", file_path="com/foo/AuthManager.java",
                            line_number=5))
        # constructor body line 10 -> <init> (smali line 9)
        session.add(Finding(scan_id=scan_id, tool="semgrep", title="ctor",
                            severity="medium", file_path="com/foo/AuthManager.java",
                            line_number=10))
        # doThing body line 15 -> doThing (smali line 13)
        session.add(Finding(scan_id=scan_id, tool="semgrep", title="throws",
                            severity="low", file_path="com/foo/AuthManager.java",
                            line_number=15))
        # line 2 (package decl) is not inside any method -> no anchor
        session.add(Finding(scan_id=scan_id, tool="semgrep", title="package",
                            severity="info", file_path="com/foo/AuthManager.java",
                            line_number=2))
        session.commit()

    r = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r.status_code == 200
    body = r.json()
    assert body["anchors"] == {
        "smali/com/foo/AuthManager.smali": {"5": 4, "10": 9, "15": 13}
    }


def test_anchors_single_line_method_bodies(
    client, db_session_factory, tmp_path, monkeypatch
):
    """jadx emits compact one-line bodies for trivial accessors
    (``public int getX() { return 1; }``) - the brace-counted parser must
    still capture the method (the body opens AND closes on the signature
    line, so depth never rises above class level)."""
    jadx = """\
package com.foo;

public class Config {
    private int value;

    public int getValue() { return this.value; }

    public void setValue(int v) {
        this.value = v;
    }
}
"""
    smali = """\
.class public Lcom/foo/Config;
.super Ljava/lang/Object;

.method public getValue()I
    return v0
.end method

.method public setValue(I)V
    return-void
.end method
"""
    scan_id = _add_scan(db_session_factory)
    root = _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    smali_dir = root / "smali" / "com" / "foo"
    smali_dir.mkdir(parents=True)
    (smali_dir / "Config.smali").write_text(smali)
    _make_sources_tree(scan_id, tmp_path, monkeypatch)
    src_dir = tmp_path / "work" / str(scan_id) / "decompiled" / "sources" / "com" / "foo"
    (src_dir / "Config.java").write_text(jadx)

    from app.models import Finding

    with db_session_factory() as session:
        # Inside the one-line getValue body (line 6) -> getValue (.method line 4)
        session.add(Finding(scan_id=scan_id, tool="semgrep", title="one-line",
                            severity="high", file_path="com/foo/Config.java",
                            line_number=6))
        # Inside the multi-line setValue body (line 9) -> setValue (.method line 8)
        session.add(Finding(scan_id=scan_id, tool="semgrep", title="multi",
                            severity="low", file_path="com/foo/Config.java",
                            line_number=9))
        session.commit()

    r = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r.status_code == 200
    assert r.json()["anchors"] == {
        "smali/com/foo/Config.smali": {"6": 4, "9": 8}
    }


def test_anchors_missing_sources_or_smali_are_empty(
    client, db_session_factory, tmp_path, monkeypatch
):
    """Missing jadx source or smali sibling degrades to no anchors (never a
    crash) - the route gates on is_ready, and file absence is best-effort."""
    scan_id = _add_scan(db_session_factory)
    root = _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    smali_dir = root / "smali" / "com" / "foo"
    smali_dir.mkdir(parents=True)
    (smali_dir / "AuthManager.smali").write_text(_SMALI_SAMPLE)
    # NO jadx sources tree at all
    _add_finding(db_session_factory, scan_id, "com/foo/AuthManager.java")

    r = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r.status_code == 200
    assert r.json()["anchors"] == {}
    assert r.json()["mapping"] == {
        "sources/com/foo/AuthManager.java": "smali/com/foo/AuthManager.smali"
    }


def test_anchors_survive_cache_roundtrip(
    client, db_session_factory, tmp_path, monkeypatch
):
    """Anchors ride the same per-scan cache as the mapping (immutable per
    scan): the second request is served from the module cache and the
    persisted file carries them (fresh-process path)."""
    from app.analysis import smali_map

    scan_id = _add_scan(db_session_factory)
    root = _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    smali_dir = root / "smali" / "com" / "foo"
    smali_dir.mkdir(parents=True)
    (smali_dir / "AuthManager.smali").write_text(_SMALI_SAMPLE)
    _make_sources_tree(scan_id, tmp_path, monkeypatch)
    _add_finding(db_session_factory, scan_id, "com/foo/AuthManager.java")
    with db_session_factory() as session:
        from app.models import Finding

        session.add(Finding(scan_id=scan_id, tool="semgrep", title="hardcoded",
                            severity="high", file_path="com/foo/AuthManager.java",
                            line_number=5))
        session.commit()

    r1 = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r1.json()["anchors"] == {"smali/com/foo/AuthManager.smali": {"5": 4}}
    r2 = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r2.json() == r1.json()  # module cache

    smali_map._MAPPING_CACHE.clear()
    r3 = client.get(f"/api/v1/scans/{scan_id}/smali-mapping")
    assert r3.json()["anchors"] == {"smali/com/foo/AuthManager.smali": {"5": 4}}
    data = json.loads(smali_map.mapping_cache_path(scan_id).read_text())
    assert data["anchors"] == {"smali/com/foo/AuthManager.smali": {"5": 4}}

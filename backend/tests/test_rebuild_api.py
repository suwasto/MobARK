"""M8 Phase C: rebuild API - trigger guards, builds list/get, download.

Redis and subprocesses are mocked; the guard ordering (analyzed → Android →
decode ready → in-flight) and the download contract are the units under test.
"""
from __future__ import annotations

from app.analysis import apktool
from app.models import Build, Scan
from tests.conftest import authed_user_id

# ---- helpers ----------------------------------------------------------------


def _add_scan(factory, *, platform="android", status="done"):
    with factory() as session:
        scan = Scan(
            filename="app.apk",
            platform=platform,
            status=status,
            storage_path="/unused/uploads",
            user_id=authed_user_id(factory),
        )
        session.add(scan)
        session.commit()
        return scan.id


def _make_decoded_tree(scan_id, tmp_path, monkeypatch):
    """Point data_dir at tmp_path and materialize a decoded apktool tree."""
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    root = apktool.decoded_root(scan_id)
    root.mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text("<manifest/>")
    (root / "smali").mkdir()
    return root


def _add_build(factory, scan_id, *, status="done", stage="done",
               artifact_path=None, artifact_name="app-resigned-test-1.apk"):
    with factory() as session:
        build = Build(
            scan_id=scan_id,
            status=status,
            stage=stage,
            artifact_name=artifact_name,
            artifact_path=artifact_path,
        )
        session.add(build)
        session.commit()
        return build.id


# ---- POST /scans/{id}/rebuild -----------------------------------------------


def test_rebuild_trigger_202_enqueues(client, db_session_factory, monkeypatch, tmp_path):
    from app.api.routes import scans as routes

    scan_id = _add_scan(db_session_factory)
    _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    enqueued = {}

    def fake_enqueue(sid, bid):
        enqueued["scan_id"] = sid
        enqueued["build_id"] = bid

    monkeypatch.setattr(routes, "enqueue_rebuild", fake_enqueue)
    r = client.post(f"/api/v1/scans/{scan_id}/rebuild")
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "queued"
    assert body["stage"] == "queued"
    assert enqueued["scan_id"] == scan_id
    assert enqueued["build_id"] == body["id"]
    with db_session_factory() as session:
        assert session.get(Build, body["id"]).scan_id == scan_id


def test_rebuild_trigger_409_not_analyzed(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, status="queued")
    r = client.post(f"/api/v1/scans/{scan_id}/rebuild")
    assert r.status_code == 409
    assert "not analyzed" in r.json()["detail"]


def test_rebuild_trigger_409_ios(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, platform="ios")
    r = client.post(f"/api/v1/scans/{scan_id}/rebuild")
    assert r.status_code == 409
    assert "Android-only" in r.json()["detail"]


def test_rebuild_trigger_409_decode_not_ready(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)  # no decode tree
    r = client.post(f"/api/v1/scans/{scan_id}/rebuild")
    assert r.status_code == 409
    assert "decode not ready" in r.json()["detail"]


def test_rebuild_trigger_reaps_stale_queued_build(
    client, db_session_factory, tmp_path, monkeypatch
):
    """A worker crash leaves a build stuck in queued forever - the trigger
    fails it as stale so the one-in-flight guard can't lock the scan out."""
    from datetime import UTC, datetime, timedelta

    from app.api.routes import scans as routes

    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)
    _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    with db_session_factory() as session:
        stale = Build(scan_id=scan_id, status="queued", stage="queued")
        stale.created_at = datetime.now(UTC) - timedelta(minutes=10)
        session.add(stale)
        session.commit()
        stale_id = stale.id
    enqueued = {}

    def fake_enqueue(sid, bid):
        enqueued["scan_id"] = sid
        enqueued["build_id"] = bid

    monkeypatch.setattr(routes, "enqueue_rebuild", fake_enqueue)
    r = client.post(f"/api/v1/scans/{scan_id}/rebuild")
    assert r.status_code == 202
    assert enqueued["build_id"] != stale_id  # a NEW build was enqueued
    with db_session_factory() as session:
        old = session.get(Build, stale_id)
        assert old.status == "failed"
        assert "stale" in old.error
        assert session.query(Build).filter_by(scan_id=scan_id, status="queued").count() == 1


def test_rebuild_trigger_409_in_flight(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)
    _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    build_id = _add_build(db_session_factory, scan_id, status="running", stage="rebuilding")

    from app.api.routes import scans as routes

    def fake_enqueue(sid, bid):
        raise AssertionError("must not enqueue while one build is running")

    monkeypatch.setattr(routes, "enqueue_rebuild", fake_enqueue)
    r = client.post(f"/api/v1/scans/{scan_id}/rebuild")
    assert r.status_code == 409
    assert f"build {build_id}" in r.json()["detail"]


def test_rebuild_trigger_500_on_enqueue_failure(client, db_session_factory, monkeypatch, tmp_path):
    from app.api.routes import scans as routes

    scan_id = _add_scan(db_session_factory)
    _make_decoded_tree(scan_id, tmp_path, monkeypatch)

    def boom(sid, bid):
        raise RuntimeError("redis down")

    monkeypatch.setattr(routes, "enqueue_rebuild", boom)
    r = client.post(f"/api/v1/scans/{scan_id}/rebuild")
    assert r.status_code == 500
    assert "redis down" in r.json()["detail"]
    # the build row exists and is marked failed, not left queued
    with db_session_factory() as session:
        builds = session.query(Build).filter_by(scan_id=scan_id).all()
        assert len(builds) == 1
        assert builds[0].status == "failed"
        assert "redis down" in builds[0].error


def test_rebuild_trigger_unknown_scan_404(client, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    assert client.post("/api/v1/scans/999999/rebuild").status_code == 404


# ---- GET /scans/{id}/builds + single ----------------------------------------


def test_builds_list_newest_first_and_edit_ids(client, db_session_factory, tmp_path):
    scan_id = _add_scan(db_session_factory)
    b1 = _add_build(db_session_factory, scan_id, artifact_name="a-resigned-test-1.apk")
    with db_session_factory() as session:
        build = session.get(Build, b1)
        build.edits_json = "[11, 12]"
        session.commit()
    _add_build(db_session_factory, scan_id, status="failed", stage="zipping",
               artifact_name=None, artifact_path=None)
    r = client.get(f"/api/v1/scans/{scan_id}/builds")
    assert r.status_code == 200
    body = r.json()
    assert [b["id"] for b in body] == [b1 + 1, b1]  # newest first
    assert body[1]["edit_ids"] == [11, 12]
    assert body[0]["status"] == "failed"
    assert body[0]["stage"] == "zipping"


def test_builds_get_single_and_404(client, db_session_factory, tmp_path):
    scan_id = _add_scan(db_session_factory)
    other_scan = _add_scan(db_session_factory)
    build_id = _add_build(db_session_factory, scan_id)
    r = client.get(f"/api/v1/scans/{scan_id}/builds/{build_id}")
    assert r.status_code == 200
    assert r.json()["id"] == build_id
    # same build id under a different scan -> 404
    assert client.get(f"/api/v1/scans/{other_scan}/builds/{build_id}").status_code == 404
    assert client.get(f"/api/v1/scans/{scan_id}/builds/999999").status_code == 404


# ---- GET /scans/{id}/builds/{bid}/download -----------------------------------


def test_download_ok_serves_artifact(client, db_session_factory, tmp_path, monkeypatch):
    from app.analysis import rebuild

    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)
    # the artifact must live under the scan's artifact dir (path guard)
    artifact = rebuild.artifact_dir(scan_id) / "app-resigned-test-1.apk"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"PK\x03\x04signed")
    build_id = _add_build(
        db_session_factory, scan_id, artifact_path=str(artifact)
    )
    r = client.get(f"/api/v1/scans/{scan_id}/builds/{build_id}/download")
    assert r.status_code == 200
    assert r.headers["content-disposition"].startswith("attachment")
    assert "app-resigned-test-1.apk" in r.headers["content-disposition"]
    assert r.headers["x-resigned-test-build"] == "true"
    assert r.content == b"PK\x03\x04signed"


def test_download_409_before_done(client, db_session_factory, tmp_path):
    scan_id = _add_scan(db_session_factory)
    build_id = _add_build(db_session_factory, scan_id, status="running", stage="signing")
    r = client.get(f"/api/v1/scans/{scan_id}/builds/{build_id}/download")
    assert r.status_code == 409
    assert "no downloadable artifact" in r.json()["detail"]


def test_download_404_missing_on_disk(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)
    # done row whose artifact file is gone (e.g. volume wiped)
    build_id = _add_build(
        db_session_factory, scan_id,
        artifact_path=str(tmp_path / "artifacts" / str(scan_id) / "ghost.apk"),
    )
    r = client.get(f"/api/v1/scans/{scan_id}/builds/{build_id}/download")
    assert r.status_code == 404
    assert "missing on disk" in r.json()["detail"]


def test_download_404_path_escapes_artifact_dir(
    client, db_session_factory, tmp_path, monkeypatch
):
    """A stale/edited artifact_path pointing outside the scan's artifact dir
    is refused - the download endpoint never streams arbitrary files."""
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)
    outside = tmp_path / "outside.apk"
    outside.write_bytes(b"PK")
    build_id = _add_build(
        db_session_factory, scan_id, artifact_path=str(outside)
    )
    r = client.get(f"/api/v1/scans/{scan_id}/builds/{build_id}/download")
    assert r.status_code == 404
    assert "escapes" in r.json()["detail"]


# ---- GET /scans/{id}/source-zip ----------------------------------------------


def test_source_zip_serves_tree_with_applied_edits(
    client, db_session_factory, tmp_path, monkeypatch
):
    """The decoded source tree streams as a zip with the newest applied edit
    overlaid - the effective source a rebuild starts from, under a top-level
    ``<stem>-source/`` folder. The on-disk decode is never mutated."""
    import io
    import zipfile

    from app.models import Edit

    scan_id = _add_scan(db_session_factory)
    root = _make_decoded_tree(scan_id, tmp_path, monkeypatch)
    (root / "smali" / "com").mkdir(parents=True)
    (root / "smali" / "com" / "Auth.smali").write_text("original smali")
    (root / "res").mkdir()  # empty dir - must survive as an entry
    with db_session_factory() as session:
        session.add(
            Edit(
                scan_id=scan_id,
                file_path="smali/com/Auth.smali",
                original_content="original smali",
                new_content="edited smali",
                unified_diff="-original smali\n+edited smali\n",
                source="manual",
                status="applied",
            )
        )
        session.commit()
    r = client.get(f"/api/v1/scans/{scan_id}/source-zip")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert r.headers["content-disposition"].startswith("attachment")
    assert "app-source.zip" in r.headers["content-disposition"]
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    assert "app-source/AndroidManifest.xml" in zf.namelist()
    assert "app-source/res/" in zf.namelist()
    assert zf.read("app-source/smali/com/Auth.smali").decode() == "edited smali"
    assert zf.read("app-source/AndroidManifest.xml").decode() == "<manifest/>"
    # the pristine decode is untouched
    assert (root / "smali" / "com" / "Auth.smali").read_text() == "original smali"


def test_source_zip_409_not_analyzed(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, status="queued")
    r = client.get(f"/api/v1/scans/{scan_id}/source-zip")
    assert r.status_code == 409
    assert "not analyzed" in r.json()["detail"]


def test_source_zip_409_ios(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, platform="ios")
    r = client.get(f"/api/v1/scans/{scan_id}/source-zip")
    assert r.status_code == 409
    assert "Android-only" in r.json()["detail"]


def test_source_zip_409_decode_not_ready(client, db_session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)  # analyzed but no decode tree
    r = client.get(f"/api/v1/scans/{scan_id}/source-zip")
    assert r.status_code == 409
    assert "decode not ready" in r.json()["detail"]


def test_source_zip_404_unknown_scan(client, tmp_path, monkeypatch):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    assert client.get("/api/v1/scans/999999/source-zip").status_code == 404

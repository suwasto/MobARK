"""M5 Phase A API tests — upload, findings GET, explain, summary, files.

LLM-backed endpoints are monkeypatched (no network, no model store); the
insights module itself has its own mocked unit tests (test_agent/).
"""
from __future__ import annotations

import io
import json
import zipfile

from app.agent.insights import InsightError
from app.analysis import tree
from app.models import Finding, Scan

# ---- helpers ----------------------------------------------------------------


def _apk_bytes(with_manifest: bool = True) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if with_manifest:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
        else:
            zf.writestr("other.txt", "not an apk")
    return buf.getvalue()


def _scan(db_session_factory, *, status="done", platform="android"):
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform=platform, status=status)
        session.add(scan)
        session.commit()
        return scan.id


def _scan_with_findings(
    db_session_factory, severities=("high", "medium", "info"), platform="android"
):
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform=platform, status="done")
        session.add(scan)
        session.commit()
        for i, sev in enumerate(severities):
            session.add(
                Finding(
                    scan_id=scan.id,
                    tool="semgrep",
                    title=f"{sev}-{i}",
                    severity=sev,
                    file_path="com/foo/F.java",
                    line_number=i + 1,
                    mastg_test_id="MASTG-TEST-0073",
                )
            )
        session.commit()
        return scan.id


def _finding_id(client, scan_id) -> int:
    return client.get(f"/api/v1/scans/{scan_id}/findings").json()[0]["id"]


def _make_android_tree(scan_id, tmp_path, monkeypatch):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    work = tmp_path / "work" / str(scan_id)
    java = work / "decompiled" / "sources" / "com" / "foo"
    java.mkdir(parents=True)
    (work / "decompiled" / "resources").mkdir(parents=True)
    (java / "AuthManager.java").write_text(
        "package com.foo;\npublic class AuthManager {\n  void f() {}\n}\n"
    )
    (work / "decompiled" / "resources" / "AndroidManifest.xml").write_text(
        "<manifest/>"
    )


def _make_ios_tree(scan_id, tmp_path, monkeypatch, with_binary=False):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    app_dir = (
        tmp_path / "work" / str(scan_id) / "bundle" / "Payload" / "Northbank.app"
    )
    app_dir.mkdir(parents=True)
    (app_dir / "Resources").mkdir()
    import plistlib

    (app_dir / "Info.plist").write_bytes(
        plistlib.dumps({"CFBundleIdentifier": "com.northbank.mobile"})
    )
    (app_dir / "Resources" / "strings.txt").write_text("hello")
    if with_binary:
        # the app executable — NUL bytes sniff as binary and get hidden
        (app_dir / "northbank").write_bytes(b"\x00\x01\x02\xcf\xfa\xed\xfe...")


# ---- upload -----------------------------------------------------------------


def test_upload_creates_scan_saves_artifact_and_enqueues(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.config
    from app.api.routes import scans as routes

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    enqueued = {}

    def fake_enqueue(scan_id):
        enqueued["scan_id"] = scan_id

    monkeypatch.setattr(routes, "enqueue_scan", fake_enqueue)

    r = client.post(
        "/api/v1/scans",
        files={"file": ("app.apk", _apk_bytes(), "application/vnd.android.package-archive")},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "queued"
    assert body["filename"] == "app.apk"
    assert body["stage"] is None
    assert enqueued["scan_id"] == body["id"]
    assert (tmp_path / "uploads" / str(body["id"]) / "app.apk").is_file()


def test_upload_rejects_bad_extension_without_phantom_row(client):
    r = client.post(
        "/api/v1/scans",
        files={"file": ("evil.exe", b"x", "application/octet-stream")},
    )
    assert r.status_code == 400
    assert "unsupported" in r.json()["detail"]
    assert client.get("/api/v1/scans").json() == []


def test_upload_rejects_non_zip_without_phantom_row(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    r = client.post(
        "/api/v1/scans",
        files={"file": ("app.apk", b"definitely not a zip", "application/octet-stream")},
    )
    assert r.status_code == 400
    assert "ZIP" in r.json()["detail"]
    assert client.get("/api/v1/scans").json() == []


def test_upload_over_size_limit_413(client, db_session_factory, monkeypatch, tmp_path):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    monkeypatch.setattr(app.config.settings, "max_upload_mb", 0)  # everything exceeds
    r = client.post(
        "/api/v1/scans",
        files={"file": ("big.apk", _apk_bytes(), "application/octet-stream")},
    )
    assert r.status_code == 413
    assert "limit" in r.json()["detail"]
    assert client.get("/api/v1/scans").json() == []


def test_upload_enqueue_failure_marks_scan_failed(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.config
    from app.api.routes import scans as routes

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)

    def boom(scan_id):
        raise RuntimeError("redis down")

    monkeypatch.setattr(routes, "enqueue_scan", boom)
    r = client.post(
        "/api/v1/scans",
        files={"file": ("app.apk", _apk_bytes(), "application/octet-stream")},
    )
    assert r.status_code == 500
    assert "enqueued" in r.json()["detail"]
    scans = client.get("/api/v1/scans").json()
    assert len(scans) == 1
    assert scans[0]["status"] == "failed"


# ---- findings ---------------------------------------------------------------


def test_findings_ordered_high_first(client, db_session_factory):
    scan_id = _scan_with_findings(
        db_session_factory, severities=("info", "high", "medium")
    )
    r = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert r.status_code == 200
    body = r.json()
    assert [f["severity"] for f in body] == ["high", "medium", "info"]
    assert body[0]["mastg_test_id"] == "MASTG-TEST-0073"


def test_findings_severity_filter(client, db_session_factory):
    scan_id = _scan_with_findings(
        db_session_factory, severities=("high", "medium", "info")
    )
    r = client.get(f"/api/v1/scans/{scan_id}/findings", params={"severity": "high"})
    assert [f["severity"] for f in r.json()] == ["high"]


def test_findings_bad_severity_400(client, db_session_factory):
    scan_id = _scan_with_findings(db_session_factory)
    r = client.get(f"/api/v1/scans/{scan_id}/findings", params={"severity": "banana"})
    assert r.status_code == 400


def test_findings_limit_and_offset(client, db_session_factory):
    scan_id = _scan_with_findings(
        db_session_factory, severities=("medium", "medium", "medium", "medium")
    )
    r = client.get(f"/api/v1/scans/{scan_id}/findings", params={"limit": 2, "offset": 1})
    titles = [f["title"] for f in r.json()]
    assert titles == ["medium-1", "medium-2"]


def test_findings_missing_scan_404(client):
    assert client.get("/api/v1/scans/999999/findings").status_code == 404


# ---- explain ----------------------------------------------------------------


def test_explain_success(client, db_session_factory, monkeypatch):
    scan_id = _scan_with_findings(db_session_factory)
    finding_id = _finding_id(client, scan_id)
    from app.api.routes import scans as routes

    def fake_explain(scan_id_, finding, regenerate=False):
        return {
            "explanation": "Stored with MODE_PRIVATE — readable on rooted devices.",
            "cached": False,
            "model": "qwen2.5:7b",
            "generated_at": "2026-08-06T00:00:00Z",
        }

    monkeypatch.setattr(routes.insights, "explain_finding", fake_explain)
    r = client.post(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explain")
    assert r.status_code == 200
    body = r.json()
    assert "MODE_PRIVATE" in body["explanation"]
    assert body["cached"] is False
    assert body["model"] == "qwen2.5:7b"


def test_explain_cached_skips_llm(client, db_session_factory):
    scan_id = _scan_with_findings(db_session_factory)
    finding_id = _finding_id(client, scan_id)
    with db_session_factory() as session:
        finding = session.get(Finding, finding_id)
        finding.explanation = "already explained"
        session.commit()
    r = client.post(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explain")
    assert r.status_code == 200
    assert r.json()["cached"] is True
    assert r.json()["explanation"] == "already explained"


def test_explain_no_model_400(client, db_session_factory, monkeypatch):
    scan_id = _scan_with_findings(db_session_factory)
    finding_id = _finding_id(client, scan_id)
    from app.api.routes import scans as routes
    from app.model.selection import NoModelConfigured

    def no_model(scan_id_, finding, regenerate=False):
        raise NoModelConfigured("no chat model configured — pick a backend + model in Settings")

    monkeypatch.setattr(routes.insights, "explain_finding", no_model)
    r = client.post(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explain")
    assert r.status_code == 400
    assert "no chat model" in r.json()["detail"]


def test_explain_upstream_failure_502(client, db_session_factory, monkeypatch):
    scan_id = _scan_with_findings(db_session_factory)
    finding_id = _finding_id(client, scan_id)
    from app.api.routes import scans as routes

    def upstream_down(scan_id_, finding, regenerate=False):
        raise InsightError("LLM call failed: connection refused")

    monkeypatch.setattr(routes.insights, "explain_finding", upstream_down)
    r = client.post(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explain")
    assert r.status_code == 502


def test_explain_not_analyzed_409(client, db_session_factory):
    scan_id = _scan_with_findings(db_session_factory)
    with db_session_factory() as session:
        session.get(Scan, scan_id).status = "running"
        session.commit()
    finding_id = _finding_id(client, scan_id)
    r = client.post(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explain")
    assert r.status_code == 409


def test_explain_regenerate_bypasses_cache(client, db_session_factory, monkeypatch):
    """regenerate=true reaches the LLM even when the finding already has a
    cached explanation — the Regenerate button is an explicit opt-in that
    spends cost; the default call stays cache-first."""
    scan_id = _scan_with_findings(db_session_factory)
    finding_id = _finding_id(client, scan_id)
    with db_session_factory() as session:
        session.get(Finding, finding_id).explanation = "already explained"
        session.commit()
    from app.api.routes import scans as routes

    captured = {}

    def fake_explain(scan_id_, finding, regenerate=False):
        captured["regenerate"] = regenerate
        return {
            "explanation": "fresh explanation",
            "cached": False,
            "model": None,
            "generated_at": "2026-08-06T00:00:00Z",
        }

    monkeypatch.setattr(routes.insights, "explain_finding", fake_explain)
    # default call: cache-first (no regenerate flag sent)
    r0 = client.post(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explain")
    assert r0.status_code == 200
    assert captured["regenerate"] is False
    # explicit regenerate=true bypasses the cache
    r = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/explain",
        params={"regenerate": "true"},
    )
    assert r.status_code == 200
    assert captured["regenerate"] is True
    assert r.json()["cached"] is False
    assert r.json()["explanation"] == "fresh explanation"


def test_explain_finding_of_another_scan_404(client, db_session_factory):
    scan_a = _scan_with_findings(db_session_factory)
    scan_b = _scan(db_session_factory)
    finding_a = _finding_id(client, scan_a)
    r = client.post(f"/api/v1/scans/{scan_b}/findings/{finding_a}/explain")
    assert r.status_code == 404


def test_explain_unknown_scan_404(client):
    assert client.post("/api/v1/scans/999999/findings/1/explain").status_code == 404


# ---- summary ----------------------------------------------------------------


def test_summary_success(client, db_session_factory, monkeypatch):
    scan_id = _scan_with_findings(db_session_factory)
    from app.api.routes import scans as routes

    def fake_summarize(scan, findings, security_score, regenerate=False):
        return {
            "summary": "Storage and network findings dominate.",
            "cached": False,
            "model": "qwen2.5:7b",
            "generated_at": "2026-08-06T00:00:00Z",
        }

    monkeypatch.setattr(routes.insights, "summarize_scan", fake_summarize)
    r = client.post(f"/api/v1/scans/{scan_id}/summary")
    assert r.status_code == 200
    assert "dominate" in r.json()["summary"]
    assert r.json()["cached"] is False


def test_summary_cached_skips_llm(client, db_session_factory):
    scan_id = _scan_with_findings(db_session_factory)
    with db_session_factory() as session:
        session.get(Scan, scan_id).ai_summary = "cached overview"
        session.commit()
    r = client.post(f"/api/v1/scans/{scan_id}/summary")
    assert r.status_code == 200
    assert r.json()["cached"] is True
    assert r.json()["summary"] == "cached overview"


def test_summary_regenerate_bypasses_cache(client, db_session_factory, monkeypatch):
    """regenerate=true reaches the LLM even when the scan already has a
    cached summary — same explicit-opt-in contract as explanations."""
    scan_id = _scan_with_findings(db_session_factory)
    with db_session_factory() as session:
        session.get(Scan, scan_id).ai_summary = "cached overview"
        session.commit()
    from app.api.routes import scans as routes

    captured = {}

    def fake_summarize(scan, findings, security_score, regenerate=False):
        captured["regenerate"] = regenerate
        return {
            "summary": "fresh overview",
            "cached": False,
            "model": None,
            "generated_at": "2026-08-06T00:00:00Z",
        }

    monkeypatch.setattr(routes.insights, "summarize_scan", fake_summarize)
    r0 = client.post(f"/api/v1/scans/{scan_id}/summary")
    assert r0.status_code == 200
    assert captured["regenerate"] is False
    r = client.post(f"/api/v1/scans/{scan_id}/summary", params={"regenerate": "true"})
    assert r.status_code == 200
    assert captured["regenerate"] is True
    assert r.json()["cached"] is False
    assert r.json()["summary"] == "fresh overview"


def test_summary_not_analyzed_409(client, db_session_factory):
    scan_id = _scan(db_session_factory, status="queued")
    r = client.post(f"/api/v1/scans/{scan_id}/summary")
    assert r.status_code == 409


def test_summary_no_model_400(client, db_session_factory, monkeypatch):
    scan_id = _scan_with_findings(db_session_factory)
    from app.api.routes import scans as routes
    from app.model.selection import NoModelConfigured

    def no_model(*args, **kwargs):
        raise NoModelConfigured("no chat model configured")

    monkeypatch.setattr(routes.insights, "summarize_scan", no_model)
    r = client.post(f"/api/v1/scans/{scan_id}/summary")
    assert r.status_code == 400


def test_summary_upstream_failure_502(client, db_session_factory, monkeypatch):
    scan_id = _scan_with_findings(db_session_factory)
    from app.api.routes import scans as routes

    def upstream_down(*args, **kwargs):
        raise InsightError("LLM call failed")

    monkeypatch.setattr(routes.insights, "summarize_scan", upstream_down)
    r = client.post(f"/api/v1/scans/{scan_id}/summary")
    assert r.status_code == 502


# ---- file tree + content ----------------------------------------------------


def test_files_android_roots_and_nesting(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _scan_with_findings(db_session_factory)
    _make_android_tree(scan_id, tmp_path, monkeypatch)
    r = client.get(f"/api/v1/scans/{scan_id}/files")
    assert r.status_code == 200
    body = r.json()
    assert body["platform"] == "android"
    assert [root["name"] for root in body["roots"]] == ["sources", "resources"]
    sources = body["roots"][0]
    assert sources["truncated"] is False
    # sources/com/foo/AuthManager.java reachable
    com = sources["tree"][0]
    assert com["type"] == "dir" and com["name"] == "com"
    foo = com["children"][0]
    assert [n["name"] for n in foo["children"]] == ["AuthManager.java"]


def test_files_content_java(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _scan_with_findings(db_session_factory)
    _make_android_tree(scan_id, tmp_path, monkeypatch)
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "sources/com/foo/AuthManager.java"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["language"] == "java"
    assert "public class AuthManager" in body["content"]
    assert body["truncated"] is False


def test_files_content_resource_xml(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _scan_with_findings(db_session_factory)
    _make_android_tree(scan_id, tmp_path, monkeypatch)
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "resources/AndroidManifest.xml"},
    )
    assert r.status_code == 200
    assert r.json()["language"] == "xml"


def test_files_content_traversal_escapes_400(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _scan_with_findings(db_session_factory)
    _make_android_tree(scan_id, tmp_path, monkeypatch)
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "sources/../../secret"},
    )
    assert r.status_code == 400
    assert "escapes" in r.json()["detail"]


def test_files_content_unknown_root_400(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _scan_with_findings(db_session_factory)
    _make_android_tree(scan_id, tmp_path, monkeypatch)
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "nope/x.java"},
    )
    assert r.status_code == 400


def test_files_content_missing_file_404(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _scan_with_findings(db_session_factory)
    _make_android_tree(scan_id, tmp_path, monkeypatch)
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "sources/com/foo/Missing.java"},
    )
    assert r.status_code == 404


def test_files_not_analyzed_409(client, db_session_factory):
    scan_id = _scan(db_session_factory, status="queued")
    assert client.get(f"/api/v1/scans/{scan_id}/files").status_code == 409


def test_files_ios_bundle_root(client, db_session_factory, monkeypatch, tmp_path):
    import app.db

    scan_id = _scan_with_findings(db_session_factory, platform="ios")
    _make_ios_tree(scan_id, tmp_path, monkeypatch)
    # tree.py opens its own session for the analysis docs — point it at the
    # scratch DB (same pattern as agent/tools.py).
    monkeypatch.setattr(app.db, "SessionLocal", db_session_factory)
    r = client.get(f"/api/v1/scans/{scan_id}/files")
    assert r.status_code == 200
    # no binary-level (lief/symbols) findings -> no synthetic analysis root
    assert [root["name"] for root in r.json()["roots"]] == ["Northbank.app"]
    # plist content decodes to JSON text
    r2 = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "Northbank.app/Info.plist"},
    )
    assert r2.status_code == 200
    assert r2.json()["language"] == "json"
    assert "com.northbank.mobile" in r2.json()["content"]


def _make_ios_analysis_findings(db_session_factory, scan_id):
    import json

    with db_session_factory() as session:
        findings = [
            Finding(
                scan_id=scan_id,
                tool="lief",
                title="Binary slices: arm64_64",
                severity="info",
                detail=json.dumps({"architectures": ["arm64_64"]}),
            ),
            Finding(
                scan_id=scan_id,
                tool="lief",
                title="Position-independent executable (PIE) disabled",
                severity="high",
                category="MASVS-CODE-4",
                detail=json.dumps({"arch": "CPU_TYPE.ARM64_64"}),
            ),
            Finding(
                scan_id=scan_id,
                tool="lief",
                title="ARC enabled (ObjC runtime symbols present)",
                severity="info",
                detail=json.dumps({"evidence": ["_objc_release"]}),
            ),
            Finding(
                scan_id=scan_id,
                tool="lief",
                title="Linked dylibs (2)",
                severity="info",
                detail=json.dumps(
                    {
                        "count": 2,
                        "dylibs": [
                            "/usr/lib/libSystem.B.dylib",
                            "/usr/lib/libobjc.A.dylib",
                        ],
                    }
                ),
            ),
            Finding(
                scan_id=scan_id,
                tool="lief",
                title="Exported symbols (3)",
                severity="info",
                detail=json.dumps(
                    {"count": 3, "sample": ["_objc_msgSend", "_malloc", "_free"]}
                ),
            ),
            Finding(
                scan_id=scan_id,
                tool="lief",
                title="Entitlements granted (2)",
                severity="info",
                category="MASVS-PLATFORM-1",
                detail=json.dumps(
                    {
                        "entitlements": {
                            "get-task-allow": True,
                            "application-identifier": "com.northbank",
                        }
                    }
                ),
            ),
            Finding(
                scan_id=scan_id,
                tool="symbols",
                title="Legacy SHA-1 hashing imported (CC_SHA1)",
                severity="medium",
                category="MASVS-CRYPTO-2",
                detail=json.dumps(
                    {"symbol": "_CC_SHA1", "note": "SHA-1 is deprecated for security uses."}
                ),
            ),
        ]
        session.add_all(findings)
        session.commit()


def test_files_ios_curates_binaries(client, db_session_factory, monkeypatch, tmp_path):
    import app.db

    scan_id = _scan_with_findings(db_session_factory, platform="ios")
    _make_ios_tree(scan_id, tmp_path, monkeypatch, with_binary=True)
    monkeypatch.setattr(app.db, "SessionLocal", db_session_factory)
    r = client.get(f"/api/v1/scans/{scan_id}/files")
    assert r.status_code == 200
    app_root = next(
        root for root in r.json()["roots"] if root["name"] == "Northbank.app"
    )
    # the Mach-O executable is hidden, counted, and listed under the
    # collapsed "Binary (Mach-O)" entry instead of rendered as a file row
    assert app_root["filtered_binaries"] == 1
    binary_dir = next(
        n for n in app_root["tree"] if n["name"].startswith("Binary (Mach-O)")
    )
    assert binary_dir["type"] == "dir"
    assert [c["path"] for c in binary_dir["children"]] == ["northbank"]
    assert binary_dir["children"][0]["binary"] is True

    def top_level_paths(nodes):
        return [n["path"] for n in nodes]

    assert "northbank" not in top_level_paths(app_root["tree"])  # not a plain row
    assert "Info.plist" in top_level_paths(app_root["tree"])
    assert "Resources" in top_level_paths(app_root["tree"])


def test_files_ios_analysis_root_and_content(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.db

    scan_id = _scan_with_findings(db_session_factory, platform="ios")
    _make_ios_tree(scan_id, tmp_path, monkeypatch)
    _make_ios_analysis_findings(db_session_factory, scan_id)
    # tree.py opens its own session (app.db.SessionLocal) for the analysis
    # docs — point it at the scratch DB, same pattern as agent/tools.py.
    monkeypatch.setattr(app.db, "SessionLocal", db_session_factory)

    r = client.get(f"/api/v1/scans/{scan_id}/files")
    assert r.status_code == 200
    assert [root["name"] for root in r.json()["roots"]] == [
        "analysis",
        "Northbank.app",
    ]
    analysis = r.json()["roots"][0]
    assert [n["name"] for n in analysis["tree"]] == [
        "macho-profile.md",
        "entitlements.plist",
        "exported-symbols.txt",
        "insecure-imports.txt",
    ]

    md = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "analysis/macho-profile.md"},
    )
    assert md.status_code == 200
    assert md.json()["language"] == "markdown"
    assert "arm64_64" in md.json()["content"]
    assert "libSystem.B.dylib" in md.json()["content"]
    assert "PIE: disabled (finding present)" in md.json()["content"]
    assert "ARC: enabled (finding present)" in md.json()["content"]

    ents = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "analysis/entitlements.plist"},
    )
    assert ents.status_code == 200
    assert ents.json()["language"] == "json"
    assert "get-task-allow" in ents.json()["content"]

    syms = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "analysis/exported-symbols.txt"},
    )
    assert syms.status_code == 200
    assert "_objc_msgSend" in syms.json()["content"]

    imports = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "analysis/insecure-imports.txt"},
    )
    assert imports.status_code == 200
    assert "CC_SHA1" in imports.json()["content"]

    # unknown analysis file -> 404; unknown root stays 400
    assert (
        client.get(
            f"/api/v1/scans/{scan_id}/files/content",
            params={"path": "analysis/nope.txt"},
        ).status_code
        == 404
    )
    assert (
        client.get(
            f"/api/v1/scans/{scan_id}/files/content",
            params={"path": "other/x.txt"},
        ).status_code
        == 400
    )


def test_files_tree_caps_set_truncated(db_session_factory, monkeypatch, tmp_path):
    scan_id = _scan_with_findings(db_session_factory)
    _make_android_tree(scan_id, tmp_path, monkeypatch)
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        roots = tree.list_tree(scan, max_depth=1, max_nodes=2)
    assert len(roots) == 2
    assert roots[0].truncated is True


def test_files_tree_unbounded_by_default(db_session_factory, monkeypatch, tmp_path):
    """The per-root node cap was removed (owner decision, Aug 10): a tree
    with thousands of nodes serves in FULL with default caps — the old 1500
    cap truncated real trees mid-branch, hiding app code behind library
    subtrees. An explicit ``max_nodes`` still caps (the test above)."""
    import app.config

    scan_id = _scan_with_findings(db_session_factory)
    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    work = tmp_path / "work" / str(scan_id)
    java = work / "decompiled" / "sources" / "com" / "foo"
    java.mkdir(parents=True)
    for i in range(2000):
        (java / f"F{i:04d}.java").write_text("class F {}\n")
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        roots = tree.list_tree(scan)
    sources = next(r for r in roots if r.name == "sources")
    assert sources.truncated is False
    # com + foo dirs + all 2000 files — nothing cut off
    assert sources.total_nodes == 2002


def test_tree_cache_serves_second_call_without_walk(
    db_session_factory, monkeypatch, tmp_path
):
    """The tree is computed once per scan; a second call is served from the
    module cache without re-walking the filesystem (owner, Aug 10 — repeated
    Decompiler opens shouldn't re-walk)."""
    scan_id = _scan_with_findings(db_session_factory)
    _make_android_tree(scan_id, tmp_path, monkeypatch)
    calls = {"n": 0}
    real_walk = tree._walk

    def counting_walk(*args, **kwargs):
        calls["n"] += 1
        return real_walk(*args, **kwargs)

    monkeypatch.setattr(tree, "_walk", counting_walk)
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        r1 = tree.cached_list_tree(scan)
    assert calls["n"] > 0  # the first call computed (walks recurse per dir)
    first = calls["n"]
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        r2 = tree.cached_list_tree(scan)
    assert calls["n"] == first  # the second call added ZERO walks — cache-served
    assert [r.name for r in r1] == [r.name for r in r2]
    assert r1[0].total_nodes == r2[0].total_nodes


def test_tree_cache_disk_survives_and_invalidates(
    db_session_factory, monkeypatch, tmp_path
):
    """The persisted tree_cache.json serves across processes (module cache
    cleared), and a stale identity file recomputes instead of serving
    garbage."""
    scan_id = _scan_with_findings(db_session_factory)
    _make_android_tree(scan_id, tmp_path, monkeypatch)
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        tree.cached_list_tree(scan)
    cache_path = tree.tree_cache_path(scan_id)
    assert cache_path.is_file()

    # Module cache cleared -> the disk file is the only source.
    tree._TREE_CACHE.clear()
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        roots = tree.cached_list_tree(scan)
    assert [r.name for r in roots] == ["sources", "resources"]

    # A stale identity (e.g. a pre-decode capture) must recompute, not serve.
    data = json.loads(cache_path.read_text())
    data["identity"] = "stale|identity"
    cache_path.write_text(json.dumps(data))
    tree._TREE_CACHE.clear()
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        roots = tree.cached_list_tree(scan)
    assert [r.name for r in roots] == ["sources", "resources"]


# ---- risk backfill ----------------------------------------------------------


def test_get_scan_backfills_risk_score_for_legacy(client, db_session_factory):
    scan_id = _scan_with_findings(db_session_factory, severities=("high", "medium"))
    r = client.get(f"/api/v1/scans/{scan_id}")
    assert r.status_code == 200
    # CVSS 4.0 max aggregation (owner decision, Aug 7): worst finding is
    # high -> CVSS 8.0 -> risk round(10*8.0) = 80 (no critical band, Aug 8)
    assert r.json()["risk_score"] == 80
    # public-facing complement: higher is better (owner decision, Aug 7)
    assert r.json()["security_score"] == 20


def test_list_scans_exposes_security_score(client, db_session_factory):
    scan_id = _scan_with_findings(db_session_factory, severities=("high",))
    # Backfill (like the detail endpoint does for legacy scans), then verify
    # the list read path derives security_score from the stored risk via the
    # Scan.security_score property.
    assert client.get(f"/api/v1/scans/{scan_id}").status_code == 200
    r = client.get("/api/v1/scans")
    assert r.status_code == 200
    scan = next(s for s in r.json() if s["id"] == scan_id)
    # high only -> risk 80 -> security 20 (CVSS 4.0, worst finding)
    assert scan["risk_score"] == 80
    assert scan["security_score"] == 20


# ---- suppression (M5 Aug 8: per-finding false-positive suppression) ---------


def test_suppress_hides_finding_and_recomputes_risk(client, db_session_factory):
    # high + low -> risk 80; suppressing the high leaves only low -> risk 20.
    scan_id = _scan_with_findings(db_session_factory, severities=("high", "low"))
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    assert [f["severity"] for f in findings] == ["high", "low"]
    high_id = findings[0]["id"]

    r = client.post(f"/api/v1/scans/{scan_id}/findings/{high_id}/suppress")
    assert r.status_code == 200
    body = r.json()
    assert body["suppressed"] is True
    assert body["suppressed_at"] is not None

    # hidden from the default list, visible with the review toggle
    assert [f["id"] for f in client.get(f"/api/v1/scans/{scan_id}/findings").json()] == [
        findings[1]["id"]
    ]
    visible = client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"include_suppressed": "true"}
    ).json()
    assert {f["id"] for f in visible} == {findings[0]["id"], findings[1]["id"]}

    # risk recomputed on the scan (suppressed findings don't drive posture)
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["risk_score"] == 20
    assert scan["security_score"] == 80


def test_unsuppress_restores_finding_and_risk(client, db_session_factory):
    scan_id = _scan_with_findings(db_session_factory, severities=("high", "low"))
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    high_id = findings[0]["id"]
    client.post(f"/api/v1/scans/{scan_id}/findings/{high_id}/suppress")
    assert client.get(f"/api/v1/scans/{scan_id}").json()["risk_score"] == 20

    r = client.post(f"/api/v1/scans/{scan_id}/findings/{high_id}/unsuppress")
    assert r.status_code == 200
    body = r.json()
    assert body["suppressed"] is False
    assert body["suppressed_at"] is None

    assert [f["severity"] for f in client.get(f"/api/v1/scans/{scan_id}/findings").json()] == [
        "high",
        "low",
    ]
    assert client.get(f"/api/v1/scans/{scan_id}").json()["risk_score"] == 80


def test_suppression_invalidates_cached_ai_summary(client, db_session_factory):
    """A cached overview summary must not survive a suppress/restore toggle —
    it may cite the finding being reviewed (Aug 8 follow-up)."""
    scan_id = _scan_with_findings(db_session_factory, severities=("high", "low"))
    with db_session_factory() as session:
        session.get(Scan, scan_id).ai_summary = "cached overview"
        session.commit()
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    client.post(f"/api/v1/scans/{scan_id}/findings/{findings[0]['id']}/suppress")
    with db_session_factory() as session:
        assert session.get(Scan, scan_id).ai_summary is None


def test_suppress_is_idempotent(client, db_session_factory):
    scan_id = _scan_with_findings(db_session_factory, severities=("high",))
    finding_id = _finding_id(client, scan_id)
    r1 = client.post(f"/api/v1/scans/{scan_id}/findings/{finding_id}/suppress")
    r2 = client.post(f"/api/v1/scans/{scan_id}/findings/{finding_id}/suppress")
    assert r1.json()["suppressed_at"] == r2.json()["suppressed_at"]


def test_suppress_unknown_finding_404(client, db_session_factory):
    scan_id = _scan_with_findings(db_session_factory)
    assert client.post(f"/api/v1/scans/{scan_id}/findings/999999/suppress").status_code == 404


def test_suppress_requires_analyzed_409(client, db_session_factory):
    scan_id = _scan_with_findings(db_session_factory)
    with db_session_factory() as session:
        session.get(Scan, scan_id).status = "running"
        session.commit()
    finding_id = _finding_id(client, scan_id)
    assert (
        client.post(f"/api/v1/scans/{scan_id}/findings/{finding_id}/suppress").status_code
        == 409
    )


def test_summary_excludes_suppressed_findings(client, db_session_factory, monkeypatch):
    """The AI summary counts/top list must not include false positives."""
    from app.api.routes import scans as routes

    captured = {}

    def fake_summarize(scan, findings, security_score, regenerate=False):
        # Read scalar attributes while the session is still open.
        captured["severities"] = sorted(f.severity for f in findings)
        return {
            "summary": "ok",
            "cached": False,
            "model": None,
            "generated_at": "2026-08-06T00:00:00Z",
        }

    monkeypatch.setattr(routes.insights, "summarize_scan", fake_summarize)
    scan_id = _scan_with_findings(db_session_factory, severities=("high", "low"))
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    client.post(f"/api/v1/scans/{scan_id}/findings/{findings[0]['id']}/suppress")

    r = client.post(f"/api/v1/scans/{scan_id}/summary")
    assert r.status_code == 200
    assert captured["severities"] == ["low"]

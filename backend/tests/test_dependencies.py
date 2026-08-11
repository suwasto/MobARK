"""Dependencies tab - inventory unit tests + API surface.

The inventory is derived on demand from scan output (jadx sources tree, the
APK zip, the persisted LIEF profile, Info.plist) - no new persistence. Known-
CVE research is deliberately the agent's M7 web-research use case, so these
tests cover the local inventory only.
"""
from __future__ import annotations

import io
import json
import plistlib
import zipfile

from app.analysis import dependencies
from app.models import Finding, Scan

# ---- group key -----------------------------------------------------------------


def test_group_key_known_library_wins_longest_prefix():
    # com/google/android/gms groups under its known label key, not com/google
    assert dependencies._group_key("com/google/android/gms/internal") == (
        "com.google.android.gms"
    )
    assert dependencies._group_key("com/google/android/gms") == "com.google.android.gms"


def test_group_key_generic_tld_second_segment():
    assert dependencies._group_key("com/foo/bar") == "com.foo"
    assert dependencies._group_key("org/apache/commons") == "org.apache"


def test_group_key_top_level_library_is_own_group():
    assert dependencies._group_key("okhttp3/internal") == "okhttp3"
    assert dependencies._group_key("retrofit2") == "retrofit2"
    assert dependencies._group_key("io/reactivex") == "io.reactivex"


def test_group_key_jdk_namespaces_are_noise():
    assert dependencies._group_key("java/lang") is None
    assert dependencies._group_key("javax/crypto") is None
    assert dependencies._group_key("sun/misc") is None


def test_group_key_androidx():
    assert dependencies._group_key("androidx/appcompat/app") == "androidx"


def test_group_key_support_library_is_not_the_framework():
    # android/support/... is the pre-AndroidX Support Library - its own group
    # (labelled), never the ambiguous bare "android" bucket.
    assert dependencies._group_key("android/support/v4/content") == "android.support"
    assert dependencies._group_key("android/support/annotation") == "android.support"


# ---- Android inventory -----------------------------------------------------------


def _make_android_scan(
    tmp_path, monkeypatch, db_session_factory, *, findings=(), apk_entries=()
):
    """A done Android scan with a jadx tree + optional APK + findings."""
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    with db_session_factory() as db:
        scan = Scan(filename="app.apk", platform="android", status="done")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        # uploads/<id>/app.apk
        upload_dir = tmp_path / "uploads" / str(scan_id)
        upload_dir.mkdir(parents=True)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in apk_entries:
                zf.writestr(name, data)
        (upload_dir / "app.apk").write_bytes(buf.getvalue())
        scan.storage_path = str(upload_dir)
        db.commit()
        for tool, title, severity, file_path in findings:
            db.add(
                Finding(
                    scan_id=scan_id,
                    tool=tool,
                    title=title,
                    severity=severity,
                    file_path=file_path,
                )
            )
        db.commit()
        return db.get(Scan, scan_id)


def _make_android_tree(scan_id, tmp_path, manifest="<manifest package=\"com.foo\"/>", files=()):
    work = tmp_path / "work" / str(scan_id)
    res = work / "decompiled" / "resources"
    res.mkdir(parents=True)
    (res / "AndroidManifest.xml").write_text(manifest)
    # a done Android scan always has a sources tree (even if empty here) - the
    # inventory cache gates on its presence (a vanished tree = cache miss)
    (work / "decompiled" / "sources").mkdir(parents=True, exist_ok=True)
    for rel in files:
        p = work / "decompiled" / "sources" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("class X {}\n")


def _findings_for(scan_id, db_session_factory):
    with db_session_factory() as session:
        return list(session.query(Finding).filter(Finding.scan_id == scan_id).all())


def test_android_inventory_packages_labels_counts_and_natives(
    tmp_path, monkeypatch, db_session_factory
):
    scan = _make_android_scan(
        tmp_path,
        monkeypatch,
        db_session_factory,
        findings=[
            ("semgrep", "gms bad", "high", "com/google/android/gms/internal/zzgf.java"),
            ("semgrep", "gms meh", "medium", "com/google/android/gms/internal/zzhe.java"),
            ("semgrep", "okhttp bad", "high", "okhttp3/internal/http/Call.java"),
            ("semgrep", "app code", "high", "com/foo/LoginActivity.java"),
            ("androguard", "manifest", "info", "AndroidManifest.xml"),
        ],
        apk_entries=[
            ("lib/arm64-v8a/libfoo.so", b""),
            ("lib/armeabi-v7a/libfoo.so", b""),
            ("lib/arm64-v8a/libflutter.so", b""),
            ("assets/flutter_assets/AssetManifest.bin", b""),
            ("AndroidManifest.xml", b""),
        ],
    )
    _make_android_tree(
        scan.id,
        tmp_path,
        files=[
            "com/foo/LoginActivity.java",  # the app itself - excluded
            "com/google/android/gms/internal/zzgf.java",
            "com/google/android/gms/internal/zzhe.java",
            "okhttp3/internal/http/Call.java",
            "java/lang/String.java",  # noise - excluded
        ],
    )
    data = dependencies.inventory(scan, _findings_for(scan.id, db_session_factory))
    assert data["platform"] == "android"
    assert data["app"]["package"] == "com.foo"
    assert data["runtime_markers"] == ["Flutter"]
    deps = {d["name"]: d for d in data["dependencies"]}

    # Google Play services: labelled, file count + both findings tallied
    gms = deps["com.google.android.gms"]
    assert gms["label"] == "Google Play services"
    assert gms["kind"] == "package"
    assert gms["file_count"] == 2
    assert gms["finding_count"] == 2
    assert gms["high_count"] == 1
    assert gms["medium_count"] == 1

    # OkHttp top-level lib
    ok = deps["okhttp3"]
    assert ok["label"] == "OkHttp"
    assert ok["finding_count"] == 1
    assert ok["high_count"] == 1

    # the app's own package + JDK never appear
    assert "com.foo" not in deps
    assert "java" not in deps

    # native libs: libfoo.so in two ABIs; flutter .so is not listed as a
    # standalone native lib here because it is only under lib/ - it IS listed
    natives = {d["name"] for d in data["dependencies"] if d["kind"] == "native"}
    assert "libfoo.so" in natives
    libfoo = next(d for d in data["dependencies"] if d["name"] == "libfoo.so")
    assert libfoo["abis"] == ["arm64-v8a", "armeabi-v7a"]


def test_android_inventory_empty_tree_and_missing_apk_never_crashes(
    tmp_path, monkeypatch, db_session_factory
):
    scan = _make_android_scan(tmp_path, monkeypatch, db_session_factory)
    data = dependencies.inventory(scan, _findings_for(scan.id, db_session_factory))
    assert data["platform"] == "android"
    assert data["dependencies"] == []
    # no manifest on disk -> no app metadata at all
    assert data["app"] == {}


def test_android_sdk_metadata_from_manifest(tmp_path, monkeypatch, db_session_factory):
    scan = _make_android_scan(tmp_path, monkeypatch, db_session_factory)
    _make_android_tree(
        scan.id,
        tmp_path,
        manifest=(
            '<manifest package="com.foo" xmlns:android='
            '"http://schemas.android.com/apk/res/android">'
            '<uses-sdk android:minSdkVersion="21" '
            'android:targetSdkVersion="33"/></manifest>'
        ),
    )
    data = dependencies.inventory(scan, _findings_for(scan.id, db_session_factory))
    assert data["app"]["package"] == "com.foo"
    assert data["app"]["min_sdk"] == 21
    assert data["app"]["target_sdk"] == 33


# ---- iOS inventory ----------------------------------------------------------------


def _make_ios_scan(
    tmp_path,
    monkeypatch,
    db_session_factory,
    *,
    dylibs=(),
    frameworks=(),
    bundle_id=None,
):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    with db_session_factory() as db:
        scan = Scan(filename="app.ipa", platform="ios", status="done")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        app_dir = tmp_path / "work" / str(scan_id) / "bundle" / "Payload" / "Northbank.app"
        app_dir.mkdir(parents=True)
        (app_dir / "Info.plist").write_bytes(
            plistlib.dumps(
                {
                    "CFBundleIdentifier": bundle_id or "com.northbank.mobile",
                    "CFBundleShortVersionString": "1.4.2",
                }
            )
        )
        fw_dir = app_dir / "Frameworks"
        if frameworks:
            fw_dir.mkdir()
            for fw in frameworks:
                (fw_dir / f"{fw}.framework").mkdir()
        if dylibs:
            db.add(
                Finding(
                    scan_id=scan_id,
                    tool="lief",
                    title=f"Linked dylibs ({len(dylibs)})",
                    severity="info",
                    detail=json.dumps({"count": len(dylibs), "dylibs": list(dylibs)}),
                )
            )
            db.commit()
        return db.get(Scan, scan_id)


def test_ios_inventory_dylibs_frameworks_and_plist(
    tmp_path, monkeypatch, db_session_factory
):
    scan = _make_ios_scan(
        tmp_path,
        monkeypatch,
        db_session_factory,
        dylibs=[
            "/usr/lib/libSystem.B.dylib",
            "/usr/lib/libobjc.A.dylib",
            "@rpath/libswiftCore.dylib",
            "@rpath/Alamofire.framework/Alamofire",
        ],
        frameworks=["Alamofire", "SQLCipher"],
        bundle_id="com.northbank.mobile",
    )
    data = dependencies.inventory(scan, _findings_for(scan.id, db_session_factory))
    assert data["platform"] == "ios"
    assert data["app"]["bundle_id"] == "com.northbank.mobile"
    assert data["app"]["version"] == "1.4.2"

    deps = {d["name"]: d for d in data["dependencies"]}
    # Apple system libs + Swift runtime are system; @rpath frameworks aren't
    assert deps["/usr/lib/libSystem.B.dylib"]["system"] is True
    assert deps["@rpath/libswiftCore.dylib"]["system"] is True
    assert deps["@rpath/Alamofire.framework/Alamofire"]["system"] is False
    assert deps["Alamofire"]["kind"] == "framework"
    assert deps["SQLCipher"]["kind"] == "framework"


def test_ios_inventory_without_profile_is_empty(tmp_path, monkeypatch, db_session_factory):
    scan = _make_ios_scan(tmp_path, monkeypatch, db_session_factory)
    data = dependencies.inventory(scan, _findings_for(scan.id, db_session_factory))
    assert data["dependencies"] == []
    assert data["app"]["bundle_id"] == "com.northbank.mobile"


# ---- inventory cache -------------------------------------------------------------


def test_cached_inventory_serves_second_call_without_recompute(
    tmp_path, monkeypatch, db_session_factory
):
    """The walk+APK read runs once per scan; a second call is served from the
    cache with zero recompute (the tree/smali-mapping cache pattern)."""
    scan = _make_android_scan(
        tmp_path, monkeypatch, db_session_factory, apk_entries=[("lib/arm64-v8a/libx.so", b"")]
    )
    _make_android_tree(
        scan.id, tmp_path, files=["com/google/android/gms/internal/A.java", "okhttp3/B.java"]
    )
    findings = _findings_for(scan.id, db_session_factory)

    calls = {"n": 0}
    real_inventory = dependencies.inventory

    def counting_inventory(scan_, findings_):
        calls["n"] += 1
        return real_inventory(scan_, findings_)

    monkeypatch.setattr(dependencies, "inventory", counting_inventory)

    r1 = dependencies.cached_inventory(scan, findings)
    assert r1 is None  # cold
    data = dependencies.inventory(scan, findings)
    dependencies.store_inventory(scan, findings, data)
    assert calls["n"] == 1

    r2 = dependencies.cached_inventory(scan, findings)
    assert r2 == data  # served from cache, no recompute
    assert calls["n"] == 1
    assert dependencies.cache_path_for(scan.id).is_file()


def test_cached_inventory_invalidated_by_suppression(
    tmp_path, monkeypatch, db_session_factory
):
    """Suppression changes the (non-suppressed) findings set -> identity flips
    -> the cache misses instead of serving stale counts."""
    scan = _make_android_scan(
        tmp_path,
        monkeypatch,
        db_session_factory,
        findings=[("semgrep", "hit", "high", "okhttp3/A.java")],
    )
    _make_android_tree(scan.id, tmp_path, files=["okhttp3/A.java"])
    findings = _findings_for(scan.id, db_session_factory)

    data = dependencies.inventory(scan, findings)
    dependencies.store_inventory(scan, findings, data)
    assert dependencies.cached_inventory(scan, findings) == data

    # suppress the only finding -> the non-suppressed set (what the route
    # passes) is now empty -> identity flips -> cache miss
    with db_session_factory() as session:
        f = session.query(Finding).filter(Finding.scan_id == scan.id).first()
        f.suppressed = True
        session.commit()
    findings2 = [
        f for f in _findings_for(scan.id, db_session_factory) if not f.suppressed
    ]
    assert len(findings2) == 0
    assert dependencies.cached_inventory(scan, findings2) is None  # miss -> recompute


def test_cached_inventory_torn_file_recomputes(tmp_path, monkeypatch, db_session_factory):
    scan = _make_android_scan(tmp_path, monkeypatch, db_session_factory)
    _make_android_tree(scan.id, tmp_path)
    cache_path = dependencies.cache_path_for(scan.id)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("{ not valid json", encoding="utf-8")
    assert dependencies.cached_inventory(scan, _findings_for(scan.id, db_session_factory)) is None


def test_cached_inventory_stale_identity_recomputes(
    tmp_path, monkeypatch, db_session_factory
):
    """A persisted file captured under a different identity (e.g. before a
    suppression toggle) recomputes instead of serving garbage."""
    scan = _make_android_scan(tmp_path, monkeypatch, db_session_factory)
    _make_android_tree(scan.id, tmp_path)
    findings = _findings_for(scan.id, db_session_factory)
    data = dependencies.inventory(scan, findings)
    dependencies.store_inventory(scan, findings, data)
    cache_path = dependencies.cache_path_for(scan.id)
    assert cache_path.is_file()
    # tamper with the stored identity
    raw = json.loads(cache_path.read_text())
    raw["identity"] = "stale|identity"
    cache_path.write_text(json.dumps(raw))
    # Clear the module cache first - the in-memory entry (stored under the
    # ORIGINAL identity) would otherwise shadow the tampered file.
    dependencies._DEPENDENCIES_CACHE.clear()
    assert dependencies.cached_inventory(scan, findings) is None


def test_cached_inventory_disk_serves_across_processes(
    tmp_path, monkeypatch, db_session_factory
):
    """The persisted file serves a fresh process (module cache cleared) with
    no recompute - the cross-restart win."""
    scan = _make_android_scan(tmp_path, monkeypatch, db_session_factory)
    _make_android_tree(scan.id, tmp_path)
    findings = _findings_for(scan.id, db_session_factory)
    data = dependencies.inventory(scan, findings)
    dependencies.store_inventory(scan, findings, data)
    assert dependencies.cache_path_for(scan.id).is_file()

    dependencies._DEPENDENCIES_CACHE.clear()
    calls = {"n": 0}
    real_inventory = dependencies.inventory

    def counting_inventory(scan_, findings_):
        calls["n"] += 1
        return real_inventory(scan_, findings_)

    monkeypatch.setattr(dependencies, "inventory", counting_inventory)
    served = dependencies.cached_inventory(scan, findings)
    assert served == data
    assert calls["n"] == 0  # served from the disk file


# ---- API surface -----------------------------------------------------------------


def _scan_row(db_session_factory, *, platform="android", status="done"):
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform=platform, status=status)
        session.add(scan)
        session.commit()
        return scan.id


def test_dependencies_endpoint_android(client, db_session_factory, monkeypatch, tmp_path):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _scan_row(db_session_factory)
    _make_android_tree(scan_id, tmp_path)
    with db_session_factory() as session:
        session.add(
            Finding(
                scan_id=scan_id,
                tool="semgrep",
                title="lib hit",
                severity="high",
                file_path="okhttp3/RealCall.java",
            )
        )
        session.commit()

    r = client.get(f"/api/v1/scans/{scan_id}/dependencies")
    assert r.status_code == 200
    body = r.json()
    assert body["platform"] == "android"
    assert body["total"] == 1
    dep = body["dependencies"][0]
    assert dep["name"] == "okhttp3"
    assert dep["label"] == "OkHttp"
    assert dep["kind"] == "package"
    assert dep["finding_count"] == 1
    assert dep["high_count"] == 1
    assert body["generated_at"] is not None


def test_dependencies_endpoint_ios(client, db_session_factory, monkeypatch, tmp_path):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _scan_row(db_session_factory, platform="ios")
    app_dir = tmp_path / "work" / str(scan_id) / "bundle" / "Payload" / "N.app"
    app_dir.mkdir(parents=True)
    (app_dir / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.n"}))
    with db_session_factory() as session:
        session.add(
            Finding(
                scan_id=scan_id,
                tool="lief",
                title="Linked dylibs (1)",
                severity="info",
                detail=json.dumps(
                    {"count": 1, "dylibs": ["/usr/lib/libSystem.B.dylib"]}
                ),
            )
        )
        session.commit()

    r = client.get(f"/api/v1/scans/{scan_id}/dependencies")
    assert r.status_code == 200
    body = r.json()
    assert body["platform"] == "ios"
    assert body["dependencies"][0]["name"] == "/usr/lib/libSystem.B.dylib"
    assert body["dependencies"][0]["system"] is True


def test_dependencies_endpoint_caches_across_calls(
    client, db_session_factory, monkeypatch, tmp_path
):
    """The route computes the inventory once and cache-serves the second GET
    (the walk + APK read only happens on the first - the route calls
    ``dependencies.inventory`` through the module, so counting its calls is
    the computes counter)."""
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _scan_row(db_session_factory)
    _make_android_tree(scan_id, tmp_path)
    calls = {"n": 0}
    real_inventory = dependencies.inventory

    def counting_inventory(scan_, findings_):
        calls["n"] += 1
        return real_inventory(scan_, findings_)

    monkeypatch.setattr(dependencies, "inventory", counting_inventory)

    r1 = client.get(f"/api/v1/scans/{scan_id}/dependencies")
    assert r1.status_code == 200
    assert calls["n"] == 1
    r2 = client.get(f"/api/v1/scans/{scan_id}/dependencies")
    assert r2.status_code == 200
    # generated_at is a response-serialization timestamp (set fresh per
    # response even on a cache hit) - the inventory payload itself is equal.
    def without_ts(body):
        body.pop("generated_at", None)
        return body

    assert without_ts(r2.json()) == without_ts(r1.json())
    assert calls["n"] == 1  # second call was cache-served


def test_dependencies_endpoint_suppressed_excluded(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _scan_row(db_session_factory)
    _make_android_tree(scan_id, tmp_path)
    with db_session_factory() as session:
        session.add(
            Finding(
                scan_id=scan_id,
                tool="semgrep",
                title="suppressed hit",
                severity="high",
                file_path="okhttp3/RealCall.java",
                suppressed=True,
            )
        )
        session.commit()
    body = client.get(f"/api/v1/scans/{scan_id}/dependencies").json()
    assert body["total"] == 0  # the only finding is a false positive


def test_dependencies_endpoint_not_analyzed_409(client, db_session_factory):
    scan_id = _scan_row(db_session_factory, status="running")
    r = client.get(f"/api/v1/scans/{scan_id}/dependencies")
    assert r.status_code == 409


def test_dependencies_endpoint_unknown_scan_404(client):
    assert client.get("/api/v1/scans/999999/dependencies").status_code == 404

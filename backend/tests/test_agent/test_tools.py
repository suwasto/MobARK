"""Layer 2/3 + M6 tool tests - real temp trees, no network, no LLM, no
graphify subprocess (graph wrappers stub the graphify module), gitleaks
wrapper monkeypatched for run_secrets_scan.
"""
from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest

from app.agent import tools
from app.analysis.base import FindingOut, StageResult
from app.models import Scan

ANDROID_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.insecure">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"
                     android:maxSdkVersion="30"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:allowBackup="true" android:debuggable="true"
                 android:usesCleartextTraffic="true" android:label="App">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
            </intent-filter>
        </activity>
        <service android:name=".BackgroundService" android:exported="false"/>
    </application>
</manifest>
"""

IOS_PLIST = {
    "CFBundleIdentifier": "com.example.iosapp",
    "CFBundleName": "TestApp",
    "CFBundleShortVersionString": "1.2.3",
    "MinimumOSVersion": "13.0",
    "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    "NSCameraUsageDescription": "Needs camera access",
    "UIBackgroundModes": ["audio"],
}


def _android_manifest(tmp_path, scan_id, manifest: str = ANDROID_MANIFEST) -> None:
    """Write a decompiled resources/AndroidManifest.xml for the scan."""
    root = tmp_path / "work" / str(scan_id) / "decompiled" / "resources"
    root.mkdir(parents=True, exist_ok=True)
    (root / "AndroidManifest.xml").write_text(manifest)


def _ios_tree(tmp_path, scan_id, plist: dict | None = None) -> None:
    """Write a Payload/*.app tree with a (binary) Info.plist."""
    root = tmp_path / "work" / str(scan_id) / "bundle" / "Payload" / "Test.app"
    root.mkdir(parents=True, exist_ok=True)
    (root / "Info.plist").write_bytes(
        plistlib.dumps(plist or IOS_PLIST, fmt=plistlib.FMT_BINARY)
    )


@pytest.fixture()
def env(monkeypatch, db_session_factory, tmp_path, platform="android"):
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform=platform, status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    return scan_id, tmp_path, db_session_factory


@pytest.fixture()
def env_ios(monkeypatch, db_session_factory, tmp_path):
    """Like ``env`` but for an iOS scan (Payload/*.app tree)."""
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.ipa", platform="ios", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    return scan_id, tmp_path, db_session_factory


def _android_tree(tmp_path, scan_id, files: dict[str, str]) -> None:
    root = tmp_path / "work" / str(scan_id) / "decompiled" / "sources"
    root.mkdir(parents=True)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def _binary_file(tmp_path, scan_id, rel: str, data: bytes) -> None:
    root = tmp_path / "work" / str(scan_id) / "decompiled" / "sources"
    root.mkdir(parents=True, exist_ok=True)
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


# ---- search_code --------------------------------------------------------------


def test_search_code_finds_matches(env):
    scan_id, tmp_path, _ = env
    _android_tree(
        tmp_path,
        scan_id,
        {
            "com/app/Login.java": "package com.app;\npublic class Login {\n  void check() {}\n}\n",
            "res/xml/netsec.xml": "<network-security-config/>\n",
        },
    )
    hits = tools.search_code(scan_id, "Login")
    assert len(hits) == 1
    assert hits[0]["file"] == "com/app/Login.java"
    assert hits[0]["line"] == 2  # `public class Login` is line 2


def test_search_code_respects_glob(env):
    scan_id, tmp_path, _ = env
    _android_tree(
        tmp_path,
        scan_id,
        {
            "a.java": "config\n",
            "res/netsec.xml": "config\n",
        },
    )
    hits = tools.search_code(scan_id, "config", glob="*.java")
    assert len(hits) == 1
    assert hits[0]["file"] == "a.java"


def test_search_code_invalid_regex_is_tool_error(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"a.java": "x\n"})
    with pytest.raises(tools.ToolError, match="invalid regex"):
        tools.search_code(scan_id, "(")


def test_search_code_skips_binary_files(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"a.txt": "Login here\n"})
    _binary_file(tmp_path, scan_id, "blob.bin", b"\x00\x01\x02Login\x00\xff")
    hits = tools.search_code(scan_id, "Login")
    assert len(hits) == 1
    assert hits[0]["file"] == "a.txt"


def test_search_code_no_tree_is_tool_error(env):
    scan_id, tmp_path, _ = env
    with pytest.raises(tools.ToolError, match="no decompiled"):
        tools.search_code(scan_id, "x")


# ---- read_file ----------------------------------------------------------------


def test_read_file_whole_and_range(env):
    scan_id, tmp_path, _ = env
    text = "\n".join(f"line {i}" for i in range(1, 11))
    _android_tree(tmp_path, scan_id, {"a.txt": text})
    assert tools.read_file(scan_id, "a.txt") == text
    assert tools.read_file(scan_id, "a.txt", line_start=2, line_end=3) == "line 2\nline 3"


def test_read_file_traversal_guard(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"a.txt": "x"})
    with pytest.raises(tools.ToolError, match="escapes"):
        tools.read_file(scan_id, "../../../etc/passwd")


def test_read_file_missing_is_tool_error(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"a.txt": "x"})
    with pytest.raises(tools.ToolError, match="not a file"):
        tools.read_file(scan_id, "nope.txt")


def test_read_file_refuses_binary(env):
    scan_id, tmp_path, _ = env
    _binary_file(tmp_path, scan_id, "blob.bin", b"\x00\x01\x02")
    with pytest.raises(tools.ToolError, match="binary file"):
        tools.read_file(scan_id, "blob.bin")


def test_read_file_decodes_binary_plist(env):
    scan_id, tmp_path, _ = env
    _binary_file(
        tmp_path,
        scan_id,
        "Info.plist",
        plistlib.dumps(
            {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}},
            fmt=plistlib.FMT_BINARY,
        ),
    )
    out = tools.read_file(scan_id, "Info.plist")
    assert "NSAllowsArbitraryLoads" in out
    assert "True" in out or "true" in out


# ---- iOS tree resolution ------------------------------------------------------


def test_ios_tree_root_resolves_payload_app(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.ipa", platform="ios", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    app_root = tmp_path / "work" / str(scan_id) / "bundle" / "Payload" / "Test.app"
    app_root.mkdir(parents=True)
    (app_root / "Info.plist").write_text("<?xml version='1.0'?><plist/>")
    hits = tools.search_code(scan_id, "plist")
    assert hits and hits[0]["file"] == "Info.plist"


# ---- Layer 3 graph tools (graphify stubbed) ----------------------------------


def _write_graph(tmp_path, scan_id):
    p = tmp_path / "graphs" / str(scan_id) / "graphify-out" / "graph.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"nodes": [{"id": "a"}], "links": []}))
    return p


def test_graph_tools_wrap_graphify(env, monkeypatch):
    scan_id, tmp_path, _ = env
    _write_graph(tmp_path, scan_id)
    from app.graph import graphify

    monkeypatch.setattr(
        graphify,
        "query",
        lambda p, q, budget=1500: {"found": True, "text": "X", "nodes": [], "via": "t"},
    )
    monkeypatch.setattr(graphify, "path_between", lambda p, a, b: "PATH: a -> b")
    monkeypatch.setattr(graphify, "explain", lambda p, n: "EXPLAIN: n")

    assert tools.graph_query(scan_id, "where is X")["found"] is True
    assert tools.graph_path_between(scan_id, "a", "b") == "PATH: a -> b"
    assert tools.graph_explain_node(scan_id, "n") == "EXPLAIN: n"


def test_graph_tool_no_graph_is_tool_error(env):
    scan_id, tmp_path, _ = env
    with pytest.raises(tools.ToolError, match="no code graph"):
        tools.graph_query(scan_id, "where")


# ---- M6 app-oriented tools ----------------------------------------------------


def test_read_manifest_android(env):
    scan_id, tmp_path, _ = env
    _android_manifest(tmp_path, scan_id)
    out = tools.read_manifest(scan_id)
    assert out["package"] == "com.example.insecure"
    assert out["min_sdk"] == "21" and out["target_sdk"] == "33"
    assert out["debuggable"] is True
    assert out["allow_backup"] is True
    assert out["cleartext_traffic"] is True
    components = out["exported_components"]
    main = next(c for c in components if c["name"] == ".MainActivity")
    assert main["exported"] is True and main["has_intent_filter"] is True
    bg = next(c for c in components if c["name"] == ".BackgroundService")
    assert bg["exported"] is False and bg["has_intent_filter"] is False


def test_read_manifest_ios(env_ios):
    scan_id, tmp_path, _ = env_ios
    _ios_tree(tmp_path, scan_id)
    out = tools.read_manifest(scan_id)
    assert out["bundle_identifier"] == "com.example.iosapp"
    assert out["bundle_version"] == "1.2.3"
    assert out["minimum_os_version"] == "13.0"
    assert out["app_transport_security"] == {"NSAllowsArbitraryLoads": True}
    assert out["usage_descriptions"]["NSCameraUsageDescription"]["value"] == "Needs camera access"
    assert out["background_modes"] == ["audio"]


def test_read_manifest_missing_android_manifest_is_tool_error(env):
    scan_id, tmp_path, _ = env
    with pytest.raises(tools.ToolError, match="AndroidManifest.xml not found"):
        tools.read_manifest(scan_id)


def test_get_decompiled_class_resolves_and_reads(env):
    scan_id, tmp_path, _ = env
    _android_tree(
        tmp_path,
        scan_id,
        {"com/app/Login.java": "package com.app;\npublic class Login {}\n"},
    )
    out = tools.get_decompiled_class(scan_id, "com.app.Login")
    assert "public class Login" in out


def test_get_decompiled_class_inner_class_and_kotlin(env):
    scan_id, tmp_path, _ = env
    _android_tree(
        tmp_path,
        scan_id,
        {"com/app/Foo$Inner.kt": "class Foo$Inner\n"},
    )
    assert "class Foo$Inner" in tools.get_decompiled_class(scan_id, "com.app.Foo$Inner")


def test_get_decompiled_class_missing_is_tool_error(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"com/app/Other.java": "class Other {}\n"})
    with pytest.raises(tools.ToolError, match="not found in the decompiled source tree"):
        tools.get_decompiled_class(scan_id, "com.app.Missing")


def test_get_decompiled_class_invalid_name_is_tool_error(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"a.java": "class A {}\n"})
    with pytest.raises(tools.ToolError, match="invalid class name"):
        tools.get_decompiled_class(scan_id, "../../etc/passwd")


def test_get_decompiled_class_ios_is_explicit_error(env_ios):
    scan_id, tmp_path, _ = env_ios
    _ios_tree(tmp_path, scan_id)
    with pytest.raises(tools.ToolError, match="no decompiled source on iOS"):
        tools.get_decompiled_class(scan_id, "com.app.Foo")


def test_get_permissions_android(env):
    scan_id, tmp_path, _ = env
    _android_manifest(tmp_path, scan_id)
    rows = tools.get_permissions(scan_id)
    by_name = {r["name"]: r for r in rows}
    assert by_name["android.permission.CAMERA"]["dangerous"] is True  # curated risky set
    loc = by_name["android.permission.ACCESS_FINE_LOCATION"]
    assert loc["dangerous"] is True and loc["max_sdk_version"] == 30
    assert by_name["android.permission.INTERNET"]["dangerous"] is False


def test_get_permissions_ios(env_ios):
    scan_id, tmp_path, _ = env_ios
    _ios_tree(tmp_path, scan_id)
    rows = tools.get_permissions(scan_id)
    assert rows == [
        {"key": "NSCameraUsageDescription", "label": "camera", "value": "Needs camera access"}
    ]


def test_run_secrets_scan_wraps_gitleaks(env, monkeypatch):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"res/strings.xml": "<string>hi</string>\n"})
    captured = {}

    def fake_scan(target, report_path, timeout=None, config=None):
        captured["target"] = Path(target)
        captured["timeout"] = timeout
        return StageResult(
            findings=[
                FindingOut(
                    tool="gitleaks",
                    title="Hardcoded secret detected: aws-access-token",
                    severity="high",
                    file_path="res/strings.xml",
                    line_number=4,
                    detail={"rule_id": "aws-access-token"},
                )
            ]
        )

    monkeypatch.setattr("app.analysis.gitleaks.scan_directory", fake_scan)
    rows = tools.run_secrets_scan(scan_id, "res")
    assert rows[0]["rule_id"] == "aws-access-token"
    assert rows[0]["file"] == "res/strings.xml"
    assert rows[0]["severity"] == "high"
    assert captured["timeout"] == tools._SECRETS_SCAN_TIMEOUT
    expected_target = tmp_path / "work" / str(scan_id) / "decompiled" / "sources" / "res"
    assert captured["target"] == expected_target


def test_run_secrets_scan_gitleaks_unavailable_is_tool_error(env, monkeypatch):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"res/a.txt": "x\n"})
    from app.analysis import gitleaks

    def boom(target, report_path, timeout=None, config=None):
        raise gitleaks.GitleaksError("gitleaks not found on PATH")

    monkeypatch.setattr("app.analysis.gitleaks.scan_directory", boom)
    with pytest.raises(tools.ToolError, match="gitleaks unavailable"):
        tools.run_secrets_scan(scan_id, "res")


def test_run_secrets_scan_errors_surface_as_tool_error(env, monkeypatch):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"res/a.txt": "x\n"})

    def errored(target, report_path, timeout=None, config=None):
        result = StageResult()
        result.errors.append("gitleaks timed out after 30s")
        return result

    monkeypatch.setattr("app.analysis.gitleaks.scan_directory", errored)
    with pytest.raises(tools.ToolError, match="secrets scan failed"):
        tools.run_secrets_scan(scan_id, "res")


def test_run_secrets_scan_traversal_guard_and_not_dir(env, monkeypatch):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"a.txt": "x\n"})
    with pytest.raises(tools.ToolError, match="escapes"):
        tools.run_secrets_scan(scan_id, "../../etc")
    with pytest.raises(tools.ToolError, match="not a directory"):
        tools.run_secrets_scan(scan_id, "a.txt")


def test_search_strings_targets_resources_only(env):
    scan_id, tmp_path, _ = env
    _android_tree(
        tmp_path,
        scan_id,
        {
            "com/app/Login.java": "public class Login { String token; }\n",
            "res/values/strings.xml": "<string name=\"app_name\">Login app</string>\n",
            "res/layout/activity.xml": "<TextView text=\"Login\"/>\n",
        },
    )
    hits = tools.search_strings(scan_id, "Login")
    files = {h["file"] for h in hits}
    assert files == {"res/values/strings.xml", "res/layout/activity.xml"}
    assert "com/app/Login.java" not in files


def test_schemas_for_platform_filters_android_only():
    android = {s["function"]["name"] for s in tools.schemas_for_platform("android")}
    ios = {s["function"]["name"] for s in tools.schemas_for_platform("ios")}
    assert "get_decompiled_class" in android
    assert "get_decompiled_class" not in ios
    for name in ("search_code", "read_file", "read_manifest", "get_permissions",
                 "run_secrets_scan", "search_strings"):
        assert name in ios
    assert android - ios == {"get_decompiled_class"}


def test_m6_tools_dispatch_via_execute_tool(env, monkeypatch):
    """The M6 handlers are wired into execute_tool like the Layer 2/3 ones."""
    scan_id, tmp_path, _ = env
    _android_manifest(tmp_path, scan_id)
    _android_tree(
        tmp_path,
        scan_id,
        {
            "com/app/Login.java": "public class Login {}\n",
            "res/values/strings.xml": "<string name=\"app_name\">Login</string>\n",
        },
    )

    out = json.loads(tools.execute_tool(scan_id, "read_manifest", {}))
    assert out["package"] == "com.example.insecure"

    out = json.loads(tools.execute_tool(scan_id, "get_decompiled_class", {"fqcn": "com.app.Login"}))
    assert "public class Login" in out

    out = json.loads(tools.execute_tool(scan_id, "get_permissions", {}))
    assert any(r["name"] == "android.permission.CAMERA" for r in out)

    out = json.loads(tools.execute_tool(scan_id, "search_strings", {"pattern": "app_name"}))
    assert out and out[0]["file"] == "res/values/strings.xml"

    out = json.loads(
        tools.execute_tool(scan_id, "get_decompiled_class", {"fqcn": "com.app.Nope"})
    )
    assert "error" in out


# ---- execute_tool dispatch ----------------------------------------------------


def test_execute_tool_dispatch_and_error_paths(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"com/app/Login.java": "public class Login {}\n"})

    out = json.loads(tools.execute_tool(scan_id, "search_code", {"pattern": "Login"}))
    assert out[0]["file"] == "com/app/Login.java"

    out = json.loads(tools.execute_tool(scan_id, "search_code", {"pattern": "("}))
    assert "error" in out

    out = json.loads(tools.execute_tool(scan_id, "not_a_tool", {}))
    assert "unknown tool" in out["error"]

    out = json.loads(tools.execute_tool(scan_id, "read_file", {"path": "../../etc/passwd"}))
    assert "error" in out

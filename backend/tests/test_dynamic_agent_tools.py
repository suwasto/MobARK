"""M16 (V2) agent-authored script tools + approval gate tests - fake-posture.

Covers FR-D18/D19/D20: the five M16 agent tools
(``attach_session``/``list_active_scripts``/``draft_frida_script``/
``run_script``/``stop_script``), the live-session gate
(``dynamic_tools_allowed`` + ``schemas_for_platform`` offering the tools only
when the scan is connected), and the FR-D19 approval gate - a drafted script
is stored ``origin=agent, status=proposed``, refuses to run/stop, and only
becomes a normal manageable script (FR-D20) after the tester approves it via
``POST /session/scripts/managed/{id}/approve`` (or rejects the draft with
DELETE). No real frida - the runner flips flags; real injection is an owner
manual checkpoint.
"""
from __future__ import annotations

import json

import pytest

from app.agent import tools
from app.dynamic import base
from app.models import Scan


class FakeBackend:
    platform = "android"

    def __init__(self, platform="android"):
        self.platform = platform
        if platform == "ios":
            self.attach_meta = {
                "connection_type": "ssh",
                "frida_version": "16.0.0",
                "target_pid": 999,
                "jailbreak_method": "palera1n",
            }
            self.checks = {
                "device_reachable": True,
                "frida_server_reachable": True,
                "jailbreak_detected": True,
                "target_installed": True,
            }
        else:
            self.attach_meta = {
                "connection_type": "adb",
                "frida_version": "16.0.0",
                "target_pid": 1234,
                "root_status": True,
            }
            self.checks = {
                "adb_ok": True,
                "device_present": True,
                "frida_server_reachable": True,
                "target_installed": True,
            }

    def list_devices(self):
        return [{"id": "emulator-5554", "name": "emulator-5554",
                 "model": "pixel", "detail": None}]

    def preflight(self, device_id, target_app):
        return dict(self.checks)

    def attach(self, device_id, target_app, artifact_path=None):
        return dict(self.attach_meta)

    def disconnect(self):
        pass


@pytest.fixture()
def patch_backend(monkeypatch):
    import app.dynamic.router as router

    backend = FakeBackend()
    monkeypatch.setattr(router, "get_backend", lambda platform: backend)
    return backend


@pytest.fixture()
def patch_backend_ios(monkeypatch):
    import app.dynamic.router as router

    backend = FakeBackend("ios")
    monkeypatch.setattr(router, "get_backend", lambda platform: backend)
    return backend


@pytest.fixture(autouse=True)
def _reset_active():
    yield
    base.end_session()


@pytest.fixture()
def patch_db(monkeypatch, db_session_factory):
    """The agent tools open their own ``app.db.SessionLocal`` - point it at
    the test factory so the draft/run/list rows share the API client's DB."""
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)


def _make_scan(factory, user_id, *, platform="android", filename="app.apk"):
    with factory() as db:
        scan = Scan(filename=filename, status="done", platform=platform, user_id=user_id)
        db.add(scan)
        db.commit()
        return scan.id


def _connect(client, scan_id, platform="android", device="emulator-5554"):
    return client.post(
        "/api/v1/dynamic/session/connect",
        json={
            "scan_id": scan_id,
            "platform": platform,
            "device_id": device,
            "target_app": "com.example.app",
        },
    )


def _connected(client, db_session_factory, auth_user_id, platform="android"):
    scan_id = _make_scan(db_session_factory, auth_user_id, platform=platform)
    _connect(client, scan_id, platform=platform)
    return scan_id


MANAGED = "/api/v1/dynamic/session/scripts/managed"


def _draft(
    client,
    db_session_factory,
    auth_user_id,
    *,
    platform="android",
    body="Java.perform(function(){ console.log('x'); });",
):
    """Connect + draft one agent script; returns (scan_id, draft_id, draft)."""
    scan_id = _connected(client, db_session_factory, auth_user_id, platform=platform)
    draft = tools.draft_frida_script(
        scan_id,
        request="log all https traffic",
        body=body,
        name="log https",
        description="Hooks OkHttp to log requests.",
    )
    return scan_id, draft["id"], draft


# ---- the live-session gate (dynamic_tools_allowed + schemas_for_platform) ---


def test_dynamic_tools_allowed_requires_live_session(
    client, patch_backend, db_session_factory, auth_user_id
):
    other_scan = _make_scan(db_session_factory, auth_user_id, platform="android")
    assert tools.dynamic_tools_allowed(other_scan) is False  # no session yet
    scan_id = _connected(client, db_session_factory, auth_user_id)
    assert tools.dynamic_tools_allowed(scan_id) is True
    # a different scan (same user) with the session live on scan_id -> False
    assert tools.dynamic_tools_allowed(other_scan) is False
    # disconnect tears the gate down
    client.post("/api/v1/dynamic/session/disconnect")
    assert tools.dynamic_tools_allowed(scan_id) is False


def test_schemas_gate_dynamic_tools():
    names = {s["function"]["name"] for s in tools.TOOL_SCHEMAS}
    assert {"attach_session", "list_active_scripts", "draft_frida_script",
            "run_script", "stop_script"} <= names
    # offered on BOTH platforms when enabled (V2 has Android AND iOS sessions)
    for platform in ("android", "ios"):
        offered = {
            s["function"]["name"]
            for s in tools.schemas_for_platform(platform, dynamic_tools_enabled=True)
        }
        assert {"attach_session", "list_active_scripts", "draft_frida_script",
                "run_script", "stop_script"} <= offered
        # never even seen when the gate is off (the never-even-offered rule)
        hidden = {
            s["function"]["name"]
            for s in tools.schemas_for_platform(platform, dynamic_tools_enabled=False)
        }
        assert not {"attach_session", "list_active_scripts", "draft_frida_script",
                    "run_script", "stop_script"} & hidden


def test_execute_tool_dispatch_unknown_dynamic_gate(
    client, patch_backend, db_session_factory, auth_user_id
):
    # without a session, execute_tool returns a clean error, never raises
    scan_id = _make_scan(db_session_factory, auth_user_id, platform="android")
    result = json.loads(tools.execute_tool(scan_id, "attach_session", {}))
    assert "error" in result
    assert "no live dynamic session" in result["error"]


# ---- attach_session (FR-D3 observe-only) ------------------------------------


def test_attach_session_reports_state(
    client, patch_backend, db_session_factory, auth_user_id
):
    scan_id = _connected(client, db_session_factory, auth_user_id)  # android
    state = tools.attach_session(scan_id)
    assert state["attached"] is True
    assert state["platform"] == "android"
    assert state["device_id"] == "emulator-5554"
    assert state["frida_version"] == "16.0.0"
    assert state["target_pid"] == 1234
    assert state["root_status"] is True


def test_attach_session_ios(
    client, patch_backend_ios, db_session_factory, auth_user_id
):
    scan_id = _connected(client, db_session_factory, auth_user_id, platform="ios")
    state = tools.attach_session(scan_id)
    assert state["platform"] == "ios"
    assert state["target_pid"] == 999
    assert state["jailbreak_method"] == "palera1n"


def test_attach_session_foreign_scan_error(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    other_scan = _make_scan(db_session_factory, auth_user_id, platform="android")
    with pytest.raises(tools.ToolError, match="belongs to scan"):
        tools.attach_session(other_scan)


# ---- draft_frida_script (FR-D18 + FR-D19 proposed state) -------------------


def test_draft_frida_script_stores_proposed(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id = _connected(client, db_session_factory, auth_user_id)  # android
    draft = tools.draft_frida_script(
        scan_id,
        request="bypass certificate pinning",
        body="Java.perform(function(){ console.log('pinning bypass'); });",
        name="pinning bypass",
        description="Disables the OkHttp certificate pinner.",
    )
    assert draft["origin"] == "agent"
    assert draft["status"] == "proposed"  # never auto-approved
    assert draft["platform"] == "android"  # from the active session
    assert draft["name"] == "pinning bypass"
    assert draft["description"] == "Disables the OkHttp certificate pinner."
    assert draft["request"] == "bypass certificate pinning"
    # it lands in the managed list as a PROPOSED agent draft (FR-D20 list)
    row = next(r for r in client.get(MANAGED).json() if r["id"] == draft["id"])
    assert row["origin"] == "agent"
    assert row["status"] == "proposed"
    assert row["script"].startswith("Java.perform")


def test_draft_frida_script_defaults_name_from_request(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id = _connected(client, db_session_factory, auth_user_id)
    draft = tools.draft_frida_script(
        scan_id, request="log SSL key log material", body="Java.perform(function(){})"
    )
    assert draft["name"].startswith("agent:")
    assert "log SSL" in draft["name"]


def test_draft_frida_script_platform_ios(
    client, patch_backend_ios, db_session_factory, auth_user_id, patch_db
):
    scan_id = _connected(client, db_session_factory, auth_user_id, platform="ios")
    draft = tools.draft_frida_script(
        scan_id,
        request="bypass ATS",
        body="ObjC.schedulePerformBlock(function(){ console.log('ats'); });",
    )
    assert draft["platform"] == "ios"
    assert draft["origin"] == "agent"
    assert draft["status"] == "proposed"


def test_draft_frida_script_requires_body(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id = _connected(client, db_session_factory, auth_user_id)
    with pytest.raises(tools.ToolError, match="requires a script body"):
        tools.draft_frida_script(scan_id, request="bypass pinning", body="  ")


def test_draft_frida_script_bounds(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id = _connected(client, db_session_factory, auth_user_id)
    with pytest.raises(tools.ToolError, match="name must be"):
        tools.draft_frida_script(scan_id, request="x", body="y", name="n" * 129)
    with pytest.raises(tools.ToolError, match="body must be"):
        tools.draft_frida_script(scan_id, request="x", body="y" * (256 * 1024 + 1))


def test_draft_frida_script_foreign_scan_error(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    _connected(client, db_session_factory, auth_user_id)
    other_scan = _make_scan(db_session_factory, auth_user_id, platform="android")
    with pytest.raises(tools.ToolError, match="belongs to scan"):
        tools.draft_frida_script(other_scan, request="x", body="y")


# ---- run/stop + the FR-D19 approval gate -----------------------------------


def test_run_refuses_unapproved_draft(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id, draft_id, _ = _draft(client, db_session_factory, auth_user_id)
    # approval-gate refusal: an agent draft can never run before approval
    result = json.loads(tools.execute_tool(scan_id, "run_script", {"script_id": draft_id}))
    assert "error" in result
    assert "approve" in result["error"].lower()
    with pytest.raises(tools.ToolError, match="approve"):
        tools.stop_script(scan_id, draft_id)


def test_approve_makes_agent_script_runnable(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id, draft_id, draft = _draft(client, db_session_factory, auth_user_id)
    # approve via the API -> status ready (FR-D19 gate)
    resp = client.post(f"{MANAGED}/{draft_id}/approve")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"
    assert resp.json()["origin"] == "agent"
    # now runnable + stoppable like any manual/builtin (FR-D20)
    assert tools.run_script(scan_id, draft_id)["running"] is True
    running = tools.list_active_scripts(scan_id)
    assert any(s["id"] == draft_id and s["name"] == draft["name"] for s in running)
    assert tools.stop_script(scan_id, draft_id)["running"] is False
    assert tools.list_active_scripts(scan_id) == []
    # double-approve is refused (already approved)
    assert client.post(f"{MANAGED}/{draft_id}/approve").status_code == 400


def test_approve_refuses_manual_and_builtin(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    _connected(client, db_session_factory, auth_user_id)
    manual = client.post(
        MANAGED, json={"name": "a", "body": "x"}
    ).json()
    assert client.post(f"{MANAGED}/{manual['id']}/approve").status_code == 400
    builtin = next(
        r for r in client.get(MANAGED).json() if r["origin"] == "builtin"
    )
    assert client.post(f"{MANAGED}/{builtin['id']}/approve").status_code == 400


def test_approved_agent_script_read_only_like_builtin(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id, draft_id, _ = _draft(client, db_session_factory, auth_user_id)
    client.post(f"{MANAGED}/{draft_id}/approve")
    # once approved it is read-only (like builtin) - PUT + DELETE 400
    assert client.put(f"{MANAGED}/{draft_id}", json={"body": "z"}).status_code == 400
    assert client.delete(f"{MANAGED}/{draft_id}").status_code == 400


def test_delete_rejects_unapproved_draft(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id, draft_id, _ = _draft(client, db_session_factory, auth_user_id)
    # rejection path: an unapproved draft can be deleted
    assert client.delete(f"{MANAGED}/{draft_id}").status_code == 200
    assert client.get(f"{MANAGED}/{draft_id}").status_code == 404


def test_run_stop_ready_manual_script(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id = _connected(client, db_session_factory, auth_user_id)
    manual = client.post(MANAGED, json={"name": "log", "body": "x"}).json()
    assert tools.run_script(scan_id, manual["id"])["running"] is True
    running = tools.list_active_scripts(scan_id)
    assert any(s["id"] == manual["id"] and s["origin"] == "manual" for s in running)
    assert tools.stop_script(scan_id, manual["id"])["running"] is False
    assert tools.list_active_scripts(scan_id) == []


def test_run_script_not_found(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id = _connected(client, db_session_factory, auth_user_id)
    with pytest.raises(tools.ToolError, match="not found"):
        tools.run_script(scan_id, 99999)


def test_run_script_foreign_scan_error(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    first_scan = _connected(client, db_session_factory, auth_user_id)
    sid = client.post(MANAGED, json={"name": "a", "body": "x"}).json()["id"]
    client.post("/api/v1/dynamic/session/disconnect")
    second_scan = _make_scan(db_session_factory, auth_user_id, platform="android")
    _connect(client, second_scan)
    # the script belongs to the first scan's session -> foreign (not found)
    with pytest.raises(tools.ToolError, match="not found"):
        tools.run_script(second_scan, sid)
    assert first_scan != second_scan


def test_list_active_scripts_empty(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    scan_id = _connected(client, db_session_factory, auth_user_id)
    assert tools.list_active_scripts(scan_id) == []


# ---- approve API guards (404 no-session / 401 unauth / foreign 404) ---------


def test_approve_404_without_session(client, patch_backend):
    assert client.post(f"{MANAGED}/1/approve").status_code == 404


def test_approve_behind_auth(unauth_client, patch_backend):
    assert unauth_client.post(f"{MANAGED}/1/approve").status_code == 401


def test_approve_foreign_scan_404(
    client, patch_backend, db_session_factory, auth_user_id, patch_db
):
    first_scan, draft_id, _ = _draft(client, db_session_factory, auth_user_id)
    client.post("/api/v1/dynamic/session/disconnect")
    _connect(client, first_scan)  # reconnect SAME scan -> still approveable
    assert client.post(f"{MANAGED}/{draft_id}/approve").status_code == 200
    client.post("/api/v1/dynamic/session/disconnect")
    second_scan = _make_scan(db_session_factory, auth_user_id, platform="android")
    _connect(client, second_scan)
    # the draft belongs to the previous scan -> foreign 404
    assert client.post(f"{MANAGED}/{draft_id}/approve").status_code == 404

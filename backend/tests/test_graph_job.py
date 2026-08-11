"""build_graph_scan job tests - graphify stubbed; no Redis, no network."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.graph.graphify import GraphStats
from app.models import Scan
from app.workers import jobs


@pytest.fixture()
def patched_env(monkeypatch, db_session_factory, tmp_path):
    """Point settings.data_dir + SessionLocal at the test DB, stub graphify."""
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    monkeypatch.setattr(
        "app.graph.graphify.build",
        lambda scan_id, root, graphs: GraphStats(nodes=10, edges=20, graph_path=Path("g.json")),
    )
    return db_session_factory, tmp_path


def _add_scan(factory, *, platform="android", status="done"):
    with factory() as session:
        scan = Scan(filename="app.apk", platform=platform, status=status)
        session.add(scan)
        session.commit()
        return scan.id


def test_build_graph_success(patched_env):
    factory, tmp_path = patched_env
    scan_id = _add_scan(factory)
    (tmp_path / "work" / str(scan_id) / "decompiled" / "sources").mkdir(parents=True)

    result = jobs.build_graph_scan(scan_id)
    assert result["ok"] is True
    assert result["built"] is True
    assert result["nodes"] == 10
    assert result["edges"] == 20


def test_build_graph_ios_skips_with_reason(patched_env):
    factory, tmp_path = patched_env
    scan_id = _add_scan(factory, platform="ios")

    result = jobs.build_graph_scan(scan_id)
    assert result["ok"] is True
    assert result["built"] is False
    assert result["reason"] == "ios-no-source"


def test_build_graph_missing_decompiled_fails_cleanly(patched_env):
    factory, tmp_path = patched_env
    scan_id = _add_scan(factory)

    result = jobs.build_graph_scan(scan_id)
    assert result["ok"] is False
    assert result["built"] is False
    assert "no decompiled source" in result["error"]


def test_build_graph_unknown_scan(patched_env):
    factory, tmp_path = patched_env
    result = jobs.build_graph_scan(999999)
    assert result["ok"] is False
    assert "not found" in result["error"]

"""M9 open item 1 - per-scan web-source capture.

``web_sources.capture_from_turn`` persists the final post-redirect URLs the
agent actually fetched (from the turn's tool_runs) into a per-scan ledger
that the report's External references section reads. No LLM, no network in
these tests - ToolRun objects are constructed directly and the ledger is a
file under the (tmp) data dir.
"""
from __future__ import annotations

import json

from app.agent.chat import AgentResult, ToolRun
from app.analysis import web_sources
from app.models import Scan


def _fetch_run(url, preview=None, status="ok", name="web_fetch"):
    return ToolRun(
        id="t1",
        name=name,
        args={"url": url},
        status=status,
        duration_ms=5,
        result_preview=preview if preview is not None else json.dumps({"url": url}),
    )


# ---- extraction ---------------------------------------------------------------


def test_captures_final_post_redirect_url(tmp_path, monkeypatch):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    # The preview is the web_fetch result JSON: url is the FIRST field and
    # carries the final post-redirect location the model was told to cite.
    runs = [
        _fetch_run(
            "https://example.com/r",
            preview=(
                '{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001", '
                '"title": "CVE-2026-0001", "text": "..."}'
            ),
        )
    ]
    web_sources.capture_from_turn(1, runs)
    assert web_sources.sources_for(1) == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    ]


def test_only_successful_web_fetch_runs_count(tmp_path, monkeypatch):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    runs = [
        _fetch_run("https://ok.example/page"),  # ok web_fetch -> captured
        _fetch_run("https://fail.example/page", status="error"),  # failed -> skipped
        _fetch_run("https://nope.example/x", name="web_search"),  # not fetch -> skipped
        _fetch_run("https://nope.example/y", name="search_code"),  # not web -> skipped
    ]
    web_sources.capture_from_turn(1, runs)
    assert web_sources.sources_for(1) == ["https://ok.example/page"]


def test_unreadable_preview_degrades_to_empty(tmp_path, monkeypatch):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    # A preview that isn't JSON and has no url field -> no URL captured.
    web_sources.capture_from_turn(1, [_fetch_run("https://x.example", preview="[broken")])
    assert web_sources.sources_for(1) == []


# ---- dedup + bounded ----------------------------------------------------------


def test_capture_dedups_across_turns(tmp_path, monkeypatch):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    web_sources.capture_from_turn(1, [_fetch_run("https://a.example/1")])
    web_sources.capture_from_turn(1, [_fetch_run("https://a.example/1"), _fetch_run("https://b.example/2")])
    assert web_sources.sources_for(1) == ["https://a.example/1", "https://b.example/2"]


def test_capture_bounded_at_max(tmp_path, monkeypatch):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    many = [_fetch_run(f"https://s.example/{i}") for i in range(web_sources._MAX_SOURCES + 20)]
    web_sources.capture_from_turn(1, many)
    urls = web_sources.sources_for(1)
    assert len(urls) == web_sources._MAX_SOURCES
    assert urls[0] == "https://s.example/0"  # first-come first-kept
    assert "https://s.example/500" not in urls


# ---- persistence --------------------------------------------------------------


def test_ledger_persists_across_processes(tmp_path, monkeypatch):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    ledger = web_sources.ledger_path(1)
    web_sources.capture_from_turn(1, [_fetch_run("https://persist.example/p")])
    assert ledger.is_file()
    data = json.loads(ledger.read_text())
    assert data["version"] == web_sources._WEB_SOURCES_VERSION
    assert data["urls"] == ["https://persist.example/p"]


def test_torn_ledger_reads_empty(tmp_path, monkeypatch):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    ledger = web_sources.ledger_path(1)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text("{ not json", encoding="utf-8")
    assert web_sources.sources_for(1) == []


def test_missing_ledger_reads_empty(tmp_path, monkeypatch):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    assert web_sources.sources_for(1) == []


# ---- route wiring -------------------------------------------------------------


def _add_scan(db_session_factory):
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="done")
        session.add(scan)
        session.commit()
        return scan.id


def _fake_answer_with_web_fetch():
    def fake_answer(scan_id, question, **kwargs):
        return AgentResult(
            answer="The CVE is documented at the NVD link.",
            citations=[],
            sources=[],
            tools_used=["web_fetch"],
            tool_mode="tools",
            tool_runs=[
                ToolRun(
                    id="w1",
                    name="web_fetch",
                    args={"url": "https://example.com/r"},
                    status="ok",
                    duration_ms=5,
                    result_preview=(
                        '{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001", '
                        '"title": "t", "text": "..."}'
                    ),
                )
            ],
        )

    return fake_answer


def test_buffered_chat_captures_web_sources(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.config
    from app.api.routes import scans as routes

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    monkeypatch.setattr(routes, "answer_question", _fake_answer_with_web_fetch())
    scan_id = _add_scan(db_session_factory)

    r = client.post(
        f"/api/v1/scans/{scan_id}/chat", json={"question": "what is CVE-2026-0001"}
    )
    assert r.status_code == 200
    assert web_sources.sources_for(scan_id) == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    ]


def test_stream_chat_captures_web_sources(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.config
    from app.api.routes import scans as routes

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    monkeypatch.setattr(routes, "check_configured", lambda: None)
    monkeypatch.setattr(routes, "answer_question", _fake_answer_with_web_fetch())
    scan_id = _add_scan(db_session_factory)

    r = client.post(
        f"/api/v1/scans/{scan_id}/chat/stream",
        json={"question": "what is CVE-2026-0001"},
    )
    assert r.status_code == 200
    assert web_sources.sources_for(scan_id) == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    ]


def test_report_assembles_external_references_from_ledger(
    tmp_path, monkeypatch, db_session_factory
):
    """The ledger feeds the report's External references section."""
    import app.config
    from app.analysis import report

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    with db_session_factory() as db:
        scan = Scan(filename="app.apk", platform="android", status="done")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        scan = db.get(Scan, scan_id)

    web_sources.capture_from_turn(
        scan_id,
        [_fetch_run("https://nvd.nist.gov/vuln/detail/CVE-2026-0001")],
    )
    body = report.assemble_report(
        scan, [], web_sources=web_sources.sources_for(scan_id)
    )
    assert "## External references" in body
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" in body

from sqlalchemy import create_engine, inspect

from alembic import command
from alembic.config import Config


def test_alembic_upgrade_head_creates_tables(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'migrated.db'}"
    monkeypatch.setenv("MASA_DATABASE_URL", db_url)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert {"scans", "findings", "alembic_version"} <= tables

    scan_columns = {c["name"] for c in inspector.get_columns("scans")}
    assert {
        "id", "filename", "platform", "status", "risk_score",
        "error", "storage_path", "created_at", "started_at", "finished_at",
    } <= scan_columns

    finding_columns = {c["name"] for c in inspector.get_columns("findings")}
    assert {
        "id", "scan_id", "title", "severity", "file_path",
        "line_number", "category", "tool", "detail", "created_at",
    } <= finding_columns

    indexes = {ix["name"] for ix in inspector.get_indexes("findings")}
    assert "ix_findings_scan_id" in indexes
    engine.dispose()


def test_alembic_m5_columns_exist(tmp_path, monkeypatch):
    """M5 migration 0004: findings.explanation, scans.ai_summary, scans.stage."""
    db_url = f"sqlite:///{tmp_path / 'm5.db'}"
    monkeypatch.setenv("MASA_DATABASE_URL", db_url)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    scan_columns = {c["name"] for c in inspector.get_columns("scans")}
    assert {"ai_summary", "stage"} <= scan_columns
    finding_columns = {c["name"] for c in inspector.get_columns("findings")}
    assert "explanation" in finding_columns
    engine.dispose()


def test_alembic_m5_downgrade_removes_columns(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'm5-down.db'}"
    monkeypatch.setenv("MASA_DATABASE_URL", db_url)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0003")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "explanation" not in {c["name"] for c in inspector.get_columns("findings")}
    scan_columns = {c["name"] for c in inspector.get_columns("scans")}
    assert "ai_summary" not in scan_columns
    assert "stage" not in scan_columns
    engine.dispose()


def test_alembic_downgrade_removes_tables(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'downgrade.db'}"
    monkeypatch.setenv("MASA_DATABASE_URL", db_url)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "scans" not in inspector.get_table_names()
    assert "findings" not in inspector.get_table_names()
    engine.dispose()


def test_alembic_0005_suppression_columns(tmp_path, monkeypatch):
    """M5 migration 0005: findings.suppressed + findings.suppressed_at."""
    db_url = f"sqlite:///{tmp_path / 'suppress.db'}"
    monkeypatch.setenv("MASA_DATABASE_URL", db_url)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    finding_columns = {c["name"] for c in inspector.get_columns("findings")}
    assert {"suppressed", "suppressed_at"} <= finding_columns
    engine.dispose()


def test_alembic_0005_rewrites_critical_to_high_and_recomputes_risk(
    tmp_path, monkeypatch
):
    """Migration 0005 data pass: critical -> high + risk recompute under the
    post-critical CVSS mapping (high 8.0 -> risk 80)."""
    db_url = f"sqlite:///{tmp_path / 'critical-rewrite.db'}"
    monkeypatch.setenv("MASA_DATABASE_URL", db_url)

    from sqlalchemy import text

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "0004")  # pre-suppression schema
    engine = create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO scans (id, filename, platform, status, risk_score, created_at) "
                "VALUES (1, 'old.apk', 'android', 'done', 95, '2026-08-01T00:00:00')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO findings "
                "(id, scan_id, title, severity, tool, static_only, created_at) "
                "VALUES (1, 1, 'x', 'critical', 'semgrep', 1, '2026-08-01T00:00:00')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO findings "
                "(id, scan_id, title, severity, tool, static_only, created_at) "
                "VALUES (2, 1, 'y', 'info', 'semgrep', 1, '2026-08-01T00:00:00')"
            )
        )
    engine.dispose()

    command.upgrade(cfg, "head")  # 0005 runs the rewrite + risk recompute
    engine = create_engine(db_url)
    with engine.connect() as conn:
        severities = [
            row[0]
            for row in conn.execute(text("SELECT severity FROM findings ORDER BY id"))
        ]
        assert severities == ["high", "info"]  # critical -> high
        risk = conn.execute(
            text("SELECT risk_score FROM scans WHERE id = 1")
        ).scalar()
        # high 8.0 * 10 -> 80 (was 95 under the old critical mapping)
        assert risk == 80
    engine.dispose()


def test_alembic_0005_downgrade_removes_suppression_columns(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'suppress-down.db'}"
    monkeypatch.setenv("MASA_DATABASE_URL", db_url)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0004")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    finding_columns = {c["name"] for c in inspector.get_columns("findings")}
    assert "suppressed" not in finding_columns
    assert "suppressed_at" not in finding_columns
    engine.dispose()

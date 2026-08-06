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

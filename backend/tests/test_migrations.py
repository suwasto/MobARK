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


def test_alembic_0006_worst_plus_count_recompute(tmp_path, monkeypatch):
    """Migration 0006 data pass: done scans are re-scored under the
    worst+count model (11 active highs -> 89; mediums stay 55; lows stay
    20; suppressed highs never contribute)."""
    db_url = f"sqlite:///{tmp_path / 'worst-count.db'}"
    monkeypatch.setenv("MASA_DATABASE_URL", db_url)

    from sqlalchemy import text

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "0005")  # pre-recompute schema (0005 rewrites critical)
    engine = create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO scans (id, filename, platform, status, risk_score, "
                "created_at) VALUES (1, 'a.apk', 'android', 'done', 80, "
                "'2026-08-08T00:00:00')"
            )
        )
        # Stale pre-0006 score (80) — proves 0006 also corrects no-high scans.
        conn.execute(
            text(
                "INSERT INTO scans (id, filename, platform, status, risk_score, "
                "created_at) VALUES (2, 'b.ipa', 'ios', 'done', 80, "
                "'2026-08-08T00:00:00')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO scans (id, filename, platform, status, risk_score, "
                "created_at) VALUES (3, 'c.apk', 'android', 'done', 80, "
                "'2026-08-08T00:00:00')"
            )
        )
        for i in range(11):
            conn.execute(
                text(
                    "INSERT INTO findings (id, scan_id, title, severity, tool, "
                    "static_only, created_at) VALUES (:id, 1, 'h', 'high', "
                    "'semgrep', 1, '2026-08-08T00:00:00')"
                ),
                {"id": i + 1},
            )
        for i in range(3):
            conn.execute(
                text(
                    "INSERT INTO findings (id, scan_id, title, severity, tool, "
                    "static_only, created_at) VALUES (:id, 2, 'm', 'medium', "
                    "'semgrep', 1, '2026-08-08T00:00:00')"
                ),
                {"id": 100 + i},
            )
        conn.execute(
            text(
                "INSERT INTO findings (id, scan_id, title, severity, tool, "
                "static_only, created_at) VALUES (200, 3, 'l', 'low', "
                "'semgrep', 1, '2026-08-08T00:00:00')"
            )
        )
        # A suppressed high must NOT count toward the breadth bonus.
        conn.execute(
            text(
                "INSERT INTO findings (id, scan_id, title, severity, tool, "
                "static_only, suppressed, created_at) VALUES (300, 1, 's', "
                "'high', 'semgrep', 1, 1, '2026-08-08T00:00:00')"
            )
        )
    engine.dispose()

    command.upgrade(cfg, "0006")  # 0006 runs the worst+count recompute
    engine = create_engine(db_url)
    with engine.connect() as conn:
        risks = dict(conn.execute(text("SELECT id, risk_score FROM scans")).fetchall())
    # 11 active highs -> 80 + 9 (capped) = 89; the suppressed 12th is ignored
    assert risks[1] == 89
    assert risks[2] == 55  # 3 mediums keep 55 under 0006 (high-only bonus)
    assert risks[3] == 20  # low unchanged
    engine.dispose()


def test_alembic_0007_band_symmetric_recompute(tmp_path, monkeypatch):
    """Migration 0007 data pass: the breadth bonus extends to every band —
    3 mediums -> 57 (was 55 under 0006), 100 lows -> 39 (was 20), highs
    unchanged at 89."""
    db_url = f"sqlite:///{tmp_path / 'band-symmetric.db'}"
    monkeypatch.setenv("MASA_DATABASE_URL", db_url)

    from sqlalchemy import text

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "0006")
    engine = create_engine(db_url)
    with engine.begin() as conn:
        seed = [(1, "medium", 3), (2, "low", 100), (3, "high", 11)]
        for scan_id, sev, count in seed:
            conn.execute(
                text(
                    "INSERT INTO scans (id, filename, platform, status, "
                    "risk_score, created_at) VALUES (:id, 'x.apk', 'android', "
                    "'done', 0, '2026-08-08T00:00:00')"
                ),
                {"id": scan_id},
            )
            for i in range(count):
                conn.execute(
                    text(
                        "INSERT INTO findings (id, scan_id, title, severity, "
                        "tool, static_only, created_at) VALUES (:id, :sid, 'f', "
                        ":sev, 'semgrep', 1, '2026-08-08T00:00:00')"
                    ),
                    {"id": scan_id * 1000 + i, "sid": scan_id, "sev": sev},
                )
    engine.dispose()

    command.upgrade(cfg, "head")  # 0007 runs the band-symmetric recompute
    engine = create_engine(db_url)
    with engine.connect() as conn:
        risks = dict(conn.execute(text("SELECT id, risk_score FROM scans")).fetchall())
    assert risks[1] == 57  # 3 mediums -> 55 + 2
    assert risks[2] == 39  # 100 lows -> 20 + 19 (ceiling)
    assert risks[3] == 89  # 11 highs unchanged
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

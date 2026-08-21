from alembic.config import Config
from sqlalchemy import create_engine, inspect

from alembic import command


def test_alembic_upgrade_head_creates_tables(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'migrated.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

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
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

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
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

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
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

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
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

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
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

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

    command.upgrade(cfg, "0005")  # 0005 runs the rewrite + risk recompute
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
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

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
        # Stale pre-0006 score (80) - proves 0006 also corrects no-high scans.
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
    """Migration 0007 data pass: the breadth bonus extends to every band -
    3 mediums -> 57 (was 55 under 0006), 100 lows -> 39 (was 20), highs
    unchanged at 89."""
    db_url = f"sqlite:///{tmp_path / 'band-symmetric.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

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

    command.upgrade(cfg, "0007")  # 0007 runs the band-symmetric recompute
    engine = create_engine(db_url)
    with engine.connect() as conn:
        risks = dict(conn.execute(text("SELECT id, risk_score FROM scans")).fetchall())
    assert risks[1] == 57  # 3 mediums -> 55 + 2
    assert risks[2] == 39  # 100 lows -> 20 + 19 (ceiling)
    assert risks[3] == 89  # 11 highs unchanged
    engine.dispose()


def test_alembic_0016_drops_low_severity_and_recomputes_risk(tmp_path, monkeypatch):
    """Migration 0016 data pass: every ``low`` finding is rewritten to
    ``info`` (the vocabulary was then high | medium | info) and done scans
    are re-scored under the then-current CVSS mapping - low findings stop
    driving the risk score entirely (2 highs + 1 low -> 81, low-only -> 0,
    3 mediums + 1 low -> 57). Stops at 0016: 0017 (medium->warning + banded
    risk) re-scores with a different model."""
    db_url = f"sqlite:///{tmp_path / 'drop-low.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

    from sqlalchemy import text

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "0015")
    engine = create_engine(db_url)
    with engine.begin() as conn:
        seed = [(1, ["high", "high", "low"]), (2, ["low", "info"]),
                (3, ["medium"] * 3 + ["low"])]
        for scan_id, sevs in seed:
            conn.execute(
                text(
                    "INSERT INTO scans (id, filename, platform, status, "
                    "risk_score, created_at) VALUES (:id, 'x.apk', 'android', "
                    "'done', 0, '2026-08-15T00:00:00')"
                ),
                {"id": scan_id},
            )
            for i, sev in enumerate(sevs):
                conn.execute(
                    text(
                        "INSERT INTO findings (id, scan_id, title, severity, "
                        "tool, static_only, created_at) VALUES (:id, :sid, 'f', "
                        ":sev, 'semgrep', 1, '2026-08-15T00:00:00')"
                    ),
                    {"id": scan_id * 1000 + i, "sid": scan_id, "sev": sev},
                )
        # A non-done scan's findings are rewritten too (the UPDATE is global),
        # but its risk_score is left alone (only done scans re-score).
        conn.execute(
            text(
                "INSERT INTO scans (id, filename, platform, status, risk_score, "
                "created_at) VALUES (9, 'q.apk', 'android', 'queued', 20, "
                "'2026-08-15T00:00:00')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO findings (id, scan_id, title, severity, tool, "
                "static_only, created_at) VALUES (9000, 9, 'l', 'low', "
                "'semgrep', 1, '2026-08-15T00:00:00')"
            )
        )
    engine.dispose()

    command.upgrade(cfg, "0016")  # 0016 rewrites low -> info + re-scores
    engine = create_engine(db_url)
    with engine.connect() as conn:
        severities = [
            row[0]
            for row in conn.execute(text("SELECT severity FROM findings ORDER BY id"))
        ]
        assert "low" not in severities  # every low row became info
        risks = dict(conn.execute(text("SELECT id, risk_score FROM scans")).fetchall())
        assert risks[1] == 81  # 2 highs -> 80 + 1; the low no longer scores
        assert risks[2] == 0  # low + info -> nothing above info drives risk
        assert risks[3] == 57  # 3 mediums -> 55 + 2; the low no longer scores
        assert risks[9] == 20  # queued scan: severity rewritten, score untouched
    engine.dispose()


def test_alembic_0017_medium_to_warning_banded_risk(tmp_path, monkeypatch):
    """Migration 0017 data pass: every ``medium`` finding is rewritten to
    ``warning`` (the vocabulary is now high | warning | info) and done scans
    are re-scored under the banded risk index - a lone medium collapses 55
    -> 40, a lone high 80 -> 70, 2 highs + 1 medium -> 71, and 30 warnings
    cap at 69."""
    db_url = f"sqlite:///{tmp_path / 'medium-to-warning.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

    from sqlalchemy import text

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "0016")
    engine = create_engine(db_url)
    with engine.begin() as conn:
        seed = [(1, ["high", "high", "medium"]), (2, ["medium", "info"]),
                (3, ["medium"] * 30)]
        for scan_id, sevs in seed:
            conn.execute(
                text(
                    "INSERT INTO scans (id, filename, platform, status, "
                    "risk_score, created_at) VALUES (:id, 'x.apk', 'android', "
                    "'done', 0, '2026-08-15T00:00:00')"
                ),
                {"id": scan_id},
            )
            for i, sev in enumerate(sevs):
                conn.execute(
                    text(
                        "INSERT INTO findings (id, scan_id, title, severity, "
                        "tool, static_only, created_at) VALUES (:id, :sid, 'f', "
                        ":sev, 'semgrep', 1, '2026-08-15T00:00:00')"
                    ),
                    {"id": scan_id * 1000 + i, "sid": scan_id, "sev": sev},
                )
        # A non-done scan's findings are rewritten too (the UPDATE is global),
        # but its risk_score is left alone (only done scans re-score).
        conn.execute(
            text(
                "INSERT INTO scans (id, filename, platform, status, risk_score, "
                "created_at) VALUES (9, 'q.apk', 'android', 'queued', 55, "
                "'2026-08-15T00:00:00')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO findings (id, scan_id, title, severity, tool, "
                "static_only, created_at) VALUES (9000, 9, 'm', 'medium', "
                "'semgrep', 1, '2026-08-15T00:00:00')"
            )
        )
    engine.dispose()

    command.upgrade(cfg, "head")  # 0017 rewrites medium -> warning + re-scores
    engine = create_engine(db_url)
    with engine.connect() as conn:
        severities = [
            row[0]
            for row in conn.execute(text("SELECT severity FROM findings ORDER BY id"))
        ]
        assert "medium" not in severities  # every medium row became warning
        risks = dict(conn.execute(text("SELECT id, risk_score FROM scans")).fetchall())
        assert risks[1] == 71  # 2 highs -> 70 + 1; the warning is below high
        assert risks[2] == 40  # 1 warning -> the Warning band base
        assert risks[3] == 69  # 30 warnings -> 40 + 29 (ceiling)
        assert risks[9] == 55  # queued scan: severity rewritten, score untouched
    engine.dispose()


def test_alembic_0008_web_research_column(tmp_path, monkeypatch):
    """M7 migration 0008: scans.web_research_enabled (per-scan web research
    opt-in, default off - the privacy gate)."""
    db_url = f"sqlite:///{tmp_path / 'web-research.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    scan_columns = {c["name"] for c in inspector.get_columns("scans")}
    assert "web_research_enabled" in scan_columns
    engine.dispose()


def test_alembic_0008_defaults_off_and_downgrades(tmp_path, monkeypatch):
    """New scans default to web research OFF (the safe posture), and the
    downgrade drops the column."""
    db_url = f"sqlite:///{tmp_path / 'web-research-down.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

    from sqlalchemy import text

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    engine = create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO scans (id, filename, platform, status, created_at) "
                "VALUES (1, 'a.apk', 'android', 'queued', '2026-08-09T00:00:00')"
            )
        )
        default = conn.execute(
            text("SELECT web_research_enabled FROM scans WHERE id = 1")
        ).scalar()
        assert default == 0  # server_default false - opt-in is never implicit
    engine.dispose()

    command.downgrade(cfg, "0007")
    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "web_research_enabled" not in {
        c["name"] for c in inspector.get_columns("scans")
    }
    engine.dispose()


def test_alembic_0009_apktool_columns(tmp_path, monkeypatch):
    """M8 migration 0009 (Phase A + B): scans.apktool_status/error + the
    edits table (DB-diff source of truth)."""
    db_url = f"sqlite:///{tmp_path / 'apktool.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

    from sqlalchemy import text

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    engine = create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO scans (id, filename, platform, status, created_at) "
                "VALUES (1, 'a.apk', 'android', 'done', '2026-08-10T00:00:00')"
            )
        )
        # server_default: existing scans start not_started (nothing decodes
        # until the user triggers the Smali view - the on-demand posture)
        default = conn.execute(
            text("SELECT apktool_status FROM scans WHERE id = 1")
        ).scalar()
        assert default == "not_started"
    engine.dispose()

    inspector = inspect(engine)
    edit_columns = {c["name"] for c in inspector.get_columns("edits")}
    assert {
        "id", "scan_id", "file_path", "original_content", "new_content",
        "unified_diff", "source", "instruction", "status", "build_id",
        "created_at", "applied_at",
    } <= edit_columns
    assert "ix_edits_scan_id" in {ix["name"] for ix in inspector.get_indexes("edits")}

    # Phase C: the builds table (full rebuild history) + edits.build_id FK
    build_columns = {c["name"] for c in inspector.get_columns("builds")}
    assert {
        "id", "scan_id", "status", "stage", "error", "edits_json",
        "artifact_name", "artifact_path", "artifact_sha256",
        "created_at", "finished_at",
    } <= build_columns
    assert "ix_builds_scan_id" in {ix["name"] for ix in inspector.get_indexes("builds")}
    edit_fks = {fk["constrained_columns"][0] for fk in inspector.get_foreign_keys("edits")}
    assert "build_id" in edit_fks  # edits.build_id FK -> builds.id
    engine.dispose()

    command.downgrade(cfg, "0008")
    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "edits" not in inspector.get_table_names()
    assert "builds" not in inspector.get_table_names()
    scan_columns = {c["name"] for c in inspector.get_columns("scans")}
    assert "apktool_status" not in scan_columns
    assert "apktool_error" not in scan_columns
    engine.dispose()


def test_alembic_0013_auth_tables(tmp_path, monkeypatch):
    """M9.1 migration 0013: users + sessions tables, scans.user_id."""
    db_url = f"sqlite:///{tmp_path / 'auth.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

    from sqlalchemy import text

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert {"users", "sessions"} <= tables

    user_columns = {c["name"] for c in inspector.get_columns("users")}
    assert {
        "id", "username", "email", "password_hash", "auth_provider",
        "oauth_id", "is_admin", "is_active", "created_at",
    } <= user_columns
    session_columns = {c["name"] for c in inspector.get_columns("sessions")}
    assert {"id", "user_id", "token_hash", "created_at", "expires_at"} <= session_columns
    assert "ix_sessions_token_hash" in {
        ix["name"] for ix in inspector.get_indexes("sessions")
    }

    # scans.user_id: nullable FK (SQLite can't ALTER-ADD NOT NULL) - the
    # app enforces ownership on every new scan.
    scan_columns = {c["name"] for c in inspector.get_columns("scans")}
    assert "user_id" in scan_columns
    scan_fks = {fk["constrained_columns"][0] for fk in inspector.get_foreign_keys("scans")}
    assert "user_id" in scan_fks
    assert "ix_scans_user_id" in {ix["name"] for ix in inspector.get_indexes("scans")}

    # server_defaults: auth_provider=local, is_admin=0, is_active=1 for raw
    # SQL inserts (the ORM also defaults them).
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, created_at) VALUES "
                "('alice', '2026-08-14T00:00:00')"
            )
        )
        row = conn.execute(
            text("SELECT auth_provider, is_admin, is_active FROM users")
        ).first()
        assert row == ("local", 0, 1)
    engine.dispose()


def test_alembic_0013_downgrade_removes_auth(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'auth-down.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0012")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "users" not in inspector.get_table_names()
    assert "sessions" not in inspector.get_table_names()
    assert "user_id" not in {c["name"] for c in inspector.get_columns("scans")}
    engine.dispose()


def test_alembic_0014_single_admin_index(tmp_path, monkeypatch):
    """M9.1 Phase E: the partial unique index on is_admin - the concurrent
    first-user race's DB backstop (exactly one admin row possible)."""
    from sqlalchemy import text

    db_url = f"sqlite:///{tmp_path / 'single-admin.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    assert "ix_users_single_admin" in {ix["name"] for ix in inspector.get_indexes("users")}

    # The guarantee: a second admin insert fails; a non-admin insert is fine.
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, is_admin, created_at) VALUES "
                "('first', 1, '2026-08-14T00:00:00')"
            )
        )
    with engine.begin() as conn:
        try:
            conn.execute(
                text(
                    "INSERT INTO users (username, is_admin, created_at) VALUES "
                    "('second', 1, '2026-08-14T00:00:00')"
                )
            )
            raise AssertionError("second admin row should violate the index")
        except Exception:
            pass  # IntegrityError - the guarantee held
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, is_admin, created_at) VALUES "
                "('third', 0, '2026-08-14T00:00:00')"
            )
        )

    # Down: the index goes away and two admins become possible again.
    command.downgrade(cfg, "0013")
    inspector = inspect(engine)
    assert "ix_users_single_admin" not in {
        ix["name"] for ix in inspector.get_indexes("users")
    }
    engine.dispose()


def test_alembic_0005_downgrade_removes_suppression_columns(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'suppress-down.db'}"
    monkeypatch.setenv("MOBARK_DATABASE_URL", db_url)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0004")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    finding_columns = {c["name"] for c in inspector.get_columns("findings")}
    assert "suppressed" not in finding_columns
    assert "suppressed_at" not in finding_columns
    engine.dispose()

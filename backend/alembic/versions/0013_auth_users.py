"""M9.1 auth: users + sessions tables, scans.user_id

Revision ID: 0013
Revises: 0012
Create Date: 2026-08-14

Owner decisions (Aug 14, 2026): per-user data isolation lives on the SCAN
row only - ``scans.user_id`` is the single ownership column and everything
downstream (findings, chats, edits, builds, report caches) keys off the
scan id. SQLite cannot ALTER-ADD a NOT NULL column, so ``user_id`` is
**nullable** and the app enforces ownership on every new scan
(``create_scan`` sets it from the current user). NULL rows are the legacy
set: the first registered user's transactional, idempotent
``claim_unowned`` adopts them (fresh installs have no rows; existing
dev/volume DBs get adopted on first registration).

``users.password_hash`` is NULL-able because OAuth-only users (Phase B)
have no local password; ``auth_provider`` defaults to ``local``.
``sessions`` stores only the SHA-256 digest of the opaque cookie token
(``token_hash`` unique) - a DB leak never exposes usable tokens - with a
sliding ``expires_at``.
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        # scrypt$n$r$p$salt$hex$hash_hex; NULL for OAuth-only users (Phase B)
        sa.Column("password_hash", sa.String(length=512), nullable=True),
        # local | github | google
        sa.Column(
            "auth_provider",
            sa.String(length=16),
            nullable=False,
            server_default="local",
        ),
        sa.Column("oauth_id", sa.String(length=255), nullable=True),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # SHA-256 digest of the opaque cookie token - never the raw token.
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"], unique=True)
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])

    # Ownership column - nullable (SQLite cannot ALTER-ADD NOT NULL; the app
    # enforces ownership on every new scan). SQLite also has NO native
    # ALTER ADD COLUMN with a FK, so this goes through the batch copy-and-
    # move strategy (the alembic-documented path for constraint changes on
    # SQLite) - the scans table is rebuilt with the FK in place.
    with op.batch_alter_table("scans") as batch_op:
        batch_op.add_column(
            sa.Column(
                "user_id",
                sa.Integer(),
                sa.ForeignKey(
                    "users.id", ondelete="SET NULL", name="fk_scans_user_id_users"
                ),
                nullable=True,
            )
        )
        batch_op.create_index("ix_scans_user_id", ["user_id"])


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_index("ix_scans_user_id")
        batch_op.drop_column("user_id")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_index("ix_sessions_token_hash", table_name="sessions")
    op.drop_table("sessions")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

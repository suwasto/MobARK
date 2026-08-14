"""M9.1 Phase E hardening: at most one admin row.

Revision ID: 0014
Revises: 0013
Create Date: 2026-08-14

Phase E edge coverage item: "concurrent first-user claim (two racing
registers -> exactly one admin)". The register route's first-user check is
read-then-write (``count_users == 0`` followed by an insert), so two truly
concurrent registrations can BOTH read zero users and BOTH commit an admin
row. The DB layer must be the backstop: a partial UNIQUE index over
``users(is_admin) WHERE is_admin`` permits at most one admin row - the
second concurrent admin insert fails with IntegrityError, and the register
route catches it to re-derive the loser as a non-admin (never a 500, never
two admins).

SQLite and Postgres both support partial indexes; the predicate differs
slightly (``= 1`` vs ``TRUE``), so it is emitted dialect-aware.
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    predicate = "is_admin = 1" if dialect == "sqlite" else "is_admin"
    op.execute(
        f"CREATE UNIQUE INDEX ix_users_single_admin ON users (is_admin) "
        f"WHERE {predicate}"
    )


def downgrade() -> None:
    op.execute("DROP INDEX ix_users_single_admin")

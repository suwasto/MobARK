"""M7: per-scan web research opt-in

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-09

Owner decisions (Aug 9, 2026): web research is two on-demand agent tools
(``web_search`` / ``web_fetch``), gated by **two layers** — the per-scan
opt-in on ``scans.web_research_enabled`` (default **off**; the Agent dock
🌐 toggle + Settings control it) AND an Active search engine
(``SearchStore.active()``, the Settings radio list). This column is the
per-scan privacy gate only — it is engine-agnostic and never starts a
search engine.

Data-only column add with a server default; no rewrite pass needed (every
existing scan defaults to off, which is the safe posture).
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "web_research_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "web_research_enabled")

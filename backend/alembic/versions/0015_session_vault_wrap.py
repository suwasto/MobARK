"""M9.1 vault: sessions gain the wrapped-master-key column.

Revision ID: 0015
Revises: 0014
Create Date: 2026-08-14

The vault stores each user's API keys (BYOK / search) encrypted at rest.
The per-user MASTER key is unwrapped at login from ``key_wrap.json`` and is
then wrapped AGAIN under the raw session token so every guarded request can
recover it from the cookie without asking for the password again. That
per-session wrap lives here: ``sessions.vault_wrap`` (NULL until the vault
is unlocked - local users at login, OAuth users via
``POST /auth/vault/unlock``). Only ciphertext is stored; the token's raw
form is never persisted (only its SHA-256 digest, which cannot be inverted
to unwrap the blob).
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sessions", sa.Column("vault_wrap", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("sessions", "vault_wrap")

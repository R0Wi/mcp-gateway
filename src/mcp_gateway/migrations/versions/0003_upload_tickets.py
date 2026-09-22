"""Add upload_tickets: single-use presigned URLs for the HTTP passthrough.

Minted by the ``gateway_create_upload_url`` MCP tool so model-driven clients
(which never see the gateway's OAuth token) can still upload large files
with a plain ``curl``. Stored as SHA-256 hashes, like access tokens.

A new table only, so ``CREATE TABLE IF NOT EXISTS`` is already safe against
any pre-existing database; no existence guard needed.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-22
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS upload_tickets (
            ticket_hash TEXT PRIMARY KEY,
            backend TEXT NOT NULL,
            path TEXT NOT NULL,
            method TEXT NOT NULL,
            expires_at REAL NOT NULL
        )
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Downgrading this migration is not supported")

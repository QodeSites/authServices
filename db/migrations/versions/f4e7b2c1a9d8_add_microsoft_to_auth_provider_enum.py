"""add microsoft to auth_provider_enum

Revision ID: f4e7b2c1a9d8
Revises: d1a8e23a3a7a
Create Date: 2026-03-16 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f4e7b2c1a9d8'
down_revision: Union[str, None] = 'd1a8e23a3a7a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add MICROSOFT value to the auth_provider_enum PostgreSQL enum type."""
    op.execute("ALTER TYPE auth_provider_enum ADD VALUE IF NOT EXISTS 'MICROSOFT'")


def downgrade() -> None:
    """
    PostgreSQL does not support removing values from an enum type directly.
    To downgrade, you would need to recreate the type without MICROSOFT.
    This is a no-op to avoid data loss; remove manually if needed.
    """
    pass

"""add persistent processed tasks

Revision ID: 5a548b24bf7a
Revises: 93d9e06d9369
Create Date: 2026-09-09
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "5a548b24bf7a"
down_revision: Union[str, Sequence[str], None] = "93d9e06d9369"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "processed_tasks",
        sa.Column("task_hash", sa.String(length=64), nullable=False),
        sa.Column("processed_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("task_hash"),
    )


def downgrade() -> None:
    op.drop_table("processed_tasks")

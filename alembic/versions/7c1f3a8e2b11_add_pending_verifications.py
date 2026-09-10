"""add pending verifications

Revision ID: 7c1f3a8e2b11
Revises: 5a548b24bf7a
Create Date: 2026-09-09
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7c1f3a8e2b11"
down_revision: Union[str, Sequence[str], None] = "5a548b24bf7a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "pending_verifications",
        sa.Column("task_hash", sa.String(length=64), nullable=False),
        sa.Column("proofs_json", sa.Text(), nullable=False),
        sa.Column("gn_weight", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("model_hash", sa.String(length=64), nullable=False),
        sa.Column("output_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("task_hash"),
    )


def downgrade() -> None:
    op.drop_table("pending_verifications")

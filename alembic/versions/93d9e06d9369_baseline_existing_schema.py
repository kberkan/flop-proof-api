"""baseline existing schema

Creates the proofs and proof_events tables, which existed before Alembic was
introduced (they were created by Base.metadata.create_all). This revision was
first an empty marker, so `alembic upgrade head` on an empty database left both
tables out. Databases already at this revision or later do not run it again; a
database built by create_all without an alembic_version table is adopted with
`alembic stamp head`.

Revision ID: 93d9e06d9369
Revises: 
Create Date: 2026-09-09 08:50:33.513576

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '93d9e06d9369'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "proofs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("proof_id", sa.String(length=100), nullable=False),
        sa.Column("request_id", sa.String(length=100), nullable=False),
        sa.Column("version", sa.String(length=10), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_proofs_proof_id", "proofs", ["proof_id"], unique=True)
    op.create_index("ix_proofs_request_id", "proofs", ["request_id"], unique=True)

    op.create_table(
        "proof_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(length=100), nullable=False),
        sa.Column("proof_id", sa.String(length=100), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("actor_did", sa.String(length=500), nullable=False),
        sa.Column("payload_hash", sa.String(length=128), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("canonical", sa.Text(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("previous_event_hash", sa.String(length=128), nullable=True),
        sa.Column("nonce", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_proof_events_event_id", "proof_events", ["event_id"], unique=True)
    op.create_index("ix_proof_events_proof_id", "proof_events", ["proof_id"], unique=False)
    op.create_index("ix_proof_events_nonce", "proof_events", ["nonce"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_proof_events_nonce", table_name="proof_events")
    op.drop_index("ix_proof_events_proof_id", table_name="proof_events")
    op.drop_index("ix_proof_events_event_id", table_name="proof_events")
    op.drop_table("proof_events")
    op.drop_index("ix_proofs_request_id", table_name="proofs")
    op.drop_index("ix_proofs_proof_id", table_name="proofs")
    op.drop_table("proofs")

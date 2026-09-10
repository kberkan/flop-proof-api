from datetime import datetime, timezone

from sqlalchemy import insert
from sqlalchemy.orm import Session

from .models import ProcessedTask


def claim_processed_task(db: Session, task_hash: bytes) -> bool:
    """Atomically claim a task hash in the persistent replay guard."""
    if not isinstance(task_hash, bytes) or len(task_hash) != 32:
        raise ValueError("task_hash must be exactly 32 bytes")

    task_hash_hex = task_hash.hex()

    statement = (
        insert(ProcessedTask)
        .values(
            task_hash=task_hash_hex,
            processed_at=datetime.now(timezone.utc),
        )
        .prefix_with("OR IGNORE")
    )

    result = db.execute(statement)

    if result.rowcount == 1:
        db.commit()
        return True

    db.rollback()
    return False

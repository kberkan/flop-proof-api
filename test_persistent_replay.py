from sqlalchemy import delete, select

from app.database import SessionLocal
from app.models import ProcessedTask
from app.replay import claim_processed_task


def test_persistent_processed_task_claims_once():
    task_hash = bytes.fromhex("33" * 32)

    db = SessionLocal()
    try:
        db.execute(
            delete(ProcessedTask).where(
                ProcessedTask.task_hash == task_hash.hex()
            )
        )
        db.commit()

        assert claim_processed_task(db, task_hash) is True
        assert claim_processed_task(db, task_hash) is False

        stored = db.scalar(
            select(ProcessedTask).where(
                ProcessedTask.task_hash == task_hash.hex()
            )
        )

        assert stored is not None
        assert stored.task_hash == task_hash.hex()
    finally:
        db.close()


def test_persistent_processed_task_rejects_invalid_hash():
    db = SessionLocal()
    try:
        try:
            claim_processed_task(db, b"short")
        except ValueError as exc:
            assert str(exc) == "task_hash must be exactly 32 bytes"
        else:
            raise AssertionError("expected invalid task_hash length to fail")
    finally:
        db.close()


def test_persistent_processed_task_claim_is_atomic_under_concurrency():
    from concurrent.futures import ThreadPoolExecutor

    task_hash = bytes.fromhex("44" * 32)

    cleanup = SessionLocal()
    try:
        cleanup.execute(
            delete(ProcessedTask).where(
                ProcessedTask.task_hash == task_hash.hex()
            )
        )
        cleanup.commit()
    finally:
        cleanup.close()

    def claim():
        db = SessionLocal()
        try:
            return claim_processed_task(db, task_hash)
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: claim(), range(2)))

    assert sorted(results) == [False, True]

    verify_db = SessionLocal()
    try:
        stored = verify_db.scalar(
            select(ProcessedTask).where(
                ProcessedTask.task_hash == task_hash.hex()
            )
        )
        assert stored is not None
    finally:
        verify_db.close()

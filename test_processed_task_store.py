from app.crypto import ProcessedTasks


def test_processed_tasks_claim_is_atomic_at_api_level():
    task_hash = bytes.fromhex("11" * 32)
    processed = ProcessedTasks()

    assert processed.claim(task_hash) is True
    assert processed.claim(task_hash) is False


def test_processed_tasks_claim_rejects_invalid_task_hash():
    processed = ProcessedTasks()

    try:
        processed.claim(b"short")
    except ValueError as exc:
        assert str(exc) == "task_hash must be exactly 32 bytes"
    else:
        raise AssertionError("expected invalid task_hash length to fail")

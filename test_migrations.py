"""The Alembic migrations build the schema the application uses.

`alembic upgrade head` is how a database is created, so it must produce, from
an empty file, exactly the schema of app/models.py (Base.metadata.create_all).
A model change without a matching migration fails here. Alembic runs as a
subprocess, like the CLI, so its logging setup stays out of this process.
"""

import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.canonical import build_request_canonical_v3
from app.crypto import generate_test_keypair, public_key_to_test_did, sign_message

REPO_ROOT = Path(__file__).resolve().parent
API_KEY = "migrations-test-key"


def _alembic(database: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env={**os.environ, "FLOP_DATABASE_URL": f"sqlite:///{database}"},
        capture_output=True,
        text=True,
    )


def _upgrade_head(database: Path) -> None:
    result = _alembic(database, "upgrade", "head")
    assert result.returncode == 0, result.stderr


def _create_all(database: Path) -> None:
    from app import models  # noqa: F401  (registers the tables)
    from app.database import Base

    engine = sa.create_engine(f"sqlite:///{database}")
    Base.metadata.create_all(engine)
    engine.dispose()


def _schema(database: Path) -> dict:
    engine = sa.create_engine(f"sqlite:///{database}")
    inspector = sa.inspect(engine)
    schema = {}
    for table in sorted(inspector.get_table_names()):
        if table == "alembic_version":
            continue
        schema[table] = {
            "columns": [
                (column["name"], str(column["type"]), column["nullable"], column["default"])
                for column in inspector.get_columns(table)
            ],
            "primary_key": inspector.get_pk_constraint(table)["constrained_columns"],
            "indexes": sorted(
                (index["name"], tuple(index["column_names"]), bool(index["unique"]))
                for index in inspector.get_indexes(table)
            ),
            "unique_constraints": sorted(
                tuple(constraint["column_names"]) for constraint in inspector.get_unique_constraints(table)
            ),
            "foreign_keys": sorted(
                (tuple(fk["constrained_columns"]), fk["referred_table"], tuple(fk["referred_columns"]))
                for fk in inspector.get_foreign_keys(table)
            ),
        }
    engine.dispose()
    return schema


def _signed_proof_request() -> dict:
    private_key, public_key = generate_test_keypair()
    nonce = f"migration-{uuid.uuid4().hex}"
    canonical = build_request_canonical_v3("migration-room", nonce, "first proof")
    return {
        "request": {
            "request_id": f"migration-{uuid.uuid4().hex}",
            "from_did": public_key_to_test_did(public_key),
            "text": "first proof",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "signature": {"nonce": nonce, "sig": sign_message(private_key, canonical.encode()), "canonical": canonical},
        }
    }


def test_upgrade_head_schema_matches_models(tmp_path):
    migrated = tmp_path / "migrated.db"
    created = tmp_path / "created.db"
    _upgrade_head(migrated)
    _create_all(created)

    assert _schema(migrated) == _schema(created)


def test_first_post_proofs_on_a_migrated_empty_database_returns_201(tmp_path, monkeypatch):
    from app import main
    from app.database import get_db

    database = tmp_path / "fresh.db"
    _upgrade_head(database)

    engine = sa.create_engine(f"sqlite:///{database}", connect_args={"check_same_thread": False})
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(main, "API_KEY", API_KEY)
    monkeypatch.setitem(main.app.dependency_overrides, get_db, override_get_db)
    try:
        client = TestClient(main.app, headers={"X-API-Key": API_KEY}, raise_server_exceptions=False)
        response = client.post("/proofs", json=_signed_proof_request())
    finally:
        engine.dispose()

    assert response.status_code == 201, response.text


def test_existing_create_all_database_is_adopted_with_stamp_head(tmp_path):
    """A database built by create_all (no alembic_version table) is taken
    over with `alembic stamp head`; a later `upgrade head` changes nothing."""
    database = tmp_path / "existing.db"
    _create_all(database)
    before = _schema(database)

    assert _alembic(database, "stamp", "head").returncode == 0
    _upgrade_head(database)

    assert _schema(database) == before

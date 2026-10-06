"""Request-body fields with protocol meaning accept only their own JSON type.

Pydantic's lax mode coerces true/"5"/5.0 into integers and 1/"true"/"yes"/"on"
into booleans. For fields that enter a signed payload, a task/evidence record
or a tripwire, that coercion is rejected (strict=True, 422). Request
parameters without protocol meaning (GET /proofs ?limit=) are not covered
here; see PARITY.md, "API input typing".
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from test_validator_result_validation import (  # noqa: F401  (registry is a fixture)
    API_KEY,
    _matching_result,
    registry,
)

client = TestClient(app, headers={"X-API-Key": API_KEY}, raise_server_exceptions=False)


@pytest.fixture
def in_memory_db():
    from app import models  # noqa: F401  (registers the tables)
    from app.database import Base, get_db

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    try:
        yield
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous
        engine.dispose()


# --- POST /stark-batches: gn_weight and latency_ms ----------------------------------------

def _stark_batch(**override):
    body = {
        "proofs": [],
        "gn_weight": 5,
        "task_hash": uuid.uuid4().hex * 2,
        "latency_ms": 5,
        "model_hash": "22" * 32,
        "output_hash": "33" * 32,
    }
    body.update(override)
    return body


def test_stark_batch_accepts_json_integers(in_memory_db):
    """Control: the same body with integers is accepted."""
    response = client.post("/stark-batches", json=_stark_batch())

    assert response.status_code == 200, response.text


@pytest.mark.parametrize("field", ["gn_weight", "latency_ms"])
@pytest.mark.parametrize(
    "value",
    [
        pytest.param(True, id="true"),
        pytest.param("5", id="string-5"),
        pytest.param(5.0, id="float-5.0"),
    ],
)
def test_stark_batch_integer_fields_reject_non_integers_with_422(in_memory_db, field, value):
    response = client.post("/stark-batches", json=_stark_batch(**{field: value}))

    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["loc"][-1] == field


# --- validator attestations: quote_verified and event_log_verified -------------------------

@pytest.mark.parametrize("field", ["quote_verified", "event_log_verified"])
@pytest.mark.parametrize(
    "value",
    [
        pytest.param(1, id="int-1"),
        pytest.param("true", id="string-true"),
        pytest.param("yes", id="string-yes"),
    ],
)
def test_attestation_boolean_fields_reject_non_booleans_with_422(registry, field, value):  # noqa: F811
    attestation, report_data = registry

    response = client.post(
        "/validator-attestations/accept",
        json={
            "result": _matching_result(),
            "report_data": report_data,
            "attestations": [{**attestation, field: value}],
        },
    )

    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["loc"][-1] == field

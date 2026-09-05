from fastapi.testclient import TestClient

import app.main as main


def test_http_rate_limit_returns_429(monkeypatch):
    monkeypatch.setattr(main, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(main.rate_limiter, "max_requests", 2)
    monkeypatch.setattr(main.rate_limiter, "window_seconds", 60)
    main.rate_limiter.reset()

    client = TestClient(main.app)
    headers = {"X-API-Key": main.API_KEY}

    response1 = client.get("/proofs?limit=1", headers=headers)
    response2 = client.get("/proofs?limit=1", headers=headers)
    response3 = client.get("/proofs?limit=1", headers=headers)

    assert response1.status_code == 200
    assert response2.status_code == 200
    assert response3.status_code == 429
    assert response3.json() == {"detail": "Rate limit exceeded"}
    assert "Retry-After" in response3.headers

    main.rate_limiter.reset()

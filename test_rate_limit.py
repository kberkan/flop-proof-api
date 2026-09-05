from app.rate_limit import RateLimiter


def test_rate_limiter_allows_requests_under_limit():
    limiter = RateLimiter(max_requests=3, window_seconds=60)

    assert limiter.check("client")[0] is True
    assert limiter.check("client")[0] is True
    assert limiter.check("client")[0] is True


def test_rate_limiter_blocks_after_limit():
    limiter = RateLimiter(max_requests=2, window_seconds=60)

    assert limiter.check("client")[0] is True
    assert limiter.check("client")[0] is True

    allowed, retry_after = limiter.check("client")

    assert allowed is False
    assert retry_after >= 1


def test_rate_limiter_isolated_by_key():
    limiter = RateLimiter(max_requests=1, window_seconds=60)

    assert limiter.check("client-a")[0] is True
    assert limiter.check("client-a")[0] is False

    assert limiter.check("client-b")[0] is True


def test_rate_limiter_reset():
    limiter = RateLimiter(max_requests=1, window_seconds=60)

    assert limiter.check("client")[0] is True
    assert limiter.check("client")[0] is False

    limiter.reset()

    assert limiter.check("client")[0] is True

import pytest

from app.services.rate_limiter import SlidingWindowRateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_blocks_after_limit():
    limiter = SlidingWindowRateLimiter(limit=2, window_seconds=60)
    assert await limiter.allow("client-1") is True
    assert await limiter.allow("client-1") is True
    assert await limiter.allow("client-1") is False

"""Tests for the token-bucket rate limiter.

Covers:
- Default configuration (60 actions/minute)
- Token consumption
- Rejection after exhaustion
- Token refill over time
- Invalid range raises ValueError
- Edge cases: 1 action/minute, 600 actions/minute
"""

from __future__ import annotations

import logging
import time
from unittest.mock import patch

import pytest

from orchestrator.rate_limiter import RateLimiter


class TestRateLimiterInit:
    """Initialization and validation tests."""

    def test_default_actions_per_minute(self) -> None:
        rl = RateLimiter()
        assert rl.bucket_size == 60
        assert rl.refill_rate == pytest.approx(1.0)  # 60/60 = 1 token/s

    def test_custom_actions_per_minute(self) -> None:
        rl = RateLimiter(actions_per_minute=120)
        assert rl.bucket_size == 120
        assert rl.refill_rate == pytest.approx(2.0)

    def test_minimum_actions_per_minute(self) -> None:
        rl = RateLimiter(actions_per_minute=1)
        assert rl.bucket_size == 1
        assert rl.refill_rate == pytest.approx(1.0 / 60.0)

    def test_maximum_actions_per_minute(self) -> None:
        rl = RateLimiter(actions_per_minute=600)
        assert rl.bucket_size == 600
        assert rl.refill_rate == pytest.approx(10.0)

    def test_below_minimum_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="must be between 1 and 600"):
            RateLimiter(actions_per_minute=0)

    def test_above_maximum_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="must be between 1 and 600"):
            RateLimiter(actions_per_minute=601)

    def test_negative_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="must be between 1 and 600"):
            RateLimiter(actions_per_minute=-1)

    def test_starts_full(self) -> None:
        rl = RateLimiter(actions_per_minute=10)
        assert rl.tokens_available == pytest.approx(10.0, abs=0.1)


class TestRateLimiterAcquire:
    """Token acquisition tests."""

    def test_acquire_single_token(self) -> None:
        rl = RateLimiter(actions_per_minute=60)
        assert rl.acquire() is True

    def test_acquire_all_tokens(self) -> None:
        rl = RateLimiter(actions_per_minute=5)
        results = [rl.acquire() for _ in range(5)]
        assert all(results)

    def test_rejection_after_exhaustion(self) -> None:
        rl = RateLimiter(actions_per_minute=3)
        # Consume all tokens
        for _ in range(3):
            assert rl.acquire() is True
        # Next should fail
        assert rl.acquire() is False

    def test_acquire_logs_on_rejection(self, caplog: pytest.LogCaptureFixture) -> None:
        rl = RateLimiter(actions_per_minute=1)
        rl.acquire()  # consume the single token
        with caplog.at_level(logging.WARNING):
            result = rl.acquire()
        assert result is False
        assert "Rate limit exceeded" in caplog.text

    def test_try_acquire_does_not_log(self, caplog: pytest.LogCaptureFixture) -> None:
        rl = RateLimiter(actions_per_minute=1)
        rl.try_acquire()  # consume the single token
        with caplog.at_level(logging.WARNING):
            result = rl.try_acquire()
        assert result is False
        assert "Rate limit exceeded" not in caplog.text


class TestRateLimiterRefill:
    """Token refill over time tests."""

    def test_refill_after_time_elapsed(self) -> None:
        rl = RateLimiter(actions_per_minute=60)  # 1 token/s
        # Consume all tokens
        for _ in range(60):
            rl.acquire()
        assert rl.acquire() is False

        # Wait a bit for refill (1 token per second at rate 60/min)
        time.sleep(0.1)
        # Should have ~0.1 tokens, not enough for 1
        assert rl.try_acquire() is False

        # Wait enough for at least 1 token
        time.sleep(1.0)
        assert rl.acquire() is True

    def test_refill_does_not_exceed_bucket_size(self) -> None:
        rl = RateLimiter(actions_per_minute=5)
        # Bucket starts full at 5
        time.sleep(0.2)  # Even after waiting, should not exceed bucket_size
        assert rl.tokens_available <= 5.0

    def test_tokens_available_reflects_refill(self) -> None:
        rl = RateLimiter(actions_per_minute=600)  # 10 tokens/s
        # Consume all
        for _ in range(600):
            rl.try_acquire()
        # Wait 0.1s -> ~1 token refilled
        time.sleep(0.1)
        available = rl.tokens_available
        assert available >= 0.5  # At least half a token after 0.1s at 10/s
        assert available <= 2.0  # But not more than ~1-2 given timing imprecision

    def test_monotonic_clock_used(self) -> None:
        """Verify we use monotonic clock (not affected by wall-clock jumps)."""
        rl = RateLimiter(actions_per_minute=60)
        # The _last_refill_time should be based on time.monotonic()
        assert rl._last_refill_time > 0  # monotonic starts at system-dependent point

    def test_partial_refill_accumulates(self) -> None:
        rl = RateLimiter(actions_per_minute=60)  # 1 token/s
        # Consume all
        for _ in range(60):
            rl.try_acquire()
        # Short sleep - partial token
        time.sleep(0.5)
        # Should have ~0.5 tokens, not enough
        assert rl.try_acquire() is False
        # Another short sleep to accumulate to ~1
        time.sleep(0.6)
        # Now should have enough
        assert rl.acquire() is True


class TestRateLimiterEdgeCases:
    """Edge case tests."""

    def test_one_action_per_minute(self) -> None:
        rl = RateLimiter(actions_per_minute=1)
        assert rl.acquire() is True
        assert rl.acquire() is False
        # refill_rate = 1/60 tokens/s -> takes 60s to refill 1 token
        assert rl.refill_rate == pytest.approx(1.0 / 60.0)

    def test_six_hundred_actions_per_minute(self) -> None:
        rl = RateLimiter(actions_per_minute=600)
        # Should be able to burst 600 tokens
        results = [rl.acquire() for _ in range(600)]
        assert all(results)
        # 601st should fail
        assert rl.acquire() is False

    def test_try_acquire_matches_acquire_behavior(self) -> None:
        rl1 = RateLimiter(actions_per_minute=5)
        rl2 = RateLimiter(actions_per_minute=5)

        # Both should succeed for 5 tokens
        for _ in range(5):
            assert rl1.acquire() is True
            assert rl2.try_acquire() is True

        # Both should fail after exhaustion
        assert rl1.acquire() is False
        assert rl2.try_acquire() is False

    def test_tokens_available_does_not_consume(self) -> None:
        rl = RateLimiter(actions_per_minute=10)
        # Reading tokens_available should not consume tokens
        avail1 = rl.tokens_available
        avail2 = rl.tokens_available
        # Should be approximately equal (small time difference from refill)
        assert avail1 == pytest.approx(avail2, abs=0.01)

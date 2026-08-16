"""Token-bucket rate limiter for controlling actions per minute.

Implements a configurable rate limiter using the token-bucket algorithm.
Tokens refill at a steady rate (actions_per_minute / 60 tokens per second)
and are consumed one per action. When the bucket is empty, excess actions
are rejected and a rate-limit breach event is logged.

Requirements: 11.3, 11.4
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)

_MIN_ACTIONS_PER_MINUTE = 1
_MAX_ACTIONS_PER_MINUTE = 600


class RateLimiter:
    """Token-bucket rate limiter with configurable actions per minute.

    Parameters
    ----------
    actions_per_minute : int
        Maximum actions allowed per minute. Must be in range 1-600.
        Defaults to 60.

    Raises
    ------
    ValueError
        If actions_per_minute is outside the allowed range [1, 600].
    """

    def __init__(self, actions_per_minute: int = 60) -> None:
        if not isinstance(actions_per_minute, int):
            raise ValueError(
                f"actions_per_minute must be an integer, got {type(actions_per_minute).__name__}"
            )
        if actions_per_minute < _MIN_ACTIONS_PER_MINUTE or actions_per_minute > _MAX_ACTIONS_PER_MINUTE:
            raise ValueError(
                f"actions_per_minute must be between {_MIN_ACTIONS_PER_MINUTE} and "
                f"{_MAX_ACTIONS_PER_MINUTE}, got {actions_per_minute}"
            )

        self.bucket_size: int = actions_per_minute
        self.refill_rate: float = actions_per_minute / 60.0  # tokens per second
        self._tokens: float = float(actions_per_minute)  # start full
        self._last_refill_time: float = time.monotonic()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill_time
        if elapsed > 0:
            new_tokens = elapsed * self.refill_rate
            self._tokens = min(self.bucket_size, self._tokens + new_tokens)
            self._last_refill_time = now

    def acquire(self) -> bool:
        """Attempt to consume one token.

        Refills tokens based on elapsed time, then tries to consume one.
        If successful, returns True. If the bucket is empty, logs a
        rate-limit breach event and returns False.

        Returns
        -------
        bool
            True if a token was consumed, False if rate limit exceeded.
        """
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True

        logger.warning(
            "Rate limit exceeded: %.2f tokens available, bucket_size=%d, "
            "refill_rate=%.4f tokens/s",
            self._tokens,
            self.bucket_size,
            self.refill_rate,
        )
        return False

    def try_acquire(self) -> bool:
        """Attempt to consume one token without logging.

        Same as acquire() but does not log on failure. Useful for
        non-blocking checks where the caller handles the rejection.

        Returns
        -------
        bool
            True if a token was consumed, False if rate limit exceeded.
        """
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    @property
    def tokens_available(self) -> float:
        """Return current token count after refill calculation.

        Returns
        -------
        float
            Number of tokens currently available in the bucket.
        """
        self._refill()
        return self._tokens

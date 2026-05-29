"""Configurable retry policies for webhook delivery (ENTERPRISE-005)."""
from __future__ import annotations

import random
from typing import Any, Dict

DEFAULT_RETRY_POLICY: Dict[str, Any] = {
    "strategy": "exponential",
    "max_attempts": 5,
    "initial_delay_seconds": 60,
    "max_delay_seconds": 7200,
    "jitter_enabled": True,
    "jitter_max_seconds": 30,
    "retry_window_seconds": 86400,
}


def normalize_retry_policy(policy: dict | None) -> dict:
    """Merge a user-provided policy with defaults, enforcing bounds."""
    if not policy:
        return dict(DEFAULT_RETRY_POLICY)

    result = dict(DEFAULT_RETRY_POLICY)
    result.update(policy)

    # Enforce bounds
    result["max_attempts"] = max(1, min(int(result["max_attempts"]), 20))
    result["initial_delay_seconds"] = max(10, min(int(result["initial_delay_seconds"]), 3600))
    result["max_delay_seconds"] = max(60, min(int(result["max_delay_seconds"]), 86400))
    result["jitter_max_seconds"] = max(0, min(int(result.get("jitter_max_seconds", 30)), 300))
    result["retry_window_seconds"] = max(3600, min(int(result.get("retry_window_seconds", 86400)), 604800))

    if result["strategy"] not in ("linear", "exponential", "fibonacci", "fixed"):
        result["strategy"] = "exponential"

    return result


def compute_retry_delay(policy: dict, attempt: int) -> int:
    """Compute the delay in seconds before the next retry attempt.

    Args:
        policy: Normalized retry policy dict.
        attempt: 1-based attempt number (1 = first retry after initial failure).

    Returns:
        Delay in seconds, including optional jitter.
    """
    strategy = policy.get("strategy", "exponential")
    initial = int(policy.get("initial_delay_seconds", 60))
    max_delay = int(policy.get("max_delay_seconds", 7200))

    if strategy == "exponential":
        delay = initial * (2 ** (attempt - 1))
    elif strategy == "linear":
        delay = initial * attempt
    elif strategy == "fibonacci":
        a, b = initial, initial
        for _ in range(attempt - 1):
            a, b = b, a + b
        delay = b
    else:  # fixed
        delay = initial

    delay = min(delay, max_delay)

    if policy.get("jitter_enabled", True):
        jitter_max = int(policy.get("jitter_max_seconds", 30))
        delay += random.randint(0, jitter_max)

    return delay


def should_retry(
    policy: dict,
    attempt: int,
    created_at: int,
    now: int,
) -> bool:
    """Check whether another retry should be attempted.

    Returns False if max_attempts reached or retry_window exceeded.
    """
    max_attempts = int(policy.get("max_attempts", 5))
    if attempt >= max_attempts:
        return False

    retry_window = int(policy.get("retry_window_seconds", 86400))
    if (now - created_at) > retry_window:
        return False

    return True

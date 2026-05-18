#!/usr/bin/env python3
from __future__ import annotations

import json
import os

from app.services.newsfeed_scheduler import run_scheduler_loop, scheduler_summary_has_failures


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    interval_seconds = max(0.1, _env_float("NEWSFEED_SCHEDULER_INTERVAL_SECONDS", 5.0))
    iterations = max(1, _env_int("NEWSFEED_SCHEDULER_ITERATIONS", 1))
    page_limit = max(1, _env_int("NEWSFEED_SCHEDULER_PAGE_LIMIT", 50))
    max_batches = max(1, _env_int("NEWSFEED_SCHEDULER_MAX_BATCHES", 1))
    publish_retry_max = max(0, _env_int("NEWSFEED_SCHEDULER_PUBLISH_RETRY_MAX", 3))
    retry_backoff_seconds = max(0.01, _env_float("NEWSFEED_SCHEDULER_RETRY_BACKOFF_SECONDS", 0.25))
    fail_on_errors = _env_bool("NEWSFEED_SCHEDULER_FAIL_ON_ERRORS", False)

    summaries = run_scheduler_loop(
        interval_seconds=interval_seconds,
        iterations=iterations,
        page_limit=page_limit,
        max_batches=max_batches,
        publish_retry_max=publish_retry_max,
        retry_backoff_seconds=retry_backoff_seconds,
    )
    has_failures = any(scheduler_summary_has_failures(summary) for summary in summaries)
    print(
        json.dumps(
            {
                "runs": summaries,
                "has_failures": has_failures,
                "config": {
                    "interval_seconds": interval_seconds,
                    "iterations": iterations,
                    "page_limit": page_limit,
                    "max_batches": max_batches,
                    "publish_retry_max": publish_retry_max,
                    "retry_backoff_seconds": retry_backoff_seconds,
                    "fail_on_errors": fail_on_errors,
                },
            },
            sort_keys=True,
        )
    )
    if fail_on_errors and has_failures:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

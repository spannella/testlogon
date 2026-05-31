"""Scheduled account-deletion processor (PLATFORM-018).

Background task that periodically processes account-deletion requests whose
grace period has expired. Finalization itself lives in
``app.services.account_deletion.process_due_deletions`` so that E2E tests can
drive it deterministically via the admin "process-due" endpoint without
waiting on the timer.

The background loop is disabled by default in dev/test
(``S.account_deletion_scheduler_enabled``) to keep test runs deterministic.
"""

from __future__ import annotations

import asyncio
import logging

from app.core.settings import S
from app.services.account_deletion import process_due_deletions

logger = logging.getLogger(__name__)


async def run_deletion_scanner_loop() -> None:
    if not S.account_deletion_scheduler_enabled:
        logger.info("Account deletion scheduler disabled")
        return
    interval = max(60, int(S.account_deletion_scheduler_interval_seconds))
    logger.info("Account deletion scheduler started (interval=%ds)", interval)
    while True:
        try:
            processed, skipped, _ = process_due_deletions()
            if processed or skipped:
                logger.info("Deletion scanner: processed=%d skipped=%d", processed, skipped)
        except Exception:  # noqa: BLE001
            logger.exception("Deletion scanner error")
        await asyncio.sleep(interval)


def start_deletion_scheduler_task() -> None:
    """FastAPI startup hook: launch the background scanner if enabled."""
    if not S.account_deletion_scheduler_enabled:
        logger.info("Account deletion scheduler not started (disabled)")
        return
    try:
        asyncio.get_event_loop().create_task(run_deletion_scanner_loop())
    except RuntimeError:
        # No running loop yet -- schedule on the current loop policy.
        asyncio.ensure_future(run_deletion_scanner_loop())

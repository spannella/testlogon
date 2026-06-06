"""KYC ongoing-monitoring background schedulers (GAP-0276 / KYC-016).

The review-checker and re-screening enforcement logic lives in
``app.services.kyc_monitoring`` (``run_review_checker`` / ``run_rescreening``).
Those functions were fully implemented but never launched as background tasks —
they could only be triggered manually via the admin HTTP endpoints. As a result
overdue reviews were never auto-detected and tier downgrades never fired, and
the sanctions re-screening (a compliance obligation) was inert.

This module wires the existing service functions into two in-process asyncio
loops, registered at FastAPI startup from ``app/main.py`` — mirroring the
established ``start_kyc_sla_checker_task`` pattern in
``app.services.kyc_case_assignment``. The loops run identically in dev and prod
(SECOPS-007 parity): the same ``run_review_checker`` / ``run_rescreening``
functions are invoked, hitting DynamoDB Local in dev and real DynamoDB in prod.

Intervals are env-configurable; the re-screening loop is additionally gated on
``S.kyc_rescreening_enabled``. Neither loop ever raises out of the loop body.
"""
from __future__ import annotations

import asyncio
import logging
import os

from app.core.settings import S
from app.services.kyc_monitoring import run_rescreening, run_review_checker

logger = logging.getLogger(__name__)

# Review-checker runs every 6h, re-screening every 24h, by default.
_KYC_REVIEW_CHECKER_INTERVAL_SECONDS = int(
    os.environ.get("KYC_REVIEW_CHECKER_INTERVAL_SECONDS", str(6 * 3600))
)
_KYC_RESCREENING_INTERVAL_SECONDS = int(
    os.environ.get("KYC_RESCREENING_INTERVAL_SECONDS", str(24 * 3600))
)


async def _kyc_review_checker_loop() -> None:
    """Periodically run the review-checker (grace-period / auto-downgrade).

    Never raises out of the loop — per-iteration errors are logged and the loop
    continues.
    """
    interval = max(60, _KYC_REVIEW_CHECKER_INTERVAL_SECONDS)
    while True:
        try:
            results = run_review_checker()
            logger.info(
                "kyc.monitoring.review_checker_loop completed "
                "entered_grace=%d auto_downgraded=%d",
                results.get("entered_grace_period", 0),
                results.get("auto_downgraded", 0),
            )
        except Exception:  # pragma: no cover - defensive
            logger.exception("kyc.monitoring.review_checker_loop_error")
        await asyncio.sleep(interval)


async def _kyc_rescreening_loop() -> None:
    """Periodically re-screen approved users against sanctions lists.

    Gated on ``S.kyc_rescreening_enabled`` (re-checked each iteration so the
    flag can be flipped without restart). Never raises out of the loop.
    """
    interval = max(300, _KYC_RESCREENING_INTERVAL_SECONDS)
    while True:
        try:
            if S.kyc_rescreening_enabled:
                results = run_rescreening()
                logger.info(
                    "kyc.monitoring.rescreening_loop completed "
                    "screened=%d matches=%d triggers=%d",
                    results.get("total_screened", 0),
                    results.get("matches_found", 0),
                    results.get("triggers_created", 0),
                )
        except Exception:  # pragma: no cover - defensive
            logger.exception("kyc.monitoring.rescreening_loop_error")
        await asyncio.sleep(interval)


def kyc_monitoring_startup() -> None:
    """Register the KYC review-checker and re-screening background loops.

    Registered via ``app.add_event_handler("startup", kyc_monitoring_startup)``
    in ``app/main.py``. The re-screening loop is only scheduled when
    ``S.kyc_rescreening_enabled`` is set; the review-checker is core enforcement
    and always runs (when the review-schedule table is configured).
    """
    if not S.kyc_review_schedule_table_name:
        logger.warning(
            "kyc.monitoring: kyc_review_schedule table not configured, "
            "skipping monitoring loops"
        )
        return

    asyncio.ensure_future(_kyc_review_checker_loop())
    if S.kyc_rescreening_enabled:
        asyncio.ensure_future(_kyc_rescreening_loop())

    logger.info(
        "KYC monitoring loops started (review_checker interval=%ds, "
        "rescreening interval=%ds, rescreening_enabled=%s)",
        _KYC_REVIEW_CHECKER_INTERVAL_SECONDS,
        _KYC_RESCREENING_INTERVAL_SECONDS,
        S.kyc_rescreening_enabled,
    )

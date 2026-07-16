"""ECOMX-30 — background shipment-tracking progression runner.

Honest "advance for real" driver for the seller ship-group shipment_tracking
records, modelled on the payout runner:

  * When EasyPost is configured (EASYPOST_API_KEY) and a shipment carries an
    ``easypost_tracker_id``, the runner POLLS the real EasyPost Tracker and
    applies its status through ``shipment_tracking.advance`` (the same path the
    ``tracker.updated`` webhook uses).
  * When EasyPost is NOT configured (prod-mock), the runner drives the internal
    mock progression forward one step per cycle (label_created -> in_transit ->
    out_for_delivery -> delivered) — so a shipped order reaches "delivered"
    WITHOUT an admin clicking simulate, while the buyer delivery pushes still
    fire exactly once via the ``advance`` -> ``_claim_notify_with_retry`` guard.

Both drivers funnel through ``shipment_tracking.run_progression_once`` so the
timer and the admin run-now endpoint share one code path. Disabled unless
``shipment_progression_enabled`` is set; the run-now endpoint is always the
deterministic trigger for tests.
"""
from __future__ import annotations

import asyncio
import logging

from app.core.settings import S
from app.services import shipment_tracking as st

logger = logging.getLogger(__name__)


def run_now(limit: int | None = None) -> dict:
    """Synchronous one-shot progression pass (deterministic; used by the admin
    run-now endpoint and by verification harnesses)."""
    cap = int(limit or S.shipment_progression_batch_size)
    return st.run_progression_once(limit=cap)


async def shipment_progression_loop() -> None:
    interval = max(5, int(S.shipment_progression_interval_seconds))
    logger.info("shipment progression runner started (interval=%ds)", interval)
    while True:
        try:
            summary = st.run_progression_once(limit=int(S.shipment_progression_batch_size))
            if summary.get("advanced"):
                logger.info("shipment progression: %s", summary)
        except Exception:
            logger.exception("shipment progression cycle failed")
        await asyncio.sleep(interval)


def start_shipment_progression_task() -> None:
    """Register the progression loop as an asyncio background task. No-op unless
    ``shipment_progression_enabled`` is set (the run-now endpoint is the primary
    deterministic trigger)."""
    if not getattr(S, "shipment_progression_enabled", False):
        return
    asyncio.create_task(shipment_progression_loop())

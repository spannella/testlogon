from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from boto3.dynamodb.conditions import Attr

from app.core.settings import S
from app.core.tables import T

logger = logging.getLogger(__name__)

_RESET_ATTR = "spent_today_cents"
_LAST_RESET_ATTR = "last_reset_date"


def _today_utc() -> str:
    """Return today's UTC date as an ISO date string (YYYY-MM-DD)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _seconds_until_midnight_utc() -> float:
    """Seconds remaining until the next UTC midnight (always in (0, 86400])."""
    now = datetime.now(timezone.utc)
    next_midnight = (now + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return (next_midnight - now).total_seconds()


def _reset_daily_spend_once() -> int:
    """Zero ``spent_today_cents`` for all daily-budget campaigns.

    Idempotent within a single UTC day: each campaign carries a
    ``last_reset_date`` guard, and a ``ConditionExpression`` ensures a campaign
    that was already reset today (or already at zero) is skipped. Returns the
    number of campaigns actually reset.
    """
    today = _today_utc()
    count = 0
    last_key = None
    while True:
        scan_kwargs: dict = {
            "FilterExpression": Attr("budget_type").eq("daily")
            & (Attr(_RESET_ATTR).gt(0) | Attr(_LAST_RESET_ATTR).ne(today)),
        }
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        resp = T.ad_campaigns.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            try:
                T.ad_campaigns.update_item(
                    Key={"pk": item["pk"], "sk": item["sk"]},
                    UpdateExpression=(
                        f"SET {_RESET_ATTR} = :zero, {_LAST_RESET_ATTR} = :today"
                    ),
                    ConditionExpression=Attr(_LAST_RESET_ATTR).ne(today),
                    ExpressionAttributeValues={":zero": 0, ":today": today},
                )
                count += 1
            except T.ad_campaigns.meta.client.exceptions.ConditionalCheckFailedException:
                # Already reset today by a concurrent/prior run — no-op.
                pass
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return count


async def _daily_reset_loop() -> None:
    """Background loop: wait until UTC midnight, then reset all daily budgets."""
    while True:
        sleep_secs = _seconds_until_midnight_utc()
        logger.info(
            "ad daily reset: sleeping %.0f s until next UTC midnight", sleep_secs
        )
        await asyncio.sleep(sleep_secs)
        try:
            n = _reset_daily_spend_once()
            logger.info("ad daily reset: reset %d campaigns", n)
        except Exception:
            logger.exception("ad daily reset: unhandled error during reset")


def start_ad_daily_reset_task() -> None:
    """Startup handler: schedule the daily-reset background loop."""
    if not S.ad_serving_enabled:
        logger.info("ad daily reset disabled (ad_serving_enabled=False)")
        return
    asyncio.ensure_future(_daily_reset_loop())

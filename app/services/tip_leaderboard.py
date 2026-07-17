"""Tip leaderboard aggregation and pre-computation service (SOCIAL-005).

Reads billing ledger credit entries for a creator, aggregates by tipper,
and produces ranked supporter lists.  Pre-computed data is stored in the
billing table using a BOARD# prefix key pattern with DynamoDB TTL for
automatic cleanup.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

SUPPORTED_PERIODS: Dict[str, int] = {"7d": 7 * 86400, "30d": 30 * 86400, "all": 0}
BOARD_TTL_SECONDS = 86400  # 24-hour TTL on pre-computed data
MAX_SUPPORTERS = 50  # Store top 50 per period


def _to_int(val: Any) -> int:
    """Coerce DynamoDB Decimal / string / int to int."""
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return 0


def aggregate_tips_for_creator(creator_id: str, period: str) -> List[Dict[str, Any]]:
    """Query billing credits for *creator_id*, aggregate by tipper.

    Scans ``USER#{creator_id}`` LEDGER entries with reason starting with
    ``"Tip"`` and ``type == "credit"``.  Groups by ``meta.tipper_user_id``,
    sums ``amount_cents``.

    Returns a list sorted by total_cents descending, capped at
    ``MAX_SUPPORTERS``.
    """
    pk = f"USER#{creator_id}"
    now = now_ts()
    period_seconds = SUPPORTED_PERIODS.get(period, 0)

    # Build key condition with time range
    if period_seconds > 0:
        cutoff_ts = now - period_seconds
        key_cond = Key("pk").eq(pk) & Key("sk").between(
            f"LEDGER#{cutoff_ts}", "LEDGER#9999999999z"
        )
    else:
        key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")

    # TIPX-A6/D2: exclude reversed credits so a refunded tip drops from the
    # leaderboard (reverse_tip flips the original credit to state="reversed").
    filter_expr = Attr("type").eq("credit") & Attr("reason").begins_with("Tip") & Attr("state").ne("reversed")

    # Aggregate by tipper
    tipper_totals: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"total_cents": 0, "tip_count": 0, "last_tip_at": 0}
    )

    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": filter_expr,
    }

    while True:
        resp = T.billing.query(**query_kwargs)
        for item in resp.get("Items", []):
            meta = item.get("meta", {})
            tipper_id = meta.get("tipper_user_id", "")
            if not tipper_id:
                continue
            amount = _to_int(item.get("amount_cents", 0))
            ts = _to_int(item.get("ts", 0))
            entry = tipper_totals[tipper_id]
            entry["total_cents"] += amount
            entry["tip_count"] += 1
            entry["last_tip_at"] = max(entry["last_tip_at"], ts)

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    # Sort by total_cents descending, cap at MAX_SUPPORTERS
    ranked = sorted(
        [{"user_id": uid, **data} for uid, data in tipper_totals.items()],
        key=lambda x: (-x["total_cents"], x["user_id"]),
    )[:MAX_SUPPORTERS]

    return ranked


def write_leaderboard(creator_id: str, period: str, supporters: List[Dict[str, Any]]) -> None:
    """Write pre-computed leaderboard to the billing table."""
    now = now_ts()
    total_cents = sum(_to_int(s.get("total_cents", 0)) for s in supporters)
    T.billing.put_item(Item={
        "pk": f"BOARD#{creator_id}",
        "sk": f"PERIOD#{period}",
        "supporters": supporters,
        "total_tip_cents": total_cents,
        "total_supporters": len(supporters),
        "computed_at": now,
        "ttl_epoch": now + BOARD_TTL_SECONDS,
    })


def get_leaderboard(
    creator_id: str,
    period: str,
    limit: int = 10,
    viewer_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Read pre-computed leaderboard.  Falls back to on-demand computation."""
    resp = T.billing.get_item(Key={
        "pk": f"BOARD#{creator_id}",
        "sk": f"PERIOD#{period}",
    })
    item = resp.get("Item")

    if not item or (now_ts() - _to_int(item.get("computed_at", 0)) > BOARD_TTL_SECONDS):
        # Fallback: compute on demand
        supporters = aggregate_tips_for_creator(creator_id, period)
        write_leaderboard(creator_id, period, supporters)
        item = {
            "supporters": supporters,
            "total_tip_cents": sum(_to_int(s.get("total_cents", 0)) for s in supporters),
            "total_supporters": len(supporters),
            "computed_at": now_ts(),
        }

    supporters = (item.get("supporters") or [])[:limit]

    # Enrich with display names / avatars
    enriched = []
    for i, s in enumerate(supporters):
        user_id = s.get("user_id", "")
        display_name = user_id  # fallback
        avatar_url = None
        try:
            from app.services.profile import get_profile
            profile = get_profile(user_id) or {}
            display_name = profile.get("display_name") or user_id
            avatar_url = profile.get("profile_photo_url")
        except Exception:
            pass
        enriched.append({
            "rank": i + 1,
            "user_id": user_id,
            "display_name": display_name,
            "avatar_url": avatar_url,
            "total_cents": _to_int(s.get("total_cents", 0)),
            "tip_count": _to_int(s.get("tip_count", 0)),
            "last_tip_at": _to_int(s.get("last_tip_at", 0)),
        })

    return {
        "creator_id": creator_id,
        "period": period,
        "supporters": enriched,
        "total_tip_cents": _to_int(item.get("total_tip_cents", 0)),
        "total_supporters": _to_int(item.get("total_supporters", 0)),
        "computed_at": _to_int(item.get("computed_at", 0)),
    }


def refresh_creator_leaderboard(creator_id: str) -> Dict[str, Any]:
    """Recompute all periods for a single creator."""
    periods_updated = 0
    for period in SUPPORTED_PERIODS:
        supporters = aggregate_tips_for_creator(creator_id, period)
        write_leaderboard(creator_id, period, supporters)
        periods_updated += 1
    return {"creators_processed": 1, "periods_updated": periods_updated}


def refresh_all_leaderboards() -> Dict[str, Any]:
    """Background job: find creators with recent tips, recompute all periods.

    Scans for BOARD# items in the billing table to find creators that have
    been processed before.  Bounded to 100 creators per cycle.
    """
    import time

    start = time.monotonic()
    # Collect distinct creator IDs from existing BOARD# items
    creator_ids: set[str] = set()
    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": Key("pk").begins_with("BOARD#"),
        "ProjectionExpression": "pk",
        "Limit": 1000,
    }
    try:
        while len(creator_ids) < 100:
            resp = T.billing.scan(**scan_kwargs)
            for item in resp.get("Items", []):
                pk_val = item.get("pk", "")
                if pk_val.startswith("BOARD#"):
                    creator_ids.add(pk_val[len("BOARD#"):])
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
    except Exception:
        logger.exception("tip_leaderboard_refresh_scan_failed")

    periods_updated = 0
    for cid in creator_ids:
        try:
            result = refresh_creator_leaderboard(cid)
            periods_updated += result["periods_updated"]
        except Exception:
            logger.warning("tip_leaderboard_refresh_failed creator=%s", cid)

    duration = round(time.monotonic() - start, 2)
    return {
        "ok": True,
        "creators_processed": len(creator_ids),
        "periods_updated": periods_updated,
        "duration_seconds": duration,
    }

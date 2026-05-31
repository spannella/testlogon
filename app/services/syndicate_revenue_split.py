"""Syndicate revenue splitting engine (SYND-003).

Defines per-member revenue split rules for a syndicate, attributes incoming
syndicate revenue (bundle subscriptions / tips) across members according to the
split, and exposes per-member earnings / split history.

Money is always integer cents. Split percentages are stored as integer basis
points (bps): 100% == 10000 bps. This avoids floating point entirely.

Data lives in the dedicated ``syndicate_revenue_split`` table (``T.syndicate_revenue_split``):

  - Config:   pk=SYND#{syndicate_id}  sk=CONFIG
  - Split:    pk=SYND#{syndicate_id}  sk=SPLIT#{ts}#{split_id}
              also GSI1PK=SYND#{syndicate_id} GSI1SK=ts for newest-first history

Per-member billing-ledger credits are written to ``T.billing`` under
``USER#{user_id}`` (same shape as tip_ledger) so they integrate with the
existing earnings dashboards.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc

logger = logging.getLogger(__name__)

DEFAULT_PLATFORM_FEE_BPS = 1500  # 15%
TOTAL_BPS = 10000  # 100%
MAX_PLATFORM_FEE_BPS = 5000  # 50% cap
VALID_MODES = ("equal", "weighted", "performance")
VALID_METRICS = ("views", "engagement", "subscribers")
LEDGER_REASON = "Syndicate bundle revenue share"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _config_default() -> Dict[str, Any]:
    return {
        "mode": "equal",
        "platform_fee_bps": DEFAULT_PLATFORM_FEE_BPS,
        "weights_bps": {},
        "performance_metric": "",
        "performance_window_days": 30,
        "updated_at": 0,
        "updated_by": "",
    }


def get_split_config(syndicate_id: str) -> Dict[str, Any]:
    """Return the current split config, or an equal-split default if unset."""
    resp = T.syndicate_revenue_split.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "CONFIG"}
    )
    item = resp.get("Item")
    if not item:
        return _config_default()
    # Normalise numeric types coming back from DynamoDB Decimals.
    return {
        "mode": item.get("mode", "equal"),
        "platform_fee_bps": int(item.get("platform_fee_bps", DEFAULT_PLATFORM_FEE_BPS)),
        "weights_bps": {k: int(v) for k, v in (item.get("weights_bps") or {}).items()},
        "performance_metric": item.get("performance_metric", ""),
        "performance_window_days": int(item.get("performance_window_days", 30)),
        "updated_at": int(item.get("updated_at", 0)),
        "updated_by": item.get("updated_by", ""),
    }


def set_split_config(
    *,
    syndicate_id: str,
    admin_sub: str,
    mode: str,
    weights_bps: Optional[Dict[str, int]] = None,
    performance_metric: Optional[str] = None,
    performance_window_days: int = 30,
    platform_fee_bps: int = DEFAULT_PLATFORM_FEE_BPS,
) -> Dict[str, Any]:
    """Create or replace the split configuration for a syndicate (admin only).

    ``weights_bps`` are integer basis points per member and MUST sum to exactly
    10000 (100%) when ``mode == "weighted"``.
    """
    # Ownership / admin scope is verified against the syndicate record.
    syndicate_svc._require_admin(syndicate_id, admin_sub)

    if mode not in VALID_MODES:
        raise HTTPException(status_code=422, detail=f"Invalid split mode: {mode}")

    if not (0 <= platform_fee_bps <= MAX_PLATFORM_FEE_BPS):
        raise HTTPException(
            status_code=400,
            detail=f"platform_fee_bps must be between 0 and {MAX_PLATFORM_FEE_BPS}",
        )

    weights_bps = {k: int(v) for k, v in (weights_bps or {}).items()}

    if mode == "weighted":
        if not weights_bps:
            raise HTTPException(status_code=400, detail="weights_bps required for weighted split mode")
        total = sum(weights_bps.values())
        if total != TOTAL_BPS:
            raise HTTPException(
                status_code=400,
                detail=f"Weights must sum to exactly 100% (10000 bps), got {total} bps",
            )
        members = {m["user_id"] for m in syndicate_svc.list_members(syndicate_id)}
        for uid in weights_bps:
            if uid not in members:
                raise HTTPException(status_code=400, detail=f"{uid} is not a syndicate member")
            if weights_bps[uid] < 0:
                raise HTTPException(status_code=400, detail="Weights must be non-negative")

    if mode == "performance":
        if performance_metric not in VALID_METRICS:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid performance_metric: {performance_metric}",
            )
        if not (7 <= performance_window_days <= 365):
            raise HTTPException(
                status_code=400,
                detail="performance_window_days must be between 7 and 365",
            )

    ts = now_ts()
    item = {
        "pk": f"SYND#{syndicate_id}",
        "sk": "CONFIG",
        "mode": mode,
        "platform_fee_bps": int(platform_fee_bps),
        "weights_bps": weights_bps,
        "performance_metric": performance_metric or "",
        "performance_window_days": int(performance_window_days),
        "updated_at": ts,
        "updated_by": admin_sub,
    }
    T.syndicate_revenue_split.put_item(Item=item)
    syndicate_svc._write_audit(
        syndicate_id, admin_sub, "split_config_updated", "", {"mode": mode}
    )
    return get_split_config(syndicate_id)


# ---------------------------------------------------------------------------
# Split execution
# ---------------------------------------------------------------------------

def execute_split(
    *,
    syndicate_id: str,
    source_type: str = "subscription",
    subscription_id: str = "",
    invoice_id: str = "",
    gross_amount_cents: int,
    currency: str = "usd",
) -> Dict[str, Any]:
    """Attribute one revenue event across syndicate members per the split config.

    Deterministic and idempotent-safe to call directly (used by E2E + the
    subscription payment flow). Writes one billing-ledger credit per member and
    an immutable split execution record. Returns the split record.

    Invariant: platform_fee_cents + sum(distributions.amount_cents) == gross.
    """
    if gross_amount_cents <= 0:
        raise HTTPException(status_code=400, detail="gross_amount_cents must be positive")

    # Ensure syndicate exists.
    syndicate_svc._get_meta(syndicate_id)

    config = get_split_config(syndicate_id)
    members = syndicate_svc.list_members(syndicate_id)
    member_ids = [m["user_id"] for m in members]
    display_names = {m["user_id"]: m.get("display_name", m["user_id"]) for m in members}

    if not member_ids:
        logger.warning("syndicate_split_no_members", extra={"syndicate_id": syndicate_id})
        raise HTTPException(status_code=400, detail="Syndicate has no members to split among")

    platform_fee_bps = int(config.get("platform_fee_bps", DEFAULT_PLATFORM_FEE_BPS))
    platform_fee_cents = (gross_amount_cents * platform_fee_bps) // TOTAL_BPS
    net_amount_cents = gross_amount_cents - platform_fee_cents

    mode = config.get("mode", "equal")
    if mode == "weighted":
        weights_bps = config.get("weights_bps", {})
        # If any member is missing a weight, fall back to equal (per spec 4.3).
        if not weights_bps or any(uid not in weights_bps for uid in member_ids):
            logger.info("syndicate_split_weighted_fallback_equal", extra={"syndicate_id": syndicate_id})
            distributions = _calculate_equal(net_amount_cents, member_ids)
            effective_mode = "equal"
        else:
            distributions = _calculate_weighted(net_amount_cents, member_ids, weights_bps)
            effective_mode = "weighted"
    elif mode == "performance":
        distributions = _calculate_performance(
            net_amount_cents,
            member_ids,
            syndicate_id,
            config.get("performance_metric", "views"),
            int(config.get("performance_window_days", 30)),
        )
        effective_mode = "performance"
    else:
        distributions = _calculate_equal(net_amount_cents, member_ids)
        effective_mode = "equal"

    # Financial integrity invariant.
    distributed = sum(d["amount_cents"] for d in distributions)
    assert distributed == net_amount_cents, (
        f"split distribution mismatch: {distributed} != {net_amount_cents}"
    )
    assert platform_fee_cents + distributed == gross_amount_cents

    ts = now_ts()
    split_id = f"split_{uuid4().hex}"

    # Write per-member ledger credit entries (same shape as tip_ledger).
    for dist in distributions:
        dist["display_name"] = display_names.get(dist["user_id"], dist["user_id"])
        entry_id = uuid4().hex
        try:
            T.billing.put_item(Item={
                "pk": f"USER#{dist['user_id']}",
                "sk": f"LEDGER#{ts}#{entry_id}",
                "entry_id": entry_id,
                "ts": ts,
                "type": "credit",
                "amount_cents": int(dist["amount_cents"]),
                "currency": currency,
                "state": "settled",
                "reason": LEDGER_REASON,
                "meta": {
                    "syndicate_id": syndicate_id,
                    "split_id": split_id,
                    "subscription_id": subscription_id,
                    "invoice_id": invoice_id,
                    "source_type": source_type,
                    "split_mode": effective_mode,
                    "percentage_bps": int(dist["percentage_bps"]),
                },
            })
            dist["ledger_entry_id"] = entry_id
        except Exception:
            logger.warning(
                "syndicate_split_ledger_write_failed",
                extra={"user_id": dist["user_id"], "syndicate_id": syndicate_id},
            )
            dist["ledger_entry_id"] = ""

    split_record = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"SPLIT#{ts}#{split_id}",
        "split_id": split_id,
        "syndicate_id": syndicate_id,
        "source_type": source_type,
        "subscription_id": subscription_id,
        "invoice_id": invoice_id,
        "gross_amount_cents": int(gross_amount_cents),
        "platform_fee_cents": int(platform_fee_cents),
        "platform_fee_bps": platform_fee_bps,
        "net_amount_cents": int(net_amount_cents),
        "currency": currency,
        "mode": effective_mode,
        "distributions": distributions,
        "created_at": ts,
        "GSI1PK": f"SYND#{syndicate_id}",
        "GSI1SK": ts,
    }
    T.syndicate_revenue_split.put_item(Item=split_record)
    return split_record


# ---------------------------------------------------------------------------
# History / earnings
# ---------------------------------------------------------------------------

def get_split_history(syndicate_id: str, *, limit: int = 50) -> List[Dict[str, Any]]:
    """Return split execution records for a syndicate, newest first."""
    resp = T.syndicate_revenue_split.query(
        KeyConditionExpression=Key("pk").eq(f"SYND#{syndicate_id}")
        & Key("sk").begins_with("SPLIT#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


def get_split(syndicate_id: str, split_id: str) -> Dict[str, Any]:
    """Return a single split execution record by id, or raise 404."""
    for split in get_split_history(syndicate_id, limit=1000):
        if split.get("split_id") == split_id:
            return split
    raise HTTPException(status_code=404, detail="Split not found")


def get_member_earnings(syndicate_id: str, user_id: str) -> Dict[str, Any]:
    """Aggregate a member's earnings across this syndicate's splits."""
    splits = get_split_history(syndicate_id, limit=1000)
    total = 0
    entries: List[Dict[str, Any]] = []
    for split in splits:
        for dist in split.get("distributions", []):
            if dist.get("user_id") == user_id:
                amount = int(dist.get("amount_cents", 0))
                total += amount
                entries.append({
                    "split_id": split.get("split_id", ""),
                    "amount_cents": amount,
                    "percentage_bps": int(dist.get("percentage_bps", 0)),
                    "created_at": int(split.get("created_at", 0)),
                    "source_type": split.get("source_type", ""),
                })
    return {
        "syndicate_id": syndicate_id,
        "user_id": user_id,
        "total_cents": total,
        "split_count": len(entries),
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Calculation helpers (pure, deterministic, integer-cent math)
# ---------------------------------------------------------------------------

def _calculate_equal(net_amount_cents: int, member_ids: List[str]) -> List[Dict[str, Any]]:
    """Equal split; remainder distributed 1 cent at a time, alphabetically."""
    ordered = sorted(member_ids)
    count = len(ordered)
    base = net_amount_cents // count
    remainder = net_amount_cents - base * count
    pct_bps = TOTAL_BPS // count
    distributions = []
    for i, uid in enumerate(ordered):
        amount = base + (1 if i < remainder else 0)
        distributions.append({
            "user_id": uid,
            "amount_cents": amount,
            "percentage_bps": pct_bps,
        })
    return distributions


def _calculate_weighted(
    net_amount_cents: int,
    member_ids: List[str],
    weights_bps: Dict[str, int],
) -> List[Dict[str, Any]]:
    """Weighted split by basis points; rounding remainder to highest weight."""
    # Highest-weight-first; ties broken alphabetically for determinism.
    ordered = sorted(member_ids, key=lambda uid: (-int(weights_bps.get(uid, 0)), uid))
    distributions = []
    allocated = 0
    for i, uid in enumerate(ordered):
        bps = int(weights_bps.get(uid, 0))
        if i == len(ordered) - 1:
            amount = net_amount_cents - allocated  # last absorbs remainder
        else:
            amount = (net_amount_cents * bps) // TOTAL_BPS
        allocated += amount
        distributions.append({
            "user_id": uid,
            "amount_cents": amount,
            "percentage_bps": bps,
        })
    return distributions


def _calculate_performance(
    net_amount_cents: int,
    member_ids: List[str],
    syndicate_id: str,
    metric: str,
    window_days: int,
) -> List[Dict[str, Any]]:
    """Performance-based split proportional to per-member engagement scores."""
    scores = _get_performance_scores(syndicate_id, member_ids, metric, window_days)
    total_score = sum(scores.values())
    if total_score <= 0:
        return _calculate_equal(net_amount_cents, member_ids)

    # Highest-score-first; ties broken alphabetically.
    ordered = sorted(member_ids, key=lambda uid: (-int(scores.get(uid, 0)), uid))
    distributions = []
    allocated = 0
    for i, uid in enumerate(ordered):
        score = int(scores.get(uid, 0))
        bps = (score * TOTAL_BPS) // total_score
        if i == len(ordered) - 1:
            amount = net_amount_cents - allocated
        else:
            amount = (net_amount_cents * score) // total_score
        allocated += amount
        distributions.append({
            "user_id": uid,
            "amount_cents": amount,
            "percentage_bps": bps,
        })
    return distributions


def _get_performance_scores(
    syndicate_id: str,
    member_ids: List[str],
    metric: str,
    window_days: int,
) -> Dict[str, int]:
    """Return an integer engagement score per member.

    Scores may be seeded by an admin via :func:`set_performance_scores` (stored
    on a PERF#{metric} item). When no seeded scores exist, every member gets an
    equal score of 1, which makes the split fall back to an even distribution.
    """
    resp = T.syndicate_revenue_split.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"PERF#{metric}"}
    )
    item = resp.get("Item") or {}
    stored = {k: int(v) for k, v in (item.get("scores") or {}).items()}
    return {uid: stored.get(uid, 1) for uid in member_ids}


def set_performance_scores(
    *,
    syndicate_id: str,
    admin_sub: str,
    metric: str,
    scores: Dict[str, int],
) -> Dict[str, Any]:
    """Seed/override per-member performance scores for a metric (admin only).

    Makes performance-based splits deterministic and testable.
    """
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    if metric not in VALID_METRICS:
        raise HTTPException(status_code=422, detail=f"Invalid metric: {metric}")
    clean = {k: int(v) for k, v in scores.items() if int(v) >= 0}
    item = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"PERF#{metric}",
        "metric": metric,
        "scores": clean,
        "updated_at": now_ts(),
        "updated_by": admin_sub,
    }
    T.syndicate_revenue_split.put_item(Item=item)
    return item

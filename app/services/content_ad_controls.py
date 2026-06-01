"""Content-Provider Ad Controls service (ADS-010).

Extends the base creator ad preferences (ADS-003, ``creator_ad_prefs.py``) with:

1. **Per-content ad-control overrides** — a creator can override their global ad
   settings for a specific piece of content (e.g. a video). An override can opt a
   piece of content out of ads entirely (``ad_enabled=False``) or set a different
   ad density (``ad_density``: ``low`` | ``standard`` | ``high``) and a per-content
   pre-roll/mid-roll/subscriber-free toggle. Overrides live in the dedicated
   ``content_ad_controls`` table keyed by ``content_id``.

2. **Revenue-share management** — the creator's negotiated revenue share (in basis
   points, default 7000 bps = 70%) is stored on the global ``AD_SETTINGS`` record in
   the ``billing`` table.

3. **Transparency / analytics layer** — an ad-revenue breakdown (by content, by
   period) derived from the existing ``ad_revenue_credit`` ledger entries written by
   ``ad_placement._credit_ad_revenue``, plus a per-advertiser transparency log.

This module does NOT duplicate ``creator_ad_prefs``; it reuses
``get_creator_ad_settings`` for the base settings and layers the new pieces on top.
The per-content override is consulted by ``ad_placement.get_ad_config`` so that the
override takes precedence over the global creator/video settings.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.creator_ad_prefs import get_creator_ad_settings

logger = logging.getLogger(__name__)

# Revenue share stored in basis points (bps). 7000 bps = 70% to creator.
DEFAULT_REVENUE_SHARE_BPS = 7000

# Valid per-content ad density values and the multiplier they apply to a video's
# default mid-roll cadence. "low" thins out mid-rolls, "high" packs more in.
AD_DENSITY_VALUES = {"low", "standard", "high"}


def _to_int(val: Any, default: int = 0) -> int:
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.lstrip("-").isdigit():
        return int(val)
    return default


# ── Global ad settings (revenue share lives here) ─────────────────────────


def get_full_ad_settings(creator_sub: str) -> Dict[str, Any]:
    """Return the complete ad settings for a creator, including revenue share.

    Reuses ``creator_ad_prefs.get_creator_ad_settings`` for the base fields and
    augments it with the revenue-share configuration read from the same
    ``AD_SETTINGS`` billing record.
    """
    base = get_creator_ad_settings(creator_sub)

    resp = T.billing.get_item(Key={"pk": f"USER#{creator_sub}", "sk": "AD_SETTINGS"})
    item = resp.get("Item") or {}
    base["revenue_share_bps"] = _to_int(
        item.get("revenue_share_bps"), DEFAULT_REVENUE_SHARE_BPS
    )
    return base


def get_creator_revenue_share_bps(creator_sub: str) -> int:
    """Return the creator's revenue share in basis points (default 7000)."""
    resp = T.billing.get_item(Key={"pk": f"USER#{creator_sub}", "sk": "AD_SETTINGS"})
    item = resp.get("Item") or {}
    return _to_int(item.get("revenue_share_bps"), DEFAULT_REVENUE_SHARE_BPS)


def set_creator_revenue_share_bps(creator_sub: str, revenue_share_bps: int) -> Dict[str, Any]:
    """Set the creator's negotiated revenue share (basis points).

    Per the ticket, the revenue share is an admin-controlled / negotiated rate and
    is therefore NOT exposed on the creator-facing PATCH settings endpoint; it is
    set via a dedicated admin/owner path. Clamped to [0, 10000].
    """
    bps = max(0, min(10000, int(revenue_share_bps)))
    T.billing.update_item(
        Key={"pk": f"USER#{creator_sub}", "sk": "AD_SETTINGS"},
        UpdateExpression="SET revenue_share_bps = :b, updated_at = :ts",
        ExpressionAttributeValues={":b": bps, ":ts": now_ts()},
    )
    return {"ok": True, "revenue_share_bps": bps}


# ── Per-content ad-control overrides ───────────────────────────────────────


def _override_pk(content_id: str) -> str:
    return content_id


def get_content_override(content_id: str) -> Optional[Dict[str, Any]]:
    """Return the raw per-content ad-control override, or None if none set."""
    resp = T.content_ad_controls.get_item(Key={"content_id": _override_pk(content_id)})
    item = resp.get("Item")
    if not item:
        return None
    return _override_out(item)


def _override_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "content_id": item.get("content_id"),
        "content_type": item.get("content_type", "video"),
        "owner_sub": item.get("owner_sub"),
        "ad_enabled": bool(item.get("ad_enabled", True)),
        "ad_density": item.get("ad_density", "standard"),
        "pre_roll_enabled": bool(item.get("pre_roll_enabled", True)),
        "mid_roll_enabled": bool(item.get("mid_roll_enabled", True)),
        "ads_free_for_subscribers": bool(item.get("ads_free_for_subscribers", False)),
        "updated_at": _to_int(item.get("updated_at")),
    }


def upsert_content_override(
    *,
    content_id: str,
    owner_sub: str,
    content_type: str = "video",
    ad_enabled: Optional[bool] = None,
    ad_density: Optional[str] = None,
    pre_roll_enabled: Optional[bool] = None,
    mid_roll_enabled: Optional[bool] = None,
    ads_free_for_subscribers: Optional[bool] = None,
) -> Dict[str, Any]:
    """Create or update a per-content ad override.

    Only non-None fields are changed; existing values are preserved otherwise.
    The caller MUST have verified ownership of ``content_id`` first.
    """
    existing = T.content_ad_controls.get_item(
        Key={"content_id": _override_pk(content_id)}
    ).get("Item") or {}

    item: Dict[str, Any] = {
        "content_id": _override_pk(content_id),
        "content_type": content_type or existing.get("content_type", "video"),
        "owner_sub": owner_sub,
        "ad_enabled": existing.get("ad_enabled", True),
        "ad_density": existing.get("ad_density", "standard"),
        "pre_roll_enabled": existing.get("pre_roll_enabled", True),
        "mid_roll_enabled": existing.get("mid_roll_enabled", True),
        "ads_free_for_subscribers": existing.get("ads_free_for_subscribers", False),
    }

    if ad_enabled is not None:
        item["ad_enabled"] = bool(ad_enabled)
    if ad_density is not None:
        if ad_density not in AD_DENSITY_VALUES:
            raise ValueError(f"Invalid ad_density: {ad_density}")
        item["ad_density"] = ad_density
    if pre_roll_enabled is not None:
        item["pre_roll_enabled"] = bool(pre_roll_enabled)
    if mid_roll_enabled is not None:
        item["mid_roll_enabled"] = bool(mid_roll_enabled)
    if ads_free_for_subscribers is not None:
        item["ads_free_for_subscribers"] = bool(ads_free_for_subscribers)

    item["updated_at"] = now_ts()
    T.content_ad_controls.put_item(Item=item)
    return _override_out(item)


def delete_content_override(content_id: str) -> Dict[str, Any]:
    """Remove a per-content ad override (revert to global/video defaults)."""
    T.content_ad_controls.delete_item(Key={"content_id": _override_pk(content_id)})
    return {"ok": True}


def list_content_overrides(owner_sub: str) -> List[Dict[str, Any]]:
    """List all per-content overrides owned by a creator."""
    resp = T.content_ad_controls.query(
        IndexName="ByOwner",
        KeyConditionExpression=Key("owner_sub").eq(owner_sub),
    )
    return [_override_out(i) for i in resp.get("Items", [])]


def apply_content_override_to_config(content_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Apply a per-content override to an already-resolved ad config.

    Precedence: the per-content override wins over the video's own ad_config.

    - ``ad_enabled=False`` → disable ads entirely for this content.
    - ``pre_roll_enabled=False`` → drop all pre_roll slots.
    - ``mid_roll_enabled=False`` → drop all mid_roll slots.
    - ``ad_density`` → thins (``low``) or expands (``high``) the mid-roll slots.

    Backward-compatible: when no override exists, ``config`` is returned unchanged.
    """
    override = get_content_override(content_id)
    if not override:
        return config

    if not override.get("ad_enabled", True):
        return {"ads_enabled": False, "slots": [], "ad_free": True, "override": True}

    slots = list(config.get("slots", []))

    if not override.get("pre_roll_enabled", True):
        slots = [s for s in slots if s.get("type") != "pre_roll"]
    if not override.get("mid_roll_enabled", True):
        slots = [s for s in slots if s.get("type") != "mid_roll"]

    density = override.get("ad_density", "standard")
    if density != "standard":
        mids = [s for s in slots if s.get("type") == "mid_roll"]
        others = [s for s in slots if s.get("type") != "mid_roll"]
        if density == "low" and mids:
            # Keep every other mid-roll (at least one).
            mids = mids[::2] or mids[:1]
        # "high" leaves the existing mid-rolls in place (cannot synthesize new
        # timestamps safely without the video duration); density acts as a thinner.
        slots = others + mids
        slots.sort(key=lambda s: s.get("timestamp_seconds", 0))

    out = dict(config)
    out["slots"] = slots
    out["ad_density"] = density
    out["override"] = True
    return out


# ── Transparency log (which advertisers served on a creator's content) ──────


def record_transparency(
    creator_sub: str,
    account_id: str,
    company_name: str,
    month: str,
    *,
    impressions: int = 0,
    clicks: int = 0,
    revenue_cents: int = 0,
) -> None:
    """Atomically increment the transparency record for creator/advertiser/month.

    Best-effort — called by the ad billing pipeline on each charge event.
    """
    try:
        T.billing.update_item(
            Key={"pk": f"USER#{creator_sub}", "sk": f"AD_TRANSPARENCY#{account_id}#{month}"},
            UpdateExpression=(
                "SET account_id = :aid, company_name = :cn, #m = :month, "
                "impression_count = if_not_exists(impression_count, :z) + :imp, "
                "click_count = if_not_exists(click_count, :z) + :clk, "
                "revenue_cents = if_not_exists(revenue_cents, :z) + :rev, "
                "updated_at = :ts"
            ),
            ExpressionAttributeNames={"#m": "month"},
            ExpressionAttributeValues={
                ":aid": account_id, ":cn": company_name, ":month": month,
                ":z": 0, ":imp": int(impressions), ":clk": int(clicks),
                ":rev": int(revenue_cents), ":ts": now_ts(),
            },
        )
    except Exception:
        logger.warning("transparency_record_failed", extra={
            "creator_sub": creator_sub, "account_id": account_id, "month": month,
        })


def get_advertiser_transparency(creator_sub: str, month: Optional[str] = None) -> List[Dict[str, Any]]:
    """List advertisers who ran ads on this creator's content (creator-scoped)."""
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{creator_sub}")
        & Key("sk").begins_with("AD_TRANSPARENCY#"),
    )
    items = resp.get("Items", [])
    if month:
        items = [i for i in items if i.get("month") == month]

    accounts: Dict[str, Dict[str, Any]] = {}
    for item in items:
        aid = item.get("account_id", "")
        acc = accounts.setdefault(aid, {
            "account_id": aid,
            "company_name": item.get("company_name", "Unknown"),
            "total_impressions": 0,
            "total_clicks": 0,
            "total_revenue_cents": 0,
        })
        acc["total_impressions"] += _to_int(item.get("impression_count"))
        acc["total_clicks"] += _to_int(item.get("click_count"))
        acc["total_revenue_cents"] += _to_int(item.get("revenue_cents"))

    return sorted(accounts.values(), key=lambda a: a["total_revenue_cents"], reverse=True)


# ── Ad-revenue breakdown (transparency / analytics) ─────────────────────────


def get_ad_revenue_breakdown(creator_sub: str, days: int = 30) -> Dict[str, Any]:
    """Return the creator's ad-revenue breakdown by content over a period.

    Reads the ``ad_revenue_credit`` ledger entries written by
    ``ad_placement._credit_ad_revenue`` and aggregates them by content id.
    """
    from app.services.billing_shared import user_pk

    cutoff = now_ts() - (int(days) * 86400)

    entries: List[Dict[str, Any]] = []
    last_key = None
    # Loop pages — ad_revenue_credit is sparse on a busy ledger.
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(user_pk(creator_sub))
            & Key("sk").begins_with("LEDGER#"),
            "ScanIndexForward": False,
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.billing.query(**kwargs)
        for item in resp.get("Items", []):
            if item.get("type") != "ad_revenue_credit":
                continue
            if _to_int(item.get("ts")) < cutoff:
                continue
            entries.append(item)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    total_cents = sum(_to_int(e.get("amount_cents")) for e in entries)

    by_content: Dict[str, int] = {}
    for entry in entries:
        meta = entry.get("meta", {}) or {}
        cid = meta.get("video_id") or meta.get("content_id") or "unknown"
        by_content[cid] = by_content.get(cid, 0) + _to_int(entry.get("amount_cents"))

    top_content = sorted(by_content.items(), key=lambda x: x[1], reverse=True)[:20]

    return {
        "total_ad_revenue_cents": total_cents,
        "entry_count": len(entries),
        "days": int(days),
        "revenue_share_bps": get_creator_revenue_share_bps(creator_sub),
        "top_content": [
            {"content_id": cid, "revenue_cents": rev} for cid, rev in top_content
        ],
    }

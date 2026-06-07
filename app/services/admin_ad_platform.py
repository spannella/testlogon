"""Admin ad-platform management service (ADS-018).

Platform-admin oversight layer over the existing advertiser ad system
(ad_accounts / ad_campaigns / ad_creatives / ad_billing). This module does
NOT recreate those services — it READS and AGGREGATES across all users and
adds admin-only state transitions (account/creative moderation) plus
platform-wide revenue / spend / impression metrics.

Cross-user listing uses table scans (like admin_compute), because the ad
tables are keyed per advertiser account. This is acceptable for admin views.

All money values are integer cents. The ad_billing ledger (T.ad_billing) is
the authoritative source for spend/revenue: charge entries (impression_charge,
click_charge, conversion_charge) are advertiser spend; the platform takes
PLATFORM_REVENUE_SHARE_PCT (30%) as platform revenue and the rest is the
creator share.
"""

from __future__ import annotations

import logging
import time as _time
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.ad_billing import PLATFORM_REVENUE_SHARE_PCT
from app.services.ad_accounts import get_ad_account, review_ad_account
from app.services.ad_creatives import get_creative_by_id, review_creative
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

# Charge entry types that represent advertiser spend / platform revenue.
_CHARGE_ENTRY_TYPES = ("impression_charge", "click_charge", "conversion_charge")

# Account admin-status transitions managed by platform admins.
_ACCOUNT_STATUSES = ("pending_review", "active", "rejected", "suspended")

# Creative moderation statuses.
_CREATIVE_STATUSES = ("draft", "pending_review", "approved", "rejected")


# ---------------------------------------------------------------------------
# Generic scan helper
# ---------------------------------------------------------------------------

def _scan_all(table, *, item_filter=None) -> List[Dict[str, Any]]:
    """Scan an entire table, optionally keeping only items matching filter."""
    out: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {}
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            if item_filter is None or item_filter(item):
                out.append(item)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return out


def _i(item: Dict[str, Any], key: str, default: int = 0) -> int:
    try:
        return int(item.get(key, default))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Cross-user listing
# ---------------------------------------------------------------------------

def list_all_advertiser_accounts(
    *, status: Optional[str] = None, owner_sub: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """List ALL advertiser accounts across all users with optional filters."""

    def _keep(item: Dict[str, Any]) -> bool:
        if item.get("sk") != "META" or "account_id" not in item:
            return False
        if status is not None and item.get("status") != status:
            return False
        if owner_sub is not None and item.get("owner_sub") != owner_sub:
            return False
        return True

    items = _scan_all(T.ad_accounts, item_filter=_keep)
    items.sort(key=lambda x: _i(x, "created_at"), reverse=True)
    return items[:limit]


def list_all_campaigns(
    *, status: Optional[str] = None, account_id: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """List ALL campaigns across all advertiser accounts with optional filters."""

    def _keep(item: Dict[str, Any]) -> bool:
        if "campaign_id" not in item:
            return False
        if status is not None and item.get("status") != status:
            return False
        if account_id is not None and item.get("account_id") != account_id:
            return False
        return True

    items = _scan_all(T.ad_campaigns, item_filter=_keep)
    items.sort(key=lambda x: _i(x, "created_at"), reverse=True)
    return items[:limit]


def list_all_creatives(
    *, status: Optional[str] = None, account_id: Optional[str] = None,
    campaign_id: Optional[str] = None, limit: int = 200,
) -> List[Dict[str, Any]]:
    """List ALL creatives across all campaigns with optional filters."""

    def _keep(item: Dict[str, Any]) -> bool:
        if "creative_id" not in item:
            return False
        if status is not None and item.get("status") != status:
            return False
        if account_id is not None and item.get("account_id") != account_id:
            return False
        if campaign_id is not None and item.get("campaign_id") != campaign_id:
            return False
        return True

    items = _scan_all(T.ad_creatives, item_filter=_keep)
    items.sort(key=lambda x: _i(x, "created_at"), reverse=True)
    return items[:limit]


# ---------------------------------------------------------------------------
# Account details + admin moderation
# ---------------------------------------------------------------------------

def get_account_detail(account_id: str) -> Optional[Dict[str, Any]]:
    """Account meta plus its campaigns and aggregate spend."""
    acct = get_ad_account(account_id)
    if not acct:
        return None
    campaigns = list_all_campaigns(account_id=account_id, limit=500)
    return {
        "account": acct,
        "campaigns": campaigns,
        "campaign_count": len(campaigns),
    }


def _log_moderation(
    *, item_type: str, item_id: str, action: str, admin_sub: str,
    reason: str = "", notes: str = "", prev_status: str = "",
    new_status: str = "", request=None,
) -> Dict[str, Any]:
    """Write an immutable moderation log entry + audit event."""
    ts = now_ts()
    event_id = f"mod_{uuid.uuid4().hex[:12]}"
    item = {
        "pk": f"MODERATION#{item_type}#{item_id}",
        "sk": f"EVENT#{ts}#{event_id}",
        "event_id": event_id,
        "item_type": item_type,
        "item_id": item_id,
        "action": action,
        "admin_sub": admin_sub,
        "reason": reason or "",
        "notes": notes or "",
        "prev_status": prev_status or "",
        "new_status": new_status or "",
        "created_at": ts,
    }
    T.ad_moderation_log.put_item(Item=item)
    audit_event(
        f"ad_platform_{item_type}_{action}",
        admin_sub,
        request,
        item_type=item_type,
        item_id=item_id,
        action=action,
        reason=reason,
        prev_status=prev_status,
        new_status=new_status,
    )
    return item


def get_moderation_history(item_type: str, item_id: str) -> List[Dict[str, Any]]:
    resp = T.ad_moderation_log.query(
        KeyConditionExpression=Key("pk").eq(f"MODERATION#{item_type}#{item_id}")
        & Key("sk").begins_with("EVENT#"),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


# ---------------------------------------------------------------------------
# Platform-level kill switch (GAP-0068)
# ---------------------------------------------------------------------------

_KILL_SWITCH_PK = "PLATFORM_CONFIG"
_KILL_SWITCH_SK = "AD_KILL_SWITCH"
_KS_CACHE: Dict[str, Any] = {}   # {"active": bool, "expires": float}
_KS_TTL_SECONDS = 5              # cache lifespan to cap DDB read latency impact


def is_kill_switch_active() -> bool:
    """Return True if the platform-wide ad kill switch is currently on.

    Result is cached for _KS_TTL_SECONDS to limit DynamoDB reads to at most
    once per 5 seconds per worker, while still reacting to a toggle within that
    window. Failures fail open (return False) so a DDB outage does not
    accidentally halt all ad serving.
    """
    now = _time.monotonic()
    if _KS_CACHE.get("expires", 0) > now:
        return bool(_KS_CACHE.get("active", False))
    try:
        resp = T.ad_accounts.get_item(
            Key={"pk": _KILL_SWITCH_PK, "sk": _KILL_SWITCH_SK}
        )
        item = resp.get("Item") or {}
        active = bool(item.get("active", False))
    except Exception:
        logger.warning("ad_kill_switch_read_failed — failing open")
        active = False
    _KS_CACHE.update({"active": active, "expires": now + _KS_TTL_SECONDS})
    return active


def toggle_kill_switch(
    *, enabled: bool, admin_sub: str, reason: str = "", request=None
) -> Dict[str, Any]:
    """Enable or disable the platform-wide ad kill switch.

    Requires ROOT role (enforced at the router layer). Writes state to DynamoDB
    and an immutable audit/moderation log entry. Invalidates the in-process
    cache so the change takes effect within _KS_TTL_SECONDS on this worker.
    """
    ts = now_ts()
    T.ad_accounts.put_item(
        Item={
            "pk": _KILL_SWITCH_PK,
            "sk": _KILL_SWITCH_SK,
            "active": enabled,
            "toggled_by": admin_sub,
            "reason": reason or "",
            "updated_at": ts,
        }
    )
    # Invalidate cache so this worker picks up the change immediately.
    _KS_CACHE.clear()
    _log_moderation(
        item_type="platform",
        item_id="ad_kill_switch",
        action="enable" if enabled else "disable",
        admin_sub=admin_sub,
        reason=reason,
        prev_status="inactive" if enabled else "active",
        new_status="active" if enabled else "inactive",
        request=request,
    )
    logger.warning(
        "ad_kill_switch_toggled enabled=%s admin_sub=%s reason=%s",
        enabled, admin_sub, reason,
    )
    return {
        "active": enabled,
        "toggled_by": admin_sub,
        "reason": reason or "",
        "updated_at": ts,
    }


def get_kill_switch_state() -> Dict[str, Any]:
    """Return the current kill switch state from DynamoDB (bypasses cache)."""
    try:
        resp = T.ad_accounts.get_item(
            Key={"pk": _KILL_SWITCH_PK, "sk": _KILL_SWITCH_SK}
        )
        item = resp.get("Item") or {}
        return {
            "active": bool(item.get("active", False)),
            "toggled_by": item.get("toggled_by", ""),
            "reason": item.get("reason", ""),
            "updated_at": int(item.get("updated_at", 0)),
        }
    except Exception:
        return {"active": False, "toggled_by": "", "reason": "", "updated_at": 0}


def _pause_account_campaigns(
    *, account_id: str, admin_sub: str, reason: str = ""
) -> List[str]:
    """Set all active campaigns for account_id to status='paused' (GAP-0069).

    Uses a direct DynamoDB update rather than update_campaign() to bypass the
    user-facing status-machine validation. The transition active→paused is
    valid per _CAMPAIGN_TRANSITIONS; only the validation layer is bypassed. The
    ConditionExpression makes the update idempotent: a campaign that was paused
    or completed between the list and the update is skipped silently.

    Returns the list of campaign_ids that were paused.
    """
    ts = now_ts()
    paused: List[str] = []

    campaigns = list_all_campaigns(account_id=account_id, status="active", limit=1000)
    cond_failed = T.ad_campaigns.meta.client.exceptions.ConditionalCheckFailedException

    for camp in campaigns:
        try:
            T.ad_campaigns.update_item(
                Key={"pk": camp["pk"], "sk": camp["sk"]},
                UpdateExpression=(
                    "SET #s = :paused, admin_paused_by = :admin, "
                    "admin_pause_reason = :reason, admin_paused_at = :ts, "
                    "updated_at = :ts"
                ),
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":paused": "paused",
                    ":admin": admin_sub,
                    ":reason": reason or "account suspended",
                    ":ts": ts,
                    ":active": "active",
                },
                ConditionExpression="#s = :active",
            )
            paused.append(camp["campaign_id"])
            logger.info(
                "ad_campaign_suspended_cascade account_id=%s campaign_id=%s",
                account_id, camp["campaign_id"],
            )
        except cond_failed:
            # Campaign was already paused/completed between list and update.
            pass
        except Exception:
            logger.error(
                "ad_campaign_suspend_cascade_failed account_id=%s campaign_id=%s",
                account_id, camp.get("campaign_id"),
            )

    return paused


def moderate_account(
    *, account_id: str, action: str, admin_sub: str,
    reason: str = "", notes: str = "", request=None,
) -> Optional[Dict[str, Any]]:
    """Approve / reject / suspend an advertiser account.

    action ∈ {approve, reject, suspend}. Returns None if account not found.

    For action="suspend", all active campaigns belonging to the account are
    immediately paused (GAP-0069 fix). The paused campaign IDs are returned and
    can be surfaced for audit / potential reversal.
    """
    acct = get_ad_account(account_id)
    if not acct:
        return None
    prev_status = acct.get("status", "")
    # ad_accounts.review_ad_account maps approve→active, otherwise keeps decision.
    result = review_ad_account(account_id, admin_sub, action, notes or reason)
    if result is None:
        return None
    new_status = result["status"]

    paused_campaign_ids: List[str] = []
    if action == "suspend":
        # Cascade: pause all active campaigns for this account.
        paused_campaign_ids = _pause_account_campaigns(
            account_id=account_id,
            admin_sub=admin_sub,
            reason=reason or notes,
        )

    _log_moderation(
        item_type="account", item_id=account_id, action=action,
        admin_sub=admin_sub, reason=reason, notes=notes,
        prev_status=prev_status, new_status=new_status, request=request,
    )
    return {
        "account_id": account_id,
        "admin_status": new_status,
        "status": new_status,
        "paused_campaign_ids": paused_campaign_ids,
    }


def moderate_creative(
    *, creative_id: str, action: str, admin_sub: str,
    reason: str = "", notes: str = "", request=None,
) -> Optional[Dict[str, Any]]:
    """Approve / reject / suspend a creative.

    action ∈ {approve, reject, suspend}. Returns None if not found.
    """
    cr = get_creative_by_id(creative_id)
    if not cr:
        return None
    prev_status = cr.get("status", "")
    if action == "suspend":
        # ad_creatives.review_creative only handles approve/reject. Suspend is
        # an admin-only transition we apply directly.
        T.ad_creatives.update_item(
            Key={"pk": cr["pk"], "sk": cr["sk"]},
            UpdateExpression="SET #s = :s, reviewed_by = :r, review_notes = :n, updated_at = :u",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "rejected", ":r": admin_sub,
                ":n": notes or reason, ":u": now_ts(),
            },
        )
        new_status = "rejected"
    else:
        result = review_creative(creative_id, admin_sub, action, notes or reason)
        if result is None:
            return None
        new_status = result["status"]
    _log_moderation(
        item_type="creative", item_id=creative_id, action=action,
        admin_sub=admin_sub, reason=reason, notes=notes,
        prev_status=prev_status, new_status=new_status, request=request,
    )
    return {"creative_id": creative_id, "status": new_status}


# ---------------------------------------------------------------------------
# Platform-wide metrics (revenue / spend / impressions)
# ---------------------------------------------------------------------------

def _scan_billing_charges() -> List[Dict[str, Any]]:
    """All charge ledger entries across all advertiser accounts."""

    def _keep(item: Dict[str, Any]) -> bool:
        return item.get("entry_type") in _CHARGE_ENTRY_TYPES

    return _scan_all(T.ad_billing, item_filter=_keep)


def get_platform_metrics() -> Dict[str, Any]:
    """Platform-wide ad revenue / spend / impression / click summary.

    Spend = sum of all charge entries. Platform revenue = platform share of
    that spend; creator share is the remainder.
    """
    charges = _scan_billing_charges()
    total_spend = 0
    impressions = 0
    clicks = 0
    conversions = 0
    for e in charges:
        amt = _i(e, "amount_cents")
        total_spend += amt
        et = e.get("entry_type")
        if et == "impression_charge":
            impressions += 1
        elif et == "click_charge":
            clicks += 1
        elif et == "conversion_charge":
            conversions += 1

    platform_share = (total_spend * PLATFORM_REVENUE_SHARE_PCT) // 100
    creator_share = total_spend - platform_share
    effective_cpm = (total_spend * 1000) // impressions if impressions else 0

    # Account / campaign / creative population counts.
    accounts = list_all_advertiser_accounts(limit=10000)
    campaigns = list_all_campaigns(limit=10000)
    creatives = list_all_creatives(limit=10000)

    def _count_by_status(rows: List[Dict[str, Any]]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in rows:
            s = str(r.get("status", "unknown"))
            out[s] = out.get(s, 0) + 1
        return out

    return {
        "total_spend_cents": total_spend,
        "platform_revenue_cents": platform_share,
        "creator_share_cents": creator_share,
        "revenue_share_percent": float(PLATFORM_REVENUE_SHARE_PCT),
        "impressions": impressions,
        "clicks": clicks,
        "conversions": conversions,
        "effective_cpm_cents": effective_cpm,
        "account_count": len(accounts),
        "campaign_count": len(campaigns),
        "creative_count": len(creatives),
        "accounts_by_status": _count_by_status(accounts),
        "campaigns_by_status": _count_by_status(campaigns),
        "creatives_by_status": _count_by_status(creatives),
        "pending_account_reviews": _count_by_status(accounts).get("pending_review", 0),
        "pending_creative_reviews": _count_by_status(creatives).get("pending_review", 0),
    }


def get_monthly_revenue_series() -> List[Dict[str, Any]]:
    """Per-month revenue / spend time series, oldest→newest."""
    charges = _scan_billing_charges()
    by_month: Dict[str, Dict[str, int]] = {}
    for e in charges:
        month = str(e.get("month_key", "")) or "unknown"
        bucket = by_month.setdefault(
            month, {"spend_cents": 0, "impressions": 0, "clicks": 0}
        )
        bucket["spend_cents"] += _i(e, "amount_cents")
        et = e.get("entry_type")
        if et == "impression_charge":
            bucket["impressions"] += 1
        elif et == "click_charge":
            bucket["clicks"] += 1
    out: List[Dict[str, Any]] = []
    for month in sorted(by_month.keys()):
        b = by_month[month]
        spend = b["spend_cents"]
        platform = (spend * PLATFORM_REVENUE_SHARE_PCT) // 100
        out.append({
            "month": month,
            "spend_cents": spend,
            "platform_revenue_cents": platform,
            "creator_share_cents": spend - platform,
            "impressions": b["impressions"],
            "clicks": b["clicks"],
        })
    return out


def get_top_spenders(limit: int = 10) -> List[Dict[str, Any]]:
    """Top advertiser accounts by total ad spend (descending)."""
    charges = _scan_billing_charges()
    by_acct: Dict[str, int] = {}
    for e in charges:
        acct = str(e.get("account_id", ""))
        if acct:
            by_acct[acct] = by_acct.get(acct, 0) + _i(e, "amount_cents")
    rows: List[Dict[str, Any]] = []
    for account_id, spend in by_acct.items():
        acct = get_ad_account(account_id)
        rows.append({
            "account_id": account_id,
            "company_name": (acct or {}).get("company_name", ""),
            "owner_sub": (acct or {}).get("owner_sub", ""),
            "spend_cents": spend,
        })
    rows.sort(key=lambda r: r["spend_cents"], reverse=True)
    return rows[:limit]

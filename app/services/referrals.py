"""Referral & Affiliate System — service layer (AFFILIATE-001).

All referral data lives in ``app_single_table`` using the entity patterns:

* **ReferralCode** — ``pk=REFCODE#{code}  sk=META``
  GSI1: ``REFCODES#{owner_user_id} / {created_at}#REFCODE#{code}``
* **ReferralAttribution** — ``pk=REFERRAL#{referred_user_id}  sk=META``
  GSI1: ``REFERRALS#{referrer_user_id} / {attributed_at}#REF#{referred_user_id}``
* **AffiliateCommission** — ``pk=AFFILIATE#{referrer_user_id}  sk=COMMISSION#{ts}#{tx_id}``
"""

from __future__ import annotations

import logging
import secrets
import string
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

import boto3
from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Table handle — lazily resolved to avoid import-time DDB calls
# ---------------------------------------------------------------------------

_TABLE = None


def _tbl():
    global _TABLE
    if _TABLE is None:
        import os
        endpoint = os.getenv("DDB_ENDPOINT_URL") or os.getenv("AWS_ENDPOINT_URL") or ""
        kwargs: dict[str, str] = {"region_name": S.aws_region or "us-east-1"}
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        _TABLE = boto3.resource("dynamodb", **kwargs).Table(
            os.getenv("APP_TABLE", "app_single_table"),
        )
    return _TABLE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CODE_CHARS = string.ascii_uppercase + string.digits
_CODE_LEN = 8


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_unique_code() -> str:
    """Generate a random 8-char alphanumeric code."""
    return "".join(secrets.choice(_CODE_CHARS) for _ in range(_CODE_LEN))


# ---------------------------------------------------------------------------
# Referral Code CRUD
# ---------------------------------------------------------------------------


def create_referral_code(user_id: str) -> Dict[str, Any]:
    """Create a new referral code for *user_id*.

    Raises ``ValueError`` if the user already has ``referral_max_codes_per_user``
    active codes.
    """
    tbl = _tbl()
    # Count existing active codes via GSI1
    resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"REFCODES#{user_id}"),
    )
    active = [i for i in resp.get("Items", []) if i.get("active") is True]
    if len(active) >= S.referral_max_codes_per_user:
        raise ValueError("maximum active referral codes reached")

    code = _generate_unique_code()
    now = _now_iso()
    item: Dict[str, Any] = {
        "pk": f"REFCODE#{code}",
        "sk": "META",
        "Entity": "ReferralCode",
        "code": code,
        "owner_user_id": user_id,
        "created_at": now,
        "active": True,
        "commission_tier": "standard",
        "GSI1PK": f"REFCODES#{user_id}",
        "GSI1SK": f"{now}#REFCODE#{code}",
    }
    tbl.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
    return {
        "code": code,
        "link": f"{S.public_base_url}/?ref={code}",
        "commission_tier": "standard",
        "created_at": now,
    }


def list_referral_codes(user_id: str) -> List[Dict[str, Any]]:
    tbl = _tbl()
    resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"REFCODES#{user_id}"),
        ScanIndexForward=False,
    )
    out: list[dict[str, Any]] = []
    for item in resp.get("Items", []):
        out.append({
            "code": item["code"],
            "active": item.get("active", False),
            "commission_tier": item.get("commission_tier", "standard"),
            "created_at": item.get("created_at"),
        })
    return out


def disable_referral_code(user_id: str, code: str) -> bool:
    """Deactivate *code*. Returns ``True`` on success."""
    tbl = _tbl()
    item = tbl.get_item(Key={"pk": f"REFCODE#{code}", "sk": "META"}).get("Item")
    if not item or item.get("owner_user_id") != user_id:
        return False
    tbl.update_item(
        Key={"pk": f"REFCODE#{code}", "sk": "META"},
        UpdateExpression="SET active = :f",
        ExpressionAttributeValues={":f": False},
    )
    return True


def lookup_referral_code(code: str) -> Optional[Dict[str, Any]]:
    tbl = _tbl()
    item = tbl.get_item(Key={"pk": f"REFCODE#{code}", "sk": "META"}).get("Item")
    if not item:
        return None
    return item


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


def attribute_referral(
    referred_user_id: str,
    referral_code: str,
    ip_address: str = "",
    source: str = "cookie",
) -> Optional[Dict[str, Any]]:
    """Record that *referred_user_id* signed up via *referral_code*.

    Returns the attribution item on success, or ``None`` if blocked.
    """
    tbl = _tbl()
    code_item = tbl.get_item(Key={"pk": f"REFCODE#{referral_code}", "sk": "META"}).get("Item")
    if not code_item or not code_item.get("active"):
        return None

    referrer_id = code_item["owner_user_id"]

    # Self-referral prevention
    if referrer_id == referred_user_id:
        logger.warning("Self-referral blocked: %s", referrer_id)
        return None

    # Check for existing attribution
    existing = tbl.get_item(Key={"pk": f"REFERRAL#{referred_user_id}", "sk": "META"}).get("Item")
    if existing:
        return None

    now = _now_iso()
    window_end = (
        datetime.now(timezone.utc) + timedelta(days=S.referral_commission_window_days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    item: Dict[str, Any] = {
        "pk": f"REFERRAL#{referred_user_id}",
        "sk": "META",
        "Entity": "ReferralAttribution",
        "referred_user_id": referred_user_id,
        "referrer_user_id": referrer_id,
        "referral_code": referral_code,
        "attributed_at": now,
        "attribution_source": source,
        "status": "pending",
        "commission_window_ends_at": window_end,
        "ip_address": ip_address,
        "GSI1PK": f"REFERRALS#{referrer_id}",
        "GSI1SK": f"{now}#REF#{referred_user_id}",
    }
    tbl.put_item(Item=item)
    return item


def get_attribution(user_id: str) -> Optional[Dict[str, Any]]:
    """Get referral attribution for *user_id* (as the referred user)."""
    tbl = _tbl()
    item = tbl.get_item(Key={"pk": f"REFERRAL#{user_id}", "sk": "META"}).get("Item")
    return item


def list_referrals(referrer_user_id: str) -> List[Dict[str, Any]]:
    """List users referred by *referrer_user_id*."""
    tbl = _tbl()
    resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"REFERRALS#{referrer_user_id}"),
        ScanIndexForward=False,
    )
    out: list[dict[str, Any]] = []
    for item in resp.get("Items", []):
        out.append({
            "referred_user_id": item.get("referred_user_id"),
            "referral_code": item.get("referral_code"),
            "status": item.get("status", "pending"),
            "attributed_at": item.get("attributed_at"),
        })
    return out


# ---------------------------------------------------------------------------
# Commission
# ---------------------------------------------------------------------------


def record_affiliate_commission(
    referred_user_id: str,
    transaction_id: str,
    source_type: str,
    gross_amount_cents: int,
    platform_fee_cents: int = 0,
) -> Optional[Dict[str, Any]]:
    """Calculate and record commission for a purchase by *referred_user_id*.

    Returns the commission item on success, or ``None`` if no attribution or
    commission window expired.
    """
    tbl = _tbl()
    attribution = tbl.get_item(
        Key={"pk": f"REFERRAL#{referred_user_id}", "sk": "META"},
    ).get("Item")
    if not attribution or attribution.get("status") == "revoked":
        return None

    if _now_iso() > attribution.get("commission_window_ends_at", ""):
        return None

    referrer_id = attribution["referrer_user_id"]
    net_amount = gross_amount_cents - platform_fee_cents

    code_item = tbl.get_item(
        Key={"pk": f"REFCODE#{attribution['referral_code']}", "sk": "META"},
    ).get("Item")
    tier = (code_item or {}).get("commission_tier", "standard")
    rate_bps = S.referral_standard_rate_bps if tier == "standard" else S.referral_premium_rate_bps

    commission_cents = max(1, (net_amount * rate_bps) // 10000)
    ts = now_ts()
    now = _now_iso()

    entry: Dict[str, Any] = {
        "pk": f"AFFILIATE#{referrer_id}",
        "sk": f"COMMISSION#{ts}#{transaction_id}",
        "Entity": "AffiliateCommission",
        "referrer_user_id": referrer_id,
        "referred_user_id": referred_user_id,
        "source_transaction_id": transaction_id,
        "source_type": source_type,
        "gross_amount_cents": gross_amount_cents,
        "net_amount_cents": net_amount,
        "commission_rate_bps": rate_bps,
        "commission_cents": commission_cents,
        "currency": "usd",
        "status": "pending",
        "created_at": now,
    }
    tbl.put_item(Item=entry)
    return entry


def list_commissions(
    referrer_user_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Paginated list of commission entries for *referrer_user_id*."""
    tbl = _tbl()
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"AFFILIATE#{referrer_user_id}"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        import json, base64
        kwargs["ExclusiveStartKey"] = json.loads(base64.b64decode(cursor))

    resp = tbl.query(**kwargs)
    items = resp.get("Items", [])
    commissions = []
    for item in items:
        commissions.append({
            "source_type": item.get("source_type"),
            "referred_user_id": item.get("referred_user_id"),
            "gross_amount_cents": _to_int(item.get("gross_amount_cents", 0)),
            "net_amount_cents": _to_int(item.get("net_amount_cents", 0)),
            "commission_cents": _to_int(item.get("commission_cents", 0)),
            "commission_rate_bps": _to_int(item.get("commission_rate_bps", 0)),
            "status": item.get("status"),
            "created_at": item.get("created_at"),
        })

    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        import json, base64
        next_cursor = base64.b64encode(json.dumps(resp["LastEvaluatedKey"]).encode()).decode()

    return {"commissions": commissions, "next_cursor": next_cursor}


def _to_int(val: Any) -> int:
    if isinstance(val, Decimal):
        return int(val)
    return int(val) if val else 0


# ---------------------------------------------------------------------------
# Dashboard / Stats
# ---------------------------------------------------------------------------


def get_referral_dashboard(user_id: str) -> Dict[str, Any]:
    """Aggregate referral stats for *user_id*."""
    tbl = _tbl()

    # Get codes
    codes_resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"REFCODES#{user_id}"),
    )
    codes = codes_resp.get("Items", [])

    # Get referrals
    referrals_resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"REFERRALS#{user_id}"),
    )
    referrals = referrals_resp.get("Items", [])
    total_referrals = len(referrals)
    confirmed = sum(1 for r in referrals if r.get("status") == "confirmed")
    pending = sum(1 for r in referrals if r.get("status") == "pending")

    # Get commissions
    commissions_resp = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"AFFILIATE#{user_id}"),
    )
    commissions = commissions_resp.get("Items", [])

    total_earned = sum(_to_int(c.get("commission_cents", 0)) for c in commissions)
    pending_commission = sum(
        _to_int(c.get("commission_cents", 0))
        for c in commissions
        if c.get("status") == "pending"
    )
    paid_commission = sum(
        _to_int(c.get("commission_cents", 0))
        for c in commissions
        if c.get("status") == "paid"
    )
    confirmed_commission = sum(
        _to_int(c.get("commission_cents", 0))
        for c in commissions
        if c.get("status") in ("confirmed", "pending")
    )

    available = confirmed_commission - paid_commission

    # Referral count per code
    code_referral_counts: dict[str, int] = {}
    for r in referrals:
        rc = r.get("referral_code", "")
        code_referral_counts[rc] = code_referral_counts.get(rc, 0) + 1

    referral_codes_out = []
    for c in codes:
        referral_codes_out.append({
            "code": c.get("code"),
            "active": c.get("active", False),
            "commission_tier": c.get("commission_tier", "standard"),
            "referral_count": code_referral_counts.get(c.get("code", ""), 0),
            "created_at": c.get("created_at"),
        })

    return {
        "total_referrals": total_referrals,
        "confirmed_referrals": confirmed,
        "pending_referrals": pending,
        "total_earned_cents": total_earned,
        "pending_commission_cents": pending_commission,
        "paid_commission_cents": paid_commission,
        "available_for_withdrawal_cents": max(0, available),
        "referral_codes": referral_codes_out,
    }

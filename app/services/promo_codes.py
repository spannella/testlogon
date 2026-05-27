"""
Promo Codes & Coupons service (PROMO-001).

Provides CRUD, validation, and redemption for promo codes.
Codes are stored in a dedicated PromoCodes DynamoDB table with
GSIs for creator listing and global code-string lookup.
"""
from __future__ import annotations

import re
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ─── Constants ────────────────────────────────────────────────────

CODE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,30}$")
VALID_CHECKOUT_TYPES = {"subscription", "vod", "shop"}
VALID_DISCOUNT_TYPES = {"percentage", "fixed_amount", "free_trial"}


# ─── Key helpers ──────────────────────────────────────────────────

def _promo_pk(code_id: str) -> str:
    return f"PROMO#{code_id}"


def _code_lookup_pk(code: str) -> str:
    return f"CODE#{code.upper()}"


def _creator_scope(creator_id: str) -> str:
    return f"CREATOR#{creator_id}"


def _redeem_sk(user_id: str, ts: int) -> str:
    return f"REDEEM#{user_id}#{ts}"


def _new_code_id() -> str:
    return f"pc_{uuid.uuid4().hex[:12]}"


# ─── Table access helpers ─────────────────────────────────────────

def _tbl():
    return T.promo_codes


def _put(item: Dict[str, Any]) -> None:
    _tbl().put_item(Item=item)


def _get(pk: str, sk: str) -> Optional[Dict[str, Any]]:
    resp = _tbl().get_item(Key={"pk": pk, "sk": sk})
    return resp.get("Item")


def _query_gsi(index_name: str, pk_name: str, pk_val: str, **kwargs) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {
        "IndexName": index_name,
        "KeyConditionExpression": Key(pk_name).eq(pk_val),
    }
    params.update(kwargs)
    items: List[Dict[str, Any]] = []
    while True:
        resp = _tbl().query(**params)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        params["ExclusiveStartKey"] = lek
    return items


# ─── CRUD ─────────────────────────────────────────────────────────

def create_promo_code(
    creator_id: str,
    code: str,
    discount_type: str,
    discount_value: int = 0,
    free_trial_days: int = 0,
    applies_to: Optional[List[str]] = None,
    min_purchase_cents: int = 0,
    max_uses: int = 0,
    max_uses_per_user: int = 1,
    expires_at: int = 0,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Create a promo code.  Returns (item, None) on success or (None, error_message) on failure."""

    normalized = code.strip().upper()
    if not CODE_PATTERN.match(normalized):
        return None, "Code must be 3-30 alphanumeric characters (plus _ and -)"

    if discount_type not in VALID_DISCOUNT_TYPES:
        return None, f"Invalid discount_type: {discount_type}"

    if applies_to is None:
        applies_to = ["subscription"]
    for at in applies_to:
        if at not in VALID_CHECKOUT_TYPES:
            return None, f"Invalid applies_to value: {at}"
    if not applies_to:
        return None, "applies_to must have at least one value"

    if discount_type == "percentage":
        if discount_value < 1 or discount_value > S.promo_code_max_discount_percent:
            return None, f"discount_value must be between 1 and {S.promo_code_max_discount_percent} for percentage type"
    elif discount_type == "fixed_amount":
        if discount_value < 1:
            return None, "discount_value must be at least 1 cent for fixed_amount type"
    elif discount_type == "free_trial":
        if free_trial_days < 1 or free_trial_days > S.promo_code_max_free_trial_days:
            return None, f"free_trial_days must be between 1 and {S.promo_code_max_free_trial_days}"
        if applies_to != ["subscription"]:
            return None, "free_trial applies only to subscriptions"

    ts = now_ts()
    if expires_at and expires_at <= ts:
        return None, "expires_at must be in the future"

    # Check creator code limit
    existing = _query_gsi(
        "ByCreatorCreatedAt",
        "creator_scope",
        _creator_scope(creator_id),
    )
    meta_items = [i for i in existing if i.get("sk") == "META"]
    if len(meta_items) >= S.promo_code_max_per_creator:
        return None, f"Maximum {S.promo_code_max_per_creator} promo codes per creator"

    # Check global code uniqueness via GSI2
    dup = _query_gsi(
        "ByCodeString",
        "code_lookup_pk",
        _code_lookup_pk(normalized),
    )
    if dup:
        return None, "A promo code with this string already exists"

    code_id = _new_code_id()
    item: Dict[str, Any] = {
        "pk": _promo_pk(code_id),
        "sk": "META",
        "code_id": code_id,
        "code": normalized,
        "code_lookup_pk": _code_lookup_pk(normalized),
        "code_lookup_sk": "META",
        "creator_user_id": creator_id,
        "creator_scope": _creator_scope(creator_id),
        "discount_type": discount_type,
        "discount_value": discount_value,
        "free_trial_days": free_trial_days,
        "applies_to": applies_to,
        "min_purchase_cents": min_purchase_cents,
        "max_uses": max_uses,
        "max_uses_per_user": max_uses_per_user,
        "current_uses": 0,
        "expires_at": expires_at,
        "active": True,
        "created_at": ts,
        "updated_at": ts,
    }
    _put(item)
    return item, None


def list_promo_codes(creator_id: str) -> List[Dict[str, Any]]:
    """List all META promo codes for a creator, ordered by created_at desc."""
    items = _query_gsi(
        "ByCreatorCreatedAt",
        "creator_scope",
        _creator_scope(creator_id),
        ScanIndexForward=False,
    )
    return [i for i in items if i.get("sk") == "META"]


def get_promo_code(code_id: str) -> Optional[Dict[str, Any]]:
    return _get(_promo_pk(code_id), "META")


def get_promo_code_by_string(code: str) -> Optional[Dict[str, Any]]:
    """Look up a promo code by its code string (case-insensitive)."""
    results = _query_gsi(
        "ByCodeString",
        "code_lookup_pk",
        _code_lookup_pk(code),
    )
    metas = [r for r in results if r.get("sk") == "META"]
    return metas[0] if metas else None


def update_promo_code(
    code_id: str,
    creator_id: str,
    active: Optional[bool] = None,
    expires_at: Optional[int] = None,
    max_uses: Optional[int] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Update mutable fields on a promo code. Returns (item, None) or (None, error)."""
    item = _get(_promo_pk(code_id), "META")
    if not item:
        return None, "Promo code not found"
    if item["creator_user_id"] != creator_id:
        return None, "Not your promo code"

    if active is not None:
        item["active"] = active
    if expires_at is not None:
        if expires_at > 0 and expires_at <= now_ts():
            return None, "expires_at must be in the future"
        item["expires_at"] = expires_at
    if max_uses is not None:
        if max_uses < 0:
            return None, "max_uses cannot be negative"
        item["max_uses"] = max_uses

    item["updated_at"] = now_ts()
    _put(item)
    return item, None


def deactivate_promo_code(code_id: str, creator_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Soft-deactivate a promo code."""
    return update_promo_code(code_id, creator_id, active=False)


# ─── Validation ───────────────────────────────────────────────────

def validate_promo_code(
    code: str,
    user_id: Optional[str],
    checkout_type: str,
    item_price_cents: int,
    creator_user_id: str,
) -> Dict[str, Any]:
    """
    Validate a promo code for a given checkout context.
    Returns a dict matching PromoValidateOut shape:
      { valid, code_id, discount_type, discount_cents, final_price_cents, free_trial_days, message }
    """
    fail = {
        "valid": False,
        "code_id": None,
        "discount_type": None,
        "discount_cents": 0,
        "final_price_cents": item_price_cents,
        "free_trial_days": 0,
        "message": None,
    }

    promo = get_promo_code_by_string(code)
    if not promo or not promo.get("active", True):
        fail["message"] = "Code not found"
        return fail

    ts = now_ts()

    # Expiry check
    exp = int(promo.get("expires_at") or 0)
    if exp > 0 and exp < ts:
        fail["message"] = "This code has expired"
        fail["code_id"] = promo["code_id"]
        return fail

    # Max uses check
    max_uses = int(promo.get("max_uses") or 0)
    current = int(promo.get("current_uses") or 0)
    if max_uses > 0 and current >= max_uses:
        fail["message"] = "This code has been fully redeemed"
        fail["code_id"] = promo["code_id"]
        return fail

    # Per-user limit check
    if user_id:
        max_per = int(promo.get("max_uses_per_user") or 0)
        if max_per > 0:
            user_redeems = _query_promo_user_redeems(promo["code_id"], user_id)
            if len(user_redeems) >= max_per:
                fail["message"] = "You have already used this code"
                fail["code_id"] = promo["code_id"]
                return fail

    # Checkout type check
    applies = promo.get("applies_to") or []
    if checkout_type not in applies:
        fail["message"] = "This code does not apply to this checkout type"
        fail["code_id"] = promo["code_id"]
        return fail

    # Creator scope check
    if promo["creator_user_id"] != creator_user_id:
        fail["message"] = "This code is not valid for this creator"
        fail["code_id"] = promo["code_id"]
        return fail

    # Free trial + non-subscription check
    dtype = promo["discount_type"]
    if dtype == "free_trial" and checkout_type != "subscription":
        fail["message"] = "Free trial codes are only valid for subscriptions"
        fail["code_id"] = promo["code_id"]
        return fail

    # Min purchase check
    min_cents = int(promo.get("min_purchase_cents") or 0)
    if min_cents > 0 and item_price_cents < min_cents:
        dollars = min_cents / 100
        fail["message"] = f"Minimum purchase of ${dollars:.2f} required"
        fail["code_id"] = promo["code_id"]
        return fail

    # Calculate discount
    discount_cents, final_price, trial_days = _calculate_discount(promo, item_price_cents)

    return {
        "valid": True,
        "code_id": promo["code_id"],
        "discount_type": dtype,
        "discount_cents": discount_cents,
        "final_price_cents": final_price,
        "free_trial_days": trial_days,
        "message": None,
    }


def _calculate_discount(
    promo: Dict[str, Any], item_price_cents: int
) -> Tuple[int, int, int]:
    """Returns (discount_cents, final_price_cents, free_trial_days)."""
    dtype = promo["discount_type"]
    value = int(promo.get("discount_value") or 0)
    trial = int(promo.get("free_trial_days") or 0)

    if dtype == "percentage":
        discount = int(item_price_cents * value / 100)
        discount = min(discount, item_price_cents)
        return discount, max(0, item_price_cents - discount), 0
    elif dtype == "fixed_amount":
        discount = min(value, item_price_cents)
        return discount, max(0, item_price_cents - discount), 0
    elif dtype == "free_trial":
        return item_price_cents, 0, trial
    return 0, item_price_cents, 0


# ─── Redemption ───────────────────────────────────────────────────

def redeem_promo_code(
    code_id: str,
    user_id: str,
    original_price_cents: int = 0,
    final_price_cents: int = 0,
    checkout_type: str = "",
    checkout_item_id: str = "",
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Record a redemption. Atomically increments current_uses.
    Returns (redemption_item, None) on success or (None, error_msg) on failure.
    """
    promo = _get(_promo_pk(code_id), "META")
    if not promo:
        return None, "Promo code not found"

    # Atomic increment with condition check
    max_uses = int(promo.get("max_uses") or 0)
    try:
        if max_uses > 0:
            _tbl().update_item(
                Key={"pk": _promo_pk(code_id), "sk": "META"},
                UpdateExpression="SET current_uses = current_uses + :one, updated_at = :ts",
                ConditionExpression=Attr("current_uses").lt(max_uses),
                ExpressionAttributeValues={":one": 1, ":ts": now_ts()},
            )
        else:
            _tbl().update_item(
                Key={"pk": _promo_pk(code_id), "sk": "META"},
                UpdateExpression="SET current_uses = current_uses + :one, updated_at = :ts",
                ExpressionAttributeValues={":one": 1, ":ts": now_ts()},
            )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return None, "This code has been fully redeemed"
        raise

    discount_cents = max(0, original_price_cents - final_price_cents)
    ts = now_ts()
    redeem_item: Dict[str, Any] = {
        "pk": _promo_pk(code_id),
        "sk": _redeem_sk(user_id, ts),
        "user_id": user_id,
        "redeemed_at": ts,
        "discount_applied_cents": discount_cents,
        "original_price_cents": original_price_cents,
        "final_price_cents": final_price_cents,
        "checkout_type": checkout_type,
        "checkout_item_id": checkout_item_id,
    }
    _put(redeem_item)
    return redeem_item, None


def _query_promo_user_redeems(code_id: str, user_id: str) -> List[Dict[str, Any]]:
    """Query all REDEEM rows for a user under a code."""
    resp = _tbl().query(
        KeyConditionExpression=Key("pk").eq(_promo_pk(code_id)) & Key("sk").begins_with(f"REDEEM#{user_id}#"),
    )
    return resp.get("Items", [])


# ─── Stats ────────────────────────────────────────────────────────

def get_promo_stats(code_id: str) -> Dict[str, Any]:
    """Get redemption stats for a promo code."""
    resp = _tbl().query(
        KeyConditionExpression=Key("pk").eq(_promo_pk(code_id)) & Key("sk").begins_with("REDEEM#"),
        Limit=200,
    )
    redeems = resp.get("Items", [])
    total_discount = sum(int(r.get("discount_applied_cents") or 0) for r in redeems)
    return {
        "total_redemptions": len(redeems),
        "total_discount_cents": total_discount,
        "redemptions": [
            {
                "user_id": r.get("user_id", ""),
                "redeemed_at": int(r.get("redeemed_at") or 0),
                "discount_applied_cents": int(r.get("discount_applied_cents") or 0),
                "checkout_type": r.get("checkout_type", ""),
            }
            for r in redeems
        ],
    }


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DDB item to a dict matching PromoCodeOut shape."""
    return {
        "code_id": item.get("code_id", ""),
        "code": item.get("code", ""),
        "discount_type": item.get("discount_type", ""),
        "discount_value": int(item.get("discount_value") or 0),
        "free_trial_days": int(item.get("free_trial_days") or 0),
        "applies_to": item.get("applies_to") or [],
        "min_purchase_cents": int(item.get("min_purchase_cents") or 0),
        "max_uses": int(item.get("max_uses") or 0),
        "max_uses_per_user": int(item.get("max_uses_per_user") or 1),
        "current_uses": int(item.get("current_uses") or 0),
        "expires_at": int(item.get("expires_at") or 0),
        "active": bool(item.get("active", True)),
        "created_at": int(item.get("created_at") or 0),
        "creator_user_id": item.get("creator_user_id", ""),
    }

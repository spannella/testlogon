"""PMD-001 — Per-owner rent-policy settings service.

Provides a per-landlord configurable overlay on four defaults
(rent_due_day, late_fee_cents, grace_period_days, currency) that
leases inherit at creation time.

Storage layout (T.rent_policy):
  pk = "POLICY#{owner_sub}", sk = "CURRENT"   — live policy row
  pk = "POLICY#{owner_sub}", sk = "AUDIT#{ts:010d}#{event_id}" — append-only history

Design mirrors billing_config.py (per-owner overlay + cache + audit idiom)
and inventory.py (_flag_on/_require_enabled/_audit pattern).
"""
from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any, Dict, Iterator, Optional, Tuple

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor

_POLICY_PK_PREFIX = "POLICY#"
_SK_CURRENT = "CURRENT"
_SK_AUDIT_PREFIX = "AUDIT#"

# Per-owner in-memory TTL cache: {owner_sub: (policy_dict, cached_at_ts)}
_cache: Dict[str, Tuple[Dict[str, Any], int]] = {}


# ---------------------------------------------------------------------------
# Flag guard (mirrors inventory.py:50-57)
# ---------------------------------------------------------------------------

def _flag_on() -> bool:
    return bool(getattr(S, "property_dashboard_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Property dashboard is not enabled")


def _cache_ttl() -> int:
    return int(getattr(S, "rent_policy_cache_ttl_seconds", 60) or 60)


def _owner_pk(owner_sub: str) -> str:
    return f"{_POLICY_PK_PREFIX}{owner_sub}"


def _effective_defaults() -> Dict[str, Any]:
    """Platform-level defaults (mirrors billing_config 'override-or-env' contract)."""
    return {
        "rent_due_day": 1,
        "late_fee_cents": 0,
        "grace_period_days": 0,
        "currency": str(getattr(S, "default_currency", "usd")).lower(),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def invalidate_cache(owner_sub: str) -> None:
    """Drop the cached policy for owner_sub (call after any write)."""
    _cache.pop(owner_sub, None)


def get_policy(owner_sub: str) -> Dict[str, Any]:
    """Return the effective rent policy for owner_sub.

    Returns the stored CURRENT row when present; otherwise returns
    platform defaults with is_default=True. TTL-based in-memory cache.
    """
    _require_enabled()
    now = now_ts()
    cached = _cache.get(owner_sub)
    if cached is not None and (now - cached[1]) < _cache_ttl():
        return dict(cached[0])

    from app.core.tables import T
    resp = T.rent_policy.get_item(Key={"pk": _owner_pk(owner_sub), "sk": _SK_CURRENT})
    item = resp.get("Item")

    defaults = _effective_defaults()
    if item is None:
        policy: Dict[str, Any] = {
            **defaults,
            "updated_at": None,
            "updated_by": None,
            "is_default": True,
        }
    else:
        policy = {
            "rent_due_day":      int(item.get("rent_due_day", defaults["rent_due_day"])),
            "late_fee_cents":    int(item.get("late_fee_cents", defaults["late_fee_cents"])),
            "grace_period_days": int(item.get("grace_period_days", defaults["grace_period_days"])),
            "currency":          str(item.get("currency", defaults["currency"])).lower(),
            "updated_at":        int(item["updated_at"]) if item.get("updated_at") is not None else None,
            "updated_by":        item.get("updated_by"),
            "is_default":        False,
        }

    _cache[owner_sub] = (policy, now)
    return dict(policy)


def set_policy(
    owner_sub: str,
    *,
    rent_due_day: int,
    late_fee_cents: int,
    grace_period_days: int,
    currency: str,
    actor_sub: str,
) -> Dict[str, Any]:
    """Validate, persist, and cache-invalidate a new rent policy.

    Always appends an AUDIT row (even for identical values — every admin
    action is recorded). Returns the new effective policy dict.
    """
    _require_enabled()
    _validate_policy(rent_due_day, late_fee_cents, grace_period_days, currency)

    from app.core.tables import T

    now = now_ts()
    event_id = f"evt_{uuid.uuid4().hex[:8]}"
    pk = _owner_pk(owner_sub)
    currency_norm = currency.strip().lower()

    # Snapshot before-state for audit (may be absent on first write)
    resp = T.rent_policy.get_item(Key={"pk": pk, "sk": _SK_CURRENT})
    before_item = resp.get("Item")
    before_snap: Optional[Dict[str, Any]] = None
    if before_item is not None:
        before_snap = {
            "rent_due_day":      int(before_item.get("rent_due_day", 1)),
            "late_fee_cents":    int(before_item.get("late_fee_cents", 0)),
            "grace_period_days": int(before_item.get("grace_period_days", 0)),
            "currency":          str(before_item.get("currency", "usd")),
        }

    after_snap: Dict[str, Any] = {
        "rent_due_day": rent_due_day,
        "late_fee_cents": late_fee_cents,
        "grace_period_days": grace_period_days,
        "currency": currency_norm,
    }

    # Write CURRENT row (full replace, mirrors billing_config.py put_item pattern)
    T.rent_policy.put_item(Item={
        "pk":               pk,
        "sk":               _SK_CURRENT,
        "rent_due_day":      Decimal(str(rent_due_day)),
        "late_fee_cents":    Decimal(str(late_fee_cents)),
        "grace_period_days": Decimal(str(grace_period_days)),
        "currency":          currency_norm,
        "updated_at":        Decimal(str(now)),
        "updated_by":        str(actor_sub),
    })

    # Append AUDIT row (always, even for identical values — §5.3 spec)
    T.rent_policy.put_item(Item={
        "pk":         pk,
        "sk":         f"{_SK_AUDIT_PREFIX}{now:010d}#{event_id}",
        "actor_sub":  str(actor_sub),
        "before":     before_snap,
        "after":      after_snap,
        "created_at": Decimal(str(now)),
    })

    invalidate_cache(owner_sub)
    _audit("rent_policy.updated", actor_sub, owner_sub=owner_sub, **after_snap)

    return get_policy(owner_sub)


def list_policy_audit(
    owner_sub: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Return change history for owner_sub, newest-first.

    Mirrors billing_config.get_audit_log pagination pattern.
    """
    _require_enabled()
    from app.core.tables import T

    limit = max(1, min(int(limit), 200))
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(_owner_pk(owner_sub)) & Key("sk").begins_with(_SK_AUDIT_PREFIX)
        ),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        decoded = decode_cursor(cursor)
        if decoded:
            kwargs["ExclusiveStartKey"] = decoded

    resp = T.rent_policy.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey")) if resp.get("LastEvaluatedKey") else None

    entries = [
        {
            "actor_sub":  item.get("actor_sub", ""),
            "before":     item.get("before"),
            "after":      item.get("after"),
            "created_at": int(item.get("created_at", 0)),
        }
        for item in items
    ]
    return {"entries": entries, "count": len(entries), "cursor": next_cursor}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_policy(
    rent_due_day: int,
    late_fee_cents: int,
    grace_period_days: int,
    currency: str,
) -> None:
    """Raise ValueError on invalid inputs (router converts to 422)."""
    if not (1 <= int(rent_due_day) <= 28):
        raise ValueError("rent_due_day must be between 1 and 28 inclusive")
    if int(late_fee_cents) < 0:
        raise ValueError("late_fee_cents must be >= 0")
    if int(grace_period_days) < 0:
        raise ValueError("grace_period_days must be >= 0")
    c = str(currency).strip()
    if len(c) != 3 or not c.isalpha():
        raise ValueError("currency must be a 3-letter ISO 4217 code")


# ---------------------------------------------------------------------------
# Audit helper (lazy-import fire-and-forget; mirrors inventory.py:92-98)
# ---------------------------------------------------------------------------

def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass

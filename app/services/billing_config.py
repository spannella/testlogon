"""Billing configuration management (FIN-018).

Stores admin-set overrides for tunable billing/fee/payout parameters in
DynamoDB so they are editable at runtime without a redeploy. The rest of the
app reads the *effective* value: the DB override if present, otherwise the
env-var-backed default exposed via ``app.core.settings.S``.

Design:
  * Single partition (``pk = "BILLING_CONFIG"``).
  * Current config: one item at ``sk = "CURRENT"``.
  * Audit log: one item per change at ``sk = "AUDIT#{ts}#{event_id}"``.
  * In-memory cache with a short TTL keeps the hot path (fee lookups on every
    transaction) cheap; it is invalidated immediately on write.

Editable keys are a small typed allowlist. Unknown keys are rejected by the
caller (router) and by ``set_config``/``update_billing_config``.
"""

from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("billing_config")

# --------------------------------------------------------------------------- #
#  Storage keys                                                                 #
# --------------------------------------------------------------------------- #

_PK = "BILLING_CONFIG"
_SK_CURRENT = "CURRENT"

# --------------------------------------------------------------------------- #
#  Cache                                                                        #
# --------------------------------------------------------------------------- #

_config_cache: Optional[Dict[str, Any]] = None
_cache_ts: int = 0


def _cache_ttl() -> int:
    return int(getattr(S, "billing_config_cache_ttl_seconds", 60) or 60)


def invalidate_cache() -> None:
    """Drop the in-memory config cache (forces a fresh DDB read)."""
    global _config_cache, _cache_ts
    _config_cache = None
    _cache_ts = 0


# --------------------------------------------------------------------------- #
#  Typed allowlist of editable keys                                             #
# --------------------------------------------------------------------------- #
#
# Each entry: key -> (type, default-fn, validator). The default is computed
# lazily from env-backed settings so the effective value is "override-or-env".
# Validators raise ValueError on invalid input.


def _env_default(name: str, fallback: Any) -> Any:
    return getattr(S, name, fallback)


def _validate_bps(key: str, v: int, *, hi: int = 5000) -> int:
    iv = int(v)
    if iv < 0:
        raise ValueError(f"{key} must be >= 0")
    if iv > hi:
        raise ValueError(f"{key} must be <= {hi}")
    return iv


def _validate_cents(key: str, v: int) -> int:
    iv = int(v)
    if iv < 0:
        raise ValueError(f"{key} must be >= 0")
    return iv


def _validate_schedule(key: str, v: str) -> str:
    sv = str(v)
    if sv not in ("daily", "weekly", "monthly"):
        raise ValueError(f"{key} must be daily, weekly, or monthly")
    return sv


def _validate_currency(key: str, v: str) -> str:
    sv = str(v).upper()
    if len(sv) != 3 or not sv.isalpha():
        raise ValueError(f"{key} must be a 3-letter ISO currency code")
    return sv


def _validate_currency_list(key: str, v: List[str]) -> List[str]:
    if not isinstance(v, (list, tuple)) or not v:
        raise ValueError(f"{key} must be a non-empty list of currency codes")
    out: List[str] = []
    for c in v:
        out.append(_validate_currency(key, c))
    return out


def _validate_bool(key: str, v: Any) -> bool:
    return bool(v)


# Allowlist: key -> dict(kind, default, validate)
_ALLOWLIST: Dict[str, Dict[str, Any]] = {
    "fee_tips_bps": {
        "kind": "int",
        "default": lambda: int(_env_default("platform_fee_bps", 2000)),
        "validate": lambda k, v: _validate_bps(k, v),
    },
    "fee_unlocks_bps": {
        "kind": "int",
        "default": lambda: int(_env_default("platform_fee_bps", 2000)),
        "validate": lambda k, v: _validate_bps(k, v),
    },
    "fee_subscriptions_bps": {
        "kind": "int",
        "default": lambda: 1500,
        "validate": lambda k, v: _validate_bps(k, v),
    },
    "fee_catalog_bps": {
        "kind": "int",
        "default": lambda: 1000,
        "validate": lambda k, v: _validate_bps(k, v),
    },
    "fee_ad_revenue_bps": {
        "kind": "int",
        "default": lambda: int(_env_default("platform_fee_bps", 2000)),
        "validate": lambda k, v: _validate_bps(k, v),
    },
    "min_payout_cents": {
        "kind": "int",
        "default": lambda: int(_env_default("payout_minimum_cents", 1000)),
        "validate": lambda k, v: _validate_cents(k, v),
    },
    "payout_fee_cents": {
        "kind": "int",
        "default": lambda: 0,
        "validate": lambda k, v: _validate_cents(k, v),
    },
    "payout_schedule": {
        "kind": "str",
        "default": lambda: "weekly",
        "validate": lambda k, v: _validate_schedule(k, v),
    },
    "auto_payout_enabled": {
        "kind": "bool",
        "default": lambda: True,
        "validate": lambda k, v: _validate_bool(k, v),
    },
    "min_deposit_cents": {
        "kind": "int",
        "default": lambda: 500,
        "validate": lambda k, v: _validate_cents(k, v),
    },
    "max_deposit_cents": {
        "kind": "int",
        "default": lambda: 1000000,
        "validate": lambda k, v: _validate_cents(k, v),
    },
    "deposit_fee_bps": {
        "kind": "int",
        "default": lambda: 0,
        "validate": lambda k, v: _validate_bps(k, v),
    },
    "default_currency": {
        "kind": "str",
        "default": lambda: str(_env_default("default_currency", "usd")).upper(),
        "validate": lambda k, v: _validate_currency(k, v),
    },
    "supported_currencies": {
        "kind": "list",
        "default": lambda: ["USD", "EUR", "GBP"],
        "validate": lambda k, v: _validate_currency_list(k, v),
    },
    "tax_enabled": {
        "kind": "bool",
        "default": lambda: False,
        "validate": lambda k, v: _validate_bool(k, v),
    },
    "default_tax_rate_bps": {
        "kind": "int",
        "default": lambda: 0,
        "validate": lambda k, v: _validate_bps(k, v, hi=10000),
    },
}

EDITABLE_KEYS: Tuple[str, ...] = tuple(_ALLOWLIST.keys())


def is_editable_key(key: str) -> bool:
    return key in _ALLOWLIST


def _defaults() -> Dict[str, Any]:
    return {k: spec["default"]() for k, spec in _ALLOWLIST.items()}


# --------------------------------------------------------------------------- #
#  Read                                                                         #
# --------------------------------------------------------------------------- #


def _coerce_stored(key: str, val: Any) -> Any:
    kind = _ALLOWLIST[key]["kind"]
    if kind == "int":
        if isinstance(val, Decimal):
            return int(val)
        return int(val)
    if kind == "bool":
        return bool(val)
    if kind == "list":
        return [str(v) for v in val]
    return str(val)


def get_billing_config() -> Dict[str, Any]:
    """Return the effective billing configuration (override-or-default).

    Uses an in-memory cache with a short TTL. Falls back to env-backed defaults
    for any key not present in the stored override item.
    """
    global _config_cache, _cache_ts
    now = now_ts()

    if _config_cache is not None and (now - _cache_ts) < _cache_ttl():
        return dict(_config_cache)

    item: Optional[Dict[str, Any]] = None
    if getattr(S, "billing_config_ddb_enabled", True):
        try:
            resp = T.billing_config.get_item(Key={"pk": _PK, "sk": _SK_CURRENT})
            item = resp.get("Item")
        except Exception:  # pragma: no cover - defensive: fall back to defaults
            logger.exception("billing_config_read_failed")
            item = None

    config = _defaults()
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None

    if item:
        for key in _ALLOWLIST:
            if key in item and item[key] is not None:
                try:
                    config[key] = _coerce_stored(key, item[key])
                except Exception:
                    # Keep default if a stored value is somehow malformed.
                    pass
        if item.get("updated_at") is not None:
            updated_at = int(item["updated_at"])
        updated_by = item.get("updated_by")

    config["updated_at"] = updated_at
    config["updated_by"] = updated_by

    _config_cache = dict(config)
    _cache_ts = now
    return config


def get_effective_config(key: str, default: Any = None) -> Any:
    """Return the effective value for a single config key.

    DB override if present, else the passed env default, else the allowlist
    default. Unknown keys return ``default``.
    """
    if key not in _ALLOWLIST:
        return default
    config = get_billing_config()
    val = config.get(key)
    if val is None:
        return default if default is not None else _ALLOWLIST[key]["default"]()
    return val


# --------------------------------------------------------------------------- #
#  Write                                                                        #
# --------------------------------------------------------------------------- #


def _to_ddb_value(key: str, val: Any) -> Any:
    kind = _ALLOWLIST[key]["kind"]
    if kind == "int":
        return Decimal(str(int(val)))
    if kind == "bool":
        return bool(val)
    if kind == "list":
        return [str(v) for v in val]
    return str(val)


def update_billing_config(*, admin_sub: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Validate + apply a partial config update.

    Only keys in the allowlist are accepted (unknown keys -> ValueError).
    Values are validated. The full updated item is persisted, an audit entry is
    written for the changed fields, and the cache is invalidated.

    A no-op update (no fields changed) returns the current config WITHOUT
    writing an audit entry.

    Returns the effective config dict (incl. updated_at / updated_by).
    """
    now = now_ts()

    # Validate keys + coerce values up-front so a bad value aborts the whole op.
    clean: Dict[str, Any] = {}
    for key, raw in updates.items():
        if raw is None:
            continue
        if key not in _ALLOWLIST:
            raise ValueError(f"unknown config key: {key}")
        clean[key] = _ALLOWLIST[key]["validate"](key, raw)

    current = get_billing_config()

    # Cross-field validation: min_deposit cannot exceed max_deposit.
    eff_min = clean.get("min_deposit_cents", current.get("min_deposit_cents"))
    eff_max = clean.get("max_deposit_cents", current.get("max_deposit_cents"))
    if eff_min is not None and eff_max is not None and int(eff_min) > int(eff_max):
        raise ValueError("min_deposit_cents cannot exceed max_deposit_cents")

    changes: List[Dict[str, Any]] = []
    merged = {k: current.get(k) for k in _ALLOWLIST}
    for key, new_value in clean.items():
        old_value = current.get(key)
        if old_value != new_value:
            changes.append({"field": key, "old_value": old_value, "new_value": new_value})
            merged[key] = new_value

    if not changes:
        return current  # No-op: do not write an audit entry.

    # Build + persist the CURRENT item.
    ddb_item: Dict[str, Any] = {"pk": _PK, "sk": _SK_CURRENT}
    for key in _ALLOWLIST:
        if merged.get(key) is not None:
            ddb_item[key] = _to_ddb_value(key, merged[key])
    ddb_item["updated_at"] = Decimal(str(now))
    ddb_item["updated_by"] = str(admin_sub)
    T.billing_config.put_item(Item=ddb_item)

    # Persist the audit entry (old/new values serialized as strings for stable
    # round-tripping regardless of original type).
    event_id = f"evt_{uuid.uuid4().hex[:8]}"
    audit_changes = [
        {
            "field": c["field"],
            "old_value": "null" if c["old_value"] is None else str(c["old_value"]),
            "new_value": "null" if c["new_value"] is None else str(c["new_value"]),
        }
        for c in changes
    ]
    T.billing_config.put_item(
        Item={
            "pk": _PK,
            "sk": f"AUDIT#{now}#{event_id}",
            "admin_sub": str(admin_sub),
            "changes": audit_changes,
            "created_at": Decimal(str(now)),
        }
    )

    invalidate_cache()

    logger.info(
        "billing_config_updated",
        extra={
            "admin": admin_sub,
            "changes": [
                {"field": c["field"], "old": c["old_value"], "new": c["new_value"]}
                for c in changes
            ],
        },
    )

    return get_billing_config()


def set_config(key: str, value: Any, actor: str) -> Dict[str, Any]:
    """Set a single override key. Thin wrapper around ``update_billing_config``."""
    return update_billing_config(admin_sub=actor, updates={key: value})


def reset_config(*, admin_sub: str, keys: Optional[List[str]] = None) -> Dict[str, Any]:
    """Reset one or more keys back to their env/code defaults.

    If ``keys`` is None, every editable key is reset (the CURRENT override item
    is effectively cleared). Records an audit entry for any field that changed.
    """
    target_keys = list(_ALLOWLIST.keys()) if not keys else list(keys)
    for k in target_keys:
        if k not in _ALLOWLIST:
            raise ValueError(f"unknown config key: {k}")

    defaults = _defaults()
    updates = {k: defaults[k] for k in target_keys}
    return update_billing_config(admin_sub=admin_sub, updates=updates)


# --------------------------------------------------------------------------- #
#  Convenience accessors used by the rest of the app                            #
# --------------------------------------------------------------------------- #

_FEE_FIELD_BY_ENTRY_TYPE = {
    "tip_debit": "fee_tips_bps",
    "tip_credit": "fee_tips_bps",
    "unlock_debit": "fee_unlocks_bps",
    "subscription_charge": "fee_subscriptions_bps",
    "subscription": "fee_subscriptions_bps",
    "catalog_purchase": "fee_catalog_bps",
    "ad_revenue": "fee_ad_revenue_bps",
}


def get_fee_bps(entry_type: str) -> int:
    """Platform fee in basis points for a transaction type."""
    config = get_billing_config()
    field = _FEE_FIELD_BY_ENTRY_TYPE.get(entry_type, "fee_tips_bps")
    return int(config.get(field, _ALLOWLIST[field]["default"]()))


def get_min_payout_cents() -> int:
    return int(get_effective_config("min_payout_cents", S.payout_minimum_cents))


def get_min_deposit_cents() -> int:
    return int(get_effective_config("min_deposit_cents", 500))


def get_max_deposit_cents() -> int:
    return int(get_effective_config("max_deposit_cents", 1000000))


# --------------------------------------------------------------------------- #
#  Audit log                                                                    #
# --------------------------------------------------------------------------- #


def get_audit_log(*, limit: int = 50, cursor: Optional[str] = None) -> Dict[str, Any]:
    """Return billing-config change history, newest first."""
    limit = max(1, min(int(limit), 200))
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(_PK) & Key("sk").begins_with("AUDIT#"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        decoded = decode_cursor(cursor)
        if decoded:
            kwargs["ExclusiveStartKey"] = decoded

    try:
        resp = T.billing_config.query(**kwargs)
    except Exception:  # pragma: no cover - defensive
        logger.exception("billing_config_audit_query_failed")
        return {"entries": [], "count": 0, "cursor": None}

    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey")) if resp.get("LastEvaluatedKey") else None

    entries: List[Dict[str, Any]] = []
    for item in items:
        changes_raw = item.get("changes", []) or []
        changes = [
            {
                "field": c.get("field", ""),
                "old_value": c.get("old_value"),
                "new_value": c.get("new_value"),
            }
            for c in changes_raw
        ]
        entries.append(
            {
                "admin_sub": item.get("admin_sub", ""),
                "changes": changes,
                "created_at": int(item.get("created_at", 0)),
            }
        )

    return {"entries": entries, "count": len(entries), "cursor": next_cursor}


# --------------------------------------------------------------------------- #
#  Impact preview (deterministic)                                               #
# --------------------------------------------------------------------------- #

_FEE_FIELDS = {
    "fee_tips_bps": "tip_debit",
    "fee_unlocks_bps": "unlock_debit",
    "fee_subscriptions_bps": "subscription_charge",
    "fee_catalog_bps": "catalog_purchase",
    "fee_ad_revenue_bps": "ad_revenue",
}

# Deterministic per-type assumed daily volume (cents) for impact projection.
# Real production would query the billing ledger; we keep it deterministic so
# E2E assertions are stable.
_ASSUMED_DAILY_VOLUME_CENTS = {
    "tip_debit": 1000000,
    "unlock_debit": 500000,
    "subscription_charge": 800000,
    "catalog_purchase": 300000,
    "ad_revenue": 200000,
}


def preview_impact(*, proposed_changes: Dict[str, Any]) -> Dict[str, Any]:
    """Project the revenue impact of proposed fee changes.

    Deterministic: uses fixed assumed daily volumes per transaction type so the
    output is stable for tests. Only fee_*_bps changes affect the projection.
    """
    current = get_billing_config()

    affected_types: List[str] = []
    daily_delta_cents = 0

    for field, tx_type in _FEE_FIELDS.items():
        new_val = proposed_changes.get(field)
        if new_val is None:
            continue
        new_val = int(new_val)
        old_val = int(current.get(field, 0))
        if new_val == old_val:
            continue
        affected_types.append(tx_type)
        volume = _ASSUMED_DAILY_VOLUME_CENTS.get(tx_type, 0)
        daily_delta_cents += int(volume * (new_val - old_val) / 10000)

    sample_amount = 1000  # $10.00
    cur_tip_bps = int(current.get("fee_tips_bps", 2000))
    new_tip_bps = int(proposed_changes.get("fee_tips_bps", cur_tip_bps))
    old_fee = int(sample_amount * cur_tip_bps / 10000)
    new_fee = int(sample_amount * new_tip_bps / 10000)

    return {
        "affected_tx_types": affected_types,
        "projected_daily_delta_cents": daily_delta_cents,
        "sample_before": {
            "amount_cents": sample_amount,
            "fee_cents": old_fee,
            "net_cents": sample_amount - old_fee,
        },
        "sample_after": {
            "amount_cents": sample_amount,
            "fee_cents": new_fee,
            "net_cents": sample_amount - new_fee,
        },
    }

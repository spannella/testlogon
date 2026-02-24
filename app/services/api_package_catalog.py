from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import HTTPException

from app.core.tables import T
from app.models import ApiPackageSkuCreateIn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sku_key(sku: str) -> Dict[str, str]:
    return {"PK": f"SKU#{sku}", "SK": "LATEST"}


def _require_positive_int(value: Any, field_name: str) -> int:
    try:
        n = int(value)
    except Exception as exc:
        raise HTTPException(400, f"{field_name} must be an integer") from exc
    if n <= 0:
        raise HTTPException(400, f"{field_name} must be > 0")
    return n


def _validate_template(body: ApiPackageSkuCreateIn) -> None:
    has_credit = bool(body.credit_grant)
    has_limits = bool(body.limit_overrides)
    has_access = bool(body.access_template)
    if not (has_credit or has_limits or has_access):
        raise HTTPException(400, "At least one entitlement template is required")

    if has_credit:
        _require_positive_int(body.credit_grant.get("credits"), "credit_grant.credits")
        bucket = str(body.credit_grant.get("bucket") or "").strip()
        if not bucket:
            raise HTTPException(400, "credit_grant.bucket is required")

    if has_limits:
        period = str(body.limit_overrides.get("period") or "monthly").strip().lower()
        if period != "monthly":
            raise HTTPException(400, "limit_overrides.period must be monthly")
        unlimited_calls = bool(body.limit_overrides.get("unlimited_calls"))
        monthly_calls = body.limit_overrides.get("monthly_call_limit")
        if unlimited_calls and monthly_calls is not None:
            raise HTTPException(400, "Conflicting limit definitions: unlimited_calls cannot be combined with monthly_call_limit")
        for key in ("monthly_call_limit", "monthly_spend_micros_limit", "rps_limit"):
            val = body.limit_overrides.get(key)
            if val is None:
                continue
            _require_positive_int(val, f"limit_overrides.{key}")

    if has_access:
        route_allowlist = body.access_template.get("route_allowlist")
        feature_unlocks = body.access_template.get("feature_unlocks")
        if route_allowlist is not None and not isinstance(route_allowlist, list):
            raise HTTPException(400, "access_template.route_allowlist must be an array")
        if feature_unlocks is not None and not isinstance(feature_unlocks, list):
            raise HTTPException(400, "access_template.feature_unlocks must be an array")
        if route_allowlist is not None and feature_unlocks is not None:
            overlap = set(str(x) for x in route_allowlist) & set(str(x) for x in feature_unlocks)
            if overlap:
                raise HTTPException(400, "Conflicting access definitions: route ids cannot overlap feature unlock names")


def create_api_package_sku_version(author_id: str, body: ApiPackageSkuCreateIn) -> Dict[str, Any]:
    _validate_template(body)

    effective_at = str(body.effective_at).strip()
    if effective_at.endswith("Z"):
        effective_at = effective_at[:-1] + "+00:00"
    try:
        datetime.fromisoformat(effective_at)
    except Exception as exc:
        raise HTTPException(400, "effective_at must be ISO8601 datetime") from exc

    now = _now_iso()
    version_item = {
        "sku": body.sku,
        "effective_at": effective_at,
        "product_type": "api_package",
        "display_name": body.display_name,
        "currency": body.currency.upper(),
        "amount_cents": int(body.amount_cents),
        "billing_model": body.billing_model,
        "credit_grant": dict(body.credit_grant or {}),
        "limit_overrides": dict(body.limit_overrides or {}),
        "access_template": dict(body.access_template or {}),
        "created_at": now,
        "created_by": author_id,
    }

    T.catalog_product_versions.put_item(
        Item=version_item,
        ConditionExpression="attribute_not_exists(sku) AND attribute_not_exists(effective_at)",
    )

    latest = {
        **_sku_key(body.sku),
        "entity": "api_package_sku",
        "sku": body.sku,
        "product_type": "api_package",
        "display_name": body.display_name,
        "currency": body.currency.upper(),
        "amount_cents": int(body.amount_cents),
        "billing_model": body.billing_model,
        "latest_effective_at": effective_at,
        "created_at": now,
        "created_by": author_id,
        "updated_at": now,
    }
    T.catalog_products.put_item(Item=latest)

    return {
        "sku": body.sku,
        "product_type": "api_package",
        "display_name": body.display_name,
        "currency": body.currency.upper(),
        "amount_cents": int(body.amount_cents),
        "billing_model": body.billing_model,
        "effective_at": effective_at,
        "credit_grant": dict(body.credit_grant or {}),
        "limit_overrides": dict(body.limit_overrides or {}),
        "access_template": dict(body.access_template or {}),
    }

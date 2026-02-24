from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from app.core.settings import S

ProductType = Literal["file_bundle", "api_package", "internal_api_package"]
BillingModel = Literal["one_time", "rental", "subscription", "credit_pack"]


@dataclass(frozen=True)
class ProductVersion:
    sku: str
    product_type: ProductType
    display_name: str
    billing_model: BillingModel
    effective_at: int
    sunset_at: Optional[int]
    amount: int
    currency: str
    tax_code: Optional[str]
    config: Dict[str, Any]


@dataclass(frozen=True)
class ProductCatalog:
    versions: List[ProductVersion]


def _parse_epoch(raw: Any, *, field_name: str, required: bool) -> Optional[int]:
    if raw is None:
        if required:
            raise ValueError(f"{field_name} is required")
        return None
    if isinstance(raw, (int, float)):
        return int(raw)
    text = str(raw).strip()
    if not text:
        if required:
            raise ValueError(f"{field_name} is required")
        return None
    if text.isdigit():
        return int(text)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _require_str(data: Dict[str, Any], key: str) -> str:
    value = str(data.get(key) or "").strip()
    if not value:
        raise ValueError(f"{key} is required")
    return value


def _validate_file_bundle(config: Dict[str, Any], *, billing_model: str) -> None:
    selection_type = _require_str(config, "selection_type")
    if selection_type != "date_range":
        raise ValueError("file_bundle.selection_type must be 'date_range'")
    _parse_epoch(config.get("date_start"), field_name="file_bundle.date_start", required=True)
    _parse_epoch(config.get("date_end"), field_name="file_bundle.date_end", required=True)
    access_mode = _require_str(config, "access_mode")
    if access_mode not in ("purchase", "rental"):
        raise ValueError("file_bundle.access_mode must be 'purchase' or 'rental'")
    if billing_model == "rental" or access_mode == "rental":
        hours = int(config.get("rental_duration_hours") or 0)
        if hours <= 0:
            raise ValueError("file_bundle.rental_duration_hours must be > 0 for rental")


def _validate_api_package(config: Dict[str, Any]) -> None:
    route_allowlist = config.get("route_allowlist")
    credits = int(config.get("credit_amount") or 0)
    period_limit = int(config.get("monthly_call_limit") or 0)
    if not isinstance(route_allowlist, list) and credits <= 0 and period_limit <= 0:
        raise ValueError("api_package requires at least one of route_allowlist, credit_amount, monthly_call_limit")


def _validate_internal_api_package(config: Dict[str, Any]) -> None:
    namespaces = config.get("internal_namespaces")
    if not isinstance(namespaces, list) or not namespaces:
        raise ValueError("internal_api_package.internal_namespaces must be a non-empty list")


def _validate_product_version(data: Dict[str, Any]) -> ProductVersion:
    sku = _require_str(data, "sku")
    product_type = _require_str(data, "product_type")
    if product_type not in ("file_bundle", "api_package", "internal_api_package"):
        raise ValueError("product_type must be one of: file_bundle, api_package, internal_api_package")
    billing_model = _require_str(data, "billing_model")
    if billing_model not in ("one_time", "rental", "subscription", "credit_pack"):
        raise ValueError("billing_model must be one of: one_time, rental, subscription, credit_pack")

    config = data.get("config") if isinstance(data.get("config"), dict) else {}
    if product_type == "file_bundle":
        _validate_file_bundle(config, billing_model=billing_model)
    elif product_type == "api_package":
        _validate_api_package(config)
    else:
        _validate_internal_api_package(config)

    return ProductVersion(
        sku=sku,
        product_type=product_type,
        display_name=_require_str(data, "display_name"),
        billing_model=billing_model,
        effective_at=_parse_epoch(data.get("effective_at"), field_name="effective_at", required=True) or 0,
        sunset_at=_parse_epoch(data.get("sunset_at"), field_name="sunset_at", required=False),
        amount=max(0, int(data.get("amount") or 0)),
        currency=_require_str(data, "currency").upper(),
        tax_code=str(data.get("tax_code") or "").strip() or None,
        config=config,
    )


def load_product_catalog() -> ProductCatalog:
    enabled = bool(getattr(S, "catalog_commercialization_enabled", False))
    raw = str(getattr(S, "catalog_pricing_catalog", "") or "")
    if not enabled:
        return ProductCatalog(versions=[])
    if not raw.strip():
        return ProductCatalog(versions=[])
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ValueError("invalid CATALOG_PRICING_CATALOG json") from exc

    versions_raw = payload.get("versions") if isinstance(payload, dict) else None
    if not isinstance(versions_raw, list):
        raise ValueError("CATALOG_PRICING_CATALOG must contain versions[]")

    versions = [_validate_product_version(row) for row in versions_raw if isinstance(row, dict)]
    versions.sort(key=lambda x: (x.sku, x.effective_at))
    return ProductCatalog(versions=versions)

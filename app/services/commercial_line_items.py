from __future__ import annotations

from typing import Any, Dict, Literal

from pydantic import BaseModel, Field, field_validator

from app.services.subscription_entitlement_templates import map_plan_to_entitlement_template, assert_plan_version_compatible

ProductType = Literal["file_bundle", "api_package", "internal_api_package"]
BillingModel = Literal["one_time", "rental", "subscription", "credit_pack"]
SourceSystem = Literal["shopping_cart", "commercial_direct", "subscription_cycle"]

SCHEMA_VERSION = "v1"


class CommercialLineItem(BaseModel):
    schema_version: str = Field(default=SCHEMA_VERSION)
    sku: str
    product_type: ProductType
    billing_model: BillingModel
    source_system: SourceSystem
    quantity: int = Field(default=1, ge=1)
    scope: Dict[str, Any] = Field(default_factory=dict)
    pricing_ref: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("sku")
    @classmethod
    def _validate_sku(cls, value: str) -> str:
        out = str(value or "").strip()
        if not out:
            raise ValueError("sku is required")
        return out


def validate_commercial_line_item(payload: Dict[str, Any]) -> CommercialLineItem:
    return CommercialLineItem.model_validate(payload)


def from_shopping_cart_item(item: Dict[str, Any]) -> CommercialLineItem:
    product_type = str(item.get("product_type") or "").strip()
    if product_type not in {"file_bundle", "api_package", "internal_api_package"}:
        raise ValueError("shopping cart commercial item requires product_type")
    billing_model = str(item.get("billing_model") or "one_time")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "sku": item.get("sku"),
        "product_type": product_type,
        "billing_model": billing_model,
        "source_system": "shopping_cart",
        "quantity": int(item.get("quantity") or 1),
        "scope": dict(item.get("scope") or {}),
        "pricing_ref": {
            "currency": item.get("currency") or "USD",
            "unit_price_cents": int(item.get("unit_price_cents") or 0),
            "cart_id": item.get("cart_id"),
        },
    }
    return validate_commercial_line_item(payload)


def from_direct_checkout_request(payload: Dict[str, Any]) -> CommercialLineItem:
    normalized = {
        "schema_version": payload.get("schema_version") or SCHEMA_VERSION,
        "sku": payload.get("sku"),
        "product_type": payload.get("product_type"),
        "billing_model": payload.get("billing_model"),
        "source_system": "commercial_direct",
        "quantity": int(payload.get("quantity") or 1),
        "scope": dict(payload.get("scope") or {}),
        "pricing_ref": dict(payload.get("pricing_ref") or {}),
    }
    return validate_commercial_line_item(normalized)


def from_subscription_plan(plan: Dict[str, Any]) -> CommercialLineItem:
    plan_id = str(plan.get("plan_id") or "").strip()
    if not plan_id:
        raise ValueError("subscription plan requires plan_id")
    assert_plan_version_compatible(plan)

    sku = str(plan.get("sku") or f"subscription_plan:{plan_id}")
    product_type = str(plan.get("product_type") or "internal_api_package")
    billing_model = str(plan.get("billing_model") or "subscription")
    entitlement_template = map_plan_to_entitlement_template(plan)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "sku": sku,
        "product_type": product_type,
        "billing_model": billing_model,
        "source_system": "subscription_cycle",
        "quantity": int(plan.get("quantity") or 1),
        "scope": {
            "plan_id": plan_id,
            "interval": plan.get("interval") or "month",
            "renewal_policy": plan.get("renewal_policy") or "auto",
            "entitlement_template": entitlement_template,
            **dict(plan.get("scope") or {}),
        },
        "pricing_ref": {
            "currency": plan.get("currency") or "USD",
            "price_cents": int(plan.get("price_cents") or 0),
            "subscription_id": plan.get("subscription_id"),
            "plan_version": int(plan.get("plan_version") or 1),
        },
    }
    return validate_commercial_line_item(payload)

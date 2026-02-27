from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc(value: Any, *, default: datetime | None = None) -> datetime:
    if value is None:
        if default is not None:
            return default
        return _utc_now()
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _interval_seconds(interval: str) -> int:
    if interval == "year":
        return 365 * 24 * 3600
    if interval == "week":
        return 7 * 24 * 3600
    return 30 * 24 * 3600


def assert_plan_version_compatible(plan: Dict[str, Any]) -> None:
    version = int(plan.get("plan_version") or 1)
    min_supported = int(plan.get("min_supported_version") or 1)
    max_supported = int(plan.get("max_supported_version") or version)
    if version < min_supported or version > max_supported:
        raise ValueError("subscription plan version is not compatible with entitlement template mapper")


def map_plan_to_entitlement_template(plan: Dict[str, Any], *, now: datetime | None = None) -> Dict[str, Any]:
    assert_plan_version_compatible(plan)
    now_utc = _to_utc(now, default=_utc_now())

    interval = str(plan.get("interval") or "month")
    starts_at = _to_utc(plan.get("current_period_start") or plan.get("starts_at"), default=now_utc)
    ends_at = _to_utc(
        plan.get("current_period_end"),
        default=starts_at + timedelta(seconds=_interval_seconds(interval)),
    )

    access = dict(plan.get("access_template") or {})
    limits = dict(plan.get("limit_overrides") or {})
    credits = dict(plan.get("credit_grant") or {})
    if not access and not limits and not credits:
        # allow subscription plans to use generic scope mapping
        access = dict(plan.get("scope") or {})

    return {
        "template_version": "v1",
        "plan_id": str(plan.get("plan_id") or ""),
        "plan_version": int(plan.get("plan_version") or 1),
        "sku": str(plan.get("sku") or f"subscription_plan:{plan.get('plan_id') or 'unknown'}"),
        "product_type": str(plan.get("product_type") or "internal_api_package"),
        "billing_model": "subscription",
        "access": access,
        "limits": limits,
        "credits": credits,
        "window": {
            "interval": interval,
            "starts_at": starts_at.isoformat(),
            "ends_at": ends_at.isoformat(),
            "renewal_policy": str(plan.get("renewal_policy") or "auto"),
            "pause_policy": str(plan.get("pause_policy") or "suspend_access"),
            "resumption_policy": str(plan.get("resumption_policy") or "resume_current_period"),
            "cancel_at_period_end": bool(plan.get("cancel_at_period_end") or False),
        },
    }


def map_subscription_state_to_entitlement(subscription: Dict[str, Any], template: Dict[str, Any], *, now: datetime | None = None) -> Dict[str, Any]:
    now_utc = _to_utc(now, default=_utc_now())
    status = str(subscription.get("status") or "").lower()
    starts_at = _to_utc(subscription.get("current_period_start") or template.get("window", {}).get("starts_at"), default=now_utc)
    ends_at = _to_utc(subscription.get("current_period_end") or template.get("window", {}).get("ends_at"), default=starts_at)
    cancel_at_period_end = bool(subscription.get("cancel_at_period_end") or template.get("window", {}).get("cancel_at_period_end"))

    if status in {"active", "trialing"}:
        entitlement_status = "active" if starts_at <= now_utc and (not cancel_at_period_end or now_utc < ends_at) else "pending_payment"
        if cancel_at_period_end and now_utc >= ends_at:
            entitlement_status = "expired"
    elif status in {"paused"}:
        entitlement_status = "pending_payment"
    elif status in {"past_due", "unpaid", "incomplete"}:
        entitlement_status = "pending_payment"
    elif status in {"canceled", "cancelled", "expired", "ended"}:
        entitlement_status = "expired"
    else:
        entitlement_status = "pending_payment"

    return {
        "status": entitlement_status,
        "starts_at": starts_at.isoformat(),
        "ends_at": ends_at.isoformat(),
        "scope": {
            "access": dict(template.get("access") or {}),
            "limits": dict(template.get("limits") or {}),
            "credits": dict(template.get("credits") or {}),
            "subscription": {
                "plan_id": template.get("plan_id"),
                "plan_version": template.get("plan_version"),
                "renewal_policy": template.get("window", {}).get("renewal_policy"),
                "pause_policy": template.get("window", {}).get("pause_policy"),
                "resumption_policy": template.get("window", {}).get("resumption_policy"),
                "cancel_at_period_end": cancel_at_period_end,
            },
        },
    }


def project_plan_change_templates(current_plan: Dict[str, Any], next_plan: Dict[str, Any], *, effective_at: Any) -> Dict[str, Any]:
    effective_dt = _to_utc(effective_at)
    current_template = map_plan_to_entitlement_template(current_plan, now=effective_dt)
    next_template = map_plan_to_entitlement_template(next_plan, now=effective_dt)
    return {
        "effective_at": effective_dt.isoformat(),
        "current_template": current_template,
        "future_template": next_template,
        "update_policy": "apply_future_template_from_effective_at",
    }

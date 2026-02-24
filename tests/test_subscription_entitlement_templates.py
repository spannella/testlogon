from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.subscription_entitlement_templates import (
    map_plan_to_entitlement_template,
    map_subscription_state_to_entitlement,
    project_plan_change_templates,
)


def test_active_subscription_maps_to_active_entitlement() -> None:
    plan = {
        "plan_id": "pro-monthly",
        "plan_version": 2,
        "product_type": "api_package",
        "interval": "month",
        "access_template": {"route_allowlist": ["/v1/api/data"]},
        "limit_overrides": {"monthly_call_limit": 1000},
        "credit_grant": {"credits": 500},
    }
    template = map_plan_to_entitlement_template(plan)
    out = map_subscription_state_to_entitlement(
        {
            "status": "active",
            "current_period_start": "2026-01-01T00:00:00Z",
            "current_period_end": "2026-02-01T00:00:00Z",
        },
        template,
        now=datetime(2026, 1, 15, tzinfo=timezone.utc),
    )
    assert out["status"] == "active"
    assert out["scope"]["limits"]["monthly_call_limit"] == 1000


def test_plan_change_updates_future_template_behavior() -> None:
    current_plan = {
        "plan_id": "pro-monthly",
        "plan_version": 1,
        "product_type": "api_package",
        "interval": "month",
        "limit_overrides": {"monthly_call_limit": 1000},
    }
    next_plan = {
        "plan_id": "pro-monthly",
        "plan_version": 2,
        "product_type": "api_package",
        "interval": "month",
        "limit_overrides": {"monthly_call_limit": 5000},
        "renewal_policy": "auto",
    }
    projection = project_plan_change_templates(current_plan, next_plan, effective_at="2026-03-01T00:00:00Z")
    assert projection["future_template"]["plan_version"] == 2
    assert projection["future_template"]["limits"]["monthly_call_limit"] == 5000
    assert projection["current_template"]["limits"]["monthly_call_limit"] == 1000


def test_incompatible_plan_version_rejected() -> None:
    with pytest.raises(ValueError):
        map_plan_to_entitlement_template(
            {
                "plan_id": "legacy",
                "plan_version": 5,
                "min_supported_version": 1,
                "max_supported_version": 3,
            }
        )


def test_pause_cancel_resume_policy_mapping() -> None:
    template = map_plan_to_entitlement_template(
        {
            "plan_id": "creator",
            "plan_version": 3,
            "pause_policy": "suspend_access",
            "resumption_policy": "resume_current_period",
            "renewal_policy": "auto",
        }
    )
    paused = map_subscription_state_to_entitlement({"status": "paused"}, template)
    assert paused["status"] == "pending_payment"

    canceled = map_subscription_state_to_entitlement(
        {
            "status": "active",
            "cancel_at_period_end": True,
            "current_period_start": "2026-01-01T00:00:00Z",
            "current_period_end": "2026-02-01T00:00:00Z",
        },
        template,
        now=datetime(2026, 2, 2, tzinfo=timezone.utc),
    )
    assert canceled["status"] == "expired"

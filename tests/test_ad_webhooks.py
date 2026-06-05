"""Offline regression tests for ad-platform webhooks (ADS-011 / GAP-0055).

These run fully in-memory with mocked dispatch — no real AWS, no dev stack.
Fails before the fix (AD_WEBHOOK_EVENT_TYPES / ad_webhooks.emit_ad_event absent);
passes after.
"""
from __future__ import annotations

from unittest.mock import patch


def test_ad_event_types_registered_in_v2():
    """All AD_WEBHOOK_EVENT_TYPES must be present in WEBHOOK_EVENT_TYPES_V2."""
    from app.services.webhook_service import (
        WEBHOOK_EVENT_TYPES_V2,
        AD_WEBHOOK_EVENT_TYPES,
    )

    assert AD_WEBHOOK_EVENT_TYPES, "AD_WEBHOOK_EVENT_TYPES is empty"
    for event_type in AD_WEBHOOK_EVENT_TYPES:
        assert event_type.startswith("ad."), event_type
        assert event_type in WEBHOOK_EVENT_TYPES_V2, (
            f"Ad event type '{event_type}' not registered in WEBHOOK_EVENT_TYPES_V2"
        )


def test_emit_ad_event_dispatches_for_known_type():
    """emit_ad_event must dispatch a known ad.* event via the webhook service."""
    from app.services.ad_webhooks import emit_ad_event

    with patch(
        "app.services.ad_webhooks.dispatch_webhook_event",
        return_value=["del_abc123"],
    ) as mock_dispatch:
        result = emit_ad_event(
            "ad.campaign.completed",
            "user1",
            {"campaign_id": "c1", "budget_cents": 5000},
        )

    mock_dispatch.assert_called_once()
    kwargs = mock_dispatch.call_args.kwargs
    assert kwargs["event_type"] == "ad.campaign.completed"
    assert kwargs["user_sub"] == "user1"
    assert kwargs["data"]["campaign_id"] == "c1"
    assert result == ["del_abc123"]


def test_emit_ad_event_ignores_unknown_type():
    """emit_ad_event must silently ignore unknown / non-ad event types."""
    from app.services.ad_webhooks import emit_ad_event

    with patch("app.services.ad_webhooks.dispatch_webhook_event") as mock_dispatch:
        assert emit_ad_event("unknown.event", "user1", {}) == []
        # A valid non-ad event type must also be rejected by this adapter.
        assert emit_ad_event("message.created", "user1", {}) == []
        mock_dispatch.assert_not_called()


def test_emit_ad_event_requires_owner():
    """emit_ad_event must no-op when there is no account owner sub."""
    from app.services.ad_webhooks import emit_ad_event

    with patch("app.services.ad_webhooks.dispatch_webhook_event") as mock_dispatch:
        assert emit_ad_event("ad.campaign.paused", "", {"campaign_id": "c1"}) == []
        mock_dispatch.assert_not_called()


def test_emit_ad_event_does_not_raise_on_dispatch_failure():
    """emit_ad_event must never raise even if dispatch throws."""
    from app.services.ad_webhooks import emit_ad_event

    with patch(
        "app.services.ad_webhooks.dispatch_webhook_event",
        side_effect=RuntimeError("DDB unavailable"),
    ):
        assert emit_ad_event("ad.campaign.paused", "user1", {"campaign_id": "c1"}) == []

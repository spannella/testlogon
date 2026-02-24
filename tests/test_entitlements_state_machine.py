from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.models_entitlements import EntitlementModel
from app.services import entitlements


def _ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def test_allowed_transitions() -> None:
    assert entitlements.can_transition("pending_payment", "active")
    assert entitlements.can_transition("pending_payment", "revoked")
    assert entitlements.can_transition("active", "expired")
    assert entitlements.can_transition("active", "revoked")
    assert entitlements.can_transition("active", "consumed")


def test_forbidden_transitions() -> None:
    with pytest.raises(ValueError, match="forbidden entitlement transition"):
        entitlements.assert_transition_allowed("pending_payment", "consumed")
    with pytest.raises(ValueError, match="forbidden entitlement transition"):
        entitlements.assert_transition_allowed("expired", "active")
    with pytest.raises(ValueError, match="forbidden entitlement transition"):
        entitlements.assert_transition_allowed("revoked", "active")
    with pytest.raises(ValueError, match="forbidden entitlement transition"):
        entitlements.assert_transition_allowed("consumed", "active")


def test_expiration_semantics_use_utc_clock() -> None:
    state = entitlements.EntitlementState(
        status="active",
        starts_at=_ts("2026-01-01T00:00:00Z"),
        ends_at=_ts("2026-01-05T00:00:00Z"),
    )
    before = entitlements.resolve_effective_status(state, now=_ts("2026-01-04T23:59:59Z"))
    at_end = entitlements.resolve_effective_status(state, now=_ts("2026-01-05T00:00:00Z"))
    assert before == "active"
    assert at_end == "expired"


def test_model_contains_required_domain_fields_and_normalizes_utc() -> None:
    model = EntitlementModel(
        entitlement_id="ent_1",
        user_id="user_1",
        sku="files-daily-2026-01",
        product_type="file_bundle",
        status="pending_payment",
        scope={"selection_type": "date_range"},
        starts_at="2026-01-01T00:00:00Z",
        ends_at="2026-01-31T00:00:00+00:00",
        usage_limit=100,
        usage_consumed=0,
        created_at=datetime(2026, 1, 1, 0, 0, 0),
        updated_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        created_by="system",
    )
    assert model.entitlement_id == "ent_1"
    assert model.user_id == "user_1"
    assert model.sku == "files-daily-2026-01"
    assert model.product_type == "file_bundle"
    assert model.scope["selection_type"] == "date_range"
    assert model.starts_at.tzinfo is not None
    assert model.created_at.tzinfo is not None
    assert model.created_at.utcoffset() == timezone.utc.utcoffset(model.created_at)


def test_transition_state_rejects_terminal_state_updates() -> None:
    state = entitlements.EntitlementState(
        status="revoked",
        starts_at=_ts("2026-01-01T00:00:00Z"),
        ends_at=None,
    )
    with pytest.raises(ValueError, match="forbidden entitlement transition"):
        entitlements.transition_state(state, to_status="active")

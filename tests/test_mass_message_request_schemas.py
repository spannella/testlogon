from __future__ import annotations

import time

import pytest
pydantic = pytest.importorskip("pydantic")
ValidationError = pydantic.ValidationError

from app.models_mass_message import MassMessageCreateCampaignRequest


def _valid_payload() -> dict:
    return {
        "conversation_ids": ["c1", "c2"],
        "content": {"kind": "text", "text": "hello"},
        "mode": "immediate",
        "idempotency_key": "idem-key-12345",
    }


def test_create_campaign_schema_accepts_valid_immediate_payload() -> None:
    model = MassMessageCreateCampaignRequest(**_valid_payload())
    assert model.mode == "immediate"
    assert model.send_at is None
    assert model.conversation_ids == ["c1", "c2"]


def test_create_campaign_schema_deduplicates_conversation_ids() -> None:
    payload = _valid_payload()
    payload["conversation_ids"] = ["c1", "c1", "c2", "c2"]
    model = MassMessageCreateCampaignRequest(**payload)
    assert model.conversation_ids == ["c1", "c2"]


def test_create_campaign_schema_rejects_destination_limit_overflow() -> None:
    payload = _valid_payload()
    payload["conversation_ids"] = [f"c{i}" for i in range(101)]
    with pytest.raises(ValidationError) as ctx:
        MassMessageCreateCampaignRequest(**payload)
    errors = ctx.value.errors()
    assert any(err["loc"] == ("conversation_ids",) for err in errors)


def test_create_campaign_schema_rejects_empty_text_payload() -> None:
    payload = _valid_payload()
    payload["content"]["text"] = "   "
    with pytest.raises(ValidationError) as ctx:
        MassMessageCreateCampaignRequest(**payload)
    errors = ctx.value.errors()
    assert any("text must not be empty" in err["msg"] for err in errors)


def test_create_campaign_schema_requires_future_send_at_for_scheduled() -> None:
    payload = _valid_payload()
    payload["mode"] = "scheduled"
    payload["send_at"] = int(time.time()) - 5
    with pytest.raises(ValidationError) as ctx:
        MassMessageCreateCampaignRequest(**payload)
    errors = ctx.value.errors()
    assert any("send_at must be in the future" in err["msg"] for err in errors)


def test_create_campaign_schema_rejects_send_at_in_immediate_mode() -> None:
    payload = _valid_payload()
    payload["send_at"] = int(time.time()) + 120
    with pytest.raises(ValidationError) as ctx:
        MassMessageCreateCampaignRequest(**payload)
    errors = ctx.value.errors()
    assert any("send_at is not allowed in immediate mode" in err["msg"] for err in errors)


def test_create_campaign_schema_structured_validation_error_for_unknown_field() -> None:
    payload = _valid_payload()
    payload["unknown"] = "field"
    with pytest.raises(ValidationError) as ctx:
        MassMessageCreateCampaignRequest(**payload)
    errors = ctx.value.errors()
    assert any(err["type"] == "extra_forbidden" for err in errors)

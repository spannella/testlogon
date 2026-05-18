from __future__ import annotations

import pytest

pydantic = pytest.importorskip("pydantic")

from app.models_mass_message import (
    MassMessageCancelCampaignResponse,
    MassMessageCampaignListResponse,
    MassMessageCampaignDetailResponse,
    MassMessageCreateCampaignResponse,
)


def test_create_response_schema_serializes_consistent_fields() -> None:
    model = MassMessageCreateCampaignResponse(
        campaign_id="mmc_1",
        mode="immediate",
        status="pending",
        send_at=None,
        accepted_count=2,
        accepted_conversation_ids=["c1", "c2"],
        rejected=[{"conversation_id": "c3", "reason": "not_a_participant"}],
        counters={"total": 2, "queued": 2, "sent": 0, "failed": 0, "cancelled": 0},
        created_at=1760000000,
        updated_at=1760000000,
    )
    payload = model.model_dump()
    assert payload["campaign_id"] == "mmc_1"
    assert payload["accepted_count"] == 2
    assert set(payload["counters"].keys()) == {"total", "queued", "sent", "failed", "cancelled"}
    assert payload["rejected"][0]["conversation_id"] == "c3"


def test_detail_response_schema_serializes_destination_statuses_consistently() -> None:
    model = MassMessageCampaignDetailResponse(
        campaign_id="mmc_1",
        sender_id="u1",
        mode="scheduled",
        status="processing",
        send_at=1760003600,
        counters={"total": 1, "queued": 0, "sent": 1, "failed": 0, "cancelled": 0},
        destinations=[
            {
                "campaign_id": "mmc_1",
                "conversation_id": "c1",
                "state": "sent",
                "message_id": "m1",
                "error_code": None,
                "attempt_count": 1,
                "updated_at": 1760003601,
                "created_at": 1760003500,
                "campaign_state": "mmc_1#sent",
            }
        ],
        created_at=1760003500,
        updated_at=1760003601,
    )
    payload = model.model_dump()
    assert payload["destinations"][0]["state"] == "sent"
    assert payload["destinations"][0]["campaign_state"] == "mmc_1#sent"
    assert set(payload["counters"].keys()) == {"total", "queued", "sent", "failed", "cancelled"}


def test_openapi_schema_contains_examples_for_create_and_detail_models() -> None:
    create_schema = MassMessageCreateCampaignResponse.model_json_schema()
    detail_schema = MassMessageCampaignDetailResponse.model_json_schema()
    list_schema = MassMessageCampaignListResponse.model_json_schema()
    cancel_schema = MassMessageCancelCampaignResponse.model_json_schema()

    assert "examples" in create_schema
    assert "examples" in detail_schema
    assert "examples" in list_schema
    assert "examples" in cancel_schema
    assert create_schema["examples"][0]["campaign_id"] == "mmc_123"
    assert detail_schema["examples"][0]["campaign_id"] == "mmc_123"
    assert list_schema["examples"][0]["items"][0]["campaign_id"] == "mmc_123"
    assert cancel_schema["examples"][0]["campaign_id"] == "mmc_123"


def test_cancel_response_schema_serializes_consistent_fields() -> None:
    model = MassMessageCancelCampaignResponse(
        campaign_id="mmc_1",
        status="cancelled",
        cancelled_destinations=3,
        counters={"total": 5, "queued": 1, "sent": 1, "failed": 0, "cancelled": 3},
        updated_at=1760000123,
    )
    payload = model.model_dump()
    assert payload["campaign_id"] == "mmc_1"
    assert payload["status"] == "cancelled"
    assert payload["cancelled_destinations"] == 3

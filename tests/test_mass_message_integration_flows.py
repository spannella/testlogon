from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("anyio")
pytest.importorskip("fastapi")
pytest.importorskip("pydantic")

from app.models_mass_message import MassMessageCreateCampaignRequest
from app.routers import messaging


def test_immediate_campaign_integration_create_worker_status_with_partial_failure() -> None:
    req = MassMessageCreateCampaignRequest(
        conversation_ids=["c1", "c2"],
        content={"kind": "text", "text": "hello world"},
        mode="immediate",
        idempotency_key="idem-int-1",
    )
    convo_table = MagicMock()
    convo_table.get_item.side_effect = [
        {"Item": {"conversation_id": "c1", "type": "dm"}},
        {"Item": {"conversation_id": "c2", "type": "group"}},
    ]

    campaign_store = {
        "campaign_id": "mmc_int_1",
        "sender_id": "u1",
        "mode": "immediate",
        "status": "pending",
        "total": 0,
        "queued": 0,
        "sent": 0,
        "failed": 0,
        "cancelled": 0,
        "created_at": 1760000000,
        "updated_at": 1760000000,
    }
    destinations_store: dict[str, dict] = {}

    def _create_or_get(**kwargs):
        assert kwargs["mode"] == "immediate"
        return dict(campaign_store), True

    def _upsert_destination(**kwargs):
        cid = kwargs["conversation_id"]
        row = {
            "campaign_id": kwargs["campaign_id"],
            "conversation_id": cid,
            "state": kwargs["state"],
            "message_id": kwargs.get("message_id"),
            "error_code": kwargs.get("error_code"),
            "attempt_count": destinations_store.get(cid, {}).get("attempt_count", 0) + 1,
            "updated_at": kwargs.get("updated_at", 1760000001),
            "created_at": destinations_store.get(cid, {}).get("created_at", 1760000001),
            "campaign_state": f"{kwargs['campaign_id']}#{kwargs['state']}",
        }
        destinations_store[cid] = row
        return row

    def _apply_counter_delta(*, from_state=None, to_state: str, **_kwargs):
        field_map = {"pending": "queued", "sent": "sent", "failed": "failed", "cancelled": "cancelled"}
        if from_state in field_map:
            campaign_store[field_map[from_state]] = max(0, campaign_store[field_map[from_state]] - 1)
        if to_state in field_map:
            campaign_store[field_map[to_state]] += 1
        if from_state is None:
            campaign_store["total"] += 1
        campaign_store["updated_at"] += 1
        return dict(campaign_store)

    def _set_submission_result(*, accepted_conversation_ids, rejected, **_kwargs):
        campaign_store["accepted_conversation_ids"] = list(accepted_conversation_ids)
        campaign_store["rejected_destinations"] = list(rejected)
        return dict(campaign_store)

    def _update_status(*, next_status: str, **_kwargs):
        campaign_store["status"] = next_status
        campaign_store["updated_at"] += 1
        return dict(campaign_store)

    def _process_with_retry(*, destination: dict, **_kwargs):
        if destination["conversation_id"] == "c2":
            return {"state": "failed", "message_id": None, "error_code": "policy_blocked", "attempts": 1}
        return {"state": "sent", "message_id": f"m_{destination['conversation_id']}", "error_code": None, "attempts": 1}

    with (
        patch.object(messaging, "tbl_convos", convo_table),
        patch.object(messaging, "get_participant_any", return_value={"status": "active"}),
        patch.object(messaging, "create_or_get_mass_campaign_record", side_effect=_create_or_get),
        patch.object(messaging, "upsert_mass_destination", side_effect=_upsert_destination),
        patch.object(messaging, "apply_destination_counter_delta", side_effect=_apply_counter_delta),
        patch.object(messaging, "set_campaign_submission_result", side_effect=_set_submission_result),
        patch.object(messaging, "get_mass_campaign_record", side_effect=lambda campaign_id: dict(campaign_store)),
        patch.object(
            messaging,
            "list_mass_destinations_page",
            side_effect=lambda campaign_id, limit=100, start_key=None: (list(destinations_store.values()), None),
        ),
        patch.object(messaging, "update_mass_campaign_status", side_effect=_update_status),
        patch.object(messaging, "_process_mass_message_destination_with_retry", side_effect=_process_with_retry),
        patch.object(messaging, "_kickoff_mass_message_dispatch"),
    ):
        created = messaging.create_mass_message_campaign(req, user_id="u1")
        worker_out = messaging.run_mass_message_immediate_worker(campaign_id=created.campaign_id, max_concurrency=4)
        detail = messaging.get_mass_message_campaign(created.campaign_id, limit=100, user_id="u1")

    assert created.accepted_count == 2
    assert worker_out == {"processed": 2, "sent": 1, "failed": 1}
    assert detail.counters.total == 2
    assert detail.counters.sent == 1
    assert detail.counters.failed == 1
    states = {d.conversation_id: d.state for d in detail.destinations}
    assert states == {"c1": "sent", "c2": "failed"}
    message_ids = {d.conversation_id: d.message_id for d in detail.destinations}
    assert message_ids["c1"] == "m_c1"


def test_scheduled_campaign_integration_pre_due_and_post_due_dispatch() -> None:
    import time as _time
    _future_ts = int(_time.time()) + 600
    req = MassMessageCreateCampaignRequest(
        conversation_ids=["c1"],
        content={"kind": "text", "text": "scheduled hello"},
        mode="scheduled",
        send_at=_future_ts,
        idempotency_key="idem-int-2",
    )
    convo_table = MagicMock()
    convo_table.get_item.return_value = {"Item": {"conversation_id": "c1", "type": "dm"}}

    campaign_store = {
        "campaign_id": "mmc_sched_1",
        "sender_id": "u1",
        "mode": "scheduled",
        "status": "scheduled",
        "send_at": _future_ts,
        "total": 0,
        "queued": 0,
        "sent": 0,
        "failed": 0,
        "cancelled": 0,
        "created_at": _future_ts - 1000,
        "updated_at": _future_ts - 1000,
    }

    def _create_or_get(**kwargs):
        assert kwargs["mode"] == "scheduled"
        return dict(campaign_store), True

    def _apply_counter_delta(*, from_state=None, to_state: str, **_kwargs):
        if from_state is None and to_state == "pending":
            campaign_store["total"] = 1
            campaign_store["queued"] = 1
        return dict(campaign_store)

    def _list_due(*, now_ts: int, limit: int):
        if now_ts < campaign_store["send_at"]:
            return []
        if campaign_store["status"] != "scheduled":
            return []
        return [dict(campaign_store)]

    def _update_status(*, next_status: str, **_kwargs):
        campaign_store["status"] = next_status
        return dict(campaign_store)

    with (
        patch.object(messaging, "tbl_convos", convo_table),
        patch.object(messaging, "get_participant_any", return_value={"status": "active"}),
        patch.object(messaging, "create_or_get_mass_campaign_record", side_effect=_create_or_get),
        patch.object(messaging, "upsert_mass_destination", return_value={"state": "pending"}),
        patch.object(messaging, "apply_destination_counter_delta", side_effect=_apply_counter_delta),
        patch.object(messaging, "set_campaign_submission_result"),
        patch.object(messaging, "get_mass_campaign_record", side_effect=lambda campaign_id: dict(campaign_store)),
        patch.object(messaging, "_kickoff_mass_message_dispatch"),
        patch.object(messaging, "list_due_scheduled_mass_campaigns", side_effect=_list_due),
        patch.object(messaging, "update_mass_campaign_status", side_effect=_update_status),
        patch.object(messaging.threading, "Thread") as thread_cls,
    ):
        created = messaging.create_mass_message_campaign(req, user_id="u1")
        pre_due = messaging.dispatch_due_scheduled_mass_campaigns(now_ts_value=_future_ts - 100, limit=10)
        post_due = messaging.dispatch_due_scheduled_mass_campaigns(now_ts_value=_future_ts + 1, limit=10)

    assert created.mode == "scheduled"
    assert pre_due == {"scanned": 0, "claimed": 0, "skipped": 0}
    assert post_due == {"scanned": 1, "claimed": 1, "skipped": 0}
    thread_cls.assert_called_once()

from __future__ import annotations

import pytest
from unittest.mock import patch

pytest.importorskip("fastapi")
pytest.importorskip("anyio")

from app.routers import messaging


def test_dispatch_due_scheduled_mass_campaigns_claims_once_and_enqueues() -> None:
    due = [
        {"campaign_id": "mmc_1", "status": "scheduled", "send_at": 1700000000},
        {"campaign_id": "mmc_2", "status": "scheduled", "send_at": 1700000001},
    ]
    with (
        patch.object(messaging, "list_due_scheduled_mass_campaigns", return_value=due),
        patch.object(messaging, "update_mass_campaign_status") as update_status,
        patch.object(messaging.threading, "Thread") as thread_cls,
    ):
        # Simulate second campaign already claimed by another dispatcher.
        update_status.side_effect = [None, RuntimeError("conditional")]
        out = messaging.dispatch_due_scheduled_mass_campaigns(now_ts_value=1700000100, limit=100)

    assert out == {"scanned": 2, "claimed": 1, "skipped": 1}
    assert update_status.call_count == 2
    thread_cls.assert_called_once()


def test_dispatch_due_scheduled_mass_campaigns_does_not_include_not_due_campaigns() -> None:
    with (
        patch.object(messaging, "list_due_scheduled_mass_campaigns", return_value=[]),
        patch.object(messaging, "update_mass_campaign_status") as update_status,
        patch.object(messaging.threading, "Thread") as thread_cls,
    ):
        out = messaging.dispatch_due_scheduled_mass_campaigns(now_ts_value=1700000000, limit=50)

    assert out == {"scanned": 0, "claimed": 0, "skipped": 0}
    update_status.assert_not_called()
    thread_cls.assert_not_called()


def test_dispatch_due_scheduled_mass_campaigns_respects_feature_flag() -> None:
    with (
        patch.object(messaging, "_messaging_mass_send_enabled", return_value=False),
        patch.object(messaging, "list_due_scheduled_mass_campaigns") as list_due,
    ):
        out = messaging.dispatch_due_scheduled_mass_campaigns(now_ts_value=1700000000, limit=50)
    assert out == {"scanned": 0, "claimed": 0, "skipped": 0}
    list_due.assert_not_called()


def test_dispatch_due_scheduled_mass_campaigns_rolls_back_status_when_no_worker_slot() -> None:
    due = [{"campaign_id": "mmc_1", "status": "scheduled", "send_at": 1700000000}]
    with (
        patch.object(messaging, "list_due_scheduled_mass_campaigns", return_value=due),
        patch.object(messaging, "update_mass_campaign_status") as update_status,
        patch.object(messaging, "_reserve_mass_message_worker_slot", return_value=False),
        patch.object(messaging, "record_mass_message_limit_event") as record_limit_event,
        patch.object(messaging.threading, "Thread") as thread_cls,
    ):
        out = messaging.dispatch_due_scheduled_mass_campaigns(now_ts_value=1700000100, limit=10)

    assert out == {"scanned": 1, "claimed": 0, "skipped": 1}
    assert update_status.call_count == 2
    first = update_status.call_args_list[0].kwargs
    second = update_status.call_args_list[1].kwargs
    assert first["next_status"] == "processing"
    assert second["next_status"] == "scheduled"
    assert second["expected_status"] == "processing"
    record_limit_event.assert_called_once_with(scope="worker", limit_name="concurrent_workers", outcome="rollback")
    thread_cls.assert_not_called()


def test_dispatch_due_scheduled_mass_campaigns_recovers_when_worker_thread_start_fails() -> None:
    due = [{"campaign_id": "mmc_1", "status": "scheduled", "send_at": 1700000000}]
    with (
        patch.object(messaging, "list_due_scheduled_mass_campaigns", return_value=due),
        patch.object(messaging, "update_mass_campaign_status") as update_status,
        patch.object(messaging, "_reserve_mass_message_worker_slot", return_value=True),
        patch.object(messaging, "_release_mass_message_worker_slot") as release_slot,
        patch.object(messaging, "record_mass_message_limit_event") as record_limit_event,
        patch.object(messaging.threading, "Thread") as thread_cls,
    ):
        thread_cls.return_value.start.side_effect = RuntimeError("thread start failed")
        out = messaging.dispatch_due_scheduled_mass_campaigns(now_ts_value=1700000100, limit=10)

    assert out == {"scanned": 1, "claimed": 0, "skipped": 1}
    release_slot.assert_called_once()
    assert update_status.call_count == 2
    record_limit_event.assert_called_once_with(scope="worker", limit_name="concurrent_workers", outcome="start_failure")

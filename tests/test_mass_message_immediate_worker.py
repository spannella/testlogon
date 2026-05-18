from __future__ import annotations

from unittest.mock import patch

from app.routers import messaging
from fastapi import HTTPException


def test_run_mass_message_immediate_worker_continues_after_failure() -> None:
    campaign = {
        "campaign_id": "mmc_1",
        "sender_id": "u_1",
        "status": "pending",
        "content_kind": "text",
        "content_text": "hello",
    }
    destinations = [
        {"campaign_id": "mmc_1", "conversation_id": "c_ok", "state": "pending"},
        {"campaign_id": "mmc_1", "conversation_id": "c_fail", "state": "pending"},
    ]

    def _fake_process(**kwargs) -> dict:
        destination = kwargs["destination"]
        if destination["conversation_id"] == "c_fail":
            raise RuntimeError("boom")
        return {"state": "sent", "message_id": "m_sent", "error_code": None}

    with (
        patch.object(messaging, "get_mass_campaign_record", return_value=campaign),
        patch.object(messaging, "list_mass_destinations_page", side_effect=[(destinations, None)]),
        patch.object(messaging, "_process_mass_message_destination_with_retry", side_effect=_fake_process),
        patch.object(messaging, "upsert_mass_destination") as upsert_destination,
        patch.object(messaging, "apply_destination_counter_delta") as apply_delta,
        patch.object(messaging, "update_mass_campaign_status") as update_status,
    ):
        out = messaging.run_mass_message_immediate_worker(campaign_id="mmc_1", max_concurrency=2)

    assert out == {"processed": 2, "sent": 1, "failed": 1}
    assert upsert_destination.call_count == 2
    states = {call.kwargs["conversation_id"]: call.kwargs["state"] for call in upsert_destination.call_args_list}
    assert states["c_ok"] == "sent"
    assert states["c_fail"] == "failed"
    apply_delta.assert_called()
    update_status.assert_called()


def test_process_mass_message_destination_requires_stored_payload() -> None:
    with patch.object(messaging, "_get_conversation_or_404") as get_convo:
        try:
            messaging._process_mass_message_destination(
                campaign={"campaign_id": "mmc_1", "sender_id": "u_1", "content_kind": "text", "content_text": ""},
                destination={"conversation_id": "c_1"},
            )
            assert False, "expected ValueError"
        except ValueError as exc:
            assert str(exc) == "campaign_payload_invalid"
    get_convo.assert_not_called()


def test_process_mass_message_destination_with_retry_retries_retryable_errors() -> None:
    destination = {"conversation_id": "c_1"}
    calls = {"count": 0}

    def _flaky_process(*, campaign: dict, destination: dict) -> dict:
        calls["count"] += 1
        if calls["count"] < 3:
            raise RuntimeError("temporary")
        return {"state": "sent", "message_id": "m_1", "error_code": None}

    with (
        patch.object(messaging, "_process_mass_message_destination", side_effect=_flaky_process),
        patch.object(messaging, "time") as time_mod,
    ):
        result = messaging._process_mass_message_destination_with_retry(
            campaign={"campaign_id": "mmc_1"},
            destination=destination,
            max_attempts=3,
            base_backoff=0.1,
            max_backoff=1.0,
        )

    assert result["state"] == "sent"
    assert result["attempts"] == 3
    assert calls["count"] == 3
    assert time_mod.sleep.call_count == 2


def test_process_mass_message_destination_with_retry_does_not_retry_permanent_errors() -> None:
    with patch.object(messaging, "_process_mass_message_destination", side_effect=ValueError("campaign_payload_invalid")) as process:
        result = messaging._process_mass_message_destination_with_retry(
            campaign={"campaign_id": "mmc_1"},
            destination={"conversation_id": "c_1"},
            max_attempts=5,
            base_backoff=0.1,
            max_backoff=1.0,
        )

    assert result["state"] == "failed"
    assert result["error_code"] == "unknown"
    assert result["attempts"] == 1
    assert process.call_count == 1


def test_process_mass_message_destination_with_retry_retries_transient_http_errors() -> None:
    destination = {"conversation_id": "c_1"}
    calls = {"count": 0}

    def _flaky_process(*, campaign: dict, destination: dict) -> dict:
        calls["count"] += 1
        if calls["count"] == 1:
            raise HTTPException(status_code=503)
        return {"state": "sent", "message_id": "m_1", "error_code": None}

    with (
        patch.object(messaging, "_process_mass_message_destination", side_effect=_flaky_process),
        patch.object(messaging, "record_mass_message_destination_retry") as record_retry,
        patch.object(messaging, "time") as time_mod,
    ):
        result = messaging._process_mass_message_destination_with_retry(
            campaign={"campaign_id": "mmc_1"},
            destination=destination,
            max_attempts=3,
            base_backoff=0.1,
            max_backoff=1.0,
        )

    assert result["state"] == "sent"
    assert result["attempts"] == 2
    assert calls["count"] == 2
    record_retry.assert_called_once_with(mode="immediate", error_code="transient_infra")
    time_mod.sleep.assert_called_once()


def test_process_mass_message_destination_with_retry_treats_policy_errors_as_terminal() -> None:
    with (
        patch.object(messaging, "_process_mass_message_destination", side_effect=HTTPException(status_code=409)) as process,
        patch.object(messaging, "record_mass_message_destination_retry") as record_retry,
        patch.object(messaging, "time") as time_mod,
    ):
        result = messaging._process_mass_message_destination_with_retry(
            campaign={"campaign_id": "mmc_1"},
            destination={"conversation_id": "c_1"},
            max_attempts=5,
            base_backoff=0.1,
            max_backoff=1.0,
        )

    assert result["state"] == "failed"
    assert result["error_code"] == "policy_blocked"
    assert result["attempts"] == 1
    assert process.call_count == 1
    record_retry.assert_not_called()
    time_mod.sleep.assert_not_called()


def test_process_mass_message_destination_with_retry_returns_cancelled_when_campaign_cancelled() -> None:
    with (
        patch.object(messaging, "get_mass_campaign_record", return_value={"campaign_id": "mmc_1", "status": "cancelled"}),
        patch.object(messaging, "_process_mass_message_destination") as process,
    ):
        result = messaging._process_mass_message_destination_with_retry(
            campaign={"campaign_id": "mmc_1"},
            destination={"conversation_id": "c_1"},
            max_attempts=3,
            base_backoff=0.1,
            max_backoff=1.0,
        )

    assert result["state"] == "cancelled"
    assert result["attempts"] == 1
    process.assert_not_called()


def test_classify_mass_destination_error_uses_canonical_taxonomy() -> None:
    assert messaging._classify_mass_destination_error(HTTPException(status_code=403)) == "authorization"
    assert messaging._classify_mass_destination_error(HTTPException(status_code=404)) == "conversation_missing"
    assert messaging._classify_mass_destination_error(HTTPException(status_code=409)) == "policy_blocked"
    assert messaging._classify_mass_destination_error(RuntimeError("boom")) == "transient_infra"


def test_run_mass_message_immediate_worker_respects_kill_switch() -> None:
    with patch.object(messaging, "_messaging_mass_send_enabled", return_value=False):
        out = messaging.run_mass_message_immediate_worker(campaign_id="mmc_1", max_concurrency=1)
    assert out == {"processed": 0, "sent": 0, "failed": 0}


def test_run_mass_message_immediate_worker_emits_completion_audit_event() -> None:
    campaign = {
        "campaign_id": "mmc_1",
        "sender_id": "u_1",
        "status": "pending",
        "mode": "immediate",
        "content_kind": "text",
        "content_text": "hello",
    }
    destinations = [{"campaign_id": "mmc_1", "conversation_id": "c_ok", "state": "pending"}]
    with (
        patch.object(messaging, "get_mass_campaign_record", return_value=campaign),
        patch.object(messaging, "list_mass_destinations_page", side_effect=[(destinations, None)]),
        patch.object(
            messaging,
            "_process_mass_message_destination_with_retry",
            return_value={"state": "sent", "message_id": "m_1", "error_code": None},
        ),
        patch.object(messaging, "upsert_mass_destination"),
        patch.object(messaging, "apply_destination_counter_delta"),
        patch.object(messaging, "update_mass_campaign_status"),
        patch.object(messaging, "audit_event") as audit_event,
    ):
        messaging.run_mass_message_immediate_worker(campaign_id="mmc_1", max_concurrency=1)

    audit_event.assert_called_once()
    assert audit_event.call_args.args[0] == "messaging_mass_campaign_completed"


def test_run_mass_message_immediate_worker_processes_multiple_pages() -> None:
    campaign = {
        "campaign_id": "mmc_1",
        "sender_id": "u_1",
        "status": "pending",
        "mode": "immediate",
        "content_kind": "text",
        "content_text": "hello",
    }
    page_one = [{"campaign_id": "mmc_1", "conversation_id": "c_1", "state": "pending"}]
    page_two = [{"campaign_id": "mmc_1", "conversation_id": "c_2", "state": "pending"}]
    with (
        patch.object(messaging, "get_mass_campaign_record", return_value=campaign),
        patch.object(
            messaging,
            "list_mass_destinations_page",
            side_effect=[
                (page_one, {"campaign_id": "mmc_1", "conversation_id": "c_1"}),
                (page_two, None),
            ],
        ),
        patch.object(
            messaging,
            "_process_mass_message_destination_with_retry",
            return_value={"state": "sent", "message_id": "m_1", "error_code": None},
        ),
        patch.object(messaging, "upsert_mass_destination"),
        patch.object(messaging, "apply_destination_counter_delta"),
        patch.object(messaging, "update_mass_campaign_status"),
    ):
        out = messaging.run_mass_message_immediate_worker(campaign_id="mmc_1", max_concurrency=2)

    assert out == {"processed": 2, "sent": 2, "failed": 0}


def test_run_mass_message_immediate_worker_processes_pending_on_later_page() -> None:
    campaign = {
        "campaign_id": "mmc_1",
        "sender_id": "u_1",
        "status": "pending",
        "mode": "immediate",
        "content_kind": "text",
        "content_text": "hello",
    }
    page_one = [{"campaign_id": "mmc_1", "conversation_id": "c_done", "state": "sent"}]
    page_two = [{"campaign_id": "mmc_1", "conversation_id": "c_pending", "state": "pending"}]
    with (
        patch.object(messaging, "get_mass_campaign_record", return_value=campaign),
        patch.object(
            messaging,
            "list_mass_destinations_page",
            side_effect=[
                (page_one, {"campaign_id": "mmc_1", "conversation_id": "c_done"}),
                (page_two, None),
            ],
        ),
        patch.object(
            messaging,
            "_process_mass_message_destination_with_retry",
            return_value={"state": "sent", "message_id": "m_pending", "error_code": None},
        ),
        patch.object(messaging, "upsert_mass_destination") as upsert_destination,
        patch.object(messaging, "apply_destination_counter_delta"),
        patch.object(messaging, "update_mass_campaign_status") as update_status,
    ):
        out = messaging.run_mass_message_immediate_worker(campaign_id="mmc_1", max_concurrency=2)

    assert out == {"processed": 1, "sent": 1, "failed": 0}
    upsert_destination.assert_called_once()
    update_status.assert_called_once()


def test_run_mass_message_immediate_worker_stops_when_campaign_cancelled() -> None:
    campaign = {
        "campaign_id": "mmc_1",
        "sender_id": "u_1",
        "status": "pending",
        "mode": "immediate",
        "content_kind": "text",
        "content_text": "hello",
    }
    with (
        patch.object(
            messaging,
            "get_mass_campaign_record",
            side_effect=[
                campaign,
                {"campaign_id": "mmc_1", "status": "cancelled"},
            ],
        ),
        patch.object(messaging, "list_mass_destinations_page") as list_page,
        patch.object(messaging, "_process_mass_message_destination_with_retry") as process_with_retry,
    ):
        out = messaging.run_mass_message_immediate_worker(campaign_id="mmc_1", max_concurrency=2)

    assert out == {"processed": 0, "sent": 0, "failed": 0}
    list_page.assert_not_called()
    process_with_retry.assert_not_called()


def test_run_mass_message_immediate_worker_records_cancelled_destination_outcome() -> None:
    campaign = {
        "campaign_id": "mmc_1",
        "sender_id": "u_1",
        "status": "pending",
        "mode": "immediate",
        "content_kind": "text",
        "content_text": "hello",
    }
    destinations = [{"campaign_id": "mmc_1", "conversation_id": "c_cancel", "state": "pending"}]
    with (
        patch.object(messaging, "get_mass_campaign_record", return_value=campaign),
        patch.object(messaging, "list_mass_destinations_page", side_effect=[(destinations, None)]),
        patch.object(
            messaging,
            "_process_mass_message_destination_with_retry",
            return_value={"state": "cancelled", "message_id": None, "error_code": None},
        ),
        patch.object(messaging, "upsert_mass_destination") as upsert_destination,
        patch.object(messaging, "apply_destination_counter_delta") as apply_delta,
        patch.object(messaging, "update_mass_campaign_status"),
        patch.object(messaging, "record_mass_message_destination_outcome") as record_outcome,
    ):
        out = messaging.run_mass_message_immediate_worker(campaign_id="mmc_1", max_concurrency=1)

    assert out == {"processed": 1, "sent": 0, "failed": 0}
    upsert_destination.assert_called_once_with(
        campaign_id="mmc_1",
        conversation_id="c_cancel",
        state="cancelled",
        message_id=None,
        error_code=None,
    )
    apply_delta.assert_called_once_with(campaign_id="mmc_1", to_state="cancelled", from_state="pending")
    record_outcome.assert_called_once_with(mode="immediate", outcome="cancelled", error_code="none")


def test_process_mass_message_destination_includes_campaign_id_in_archive_payload() -> None:
    campaign = {
        "campaign_id": "mmc_1",
        "sender_id": "u_1",
        "content_kind": "text",
        "content_text": "hello campaign",
    }
    destination = {"conversation_id": "c_1"}
    with (
        patch.object(messaging, "_get_conversation_or_404", return_value={"conversation_id": "c_1", "type": "dm"}),
        patch.object(messaging, "_enforce_helpdesk_send_constraints"),
        patch.object(messaging, "require_participant_active"),
        patch.object(messaging, "tbl_parts") as tbl_parts,
        patch.object(messaging, "tbl_msgs"),
        patch.object(messaging, "_sync_gallery_index_message"),
        patch.object(messaging, "_send_mass_message_destination"),
        patch.object(messaging, "_message_retention_ttl", return_value=None),
        patch.object(messaging, "_serialize_message_event_payload", return_value={"message_id": "m_1"}),
        patch.object(messaging, "_emit_message_lifecycle_archive_event_or_503") as archive_emit,
        patch.object(messaging, "_meter_message_send"),
        patch.object(messaging, "new_id", return_value="abc"),
        patch.object(messaging, "now_ts", return_value=1700000000),
    ):
        tbl_parts.query.return_value = {"Items": []}
        messaging._process_mass_message_destination(campaign=campaign, destination=destination)

    payload = archive_emit.call_args.kwargs["payload"]
    assert payload["campaign_id"] == "mmc_1"

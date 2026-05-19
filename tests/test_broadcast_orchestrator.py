from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch, Mock, ANY

import pytest

from app.services import broadcast_orchestrator


def _session(status: str = "draft") -> SimpleNamespace:
    return SimpleNamespace(id="s1", status=status, profile_id="p1", stream_key_ref=None)


def test_start_session_provisioning_failure_transitions_to_error() -> None:
    provider = SimpleNamespace(name="local", provision=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("aws down")))
    with (
        patch.object(broadcast_orchestrator, "get_broadcast_provider", return_value=provider),
        patch.object(broadcast_orchestrator, "get_session", return_value=_session("draft")),
        patch.object(broadcast_orchestrator, "get_profile", return_value=SimpleNamespace(id="p1")),
        patch.object(broadcast_orchestrator, "put_output"),
        patch.object(broadcast_orchestrator, "transition_session_status") as transition,
    ):
        transition.side_effect = [
            _session("provisioning"),
            _session("error"),
        ]
        with pytest.raises(RuntimeError):
            broadcast_orchestrator.start_session_with_provider(
                session_id="s1",
                actor="ops",
                reason="start",
                correlation_id="cid-1",
                idempotency_key="idem-1",
            )

    assert transition.call_args_list[1].kwargs["to_status"] == "error"
    assert "provisioning_failed:RuntimeError" in transition.call_args_list[1].kwargs["reason"]


def test_stop_session_from_ready_transitions_to_stopped() -> None:
    stop = Mock(return_value=None)
    provider = SimpleNamespace(name="local", stop=stop)
    with (
        patch.object(broadcast_orchestrator, "get_broadcast_provider", return_value=provider),
        patch.object(broadcast_orchestrator, "get_session", return_value=_session("ready")),
        patch.object(broadcast_orchestrator, "record_broadcast_session_action") as record_action,
        patch.object(broadcast_orchestrator, "transition_session_status") as transition,
    ):
        transition.side_effect = [_session("stopping"), _session("stopped")]
        out = broadcast_orchestrator.stop_session_with_provider(
            session_id="s1",
            actor="ops",
            reason="operator-stop",
            correlation_id="cid-9",
            idempotency_key="idem-9",
        )

    assert out.status == "stopped"
    stop.assert_called_once_with(ANY, correlation_id="cid-9", idempotency_key="idem-9")
    assert transition.call_args_list[0].kwargs["to_status"] == "stopping"
    assert transition.call_args_list[1].kwargs["to_status"] == "stopped"
    record_action.assert_called_once_with(provider="local", action="stop", result="success")


def test_stop_session_failure_transitions_to_error() -> None:
    stop = Mock(side_effect=RuntimeError("provider stop failed"))
    provider = SimpleNamespace(name="aws", stop=stop)
    with (
        patch.object(broadcast_orchestrator, "get_broadcast_provider", return_value=provider),
        patch.object(broadcast_orchestrator, "get_session", return_value=_session("live")),
        patch.object(broadcast_orchestrator, "record_broadcast_session_action") as record_action,
        patch.object(broadcast_orchestrator, "transition_session_status") as transition,
    ):
        transition.side_effect = [_session("stopping"), _session("error")]
        with pytest.raises(RuntimeError):
            broadcast_orchestrator.stop_session_with_provider(session_id="s1", actor="ops", reason="operator-stop")

    assert transition.call_args_list[0].kwargs["to_status"] == "stopping"
    assert transition.call_args_list[1].kwargs["to_status"] == "error"
    assert "stop_failed:RuntimeError" in transition.call_args_list[1].kwargs["reason"]
    record_action.assert_called_once_with(provider="aws", action="stop", result="failure")


def test_start_session_failure_from_ready_transitions_to_error() -> None:
    start = Mock(side_effect=RuntimeError("provider start failed"))
    provider = SimpleNamespace(name="aws", start=start)
    with (
        patch.object(broadcast_orchestrator, "get_broadcast_provider", return_value=provider),
        patch.object(broadcast_orchestrator, "get_session", return_value=_session("ready")),
        patch.object(broadcast_orchestrator, "get_profile", return_value=SimpleNamespace(id="p1")),
        patch.object(broadcast_orchestrator, "record_broadcast_session_action") as record_action,
        patch.object(broadcast_orchestrator, "transition_session_status") as transition,
        patch.object(broadcast_orchestrator, "get_output", return_value=None),
        patch.object(broadcast_orchestrator, "put_output"),
    ):
        transition.side_effect = [_session("error")]
        with pytest.raises(RuntimeError):
            broadcast_orchestrator.start_session_with_provider(
                session_id="s1",
                actor="ops",
                reason="operator-start",
                correlation_id="cid-2",
                idempotency_key="idem-2",
            )

    start.assert_called_once_with(ANY, correlation_id="cid-2", idempotency_key="idem-2")
    assert transition.call_args_list[0].kwargs["to_status"] == "error"
    assert "start_failed:RuntimeError" in transition.call_args_list[0].kwargs["reason"]
    record_action.assert_called_once_with(provider="aws", action="start", result="failure")


def test_delete_session_records_success_metric() -> None:
    provider = SimpleNamespace(name="local", teardown=Mock(return_value=None))
    with (
        patch.object(broadcast_orchestrator, "get_broadcast_provider", return_value=provider),
        patch.object(broadcast_orchestrator, "get_session", return_value=_session("stopped")),
        patch.object(broadcast_orchestrator, "delete_session", return_value={"ok": True}) as delete_session,
        patch.object(broadcast_orchestrator, "record_broadcast_session_action") as record_action,
    ):
        out = broadcast_orchestrator.delete_session_with_provider(session_id="s1")
    assert out == {"ok": True}
    delete_session.assert_called_once_with("s1")
    record_action.assert_called_once_with(provider="local", action="delete", result="success")


def test_delete_session_records_failure_metric_and_raises() -> None:
    provider = SimpleNamespace(name="aws", teardown=Mock(side_effect=RuntimeError("teardown failed")))
    with (
        patch.object(broadcast_orchestrator, "get_broadcast_provider", return_value=provider),
        patch.object(broadcast_orchestrator, "get_session", return_value=_session("stopped")),
        patch.object(broadcast_orchestrator, "delete_session") as delete_session,
        patch.object(broadcast_orchestrator, "record_broadcast_session_action") as record_action,
        pytest.raises(RuntimeError),
    ):
        broadcast_orchestrator.delete_session_with_provider(session_id="s1")
    delete_session.assert_not_called()
    record_action.assert_called_once_with(provider="aws", action="delete", result="failure")

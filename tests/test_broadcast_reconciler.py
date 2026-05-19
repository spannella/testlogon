from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from app.services import broadcast_reconciler


def _session(session_id: str, status: str, updated_at: str = "2026-03-01T00:00:00+00:00") -> SimpleNamespace:
    return SimpleNamespace(id=session_id, status=status, updated_at=updated_at)


def test_reconcile_detects_drift_and_transitions_after_sla() -> None:
    output = SimpleNamespace(
        mediapackage_endpoint=None,
        cloudfront_playback_url=None,
        s3_archive_prefix=None,
        aws_input_arn=None,
        aws_channel_arn=None,
        provider_state_snapshot={"drift_first_detected_at": 1_000},
    )
    provider = SimpleNamespace(name="local", status=lambda _s: SimpleNamespace(state="stopped"))
    fake_settings = SimpleNamespace(broadcast_drift_sla_seconds=10, broadcast_stale_session_seconds=300)
    with (
        patch.object(broadcast_reconciler, "S", fake_settings),
        patch.object(broadcast_reconciler, "get_broadcast_provider", return_value=provider),
        patch.object(broadcast_reconciler, "list_sessions_by_status", side_effect=lambda status, **kw: {"items": [_session("s1", "live")]} if status == "live" else {"items": []}),
        patch.object(broadcast_reconciler, "get_output", return_value=output),
        patch.object(broadcast_reconciler, "put_output"),
        patch.object(broadcast_reconciler, "transition_session_status") as transition,
    ):
        out = broadcast_reconciler.reconcile_once(now_ts=1_100)

    assert out["drift_incidents"] == 1
    assert transition.call_args.kwargs["reason"].startswith("drift_detected:")


def test_reconcile_marks_stale_sessions() -> None:
    output = SimpleNamespace(
        mediapackage_endpoint=None,
        cloudfront_playback_url=None,
        s3_archive_prefix=None,
        aws_input_arn=None,
        aws_channel_arn=None,
        provider_state_snapshot={},
    )
    provider = SimpleNamespace(name="local", status=lambda _s: SimpleNamespace(state="provisioning"))
    fake_settings = SimpleNamespace(broadcast_drift_sla_seconds=120, broadcast_stale_session_seconds=60)
    with (
        patch.object(broadcast_reconciler, "S", fake_settings),
        patch.object(broadcast_reconciler, "get_broadcast_provider", return_value=provider),
        patch.object(broadcast_reconciler, "list_sessions_by_status", side_effect=lambda status, **kw: {"items": [_session("s2", "provisioning", "2026-03-01T00:00:00+00:00")]} if status == "provisioning" else {"items": []}),
        patch.object(broadcast_reconciler, "get_output", return_value=output),
        patch.object(broadcast_reconciler, "put_output"),
        patch.object(broadcast_reconciler, "transition_session_status") as transition,
    ):
        out = broadcast_reconciler.reconcile_once(now_ts=2_000_000_000)

    assert out["stale_incidents"] == 1
    assert transition.call_args.kwargs["reason"] == "stale_session_timeout:provisioning"

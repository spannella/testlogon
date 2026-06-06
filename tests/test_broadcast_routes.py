from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import broadcast


def _ctx(role: str = "user") -> dict:
    return {"user_sub": "user-1", "session_id": "sid-1", "role": role}

def _req(cid: str = "cid-1"):
    return SimpleNamespace(headers={"x-correlation-id": cid})


def _session(status: str = "draft"):
    return SimpleNamespace(
        model_dump=lambda: {
            "id": "s1",
            "profile_id": "p1",
            "status": status,
            "ingest_url": None,
            "stream_key_ref": None,
            "started_at": None,
            "stopped_at": None,
            "created_by": "user-1",
            "created_at": "2026-03-25T00:00:00+00:00",
            "updated_at": "2026-03-25T00:00:00+00:00",
        },
        status=status,
        id="s1",
        profile_id="p1",
        ingest_url=None,
        stream_key_ref=None,
        started_at=None,
        stopped_at=None,
        created_by="user-1",
        created_at="2026-03-25T00:00:00+00:00",
        updated_at="2026-03-25T00:00:00+00:00",
    )


def test_create_profile_route_contract() -> None:
    profile = SimpleNamespace(
        model_dump=lambda: {
            "id": "bp-1",
            "name": "Main",
            "region": "us-east-1",
            "rendition_preset": "720p",
            "watermark_asset": None,
            "drm_policy_id": None,
            "created_by": "user-1",
            "created_at": "2026-03-25T00:00:00+00:00",
            "updated_at": "2026-03-25T00:00:00+00:00",
        },
        id="bp-1",
        drm_credentials_ref=None,
    )
    body = broadcast.BroadcastProfileCreateIn(name="Main", region="us-east-1", rendition_preset="720p")
    with (
        patch.object(broadcast, "create_profile", return_value=profile) as create_profile,
        patch.object(broadcast, "record_broadcast_action") as record_broadcast_action,
    ):
        out = broadcast.create_profile_route(body, request=_req(), ctx=_ctx())
    create_profile.assert_called_once()
    record_broadcast_action.assert_called_once()
    assert out.id == "bp-1"


def test_start_session_forbidden_for_non_admin() -> None:
    with pytest.raises(HTTPException) as exc:
        broadcast.start_session_route("s1", broadcast.BroadcastSessionActionIn(reason="x"), request=_req(), ctx=_ctx(role="user"))
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "BROADCAST_ROLE_FORBIDDEN"


def test_start_session_transitions_to_live_from_ready() -> None:
    with (
        patch.object(broadcast, "get_session", return_value=_session("ready")),
        patch.object(broadcast, "start_session_with_provider", return_value=_session("live")) as start_session_with_provider,
        patch.object(broadcast, "record_broadcast_action") as record_broadcast_action,
        patch.object(broadcast, "get_output", return_value=None),
    ):
        out = broadcast.start_session_route("s1", broadcast.BroadcastSessionActionIn(reason="start"), request=_req(), ctx=_ctx(role="admin"))
    start_session_with_provider.assert_called_once()
    record_broadcast_action.assert_called_once()
    assert out.status == "live"


def test_start_session_forwards_correlation_and_idempotency_headers() -> None:
    req = SimpleNamespace(headers={"x-correlation-id": "cid-77", "x-idempotency-key": "idem-77"})
    with (
        patch.object(broadcast, "get_session", return_value=_session("ready")),
        patch.object(broadcast, "start_session_with_provider", return_value=_session("live")) as start_session_with_provider,
        patch.object(broadcast, "record_broadcast_action"),
        patch.object(broadcast, "get_output", return_value=None),
    ):
        broadcast.start_session_route("s1", broadcast.BroadcastSessionActionIn(reason="start"), request=req, ctx=_ctx(role="admin"))
    assert start_session_with_provider.call_args.kwargs["correlation_id"] == "cid-77"
    assert start_session_with_provider.call_args.kwargs["idempotency_key"] == "idem-77"


def test_start_session_failure_records_failed_audit_action() -> None:
    req = SimpleNamespace(headers={"x-correlation-id": "cid-start-fail"})
    with (
        patch.object(broadcast, "get_session", return_value=_session("ready")),
        patch.object(broadcast, "start_session_with_provider", side_effect=HTTPException(status_code=409, detail="conflict")),
        patch.object(broadcast, "record_broadcast_action") as record_broadcast_action,
        patch.object(broadcast, "get_output", return_value=None),
        pytest.raises(HTTPException),
    ):
        broadcast.start_session_route("s1", broadcast.BroadcastSessionActionIn(reason="start"), request=req, ctx=_ctx(role="admin"))
    record_broadcast_action.assert_called_once_with(
        action="start_session_failed",
        actor="user-1",
        correlation_id="cid-start-fail",
        resource_type="session",
        resource_id="s1",
        metadata={"reason": "start", "error": "HTTPException"},
    )


def test_get_session_route_passes_through() -> None:
    with (
        patch.object(broadcast, "get_session", return_value=_session("stopped")),
        patch.object(broadcast, "get_output", return_value=SimpleNamespace(mediapackage_endpoint="https://pkg.example/hls.m3u8", cloudfront_playback_url=None, s3_archive_prefix=None, aws_input_arn=None, aws_channel_arn=None, provider_state_snapshot={})),
    ):
        out = broadcast.get_session_route("s1", ctx=_ctx())
    assert out.status == "stopped"
    assert out.mediapackage_endpoint == "https://pkg.example/hls.m3u8"


def test_admin_audit_query_requires_operator_role() -> None:
    with pytest.raises(HTTPException) as exc:
        broadcast.query_audit_route(ctx=_ctx(role="user"))
    assert exc.value.status_code == 403


def test_mint_playback_url_route_uses_existing_output_url_when_present() -> None:
    with (
        patch.object(broadcast, "get_session", return_value=_session("live")),
        patch.object(
            broadcast,
            "get_output",
            return_value=SimpleNamespace(cloudfront_playback_url="http://localhost:8090/hls/s1/master.m3u8?md5=x&expires=1"),
        ),
        patch.object(
            broadcast,
            "mint_local_playback_url",
            return_value=SimpleNamespace(url="http://localhost:8090/new", expires_at=1234),
        ),
    ):
        out = broadcast.mint_playback_url_route("s1", ctx=_ctx())
    assert out.session_id == "s1"
    assert out.playback_url == "http://localhost:8090/hls/s1/master.m3u8?md5=x&expires=1"
    assert out.expires_at == 1234


def test_verify_playback_token_route_rejects_invalid_signature() -> None:
    with (
        patch.object(broadcast, "validate_cloudfront_token", return_value=False),
        patch.object(broadcast, "record_broadcast_output_error") as record_broadcast_output_error,
        pytest.raises(HTTPException) as exc,
    ):
        broadcast.verify_playback_token_route(path="/hls/x.m3u8", cf_token="bad", cf_expires=1, ctx=_ctx())
    assert exc.value.status_code == 403
    record_broadcast_output_error.assert_called_once_with(provider="aws", reason="invalid_playback_token")


def test_stop_session_route_handles_ready_session_stop() -> None:
    req = SimpleNamespace(headers={"x-correlation-id": "cid-stop-1", "x-idempotency-key": "idem-stop-1"})
    with (
        patch.object(broadcast, "get_session", return_value=_session("live")),
        patch.object(broadcast, "stop_session_with_provider", return_value=_session("stopped")) as stop_session_with_provider,
        patch.object(broadcast, "record_broadcast_action") as record_broadcast_action,
        patch.object(broadcast, "get_output", return_value=None),
    ):
        out = broadcast.stop_session_route("s1", broadcast.BroadcastSessionActionIn(reason="stop"), request=req, ctx=_ctx(role="admin"))
    assert out.status == "stopped"
    stop_session_with_provider.assert_called_once_with(
        session_id="s1",
        actor="user-1",
        reason="stop",
        correlation_id="cid-stop-1",
        idempotency_key="idem-stop-1",
    )
    record_broadcast_action.assert_called_once()


def test_stop_session_failure_records_failed_audit_action() -> None:
    req = SimpleNamespace(headers={"x-correlation-id": "cid-stop-fail", "x-idempotency-key": "idem-stop-fail"})
    with (
        patch.object(broadcast, "get_session", return_value=_session("live")),
        patch.object(broadcast, "stop_session_with_provider", side_effect=HTTPException(status_code=409, detail="conflict")),
        patch.object(broadcast, "record_broadcast_action") as record_broadcast_action,
        patch.object(broadcast, "get_output", return_value=None),
        pytest.raises(HTTPException),
    ):
        broadcast.stop_session_route("s1", broadcast.BroadcastSessionActionIn(reason="stop"), request=req, ctx=_ctx(role="admin"))
    record_broadcast_action.assert_called_once_with(
        action="stop_session_failed",
        actor="user-1",
        correlation_id="cid-stop-fail",
        resource_type="session",
        resource_id="s1",
        metadata={"reason": "stop", "error": "HTTPException"},
    )


def test_delete_session_failure_records_failed_audit_action() -> None:
    req = SimpleNamespace(headers={"x-correlation-id": "cid-del-fail"})
    with (
        patch.object(broadcast, "get_session", return_value=_session("stopped")),
        patch.object(broadcast, "delete_session_with_provider", side_effect=HTTPException(status_code=409, detail="conflict")),
        patch.object(broadcast, "record_broadcast_action") as record_broadcast_action,
        pytest.raises(HTTPException),
    ):
        broadcast.delete_session_route("s1", request=req, ctx=_ctx(role="admin"))
    record_broadcast_action.assert_called_once_with(
        action="delete_session_failed",
        actor="user-1",
        correlation_id="cid-del-fail",
        resource_type="session",
        resource_id="s1",
        metadata={"error": "HTTPException"},
    )


def test_delete_session_route_records_success_audit_action() -> None:
    req = SimpleNamespace(headers={"x-correlation-id": "cid-del-ok"})
    with (
        patch.object(broadcast, "get_session", return_value=_session("stopped")),
        patch.object(broadcast, "delete_session_with_provider", return_value={"ok": True}) as delete_session_with_provider,
        patch.object(broadcast, "record_broadcast_action") as record_broadcast_action,
    ):
        out = broadcast.delete_session_route("s1", request=req, ctx=_ctx(role="admin"))
    assert out.ok is True
    delete_session_with_provider.assert_called_once_with(session_id="s1")
    record_broadcast_action.assert_called_once_with(
        action="delete_session",
        actor="user-1",
        correlation_id="cid-del-ok",
        resource_type="session",
        resource_id="s1",
        metadata={},
    )


def test_mint_playback_url_route_returns_400_for_invalid_stream_key() -> None:
    with (
        patch.object(broadcast, "get_session", return_value=_session("live")),
        patch.object(broadcast, "get_output", return_value=None),
        patch.object(broadcast, "mint_local_playback_url", side_effect=ValueError("invalid stream key format")),
        patch.object(broadcast, "record_broadcast_output_error") as record_broadcast_output_error,
        pytest.raises(HTTPException) as exc,
    ):
        broadcast.mint_playback_url_route("s1", ctx=_ctx())
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "BROADCAST_INVALID_STREAM_KEY"
    record_broadcast_output_error.assert_called_once_with(provider="local", reason="invalid_stream_key")

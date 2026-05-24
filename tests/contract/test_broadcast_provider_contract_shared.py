from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.models_broadcast import BroadcastSessionModel
from app.services.broadcast_provider import AwsBroadcastProvider, LocalBroadcastProvider


def _session() -> BroadcastSessionModel:
    return BroadcastSessionModel(
        id="s1",
        profile_id="p1",
        status="ready",
        created_by="u1",
        created_at="2026-04-01T00:00:00+00:00",
        updated_at="2026-04-01T00:00:00+00:00",
    )


def _profile():
    return type("_P", (), {"rendition_preset": "720p", "drm_policy_id": None, "drm_credentials_ref": None})()


def _run_contract(provider) -> None:
    session = _session()
    out = provider.provision(session, profile=_profile(), correlation_id="cid-1", idempotency_key="idem-1")
    assert out.operation == "provision"
    assert provider.start(session).operation == "start"
    assert provider.stop(session).operation == "stop"
    assert provider.status(session).operation == "status"
    assert provider.teardown(session).operation == "teardown"


def test_local_provider_passes_shared_contract() -> None:
    _run_contract(LocalBroadcastProvider())


def test_aws_provider_passes_shared_contract() -> None:
    mock_ml_client = MagicMock()
    mock_ml_client.describe_channel.return_value = {"State": "IDLE"}
    mock_ml_client.delete_channel.return_value = {}
    mock_ml_client.list_inputs.return_value = {"Inputs": []}
    mock_mp_client = MagicMock()
    mock_mp_client.delete_origin_endpoint.return_value = {}
    mock_mp_client.delete_channel.return_value = {}

    with (
        patch("app.services.broadcast_provider.provision_mediolive_input_and_channel") as live,
        patch("app.services.broadcast_provider.provision_mediapackage_channel_and_endpoint") as pkg,
        patch("app.services.broadcast_provider._medialive_client", return_value=mock_ml_client),
        patch("app.services.broadcast_provider._mediapackage_client", return_value=mock_mp_client),
        patch("app.services.broadcast_provider._resolve_channel_id", return_value="ch1"),
        patch("app.services.broadcast_provider._find_input_by_name", return_value=None),
    ):
        live.return_value = type("_L", (), {"input_arn": "arn:live:in", "channel_arn": "arn:live:ch", "channel_id": "ch1", "archive_prefix": "s3://b/s1/", "state_snapshot": {"channel_state": "CREATING"}})()
        pkg.return_value = type("_P", (), {"channel_id": "pkg1", "channel_arn": "arn:pkg:ch", "endpoint_id": "ep1", "endpoint_url": "https://pkg.example/s1/master.m3u8", "endpoint_arn": "arn:pkg:ep", "packaging_metadata": {"drm_enabled": False}})()
        _run_contract(AwsBroadcastProvider())

from __future__ import annotations

from unittest.mock import patch

from app.models_broadcast import BroadcastSessionModel
from app.services.broadcast_provider import AwsBroadcastProvider, LocalBroadcastProvider, get_broadcast_provider


def _session() -> BroadcastSessionModel:
    return BroadcastSessionModel(
        id="s1",
        profile_id="p1",
        status="ready",
        created_by="u1",
        created_at="2026-03-26T00:00:00+00:00",
        updated_at="2026-03-26T00:00:00+00:00",
    )


def _assert_provider_contract(provider) -> None:
    session = _session()
    profile = type("_P", (), {"rendition_preset": "720p", "drm_policy_id": None, "drm_credentials_ref": None})()
    assert provider.provision(session, profile=profile).operation == "provision"
    assert provider.start(session).operation == "start"
    assert provider.stop(session).operation == "stop"
    assert provider.status(session).operation == "status"
    assert provider.teardown(session).operation == "teardown"


def test_local_provider_contract() -> None:
    _assert_provider_contract(LocalBroadcastProvider())


def test_aws_provider_contract() -> None:
    with (
        patch("app.services.broadcast_provider.provision_mediolive_input_and_channel") as provision_live,
        patch("app.services.broadcast_provider.provision_mediapackage_channel_and_endpoint") as provision_pkg,
    ):
        provision_live.return_value = type(
            "_RL",
            (),
            {"input_arn": "arn:aws:medialive:us-east-1:123:input:1", "channel_arn": "arn:aws:medialive:us-east-1:123:channel:1", "channel_id": "1", "archive_prefix": "s3://broadcast-archive/sessions/s1/", "state_snapshot": {"channel_state": "CREATING"}},
        )()
        provision_pkg.return_value = type(
            "_RP",
            (),
            {"channel_id": "pkg1", "channel_arn": "arn:aws:mediapackage:us-east-1:123:channels/pkg1", "endpoint_id": "ep1", "endpoint_url": "https://example/hls.m3u8", "endpoint_arn": "arn:aws:mediapackage:us-east-1:123:origin_endpoints/ep1", "packaging_metadata": {"drm_enabled": False}},
        )()
        _assert_provider_contract(AwsBroadcastProvider())


def test_provider_factory_switches_by_configuration_name() -> None:
    assert get_broadcast_provider("local").name == "local"
    assert get_broadcast_provider("aws").name == "aws"

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from app.services import broadcast_mediapackage


class _FakeMediaPackageClient:
    def __init__(self) -> None:
        self.channels = {}
        self.endpoints = {}

    def describe_channel(self, Id):  # noqa: N803
        if Id not in self.channels:
            raise RuntimeError("missing channel")
        return self.channels[Id]

    def create_channel(self, **kwargs):
        item = {"Id": kwargs["Id"], "Arn": f"arn:aws:mediapackage:channel:{kwargs['Id']}"}
        self.channels[kwargs["Id"]] = item
        return item

    def describe_origin_endpoint(self, Id):  # noqa: N803
        if Id not in self.endpoints:
            raise RuntimeError("missing endpoint")
        return self.endpoints[Id]

    def create_origin_endpoint(self, **kwargs):
        item = {"Id": kwargs["Id"], "Arn": f"arn:aws:mediapackage:endpoint:{kwargs['Id']}", "Url": f"https://pkg.example/{kwargs['Id']}.m3u8"}
        self.endpoints[kwargs["Id"]] = item
        return item


def test_provision_mediapackage_attaches_drm_for_drm_profile() -> None:
    fake = _FakeMediaPackageClient()
    profile = SimpleNamespace(rendition_preset="1080p", drm_policy_id="drm-1", drm_credentials_ref="secret://drm")
    with patch.object(broadcast_mediapackage, "_client", return_value=fake):
        out = broadcast_mediapackage.provision_mediapackage_channel_and_endpoint(
            session_id="s100",
            profile=profile,
            correlation_id="cid-1",
            idempotency_key="idem-1",
        )
    assert out.endpoint_url.endswith(".m3u8")
    assert out.packaging_metadata["drm_enabled"] is True

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

try:
    import boto3
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore[assignment]

from app.core.settings import S
from app.models_broadcast import BroadcastProfileModel


@dataclass(frozen=True)
class MediaPackageProvisionResult:
    channel_id: str
    channel_arn: str
    endpoint_id: str
    endpoint_url: str
    endpoint_arn: str
    packaging_metadata: Dict[str, Any]


def _client():
    if boto3 is None:  # pragma: no cover
        raise RuntimeError("boto3 is required for aws broadcast provider")
    return boto3.client(
        "mediapackage",
        region_name=S.aws_region or "us-east-1",
        endpoint_url=S.aws_endpoint_url or None,
    )


def _packaging_config_from_profile(profile: BroadcastProfileModel) -> Dict[str, Any]:
    return {
        "segment_duration_seconds": 4,
        "rendition_preset": profile.rendition_preset,
        "drm_enabled": bool(profile.drm_policy_id),
        "drm_policy_id": profile.drm_policy_id,
        "drm_key_provider_ref": profile.drm_credentials_ref,
        "playlist_window_seconds": 60,
    }


def provision_mediapackage_channel_and_endpoint(
    *,
    session_id: str,
    profile: BroadcastProfileModel,
    correlation_id: str,
    idempotency_key: str,
) -> MediaPackageProvisionResult:
    client = _client()
    channel_id = f"broadcast-{session_id}-pkg"
    endpoint_id = f"broadcast-{session_id}-hls"

    try:
        channel = client.describe_channel(Id=channel_id)
    except Exception:
        channel = client.create_channel(
            Id=channel_id,
            Description=f"Broadcast session {session_id}",
            Tags={"broadcast-session-id": session_id, "correlation-id": correlation_id, "idempotency-key": idempotency_key},
        )

    try:
        endpoint = client.describe_origin_endpoint(Id=endpoint_id)
    except Exception:
        package = _packaging_config_from_profile(profile)
        hls_package = {
            "SegmentDurationSeconds": package["segment_duration_seconds"],
            "PlaylistWindowSeconds": package["playlist_window_seconds"],
        }
        if package["drm_enabled"]:
            hls_package["Encryption"] = {
                "SpekeKeyProvider": {
                    "RoleArn": "arn:aws:iam::000000000000:role/MediaPackageSpekeRole",
                    "SystemIds": ["edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"],
                    "Url": "https://example.invalid/speke",
                },
                "ConstantInitializationVector": "00000000000000000000000000000000",
            }

        endpoint = client.create_origin_endpoint(
            Id=endpoint_id,
            ChannelId=channel_id,
            Description=f"Broadcast endpoint {session_id}",
            HlsPackage=hls_package,
            Tags={
                "broadcast-session-id": session_id,
                "correlation-id": correlation_id,
                "idempotency-key": idempotency_key,
                "drm-enabled": str(package["drm_enabled"]).lower(),
            },
        )

    package_meta = _packaging_config_from_profile(profile)
    package_meta["correlation_id"] = correlation_id
    package_meta["idempotency_key"] = idempotency_key
    return MediaPackageProvisionResult(
        channel_id=channel_id,
        channel_arn=str(channel.get("Arn") or ""),
        endpoint_id=endpoint_id,
        endpoint_url=str(endpoint.get("Url") or ""),
        endpoint_arn=str(endpoint.get("Arn") or ""),
        packaging_metadata=package_meta,
    )

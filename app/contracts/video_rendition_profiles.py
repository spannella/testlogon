from __future__ import annotations

from typing import Literal, TypedDict

RenditionName = Literal["1080p", "720p", "540p", "360p"]


class CanonicalRenditionProfile(TypedDict):
    name: RenditionName
    width: int
    height: int
    video_bitrate_kbps: int
    audio_bitrate_kbps: int
    fps: int
    gop_seconds: int


CANONICAL_ABR_LADDER: tuple[CanonicalRenditionProfile, ...] = (
    {
        "name": "1080p",
        "width": 1920,
        "height": 1080,
        "video_bitrate_kbps": 6000,
        "audio_bitrate_kbps": 192,
        "fps": 30,
        "gop_seconds": 2,
    },
    {
        "name": "720p",
        "width": 1280,
        "height": 720,
        "video_bitrate_kbps": 3500,
        "audio_bitrate_kbps": 128,
        "fps": 30,
        "gop_seconds": 2,
    },
    {
        "name": "540p",
        "width": 960,
        "height": 540,
        "video_bitrate_kbps": 2200,
        "audio_bitrate_kbps": 128,
        "fps": 30,
        "gop_seconds": 2,
    },
    {
        "name": "360p",
        "width": 640,
        "height": 360,
        "video_bitrate_kbps": 1200,
        "audio_bitrate_kbps": 96,
        "fps": 30,
        "gop_seconds": 2,
    },
)

CANONICAL_RENDITION_NAMES: tuple[RenditionName, ...] = tuple(profile["name"] for profile in CANONICAL_ABR_LADDER)


def manifest_variant_path(*, tenant_id: str, asset_id: str, rendition: RenditionName) -> str:
    return f"tenants/{tenant_id}/assets/{asset_id}/hls/{rendition}/index.m3u8"


def dash_representation_id(rendition: RenditionName) -> str:
    return f"v_{rendition}"

from __future__ import annotations

from typing import Any

from app.contracts.video_rendition_profiles import CANONICAL_ABR_LADDER


def ffmpeg_abr_profiles() -> list[dict[str, Any]]:
    profiles: list[dict[str, Any]] = []
    for rendition in CANONICAL_ABR_LADDER:
        profiles.append(
            {
                "name": rendition["name"],
                "width": rendition["width"],
                "height": rendition["height"],
                "fps": rendition["fps"],
                "video_bitrate": f"{rendition['video_bitrate_kbps']}k",
                "audio_bitrate": f"{rendition['audio_bitrate_kbps']}k",
                "gop_seconds": rendition["gop_seconds"],
            }
        )
    return profiles


def medialive_abr_profiles() -> list[dict[str, Any]]:
    profiles: list[dict[str, Any]] = []
    for rendition in CANONICAL_ABR_LADDER:
        profiles.append(
            {
                "NameModifier": f"_{rendition['name']}",
                "VideoDescription": {
                    "Width": rendition["width"],
                    "Height": rendition["height"],
                    "CodecSettings": {
                        "H264Settings": {
                            "Bitrate": rendition["video_bitrate_kbps"] * 1000,
                            "GopSize": rendition["gop_seconds"],
                            "GopSizeUnits": "SECONDS",
                            "FramerateNumerator": rendition["fps"],
                            "FramerateDenominator": 1,
                        }
                    },
                },
                "AudioDescriptions": [
                    {
                        "CodecSettings": {
                            "AacSettings": {
                                "Bitrate": rendition["audio_bitrate_kbps"] * 1000,
                            }
                        }
                    }
                ],
            }
        )
    return profiles

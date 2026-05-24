"""Centralized FFmpeg binary management (MEDIA-002).

Provides detection, validation, version checking, and codec verification
for the FFmpeg binary. All callsites should use `get_ffmpeg_path()` or
`is_ffmpeg_available()` instead of hardcoding "ffmpeg" or calling
`shutil.which("ffmpeg")` directly.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache

from app.core.settings import S

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FFmpegInfo:
    path: str
    version: str
    codecs: list[str] = field(default_factory=list)
    available: bool = False


REQUIRED_CODECS = {"libx264", "aac"}
RECOMMENDED_CODECS = {"libx265", "libvpx", "libopus"}
MIN_VERSION = (5, 0)  # Minimum FFmpeg 5.0


def _parse_version(version_line: str) -> str:
    """Extract version string from ffmpeg -version output first line.

    Examples:
        "ffmpeg version 6.1.1 Copyright ..." -> "6.1.1"
        "ffmpeg version n6.0-full ..." -> "n6.0-full"
        "ffmpeg version 5.1.4-0+deb12u1 ..." -> "5.1.4-0+deb12u1"
    """
    match = re.search(r"ffmpeg version\s+(\S+)", version_line)
    if match:
        return match.group(1)
    return ""


def _parse_version_tuple(version_str: str) -> tuple[int, int]:
    """Extract (major, minor) from a version string. Returns (0, 0) on failure."""
    # Strip leading 'n' or 'N' (e.g., "n6.0-full")
    cleaned = version_str.lstrip("nN")
    match = re.match(r"(\d+)\.(\d+)", cleaned)
    if match:
        return int(match.group(1)), int(match.group(2))
    return (0, 0)


def _parse_codecs(codecs_output: str) -> list[str]:
    """Parse ffmpeg -codecs output to find known encoder names.

    We look for lines containing encoder names we care about.
    Format: " DEAIL. codec_name  description (encoders: enc1 enc2 ...)"
    or lines that simply mention the encoder name.
    """
    known_encoders = {
        "libx264", "libx265", "libvpx", "libvpx-vp9",
        "libopus", "aac", "libfdk_aac", "libmp3lame",
        "libsvtav1", "libaom-av1",
    }
    found: list[str] = []
    for encoder in known_encoders:
        # Check if the encoder name appears in the codecs output
        if encoder in codecs_output:
            found.append(encoder)
    return sorted(found)


@lru_cache(maxsize=1)
def get_ffmpeg_info() -> FFmpegInfo:
    """Detect, validate, and cache FFmpeg binary info."""
    binary_path = S.ffmpeg_binary_path if S.ffmpeg_binary_path and S.ffmpeg_binary_path != "ffmpeg" else shutil.which("ffmpeg")
    if not binary_path:
        return FFmpegInfo(path="", version="", codecs=[], available=False)

    try:
        # Get version
        result = subprocess.run(
            [binary_path, "-version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return FFmpegInfo(path=binary_path, version="", codecs=[], available=False)

        version_line = result.stdout.split("\n")[0] if result.stdout else ""
        version = _parse_version(version_line)

        # Get codecs
        codec_result = subprocess.run(
            [binary_path, "-codecs"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        codecs = _parse_codecs(codec_result.stdout) if codec_result.returncode == 0 else []

        return FFmpegInfo(path=binary_path, version=version, codecs=codecs, available=True)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("FFmpeg detection failed: %s", exc)
        return FFmpegInfo(path=binary_path or "", version="", codecs=[], available=False)


def get_ffmpeg_path() -> str:
    """Get the validated FFmpeg binary path. Raises if unavailable."""
    info = get_ffmpeg_info()
    if not info.available:
        raise FFmpegNotAvailableError("FFmpeg binary not found or not functional")
    return info.path


def is_ffmpeg_available() -> bool:
    """Quick check if FFmpeg is available."""
    return get_ffmpeg_info().available


def validate_ffmpeg() -> dict:
    """Full validation returning status dict for health checks."""
    info = get_ffmpeg_info()
    if not info.available:
        return {
            "status": "unavailable",
            "path": info.path,
            "error": "Binary not found or not functional",
        }

    issues: list[str] = []

    # Check version
    major, minor = _parse_version_tuple(info.version)
    if (major, minor) < MIN_VERSION:
        issues.append(f"Version {info.version} is below minimum {MIN_VERSION[0]}.{MIN_VERSION[1]}")

    # Check required codecs
    missing_required = REQUIRED_CODECS - set(info.codecs)
    if missing_required:
        issues.append(f"Missing required codecs: {missing_required}")

    # Check recommended codecs
    missing_recommended = RECOMMENDED_CODECS - set(info.codecs)

    return {
        "status": "healthy" if not issues else "degraded",
        "path": info.path,
        "version": info.version,
        "codecs": info.codecs,
        "missing_required": sorted(missing_required) if missing_required else [],
        "missing_recommended": sorted(missing_recommended) if missing_recommended else [],
        "issues": issues,
    }


def clear_cache():
    """Clear the cached FFmpeg info (for testing or after install)."""
    get_ffmpeg_info.cache_clear()


class FFmpegNotAvailableError(Exception):
    """Raised when FFmpeg binary is not available."""
    pass

"""Regression test for GAP-0301: GET /internal/dev-tools/ffmpeg-health.

Offline / hermetic: patches `validate_ffmpeg` in the router module so no real
ffmpeg subprocess is forked. Verifies:
  - 200 + full body when ffmpeg is available (full dict).
  - 200 + minimal body when ffmpeg is UNAVAILABLE (3-key dict) -- the regression
    for the optional-fields correction (DevtoolsFfmpegHealthOut(**result) must not
    raise on the 3-key unavailable dict).
  - 404 when S.dev_mode is False (SECOPS-007 dev gate).

TestClient is avoided (broken in this env); the route handler coroutine/function
is called directly.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.core.settings import S
import app.routers.internal_devtools as devtools


FULL_AVAILABLE = {
    "status": "healthy",
    "path": "/usr/bin/ffmpeg",
    "version": "6.1.1",
    "codecs": ["aac", "libx264", "libx265"],
    "missing_required": [],
    "missing_recommended": [],
    "issues": [],
}

# The actual shape returned by validate_ffmpeg() when the binary is unavailable:
# only 3 keys (status, path, error). No version/codecs/missing_*/issues.
UNAVAILABLE_3KEY = {
    "status": "unavailable",
    "path": "/nonexistent/ffmpeg",
    "error": "Binary not found or not functional",
}


@pytest.fixture
def dev_mode_on():
    prev = S.dev_mode
    object.__setattr__(S, "dev_mode", True)
    try:
        yield
    finally:
        object.__setattr__(S, "dev_mode", prev)


def test_ffmpeg_health_available_returns_full_body(dev_mode_on):
    with patch.object(devtools, "validate_ffmpeg", return_value=FULL_AVAILABLE):
        out = devtools.get_devtools_ffmpeg_health()
    assert out.status == "healthy"
    assert out.version == "6.1.1"
    assert out.path == "/usr/bin/ffmpeg"
    assert "libx264" in out.codecs
    assert out.missing_required == []
    assert out.error is None


def test_ffmpeg_health_unavailable_3key_does_not_raise(dev_mode_on):
    """Regression: the 3-key unavailable dict must NOT raise ValidationError."""
    with patch.object(devtools, "validate_ffmpeg", return_value=UNAVAILABLE_3KEY):
        out = devtools.get_devtools_ffmpeg_health()
    assert out.status == "unavailable"
    assert out.path == "/nonexistent/ffmpeg"
    assert out.error == "Binary not found or not functional"
    # Optional fields default sensibly rather than crashing.
    assert out.version is None
    assert out.codecs == []
    assert out.missing_required == []
    assert out.missing_recommended == []
    assert out.issues == []


def test_ffmpeg_health_degraded_passthrough(dev_mode_on):
    degraded = dict(FULL_AVAILABLE, status="degraded", missing_required=["libx264"],
                    issues=["Missing required codecs: {'libx264'}"])
    with patch.object(devtools, "validate_ffmpeg", return_value=degraded):
        out = devtools.get_devtools_ffmpeg_health()
    assert out.status == "degraded"
    assert out.missing_required == ["libx264"]
    assert out.issues


def test_ffmpeg_health_404_when_dev_mode_off():
    prev = S.dev_mode
    object.__setattr__(S, "dev_mode", False)
    try:
        with patch.object(devtools, "validate_ffmpeg", return_value=FULL_AVAILABLE) as mock_v:
            with pytest.raises(HTTPException) as ei:
                devtools.get_devtools_ffmpeg_health()
        assert ei.value.status_code == 404
        # Guard runs before validate_ffmpeg is ever called.
        mock_v.assert_not_called()
    finally:
        object.__setattr__(S, "dev_mode", prev)

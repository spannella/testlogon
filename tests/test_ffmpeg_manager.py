"""Unit tests for app.services.ffmpeg_manager (MEDIA-002)."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_version_output(version: str = "6.1.1") -> str:
    return f"ffmpeg version {version} Copyright (c) 2000-2024 the FFmpeg developers\nbuilt with gcc 12"


def _make_codecs_output(encoders: list[str] | None = None) -> str:
    if encoders is None:
        encoders = ["libx264", "libx265", "aac", "libopus", "libvpx"]
    lines = ["Codecs:", " -------"]
    for enc in encoders:
        lines.append(f" DEV.LS {enc}       Some description (encoders: {enc})")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestParseVersion:
    def test_standard_version(self):
        from app.services.ffmpeg_manager import _parse_version

        assert _parse_version("ffmpeg version 6.1.1 Copyright (c) 2000-2024") == "6.1.1"

    def test_version_with_suffix(self):
        from app.services.ffmpeg_manager import _parse_version

        assert _parse_version("ffmpeg version 5.1.4-0+deb12u1 Copyright") == "5.1.4-0+deb12u1"

    def test_n_prefixed_version(self):
        from app.services.ffmpeg_manager import _parse_version

        assert _parse_version("ffmpeg version n6.0-full something") == "n6.0-full"

    def test_empty_string(self):
        from app.services.ffmpeg_manager import _parse_version

        assert _parse_version("") == ""


class TestParseVersionTuple:
    def test_standard(self):
        from app.services.ffmpeg_manager import _parse_version_tuple

        assert _parse_version_tuple("6.1.1") == (6, 1)

    def test_n_prefix(self):
        from app.services.ffmpeg_manager import _parse_version_tuple

        assert _parse_version_tuple("n6.0-full") == (6, 0)

    def test_invalid(self):
        from app.services.ffmpeg_manager import _parse_version_tuple

        assert _parse_version_tuple("unknown") == (0, 0)

    def test_below_minimum(self):
        from app.services.ffmpeg_manager import _parse_version_tuple

        assert _parse_version_tuple("4.4.2") == (4, 4)


class TestParseCodecs:
    def test_finds_known_encoders(self):
        from app.services.ffmpeg_manager import _parse_codecs

        output = _make_codecs_output(["libx264", "aac", "libvpx", "unknown_thing"])
        codecs = _parse_codecs(output)
        assert "libx264" in codecs
        assert "aac" in codecs
        assert "libvpx" in codecs
        assert "unknown_thing" not in codecs

    def test_empty_output(self):
        from app.services.ffmpeg_manager import _parse_codecs

        assert _parse_codecs("") == []


class TestGetFfmpegInfo:
    def test_detects_binary(self):
        from app.services.ffmpeg_manager import get_ffmpeg_info, clear_cache

        clear_cache()
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("6.1.1")

        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["libx264", "aac", "libx265"])

        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result]):
                with patch("app.services.ffmpeg_manager.S") as mock_s:
                    mock_s.ffmpeg_binary_path = "ffmpeg"
                    info = get_ffmpeg_info()

        assert info.available is True
        assert info.path == "/usr/bin/ffmpeg"
        assert info.version == "6.1.1"
        assert "libx264" in info.codecs
        assert "aac" in info.codecs
        clear_cache()

    def test_not_found(self):
        from app.services.ffmpeg_manager import get_ffmpeg_info, clear_cache

        clear_cache()
        with patch("app.services.ffmpeg_manager.shutil.which", return_value=None):
            with patch("app.services.ffmpeg_manager.S") as mock_s:
                mock_s.ffmpeg_binary_path = "ffmpeg"
                info = get_ffmpeg_info()

        assert info.available is False
        assert info.path == ""
        clear_cache()

    def test_custom_binary_path(self):
        from app.services.ffmpeg_manager import get_ffmpeg_info, clear_cache

        clear_cache()
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("7.0")

        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["libx264", "aac"])

        with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result]):
            with patch("app.services.ffmpeg_manager.S") as mock_s:
                mock_s.ffmpeg_binary_path = "/opt/ffmpeg/bin/ffmpeg"
                info = get_ffmpeg_info()

        assert info.available is True
        assert info.path == "/opt/ffmpeg/bin/ffmpeg"
        assert info.version == "7.0"
        clear_cache()

    def test_timeout_handling(self):
        from app.services.ffmpeg_manager import get_ffmpeg_info, clear_cache

        clear_cache()
        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=subprocess.TimeoutExpired("ffmpeg", 5)):
                with patch("app.services.ffmpeg_manager.S") as mock_s:
                    mock_s.ffmpeg_binary_path = "ffmpeg"
                    info = get_ffmpeg_info()

        assert info.available is False
        assert info.path == "/usr/bin/ffmpeg"
        clear_cache()

    def test_cache_works(self):
        from app.services.ffmpeg_manager import get_ffmpeg_info, clear_cache

        clear_cache()
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("6.0")

        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["libx264", "aac"])

        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result]) as mock_run:
                with patch("app.services.ffmpeg_manager.S") as mock_s:
                    mock_s.ffmpeg_binary_path = "ffmpeg"
                    info1 = get_ffmpeg_info()
                    info2 = get_ffmpeg_info()

        # subprocess.run called only twice (version + codecs) for the first call; cache serves the second
        assert mock_run.call_count == 2
        assert info1 is info2
        clear_cache()

    def test_clear_cache(self):
        from app.services.ffmpeg_manager import get_ffmpeg_info, clear_cache

        clear_cache()
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("6.0")

        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["libx264", "aac"])

        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result, version_result, codec_result]) as mock_run:
                with patch("app.services.ffmpeg_manager.S") as mock_s:
                    mock_s.ffmpeg_binary_path = "ffmpeg"
                    get_ffmpeg_info()
                    clear_cache()
                    get_ffmpeg_info()

        # Called 4 times total: 2 for first call, 2 after cache clear
        assert mock_run.call_count == 4
        clear_cache()


class TestGetFfmpegPath:
    def test_raises_when_unavailable(self):
        from app.services.ffmpeg_manager import get_ffmpeg_path, clear_cache, FFmpegNotAvailableError

        clear_cache()
        with patch("app.services.ffmpeg_manager.shutil.which", return_value=None):
            with patch("app.services.ffmpeg_manager.S") as mock_s:
                mock_s.ffmpeg_binary_path = "ffmpeg"
                with pytest.raises(FFmpegNotAvailableError):
                    get_ffmpeg_path()
        clear_cache()

    def test_returns_path_when_available(self):
        from app.services.ffmpeg_manager import get_ffmpeg_path, clear_cache

        clear_cache()
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("6.1")

        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["libx264", "aac"])

        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result]):
                with patch("app.services.ffmpeg_manager.S") as mock_s:
                    mock_s.ffmpeg_binary_path = "ffmpeg"
                    path = get_ffmpeg_path()

        assert path == "/usr/bin/ffmpeg"
        clear_cache()


class TestIsFfmpegAvailable:
    def test_shortcut_true(self):
        from app.services.ffmpeg_manager import is_ffmpeg_available, clear_cache

        clear_cache()
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("6.0")

        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["libx264", "aac"])

        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result]):
                with patch("app.services.ffmpeg_manager.S") as mock_s:
                    mock_s.ffmpeg_binary_path = "ffmpeg"
                    assert is_ffmpeg_available() is True
        clear_cache()

    def test_shortcut_false(self):
        from app.services.ffmpeg_manager import is_ffmpeg_available, clear_cache

        clear_cache()
        with patch("app.services.ffmpeg_manager.shutil.which", return_value=None):
            with patch("app.services.ffmpeg_manager.S") as mock_s:
                mock_s.ffmpeg_binary_path = "ffmpeg"
                assert is_ffmpeg_available() is False
        clear_cache()


class TestValidateFfmpeg:
    def test_healthy(self):
        from app.services.ffmpeg_manager import validate_ffmpeg, clear_cache

        clear_cache()
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("6.1.1")

        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["libx264", "libx265", "aac", "libopus", "libvpx"])

        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result]):
                with patch("app.services.ffmpeg_manager.S") as mock_s:
                    mock_s.ffmpeg_binary_path = "ffmpeg"
                    result = validate_ffmpeg()

        assert result["status"] == "healthy"
        assert result["version"] == "6.1.1"
        assert result["path"] == "/usr/bin/ffmpeg"
        assert result["missing_required"] == []
        assert result["issues"] == []
        clear_cache()

    def test_degraded_missing_recommended(self):
        from app.services.ffmpeg_manager import validate_ffmpeg, clear_cache

        clear_cache()
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("6.1.1")

        # Has required codecs but missing recommended
        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["libx264", "aac"])

        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result]):
                with patch("app.services.ffmpeg_manager.S") as mock_s:
                    mock_s.ffmpeg_binary_path = "ffmpeg"
                    result = validate_ffmpeg()

        # No issues because only recommended are missing (not required)
        assert result["status"] == "healthy"
        assert len(result["missing_recommended"]) > 0
        clear_cache()

    def test_degraded_missing_required(self):
        from app.services.ffmpeg_manager import validate_ffmpeg, clear_cache

        clear_cache()
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("6.1.1")

        # Missing libx264 (required)
        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["aac"])

        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result]):
                with patch("app.services.ffmpeg_manager.S") as mock_s:
                    mock_s.ffmpeg_binary_path = "ffmpeg"
                    result = validate_ffmpeg()

        assert result["status"] == "degraded"
        assert "libx264" in result["missing_required"]
        assert len(result["issues"]) > 0
        clear_cache()

    def test_version_below_minimum(self):
        from app.services.ffmpeg_manager import validate_ffmpeg, clear_cache

        clear_cache()
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("4.4.2")

        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["libx264", "aac", "libx265", "libopus", "libvpx"])

        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result]):
                with patch("app.services.ffmpeg_manager.S") as mock_s:
                    mock_s.ffmpeg_binary_path = "ffmpeg"
                    result = validate_ffmpeg()

        assert result["status"] == "degraded"
        assert any("below minimum" in issue for issue in result["issues"])
        clear_cache()

    def test_unavailable(self):
        from app.services.ffmpeg_manager import validate_ffmpeg, clear_cache

        clear_cache()
        with patch("app.services.ffmpeg_manager.shutil.which", return_value=None):
            with patch("app.services.ffmpeg_manager.S") as mock_s:
                mock_s.ffmpeg_binary_path = "ffmpeg"
                result = validate_ffmpeg()

        assert result["status"] == "unavailable"
        assert "error" in result
        clear_cache()


class TestHealthEndpoint:
    """Integration test for the /internal/ffmpeg-status HTTP endpoint."""

    def test_returns_status(self):
        from fastapi.testclient import TestClient
        from app.services.ffmpeg_manager import clear_cache

        clear_cache()

        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = _make_version_output("6.1.1")

        codec_result = MagicMock()
        codec_result.returncode = 0
        codec_result.stdout = _make_codecs_output(["libx264", "aac", "libx265", "libopus", "libvpx"])

        with patch("app.services.ffmpeg_manager.shutil.which", return_value="/usr/bin/ffmpeg"):
            with patch("app.services.ffmpeg_manager.subprocess.run", side_effect=[version_result, codec_result]):
                from app.main import create_app
                app = create_app()
                client = TestClient(app)
                resp = client.get("/internal/ffmpeg-status")

        assert resp.status_code == 200
        body = resp.json()
        assert "status" in body
        assert "path" in body
        assert "version" in body
        clear_cache()

"""Regression tests for GAP-0040: server-side MIME magic-byte validation on
ad creative asset upload (`app/routers/ads.py`).

Offline, in-memory, no AWS — imports the pure-Python validation helpers only.
"""
import pytest
from fastapi import HTTPException

from app.routers.ads import _validate_asset, _check_magic_bytes


# Real magic-byte prefixes
JPEG_HEADER = b"\xff\xd8\xff\xe0" + b"\x00" * 100  # JFIF JPEG
PNG_HEADER = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
WEBP_HEADER = b"RIFF\x1c\x00\x00\x00WEBP" + b"\x00" * 100
MP4_HEADER = b"\x00\x00\x00\x18ftypisom" + b"\x00" * 100
EXE_HEADER = b"MZ" + b"\x00" * 200  # Windows PE / DOS stub
HTML_BODY = b"<html><body><script>alert(1)</script></body></html>"
PDF_HEADER = b"%PDF-1.4\n" + b"\x00" * 100


# ── _check_magic_bytes unit tests ──────────────────────────────────

def test_jpeg_magic_accepted():
    assert _check_magic_bytes(JPEG_HEADER, "image/jpeg") is True


def test_png_magic_accepted():
    assert _check_magic_bytes(PNG_HEADER, "image/png") is True


def test_webp_magic_accepted():
    assert _check_magic_bytes(WEBP_HEADER, "image/webp") is True


def test_mp4_magic_accepted():
    assert _check_magic_bytes(MP4_HEADER, "video/mp4") is True


def test_exe_rejected_as_jpeg():
    """FAILS BEFORE FIX (no check existed); PASSES AFTER FIX (returns False)."""
    assert _check_magic_bytes(EXE_HEADER, "image/jpeg") is False


def test_html_rejected_as_jpeg():
    assert _check_magic_bytes(HTML_BODY, "image/jpeg") is False


def test_pdf_rejected_as_png():
    assert _check_magic_bytes(PDF_HEADER, "image/png") is False


def test_webp_riff_without_webp_fourcc_rejected():
    """A WAV file starts with RIFF but not WEBP at bytes 8-11."""
    wav_header = b"RIFF\x24\x00\x00\x00WAVE" + b"\x00" * 100
    assert _check_magic_bytes(wav_header, "image/webp") is False


def test_empty_data_rejected():
    assert _check_magic_bytes(b"", "image/jpeg") is False


def test_too_short_rejected():
    assert _check_magic_bytes(b"\xff\xd8", "image/jpeg") is False


# ── _validate_asset integration tests ──────────────────────────────

def test_validate_image_jpeg_valid_data_passes():
    """Valid JPEG bytes with correct content-type — must not raise."""
    _validate_asset(JPEG_HEADER + b"\x00" * 1000, "image/jpeg", "image")


def test_validate_image_exe_disguised_as_jpeg_raises():
    """FAILS BEFORE FIX (no byte inspection); PASSES AFTER FIX (400)."""
    with pytest.raises(HTTPException) as exc_info:
        _validate_asset(EXE_HEADER, "image/jpeg", "image")
    assert exc_info.value.status_code == 400
    assert "does not match" in exc_info.value.detail


def test_validate_video_exe_disguised_as_mp4_raises():
    with pytest.raises(HTTPException) as exc_info:
        _validate_asset(EXE_HEADER, "video/mp4", "video")
    assert exc_info.value.status_code == 400


def test_validate_thumbnail_html_disguised_as_jpeg_raises():
    with pytest.raises(HTTPException) as exc_info:
        _validate_asset(HTML_BODY, "image/jpeg", "thumbnail")
    assert exc_info.value.status_code == 400


def test_validate_image_wrong_header_type_still_rejected():
    """Content-Type mismatch (header says PNG but data is JPEG) still rejected."""
    with pytest.raises(HTTPException) as exc_info:
        _validate_asset(JPEG_HEADER, "image/png", "image")
    assert exc_info.value.status_code == 400
    assert "does not match" in exc_info.value.detail


def test_validate_image_size_limit_still_enforced():
    """Size limit must still be enforced even when magic bytes are valid."""
    large_jpeg = JPEG_HEADER + b"\x00" * (6 * 1024 * 1024)  # 6 MB > 5 MB limit
    with pytest.raises(HTTPException) as exc_info:
        _validate_asset(large_jpeg, "image/jpeg", "image")
    assert exc_info.value.status_code == 400
    assert "5 MB" in exc_info.value.detail

"""GAP-0315 regression: sticker upload must validate MIME from magic bytes.

Before the fix, ``create_collection`` trusted the caller-supplied ``content_type``
header and never inspected the actual bytes, so a JPEG (or anything) declared as
``image/png`` was accepted. After the fix, the sniffed magic-byte type is
authoritative and ``image/svg+xml`` is removed from the allowed set.

Hermetic / offline: the magic-byte detector is pure (bytes in -> mime out), and
the rejection paths in ``create_collection`` raise BEFORE any S3/DDB write. The
accept paths stub the S3 client and the DynamoDB table handle so no real AWS is
touched.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import app.services.sticker_collections as sc
from app.services.sticker_collections import _detect_content_type, create_collection

# Valid magic-byte payloads.
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
WEBP_BYTES = b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 100
# JPEG (SOI + APP0) header — declared as PNG by an attacker.
JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"\x00" * 100
JUNK_BYTES = b"\xde\xad\xbe\xef" * 50
SVG_BYTES = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


# ---------------------------------------------------------------------------
# Pure detector tests (no AWS, no stubbing)
# ---------------------------------------------------------------------------

def test_detect_content_type_png():
    assert _detect_content_type(PNG_BYTES) == "image/png"


def test_detect_content_type_webp():
    assert _detect_content_type(WEBP_BYTES) == "image/webp"


def test_detect_content_type_jpeg_returns_none():
    # JPEG is not an allowed sticker type and has no entry in _detect_content_type.
    assert _detect_content_type(JPEG_BYTES) is None


def test_detect_content_type_junk_returns_none():
    assert _detect_content_type(JUNK_BYTES) is None


def test_detect_content_type_svg_returns_none():
    # SVG has no reliable magic bytes -> never detected, hence never allowed.
    assert _detect_content_type(SVG_BYTES) is None


def test_svg_removed_from_allowed_mime():
    assert "image/svg+xml" not in sc._ALLOWED_MIME
    assert set(sc._ALLOWED_MIME) == {"image/png", "image/webp"}


# ---------------------------------------------------------------------------
# Upload-path tests
# ---------------------------------------------------------------------------

def test_create_collection_rejects_jpeg_declared_as_png():
    """Core fails-before / passes-after: declared image/png but bytes are JPEG.

    Reaches the validation check before any S3/DDB write, so no stubbing needed.
    """
    with pytest.raises(ValueError, match="invalid_file_type"):
        create_collection(
            name="Test",
            description="",
            created_by="admin_sub",
            files=[(JPEG_BYTES, "image/png", "fake png")],
        )


def test_create_collection_rejects_svg():
    with pytest.raises(ValueError, match="invalid_file_type"):
        create_collection(
            name="Test",
            description="",
            created_by="admin_sub",
            files=[(SVG_BYTES, "image/svg+xml", "xss sticker")],
        )


def test_create_collection_rejects_unrecognised_bytes():
    with pytest.raises(ValueError, match="invalid_file_type"):
        create_collection(
            name="Test",
            description="",
            created_by="admin_sub",
            files=[(JUNK_BYTES, "image/png", "garbage")],
        )


def _stub_storage(monkeypatch):
    """Replace the S3 client factory and the DDB table handle with in-memory fakes."""
    fake_s3 = MagicMock()
    monkeypatch.setattr(sc, "s3_client", lambda: fake_s3)

    fake_table = MagicMock()
    # T is frozen; patch the attribute used by the module via object.__setattr__.
    monkeypatch.setattr(sc, "T", SimpleNamespace(sticker_collections=fake_table))
    return fake_s3, fake_table


def test_create_collection_accepts_real_png(monkeypatch):
    fake_s3, fake_table = _stub_storage(monkeypatch)
    result = create_collection(
        name="Test",
        description="",
        created_by="admin_sub",
        files=[(PNG_BYTES, "image/png", "a real png")],
    )
    assert result["sticker_count"] == 1
    # Stored S3 ContentType is the *sniffed* type and key uses the png ext.
    _, kwargs = fake_s3.put_object.call_args
    assert kwargs["ContentType"] == "image/png"
    assert kwargs["Key"].endswith(".png")
    assert fake_table.put_item.called


def test_create_collection_accepts_real_webp_even_if_declared_png(monkeypatch):
    """Sniffed type is authoritative: WebP bytes are accepted as webp regardless
    of a (wrong) declared image/png header, and stored with the correct ext."""
    fake_s3, _ = _stub_storage(monkeypatch)
    result = create_collection(
        name="Test",
        description="",
        created_by="admin_sub",
        files=[(WEBP_BYTES, "image/png", "really a webp")],
    )
    assert result["sticker_count"] == 1
    _, kwargs = fake_s3.put_object.call_args
    assert kwargs["ContentType"] == "image/webp"
    assert kwargs["Key"].endswith(".webp")

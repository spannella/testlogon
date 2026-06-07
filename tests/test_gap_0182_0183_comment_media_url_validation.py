"""Regression tests for GAP-0182 and GAP-0183.

GAP-0182: ``CreateCommentRequest.gif_url`` must only accept ``http(s)`` URLs from
an allowlisted GIF CDN domain (media.giphy.com / media.tenor.com / ...). Before
the fix, any value — including ``data:``, ``javascript:``, ``file:``,
scheme-relative ``//``, and arbitrary third-party domains — passed validation.

GAP-0183: ``CreateCommentRequest.sticker_url`` must only reference
platform-hosted content: a platform-relative path (``/mock/s3/stickers/...``,
``/stickers/...``) or an absolute URL under the configured CDN base. Before the
fix, arbitrary external URLs and dangerous schemes were accepted.

Both fixes live in the ``validate_comment_kind`` model validator in
``app/routers/newsfeed.py``. These tests instantiate the Pydantic model directly,
so they are fully offline (no FastAPI TestClient, no DynamoDB, no AWS).

Settings ``S`` is frozen; the CDN-base test mutates it via ``object.__setattr__``
and restores the original value afterwards.

Fails-before / passes-after for every "rejected" case.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.settings import S
from app.routers.newsfeed import CreateCommentRequest


# --------------------------------------------------------------------------- #
# GAP-0182 — gif_url
# --------------------------------------------------------------------------- #

def _gif(gif_url: str) -> dict:
    return {"kind": "gif", "gif_url": gif_url}


def test_gif_valid_giphy_url_accepted():
    url = "https://media.giphy.com/media/abc123/giphy.gif"
    req = CreateCommentRequest(**_gif(url))
    assert req.gif_url == url


def test_gif_valid_tenor_url_accepted():
    url = "https://media.tenor.com/xyz.gif"
    req = CreateCommentRequest(**_gif(url))
    assert req.gif_url == url


def test_gif_data_uri_rejected():
    with pytest.raises(ValidationError, match="scheme"):
        CreateCommentRequest(**_gif("data:text/html,<script>alert(1)</script>"))


def test_gif_javascript_uri_rejected():
    with pytest.raises(ValidationError, match="scheme"):
        CreateCommentRequest(**_gif("javascript:alert(1)"))


def test_gif_file_uri_rejected():
    with pytest.raises(ValidationError, match="scheme"):
        CreateCommentRequest(**_gif("file:///etc/passwd"))


def test_gif_scheme_relative_rejected():
    # urlparse("//evil.com/x.gif") has empty scheme -> rejected at scheme check
    with pytest.raises(ValidationError, match="scheme"):
        CreateCommentRequest(**_gif("//evil.com/img.gif"))


def test_gif_arbitrary_http_domain_rejected():
    with pytest.raises(ValidationError, match="domain"):
        CreateCommentRequest(**_gif("https://attacker.example.com/evil.gif"))


# --------------------------------------------------------------------------- #
# GAP-0183 — sticker_url
# --------------------------------------------------------------------------- #

def _sticker(sticker_url: str) -> dict:
    return {
        "kind": "sticker",
        "sticker_id": "stk001",
        "sticker_collection_id": "pack1",
        "sticker_url": sticker_url,
        "sticker_alt_text": "test sticker",
    }


def test_sticker_valid_dev_mock_path_accepted():
    url = "/mock/s3/stickers/coll_love_pack/stk_love_heart_01.webp"
    req = CreateCommentRequest(**_sticker(url))
    assert req.sticker_url == url


def test_sticker_valid_stickers_path_accepted():
    url = "/stickers/pack1/stk001.webp"
    req = CreateCommentRequest(**_sticker(url))
    assert req.sticker_url == url


def test_sticker_arbitrary_https_rejected():
    with pytest.raises(ValidationError, match="platform"):
        CreateCommentRequest(**_sticker("https://attacker.example.com/evil.webp"))


def test_sticker_data_uri_rejected():
    with pytest.raises(ValidationError, match="platform"):
        CreateCommentRequest(**_sticker("data:image/webp;base64,AAAA"))


def test_sticker_javascript_uri_rejected():
    with pytest.raises(ValidationError, match="platform"):
        CreateCommentRequest(**_sticker("javascript:alert(1)"))


def test_sticker_arbitrary_relative_path_rejected():
    with pytest.raises(ValidationError, match="platform"):
        CreateCommentRequest(**_sticker("/uploads/attacker/malicious.webp"))


def test_sticker_scheme_relative_rejected():
    with pytest.raises(ValidationError, match="platform"):
        CreateCommentRequest(**_sticker("//evil.com/sticker.webp"))


def test_sticker_cdn_url_accepted_when_configured():
    """Absolute CDN URL accepted only when the CDN base is configured.

    S is frozen, so mutate via object.__setattr__ and restore afterwards.
    """
    cdn = "https://cdn.example.com"
    original = getattr(S, "filemgr_media_preview_cdn_base_url", "")
    object.__setattr__(S, "filemgr_media_preview_cdn_base_url", cdn)
    try:
        url = f"{cdn}/stickers/pack1/stk001.webp"
        req = CreateCommentRequest(**_sticker(url))
        assert req.sticker_url == url
        # A different external host is still rejected even with CDN configured.
        with pytest.raises(ValidationError, match="platform"):
            CreateCommentRequest(**_sticker("https://other.example.com/x.webp"))
    finally:
        object.__setattr__(S, "filemgr_media_preview_cdn_base_url", original)

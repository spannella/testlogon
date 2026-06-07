"""GAP-0316: gif_url domain allowlist / scheme validation in send_gif_message.

Offline / hermetic. Exercises the `_validate_gif_url` helper directly (it is the
single security gate) plus the `send_gif_message` handler with all post-validation
collaborators stubbed (no AWS / DDB / S3 / network).

Fails before the fix (no `_validate_gif_url` / `gif_allowed_domains`), passes after.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

import app.routers.messaging as M
from app.core.settings import S


# ---------------------------------------------------------------------------
# Direct unit tests of the validator
# ---------------------------------------------------------------------------

@pytest.fixture
def allowlist_media_example():
    """Set a deterministic allowlist for the duration of a test."""
    orig = S.gif_allowed_domains
    object.__setattr__(S, "gif_allowed_domains", "media.example.com")
    try:
        yield
    finally:
        object.__setattr__(S, "gif_allowed_domains", orig)


@pytest.mark.parametrize(
    "url",
    [
        "/mock/gifs/placeholder_1.gif",          # relative dev mock URL
        "/mock/gifs/cat.gif",
        "https://media.example.com/abc/cat.gif",  # exact allowlisted host
        "https://cdn.media.example.com/x.gif",    # subdomain of allowlisted host
    ],
)
def test_validate_gif_url_allowed(url, allowlist_media_example):
    # Should not raise.
    M._validate_gif_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/x.gif",             # non-allowlisted domain
        "https://media.example.com.evil.com/x",   # lookalike, not a subdomain
        "javascript:alert(1)",                    # dangerous scheme
        "data:image/gif;base64,R0lGODlhAQAB",     # data URI
        "file:///etc/passwd",                     # file scheme
        "//media.example.com/x.gif",              # scheme-relative -> netloc set but scheme empty
        "relative/no/leading/slash.gif",          # relative but not absolute path
        "",                                        # empty
    ],
)
def test_validate_gif_url_rejected(url, allowlist_media_example):
    with pytest.raises(HTTPException) as ei:
        M._validate_gif_url(url)
    assert ei.value.status_code == 400
    assert ei.value.detail == "gif_url_not_allowed"


def test_http_scheme_allowed_host_passes(allowlist_media_example):
    # The validator permits http/https for absolute URLs; host gate still applies.
    M._validate_gif_url("http://media.example.com/x.gif")


def test_empty_allowlist_rejects_absolute(monkeypatch):
    orig = S.gif_allowed_domains
    object.__setattr__(S, "gif_allowed_domains", "")
    try:
        with pytest.raises(HTTPException) as ei:
            M._validate_gif_url("https://media.example.com/x.gif")
        assert ei.value.status_code == 400
    finally:
        object.__setattr__(S, "gif_allowed_domains", orig)


def test_empty_allowlist_still_allows_relative_mock():
    orig = S.gif_allowed_domains
    object.__setattr__(S, "gif_allowed_domains", "")
    try:
        M._validate_gif_url("/mock/gifs/placeholder_1.gif")  # no raise
    finally:
        object.__setattr__(S, "gif_allowed_domains", orig)


# ---------------------------------------------------------------------------
# Handler-level test: a bad URL must abort before any storage happens
# ---------------------------------------------------------------------------

def test_send_gif_message_rejects_bad_url():
    inp = M.SendGifMessageIn(gif_url="https://evil.example/track.gif")

    orig = S.gif_allowed_domains
    object.__setattr__(S, "gif_allowed_domains", "media.example.com")
    try:
        with patch.object(M, "require_participant_active") as mp_active, \
             patch.object(M, "_get_conversation_or_404", return_value={}) as mp_convo, \
             patch.object(M, "_validate_reply_target") as mp_reply, \
             patch.object(M, "tbl_msgs") as mp_msgs, \
             patch.object(M, "tbl_convos") as mp_convos, \
             patch.object(M, "tbl_parts") as mp_parts:
            with pytest.raises(HTTPException) as ei:
                M.send_gif_message("c_1", inp, req=MagicMock(), user_id="u_1")
            assert ei.value.status_code == 400
            assert ei.value.detail == "gif_url_not_allowed"
            # Nothing must have been persisted.
            mp_msgs.put_item.assert_not_called()
            mp_convos.update_item.assert_not_called()
    finally:
        object.__setattr__(S, "gif_allowed_domains", orig)

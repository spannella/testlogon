from __future__ import annotations

import pytest

from app.services.broadcast_playback import mint_local_playback_url


def test_mint_local_playback_url_generates_signed_query_params() -> None:
    out = mint_local_playback_url("stream-123", ttl_seconds=120)
    assert out.url.startswith("http://localhost:8090/hls/stream-123/master.m3u8?")
    assert "md5=" in out.url
    assert "expires=" in out.url
    assert out.expires_at > 0


def test_mint_local_playback_url_rejects_invalid_stream_key() -> None:
    with pytest.raises(ValueError):
        mint_local_playback_url("../etc/passwd")

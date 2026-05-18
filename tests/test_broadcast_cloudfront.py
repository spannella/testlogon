from __future__ import annotations

from unittest.mock import patch

from app.services import broadcast_cloudfront


def test_mint_and_validate_cloudfront_token() -> None:
    with patch.object(broadcast_cloudfront.time, "time", return_value=1_700_000_000):
        signed = broadcast_cloudfront.mint_cloudfront_signed_playback_url(origin_url="https://pkg.example/path/master.m3u8", ttl_seconds=60)
        ok = broadcast_cloudfront.validate_cloudfront_token(
            path="/path/master.m3u8",
            token=signed.token,
            expires_at=signed.expires_at,
        )
    assert signed.playback_url.startswith("https://")
    assert ok is True


def test_validate_cloudfront_token_rejects_path_traversal() -> None:
    with patch.object(broadcast_cloudfront.time, "time", return_value=1_700_000_000):
        signed = broadcast_cloudfront.mint_cloudfront_signed_playback_url(origin_url="https://pkg.example/path/master.m3u8", ttl_seconds=60)
        ok = broadcast_cloudfront.validate_cloudfront_token(
            path="/path/../../etc/passwd",
            token=signed.token,
            expires_at=signed.expires_at,
        )
    assert ok is False


def test_validate_cloudfront_token_accepts_absolute_url_path_shape() -> None:
    with patch.object(broadcast_cloudfront.time, "time", return_value=1_700_000_000):
        signed = broadcast_cloudfront.mint_cloudfront_signed_playback_url(origin_url="https://pkg.example/path/master.m3u8", ttl_seconds=60)
        ok = broadcast_cloudfront.validate_cloudfront_token(
            path="https://cdn.example/path/master.m3u8?cf_token=ignored",
            token=signed.token,
            expires_at=signed.expires_at,
        )
    assert ok is True


def test_validate_cloudfront_token_rejects_unreasonably_long_ttl() -> None:
    with patch.object(broadcast_cloudfront.time, "time", return_value=1_700_000_000):
        far_future_expires = 1_700_010_000
        token = broadcast_cloudfront._sign("/path/master.m3u8", far_future_expires)
        ok = broadcast_cloudfront.validate_cloudfront_token(
            path="/path/master.m3u8",
            token=token,
            expires_at=far_future_expires,
        )
    assert ok is False


def test_validate_cloudfront_token_rejects_non_numeric_expiry() -> None:
    ok = broadcast_cloudfront.validate_cloudfront_token(
        path="/path/master.m3u8",
        token="abc",
        expires_at="not-an-int",  # type: ignore[arg-type]
    )
    assert ok is False

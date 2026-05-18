from __future__ import annotations

from fastapi import HTTPException

from app.services import rate_limit


def test_profile_lookup_rate_limit_allows_when_bucket_available(monkeypatch) -> None:
    monkeypatch.setattr(rate_limit, "_bucket_limit", lambda *args, **kwargs: True)
    rate_limit.rate_limit_profile_lookup("user_1", "198.51.100.10")
    rate_limit.rate_limit_profile_lookup(None, "198.51.100.10")


def test_profile_lookup_rate_limit_blocks_authenticated_tier(monkeypatch) -> None:
    monkeypatch.setattr(rate_limit, "_bucket_limit", lambda *args, **kwargs: False)
    monkeypatch.setenv("PROFILE_LOOKUP_RATE_LIMIT_WINDOW_SECONDS", "42")

    try:
        rate_limit.rate_limit_profile_lookup("user_1", "198.51.100.10")
        assert False, "expected HTTPException"
    except HTTPException as exc:
        assert exc.status_code == 429
        assert exc.detail == {
            "code": "profile_lookup_rate_limited",
            "tier": "authenticated",
            "retry_after_seconds": 42,
        }
        assert (exc.headers or {}).get("Retry-After") == "42"


def test_profile_lookup_rate_limit_blocks_anonymous_tier(monkeypatch) -> None:
    monkeypatch.setattr(rate_limit, "_bucket_limit", lambda *args, **kwargs: False)
    monkeypatch.setenv("PROFILE_LOOKUP_RATE_LIMIT_WINDOW_SECONDS", "17")

    try:
        rate_limit.rate_limit_profile_lookup(None, "198.51.100.10")
        assert False, "expected HTTPException"
    except HTTPException as exc:
        assert exc.status_code == 429
        assert exc.detail == {
            "code": "profile_lookup_rate_limited",
            "tier": "anonymous",
            "retry_after_seconds": 17,
        }
        assert (exc.headers or {}).get("Retry-After") == "17"

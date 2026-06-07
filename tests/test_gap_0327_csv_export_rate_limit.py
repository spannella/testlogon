"""GAP-0327 (SEC-007): rate-limit guard on GET /ui/export/csv.

Offline / hermetic. The handler is an async coroutine; the project's
TestClient path is broken, so we call ``export_csv`` directly with a fake
``ctx``. ``_bucket_limit`` (DDB-backed) and ``generate_csv_rows`` (which would
paginate DynamoDB) are patched in the ``csv_export`` router namespace so no AWS
access occurs.

Fails-before/passes-after:
  * BEFORE the fix there is no rate-limit call, so a 6th over-limit call still
    returns a CSV StreamingResponse (no 429).
  * AFTER the fix the over-limit call raises ``HTTPException(429)`` and
    ``generate_csv_rows`` is NOT invoked.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from fastapi.responses import StreamingResponse

import app.routers.csv_export as csv_export


def _call(monkeypatch, *, bucket_allows: bool):
    """Invoke export_csv with patched collaborators; return the result.

    Returns a tuple ``(result_or_exc, generate_called)``.
    """
    calls = {"generate": 0}

    def fake_bucket_limit(user_sub, sid, max_n, win):
        # Sanity-check the handler wired the expected key/limits.
        assert sid == "rl#csv_export"
        assert max_n == csv_export._CSV_EXPORT_MAX == 5
        assert win == csv_export._CSV_EXPORT_WINDOW == 60
        return bucket_allows

    def fake_generate(source, user_sub, **kwargs):
        calls["generate"] += 1
        def _gen():
            yield b"col1,col2\r\n"
        return _gen()

    monkeypatch.setattr(csv_export, "_bucket_limit", fake_bucket_limit)
    monkeypatch.setattr(csv_export, "generate_csv_rows", fake_generate)

    ctx = {"user_sub": "user_alice", "role": None, "admin_profile": None}
    coro = csv_export.export_csv(
        source="contacts",
        from_date=None,
        to_date=None,
        questionnaire_id=None,
        ctx=ctx,
    )
    try:
        result = asyncio.run(coro)
        return result, calls["generate"]
    except HTTPException as e:
        return e, calls["generate"]


def test_under_limit_returns_csv(monkeypatch):
    result, generate_called = _call(monkeypatch, bucket_allows=True)
    assert isinstance(result, StreamingResponse)
    assert "text/csv" in result.media_type
    assert generate_called == 1


def test_over_limit_raises_429_and_skips_export(monkeypatch):
    result, generate_called = _call(monkeypatch, bucket_allows=False)
    assert isinstance(result, HTTPException)
    assert result.status_code == 429
    # Export work must NOT run when rate-limited.
    assert generate_called == 0


def test_429_includes_retry_after_header(monkeypatch):
    result, _ = _call(monkeypatch, bucket_allows=False)
    assert isinstance(result, HTTPException)
    assert result.status_code == 429
    headers = result.headers or {}
    retry_after = headers.get("Retry-After") or headers.get("retry-after")
    assert retry_after is not None
    assert int(retry_after) == 60


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))

"""Regression test for GAP-0359: rate limiting on GET /ui/search.

The `global_search` handler fans out via `_search_aggregator` to up to 9
backend search modules with a ThreadPoolExecutor (CPU + DDB read
amplification). Before the fix it had NO rate limiting, so any authenticated
user could hammer it. The fix adds a per-user bucket check at the top of the
handler.

Offline / hermetic: patches the rate-limit function and stubs the aggregator
in the `search` module namespace so no DDB fan-out runs. Run alone:

    .venv/bin/pytest tests/test_gap_0359_search_rate_limit.py
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import search as search_mod


def _fake_session():
    return {"user_sub": "u_gap0359", "role": None, "admin_profile": None}


def test_under_limit_runs_aggregator():
    """When the bucket allows the request, the aggregator IS called."""
    fake_result = {"users": [], "posts": []}
    with patch.object(search_mod, "_bucket_limit", return_value=True) as rl, \
         patch.object(search_mod, "_search_aggregator", return_value=fake_result) as agg:
        out = search_mod.global_search(
            q="hello",
            types="users",
            limit=5,
            session=_fake_session(),
        )

    assert rl.called
    assert agg.called
    assert out["query"] == "hello"
    assert out["users"] == []


def test_over_limit_raises_429_and_skips_aggregator():
    """When the bucket is exhausted, raise 429 and never touch the aggregator."""
    with patch.object(search_mod, "_bucket_limit", return_value=False) as rl, \
         patch.object(search_mod, "_search_aggregator") as agg:
        with pytest.raises(HTTPException) as ei:
            search_mod.global_search(
                q="hello",
                types="users",
                limit=5,
                session=_fake_session(),
            )

    assert rl.called
    assert not agg.called  # fan-out must NOT run when rate limited
    exc = ei.value
    assert exc.status_code == 429
    assert exc.detail["code"] == "global_search_rate_limited"
    assert exc.headers["Retry-After"] == str(search_mod._GLOBAL_SEARCH_WINDOW_SECONDS)


def test_rate_limit_keyed_on_user_and_action():
    """The bucket is keyed on the user_sub + a 'global_search' action sid."""
    with patch.object(search_mod, "_bucket_limit", return_value=True) as rl, \
         patch.object(search_mod, "_search_aggregator", return_value={}):
        search_mod.global_search(
            q="hi", types="users", limit=5, session=_fake_session()
        )

    args, _kwargs = rl.call_args
    assert args[0] == "u_gap0359"          # keyed on user
    assert "global_search" in args[1]      # action sid
    assert args[2] == search_mod._GLOBAL_SEARCH_MAX_PER_WINDOW
    assert args[3] == search_mod._GLOBAL_SEARCH_WINDOW_SECONDS

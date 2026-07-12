"""Regression tests for GAP-0184 and GAP-0185 (FILES-001 public share links).

GAP-0184 — no IP-based rate limiting on the public download endpoint.
  Fails-before: the public POST/GET ``/public/files/share/{link_id}/download``
  endpoints had no ``Request`` dependency and never invoked any rate limiter, so
  ``rate_limit_share_link_download`` did not exist and a single IP could brute-
  force passwords / enumerate links without throttling.
  Passes-after: both endpoints derive the client IP and call
  ``rate_limit_share_link_download``, which raises HTTP 429 once the per-IP
  download cap (default 10/min) or the per-(link, IP) attempt cap (default
  5/min) is exceeded.

GAP-0185 — TOCTOU / eventual-consistency window in ``_get_link``.
  Fails-before: ``_get_link`` issued an eventually-consistent ``get_item`` (no
  ``ConsistentRead``), so the pre-flight revoked/expired/used checks in
  ``consume_share_link`` could read a stale snapshot.
  Passes-after: ``_get_link`` passes ``ConsistentRead=True``.

Fully offline: no real AWS / DynamoDB. ``_bucket_limit`` is monkeypatched and
the DynamoDB table is replaced with an in-memory fake. Settings ``S`` is frozen,
so any override uses ``object.__setattr__``.
"""
from __future__ import annotations

import inspect

import pytest
from fastapi import HTTPException

from app.core.settings import S
from app.services import file_share_links as svc
from app.services import rate_limit as rl


# ---------------------------------------------------------------------------
# GAP-0184: rate-limit function behaviour
# ---------------------------------------------------------------------------


def _gate_bucket_limit(monkeypatch, results):
    """Make ``_bucket_limit`` return successive values from ``results``."""
    seq = iter(results)
    calls: list[tuple] = []

    def fake(user_sub, sid, max_n, win):
        calls.append((user_sub, sid, max_n, win))
        try:
            return next(seq)
        except StopIteration:
            return True

    monkeypatch.setattr(rl, "_bucket_limit", fake)
    return calls


def test_rate_limit_function_exists():
    """The rate-limit helper must exist (it did not before the fix)."""
    assert hasattr(rl, "rate_limit_share_link_download")
    assert callable(rl.rate_limit_share_link_download)


def test_rate_limit_allows_within_caps(monkeypatch):
    """Both buckets passing -> no exception."""
    calls = _gate_bucket_limit(monkeypatch, [True, True])
    rl.rate_limit_share_link_download("link-abc", "1.2.3.4")
    # Two independent buckets are consulted: global IP + per-(link, IP).
    assert len(calls) == 2
    assert calls[0][0] == "ip#1.2.3.4"
    assert calls[0][1] == "rl#share_download"
    assert calls[1][1].startswith("rl#share_pwd#")


def test_rate_limit_global_ip_cap_returns_429(monkeypatch):
    """First (global IP) bucket exhausted -> 429 download_rate_limited."""
    _gate_bucket_limit(monkeypatch, [False])
    with pytest.raises(HTTPException) as exc:
        rl.rate_limit_share_link_download("link-abc", "1.2.3.4")
    assert exc.value.status_code == 429
    assert exc.value.detail["code"] == "download_rate_limited"


def test_rate_limit_per_link_attempt_cap_returns_429(monkeypatch):
    """Global passes but per-(link, IP) bucket exhausted -> 429."""
    _gate_bucket_limit(monkeypatch, [True, False])
    with pytest.raises(HTTPException) as exc:
        rl.rate_limit_share_link_download("link-abc", "1.2.3.4")
    assert exc.value.status_code == 429
    assert exc.value.detail["code"] == "password_attempt_rate_limited"


def test_rate_limit_per_link_key_is_link_specific(monkeypatch):
    """Different link IDs must produce different per-link bucket sort keys."""
    calls = _gate_bucket_limit(monkeypatch, [True, True, True, True])
    rl.rate_limit_share_link_download("link-A", "1.2.3.4")
    rl.rate_limit_share_link_download("link-B", "1.2.3.4")
    pwd_keys = [c[1] for c in calls if c[1].startswith("rl#share_pwd#")]
    assert len(pwd_keys) == 2
    assert pwd_keys[0] != pwd_keys[1]


# ---------------------------------------------------------------------------
# GAP-0184: endpoints actually invoke the rate limiter
# ---------------------------------------------------------------------------


class _FakeClient:
    def __init__(self, host):
        self.host = host

class _FakeRequest:
    def __init__(self, ip="9.9.9.9"):
        self.headers = {}  # XFF only honoured from trusted proxies; use direct client
        self.client = _FakeClient(ip)


def _import_router():
    from app.routers import file_share_links as router

    return router


def test_post_endpoint_has_request_dependency():
    """Fails-before: POST endpoint had no ``req`` parameter."""
    router = _import_router()
    sig = inspect.signature(router.download_share_link_endpoint)
    assert "req" in sig.parameters


def test_get_endpoint_has_request_dependency():
    """Fails-before: GET endpoint had no ``req`` parameter."""
    router = _import_router()
    sig = inspect.signature(router.download_share_link_get_endpoint)
    assert "req" in sig.parameters


def test_post_endpoint_calls_rate_limiter_before_consume(monkeypatch):
    """The POST endpoint must enforce the limit and short-circuit on 429."""
    router = _import_router()

    rl_calls: list[tuple] = []

    def fake_rl(link_id, ip):
        rl_calls.append((link_id, ip))
        raise HTTPException(status_code=429, detail={"code": "download_rate_limited"})

    consumed = []
    monkeypatch.setattr(router, "rate_limit_share_link_download", fake_rl)
    monkeypatch.setattr(
        router.svc, "consume_share_link", lambda **kw: consumed.append(kw)
    )

    with pytest.raises(HTTPException) as exc:
        router.download_share_link_endpoint(link_id="L1", req=_FakeRequest("8.8.8.8"))

    assert exc.value.status_code == 429
    assert rl_calls == [("L1", "8.8.8.8")]
    # consume must NOT run when rate limited.
    assert consumed == []


def test_get_endpoint_calls_rate_limiter_before_consume(monkeypatch):
    router = _import_router()

    rl_calls: list[tuple] = []
    monkeypatch.setattr(
        router,
        "rate_limit_share_link_download",
        lambda link_id, ip: rl_calls.append((link_id, ip)),
    )
    monkeypatch.setattr(
        router.svc,
        "consume_share_link",
        lambda **kw: {"content": b"x", "file_name": "f", "content_type": "text/plain"},
    )

    resp = router.download_share_link_get_endpoint(link_id="L2", req=_FakeRequest("7.7.7.7"))
    assert resp.status_code == 200
    assert rl_calls == [("L2", "7.7.7.7")]


# ---------------------------------------------------------------------------
# GAP-0185: _get_link uses a strongly consistent read
# ---------------------------------------------------------------------------


class _FakeTable:
    def __init__(self, item):
        self._item = item
        self.get_item_kwargs = None

    def get_item(self, **kwargs):
        self.get_item_kwargs = kwargs
        return {"Item": dict(self._item)} if self._item is not None else {}


def test_get_link_uses_consistent_read(monkeypatch):
    """Fails-before: get_item was called without ConsistentRead=True."""
    table = _FakeTable({"link_id": "L", "sk": "META", "file_name": "f.txt"})
    monkeypatch.setattr(svc, "_table", lambda: table)

    svc._get_link("L")

    assert table.get_item_kwargs is not None
    assert table.get_item_kwargs.get("ConsistentRead") is True
    assert table.get_item_kwargs.get("Key") == {"link_id": "L", "sk": "META"}


def test_get_link_missing_raises_404(monkeypatch):
    table = _FakeTable(None)
    monkeypatch.setattr(svc, "_table", lambda: table)
    with pytest.raises(HTTPException) as exc:
        svc._get_link("nope")
    assert exc.value.status_code == 404


def test_condition_expression_keeps_revoked_and_expires(monkeypatch):
    """Regression guard: the atomic ConditionExpression must still include
    is_revoked and expires_at (GAP-0185 write-up confirms these are required
    and must not be reverted)."""
    source = inspect.getsource(svc.consume_share_link)
    ce_start = source.find("ConditionExpression")
    assert ce_start != -1
    ce_block = source[ce_start : ce_start + 300]
    assert "is_revoked" in ce_block
    assert "expires_at" in ce_block

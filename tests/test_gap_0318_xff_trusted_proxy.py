"""GAP-0318: IP spoofing via untrusted X-Forwarded-For header.

`client_ip_from_request` must only honour the X-Forwarded-For header when the
direct TCP peer (`request.client.host`) is within `S.trusted_proxy_cidrs`.
When no proxies are configured (dev default) the direct peer IP is always
returned, preventing XFF injection / IP spoofing.

These tests are offline / pure-function (no AWS, no moto). `S` is frozen, so we
flip `trusted_proxy_cidrs` via `object.__setattr__` with cleanup.
"""

from __future__ import annotations

import contextlib

from starlette.requests import Request

from app.auth.root_network import _resolve_client_ip
from app.core.normalize import _trusted_proxy_list, client_ip_from_request
from app.core.settings import S


def _make_request(peer_host: str, xff: str | None = None) -> Request:
    headers = []
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "client": (peer_host, 12345),
        "server": ("testserver", 80),
        "scheme": "http",
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


@contextlib.contextmanager
def _trusted_cidrs(value: str):
    old = S.trusted_proxy_cidrs
    object.__setattr__(S, "trusted_proxy_cidrs", value)
    try:
        yield
    finally:
        object.__setattr__(S, "trusted_proxy_cidrs", old)


def test_xff_ignored_when_no_trusted_proxy_configured():
    """Default ("") -> XFF is spoofable; must return the direct TCP peer.

    Fails BEFORE the fix (old code returns the spoofed 1.2.3.4).
    """
    with _trusted_cidrs(""):
        req = _make_request("203.0.113.5", xff="1.2.3.4")
        assert client_ip_from_request(req) == "203.0.113.5"


def test_xff_honoured_when_peer_is_trusted_proxy():
    """Peer in TRUSTED_PROXY_CIDRS -> leftmost XFF entry is the real client."""
    with _trusted_cidrs("10.0.0.0/8"):
        req = _make_request("10.0.0.7", xff="1.2.3.4")
        assert client_ip_from_request(req) == "1.2.3.4"


def test_xff_honoured_takes_leftmost_entry():
    """RFC-7239 convention: leftmost is the real client (matches root_network)."""
    with _trusted_cidrs("10.0.0.0/8"):
        req = _make_request("10.0.0.7", xff="203.0.113.42, 10.0.0.7")
        assert client_ip_from_request(req) == "203.0.113.42"


def test_xff_ignored_when_peer_not_in_trusted_cidrs():
    """Peer outside TRUSTED_PROXY_CIDRS -> XFF discarded, direct peer used."""
    with _trusted_cidrs("10.0.0.0/8"):
        req = _make_request("203.0.113.99", xff="1.2.3.4")
        assert client_ip_from_request(req) == "203.0.113.99"


def test_trusted_peer_without_xff_returns_peer():
    with _trusted_cidrs("10.0.0.0/8"):
        req = _make_request("10.0.0.7")
        assert client_ip_from_request(req) == "10.0.0.7"


def test_no_xff_always_returns_direct():
    with _trusted_cidrs("10.0.0.0/8"):
        req = _make_request("192.168.1.10")
        assert client_ip_from_request(req) == "192.168.1.10"


def test_none_request_returns_sentinel():
    assert client_ip_from_request(None) == "0.0.0.0"


def test_missing_client_returns_sentinel():
    """Defensive: no req.client -> safe default, no crash."""
    req = _make_request("10.0.0.7", xff="1.2.3.4")
    # Force the scope to drop the client tuple (Request.client -> None).
    req.scope["client"] = None
    with _trusted_cidrs("10.0.0.0/8"):
        assert client_ip_from_request(req) == "0.0.0.0"


def test_trusted_proxy_list_parses_comma_and_space():
    with _trusted_cidrs("10.0.0.0/8, 192.168.0.0/16  172.16.0.0/12"):
        assert _trusted_proxy_list() == ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]


def test_trusted_proxy_list_empty_default():
    with _trusted_cidrs(""):
        assert _trusted_proxy_list() == []


def test_consistency_with_root_network_resolver():
    """For the same inputs, client_ip_from_request agrees with root_network."""
    # Untrusted peer: both return the direct peer, ignoring the spoofed XFF.
    with _trusted_cidrs(""):
        req = _make_request("203.0.113.5", xff="1.2.3.4")
        resolved, kind = _resolve_client_ip(req)
        assert str(resolved) == client_ip_from_request(req) == "203.0.113.5"
        assert kind == "direct_untrusted_proxy"

    # Trusted peer: both honour the leftmost XFF entry.
    with _trusted_cidrs("10.0.0.0/8"):
        req = _make_request("10.0.0.7", xff="203.0.113.42, 10.0.0.7")
        resolved, kind = _resolve_client_ip(req)
        assert str(resolved) == client_ip_from_request(req) == "203.0.113.42"
        assert kind == "trusted_proxy"

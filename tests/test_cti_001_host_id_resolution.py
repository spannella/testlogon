"""CTI-001 — server-side host_id → connection-param resolution.

When the Browser SSH terminal connect payload carries a registered ``host_id``,
the server resolves the authoritative hostname/port/username from the owner's
host inventory before validation: ``host`` is overridden (anti-spoofing) and
``port``/``username`` are filled when the client omitted them.

Hermetic: no AWS. ``get_host`` (imported into the router module) is monkeypatched.
"""
from __future__ import annotations

import app.routers.browser_ssh_terminal as m


_HOST = {
    "host_id": "h-123",
    "hostname": "10.0.1.42",
    "port": 2222,
    "username": "ec2-user",
    "protocol": "ssh",
}


def test_host_id_only_fills_all_params(monkeypatch):
    monkeypatch.setattr(m, "get_host", lambda _u, _h: dict(_HOST))
    payload = {"host_id": "h-123", "authType": "password", "password": "x"}
    m._resolve_host_id_into_payload(payload, "alice")
    assert payload["host"] == "10.0.1.42"
    assert payload["port"] == 2222
    assert payload["username"] == "ec2-user"
    # And the resolved payload now passes connect validation.
    valid, normalized, err = m._validate_connect_payload(payload)
    assert valid and err is None
    assert normalized["host"] == "10.0.1.42"


def test_host_is_overridden_but_client_port_username_preserved(monkeypatch):
    monkeypatch.setattr(m, "get_host", lambda _u, _h: dict(_HOST))
    payload = {
        "host_id": "h-123",
        "host": "attacker.example.com",  # must be overridden
        "port": 22,
        "username": "root",
        "authType": "password",
        "password": "x",
    }
    m._resolve_host_id_into_payload(payload, "alice")
    assert payload["host"] == "10.0.1.42"  # anti-spoof: inventory wins
    assert payload["port"] == 22  # client value kept
    assert payload["username"] == "root"  # client value kept


def test_no_host_id_is_noop(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(m, "get_host", lambda _u, _h: called.__setitem__("n", called["n"] + 1) or _HOST)
    payload = {"host": "h", "port": 22, "username": "u", "authType": "password", "password": "x"}
    m._resolve_host_id_into_payload(payload, "alice")
    assert payload["host"] == "h"
    assert called["n"] == 0  # get_host not consulted without a host_id


def test_unknown_host_id_is_noop(monkeypatch):
    monkeypatch.setattr(m, "get_host", lambda _u, _h: None)
    payload = {"host_id": "nope", "host": "given", "port": 22, "username": "u"}
    m._resolve_host_id_into_payload(payload, "alice")
    assert payload["host"] == "given"  # unchanged when host_id doesn't resolve


def test_get_host_error_never_raises(monkeypatch):
    def _boom(_u, _h):
        raise RuntimeError("ddb down")
    monkeypatch.setattr(m, "get_host", _boom)
    payload = {"host_id": "h-123", "host": "given", "port": 22, "username": "u"}
    m._resolve_host_id_into_payload(payload, "alice")  # must not raise
    assert payload["host"] == "given"

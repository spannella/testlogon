"""CTI-002 — inventory-backed VNC targets (user:{host_id}).

`_resolve_target` resolves a "user:{host_id}" target by loading the host
owner-scoped from host inventory and building a TargetConfig restricted to the
owner. Legacy static targets (demo/ops-admin) are unchanged.

Hermetic: no AWS. host_inventory.get_host is monkeypatched.
"""
from __future__ import annotations

import pytest

import app.services.vnc_sessions as vnc
import app.services.host_inventory as hi


def test_user_target_resolves_for_owned_host(monkeypatch):
    monkeypatch.setattr(
        hi, "get_host",
        lambda u, h: {"host_id": h, "hostname": "10.0.2.7", "port": 5901} if u == "alice" else None,
    )
    target = vnc._resolve_target("user:h-9", "alice")
    assert target.ws_url == "ws://10.0.2.7:5901/websockify"
    assert target.allowed_users == ("alice",)
    # Owner passes authorization; the dynamic target is owner-restricted.
    vnc._ensure_authorized(target, "alice", "user")


def test_user_target_default_vnc_port(monkeypatch):
    monkeypatch.setattr(hi, "get_host", lambda u, h: {"host_id": h, "hostname": "host.x", "port": 0})
    target = vnc._resolve_target("user:h-1", "alice")
    assert target.ws_url == "ws://host.x:5900/websockify"


def test_foreign_or_unknown_host_rejected(monkeypatch):
    # get_host is owner-scoped → returns None for a host the caller doesn't own.
    monkeypatch.setattr(hi, "get_host", lambda u, h: None)
    with pytest.raises(vnc.VncSessionError) as ei:
        vnc._resolve_target("user:h-foreign", "bob")
    assert ei.value.http_status == 404
    assert ei.value.code == "VNC_TARGET_NOT_FOUND"


def test_legacy_static_targets_unchanged():
    demo = vnc._resolve_target("demo", "anyone")
    assert demo.target_id == "demo" and demo.allowed_users == ("*",)
    ops = vnc._resolve_target("ops-admin")
    assert ops.target_id == "ops-admin"
    # ops-admin is still admin/root-gated.
    with pytest.raises(vnc.VncSessionError) as ei:
        vnc._ensure_authorized(ops, "alice", "user")
    assert ei.value.code == "VNC_AUTH_UNAUTHORIZED"

"""CTI-005 — RDP browser transport, Phase 1 (Option C fallback) per ADR-004.

Coverage (each ADR/ticket acceptance criterion has at least one assertion):

  * quick_connect for an ``rdp`` host emits ``/remote/rdp?host_id=...`` and NEVER
    the SSH connect form (CTI-005b / AC "never to the SSH connect form").
  * ssh + vnc quick_connect paths are byte-for-byte UNCHANGED by the fix.
  * rdp_sessions fallback resolution is owner-scoped: a foreign/unknown host_id
    fails closed with RDP_TARGET_NOT_FOUND (CTI-010 ownership AC).
  * default RDP port (3389) is applied when the host record has no port.
  * the native session endpoint is flag-gated, fail-safe: flag OFF (default) →
    503 RDP_FEATURE_DISABLED; flag ON (future native build) → 501
    RDP_NATIVE_NOT_IMPLEMENTED (the bridge is not built yet) — CTI-005 AC
    "with the RDP flag off, the UI shows a clear unavailable message and no
    broken connect attempt."
  * the router fallback handler returns the secret-free metadata payload.

Hermetic (per SECOPS-007 / repo rules): NO real AWS / network.
  * Real in-memory moto DynamoDB backs the ``host_inventory`` table, bound to
    BOTH ``host_inventory.T`` and ``rdp_sessions`` (which lazy-imports get_host).
  * The RDP feature flag is a module-level ``os.environ`` read (mirrors VNC), so
    it is toggled via ``monkeypatch.setenv`` / ``delenv``.
  * Async router handlers are invoked directly (TestClient is broken).
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_host_inventory_table(ddb):
    return ddb.create_table(
        TableName="host_inventory",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestRdpTransportCti005(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.host_table = _make_host_inventory_table(ddb)

        from app.services import host_inventory
        from app.services import rdp_sessions

        self.host_inventory = host_inventory
        self.rdp_sessions = rdp_sessions

        fake_T = SimpleNamespace(host_inventory=self.host_table)
        self.stack.enter_context(patch.object(host_inventory, "T", fake_T))

    # -- quick_connect routing (CTI-005b) ---------------------------------

    def test_quick_connect_rdp_routes_to_rdp_surface_not_ssh(self):
        host = self.host_inventory.create_host(
            "alice",
            label="win-box",
            hostname="10.0.9.9",
            port=3389,
            protocol="rdp",
            username="Administrator",
            os_type="windows",
        )
        hid = host["host_id"]
        out = self.host_inventory.quick_connect("alice", hid)
        self.assertEqual(out["protocol"], "rdp")
        self.assertEqual(out["connect_path"], f"/remote/rdp?host_id={hid}")
        self.assertNotIn("/remote/ssh", out["connect_path"])
        self.assertEqual(out["target_id"], f"user:{hid}")

    def test_quick_connect_ssh_unchanged(self):
        host = self.host_inventory.create_host(
            "alice", label="lin", hostname="10.0.1.1", port=22, protocol="ssh", username="ubuntu",
        )
        out = self.host_inventory.quick_connect("alice", host["host_id"])
        self.assertEqual(
            out["connect_path"], "/remote/ssh?host=10.0.1.1&port=22&username=ubuntu"
        )
        self.assertEqual(out["target_id"], "")

    def test_quick_connect_vnc_unchanged(self):
        host = self.host_inventory.create_host(
            "alice", label="vncbox", hostname="10.0.2.2", port=5900, protocol="vnc",
        )
        hid = host["host_id"]
        out = self.host_inventory.quick_connect("alice", hid)
        self.assertEqual(out["connect_path"], f"/remote?target_id=user:{hid}")
        self.assertEqual(out["ws_url"], "ws://10.0.2.2:5900/websockify")

    # -- fallback resolution + ownership (CTI-010) ------------------------

    def test_fallback_details_owner_scoped(self):
        host = self.host_inventory.create_host(
            "alice", label="win", hostname="10.0.9.1", port=3389, protocol="rdp", username="Admin",
        )
        hid = host["host_id"]
        details = self.rdp_sessions.get_fallback_details(user_sub="alice", host_id=hid)
        self.assertFalse(details["available"])
        self.assertEqual(details["address"], "10.0.9.1:3389")
        self.assertEqual(details["username"], "Admin")
        self.assertIn("RDP", details["instructions"])
        self.assertIn("mstsc", details["native_clients"])

    def test_fallback_foreign_host_fails_closed(self):
        host = self.host_inventory.create_host(
            "alice", label="win", hostname="10.0.9.1", protocol="rdp",
        )
        hid = host["host_id"]
        # bob does not own alice's host → owner-scoped lookup returns nothing.
        with pytest.raises(self.rdp_sessions.RdpSessionError) as ei:
            self.rdp_sessions.get_fallback_details(user_sub="bob", host_id=hid)
        self.assertEqual(ei.value.http_status, 404)
        self.assertEqual(ei.value.code, "RDP_TARGET_NOT_FOUND")

    def test_fallback_unknown_host_fails_closed(self):
        with pytest.raises(self.rdp_sessions.RdpSessionError) as ei:
            self.rdp_sessions.get_fallback_details(user_sub="alice", host_id="nope")
        self.assertEqual(ei.value.code, "RDP_TARGET_NOT_FOUND")

    def test_fallback_defaults_rdp_port(self):
        # Force a host record with port 0 to exercise the default-3389 branch.
        self.host_table.put_item(
            Item={
                "user_sub": "alice",
                "sk": self.host_inventory._sk("h-noport"),
                "host_id": "h-noport",
                "hostname": "winhost.local",
                "port": 0,
                "protocol": "rdp",
                "label": "noport",
            }
        )
        details = self.rdp_sessions.get_fallback_details(user_sub="alice", host_id="h-noport")
        self.assertEqual(details["port"], 3389)

    # -- native session endpoint flag gating (CTI-005 AC) -----------------

    def test_native_session_disabled_by_default(self):
        # No env override → flag defaults OFF → 503 RDP_FEATURE_DISABLED.
        with patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("RDP_REMOTE_DESKTOP_ENABLED", None)
            self.assertFalse(self.rdp_sessions.rdp_feature_enabled())
            host = self.host_inventory.create_host(
                "alice", label="w", hostname="10.0.9.5", protocol="rdp",
            )
            with pytest.raises(self.rdp_sessions.RdpSessionError) as ei:
                self.rdp_sessions.create_session(
                    user_sub="alice", target_id=f"user:{host['host_id']}"
                )
            self.assertEqual(ei.value.http_status, 503)
            self.assertEqual(ei.value.code, "RDP_FEATURE_DISABLED")

    def test_native_session_flag_on_not_yet_implemented(self):
        host = self.host_inventory.create_host(
            "alice", label="w", hostname="10.0.9.6", protocol="rdp",
        )
        with patch.dict("os.environ", {"RDP_REMOTE_DESKTOP_ENABLED": "1"}, clear=False):
            self.assertTrue(self.rdp_sessions.rdp_feature_enabled())
            with pytest.raises(self.rdp_sessions.RdpSessionError) as ei:
                self.rdp_sessions.create_session(
                    user_sub="alice", target_id=f"user:{host['host_id']}"
                )
            # Flag on but native bridge not built → 501, NOT a broken connect.
            self.assertEqual(ei.value.http_status, 501)
            self.assertEqual(ei.value.code, "RDP_NATIVE_NOT_IMPLEMENTED")

    def test_native_session_flag_on_foreign_host_still_denied(self):
        host = self.host_inventory.create_host(
            "alice", label="w", hostname="10.0.9.7", protocol="rdp",
        )
        with patch.dict("os.environ", {"RDP_REMOTE_DESKTOP_ENABLED": "1"}, clear=False):
            # Even with the flag on, a non-owner is rejected before any session.
            with pytest.raises(self.rdp_sessions.RdpSessionError) as ei:
                self.rdp_sessions.create_session(
                    user_sub="bob", target_id=f"user:{host['host_id']}"
                )
            self.assertEqual(ei.value.code, "RDP_TARGET_NOT_FOUND")

    # -- router fallback handler ------------------------------------------

    def test_router_fallback_handler_returns_payload(self):
        from app.auth.roles import Role
        import app.routers.rdp_sessions as router_mod

        host = self.host_inventory.create_host(
            "alice", label="winrtr", hostname="10.0.9.8", port=3389, protocol="rdp", username="Admin",
        )
        hid = host["host_id"]
        user = SimpleNamespace(sub="alice", role=Role.USER)
        req = SimpleNamespace(headers={}, client=None)

        with patch.object(router_mod, "audit_event", lambda *a, **k: None):
            resp = router_mod.rdp_fallback(req=req, host_id=hid, _ctx={}, user=user)
        self.assertEqual(resp.hostname, "10.0.9.8")
        self.assertEqual(resp.address, "10.0.9.8:3389")
        self.assertFalse(resp.available)

    def test_router_session_handler_503_when_disabled(self):
        from fastapi import HTTPException
        from app.auth.roles import Role
        import app.routers.rdp_sessions as router_mod

        host = self.host_inventory.create_host(
            "alice", label="w", hostname="10.0.9.10", protocol="rdp",
        )
        body = router_mod.CreateRdpSessionReq(target_id=f"user:{host['host_id']}")
        user = SimpleNamespace(sub="alice", role=Role.USER)
        req = SimpleNamespace(headers={}, client=None)

        import os
        os.environ.pop("RDP_REMOTE_DESKTOP_ENABLED", None)
        with patch.object(router_mod, "audit_event", lambda *a, **k: None):
            with pytest.raises(HTTPException) as ei:
                router_mod.bootstrap_rdp_session(body=body, req=req, _ctx={}, user=user)
        self.assertEqual(ei.value.status_code, 503)
        self.assertEqual(ei.value.detail["error"]["code"], "RDP_FEATURE_DISABLED")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

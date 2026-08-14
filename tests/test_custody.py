"""CUSTODY — crypto-custody proxy tests (mock path over TestClient)."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role
from app.main import create_app
from app.services.sessions import require_ui_session
import app.services.custody_gateway as cg


@pytest.fixture(autouse=True)
def _fresh_mock():
    # Reset the process-wide mock singleton so each test starts clean.
    cg._MOCK_SINGLETON = None
    cg._REAL_SINGLETON = None
    yield
    cg._MOCK_SINGLETON = None
    cg._REAL_SINGLETON = None


def _client(user_sub: str = "user-1", role: Role = Role.USER) -> TestClient:
    app = create_app()

    async def _auth_override():
        return AuthenticatedUser(sub=user_sub, role=role)

    async def _session_override():
        return {"user_sub": user_sub, "session_id": "sess_1", "role": role.value}

    app.dependency_overrides[get_authenticated_user] = _auth_override
    app.dependency_overrides[require_ui_session] = _session_override
    return TestClient(app)


def test_assets_returns_balances():
    c = _client("user-assets")
    r = c.get("/ui/custody/assets")
    assert r.status_code == 200
    assets = r.json()
    by_asset = {a["asset"]: a for a in assets}
    # Seeded demo balances are non-zero.
    assert by_asset["ETH"]["balance"] > 0
    assert by_asset["USDC"]["balance"] > 0
    assert by_asset["BTC"]["balance"] > 0
    assert by_asset["ETH"]["address_available"] is True


def test_deposit_address_returns_address():
    c = _client("user-addr")
    r = c.get("/ui/custody/deposit-address", params={"asset": "ETH", "chain": "ethereum"})
    assert r.status_code == 200
    body = r.json()
    assert body["asset"] == "ETH"
    assert body["network"] == "Mainnet"
    assert body["address"].startswith("0x") and len(body["address"]) == 42
    # Deterministic per user.
    r2 = c.get("/ui/custody/deposit-address", params={"asset": "ETH", "chain": "ethereum"})
    assert r2.json()["address"] == body["address"]


def test_withdrawal_below_threshold_is_signed():
    c = _client("user-small")
    r = c.post("/ui/custody/withdrawals", json={
        "asset": "USDC", "chain": "ethereum", "amount": 10.0,
        "destination": "0x" + "a" * 40,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "signed"
    assert body["signature"].startswith("0x")
    assert body["digest"].startswith("0x")


def test_withdrawal_invalid_destination_rejected():
    c = _client("user-bad")
    r = c.post("/ui/custody/withdrawals", json={
        "asset": "ETH", "chain": "ethereum", "amount": 0.1,
        "destination": "not-an-address",
    })
    assert r.status_code == 400


def test_withdrawal_insufficient_balance_rejected():
    c = _client("user-poor")
    r = c.post("/ui/custody/withdrawals", json={
        "asset": "ETH", "chain": "ethereum", "amount": 9999.0,
        "destination": "0x" + "b" * 40,
    })
    assert r.status_code == 400


def test_full_pending_approval_flow():
    # Give the user a big balance, then withdraw >= threshold (default 1000).
    gw = cg.get_custody_gateway()
    vault_id = f"{cg.S.custody_tenant}-u-user-big"
    gw.seed_user_vault(vault_id, "user-big")
    gw.credit_vault(vault_id, "USDC", 50000.0)

    user = _client("user-big")
    r = user.post("/ui/custody/withdrawals", json={
        "asset": "USDC", "chain": "ethereum", "amount": 25000.0,
        "destination": "0x" + "c" * 40,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "pending_approval"
    assert body["approvals_required"] == 2
    wid = body["id"]

    # User can read their own withdrawal.
    assert user.get(f"/ui/custody/withdrawals/{wid}").json()["status"] == "pending_approval"
    # It appears in the user's list.
    assert any(w["id"] == wid for w in user.get("/ui/custody/withdrawals").json())

    # A plain user cannot see the approvals queue.
    assert user.get("/ui/custody/approvals").status_code in (401, 403)

    # Officer (admin) sees it in the queue and approves M times.
    officer = _client("officer-1", role=Role.ADMIN)
    queue = officer.get("/ui/custody/approvals").json()
    assert any(w["id"] == wid for w in queue)

    a1 = officer.post(f"/ui/custody/withdrawals/{wid}/approve", json={"approver": "officer-a"})
    assert a1.status_code == 200
    assert a1.json()["status"] == "pending_approval"  # still needs 2nd

    a2 = officer.post(f"/ui/custody/withdrawals/{wid}/approve", json={"approver": "officer-b"})
    assert a2.status_code == 200
    assert a2.json()["status"] == "approved"

    # Release triggers the MPC sign.
    rel = officer.post(f"/ui/custody/withdrawals/{wid}/release")
    assert rel.status_code == 200, rel.text
    assert rel.json()["status"] == "signed"
    assert rel.json()["signature"].startswith("0x")

    # After settle window, status advances to settled.
    time.sleep(4.1)
    assert user.get(f"/ui/custody/withdrawals/{wid}").json()["status"] == "settled"


def test_audit_lists_entries_and_verifies():
    c = _client("user-audit")
    # generate activity
    c.get("/ui/custody/assets")
    c.post("/ui/custody/withdrawals", json={
        "asset": "USDC", "chain": "ethereum", "amount": 5.0,
        "destination": "0x" + "d" * 40,
    })
    officer = _client("officer-2", role=Role.ADMIN)
    audit = officer.get("/ui/custody/audit").json()
    assert len(audit["entries"]) > 0
    verify = officer.get("/ui/custody/audit/verify").json()
    assert verify["ok"] is True
    assert verify["entries"] == len(audit["entries"])

    # A plain user cannot read the audit log.
    assert c.get("/ui/custody/audit").status_code in (401, 403)


def test_sanctioned_recipient_blocked():
    c = _client("user-sanc")
    r = c.post("/ui/custody/withdrawals", json={
        "asset": "ETH", "chain": "ethereum", "amount": 0.1,
        "destination": "0x0000000000000000000000000000000000000bad",
    })
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "blocked"
    assert r.json()["error"] == "sanctioned_recipient"

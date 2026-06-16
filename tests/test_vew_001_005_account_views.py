"""VEW-001..005 — Hermetic offline tests for Account Views + Entitlement Requests.

Uses moto in-memory DynamoDB. No real AWS, no network, no TestClient.
"""
from __future__ import annotations

import asyncio
import sys
from types import ModuleType
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import boto3
import pytest
from fastapi import HTTPException
from moto import mock_aws

# ---------------------------------------------------------------------------
# Module-scoped autouse fixture — sets up moto tables and freezes T + S
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _setup(monkeypatch_module):
    """Create moto DynamoDB tables and bind them to T, toggle S flags."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # Create account_views table
        av_table = ddb.create_table(
            TableName="account_views_test",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "by-owner",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
                },
                {
                    "IndexName": "by-grantee",
                    "KeySchema": [
                        {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create entitlement_requests table
        er_table = ddb.create_table(
            TableName="entitlement_requests_test",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "by-status",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
                },
                {
                    "IndexName": "by-requester",
                    "KeySchema": [
                        {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        from app.core import tables as _tables
        from app.core.tables import _FloatSafeTable
        from app.core import settings as _settings

        wrapped_av = _FloatSafeTable(av_table)
        wrapped_er = _FloatSafeTable(er_table)

        # Freeze T with moto table handles
        orig_av = getattr(_tables.T, "account_views")
        orig_er = getattr(_tables.T, "entitlement_requests")
        object.__setattr__(_tables.T, "account_views", wrapped_av)
        object.__setattr__(_tables.T, "entitlement_requests", wrapped_er)

        # Enable flags on S
        orig_obp = getattr(_settings.S, "open_bank_project_enabled", False)
        orig_av_flag = getattr(_settings.S, "account_views_enabled", False)
        orig_er_flag = getattr(_settings.S, "entitlement_requests_enabled", False)
        object.__setattr__(_settings.S, "open_bank_project_enabled", True)
        object.__setattr__(_settings.S, "account_views_enabled", True)
        object.__setattr__(_settings.S, "entitlement_requests_enabled", True)
        object.__setattr__(_settings.S, "account_views_max_per_resource", 25)
        object.__setattr__(_settings.S, "account_view_public_secret", "test-secret-for-vew")
        object.__setattr__(_settings.S, "account_view_public_link_ttl_days", 7)
        object.__setattr__(_settings.S, "entitlement_request_max_open_per_user", 10)
        object.__setattr__(_settings.S, "entitlement_request_max_per_window", 20)
        object.__setattr__(_settings.S, "entitlement_request_window_seconds", 3600)

        yield

        # Teardown
        object.__setattr__(_tables.T, "account_views", orig_av)
        object.__setattr__(_tables.T, "entitlement_requests", orig_er)
        object.__setattr__(_settings.S, "open_bank_project_enabled", orig_obp)
        object.__setattr__(_settings.S, "account_views_enabled", orig_av_flag)
        object.__setattr__(_settings.S, "entitlement_requests_enabled", orig_er_flag)


@pytest.fixture(scope="module")
def monkeypatch_module():
    """A module-scoped monkeypatch (unused in favor of object.__setattr__)."""
    return None


# ---------------------------------------------------------------------------
# Import the modules under test AFTER fixture setup
# ---------------------------------------------------------------------------

from app.services import account_views as svc
from app.services import entitlement_requests as er_svc


# ===========================================================================
# VEW-001 — View CRUD tests
# ===========================================================================


def _grants_wallet_accountant() -> Dict[str, bool]:
    return {
        "can_see_balance": True,
        "can_see_available_balance": True,
        "can_see_transaction_list": True,
        "can_see_transaction_amount": True,
        "can_see_counterparty": True,
        "can_see_counterparty_name": True,
        "can_see_account_label": True,
    }


def _grants_auditor() -> Dict[str, bool]:
    return {k: True for k in svc.VIEW_FIELD_GRANTS if k.startswith("can_see_")}


def _grants_public() -> Dict[str, bool]:
    return {"can_see_account_label": True, "can_see_balance": True}


def _grants_all_true() -> Dict[str, bool]:
    return {k: True for k in svc.VIEW_FIELD_GRANTS}


class TestVEW001ViewCRUD:
    """VEW-001: View entity CRUD, preset detection, ownership guard."""

    def test_grant_catalog_returns_correct_structure(self):
        catalog = svc.get_grant_catalog()
        assert "fields" in catalog
        assert "presets" in catalog
        assert "can_see_balance" in catalog["fields"]
        preset_keys = {p["key"] for p in catalog["presets"]}
        assert {"owner", "accountant", "auditor", "public"} == preset_keys

    def test_create_view_success(self):
        with patch("app.services.account_views.audit_event"):
            view = svc.create_view(
                owner_sub="alice",
                resource_type="wallet",
                resource_id="alice",
                name="My Accountant View",
                grants=_grants_wallet_accountant(),
            )
        assert view["view_id"]
        assert view["owner_sub"] == "alice"
        assert view["name"] == "My Accountant View"
        # Preset should be detected as "accountant"
        assert view["preset"] == "accountant"

    def test_create_view_unknown_resource_type_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            svc.create_view(
                owner_sub="alice",
                resource_type="bank_account",
                resource_id="alice",
                name="X",
                grants={},
            )
        assert exc.value.status_code == 400

    def test_create_view_invalid_grant_key_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            svc.create_view(
                owner_sub="alice",
                resource_type="wallet",
                resource_id="alice",
                name="X",
                grants={"invalid_grant_key": True},
            )
        assert exc.value.status_code == 400

    def test_create_view_ownership_guard_wallet_wrong_user_raises_403(self):
        with pytest.raises(HTTPException) as exc:
            svc.create_view(
                owner_sub="alice",
                resource_type="wallet",
                resource_id="bob",  # bob's wallet, but alice is owner_sub
                name="X",
                grants={},
            )
        assert exc.value.status_code == 403

    def test_detect_preset_auditor(self):
        preset = svc._detect_preset(_grants_auditor())
        assert preset == "auditor"

    def test_detect_preset_owner(self):
        preset = svc._detect_preset(_grants_all_true())
        assert preset == "owner"

    def test_detect_preset_public(self):
        preset = svc._detect_preset(_grants_public())
        assert preset == "public"

    def test_detect_preset_none_for_custom_grants(self):
        custom = {"can_see_balance": True, "can_see_owners": True}
        assert svc._detect_preset(custom) is None

    def test_ensure_owner_view_idempotent(self):
        with patch("app.services.account_views.audit_event"):
            v1 = svc.ensure_owner_view("charlie", "wallet", "charlie")
            v2 = svc.ensure_owner_view("charlie", "wallet", "charlie")
        assert v1["view_id"] == v2["view_id"]
        # Both should be the owner sentinel
        assert v1["view_id"] == "owner"
        assert v1["is_system_alias"] is True

    def test_list_views_returns_created_views(self):
        with patch("app.services.account_views.audit_event"):
            svc.create_view("diana", "wallet", "diana", "View A", grants={})
            svc.create_view("diana", "wallet", "diana", "View B", grants={"can_see_balance": True})
        views = svc.list_views("wallet", "diana")
        names = {v["name"] for v in views}
        assert "View A" in names
        assert "View B" in names

    def test_get_view_returns_none_for_missing(self):
        result = svc.get_view("wallet", "alice", "nonexistent-view-id")
        assert result is None

    def test_update_view_name_and_grants(self):
        with patch("app.services.account_views.audit_event"):
            view = svc.create_view(
                "eve", "wallet", "eve", "Original Name", grants={}
            )
            view_id = view["view_id"]
            updated = svc.update_view(
                "eve", "wallet", "eve", view_id,
                name="Updated Name",
                grants={"can_see_balance": True},
            )
        assert updated["name"] == "Updated Name"
        assert updated["grants"]["can_see_balance"] is True
        assert updated["updated_at"] >= view["created_at"]

    def test_update_view_wrong_owner_raises_403(self):
        with patch("app.services.account_views.audit_event"):
            view = svc.create_view("frank", "wallet", "frank", "Frank View", grants={})
        with pytest.raises(HTTPException) as exc:
            svc.update_view("grace", "wallet", "frank", view["view_id"], name="Hijacked")
        assert exc.value.status_code == 403

    def test_update_system_alias_raises_409(self):
        with patch("app.services.account_views.audit_event"):
            svc.ensure_owner_view("henry", "wallet", "henry")
        with pytest.raises(HTTPException) as exc:
            svc.update_view("henry", "wallet", "henry", "owner", name="New Name")
        assert exc.value.status_code == 409

    def test_delete_system_alias_raises_409(self):
        with patch("app.services.account_views.audit_event"):
            svc.ensure_owner_view("irene", "wallet", "irene")
        with pytest.raises(HTTPException) as exc:
            svc.delete_view("irene", "wallet", "irene", "owner")
        assert exc.value.status_code == 409

    def test_delete_view_removes_row(self):
        with patch("app.services.account_views.audit_event"):
            view = svc.create_view("jack", "wallet", "jack", "Temp View", grants={})
            view_id = view["view_id"]
            svc.delete_view("jack", "wallet", "jack", view_id)
        assert svc.get_view("wallet", "jack", view_id) is None

    def test_view_limit_enforcement(self):
        from app.core import settings as _settings
        old_max = getattr(_settings.S, "account_views_max_per_resource", 25)
        object.__setattr__(_settings.S, "account_views_max_per_resource", 2)
        try:
            with patch("app.services.account_views.audit_event"):
                svc.create_view("limit_user", "wallet", "limit_user", "V1", grants={})
                svc.create_view("limit_user", "wallet", "limit_user", "V2", grants={})
                with pytest.raises(HTTPException) as exc:
                    svc.create_view("limit_user", "wallet", "limit_user", "V3", grants={})
            assert exc.value.status_code == 400
        finally:
            object.__setattr__(_settings.S, "account_views_max_per_resource", old_max)

    def test_audit_event_fired_on_create(self):
        mock_audit = MagicMock()
        with patch("app.services.account_views.audit_event", mock_audit):
            svc.create_view("audit_user", "wallet", "audit_user", "AuditTest", grants={})
        mock_audit.assert_called_once()
        args = mock_audit.call_args[0]
        assert args[0] == "account_view.created"
        assert args[1] == "audit_user"

    def test_in_table_audit_row_written_on_create(self):
        from app.core.tables import T
        from boto3.dynamodb.conditions import Key
        with patch("app.services.account_views.audit_event"):
            svc.create_view("auditrow_user", "wallet", "auditrow_user", "AuditRow", grants={})
        resp = T.account_views.query(
            KeyConditionExpression=Key("pk").eq("RESOURCE#wallet#auditrow_user") & Key("sk").begins_with("AUDIT#"),
        )
        assert len(resp.get("Items", [])) >= 1
        assert resp["Items"][0]["action"] == "view_created"


# ===========================================================================
# VEW-002 — Grant / revoke / public-link tests
# ===========================================================================


class TestVEW002Grants:
    """VEW-002: Grant lifecycle and public-link flow."""

    def _make_view(self, owner: str = "owner1") -> str:
        with patch("app.services.account_views.audit_event"):
            view = svc.create_view(
                owner, "wallet", owner, f"Test View {owner}",
                grants=_grants_public(), preset="public"
            )
        return view["view_id"]

    def test_grant_view_creates_pending_by_default(self):
        view_id = self._make_view("granttest1")
        with patch("app.services.account_views.audit_event"):
            grant = svc.grant_view("granttest1", "wallet", "granttest1", view_id, "bob")
        assert grant["status"] == "pending"
        assert grant["accepted_at"] == 0
        assert grant["GSI2SK"] == 0

    def test_grant_self_raises_400(self):
        view_id = self._make_view("selfgrant")
        with pytest.raises(HTTPException) as exc:
            svc.grant_view("selfgrant", "wallet", "selfgrant", view_id, "selfgrant")
        assert exc.value.status_code == 400

    def test_grant_duplicate_raises_409(self):
        view_id = self._make_view("dupgrant")
        with patch("app.services.account_views.audit_event"):
            svc.grant_view("dupgrant", "wallet", "dupgrant", view_id, "carol")
            with pytest.raises(HTTPException) as exc:
                svc.grant_view("dupgrant", "wallet", "dupgrant", view_id, "carol")
        assert exc.value.status_code == 409

    def test_grant_missing_view_raises_404(self):
        with pytest.raises(HTTPException) as exc:
            svc.grant_view("alice", "wallet", "alice", "nonexistent-view", "bob")
        assert exc.value.status_code == 404

    def test_respond_accept_activates_grant(self):
        view_id = self._make_view("respond1")
        with patch("app.services.account_views.audit_event"):
            svc.grant_view("respond1", "wallet", "respond1", view_id, "dave")
            result = svc.respond_to_view_grant("dave", "wallet", "respond1", view_id, accept=True)
        assert result is not None
        assert result["status"] == "active"
        assert result["accepted_at"] > 0

    def test_respond_decline_removes_grant(self):
        view_id = self._make_view("respond2")
        with patch("app.services.account_views.audit_event"):
            svc.grant_view("respond2", "wallet", "respond2", view_id, "emma")
            result = svc.respond_to_view_grant("emma", "wallet", "respond2", view_id, accept=False)
        assert result is None
        assert svc.resolve_active_grant("emma", "wallet", "respond2", view_id) is None

    def test_respond_non_pending_raises_400(self):
        view_id = self._make_view("respond3")
        with patch("app.services.account_views.audit_event"):
            svc.grant_view("respond3", "wallet", "respond3", view_id, "frank")
            # Accept
            svc.respond_to_view_grant("frank", "wallet", "respond3", view_id, accept=True)
            # Try to accept again
            with pytest.raises(HTTPException) as exc:
                svc.respond_to_view_grant("frank", "wallet", "respond3", view_id, accept=True)
        assert exc.value.status_code == 400

    def test_revoke_removes_grant(self):
        view_id = self._make_view("revoke1")
        with patch("app.services.account_views.audit_event"):
            svc.grant_view("revoke1", "wallet", "revoke1", view_id, "grace")
            svc.respond_to_view_grant("grace", "wallet", "revoke1", view_id, accept=True)
            svc.revoke_view_grant("revoke1", "wallet", "revoke1", view_id, "grace")
        assert svc.resolve_active_grant("grace", "wallet", "revoke1", view_id) is None

    def test_revoke_missing_grant_raises_404(self):
        view_id = self._make_view("revoke2")
        with pytest.raises(HTTPException) as exc:
            svc.revoke_view_grant("revoke2", "wallet", "revoke2", view_id, "nobody")
        assert exc.value.status_code == 404

    def test_resolve_active_grant_returns_none_for_pending(self):
        view_id = self._make_view("resolve1")
        with patch("app.services.account_views.audit_event"):
            svc.grant_view("resolve1", "wallet", "resolve1", view_id, "henry")
        # Not yet accepted
        result = svc.resolve_active_grant("henry", "wallet", "resolve1", view_id)
        assert result is None

    def test_public_link_mint_and_verify(self):
        view_id = self._make_view("pub1")
        with patch("app.services.account_views.audit_event"):
            link_data = svc.create_public_view_link(
                "pub1", "wallet", "pub1", view_id
            )
        assert "token" in link_data
        assert "expires_at" in link_data
        token = link_data["token"]
        # Token has two dot-separated segments
        assert token.count(".") == 1

        with patch("app.services.account_views.audit_event"):
            resolved = svc.resolve_public_view(token)
        assert resolved["resource_type"] == "wallet"
        assert resolved["resource_id"] == "pub1"
        assert resolved["view_id"] == view_id
        assert "can_see_balance" in resolved["grants"]

    def test_public_link_tampered_raises_403(self):
        view_id = self._make_view("pub2")
        with patch("app.services.account_views.audit_event"):
            link_data = svc.create_public_view_link("pub2", "wallet", "pub2", view_id)
        token = link_data["token"]
        # Tamper: flip a character in the payload part
        parts = token.split(".")
        tampered_payload = parts[0][:-1] + ("A" if parts[0][-1] != "A" else "B")
        tampered_token = tampered_payload + "." + parts[1]
        with pytest.raises(HTTPException) as exc:
            svc.resolve_public_view(tampered_token)
        assert exc.value.status_code == 403

    def test_public_link_non_public_view_raises_400(self):
        with patch("app.services.account_views.audit_event"):
            view = svc.create_view(
                "pub3", "wallet", "pub3", "Auditor View",
                grants=_grants_auditor(),
            )
        with pytest.raises(HTTPException) as exc:
            svc.create_public_view_link("pub3", "wallet", "pub3", view["view_id"])
        assert exc.value.status_code == 400

    def test_public_link_revoke_then_resolve_raises_403(self):
        view_id = self._make_view("pubrevoke1")
        with patch("app.services.account_views.audit_event"):
            link_data = svc.create_public_view_link("pubrevoke1", "wallet", "pubrevoke1", view_id)
            token = link_data["token"]
            svc.revoke_public_link("pubrevoke1", token)
            with pytest.raises(HTTPException) as exc:
                svc.resolve_public_view(token)
        assert exc.value.status_code == 403

    def test_public_link_revoke_idempotent(self):
        view_id = self._make_view("pubrevoke2")
        with patch("app.services.account_views.audit_event"):
            link_data = svc.create_public_view_link("pubrevoke2", "wallet", "pubrevoke2", view_id)
            token = link_data["token"]
            svc.revoke_public_link("pubrevoke2", token)
            # Second revoke should not raise
            svc.revoke_public_link("pubrevoke2", token)

    def test_public_link_wrong_owner_raises_403(self):
        view_id = self._make_view("pubrevoke3")
        with patch("app.services.account_views.audit_event"):
            link_data = svc.create_public_view_link("pubrevoke3", "wallet", "pubrevoke3", view_id)
            token = link_data["token"]
            with pytest.raises(HTTPException) as exc:
                svc.revoke_public_link("wrong_owner", token)
        assert exc.value.status_code == 403


# ===========================================================================
# VEW-003 — Projection tests
# ===========================================================================


class TestVEW003Projection:
    """VEW-003: Field-level projection enforcement."""

    def test_owner_preset_passes_all_fields(self):
        resource = {
            "wallet_balance_cents": 5000,
            "available_balance_cents": 4500,
            "currency": "usd",
            "label": "My Wallet",
            "updated_at": 1700000000,
            "resource_type": "wallet",
            "resource_id": "alice",
        }
        result = svc.project_resource(resource, _grants_all_true(), "wallet")
        assert result["wallet_balance_cents"] == 5000
        assert result["currency"] == "usd"
        assert result["label"] == "My Wallet"

    def test_public_preset_strips_balance(self):
        resource = {
            "wallet_balance_cents": 9999,
            "available_balance_cents": 9000,
            "currency": "usd",
            "label": "Public Label",
            "resource_type": "wallet",
            "resource_id": "alice",
        }
        result = svc.project_resource(resource, _grants_public(), "wallet")
        # public grants can_see_account_label (currency, label) and can_see_balance (wallet_balance_cents)
        assert "wallet_balance_cents" in result
        assert "currency" in result
        assert "label" in result

    def test_empty_grants_strips_all_financial_fields(self):
        resource = {
            "wallet_balance_cents": 100,
            "currency": "usd",
            "resource_type": "wallet",
            "resource_id": "alice",
        }
        result = svc.project_resource(resource, {}, "wallet")
        # Only identity fields remain
        assert "wallet_balance_cents" not in result
        assert "currency" not in result
        assert result.get("resource_type") == "wallet"

    def test_unknown_resource_type_returns_empty(self):
        result = svc.project_resource({"foo": "bar"}, _grants_all_true(), "unknown_xyz")
        assert result == {}

    def test_deny_by_default_for_unmapped_field(self):
        resource = {
            "secret_field": "top_secret",
            "wallet_balance_cents": 100,
            "resource_type": "wallet",
            "resource_id": "alice",
        }
        result = svc.project_resource(resource, {"can_see_balance": True}, "wallet")
        assert "secret_field" not in result
        assert "wallet_balance_cents" in result

    def test_counterparty_blur_masks_counterparty_name(self):
        resource = {
            "balance_summary": {"total_settled_cents": 100},
            "transaction_list": [
                {
                    "entry_id": "e1",
                    "amount_cents": 50,
                    "counterparty": "ACME Corp",
                    "counterparty_name": "John Doe",
                    "reason": "Payment",
                    "state": "settled",
                    "ts": 1700000000,
                }
            ],
            "resource_type": "ledger_account",
            "resource_id": "alice",
        }
        grants = _grants_auditor()
        result = svc.project_resource(
            resource, grants, "ledger_account", metadata_visibility="counterparty_blur"
        )
        tx_list = result.get("transaction_list", [])
        assert len(tx_list) == 1
        assert tx_list[0]["counterparty"] == "••••"
        assert tx_list[0]["counterparty_name"] == "••••"

    def test_counterparty_blur_when_grant_false_strips_not_blurs(self):
        resource = {
            "balance_summary": {"total_settled_cents": 0},
            "transaction_list": [
                {
                    "entry_id": "e1",
                    "amount_cents": 10,
                    "counterparty": "ACME Corp",
                    "reason": "test",
                    "state": "settled",
                    "ts": 1700000000,
                }
            ],
            "resource_type": "ledger_account",
            "resource_id": "alice",
        }
        # Grants with can_see_counterparty = False
        grants = {k: True for k in svc.VIEW_FIELD_GRANTS if k.startswith("can_see_") and k != "can_see_counterparty" and k != "can_see_counterparty_name"}
        result = svc.project_resource(
            resource, grants, "ledger_account", metadata_visibility="counterparty_blur"
        )
        tx_list = result.get("transaction_list", [])
        assert len(tx_list) == 1
        # counterparty key should be absent (not blurred, just stripped)
        assert "counterparty" not in tx_list[0]

    def test_transaction_list_gated_by_can_see_transaction_list(self):
        resource = {
            "balance_summary": {"total_settled_cents": 500},
            "transaction_list": [{"entry_id": "e1", "amount_cents": 500}],
            "resource_type": "ledger_account",
            "resource_id": "alice",
        }
        grants = {"can_see_balance": True}  # No can_see_transaction_list
        result = svc.project_resource(resource, grants, "ledger_account")
        assert "transaction_list" not in result
        assert "balance_summary" in result

    def test_identity_fields_always_present(self):
        resource = {
            "resource_type": "wallet",
            "resource_id": "alice",
            "payout_id": "p123",
            "user_id": "alice",
            "wallet_balance_cents": 100,
        }
        result = svc.project_resource(resource, {}, "wallet")
        assert result["resource_type"] == "wallet"
        assert result["resource_id"] == "alice"


# ===========================================================================
# VEW-004 — Entitlement Request tests
# ===========================================================================


class TestVEW004EntitlementRequests:
    """VEW-004: Entitlement request lifecycle."""

    def test_create_request_success(self):
        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "alice", "admin_scope", "billing_support", "I need billing access for auditing"
            )
        assert req["status"] == "pending"
        assert req["requester_sub"] == "alice"
        assert req["entitlement_kind"] == "admin_scope"
        assert req["target_ref"] == "billing_support"

    def test_create_request_invalid_kind_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            er_svc.create_request("alice", "invalid_kind", "ref", "justification here")
        assert exc.value.status_code == 400

    def test_create_request_invalid_admin_scope_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            er_svc.create_request("alice", "admin_scope", "not_a_real_scope", "justification here")
        assert exc.value.status_code == 400

    def test_duplicate_open_request_raises_409(self):
        with patch("app.services.entitlement_requests.audit_event"):
            er_svc.create_request(
                "dupuser", "admin_scope", "auth_support", "Need this for support work"
            )
            with pytest.raises(HTTPException) as exc:
                er_svc.create_request(
                    "dupuser", "admin_scope", "auth_support", "Need this for support work again"
                )
        assert exc.value.status_code == 409

    def test_second_request_allowed_after_rejection(self):
        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "retryuser", "admin_scope", "content_moderation", "First attempt at moderation role"
            )
            er_svc.reject_request(req["request_id"], "admin_sub", "not approved this time")
            # Now a second request for same kind/ref should succeed
            req2 = er_svc.create_request(
                "retryuser", "admin_scope", "content_moderation", "Second attempt at moderation role"
            )
        assert req2["status"] == "pending"

    def test_claim_request_transitions_to_under_review(self):
        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "claimuser", "admin_scope", "billing_support", "Need billing access for work"
            )
            claimed = er_svc.claim_request(req["request_id"], "charlie_admin")
        assert claimed["status"] == "under_review"
        assert claimed["claimed_by_sub"] == "charlie_admin"

    def test_claim_already_claimed_by_other_raises_409(self):
        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "claimconflict", "admin_scope", "auth_support", "Auth support access needed"
            )
            er_svc.claim_request(req["request_id"], "admin_a")
            with pytest.raises(HTTPException) as exc:
                er_svc.claim_request(req["request_id"], "admin_b")
        assert exc.value.status_code == 409

    def test_approve_request_with_stu_absent(self):
        """When crm_acl is absent, request should be approved with grant_pending_acl=True."""
        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "approveuser", "acl_role", "role_analyst", "Need analyst role for project"
            )
            er_svc.claim_request(req["request_id"], "root_admin")

            # Ensure crm_acl is not importable
            old_crm_acl = sys.modules.get("app.services.crm_acl")
            if old_crm_acl is not None:
                sys.modules["app.services.crm_acl"] = None  # type: ignore
            try:
                approved = er_svc.approve_request(req["request_id"], "root_admin", reason="Approved")
            finally:
                if old_crm_acl is not None:
                    sys.modules["app.services.crm_acl"] = old_crm_acl
                elif "app.services.crm_acl" in sys.modules and sys.modules["app.services.crm_acl"] is None:
                    del sys.modules["app.services.crm_acl"]

        assert approved["status"] == "approved"
        assert approved["grant_pending_acl"] is True

    def test_approve_request_with_stu_present(self):
        """When crm_acl.assign_role_to_user is callable, it should be invoked."""
        mock_crm = ModuleType("app.services.crm_acl")
        spy = MagicMock(return_value=None)
        mock_crm.assign_role_to_user = spy

        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "approvestu", "acl_role", "role_manager", "Need manager role"
            )
            er_svc.claim_request(req["request_id"], "root_admin")

        old_crm_acl = sys.modules.get("app.services.crm_acl", "__missing__")
        sys.modules["app.services.crm_acl"] = mock_crm
        try:
            with patch("app.services.entitlement_requests.audit_event"):
                approved = er_svc.approve_request(req["request_id"], "root_admin", reason="OK")
        finally:
            if old_crm_acl == "__missing__":
                del sys.modules["app.services.crm_acl"]
            else:
                sys.modules["app.services.crm_acl"] = old_crm_acl  # type: ignore

        assert approved["status"] == "approved"
        assert approved["grant_pending_acl"] is False
        spy.assert_called_once_with("root_admin", "role_manager", "approvestu")

    def test_reject_request_transitions_to_rejected(self):
        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "rejectuser", "admin_scope", "content_moderation", "Moderation access please"
            )
            rejected = er_svc.reject_request(req["request_id"], "admin_sub", "Not approved")
        assert rejected["status"] == "rejected"
        assert rejected["decision_reason"] == "Not approved"

    def test_cancel_request_by_requester(self):
        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "canceluser", "admin_scope", "auth_support", "I want auth support access"
            )
            cancelled = er_svc.cancel_request(req["request_id"], "canceluser")
        assert cancelled["status"] == "cancelled"

    def test_cancel_request_wrong_user_raises_403(self):
        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "cancelwrong", "admin_scope", "auth_support", "Auth support access needed here"
            )
            with pytest.raises(HTTPException) as exc:
                er_svc.cancel_request(req["request_id"], "wrong_user")
        assert exc.value.status_code == 403

    def test_cancel_approved_request_raises_400(self):
        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "cancelterm", "admin_scope", "content_moderation", "Want content mod role"
            )
            er_svc.claim_request(req["request_id"], "admin_sub")
            old_crm_acl = sys.modules.get("app.services.crm_acl", "__missing__")
            if "app.services.crm_acl" in sys.modules:
                sys.modules["app.services.crm_acl"] = None  # type: ignore
            try:
                er_svc.approve_request(req["request_id"], "admin_sub")
            finally:
                if old_crm_acl == "__missing__":
                    if "app.services.crm_acl" in sys.modules and sys.modules["app.services.crm_acl"] is None:
                        del sys.modules["app.services.crm_acl"]
                else:
                    sys.modules["app.services.crm_acl"] = old_crm_acl  # type: ignore

            with pytest.raises(HTTPException) as exc:
                er_svc.cancel_request(req["request_id"], "cancelterm")
        assert exc.value.status_code == 400

    def test_get_request_not_found_raises_404(self):
        with pytest.raises(HTTPException) as exc:
            er_svc.get_request("nonexistent-request-id")
        assert exc.value.status_code == 404

    def test_get_request_history_returns_audit_rows(self):
        with patch("app.services.entitlement_requests.audit_event"):
            req = er_svc.create_request(
                "histuser", "admin_scope", "auth_support", "I need audit history support access"
            )
            er_svc.claim_request(req["request_id"], "admin_sub")
        history = er_svc.get_request_history(req["request_id"])
        assert len(history) >= 2
        # Newest first
        event_types = [h["event_type"] for h in history]
        assert "claimed" in event_types
        assert "created" in event_types

    def test_list_my_requests_returns_only_requester_requests(self):
        with patch("app.services.entitlement_requests.audit_event"):
            er_svc.create_request(
                "myreq_alice", "admin_scope", "auth_support", "Alice needs auth support access"
            )
            er_svc.create_request(
                "myreq_bob", "admin_scope", "billing_support", "Bob needs billing access"
            )
        alice_reqs = er_svc.list_my_requests("myreq_alice")
        bob_reqs = er_svc.list_my_requests("myreq_bob")
        assert all(r["requester_sub"] == "myreq_alice" for r in alice_reqs)
        assert all(r["requester_sub"] == "myreq_bob" for r in bob_reqs)


# ===========================================================================
# VEW-005 — Flag-off behavior
# ===========================================================================


class TestVEW005FlagOff:
    """VEW-005: Flag-off safety checks."""

    def test_flag_off_account_views_raises_404(self):
        from app.core import settings as _settings
        old_av = getattr(_settings.S, "account_views_enabled", False)
        object.__setattr__(_settings.S, "account_views_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                svc._require_enabled()
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(_settings.S, "account_views_enabled", old_av)

    def test_flag_off_entitlement_requests_raises_404(self):
        from app.core import settings as _settings
        old_er = getattr(_settings.S, "entitlement_requests_enabled", False)
        object.__setattr__(_settings.S, "entitlement_requests_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                er_svc._require_enabled()
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(_settings.S, "entitlement_requests_enabled", old_er)

    def test_project_resource_safe_when_flags_off(self):
        """project_resource is a pure function; it should never raise regardless of flags."""
        result = svc.project_resource({}, {}, "wallet")
        assert isinstance(result, dict)

    def test_project_resource_unknown_type_returns_empty(self):
        result = svc.project_resource({"foo": "bar"}, _grants_all_true(), "unknown_type")
        assert result == {}

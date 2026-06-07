"""Regression tests for GAP-0038: rootctl admin grant must support scoped capabilities.

Before the fix, ``rootctl admin grant`` wrote only ``role=admin`` with no
``admin_capabilities``, producing an implicit GENERAL (full-access) admin for
every grant. ``rootctl admin revoke`` likewise never cleared stale capabilities.

These tests run fully offline using MagicMock-backed DynamoDB table handles
(no real AWS, no moto needed for this CLI path) and assert the UpdateExpression
content produced by the grant/revoke commands.
"""

import argparse

import pytest
from unittest.mock import MagicMock

from app.cli.rootctl import _admin_grant_command, _admin_revoke_command


ROOT_SUB = "root@example.com"
TARGET_SUB = "admin@example.com"


def _make_args(**kwargs):
    base = dict(
        root_sub=ROOT_SUB,
        actor_sub=ROOT_SUB,
        reason="test grant",
        target_user_sub=TARGET_SUB,
        role="admin",
        dry_run=False,
        output="json",
        request_id="req-test",
        correlation_id="cor-test",
        capability=[],
        group="admin",
        command="grant",
    )
    base.update(kwargs)
    return argparse.Namespace(**base)


@pytest.fixture()
def mock_tables(monkeypatch):
    users = MagicMock()
    users.get_item.side_effect = [
        {"Item": {"user_sub": TARGET_SUB, "role": "user"}},  # _require_existing_non_root_user
        {"Item": {"user_sub": TARGET_SUB, "role": "user"}},  # current_role check
    ]
    users.update_item.return_value = {}
    T = MagicMock()
    T.users = users
    T.role_audit = MagicMock()
    T.role_audit.put_item.return_value = {}
    monkeypatch.setattr("app.cli.rootctl.T", T)
    monkeypatch.setattr("app.cli.rootctl.audit_event", MagicMock())
    return T


def test_grant_with_no_capabilities_writes_no_capabilities_field(mock_tables):
    """No --capability flags => GENERAL admin; UpdateExpression omits admin_capabilities."""
    _admin_grant_command(_make_args(capability=[]))
    call_kwargs = mock_tables.users.update_item.call_args[1]
    assert "admin_capabilities" not in call_kwargs.get("UpdateExpression", "")


def test_grant_with_capabilities_writes_capabilities_field(mock_tables):
    """FAILS BEFORE FIX: admin_capabilities never written.

    PASSES AFTER FIX: scoped capabilities persisted on the user record.
    """
    _admin_grant_command(_make_args(capability=["user_support"]))
    call_kwargs = mock_tables.users.update_item.call_args[1]
    assert "admin_capabilities" in call_kwargs.get("UpdateExpression", "")
    assert call_kwargs["ExpressionAttributeValues"][":caps"] == ["user_support"]


def test_grant_dry_run_includes_capabilities(mock_tables):
    """Dry-run output surfaces the intended capabilities."""
    result = _admin_grant_command(_make_args(capability=["billing_read"], dry_run=True))
    assert result.get("dry_run") is True
    assert "new_capabilities" in result
    assert "billing_read" in result["new_capabilities"]


def test_revoke_clears_capabilities_field(mock_tables):
    """FAILS BEFORE FIX: REMOVE admin_capabilities absent from revoke UpdateExpression.

    PASSES AFTER FIX: revoke clears any stale capabilities.
    """
    mock_tables.users.get_item.side_effect = [
        {"Item": {"user_sub": TARGET_SUB, "role": "admin"}},
        {"Item": {"user_sub": TARGET_SUB, "role": "admin"}},
    ]
    revoke_args = _make_args(command="revoke")
    revoke_args.role = "admin"
    _admin_revoke_command(revoke_args)
    call_kwargs = mock_tables.users.update_item.call_args[1]
    assert "REMOVE admin_capabilities" in call_kwargs.get("UpdateExpression", "")

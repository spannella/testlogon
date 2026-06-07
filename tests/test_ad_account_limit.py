"""Regression tests for GAP-0039: max-5-accounts-per-user limit on ad account creation.

Offline / in-memory only: the DynamoDB table handle and the owner-listing helper
are monkeypatched, so no real AWS (or moto) is required.
"""
from unittest.mock import MagicMock

import pytest

from app.models import AdAccountCreateIn
from app.services import ad_accounts
from app.services.ad_accounts import MAX_ACCOUNTS_PER_USER, create_ad_account


def _make_body(company: str = "Test Co") -> AdAccountCreateIn:
    return AdAccountCreateIn(company_name=company, billing_email="billing@example.com")


def _make_existing(n: int, status: str = "active") -> list[dict]:
    return [
        {"account_id": f"acct_{i}", "owner_sub": "user@example.com", "status": status}
        for i in range(n)
    ]


@pytest.fixture(autouse=True)
def patch_table(monkeypatch):
    """Replace the DynamoDB table handle so put_item is a no-op recordable mock."""
    fake_T = MagicMock()
    fake_T.ad_accounts.put_item.return_value = {}
    monkeypatch.setattr(ad_accounts, "T", fake_T)
    return fake_T


def _patch_existing(monkeypatch, items: list[dict]) -> None:
    monkeypatch.setattr(ad_accounts, "list_accounts_by_owner", lambda owner_sub: items)


def test_create_succeeds_when_under_limit(monkeypatch, patch_table):
    """Creation succeeds when owner has fewer than MAX accounts."""
    _patch_existing(monkeypatch, _make_existing(MAX_ACCOUNTS_PER_USER - 1))
    result = create_ad_account("user@example.com", _make_body())
    assert result["status"] == "pending_review"
    patch_table.ad_accounts.put_item.assert_called_once()


def test_create_succeeds_when_user_has_none(monkeypatch, patch_table):
    """First account is created when user has no existing accounts."""
    _patch_existing(monkeypatch, [])
    result = create_ad_account("new@example.com", _make_body())
    assert result["owner_sub"] == "new@example.com"
    patch_table.ad_accounts.put_item.assert_called_once()


def test_create_fails_at_limit(monkeypatch, patch_table):
    """FAILS BEFORE FIX: 6th account created. AFTER FIX: ValueError, no put_item."""
    _patch_existing(monkeypatch, _make_existing(MAX_ACCOUNTS_PER_USER))
    with pytest.raises(ValueError, match="Account limit reached"):
        create_ad_account("user@example.com", _make_body("Sixth Co"))
    patch_table.ad_accounts.put_item.assert_not_called()


def test_create_fails_far_above_limit(monkeypatch, patch_table):
    """Limit enforced even when the owner has many accounts."""
    _patch_existing(monkeypatch, _make_existing(100))
    with pytest.raises(ValueError):
        create_ad_account("user@example.com", _make_body())
    patch_table.ad_accounts.put_item.assert_not_called()


def test_terminal_accounts_do_not_count_toward_limit(monkeypatch, patch_table):
    """Deleted/suspended accounts are excluded from the per-user quota."""
    items = (
        _make_existing(MAX_ACCOUNTS_PER_USER, status="deleted")
        + _make_existing(1, status="active")
    )
    _patch_existing(monkeypatch, items)
    # Only 1 active account → under the limit → creation succeeds.
    result = create_ad_account("user@example.com", _make_body())
    assert result["status"] == "pending_review"
    patch_table.ad_accounts.put_item.assert_called_once()

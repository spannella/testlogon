"""Regression tests for GAP-0060: sponsorship FTC disclosure must not leak the
advertiser's raw Cognito sub (UUID) as the brand name.

`submit_content` builds the FTC "Paid partnership with <brand>" disclosure that is
written, server-side, onto public content. The brand name is meant to be the
advertiser's company name. Before the fix, `brand_name` was *initialized* to
``deal["advertiser_sub"]`` (a Cognito UUID), so any deal whose ad account lookup
failed or whose ``company_name`` was missing/empty would publish the raw advertiser
UUID as PII in the public disclosure.

The fix initializes ``brand_name`` to a safe generic fallback before the lookup, so
the advertiser sub can never reach the disclosure.

Offline / in-memory only: all DynamoDB-touching helpers are monkeypatched, so no
real AWS (and no moto) is required.
"""
from unittest.mock import MagicMock

import pytest

from app.services import sponsorship_deals
from app.services.sponsorship_deals import submit_content

ADVERTISER_SUB = "a1b2c3d4-0000-4f00-8000-aabbccddeeff"  # Cognito-style UUID (PII)
CREATOR_SUB = "creator@example.com"


def _seed_deal(monkeypatch, *, content_type: str = "video"):
    """Stub out everything `submit_content` calls except `_add_ftc_label`.

    Returns the recorded list capturing the brand_name passed to `_add_ftc_label`.
    """
    deal = {
        "deal_id": "deal_pii",
        "creator_sub": CREATOR_SUB,
        "advertiser_sub": ADVERTISER_SUB,
        "advertiser_account_id": "acct_missing",
        "content_type": content_type,
        "status": "accepted",
    }
    monkeypatch.setattr(sponsorship_deals, "get_deal", lambda deal_id: dict(deal))
    monkeypatch.setattr(sponsorship_deals, "_verify_content_ownership", lambda *a, **k: None)
    monkeypatch.setattr(sponsorship_deals, "_update_deal", lambda deal_id, updates, **k: {**deal, **updates})
    monkeypatch.setattr(sponsorship_deals, "_record_event", lambda *a, **k: None)
    monkeypatch.setattr(sponsorship_deals, "_notify", lambda *a, **k: None)

    captured = {}

    def _capture_label(content_type, content_id, *, brand_name, deal_id):
        captured["brand_name"] = brand_name

    monkeypatch.setattr(sponsorship_deals, "_add_ftc_label", _capture_label)
    return captured


def test_brand_name_does_not_leak_advertiser_sub_when_account_missing(monkeypatch):
    """Ad account not found -> brand_name must NOT be the advertiser Cognito sub."""
    captured = _seed_deal(monkeypatch)
    # get_ad_account returns None (account not found).
    import app.services.ad_accounts as ad_accounts
    monkeypatch.setattr(ad_accounts, "get_ad_account", lambda account_id: None)

    submit_content(deal_id="deal_pii", creator_sub=CREATOR_SUB, content_id="vid_001")

    assert captured["brand_name"] != ADVERTISER_SUB
    assert ADVERTISER_SUB not in captured["brand_name"]
    assert captured["brand_name"] == "a verified brand partner"


def test_brand_name_does_not_leak_advertiser_sub_when_company_name_empty(monkeypatch):
    """Account exists but company_name is empty -> still no UUID leak."""
    captured = _seed_deal(monkeypatch)
    import app.services.ad_accounts as ad_accounts
    monkeypatch.setattr(ad_accounts, "get_ad_account", lambda account_id: {"company_name": ""})

    submit_content(deal_id="deal_pii", creator_sub=CREATOR_SUB, content_id="vid_001")

    assert captured["brand_name"] != ADVERTISER_SUB
    assert ADVERTISER_SUB not in captured["brand_name"]
    assert captured["brand_name"] == "a verified brand partner"


def test_brand_name_does_not_leak_advertiser_sub_when_lookup_raises(monkeypatch):
    """Ad account lookup raising -> caught, and no UUID leak in disclosure."""
    captured = _seed_deal(monkeypatch)
    import app.services.ad_accounts as ad_accounts

    def _boom(account_id):
        raise RuntimeError("DDB down")

    monkeypatch.setattr(ad_accounts, "get_ad_account", _boom)

    submit_content(deal_id="deal_pii", creator_sub=CREATOR_SUB, content_id="vid_001")

    assert captured["brand_name"] != ADVERTISER_SUB
    assert ADVERTISER_SUB not in captured["brand_name"]


def test_brand_name_uses_company_name_when_available(monkeypatch):
    """Sanity: a real company_name is still used as the brand name."""
    captured = _seed_deal(monkeypatch)
    import app.services.ad_accounts as ad_accounts
    monkeypatch.setattr(ad_accounts, "get_ad_account", lambda account_id: {"company_name": "AcmeCorp"})

    submit_content(deal_id="deal_pii", creator_sub=CREATOR_SUB, content_id="vid_001")

    assert captured["brand_name"] == "AcmeCorp"

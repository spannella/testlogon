"""Regression test for GAP-0154: conversion attribution chain broken.

When a visitor arrives via an affiliate link, an ``afl_ref`` tracking cookie is
set. When that visitor later completes a purchase through the unified checkout
service, the tracking code must flow through to ``record_conversion`` so the
affiliate earns commission.

Fails-before: ``create_unified_checkout_session`` did not accept ``afl_ref`` and
never called ``record_conversion`` — affiliates earned nothing regardless of
clicks.
Passes-after: the tracking code propagates to the order metadata and triggers
``record_conversion`` with the correct ``link_id`` and ``amount_cents``.

Fully offline: the order service's DynamoDB tables are replaced with in-memory
fakes and the affiliate-links lookups are monkeypatched, so no real AWS access
occurs. Settings ``S`` is frozen — mutated only via ``object.__setattr__``.
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from app.models import UnifiedCheckoutSessionIn
from app.services import affiliate_links as affiliate_links_module
from app.services import commerce_order_service as order_service_module
from app.services import unified_checkout
from app.services.unified_checkout import create_unified_checkout_session


class _FakeTable:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def put_item(self, *, Item):
        self.items.append(dict(Item))


def _make_body(amount_cents: int) -> UnifiedCheckoutSessionIn:
    return UnifiedCheckoutSessionIn(
        source="direct",
        sku="sku_001",
        product_type="api_package",
        billing_model="one_time",
        quantity=1,
        scope={},
        pricing_ref={"currency": "USD", "amount_cents": amount_cents},
    )


@pytest.fixture
def offline_order_service(monkeypatch):
    """Replace the commerce order service tables and silence audit logging."""
    svc = order_service_module.commerce_order_service
    monkeypatch.setattr(svc, "orders", _FakeTable())
    monkeypatch.setattr(svc, "order_items", _FakeTable())
    monkeypatch.setattr(order_service_module, "audit_event", lambda *a, **k: None)
    return svc


def test_checkout_attributes_conversion_when_afl_ref_present(offline_order_service, monkeypatch):
    mock_link = {
        "link_id": "link_abc",
        "tracking_code": "MYCODE",
        "status": "active",
        "commission_percent": 10,
    }
    record_calls: List[Dict[str, Any]] = []

    monkeypatch.setattr(
        affiliate_links_module, "get_link_by_code", lambda code: mock_link if code == "MYCODE" else None
    )
    monkeypatch.setattr(
        affiliate_links_module,
        "record_conversion",
        lambda **kwargs: record_calls.append(kwargs),
    )

    out = create_unified_checkout_session("user_buyer", _make_body(5000), afl_ref="MYCODE")

    # FAILS-BEFORE: record_conversion was never called.
    assert len(record_calls) == 1, "record_conversion must be called exactly once"
    assert record_calls[0]["link_id"] == "link_abc"
    assert record_calls[0]["amount_cents"] == 5000
    assert record_calls[0]["order_id"] == out["order_id"]

    # afl_ref is stored in the persisted order metadata (cookie->order bridge).
    stored_order = offline_order_service.orders.items[0]
    assert stored_order["metadata"]["afl_ref"] == "MYCODE"


def test_checkout_no_attribution_without_afl_ref(offline_order_service, monkeypatch):
    record_calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(
        affiliate_links_module,
        "record_conversion",
        lambda **kwargs: record_calls.append(kwargs),
    )

    create_unified_checkout_session("user_buyer", _make_body(1000), afl_ref=None)

    assert record_calls == [], "no attribution should occur without an afl_ref cookie"
    stored_order = offline_order_service.orders.items[0]
    assert "afl_ref" not in stored_order["metadata"]


def test_checkout_no_attribution_for_inactive_link(offline_order_service, monkeypatch):
    inactive_link = {"link_id": "link_dead", "tracking_code": "DEAD", "status": "revoked"}
    record_calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(affiliate_links_module, "get_link_by_code", lambda code: inactive_link)
    monkeypatch.setattr(
        affiliate_links_module,
        "record_conversion",
        lambda **kwargs: record_calls.append(kwargs),
    )

    create_unified_checkout_session("user_buyer", _make_body(3000), afl_ref="DEAD")

    assert record_calls == [], "inactive links must not earn conversions"


def test_attribution_failure_does_not_abort_checkout(offline_order_service, monkeypatch):
    mock_link = {"link_id": "link_xyz", "tracking_code": "CODE", "status": "active"}

    def _boom(**kwargs):
        raise RuntimeError("DDB error")

    monkeypatch.setattr(affiliate_links_module, "get_link_by_code", lambda code: mock_link)
    monkeypatch.setattr(affiliate_links_module, "record_conversion", _boom)

    # Must not raise even though record_conversion blows up.
    out = create_unified_checkout_session("user_buyer", _make_body(2000), afl_ref="CODE")

    assert "order_id" in out and out["order_id"]

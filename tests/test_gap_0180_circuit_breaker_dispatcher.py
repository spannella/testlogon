"""Regression test for GAP-0180 (ENTERPRISE-005).

The webhook circuit breaker (``app/services/webhook_circuit_breaker.py``) is
fully implemented but ``app/services/webhook_dispatcher.py`` never imported or
called it. Every delivery was attempted regardless of circuit state, and no
delivery outcome was recorded back to the circuit breaker.

This test exercises ``run_webhook_dispatcher_once`` directly (offline — the
TestClient path is broken in this environment), monkeypatching the dispatcher's
DynamoDB-backed helpers with in-memory fakes so no real AWS access occurs.

Fails-before:
  * ``test_dispatcher_skips_open_circuit`` — delivery is attempted even though
    the endpoint's circuit is open and its cooldown has not expired.
  * ``test_dispatcher_records_failure_result`` /
    ``test_dispatcher_records_success_result`` — ``record_delivery_result`` is
    never called because it was never wired into the dispatcher.

Passes-after: open circuits are skipped and every outcome is recorded.
"""
from __future__ import annotations

import asyncio

from app.core.settings import S
from app.services import webhook_dispatcher as wd


def _make_delivery(endpoint_id="ep1", user_sub="user_a"):
    return {
        "delivery_id": "del_001",
        "endpoint_id": endpoint_id,
        "user_sub": user_sub,
        "payload": "{}",
        "event_type": "test.event",
    }


def _make_endpoint(circuit_state="closed", endpoint_id="ep1", user_sub="user_a"):
    return {
        "endpoint_id": endpoint_id,
        "user_sub": user_sub,
        "url": "https://example.com/hook",
        "secret": "enc_secret",
        "enabled": True,
        "circuit_state": circuit_state,
        "circuit_test_at": 0,
        "circuit_consecutive_failures": 0,
    }


def _enable_breaker(monkeypatch):
    # Settings dataclass `S` is frozen — use object.__setattr__ to force-enable.
    object.__setattr__(S, "webhooks_circuit_breaker_enabled", True)


def _patch_common(monkeypatch, *, endpoint, deliver_result=None, deliver_record=None):
    """Wire in-memory fakes for the dispatcher's DynamoDB-backed helpers."""
    monkeypatch.setattr(wd, "_get_endpoint_raw", lambda u, e: endpoint)
    monkeypatch.setattr(wd, "_decrypt_secret", lambda s: "secret")
    monkeypatch.setattr(
        wd,
        "query_due_deliveries",
        lambda status, now, limit: [_make_delivery()] if status == "pending" else [],
    )
    # Neutralise persistence side-effects.
    monkeypatch.setattr(wd, "mark_delivery_success", lambda *a, **k: None)
    monkeypatch.setattr(wd, "mark_delivery_dead_letter", lambda *a, **k: None)
    monkeypatch.setattr(wd, "reset_endpoint_failure_count", lambda *a, **k: None)
    monkeypatch.setattr(wd, "handle_delivery_failure", lambda *a, **k: None)


def test_dispatcher_skips_open_circuit(monkeypatch):
    """Deliveries for open-circuit endpoints must be skipped, not attempted."""
    _enable_breaker(monkeypatch)
    endpoint = _make_endpoint(circuit_state="open")
    endpoint["circuit_test_at"] = 9_999_999_999  # cooldown not yet expired

    attempted: list[str] = []

    async def _fake_deliver(**kwargs):
        attempted.append(kwargs["delivery_id"])
        return {"success": True, "status_code": 200}

    _patch_common(monkeypatch, endpoint=endpoint)
    monkeypatch.setattr(wd, "deliver_webhook", _fake_deliver)
    # If record_delivery_result is reached for an open circuit something is wrong;
    # leave it as the real function (it is a no-op for a skipped delivery path).

    result = asyncio.new_event_loop().run_until_complete(wd.run_webhook_dispatcher_once())

    assert attempted == [], (
        "Expected 0 deliveries (circuit open), got: " + str(attempted)
    )
    assert result["items_processed"] == 0
    assert result["items_failed"] == 0


def test_dispatcher_records_failure_result(monkeypatch):
    """After a failed delivery, record_delivery_result must be called success=False."""
    _enable_breaker(monkeypatch)
    endpoint = _make_endpoint(circuit_state="closed")

    recorded: list[bool] = []

    async def _fake_deliver(**kwargs):
        return {"success": False, "status_code": 500, "error": "server error"}

    _patch_common(monkeypatch, endpoint=endpoint)
    monkeypatch.setattr(wd, "deliver_webhook", _fake_deliver)
    monkeypatch.setattr(
        wd, "record_delivery_result",
        lambda ep, success: recorded.append(success),
    )

    asyncio.new_event_loop().run_until_complete(wd.run_webhook_dispatcher_once())

    assert recorded == [False], (
        "Expected record_delivery_result(success=False), got: " + str(recorded)
    )


def test_dispatcher_records_success_result(monkeypatch):
    """After a successful delivery, record_delivery_result must be called success=True."""
    _enable_breaker(monkeypatch)
    endpoint = _make_endpoint(circuit_state="closed")

    recorded: list[bool] = []

    async def _fake_deliver(**kwargs):
        return {"success": True, "status_code": 200}

    _patch_common(monkeypatch, endpoint=endpoint)
    monkeypatch.setattr(wd, "deliver_webhook", _fake_deliver)
    monkeypatch.setattr(
        wd, "record_delivery_result",
        lambda ep, success: recorded.append(success),
    )

    asyncio.new_event_loop().run_until_complete(wd.run_webhook_dispatcher_once())

    assert recorded == [True]

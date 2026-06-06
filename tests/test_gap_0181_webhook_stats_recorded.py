"""Regression test for GAP-0181 (ENTERPRISE-005).

Per-delivery stats (``record_delivery_stat``) must be recorded after each
webhook delivery outcome — success and failure — in both dispatcher paths
(``run_webhook_dispatcher_loop`` and ``run_webhook_dispatcher_once``).

Fails-before: ``record_delivery_stat`` is never imported or called from
``webhook_dispatcher.py``, so the spy is never invoked.
Passes-after: each delivery outcome calls ``record_delivery_stat(endpoint_id,
result)`` alongside the circuit-breaker ``record_delivery_result`` call.

Fully offline: all DynamoDB-touching collaborators (deliver_webhook, the
delivery-state mutators, the circuit breaker, the stats recorder) are replaced
with monkeypatched spies, so no real AWS / DynamoDB access occurs.
"""
from __future__ import annotations

import asyncio

from app.services import webhook_dispatcher as wd


def _async_return(value):
    async def _coro(*args, **kwargs):
        return value

    return _coro


def _patch_common(monkeypatch, *, due, endpoint, result):
    """Wire all collaborators with offline spies. Returns the stats-call list."""
    stat_calls: list[tuple] = []

    # query_due_deliveries is called twice (pending + failed). Return the due
    # batch as "pending" and an empty batch as "failed".
    calls = {"n": 0}

    def fake_query(**kwargs):
        calls["n"] += 1
        return list(due) if kwargs.get("status") == "pending" else []

    monkeypatch.setattr(wd, "query_due_deliveries", fake_query)
    monkeypatch.setattr(wd, "_get_endpoint_raw", lambda user_sub, endpoint_id: dict(endpoint))
    monkeypatch.setattr(wd, "_decrypt_secret", lambda secret: "decrypted")
    monkeypatch.setattr(wd, "deliver_webhook", _async_return(result))
    monkeypatch.setattr(wd, "mark_delivery_success", lambda *a, **k: None)
    monkeypatch.setattr(wd, "handle_delivery_failure", lambda *a, **k: None)
    monkeypatch.setattr(wd, "reset_endpoint_failure_count", lambda *a, **k: None)
    monkeypatch.setattr(wd, "mark_delivery_dead_letter", lambda *a, **k: None)
    monkeypatch.setattr(wd, "should_attempt_delivery", lambda endpoint, now: True)
    monkeypatch.setattr(wd, "record_delivery_result", lambda *a, **k: None)

    def fake_record_stat(endpoint_id, res):
        stat_calls.append((endpoint_id, res))

    monkeypatch.setattr(wd, "record_delivery_stat", fake_record_stat)
    return stat_calls


_ENDPOINT = {
    "endpoint_id": "ep1",
    "user_sub": "u1",
    "url": "https://example.com/hook",
    "secret": "plain:test_secret",
    "enabled": True,
}

_DELIVERY = {
    "delivery_id": "d1",
    "endpoint_id": "ep1",
    "user_sub": "u1",
    "payload": '{"event": "test"}',
    "event_type": "message.created",
}


def test_run_once_records_stat_on_success(monkeypatch):
    result = {"success": True, "response_code": 200, "duration_ms": 42}
    stat_calls = _patch_common(monkeypatch, due=[_DELIVERY], endpoint=_ENDPOINT, result=result)

    asyncio.get_event_loop().run_until_complete(wd.run_webhook_dispatcher_once())

    assert stat_calls == [("ep1", result)], (
        "run_webhook_dispatcher_once must call record_delivery_stat on success"
    )


def test_run_once_records_stat_on_failure(monkeypatch):
    result = {"success": False, "response_code": 500, "error": "HTTP 500", "duration_ms": 99}
    stat_calls = _patch_common(monkeypatch, due=[_DELIVERY], endpoint=_ENDPOINT, result=result)

    asyncio.get_event_loop().run_until_complete(wd.run_webhook_dispatcher_once())

    assert stat_calls == [("ep1", result)], (
        "run_webhook_dispatcher_once must call record_delivery_stat on failure"
    )


def test_loop_records_stat_on_success_and_failure(monkeypatch):
    """The background loop must record stats for both outcomes before sleeping."""
    # First delivery succeeds, second fails — exercise both branches in one poll.
    success = {"success": True, "duration_ms": 10}
    fail = {"success": False, "error": "boom", "duration_ms": 20}

    deliveries = [dict(_DELIVERY, delivery_id="d1"), dict(_DELIVERY, delivery_id="d2")]
    stat_calls = _patch_common(monkeypatch, due=deliveries, endpoint=_ENDPOINT, result=success)

    # deliver_webhook returns success for d1, fail for d2 based on delivery_id.
    async def fake_deliver(*, url, payload, secret, delivery_id, event_type):
        return success if delivery_id == "d1" else fail

    monkeypatch.setattr(wd, "deliver_webhook", fake_deliver)
    monkeypatch.setattr(wd, "report_poll", lambda *a, **k: None)
    monkeypatch.setattr(wd, "_record_run", lambda *a, **k: None)
    monkeypatch.setattr(wd, "register_task", lambda *a, **k: None)

    # Break out of the infinite loop on the first sleep.
    async def fake_sleep(_):
        raise asyncio.CancelledError

    monkeypatch.setattr(wd.asyncio, "sleep", fake_sleep)

    try:
        asyncio.get_event_loop().run_until_complete(wd.run_webhook_dispatcher_loop())
    except asyncio.CancelledError:
        pass

    assert ("ep1", success) in stat_calls, "loop must record stat on success"
    assert ("ep1", fail) in stat_calls, "loop must record stat on failure"
    assert len(stat_calls) == 2

"""GAP-0249 (KYC-003): KYC liveness-call expiry background task.

Offline hermetic regression tests (no real AWS, no global moto interception).
We swap ``STORE._table`` for a tiny in-memory fake compatible with the boto3
DynamoDB ``Table`` resource surface that ``KycLivenessCallStore`` actually uses
(``query`` for the ByStatus GSI, ``get_item``, ``update_item`` SET).

These verify that:

1. ``expire_due_calls`` transitions a stale ``scheduled`` call to ``expired``
   and leaves fresh calls untouched.
2. A single tick of ``kyc_liveness_expiry_loop`` runs the expiry sweep
   (loop cancelled after the first ``asyncio.sleep``).
3. ``start_kyc_liveness_expiry_task`` schedules the loop when the feature flag
   is enabled and is a no-op when disabled.
4. The startup handler is wired into the FastAPI app
   (``create_app().router.on_startup``).

Settings ``S`` is frozen, so any mutation goes through ``object.__setattr__``.
Async tests use ``asyncio.run`` with a fresh loop (never ``get_event_loop``).
"""

import asyncio
from unittest.mock import patch

import pytest

import app.services.kyc_liveness_call as klc
from app.services.kyc_liveness_call import (
    STATUS_EXPIRED,
    STATUS_SCHEDULED,
    STORE,
    kyc_liveness_expiry_loop,
    start_kyc_liveness_expiry_task,
)


# ---------------------------------------------------------------------------
# In-memory fake DynamoDB table (only the methods the store uses).
# ---------------------------------------------------------------------------
class _FakeTable:
    def __init__(self):
        self.items: dict[str, dict] = {}

    def put_item(self, Item):  # noqa: N803 - boto3 kwarg name
        self.items[str(Item["call_id"])] = dict(Item)

    def get_item(self, Key):  # noqa: N803
        item = self.items.get(str(Key["call_id"]))
        return {"Item": dict(item)} if item is not None else {}

    def query(self, **kwargs):
        # The store filters by status via KeyConditionExpression on the GSI.
        # Resolve the requested status from the boto3 condition object.
        cond = kwargs.get("KeyConditionExpression")
        wanted = getattr(cond, "_values", (None, None))[1]
        matched = [
            dict(it) for it in self.items.values() if it.get("status") == wanted
        ]
        matched.sort(key=lambda i: int(i.get("created_at", 0)), reverse=True)
        return {"Items": matched}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeNames,  # noqa: N803
                    ExpressionAttributeValues):
        item = self.items[str(Key["call_id"])]
        # UpdateExpression is "SET #k0 = :v0, #k1 = :v1, ..."
        assignments = UpdateExpression.removeprefix("SET ").split(", ")
        for assign in assignments:
            name_ph, val_ph = (p.strip() for p in assign.split("="))
            field = ExpressionAttributeNames[name_ph]
            item[field] = ExpressionAttributeValues[val_ph]


@pytest.fixture
def fake_table():
    orig = STORE._table
    table = _FakeTable()
    STORE._table = table
    try:
        yield table
    finally:
        STORE._table = orig


def _seed(table, call_id, status, scheduled_at, created_at=0):
    table.put_item(Item={
        "call_id": call_id,
        "case_id": f"case_{call_id}",
        "user_sub": f"user_{call_id}",
        "status": status,
        "scheduled_at": scheduled_at,
        "created_at": created_at,
        "updated_at": scheduled_at,
    })


# ---------------------------------------------------------------------------
# expire_due_calls behaviour (the logic the loop drives)
# ---------------------------------------------------------------------------
def test_expire_due_calls_transitions_stale_scheduled(fake_table):
    now = 2_000_000_000
    cutoff = int(klc.S.kyc_liveness_call_expiry_seconds)
    _seed(fake_table, "stale", STATUS_SCHEDULED, scheduled_at=now - cutoff - 1)

    expired = STORE.expire_due_calls(now=now)

    assert "stale" in expired
    assert fake_table.items["stale"]["status"] == STATUS_EXPIRED


def test_expire_due_calls_skips_fresh_scheduled(fake_table):
    now = 2_000_000_000
    _seed(fake_table, "fresh", STATUS_SCHEDULED, scheduled_at=now + 3600)

    expired = STORE.expire_due_calls(now=now)

    assert "fresh" not in expired
    assert fake_table.items["fresh"]["status"] == STATUS_SCHEDULED


# ---------------------------------------------------------------------------
# The loop tick expires a stale call (single iteration, then cancel)
# ---------------------------------------------------------------------------
def test_expiry_loop_tick_expires_stale_call(fake_table):
    now = 2_000_000_000
    cutoff = int(klc.S.kyc_liveness_call_expiry_seconds)
    _seed(fake_table, "loop_stale", STATUS_SCHEDULED, scheduled_at=now - cutoff - 1)

    async def _run_one_tick():
        # Cancel on the first sleep so exactly one sweep runs.
        with patch("asyncio.sleep", side_effect=asyncio.CancelledError):
            with patch.object(klc, "now_ts", return_value=now):
                with pytest.raises(asyncio.CancelledError):
                    await kyc_liveness_expiry_loop()

    asyncio.run(_run_one_tick())

    assert fake_table.items["loop_stale"]["status"] == STATUS_EXPIRED


# ---------------------------------------------------------------------------
# start_kyc_liveness_expiry_task gating on the feature flag
# ---------------------------------------------------------------------------
def test_start_task_schedules_loop_when_enabled():
    orig = klc.S.kyc_liveness_call_enabled
    object.__setattr__(klc.S, "kyc_liveness_call_enabled", True)
    try:
        with patch("asyncio.ensure_future") as mock_ensure:
            start_kyc_liveness_expiry_task()
        assert mock_ensure.call_count == 1
    finally:
        object.__setattr__(klc.S, "kyc_liveness_call_enabled", orig)


def test_start_task_noop_when_disabled():
    orig = klc.S.kyc_liveness_call_enabled
    object.__setattr__(klc.S, "kyc_liveness_call_enabled", False)
    try:
        with patch("asyncio.ensure_future") as mock_ensure:
            start_kyc_liveness_expiry_task()
        mock_ensure.assert_not_called()
    finally:
        object.__setattr__(klc.S, "kyc_liveness_call_enabled", orig)


# ---------------------------------------------------------------------------
# Startup wiring in app/main.py
# ---------------------------------------------------------------------------
def test_startup_handler_registered_in_main():
    from app.main import create_app

    app = create_app()
    handler_names = [
        getattr(h, "__name__", repr(h)) for h in app.router.on_startup
    ]
    assert "start_kyc_liveness_expiry_task" in handler_names, (
        "KYC liveness expiry startup handler not found in app.on_startup"
    )

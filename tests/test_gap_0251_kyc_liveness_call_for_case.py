"""Offline regression test for GAP-0251 (KYC-003).

GAP-0251 — there was no direct case-level lookup for a KYC liveness verification
call. The admin liveness-call router exposed ``GET /admin/by-status`` and
``GET /admin/{call_id}`` but no ``GET /admin/case/{case_id}``. Reviewers had to
fan out the ByStatus GSI across every status partition and filter by ``case_id``
themselves to find the call for a case.

The fix adds:
  * ``KycLivenessCallStore.get_call_for_case(case_id)`` in
    ``app/services/kyc_liveness_call.py`` — queries the ByStatus GSI (one query
    per status bucket), filters by ``case_id``, and returns the most relevant
    call (active call preferred, else most recently created).
  * ``GET /ui/kyc/liveness-call/admin/case/{case_id}`` in
    ``app/routers/kyc_liveness_call.py`` (admin/root gated), declared before
    ``/admin/{call_id}`` so ``case`` is never matched as a ``call_id``.

This test is fully offline and hermetic:
  * A real in-memory DynamoDB table is created with moto WITHIN this module only.
    We do NOT rely on global ``@mock_aws`` interception leaking to real AWS — the
    moto context is entered/exited via ``ExitStack`` per test class and the exact
    table handle is injected onto the frozen ``T`` (via ``object.__setattr__``)
    and onto the ``STORE`` singleton.
  * The async router handler is awaited directly via ``asyncio.run`` on a fresh
    event loop (never ``asyncio.get_event_loop()``); auth is satisfied by passing
    an ``AuthenticatedUser`` in place of the ``Depends(require_admin_or_root)``
    dependency.

FAILS BEFORE FIX: ``STORE.get_call_for_case`` does not exist (AttributeError),
and the router has no ``admin_get_liveness_call_for_case`` handler.
PASSES AFTER FIX: the service returns the most relevant call for the case and the
handler returns it (or raises 404 when none exists).
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _run(coro):
    """Run an async handler on a fresh event loop (never get_event_loop())."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_kyc_liveness_calls_table(ddb):
    """Mirror the kyc_liveness_calls TableDef from scripts/local-ddb-init.py.

    PK=call_id; GSIs ByStatus (status / created_at) and ByCase (case_id /
    created_at). created_at/scheduled_at are numeric (attr_types N).
    """
    return ddb.create_table(
        TableName="kyc_liveness_calls",
        KeySchema=[{"AttributeName": "call_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "call_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "case_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByStatus",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCase",
                "KeySchema": [
                    {"AttributeName": "case_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestGetCallForCaseGap0251(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_kyc_liveness_calls_table(ddb)

        from app.core.tables import T
        from app.services import kyc_liveness_call as svc

        self.svc = svc
        self.T = T

        # Inject the moto table onto the frozen Tables singleton AND the store
        # singleton; restore both on teardown. T is a frozen dataclass, so we
        # must use object.__setattr__.
        self._prev_T = T.kyc_liveness_calls
        object.__setattr__(T, "kyc_liveness_calls", self.table)
        self.addCleanup(
            lambda: object.__setattr__(T, "kyc_liveness_calls", self._prev_T)
        )

        self._prev_store_table = svc.STORE._table
        svc.STORE._table = self.table
        self.addCleanup(setattr, svc.STORE, "_table", self._prev_store_table)

    def _put(self, *, call_id, case_id, status, created_at, user_sub="user_x"):
        self.table.put_item(
            Item={
                "call_id": call_id,
                "case_id": case_id,
                "user_sub": user_sub,
                "status": status,
                "created_at": created_at,
                "updated_at": created_at,
                "scheduled_at": created_at,
                "duration_minutes": 15,
            }
        )

    # --- service layer ----------------------------------------------------

    def test_get_call_for_case_returns_none_when_absent(self):
        self.assertIsNone(self.svc.STORE.get_call_for_case("case_missing"))

    def test_get_call_for_case_prefers_active_over_terminal(self):
        """An active (scheduled) call wins over an older OR newer terminal call.

        Seed a terminal 'passed' call created AFTER the active 'scheduled' call to
        prove the ranking prefers active status, not merely recency.
        """
        self._put(call_id="kyccall_sched", case_id="case_a", status="scheduled", created_at=1000)
        self._put(call_id="kyccall_passed", case_id="case_a", status="passed", created_at=2000)

        found = self.svc.STORE.get_call_for_case("case_a")
        self.assertIsNotNone(found)
        self.assertEqual(found["call_id"], "kyccall_sched")
        self.assertEqual(found["status"], "scheduled")

    def test_get_call_for_case_latest_terminal_when_no_active(self):
        """With no active call, the most recently created terminal call wins."""
        self._put(call_id="kyccall_old", case_id="case_b", status="failed", created_at=1000)
        self._put(call_id="kyccall_new", case_id="case_b", status="passed", created_at=3000)
        self._put(call_id="kyccall_mid", case_id="case_b", status="cancelled", created_at=2000)

        found = self.svc.STORE.get_call_for_case("case_b")
        self.assertEqual(found["call_id"], "kyccall_new")

    def test_get_call_for_case_ignores_other_cases(self):
        self._put(call_id="kyccall_other", case_id="case_other", status="scheduled", created_at=5000)
        self._put(call_id="kyccall_mine", case_id="case_mine", status="scheduled", created_at=1000)
        found = self.svc.STORE.get_call_for_case("case_mine")
        self.assertEqual(found["call_id"], "kyccall_mine")

    # --- router handler (called directly, async) --------------------------

    def _admin_user(self):
        from app.auth.deps import AuthenticatedUser
        from app.auth.roles import Role

        return AuthenticatedUser(sub="admin_sub", role=Role.ADMIN)

    def test_admin_handler_returns_call_for_case(self):
        from app.routers import kyc_liveness_call as router

        self._put(call_id="kyccall_h1", case_id="case_h", status="in_progress", created_at=4000)
        result = _run(
            router.admin_get_liveness_call_for_case(
                case_id="case_h", _user=self._admin_user()
            )
        )
        self.assertEqual(result.call_id, "kyccall_h1")
        self.assertEqual(result.case_id, "case_h")
        self.assertEqual(result.status, "in_progress")

    def test_admin_handler_404_when_no_call(self):
        from fastapi import HTTPException

        from app.routers import kyc_liveness_call as router

        with self.assertRaises(HTTPException) as ctx:
            _run(
                router.admin_get_liveness_call_for_case(
                    case_id="case_none", _user=self._admin_user()
                )
            )
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail["code"], "kyc_call_not_found")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

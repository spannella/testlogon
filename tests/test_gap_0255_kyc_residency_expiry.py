"""Offline regression test for GAP-0255 (KYC-005).

GAP-0255 — verified proof-of-residency documents whose ``document_date`` has
aged out of the recency window stayed in ``verified`` status forever, so a stale
submission kept satisfying readiness gates indefinitely. There was no expiry
method on the service and no background task in ``app/main.py``.

The fix adds:
  * ``KycResidencyStore.expire_stale_submissions(now=..., limit=...)`` in
    ``app/services/kyc_residency.py`` — iterates the ByStatus GSI ``verified``
    partition, re-applies the recency check, and transitions aged-out documents
    to ``expired``.
  * ``kyc_residency_expiry_loop`` + ``start_kyc_residency_expiry_task`` (6h
    loop, gated on ``kyc_residency_enabled`` + ``kyc_residency_expiry_enabled``).
  * ``app.add_event_handler("startup", start_kyc_residency_expiry_task)`` in
    ``app/main.py``.

This test is fully offline and hermetic:
  * A real in-memory DynamoDB table is created with moto WITHIN this module only.
    We do NOT rely on global ``@mock_aws`` interception leaking to real AWS — the
    moto context is entered/exited via ``ExitStack`` per test class and the exact
    table handle is injected onto the frozen ``T`` (via ``object.__setattr__``)
    and onto the ``STORE`` singleton.
  * The frozen settings singleton ``S`` is mutated via ``object.__setattr__``.
  * The async loop is driven on a fresh event loop (never
    ``asyncio.get_event_loop()``); a single iteration is forced by patching
    ``asyncio.sleep`` to raise ``CancelledError``.

FAILS BEFORE FIX: ``STORE.expire_stale_submissions`` does not exist
(AttributeError), and ``app/main.py`` registers no
``start_kyc_residency_expiry_task`` startup handler.
PASSES AFTER FIX: aged-out verified docs are expired, recent ones untouched, and
the startup handler is wired into the app.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from datetime import date, timedelta

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _run(coro):
    """Run a coroutine on a fresh event loop (never get_event_loop())."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_kyc_residency_documents_table(ddb):
    """Mirror the kyc_residency_documents TableDef from scripts/local-ddb-init.py.

    PK=document_id; GSIs ByStatus (status / created_at), ByCase (case_id /
    created_at), ByOwner (user_sub / created_at). created_at is numeric.
    """
    return ddb.create_table(
        TableName="kyc_residency_documents",
        KeySchema=[{"AttributeName": "document_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "document_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "case_id", "AttributeType": "S"},
            {"AttributeName": "user_sub", "AttributeType": "S"},
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
            {
                "IndexName": "ByOwner",
                "KeySchema": [
                    {"AttributeName": "user_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# A fixed "now" anchor for deterministic recency math.
_NOW_TS = 1_700_000_000  # 2023-11-14T22:13:20Z
_NOW_DATE = date.fromtimestamp(_NOW_TS)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestExpireStaleSubmissionsGap0255(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_kyc_residency_documents_table(ddb)

        from app.core.settings import S
        from app.core.tables import T
        from app.services import kyc_residency as svc

        self.svc = svc
        self.S = S

        # Inject the moto table onto the frozen Tables singleton AND the store
        # singleton; restore both on teardown. T is a frozen dataclass, so we
        # must use object.__setattr__.
        self._prev_T = T.kyc_residency_documents
        object.__setattr__(T, "kyc_residency_documents", self.table)
        self.addCleanup(
            lambda: object.__setattr__(T, "kyc_residency_documents", self._prev_T)
        )

        self._prev_store_table = svc.STORE._table
        svc.STORE._table = self.table
        self.addCleanup(setattr, svc.STORE, "_table", self._prev_store_table)

        # Pin the recency window to a known value (frozen settings -> setattr).
        self._prev_recency = S.kyc_residency_recency_days
        object.__setattr__(S, "kyc_residency_recency_days", 90)
        self.addCleanup(
            lambda: object.__setattr__(
                S, "kyc_residency_recency_days", self._prev_recency
            )
        )

    def _put(self, *, document_id, status, days_old, case_id="case_x", user_sub="user_x"):
        doc_date = (_NOW_DATE - timedelta(days=days_old)).isoformat()
        created = _NOW_TS - days_old * 86400
        self.table.put_item(
            Item={
                "document_id": document_id,
                "case_id": case_id,
                "user_sub": user_sub,
                "status": status,
                "document_type": "utility_bill",
                "document_date": doc_date,
                "created_at": created,
                "updated_at": created,
            }
        )

    # --- service layer ----------------------------------------------------

    def test_expires_old_verified_document(self):
        """A verified doc older than the recency window transitions to expired."""
        self._put(document_id="kycres_stale", status=self.svc.STATUS_VERIFIED, days_old=400)

        expired = self.svc.STORE.expire_stale_submissions(now=_NOW_DATE)

        self.assertIn("kycres_stale", expired)
        item = self.svc.STORE.get_document("kycres_stale")
        self.assertEqual(item["status"], self.svc.STATUS_EXPIRED)

    def test_keeps_recent_verified_document(self):
        """A verified doc inside the recency window is left untouched."""
        self._put(document_id="kycres_recent", status=self.svc.STATUS_VERIFIED, days_old=30)

        expired = self.svc.STORE.expire_stale_submissions(now=_NOW_DATE)

        self.assertNotIn("kycres_recent", expired)
        item = self.svc.STORE.get_document("kycres_recent")
        self.assertEqual(item["status"], self.svc.STATUS_VERIFIED)

    def test_only_touches_verified_partition(self):
        """Aged-out pending/rejected docs are not iterated (not 'verified')."""
        self._put(document_id="kycres_pending", status=self.svc.STATUS_PENDING, days_old=400)
        self._put(document_id="kycres_rejected", status=self.svc.STATUS_REJECTED, days_old=400)

        expired = self.svc.STORE.expire_stale_submissions(now=_NOW_DATE)

        self.assertEqual(expired, [])
        self.assertEqual(
            self.svc.STORE.get_document("kycres_pending")["status"],
            self.svc.STATUS_PENDING,
        )
        self.assertEqual(
            self.svc.STORE.get_document("kycres_rejected")["status"],
            self.svc.STATUS_REJECTED,
        )

    def test_mixed_batch_expires_only_aged_out(self):
        self._put(document_id="kycres_old", status=self.svc.STATUS_VERIFIED, days_old=200)
        self._put(document_id="kycres_new", status=self.svc.STATUS_VERIFIED, days_old=10)

        expired = self.svc.STORE.expire_stale_submissions(now=_NOW_DATE)

        self.assertEqual(set(expired), {"kycres_old"})
        self.assertEqual(
            self.svc.STORE.get_document("kycres_old")["status"],
            self.svc.STATUS_EXPIRED,
        )
        self.assertEqual(
            self.svc.STORE.get_document("kycres_new")["status"],
            self.svc.STATUS_VERIFIED,
        )

    # --- background loop --------------------------------------------------

    def test_loop_runs_one_iteration_and_expires(self):
        """A single iteration of the loop expires due docs without raising out."""
        from unittest.mock import patch

        self._put(document_id="kycres_loop", status=self.svc.STATUS_VERIFIED, days_old=400)

        async def _one_iteration():
            with patch("asyncio.sleep", side_effect=asyncio.CancelledError):
                with self.assertRaises(asyncio.CancelledError):
                    await self.svc.kyc_residency_expiry_loop(interval_seconds=6 * 3600)

        _run(_one_iteration())

        item = self.svc.STORE.get_document("kycres_loop")
        self.assertEqual(item["status"], self.svc.STATUS_EXPIRED)

    def test_start_task_schedules_loop_when_enabled(self):
        from unittest.mock import patch

        prev_enabled = self.S.kyc_residency_enabled
        prev_expiry = self.S.kyc_residency_expiry_enabled
        object.__setattr__(self.S, "kyc_residency_enabled", True)
        object.__setattr__(self.S, "kyc_residency_expiry_enabled", True)
        try:
            with patch("asyncio.ensure_future") as mock_ensure:
                self.svc.start_kyc_residency_expiry_task()
            self.assertEqual(mock_ensure.call_count, 1)
        finally:
            object.__setattr__(self.S, "kyc_residency_enabled", prev_enabled)
            object.__setattr__(self.S, "kyc_residency_expiry_enabled", prev_expiry)

    def test_start_task_noop_when_flag_disabled(self):
        from unittest.mock import patch

        prev_expiry = self.S.kyc_residency_expiry_enabled
        object.__setattr__(self.S, "kyc_residency_expiry_enabled", False)
        try:
            with patch("asyncio.ensure_future") as mock_ensure:
                self.svc.start_kyc_residency_expiry_task()
            mock_ensure.assert_not_called()
        finally:
            object.__setattr__(self.S, "kyc_residency_expiry_enabled", prev_expiry)


class TestResidencyExpiryStartupRegistration(unittest.TestCase):
    def test_startup_handler_registered(self):
        """app/main.py must register start_kyc_residency_expiry_task at startup."""
        from app.main import create_app

        app = create_app()
        handler_names = [
            getattr(h, "__name__", repr(h)) for h in app.router.on_startup
        ]
        self.assertIn(
            "start_kyc_residency_expiry_task",
            handler_names,
            "KYC residency expiry startup handler not found in app.on_startup",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

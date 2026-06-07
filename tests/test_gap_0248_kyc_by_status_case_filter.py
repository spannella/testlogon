"""Offline regression test for GAP-0248 (KYC-002).

GAP-0248 — ``GET /ui/kyc/documents/admin/by-status`` accepted only ``status`` and
``limit``. Listing all documents for a specific case across statuses required
multiple per-status calls or a full scan; no ``case_id`` filter existed.

The fix adds an optional ``case_id`` query param to the router and a matching
``case_id`` keyword to ``KycDocumentVerificationStore.list_by_status``, which
applies a DynamoDB ``FilterExpression`` (``Attr("case_id").eq(case_id)``) on the
``ByStatus`` GSI query so only that case's documents are returned. Without
``case_id`` the behaviour is unchanged (all docs for the status).

Hermetic / offline:
* A real in-memory DynamoDB table is created with moto inside an ExitStack — used
  ONLY as a self-contained handle, NOT via global @mock_aws interception that
  could leak to real AWS. The handle is patched onto the exact frozen ``STORE``
  attribute via ``object.__setattr__`` so no global botocore patching is relied
  upon for the code under test.
* The async router handler is invoked directly via ``asyncio.run`` on a FRESH
  event loop (never ``asyncio.get_event_loop()``).
* ``Settings`` ``S`` is frozen → patched with ``object.__setattr__``.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from types import SimpleNamespace

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_kyc_documents_table(ddb, *, status_index: str):
    """Mirror scripts/local-ddb-init.py kyc_documents table (ByStatus + ByCase)."""
    return ddb.create_table(
        TableName="kyc_documents",
        KeySchema=[{"AttributeName": "document_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "document_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "case_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": status_index,
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


def _run(coro):
    """Run an async handler on a fresh event loop (never get_event_loop)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestKycByStatusCaseFilterGap0248(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())

        from app.services import kyc_document_verification as svc
        from app.core.settings import S

        self.svc = svc
        status_index = S.kyc_documents_status_index_name

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_kyc_documents_table(ddb, status_index=status_index)

        # Patch the EXACT frozen handle on STORE (not a global botocore patch).
        object.__setattr__(svc.STORE, "_table", self.table)
        self.addCleanup(lambda: object.__setattr__(svc.STORE, "_table", self.svc.T.kyc_documents))

        self._seq = 0

    def _seed(self, *, document_id: str, status: str, case_id: str):
        self._seq += 1
        item = {
            "document_id": document_id,
            "user_sub": f"user_{document_id}",
            "document_type": "id_front",
            "file_name": f"{document_id}.png",
            "status": status,
            "case_id": case_id,  # caller passes "_none" sentinel for case-less docs
            "created_at": self._seq,
        }
        self.table.put_item(Item=item)

    # -- helper to call the router handler directly --------------------------
    def _call_endpoint(self, *, status: str, case_id=None):
        from app.routers import kyc_documents as router

        fake_user = SimpleNamespace(sub="admin_sub", role="ROOT")
        resp = _run(
            router.admin_list_by_status(
                status=status,
                limit=100,
                case_id=case_id,
                _user=fake_user,
            )
        )
        # KycDocumentListResponse -> list of KycDocumentOut
        return resp.documents

    def test_with_case_id_returns_only_that_case(self):
        """FAILS BEFORE FIX: case_id was ignored → both cases returned.

        PASSES AFTER FIX: only the target case's extracted docs are returned.
        """
        self._seed(document_id="d_a1", status="extracted", case_id="case_alpha")
        self._seed(document_id="d_a2", status="extracted", case_id="case_alpha")
        self._seed(document_id="d_b1", status="extracted", case_id="case_beta")
        # case-less doc must never match a real case_id filter
        self._seed(document_id="d_none", status="extracted", case_id="_none")

        docs = self._call_endpoint(status="extracted", case_id="case_alpha")

        ids = {d.document_id for d in docs}
        self.assertEqual(ids, {"d_a1", "d_a2"})
        self.assertTrue(all(d.case_id == "case_alpha" for d in docs))
        # other case + the _none sentinel doc excluded
        self.assertNotIn("d_b1", ids)
        self.assertNotIn("d_none", ids)

    def test_without_case_id_returns_all_for_status(self):
        """Backward compatible: no case_id → all docs for the status (both cases)."""
        self._seed(document_id="d_a1", status="extracted", case_id="case_alpha")
        self._seed(document_id="d_b1", status="extracted", case_id="case_beta")

        docs = self._call_endpoint(status="extracted", case_id=None)

        ids = {d.document_id for d in docs}
        self.assertEqual(ids, {"d_a1", "d_b1"})
        case_ids = {d.case_id for d in docs}
        self.assertEqual(case_ids, {"case_alpha", "case_beta"})

    def test_case_id_filter_respects_status(self):
        """The case filter is combined with the status partition (not all statuses)."""
        self._seed(document_id="d_ex", status="extracted", case_id="case_alpha")
        self._seed(document_id="d_pe", status="pending", case_id="case_alpha")

        docs = self._call_endpoint(status="extracted", case_id="case_alpha")
        ids = {d.document_id for d in docs}
        self.assertEqual(ids, {"d_ex"})
        self.assertNotIn("d_pe", ids)

    def test_case_id_no_match_returns_empty(self):
        """A case with no docs in the status returns [] (HTTP 200, not 404)."""
        self._seed(document_id="d_a1", status="extracted", case_id="case_alpha")
        docs = self._call_endpoint(status="extracted", case_id="case_unknown")
        self.assertEqual(docs, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

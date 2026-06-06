"""Offline regression tests for GAP-0252 (KYC-004).

GAP-0252 — ``_readiness_for_case`` in ``app/routers/kyc_cases.py`` only checked
three base requirements (questionnaire submitted, required identity files,
signature completed) and never inspected ``intake_profile``. Users with
``intake_profile=enhanced`` or ``high_risk`` could therefore submit their KYC
case without any verified proof-of-residency document, violating AML/CDD
enhanced due diligence requirements.

The fix adds a fourth ``residency_verified`` check that is only required when
the intake profile is ``enhanced``/``high_risk`` (and the
``KYC_RESIDENCY_GATE_ENABLED`` flag is on). It calls
``KycResidencyStore.get_verified_docs_for_case`` (added as part of GAP-0253) to
determine whether a verified residency document exists for the case.

Fully offline / hermetic:
  * The three status helpers (``_questionnaire_status_for_case``,
    ``_validate_file_requirements``, ``_signature_status_for_case``) are patched
    so no questionnaire/signature/file subsystems are exercised.
  * The residency lookup is tested two ways:
      1. Patching ``get_verified_docs_for_case`` directly (no AWS at all).
      2. Pointing the residency store's exact table handle at an in-memory moto
         table (object.__setattr__ on the frozen store handle) and exercising
         the real ``get_verified_docs_for_case`` -> ``list_documents_for_case``
         path, so no real AWS is touched.
  * Settings ``S`` is frozen; the gate flag is toggled with
    ``object.__setattr__`` and always restored.

Each test fails before the fix and passes after.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from app.core.settings import S
from app.routers import kyc_cases


BASE_CASE = {
    "kyc_case_id": "case_test_0252",
    "user_sub": "user_test",
    "status": "draft",
    "version": 1,
}


def _make_case(intake_profile: str) -> dict:
    return {**BASE_CASE, "intake_profile": intake_profile}


def _patch_base_checks_ready(stack: ExitStack) -> None:
    """Make the three base readiness checks pass, isolated from real subsystems."""
    stack.enter_context(
        patch.object(
            kyc_cases,
            "_questionnaire_status_for_case",
            return_value={
                "submitted": True,
                "questionnaire_id": "q1",
                "response_session_id": "r1",
                "response_pdf_ref": "pdf_ref",
            },
        )
    )
    stack.enter_context(
        patch.object(
            kyc_cases,
            "_validate_file_requirements",
            return_value={
                "ready_for_submit_gate": True,
                "missing_types": [],
                "present_types": ["selfie", "id_front", "id_back"],
            },
        )
    )
    stack.enter_context(
        patch.object(
            kyc_cases,
            "_signature_status_for_case",
            return_value={
                "ready_for_submit_gate": True,
                "packet_id": "pkt_1",
                "final_pdf_ref": "pkt_1:final",
            },
        )
    )


class _GateFlagMixin:
    """Force KYC_RESIDENCY_GATE_ENABLED on for the duration of a test (S is frozen)."""

    def _enable_gate(self):
        original = S.kyc_residency_gate_enabled
        object.__setattr__(S, "kyc_residency_gate_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "kyc_residency_gate_enabled", original))


class TestReadinessResidencyGate(_GateFlagMixin, unittest.TestCase):
    """Hermetic tests that patch get_verified_docs_for_case directly (no AWS)."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        _patch_base_checks_ready(self.stack)
        self._enable_gate()

    def _patch_verified_docs(self, docs):
        from app.services import kyc_residency

        return self.stack.enter_context(
            patch.object(
                kyc_residency.STORE, "get_verified_docs_for_case", return_value=docs
            )
        )

    def test_standard_profile_ignores_residency(self):
        """Standard profile readiness must not add a residency check."""
        # get_verified_docs_for_case must never be called for standard profiles.
        spy = self._patch_verified_docs([])
        result = kyc_cases._readiness_for_case(_make_case("standard"))
        self.assertTrue(result["ready_to_submit"])
        self.assertNotIn("residency_verified", result["checks"])
        self.assertNotIn("residency_verified", result["missing_requirements"])
        spy.assert_not_called()

    def test_enhanced_profile_blocks_submit_without_residency(self):
        """GAP-0252: enhanced profile must block submit when no verified doc exists.

        FAILS BEFORE FIX: ready_to_submit=True (residency never checked) and
        'residency_verified' absent from missing_requirements.
        """
        self._patch_verified_docs([])  # no verified residency docs
        result = kyc_cases._readiness_for_case(_make_case("enhanced"))
        self.assertFalse(result["ready_to_submit"])
        self.assertIn("residency_verified", result["checks"])
        self.assertFalse(result["checks"]["residency_verified"])
        self.assertIn("residency_verified", result["missing_requirements"])

    def test_high_risk_profile_blocks_submit_without_residency(self):
        """high_risk profile is also subject to the residency gate."""
        self._patch_verified_docs([])
        result = kyc_cases._readiness_for_case(_make_case("high_risk"))
        self.assertFalse(result["ready_to_submit"])
        self.assertIn("residency_verified", result["missing_requirements"])

    def test_high_risk_profile_passes_with_verified_residency(self):
        """high_risk profile may submit once a verified residency doc exists."""
        self._patch_verified_docs([{"document_id": "doc1", "status": "verified"}])
        result = kyc_cases._readiness_for_case(_make_case("high_risk"))
        self.assertTrue(result["ready_to_submit"])
        self.assertTrue(result["checks"]["residency_verified"])
        self.assertNotIn("residency_verified", result["missing_requirements"])

    def test_requirements_indices_stable_for_enhanced(self):
        """submit_kyc_case reads requirements[0..2] by position; keep them stable."""
        self._patch_verified_docs([])
        result = kyc_cases._readiness_for_case(_make_case("enhanced"))
        keys = [r["key"] for r in result["requirements"]]
        self.assertEqual(
            keys[:3],
            ["questionnaire_submitted", "required_files", "signature_completed"],
        )
        # residency check is appended as the 4th requirement only when required.
        self.assertEqual(keys[3], "residency_verified")

    def test_gate_disabled_skips_residency_for_enhanced(self):
        """KYC_RESIDENCY_GATE_ENABLED=false → enhanced profiles bypass the gate."""
        object.__setattr__(S, "kyc_residency_gate_enabled", False)
        spy = self._patch_verified_docs([])
        result = kyc_cases._readiness_for_case(_make_case("enhanced"))
        self.assertTrue(result["ready_to_submit"])
        self.assertNotIn("residency_verified", result["checks"])
        spy.assert_not_called()


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestResidencyStoreVerifiedDocs(_GateFlagMixin, unittest.TestCase):
    """Exercise the real get_verified_docs_for_case path against an in-memory table.

    Patches the residency store's exact ``_table`` handle (the store is a frozen
    dataclass instance) via object.__setattr__ so no real AWS is contacted and no
    global interception is relied upon for the call path.
    """

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = ddb.create_table(
            TableName="kyc_residency_documents",
            KeySchema=[{"AttributeName": "document_id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "document_id", "AttributeType": "S"},
                {"AttributeName": "case_id", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "ByCase",
                    "KeySchema": [{"AttributeName": "case_id", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        from app.services import kyc_residency

        self.store = kyc_residency.STORE
        original_table = self.store._table
        object.__setattr__(self.store, "_table", self.table)
        self.addCleanup(lambda: object.__setattr__(self.store, "_table", original_table))

        _patch_base_checks_ready(self.stack)
        self._enable_gate()

    def _seed(self, document_id: str, case_id: str, status: str):
        self.table.put_item(
            Item={
                "document_id": document_id,
                "case_id": case_id,
                "status": status,
                "created_at": 1,
            }
        )

    def test_get_verified_docs_for_case_filters_status(self):
        self._seed("d_pending", "case_x", "pending")
        self._seed("d_verified", "case_x", "verified")
        self._seed("d_other", "case_other", "verified")

        docs = self.store.get_verified_docs_for_case("case_x")
        ids = {d["document_id"] for d in docs}
        self.assertEqual(ids, {"d_verified"})

    def test_enhanced_readiness_blocks_until_verified_doc_seeded(self):
        """End-to-end through _readiness_for_case using the real store path.

        FAILS BEFORE FIX: enhanced case is ready_to_submit with no verified doc.
        """
        # Use an enhanced profile case whose kyc_case_id matches the seeded docs.
        enhanced_case = {**BASE_CASE, "kyc_case_id": "case_resi", "intake_profile": "enhanced"}

        # No verified docs yet -> blocked.
        result = kyc_cases._readiness_for_case(enhanced_case)
        self.assertFalse(result["ready_to_submit"])
        self.assertIn("residency_verified", result["missing_requirements"])

        # Seed a verified doc for this case -> now allowed.
        self._seed("d1", "case_resi", "verified")
        result2 = kyc_cases._readiness_for_case(enhanced_case)
        self.assertTrue(result2["ready_to_submit"])
        self.assertTrue(result2["checks"]["residency_verified"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

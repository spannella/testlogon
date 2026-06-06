"""Offline regression tests for GAP-0281 (KYC-018 §4.8).

GAP-0281 — ``_readiness_for_case`` in ``app/routers/kyc_cases.py`` only gated on
the base requirements (questionnaire submitted, required identity files,
signature completed) plus the GAP-0252 residency gate and the GAP-0279 template
gate. It never inspected address-verification status, so a tier_2 ("standard"/
"medium_risk") or tier_3 ("enhanced"/"high_risk") case could be submitted with
an unverified (or never-verified) address, violating KYC-018 §4.8.

The fix adds an ``address_not_verified`` requirement that is appended ONLY when
``KYC_ADDRESS_VERIFICATION_ENABLED`` is on AND ``tier_for_case`` returns
tier_2/tier_3. It queries ``KycAddressVerificationStore.get_latest(case_id)`` and
treats the address as ready iff ``status`` is ``verified`` or ``partial_match``.
The base ``requirements[0..2]`` positions stay stable (submit_kyc_case reads
them by index), matching the care taken in GAP-0252/0264/0279.

Fully offline / hermetic (no real AWS, no global moto/@mock_aws interception
relied upon for the readiness call path):
  * The three status helpers are patched so no questionnaire/signature/file
    subsystems are exercised.
  * The address lookup is tested two ways:
      1. Patching ``KycAddressVerificationStore.get_latest`` directly (no AWS).
      2. Pointing the address store's exact ``_table`` handle at an in-memory
         moto table (object.__setattr__ on the frozen dataclass instance) and
         exercising the real ``get_latest`` -> ``list_attempts`` path.
  * Settings ``S`` is frozen; the gate flag is toggled with object.__setattr__
    and always restored.

Each behavioural test fails before the fix and passes after.
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
    "kyc_case_id": "case_test_0281",
    "user_sub": "user_test",
    "status": "draft",
    "version": 1,
}


def _make_case(intake_profile: str | None) -> dict:
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


class _AddressGateFlagMixin:
    """Force flags for the duration of a test (S is frozen).

    The residency/template gates are forced OFF so this suite isolates the
    address gate (those gates have their own GAP-0252/0279 regression tests).
    """

    def _enable_address_gate(self):
        original = S.kyc_address_verification_enabled
        object.__setattr__(S, "kyc_address_verification_enabled", True)
        self.addCleanup(
            lambda: object.__setattr__(S, "kyc_address_verification_enabled", original)
        )

    def _disable_other_gates(self):
        orig_res = S.kyc_residency_gate_enabled
        orig_tpl = S.kyc_template_readiness_gate_enabled
        object.__setattr__(S, "kyc_residency_gate_enabled", False)
        object.__setattr__(S, "kyc_template_readiness_gate_enabled", False)
        self.addCleanup(
            lambda: object.__setattr__(S, "kyc_residency_gate_enabled", orig_res)
        )
        self.addCleanup(
            lambda: object.__setattr__(
                S, "kyc_template_readiness_gate_enabled", orig_tpl
            )
        )


class TestReadinessAddressGate(_AddressGateFlagMixin, unittest.TestCase):
    """Hermetic tests that patch get_latest directly (no AWS)."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        _patch_base_checks_ready(self.stack)
        self._disable_other_gates()
        self._enable_address_gate()

    def _patch_latest(self, latest):
        from app.services.kyc_address_verification import KycAddressVerificationStore

        return self.stack.enter_context(
            patch.object(
                KycAddressVerificationStore, "get_latest", return_value=latest
            )
        )

    def test_tier1_ignores_address(self):
        """tier_1 (intake None / individual) must not add an address check."""
        spy = self._patch_latest(None)
        result = kyc_cases._readiness_for_case(_make_case(None))
        self.assertTrue(result["ready_to_submit"])
        self.assertNotIn("address_verified", result["checks"])
        self.assertNotIn("address_not_verified", result["missing_requirements"])
        spy.assert_not_called()

    def test_tier2_blocks_submit_without_verified_address(self):
        """GAP-0281: tier_2 (standard) must block submit when address unverified.

        FAILS BEFORE FIX: ready_to_submit=True (address never checked) and
        'address_not_verified' absent from missing_requirements.
        """
        self._patch_latest({"status": "no_match"})
        result = kyc_cases._readiness_for_case(_make_case("standard"))
        self.assertFalse(result["ready_to_submit"])
        self.assertIn("address_not_verified", result["missing_requirements"])

    def test_tier2_blocks_submit_with_no_verification_record(self):
        """No verification record at all -> blocked for tier_2."""
        self._patch_latest(None)
        result = kyc_cases._readiness_for_case(_make_case("medium_risk"))
        self.assertFalse(result["ready_to_submit"])
        self.assertIn("address_not_verified", result["missing_requirements"])

    def test_tier3_blocks_submit_without_verified_address(self):
        """tier_3 (enhanced/high_risk) is also subject to the address gate."""
        self._patch_latest({"status": "failed"})
        result = kyc_cases._readiness_for_case(_make_case("high_risk"))
        self.assertFalse(result["ready_to_submit"])
        self.assertIn("address_not_verified", result["missing_requirements"])

    def test_tier2_verified_allows_submit(self):
        """tier_2 may submit once address status is 'verified'."""
        self._patch_latest({"status": "verified"})
        result = kyc_cases._readiness_for_case(_make_case("standard"))
        self.assertTrue(result["ready_to_submit"])
        self.assertTrue(result["checks"]["address_verified"])
        self.assertNotIn("address_not_verified", result["missing_requirements"])

    def test_tier3_partial_match_allows_submit(self):
        """'partial_match' counts as verified-enough for the gate."""
        self._patch_latest({"status": "partial_match"})
        result = kyc_cases._readiness_for_case(_make_case("enhanced"))
        self.assertTrue(result["ready_to_submit"])
        self.assertTrue(result["checks"]["address_verified"])
        self.assertNotIn("address_not_verified", result["missing_requirements"])

    def test_requirements_indices_stable_for_tier2(self):
        """submit_kyc_case reads requirements[0..2] by position; keep them stable."""
        self._patch_latest({"status": "no_match"})
        result = kyc_cases._readiness_for_case(_make_case("standard"))
        keys = [r["key"] for r in result["requirements"]]
        self.assertEqual(
            keys[:3],
            ["questionnaire_submitted", "required_files", "signature_completed"],
        )
        # address check is appended after the base 3 (and any optional gates).
        self.assertEqual(keys[3], "address_not_verified")

    def test_gate_disabled_skips_address_for_tier2(self):
        """KYC_ADDRESS_VERIFICATION_ENABLED=false → tier_2 bypasses the gate."""
        object.__setattr__(S, "kyc_address_verification_enabled", False)
        spy = self._patch_latest({"status": "no_match"})
        result = kyc_cases._readiness_for_case(_make_case("standard"))
        self.assertTrue(result["ready_to_submit"])
        self.assertNotIn("address_verified", result["checks"])
        spy.assert_not_called()

    def test_store_error_fails_open(self):
        """An address-store outage must not block submission (fail open)."""
        from app.services.kyc_address_verification import KycAddressVerificationStore

        self.stack.enter_context(
            patch.object(
                KycAddressVerificationStore,
                "get_latest",
                side_effect=RuntimeError("ddb down"),
            )
        )
        result = kyc_cases._readiness_for_case(_make_case("standard"))
        self.assertTrue(result["ready_to_submit"])
        self.assertNotIn("address_not_verified", result["missing_requirements"])


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestAddressStoreLatest(_AddressGateFlagMixin, unittest.TestCase):
    """Exercise the real get_latest path against an in-memory table.

    Patches the address store's exact ``_table`` handle (a frozen dataclass
    instance) via object.__setattr__ so no real AWS is contacted and no global
    interception is relied upon for the call path.
    """

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = ddb.create_table(
            TableName="kyc_cases_test_0281",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        from app.services import kyc_address_verification as av

        self.av = av
        self.store = av.STORE
        original_table = self.store._table
        object.__setattr__(self.store, "_table", self.table)
        self.addCleanup(
            lambda: object.__setattr__(self.store, "_table", original_table)
        )

        _patch_base_checks_ready(self.stack)
        self._disable_other_gates()
        self._enable_address_gate()

    def _seed(self, case_id: str, ts: int, verify_id: str, status: str):
        self.table.put_item(
            Item={
                "pk": self.av._case_pk(case_id),
                "sk": self.av._verify_sk(ts, verify_id),
                "status": status,
            }
        )

    def test_get_latest_returns_newest_attempt(self):
        self._seed("case_x", 1, "v_old", "no_match")
        self._seed("case_x", 2, "v_new", "verified")
        latest = self.store.get_latest("case_x")
        self.assertIsNotNone(latest)
        self.assertEqual(latest["status"], "verified")

    def test_tier2_readiness_blocks_until_verified_attempt_seeded(self):
        """End-to-end through _readiness_for_case using the real store path.

        FAILS BEFORE FIX: tier_2 case is ready_to_submit with no verified address.
        """
        case = {**BASE_CASE, "kyc_case_id": "case_addr", "intake_profile": "standard"}

        # No attempts yet -> blocked.
        result = kyc_cases._readiness_for_case(case)
        self.assertFalse(result["ready_to_submit"])
        self.assertIn("address_not_verified", result["missing_requirements"])

        # Seed a no_match attempt -> still blocked.
        self._seed("case_addr", 1, "v1", "no_match")
        result2 = kyc_cases._readiness_for_case(case)
        self.assertFalse(result2["ready_to_submit"])
        self.assertIn("address_not_verified", result2["missing_requirements"])

        # Seed a newer verified attempt -> now allowed.
        self._seed("case_addr", 2, "v2", "verified")
        result3 = kyc_cases._readiness_for_case(case)
        self.assertTrue(result3["ready_to_submit"])
        self.assertTrue(result3["checks"]["address_verified"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

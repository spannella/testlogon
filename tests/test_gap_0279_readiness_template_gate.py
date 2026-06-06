"""Offline regression tests for GAP-0279 (KYC-017 §3.6).

GAP-0279 — ``_readiness_for_case`` in ``app/routers/kyc_cases.py`` only checked
questionnaire submission, required identity files and the consent signature
packet. It never consulted ``KycDocumentTemplateService.get_required_templates_for_tier``,
so a case missing a tier-required *document template* signature could still
report ``ready_to_submit: True`` — a compliance gap (e.g. an unsigned AML
disclosure template).

The fix adds a ``templates_signed`` check (gated behind
``KYC_TEMPLATE_READINESS_GATE``). For each slug returned by
``get_required_templates_for_tier(target_tier)`` it inspects the case owner's
signature packets (``origin_channel="kyc_document_template"``,
``origin_ref="{case_id}:{slug}"``) and requires a ``completed`` packet. Each
unsigned slug is surfaced as ``"unsigned_templates:<slug>"`` in
``missing_requirements`` (alongside the ``"templates_signed"`` key).

Fully offline / hermetic — NO real AWS, NO global moto/@mock_aws interception:
  * The three base status helpers are patched so no questionnaire/signature/file
    subsystems are exercised.
  * ``app/routers/kyc_cases`` imports the document-template service and the
    packet-listing helper *lazily inside the function*, so we patch the exact
    source symbols (``app.services.kyc_document_templates.SERVICE`` and
    ``app.services.signature_packet_store.list_packets_by_sender``) on their
    defining modules — no table handles or AWS clients are touched.
  * Settings ``S`` is frozen; the gate flag is toggled with
    ``object.__setattr__`` and always restored.

Each "unsigned" test fails before the fix (case reports ready) and passes
after; the gate-off test is unaffected by the fix.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

from app.core.settings import S
from app.routers import kyc_cases
from app.services import kyc_document_templates, signature_packet_store


BASE_CASE = {
    "kyc_case_id": "case_test_0279",
    "user_sub": "user_test_0279",
    "status": "draft",
    "version": 1,
    "target_tier": "tier_2",
}


def _make_case(**overrides) -> dict:
    return {**BASE_CASE, **overrides}


def _required(slugs):
    return [
        {
            "slug": s,
            "template_id": f"kdt_{s}",
            "required_tier": "tier_2",
            "version": 1,
        }
        for s in slugs
    ]


def _completed_packet(case_id, slug):
    return {
        "packet_id": f"sp_{slug}",
        "owner_user_id": BASE_CASE["user_sub"],
        "origin_channel": "kyc_document_template",
        "origin_ref": f"{case_id}:{slug}",
        "status": "completed",
    }


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
    """Force the gate flag to a value for the duration of a test (S is frozen)."""

    def _set_gate(self, value: bool):
        original = S.kyc_template_readiness_gate_enabled
        object.__setattr__(S, "kyc_template_readiness_gate_enabled", value)
        self.addCleanup(
            lambda: object.__setattr__(
                S, "kyc_template_readiness_gate_enabled", original
            )
        )
        # The templates feature must also be enabled for the gate to engage.
        original_enabled = S.kyc_document_templates_enabled
        object.__setattr__(S, "kyc_document_templates_enabled", True)
        self.addCleanup(
            lambda: object.__setattr__(
                S, "kyc_document_templates_enabled", original_enabled
            )
        )


class TestReadinessTemplateGate(_GateFlagMixin, unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        _patch_base_checks_ready(self.stack)
        self._set_gate(True)

    def _patch_service(self, required_slugs):
        """Stub get_required_templates_for_tier on the exact source singleton."""
        return self.stack.enter_context(
            patch.object(
                kyc_document_templates.SERVICE,
                "get_required_templates_for_tier",
                return_value=_required(required_slugs),
            )
        )

    def _patch_packets(self, packets):
        """Stub list_packets_by_sender on the exact source module."""
        return self.stack.enter_context(
            patch.object(
                signature_packet_store,
                "list_packets_by_sender",
                return_value=packets,
            )
        )

    def test_not_ready_when_template_unsigned(self):
        """GAP-0279: an unsigned required template must block submission.

        FAILS BEFORE FIX: ready_to_submit=True (templates never checked) and
        'templates_signed' absent from checks/missing_requirements.
        """
        self._patch_service(["aml_disclosure"])
        self._patch_packets([])  # no completed template packets
        result = kyc_cases._readiness_for_case(_make_case())

        self.assertFalse(result["ready_to_submit"])
        self.assertIn("templates_signed", result["checks"])
        self.assertFalse(result["checks"]["templates_signed"])
        self.assertIn("templates_signed", result["missing_requirements"])
        self.assertIn(
            "unsigned_templates:aml_disclosure", result["missing_requirements"]
        )
        # The slug also appears in the requirement's structured `missing` list.
        templates_req = next(
            r for r in result["requirements"] if r["key"] == "templates_signed"
        )
        self.assertIn("unsigned_templates:aml_disclosure", templates_req["missing"])

    def test_partial_signed_blocks_on_remaining(self):
        """If one of two required templates is signed, the other still blocks."""
        self._patch_service(["aml_disclosure", "pep_attestation"])
        self._patch_packets(
            [_completed_packet(BASE_CASE["kyc_case_id"], "aml_disclosure")]
        )
        result = kyc_cases._readiness_for_case(_make_case())

        self.assertFalse(result["ready_to_submit"])
        self.assertIn(
            "unsigned_templates:pep_attestation", result["missing_requirements"]
        )
        self.assertNotIn(
            "unsigned_templates:aml_disclosure", result["missing_requirements"]
        )

    def test_ready_when_all_templates_signed(self):
        """All required templates signed -> ready_to_submit."""
        self._patch_service(["aml_disclosure"])
        self._patch_packets(
            [_completed_packet(BASE_CASE["kyc_case_id"], "aml_disclosure")]
        )
        result = kyc_cases._readiness_for_case(_make_case())

        self.assertTrue(result["ready_to_submit"])
        self.assertTrue(result["checks"]["templates_signed"])
        self.assertNotIn("templates_signed", result["missing_requirements"])

    def test_ready_when_no_templates_required(self):
        """No required templates -> the gate is a no-op (dev/e2e safety)."""
        self._patch_service([])
        spy = self._patch_packets([])
        result = kyc_cases._readiness_for_case(_make_case(target_tier="tier_1"))

        self.assertTrue(result["ready_to_submit"])
        self.assertTrue(result["checks"]["templates_signed"])
        # No required templates -> we never need to list packets.
        spy.assert_not_called()

    def test_draft_packet_does_not_count_as_signed(self):
        """Only `completed` packets count; a draft packet leaves the slug unsigned."""
        self._patch_service(["aml_disclosure"])
        draft = _completed_packet(BASE_CASE["kyc_case_id"], "aml_disclosure")
        draft["status"] = "draft"
        self._patch_packets([draft])
        result = kyc_cases._readiness_for_case(_make_case())

        self.assertFalse(result["ready_to_submit"])
        self.assertIn(
            "unsigned_templates:aml_disclosure", result["missing_requirements"]
        )

    def test_other_case_packet_does_not_count(self):
        """A completed packet for a *different* case must not satisfy the gate."""
        self._patch_service(["aml_disclosure"])
        self._patch_packets(
            [_completed_packet("some_other_case", "aml_disclosure")]
        )
        result = kyc_cases._readiness_for_case(_make_case())

        self.assertFalse(result["ready_to_submit"])
        self.assertIn(
            "unsigned_templates:aml_disclosure", result["missing_requirements"]
        )

    def test_requirement_indices_stable(self):
        """submit_kyc_case reads requirements[0..2] by position; keep them stable."""
        self._patch_service(["aml_disclosure"])
        self._patch_packets([])
        result = kyc_cases._readiness_for_case(_make_case())
        keys = [r["key"] for r in result["requirements"]]
        self.assertEqual(
            keys[:3],
            ["questionnaire_submitted", "required_files", "signature_completed"],
        )
        # templates check is appended after the base trio.
        self.assertEqual(keys[3], "templates_signed")

    def test_service_error_fails_open(self):
        """A service error must NOT block submission (availability over strictness)."""
        self.stack.enter_context(
            patch.object(
                kyc_document_templates.SERVICE,
                "get_required_templates_for_tier",
                side_effect=RuntimeError("ddb down"),
            )
        )
        result = kyc_cases._readiness_for_case(_make_case())
        self.assertTrue(result["ready_to_submit"])
        self.assertTrue(result["checks"]["templates_signed"])

    def test_gate_disabled_skips_template_check(self):
        """KYC_TEMPLATE_READINESS_GATE=false -> template check is skipped entirely.

        Unaffected by the fix: with the gate off the result is identical to the
        pre-fix behaviour (no templates_signed check, ready_to_submit=True even
        though a required template is unsigned).
        """
        object.__setattr__(S, "kyc_template_readiness_gate_enabled", False)
        spy_service = self._patch_service(["aml_disclosure"])
        spy_packets = self._patch_packets([])
        result = kyc_cases._readiness_for_case(_make_case())

        self.assertTrue(result["ready_to_submit"])
        self.assertNotIn("templates_signed", result["checks"])
        self.assertNotIn("templates_signed", result["missing_requirements"])
        spy_service.assert_not_called()
        spy_packets.assert_not_called()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""Offline regression tests for GAP-0261 (KYC-007).

GAP-0261 — ``app/services/kyc_signature_templates.py`` did not exist. KYC-007
requires a library of five hard-coded KYC consent/declaration templates
(terms_of_service, aml_declaration, pep_declaration, tax_compliance,
data_consent) with auto-populated fields, version tracking, and witness
co-signing.

FAILS BEFORE FIX: the module does not exist, so the import below raises
``ModuleNotFoundError`` and every test errors out.
PASSES AFTER FIX: the service exists and behaves per spec.

Fully offline & hermetic. We do NOT use moto / @mock_aws (that interception
leaks to real AWS). Instead we stub the exact packet-store primitives the
service calls (``create_draft_packet`` / ``upsert_packet_field`` /
``add_packet_signer``) and the profile loader (``get_profile``) on the
service module namespace, then call the service functions directly.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from app.services import kyc_signature_templates as kst
from app.services.kyc_signature_templates import (
    KYC_TEMPLATE_TYPES,
    KycSignatureTemplateService,
)


class _FakePacketStore:
    """In-memory stand-in for the signature packet store primitives."""

    def __init__(self):
        self.packets: dict[str, dict] = {}
        self.fields: dict[str, list[dict]] = {}
        self.signers: dict[str, list[dict]] = {}
        self._n = 0

    def create_draft_packet(self, **kwargs):
        self._n += 1
        packet_id = f"sp_fake_{self._n:04d}"
        item = {"packet_id": packet_id, "status": "draft", **kwargs}
        self.packets[packet_id] = item
        self.fields[packet_id] = []
        self.signers[packet_id] = []
        return item

    def upsert_packet_field(self, *, packet_id, field_id, field_type, **kwargs):
        item = {"packet_id": packet_id, "field_id": field_id,
                "field_type": field_type.value, **kwargs}
        self.fields.setdefault(packet_id, []).append(item)
        return item

    def add_packet_signer(self, *, packet_id, signer_id, **kwargs):
        item = {"packet_id": packet_id, "signer_id": signer_id,
                "status": "pending", **kwargs}
        self.signers.setdefault(packet_id, []).append(item)
        return item


class TestKycSignatureTemplatesGap0261(unittest.TestCase):
    def setUp(self):
        self.store = _FakePacketStore()
        self.profile = {
            "display_name": "Alice Smith",
            "date_of_birth": "1990-01-01",
            "mailing_address": "1 Main St",
            "email": "alice@example.com",
        }
        patchers = [
            patch.object(kst, "create_draft_packet", self.store.create_draft_packet),
            patch.object(kst, "upsert_packet_field", self.store.upsert_packet_field),
            patch.object(kst, "add_packet_signer", self.store.add_packet_signer),
            patch.object(kst, "get_profile", lambda user_sub: dict(self.profile)),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        self.svc = KycSignatureTemplateService()

    # -- template library ---------------------------------------------------

    def test_five_templates_exist(self):
        self.assertEqual(
            set(KYC_TEMPLATE_TYPES),
            {"terms_of_service", "aml_declaration", "pep_declaration",
             "tax_compliance", "data_consent"},
        )

    def test_get_required_templates_standard(self):
        types = {t["template_type"]
                 for t in self.svc.get_required_templates(intake_profile="standard")}
        self.assertEqual(types, {"terms_of_service", "aml_declaration", "data_consent"})

    def test_get_required_templates_high_risk_returns_all(self):
        result = self.svc.get_required_templates(intake_profile="high_risk")
        self.assertEqual(len(result), 5)

    # -- auto-populate ------------------------------------------------------

    def test_auto_populate_fields_maps_profile_values(self):
        tmpl = KYC_TEMPLATE_TYPES["terms_of_service"]
        populated = self.svc.auto_populate_fields(template=tmpl, profile=self.profile)
        self.assertEqual(populated["full_name"], "Alice Smith")
        self.assertEqual(populated["date_of_birth"], "1990-01-01")
        # No auto_populate hint on these → not populated.
        self.assertNotIn("signature", populated)
        self.assertNotIn("date_signed", populated)

    def test_auto_populate_via_user_sub_loads_profile(self):
        tmpl = KYC_TEMPLATE_TYPES["data_consent"]
        populated = self.svc.auto_populate_fields(template=tmpl, user_sub="u_alice")
        self.assertEqual(populated["full_name"], "Alice Smith")
        self.assertEqual(populated["email"], "alice@example.com")

    # -- packet creation ----------------------------------------------------

    def test_create_packets_for_case_creates_right_packets(self):
        results = self.svc.create_packets_for_case(
            case_id="case_1", user_sub="u_alice", intake_profile="high_risk",
        )
        self.assertEqual(len(results), 5)
        # All five template types represented.
        self.assertEqual(
            {r["template_type"] for r in results},
            set(KYC_TEMPLATE_TYPES),
        )
        # One draft packet per template, with fields written.
        self.assertEqual(len(self.store.packets), 5)
        for r in results:
            self.assertIn("packet_id", r)
            self.assertEqual(r["version"], "2026-05-v1")
            self.assertTrue(self.store.fields[r["packet_id"]])

    def test_create_packets_auto_populates_profile_fields(self):
        results = self.svc.create_packets_for_case(
            case_id="case_2", user_sub="u_alice", intake_profile="standard",
        )
        tos = next(r for r in results if r["template_type"] == "terms_of_service")
        self.assertEqual(tos["auto_populated"]["full_name"], "Alice Smith")
        self.assertEqual(tos["auto_populated"]["date_of_birth"], "1990-01-01")

    def test_create_packets_coerces_checkbox_to_text(self):
        # aml_declaration has a checkbox field; the field enum has no checkbox,
        # so it must degrade to TEXT (never raise).
        self.svc.create_packets_for_case(
            case_id="case_3", user_sub="u_alice", intake_profile="standard",
        )
        all_field_types = {
            f["field_type"]
            for fields in self.store.fields.values()
            for f in fields
        }
        self.assertNotIn("checkbox", all_field_types)
        self.assertIn("text", all_field_types)

    # -- version migration --------------------------------------------------

    def test_check_version_migration_detects_stale(self):
        case = {"signature": {"template_packets": [
            {"template_type": "terms_of_service", "version": "OLD-v0", "packet_id": "p1"},
        ]}}
        stale = self.svc.check_version_migration(case=case)
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["template_type"], "terms_of_service")
        self.assertEqual(stale[0]["signed_version"], "OLD-v0")
        self.assertEqual(
            stale[0]["current_version"],
            KYC_TEMPLATE_TYPES["terms_of_service"]["version"],
        )

    def test_check_version_migration_no_stale_when_current(self):
        current = KYC_TEMPLATE_TYPES["terms_of_service"]["version"]
        case = {"signature": {"template_packets": [
            {"template_type": "terms_of_service", "version": current, "packet_id": "p1"},
        ]}}
        self.assertEqual(self.svc.check_version_migration(case=case), [])

    # -- witness co-signing -------------------------------------------------

    def test_add_witness_signer_adds_fields_and_signer(self):
        packet = self.store.create_draft_packet(
            owner_user_id="u_alice", source_path="", source_content_type="application/pdf",
            source_name="x", origin_channel="kyc_template",
        )
        pid = packet["packet_id"]
        signer = self.svc.add_witness_signer(packet_id=pid, witness_sub="admin_bob")
        self.assertEqual(signer["signer_id"], "admin_bob")
        witness_field_ids = {f["field_id"] for f in self.store.fields[pid]}
        self.assertTrue(
            {"witness_name", "witness_role", "witness_signature", "witness_date"}
            <= witness_field_ids
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

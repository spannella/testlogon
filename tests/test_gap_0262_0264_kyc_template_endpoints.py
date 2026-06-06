"""Offline regression tests for GAP-0262 and GAP-0264 (KYC-007).

Both gaps live in ``app/routers/kyc_cases.py``:

GAP-0262 — five template/witness HTTP endpoints were missing. They are now
registered: ``GET /templates``, ``POST /{case_id}/signature-templates/create-packets``,
``GET /{case_id}/signature-templates/status``,
``GET /{case_id}/signature-templates/version-check``, and
``POST /admin/cases/{case_id}/add-witness``.

GAP-0264 — ``case["signature"]`` stored a single ``packet_id``. The template
flow now stores ``signature.template_packets = [{template_type, packet_id,
version}]`` and ``_signature_status_for_case`` gates submission on every
template packet being completed — WITHOUT breaking the legacy single-packet
path.

Fully offline & hermetic. We do NOT use moto / @mock_aws (that interception
leaks to real AWS). Instead we monkeypatch the exact packet-store primitives,
the template-service singleton's collaborators, and the ``STORE`` methods on
the router module namespace, then call the route handler functions directly.
``audit_event`` is stubbed so no real request/DDB is touched.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role
from app.contracts.kyc_cases_contract import KycLinkSignaturePacketRequest, KycAddWitnessRequest
from app.routers import kyc_cases as kc
from app.services import kyc_signature_templates as kst
from app.services.kyc_signature_templates import KYC_TEMPLATE_TYPES


_TOS_VERSION = KYC_TEMPLATE_TYPES["terms_of_service"]["version"]


class _FakePacketStore:
    """In-memory stand-in for the signature packet store primitives."""

    def __init__(self):
        self.packets: dict[str, dict] = {}
        self.fields: dict[str, list[dict]] = {}
        self.signers: dict[str, list[dict]] = {}
        self.artifacts: dict[str, dict] = {}
        self._n = 0

    def create_draft_packet(self, **kwargs):
        self._n += 1
        pid = f"sp_fake_{self._n:04d}"
        self.packets[pid] = {"packet_id": pid, "status": "draft", **kwargs}
        self.fields[pid] = []
        self.signers[pid] = []
        return self.packets[pid]

    def upsert_packet_field(self, *, packet_id, field_id, field_type, **kwargs):
        item = {"packet_id": packet_id, "field_id": field_id, "field_type": field_type.value, **kwargs}
        self.fields.setdefault(packet_id, []).append(item)
        return item

    def add_packet_signer(self, *, packet_id, signer_id, **kwargs):
        item = {"packet_id": packet_id, "signer_id": signer_id, "status": "pending", **kwargs}
        self.signers.setdefault(packet_id, []).append(item)
        return item

    def get_packet(self, packet_id):
        return self.packets.get(packet_id)

    def get_packet_artifact(self, packet_id):
        return self.artifacts.get(packet_id)


class _FakeCaseStore:
    """In-memory stand-in for app.services.kyc_cases.STORE."""

    def __init__(self):
        self.cases: dict[str, dict] = {}

    def get_case(self, case_id):
        c = self.cases.get(case_id)
        return dict(c) if c is not None else None

    def update_case_links(self, *, case_id, owner_sub, expected_version, signature=None, **kwargs):
        case = self.cases.get(case_id)
        if not case:
            return None
        if int(case.get("version") or 0) != int(expected_version):
            raise kc.KycCaseConflictError("kyc_case_update_conflict")
        if signature is not None:
            case["signature"] = dict(signature)
        case["version"] = int(case.get("version") or 0) + 1
        return dict(case)


class _Base(unittest.TestCase):
    def setUp(self):
        self.store = _FakePacketStore()
        self.cases = _FakeCaseStore()
        self.profile = {"display_name": "Alice Smith", "email": "a@x.com"}
        patchers = [
            # service-layer packet primitives used by the template service
            patch.object(kst, "create_draft_packet", self.store.create_draft_packet),
            patch.object(kst, "upsert_packet_field", self.store.upsert_packet_field),
            patch.object(kst, "add_packet_signer", self.store.add_packet_signer),
            patch.object(kst, "get_profile", lambda user_sub: dict(self.profile)),
            # router-layer collaborators
            patch.object(kc, "STORE", self.cases),
            patch.object(kc, "get_packet", self.store.get_packet),
            patch.object(kc, "get_packet_artifact", self.store.get_packet_artifact),
            patch.object(kc, "list_packet_signers", lambda pid: self.store.signers.get(pid, [])),
            patch.object(kc, "audit_event", lambda *a, **k: None),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        self.request = SimpleNamespace(headers={})

    def _user(self, sub="u_alice", role=Role.USER):
        return AuthenticatedUser(sub=sub, role=role)

    def _seed_case(self, case_id="c1", *, user_sub="u_alice", intake_profile="standard", signature=None):
        case = {
            "kyc_case_id": case_id,
            "user_sub": user_sub,
            "status": "draft",
            "intake_profile": intake_profile,
            "version": 1,
            "created_at": 1000,
            "updated_at": 1000,
            "signature": dict(signature or {}),
        }
        self.cases.cases[case_id] = case
        return case


# --------------------------------------------------------------------------
# GAP-0262: endpoint behaviour
# --------------------------------------------------------------------------
class TestTemplateEndpointsGap0262(_Base):
    def test_list_templates_returns_all_five(self):
        out = kc.list_kyc_signature_templates(intake_profile=None, _ctx={}, user=self._user())
        types = {t["template_type"] for t in out["templates"]}
        self.assertEqual(types, set(KYC_TEMPLATE_TYPES))

    def test_list_templates_filtered_standard(self):
        out = kc.list_kyc_signature_templates(intake_profile="standard", _ctx={}, user=self._user())
        types = {t["template_type"] for t in out["templates"]}
        self.assertEqual(types, {"terms_of_service", "aml_declaration", "data_consent"})

    def test_create_packets_stores_template_packets(self):
        self._seed_case("c1", intake_profile="standard")
        body = KycLinkSignaturePacketRequest(expected_version=1, source_path="/x.pdf")
        env = kc.create_signature_packets_from_templates(
            case_id="c1", body=body, request=self.request, _ctx={}, user=self._user()
        )
        tp = env.case.signature.template_packets
        self.assertEqual({p["template_type"] for p in tp}, {"terms_of_service", "aml_declaration", "data_consent"})

    def test_create_packets_idempotent_dedup(self):
        self._seed_case("c1", intake_profile="standard")
        body1 = KycLinkSignaturePacketRequest(expected_version=1, source_path="/x.pdf")
        kc.create_signature_packets_from_templates(case_id="c1", body=body1, request=self.request, _ctx={}, user=self._user())
        body2 = KycLinkSignaturePacketRequest(expected_version=2, source_path="/x.pdf")
        env = kc.create_signature_packets_from_templates(case_id="c1", body=body2, request=self.request, _ctx={}, user=self._user())
        tp = env.case.signature.template_packets
        types = [p["template_type"] for p in tp]
        self.assertEqual(types.count("terms_of_service"), 1)  # not duplicated
        self.assertEqual(len(tp), 3)

    def test_create_packets_forbidden_for_other_user(self):
        self._seed_case("c1", user_sub="other")
        body = KycLinkSignaturePacketRequest(expected_version=1, source_path="/x.pdf")
        with self.assertRaises(HTTPException) as ctx:
            kc.create_signature_packets_from_templates(case_id="c1", body=body, request=self.request, _ctx={}, user=self._user())
        self.assertEqual(ctx.exception.status_code, 403)

    def test_status_lists_required_templates(self):
        self._seed_case("c1", intake_profile="standard")
        body = KycLinkSignaturePacketRequest(expected_version=1, source_path="/x.pdf")
        kc.create_signature_packets_from_templates(case_id="c1", body=body, request=self.request, _ctx={}, user=self._user())
        env = kc.get_signature_templates_status(case_id="c1", request=self.request, _ctx={}, user=self._user())
        self.assertEqual(len(env.templates), 3)
        self.assertTrue(all(t.packet_id for t in env.templates))
        self.assertTrue(all(t.packet_status == "draft" for t in env.templates))

    def test_version_check_detects_stale(self):
        self._seed_case("c1", signature={"template_packets": [
            {"template_type": "terms_of_service", "packet_id": "p1", "version": "OLD"},
        ]})
        out = kc.check_template_version_migration(case_id="c1", request=self.request, _ctx={}, user=self._user())
        self.assertTrue(out["migration_required"])
        self.assertEqual(out["stale_templates"][0]["template_type"], "terms_of_service")

    def test_add_witness_requires_admin_role(self):
        self._seed_case("c1", intake_profile="high_risk")
        body = KycAddWitnessRequest(packet_id="p1")
        with self.assertRaises(HTTPException) as ctx:
            kc.admin_add_witness_to_packet(case_id="c1", body=body, request=self.request, _ctx={}, user=self._user(role=Role.USER))
        self.assertIn(ctx.exception.status_code, {403, 422})

    def test_add_witness_only_high_risk(self):
        self._seed_case("c1", intake_profile="standard")
        body = KycAddWitnessRequest(packet_id="p1")
        with self.assertRaises(HTTPException) as ctx:
            kc.admin_add_witness_to_packet(case_id="c1", body=body, request=self.request, _ctx={}, user=self._user(role=Role.ADMIN))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_add_witness_success_high_risk(self):
        packet = self.store.create_draft_packet(owner_user_id="u_alice")
        self._seed_case("c1", intake_profile="high_risk")
        body = KycAddWitnessRequest(packet_id=packet["packet_id"], witness_sub="admin_bob")
        kc.admin_add_witness_to_packet(case_id="c1", body=body, request=self.request, _ctx={}, user=self._user(role=Role.ADMIN))
        signer_ids = {s["signer_id"] for s in self.store.signers[packet["packet_id"]]}
        self.assertIn("admin_bob", signer_ids)


# --------------------------------------------------------------------------
# GAP-0264: _signature_status_for_case backward compat + template path
# --------------------------------------------------------------------------
class TestSignatureStatusGap0264(_Base):
    def _mk_packet(self, status="completed", final="ready"):
        p = self.store.create_draft_packet(owner_user_id="u")
        p["status"] = status
        if final:
            self.store.artifacts[p["packet_id"]] = {"status": final}
        return p["packet_id"]

    def test_legacy_single_packet_still_gates(self):
        pid = self._mk_packet(status="completed", final="ready")
        case = {"kyc_case_id": "c", "signature": {"packet_id": pid}}
        status = kc._signature_status_for_case(case)
        self.assertTrue(status["ready_for_submit_gate"])
        self.assertEqual(status["packet_id"], pid)
        self.assertEqual(status["template_packets"], [])

    def test_legacy_incomplete_packet_not_ready(self):
        pid = self._mk_packet(status="draft", final=None)
        case = {"kyc_case_id": "c", "signature": {"packet_id": pid}}
        status = kc._signature_status_for_case(case)
        self.assertFalse(status["ready_for_submit_gate"])

    def test_no_packet_not_ready(self):
        status = kc._signature_status_for_case({"kyc_case_id": "c", "signature": {}})
        self.assertFalse(status["ready_for_submit_gate"])
        self.assertEqual(status["template_packets"], [])

    def test_template_path_all_completed_ready(self):
        p1 = self._mk_packet(status="completed", final="ready")
        p2 = self._mk_packet(status="completed", final="ready")
        case = {"kyc_case_id": "c", "signature": {"template_packets": [
            {"template_type": "terms_of_service", "packet_id": p1, "version": _TOS_VERSION},
            {"template_type": "aml_declaration", "packet_id": p2, "version": _TOS_VERSION},
        ]}}
        status = kc._signature_status_for_case(case)
        self.assertTrue(status["ready_for_submit_gate"])
        self.assertTrue(status["completed"])
        self.assertEqual(len(status["template_packets"]), 2)

    def test_template_path_partial_not_ready(self):
        p1 = self._mk_packet(status="completed", final="ready")
        p2 = self._mk_packet(status="draft", final=None)
        case = {"kyc_case_id": "c", "signature": {"template_packets": [
            {"template_type": "terms_of_service", "packet_id": p1, "version": _TOS_VERSION},
            {"template_type": "aml_declaration", "packet_id": p2, "version": _TOS_VERSION},
        ]}}
        status = kc._signature_status_for_case(case)
        self.assertFalse(status["ready_for_submit_gate"])
        self.assertFalse(status["completed"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

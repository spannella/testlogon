"""Offline regression test for GAP-0258 (KYC-006).

The architectural intent is that ``SCREENING_STORE.screen_case()`` fires on
*every* KYC case submission. Before the fix, ``submit_kyc_case`` in
``app/routers/kyc_cases.py`` never called the screening store at all, so every
submission silently bypassed sanctions/PEP screening.

These tests are fully hermetic — NO real AWS, NO moto global interception, NO
FastAPI TestClient. ``submit_kyc_case`` is a synchronous handler, so we call it
directly with a fake ``Request`` and monkeypatch the exact module-level handles
it depends on (``STORE``, ``SCREENING_STORE`` and a few helpers) so that no
DynamoDB / boto3 call is ever made.

Fails-before: ``screen_case`` is never invoked → ``screen_calls`` stays empty.
Passes-after: ``screen_case`` is invoked once with ``trigger='submission'``.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.routers import kyc_cases as kyc_router
from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role
from app.contracts.kyc_cases_contract import KycSubmitCaseRequest

CASE_ID = "kyc_test_case_0258"
USER_SUB = "user_submit_0258"

_DRAFT_CASE = {
    "pk": CASE_ID,
    "sk": "CASE",
    "kyc_case_id": CASE_ID,
    "user_sub": USER_SUB,
    "status": "draft",
    "version": 1,
    "created_at": 1700000000,
    "updated_at": 1700000000,
    "submission": {},
    "files": [
        {"type": "selfie", "path": "/selfie.jpg", "verification_state": "pending"},
        {"type": "id_front", "path": "/idf.jpg", "verification_state": "pending"},
        {"type": "id_back", "path": "/idb.jpg", "verification_state": "pending"},
    ],
}

_SUBMITTED_CASE = {
    **_DRAFT_CASE,
    "status": "submitted",
    "version": 2,
    "updated_at": 1700000100,
    "review": {"ticket_id": "TKT_0258"},
}

_READINESS = {
    "ready_to_submit": True,
    "missing_requirements": [],
    "missing_hints": [],
    "requirements": [
        {"refs": {"questionnaire_id": "q1", "response_session_id": "rs1",
                  "response_pdf_ref": None}},
        {"refs": {"present_types": "selfie,id_front,id_back"}},
        {"refs": {"packet_id": "pk1", "final_pdf_ref": None}},
    ],
}


def _fake_request() -> SimpleNamespace:
    """Minimal stand-in for a FastAPI Request (only what helpers touch)."""
    return SimpleNamespace(
        state=SimpleNamespace(tenant_id="default"),
        headers={},
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(path=f"/v1/kyc/cases/{CASE_ID}/submit"),
        method="POST",
    )


class Gap0258SubmissionScreeningHook(unittest.TestCase):
    def _call_submit(self, screen_impl):
        """Invoke submit_kyc_case directly with all DDB/AWS handles patched out."""
        screen_calls: list[dict] = []

        def _recording_screen(**kw):
            screen_calls.append(kw)
            return screen_impl(**kw)

        user = AuthenticatedUser(sub=USER_SUB, role=Role.USER)

        with patch.object(kyc_router.STORE, "get_case",
                          lambda case_id: dict(_DRAFT_CASE)), \
             patch.object(kyc_router.STORE, "submit_case",
                          lambda **kw: dict(_SUBMITTED_CASE)), \
             patch.object(kyc_router, "_readiness_for_case",
                          lambda case: _READINESS), \
             patch.object(kyc_router, "_ensure_review_ticket",
                          lambda c: c), \
             patch.object(kyc_router, "_audit_state_transition",
                          lambda **kw: None), \
             patch.object(kyc_router, "_emit_kyc_metric",
                          lambda *a, **k: None), \
             patch.object(kyc_router, "audit_event",
                          lambda *a, **k: None), \
             patch.object(kyc_router.SCREENING_STORE, "screen_case",
                          _recording_screen):
            envelope = kyc_router.submit_kyc_case(
                case_id=CASE_ID,
                body=KycSubmitCaseRequest(expected_version=1),
                request=_fake_request(),
                _ctx={"user_sub": USER_SUB},
                user=user,
            )
        return envelope, screen_calls

    def test_screening_fires_on_submission(self):
        """screen_case must be called exactly once with trigger='submission'."""
        envelope, screen_calls = self._call_submit(lambda **kw: [])

        self.assertIsNotNone(envelope)
        self.assertEqual(len(screen_calls), 1,
                         f"expected exactly one screen_case call, got {screen_calls}")
        self.assertEqual(screen_calls[0]["case_id"], CASE_ID)
        self.assertEqual(screen_calls[0]["user_sub"], USER_SUB)
        self.assertEqual(screen_calls[0]["trigger"], "submission")

    def test_screening_failure_does_not_block_submission(self):
        """A screening exception must be swallowed; submission still succeeds."""
        def _boom(**kw):
            raise RuntimeError("screening service down")

        envelope, screen_calls = self._call_submit(_boom)

        # Hook was still attempted...
        self.assertEqual(len(screen_calls), 1)
        # ...and the submission completed (envelope returned, status submitted).
        self.assertIsNotNone(envelope)
        self.assertEqual(envelope.case.status, "submitted")


if __name__ == "__main__":
    unittest.main()

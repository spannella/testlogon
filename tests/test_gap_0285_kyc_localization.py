"""Offline regression tests for GAP-0285 (KYC-020 §4.9).

The KYC questionnaire-start endpoint and the KYC case-status transition alert
paths must run their user-facing content through the localization service:

  * ``start_kyc_questionnaire`` must accept ``?lang=``, resolve the user's
    locale via ``kyc_translation_service`` and call ``localize_questionnaire``
    before returning, persisting the resolved locale on the questionnaire
    sub-object.
  * ``admin_request_more_info`` / ``_admin_decide_case`` (approve/reject) must
    call ``localize_email`` on the recipient's locale when the case status
    transitions.

These are *additive* integrations: before the fix neither
``localize_questionnaire`` nor ``localize_email`` was ever reached from
``kyc_cases.py`` (the service was not even imported), so the spies below record
zero calls → the tests fail. After the fix they are invoked → the tests pass.

Hermetic / offline by construction:
  * No FastAPI ``TestClient`` and no DynamoDB. The router functions are called
    directly with their dependencies (``STORE``, ``QNR_REPO``,
    ``kyc_translation_service``, the audit/metric helpers) patched at the
    ``app.routers.kyc_cases`` module level via ``unittest.mock.patch``.
  * NO ``moto`` / ``@mock_aws``: that interception leaks to real AWS in this
    environment. We never touch boto3 at all — every AWS-backed call is mocked.
  * Settings ``S`` is frozen; we don't mutate it, but where a flag must change
    it is set via ``object.__setattr__`` (none required here).
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role
from app.contracts.kyc_cases_contract import (
    KycAdminDecisionRequest,
    KycAdminRequestInfoRequest,
    KycStartQuestionnaireRequest,
)
import app.routers.kyc_cases as kc


def _fake_request(headers: dict | None = None) -> SimpleNamespace:
    h = dict(headers or {})
    # Case-insensitive header access mirroring Starlette's Headers.get().
    lower = {k.lower(): v for k, v in h.items()}
    return SimpleNamespace(
        headers=SimpleNamespace(get=lambda key, default=None: lower.get(key.lower(), default)),
        client=SimpleNamespace(host="127.0.0.1"),
        state=SimpleNamespace(),
    )


class StartQuestionnaireLocaleTests(unittest.TestCase):
    def _run(self, *, lang):
        user = AuthenticatedUser(sub="u1", role=Role.USER)
        req = _fake_request({"accept-language": "es-ES,es;q=0.9"})
        body = KycStartQuestionnaireRequest(published_slug="kyc_standard_v1")

        with patch.object(kc, "STORE") as store, \
                patch.object(kc, "QNR_REPO") as qnr, \
                patch.object(kc, "_wrap_case", side_effect=lambda item: item), \
                patch.object(kc, "audit_event"), \
                patch.object(kc.kyc_translation_service, "resolve_locale_for_user",
                             return_value="es") as resolve, \
                patch.object(kc.kyc_translation_service, "normalize_locale",
                             return_value="fr") as normalize, \
                patch.object(kc.kyc_translation_service, "localize_questionnaire",
                             return_value=({"title": "loc"}, [])) as localize_q:
            store.get_case.return_value = {
                "kyc_case_id": "c1", "user_sub": "u1", "status": "draft",
                "version": 1, "questionnaire": {},
            }
            qnr.get_published_by_slug.return_value = {
                "questionnaire_id": "q1", "version_id": "v1",
                "slug": "kyc_standard_v1", "title": "Title",
            }
            qnr.put_response_session.return_value = {"response_session_id": "r1"}
            store.update_case_links.return_value = {"kyc_case_id": "c1", "status": "draft"}

            kc.start_kyc_questionnaire(
                case_id="c1", body=body, request=req, lang=lang,
                _ctx={}, user=user,
            )
            return resolve, normalize, localize_q, store

    def test_localize_questionnaire_called_and_locale_stored_from_profile(self):
        """No ?lang: resolve via profile, call localize_questionnaire, store locale."""
        resolve, normalize, localize_q, store = self._run(lang=None)

        resolve.assert_called_once_with("u1", accept_language="es-ES,es;q=0.9")
        normalize.assert_not_called()
        # localize_questionnaire MUST be reached (fails before fix).
        localize_q.assert_called_once()
        self.assertEqual(localize_q.call_args.kwargs["language"], "es")
        # Resolved locale persisted on the questionnaire sub-object.
        q_arg = store.update_case_links.call_args.kwargs["questionnaire"]
        self.assertEqual(q_arg.get("locale"), "es")

    def test_lang_query_param_overrides_profile_locale(self):
        """Explicit ?lang=fr → normalize_locale used, profile resolution skipped."""
        resolve, normalize, localize_q, store = self._run(lang="fr")

        normalize.assert_called_once_with("fr")
        resolve.assert_not_called()
        localize_q.assert_called_once()
        self.assertEqual(localize_q.call_args.kwargs["language"], "fr")
        q_arg = store.update_case_links.call_args.kwargs["questionnaire"]
        self.assertEqual(q_arg.get("locale"), "fr")


class NotificationEmailHelperTests(unittest.TestCase):
    def test_localize_email_called_and_dispatched(self):
        """_send_kyc_notification_email resolves locale, localizes, dispatches."""
        with patch.object(kc.kyc_translation_service, "resolve_locale_for_user",
                          return_value="de"), \
                patch.object(kc.kyc_translation_service, "localize_email",
                             return_value=("Genehmigt", "Antrag genehmigt.")) as le, \
                patch("app.services.alerts.send_alert_email") as send_email, \
                patch("app.services.profile.get_profile",
                      return_value={"email": "u1@test.local"}):
            kc._send_kyc_notification_email(
                user_sub="u1", event="kyc.approved",
                variables={"case_id": "c1", "decision": "approve"},
            )

        le.assert_called_once_with(
            event="kyc.approved", language="de",
            variables={"case_id": "c1", "decision": "approve"},
        )
        send_email.assert_called_once()
        self.assertEqual(send_email.call_args.args[0], ["u1@test.local"])
        self.assertEqual(send_email.call_args.args[1], "Genehmigt")

    def test_failure_is_swallowed(self):
        """Locale resolution failure must NOT raise (admin decision must survive)."""
        with patch.object(kc.kyc_translation_service, "resolve_locale_for_user",
                          side_effect=RuntimeError("DDB timeout")):
            # Must not raise.
            kc._send_kyc_notification_email(
                user_sub="u1", event="kyc.approved", variables={},
            )

    def test_empty_user_sub_is_noop(self):
        with patch.object(kc.kyc_translation_service, "resolve_locale_for_user") as resolve:
            kc._send_kyc_notification_email(user_sub="", event="kyc.approved", variables={})
        resolve.assert_not_called()


class AdminDecisionEmailWiringTests(unittest.TestCase):
    """Approve/reject and needs-more-info paths must invoke the email helper."""

    def _common_patches(self, stack, *, status_before, status_after, store):
        # Silence audit/metric/scope/ticket side effects.
        stack.enter_context(patch.object(kc, "_wrap_case", side_effect=lambda item: item))
        stack.enter_context(patch.object(kc, "audit_event"))
        stack.enter_context(patch.object(kc, "_audit_state_transition"))
        stack.enter_context(patch.object(kc, "_emit_kyc_metric"))
        stack.enter_context(patch.object(kc, "_is_scoped_admin_for_case", return_value=True))
        stack.enter_context(patch.object(kc, "_ensure_decision_ticket_updates"))
        stack.enter_context(patch.object(kc, "_ensure_request_info_ticket_message"))

    def test_approve_invokes_email_helper(self):
        from contextlib import ExitStack

        user = AuthenticatedUser(sub="admin1", role=Role.ADMIN)
        req = _fake_request()
        body = KycAdminDecisionRequest(
            expected_version=1, decision="approve",
            reason_codes=["identity_verified"], note="all good",
        )
        with ExitStack() as stack:
            store = stack.enter_context(patch.object(kc, "STORE"))
            self._common_patches(stack, status_before="under_review", status_after="approved", store=store)
            send = stack.enter_context(patch.object(kc, "_send_kyc_notification_email"))
            store.get_case.return_value = {
                "kyc_case_id": "c1", "user_sub": "u1", "status": "under_review",
                "version": 1, "review": {},
            }
            store.apply_admin_decision.return_value = {
                "kyc_case_id": "c1", "user_sub": "u1", "status": "approved",
                "version": 2, "review": {"risk_tier": "low"},
            }
            kc._admin_decide_case(case_id="c1", body=body, request=req, user=user, decision="approve")

        send.assert_called_once()
        self.assertEqual(send.call_args.kwargs["event"], "kyc.approved")
        self.assertEqual(send.call_args.kwargs["user_sub"], "u1")

    def test_reject_invokes_email_helper_with_rejected_event(self):
        from contextlib import ExitStack

        user = AuthenticatedUser(sub="admin1", role=Role.ADMIN)
        req = _fake_request()
        body = KycAdminDecisionRequest(
            expected_version=1, decision="reject",
            reason_codes=["doc_invalid"], note="rejected reason",
        )
        with ExitStack() as stack:
            store = stack.enter_context(patch.object(kc, "STORE"))
            self._common_patches(stack, status_before="under_review", status_after="rejected", store=store)
            send = stack.enter_context(patch.object(kc, "_send_kyc_notification_email"))
            store.get_case.return_value = {
                "kyc_case_id": "c1", "user_sub": "u1", "status": "under_review",
                "version": 1, "review": {},
            }
            store.apply_admin_decision.return_value = {
                "kyc_case_id": "c1", "user_sub": "u1", "status": "rejected",
                "version": 2, "review": {},
            }
            kc._admin_decide_case(case_id="c1", body=body, request=req, user=user, decision="reject")

        send.assert_called_once()
        self.assertEqual(send.call_args.kwargs["event"], "kyc.rejected")

    def test_request_more_info_invokes_email_helper(self):
        from contextlib import ExitStack

        user = AuthenticatedUser(sub="admin1", role=Role.ADMIN)
        req = _fake_request()
        body = KycAdminRequestInfoRequest(
            expected_version=1, requested_items=["passport"], note="need passport",
        )
        with ExitStack() as stack:
            store = stack.enter_context(patch.object(kc, "STORE"))
            self._common_patches(stack, status_before="under_review", status_after="needs_more_info", store=store)
            send = stack.enter_context(patch.object(kc, "_send_kyc_notification_email"))
            store.get_case.return_value = {
                "kyc_case_id": "c1", "user_sub": "u1", "status": "under_review",
                "version": 1, "review": {},
            }
            store.request_more_info.return_value = {
                "kyc_case_id": "c1", "user_sub": "u1", "status": "needs_more_info",
                "version": 2, "review": {},
            }
            kc.admin_request_more_info(case_id="c1", body=body, request=req, _ctx={}, user=user)

        send.assert_called_once()
        self.assertEqual(send.call_args.kwargs["event"], "kyc.needs_more_info")
        self.assertEqual(send.call_args.kwargs["user_sub"], "u1")


if __name__ == "__main__":
    unittest.main()

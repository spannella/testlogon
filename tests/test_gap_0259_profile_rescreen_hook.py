"""Offline regression test for GAP-0259 (KYC-006).

Changing an identity-sensitive profile field (display_name / first_name /
last_name / birthday) after a KYC case is approved must trigger AML
re-screening of the user's most recently approved case. Non-sensitive field
changes (e.g. ``description``) must NOT trigger re-screening, and a screening
failure must never break the profile update.

Fails before fix: ``ui_patch_profile`` / ``ui_put_profile`` never call the
screening store after a profile update -> the spy records zero re-screens.
Passes after fix: exactly one re-screen fires, with trigger="profile_change".

Fully offline and hermetic:
  * No real AWS, no moto / @mock_aws global interception (which can leak to
    real AWS in this repo). The profile read/write functions are monkeypatched
    in the router module, and the KYC case + screening STOREs are spied on
    their exact handles. No DynamoDB table is created.
  * Async route handlers are invoked directly with ``asyncio.run`` (a fresh
    event loop per call) -- never ``asyncio.get_event_loop()``.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

import app.routers.profile as profile_mod
import app.services.kyc_cases as kyc_cases_mod
import app.services.kyc_sanctions_screening as screening_mod

USER_SUB = "user_gap0259_001"
CASE_ID = "kyc_case_gap0259_approved"

_BASE_PROFILE = {
    "display_name": "Alice Smith",
    "first_name": "Alice",
    "last_name": "Smith",
    "birthday": "1990-01-01",
    "description": "original bio",
}


class _Body:
    """Stand-in for the pydantic request bodies (ProfilePatchReq/ProfilePutReq)."""

    def __init__(self, data: dict):
        self._data = dict(data)

    def model_dump(self, exclude_unset: bool = False):  # noqa: D401
        return dict(self._data)


class _Req:
    """Minimal Request stand-in; audit_event is patched so it is never used."""


def _run(coro):
    return asyncio.run(coro)


class Gap0259ProfileRescreenHookTest(unittest.TestCase):
    def setUp(self) -> None:
        self.rescreen_calls: list[dict] = []
        self.stack = []

        # Profile read returns a fixed baseline; apply_profile_update returns the
        # baseline merged with the requested updates (no DynamoDB touched).
        p_get = patch.object(
            profile_mod, "get_profile", lambda sub: dict(_BASE_PROFILE)
        )
        p_apply = patch.object(
            profile_mod,
            "apply_profile_update",
            lambda sub, updates, replace: {**_BASE_PROFILE, **updates},
        )
        p_audit = patch.object(profile_mod, "audit_event", lambda *a, **kw: None)

        # KYC case store: user has one approved case by default.
        p_cases = patch.object(
            kyc_cases_mod.STORE,
            "list_cases_by_owner",
            lambda *, user_sub, limit=25: [
                {"kyc_case_id": CASE_ID, "status": "approved"}
            ],
        )

        # Spy on the screening store's rescreen_user.
        def _spy_rescreen(**kw):
            self.rescreen_calls.append(kw)
            return []

        p_screen = patch.object(
            screening_mod.STORE, "rescreen_user", _spy_rescreen
        )

        for p in (p_get, p_apply, p_audit, p_cases, p_screen):
            p.start()
            self.stack.append(p)

    def tearDown(self) -> None:
        for p in reversed(self.stack):
            p.stop()

    # -- sensitive field change fires re-screening ------------------------
    def test_rescreen_fires_on_sensitive_field_change(self):
        result = _run(
            profile_mod.ui_patch_profile(
                _Req(),
                _Body({"display_name": "Alice Jones"}),
                ctx={"user_sub": USER_SUB},
            )
        )
        self.assertEqual(result["profile"]["display_name"], "Alice Jones")
        self.assertEqual(
            len(self.rescreen_calls),
            1,
            f"expected exactly one re-screen, got {self.rescreen_calls}",
        )
        call = self.rescreen_calls[0]
        self.assertEqual(call["trigger"], screening_mod.TRIGGER_PROFILE_CHANGE)
        self.assertEqual(call["user_sub"], USER_SUB)
        self.assertEqual(call["case_id"], CASE_ID)

    # -- non-sensitive field change does NOT fire re-screening ------------
    def test_no_rescreen_on_non_sensitive_field_change(self):
        _run(
            profile_mod.ui_patch_profile(
                _Req(),
                _Body({"description": "brand new bio"}),
                ctx={"user_sub": USER_SUB},
            )
        )
        self.assertEqual(self.rescreen_calls, [])

    # -- no approved case => no re-screen --------------------------------
    def test_no_rescreen_without_approved_case(self):
        with patch.object(
            kyc_cases_mod.STORE,
            "list_cases_by_owner",
            lambda *, user_sub, limit=25: [
                {"kyc_case_id": "draft_case", "status": "draft"}
            ],
        ):
            _run(
                profile_mod.ui_patch_profile(
                    _Req(),
                    _Body({"display_name": "Alice Jones"}),
                    ctx={"user_sub": USER_SUB},
                )
            )
        self.assertEqual(self.rescreen_calls, [])

    # -- PUT (full replace) also fires ------------------------------------
    def test_rescreen_fires_on_put_replace(self):
        _run(
            profile_mod.ui_put_profile(
                _Req(),
                _Body({**_BASE_PROFILE, "last_name": "Renamed"}),
                ctx={"user_sub": USER_SUB},
            )
        )
        self.assertEqual(len(self.rescreen_calls), 1)
        self.assertEqual(
            self.rescreen_calls[0]["trigger"],
            screening_mod.TRIGGER_PROFILE_CHANGE,
        )

    # -- screening failure never breaks the profile update ----------------
    def test_screening_failure_is_swallowed(self):
        def _boom(**kw):
            raise RuntimeError("screening backend down")

        with patch.object(screening_mod.STORE, "rescreen_user", _boom):
            result = _run(
                profile_mod.ui_patch_profile(
                    _Req(),
                    _Body({"display_name": "Alice Danger"}),
                    ctx={"user_sub": USER_SUB},
                )
            )
        # Profile update still succeeds with the new value.
        self.assertEqual(result["profile"]["display_name"], "Alice Danger")


if __name__ == "__main__":
    unittest.main()

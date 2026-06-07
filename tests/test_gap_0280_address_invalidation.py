"""GAP-0280 (KYC-018 §4.7): a mailing-address change in ``apply_profile_update``
must invalidate the address verification of the user's active KYC cases.

Without the fix, a user who changes their address after residency verification
keeps a stale ``verified`` status and can pass tier-2 readiness with an outdated
address. The fix calls ``KycAddressVerificationStore.invalidate_verification``
for each non-terminal KYC case (``draft``/``submitted``/``under_review``/
``needs_more_info``/``approved``) when any ``mailing_address`` sub-field changes.

Hermetic / fully offline: NO real AWS and NO global ``moto``/``@mock_aws``
interception (which leaks to real AWS in this environment). The profile service's
DDB-backed ``get_profile``/``save_profile`` are patched out, and the two KYC
stores — which ``apply_profile_update`` lazily imports as
``app.services.kyc_cases.STORE`` and
``app.services.kyc_address_verification.STORE`` — are replaced with in-memory
spies. The functions under test are invoked directly.

Fails BEFORE the fix (no invalidate_verification call); passes AFTER.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch


def _patch_stores(stack: ExitStack, *, old_address, cases=None, case_svc=None, addr_svc=None):
    """Patch profile DDB I/O + the lazily-imported KYC stores.

    Returns ``(case_svc, addr_svc)`` MagicMock spies.
    """
    import app.services.profile as profile_svc

    case_svc = case_svc or MagicMock()
    if cases is not None:
        case_svc.list_cases_by_owner.return_value = cases
    addr_svc = addr_svc or MagicMock()

    stack.enter_context(
        patch.object(
            profile_svc,
            "get_profile",
            return_value={"display_name": "Alice", "mailing_address": old_address},
        )
    )
    stack.enter_context(patch.object(profile_svc, "save_profile", return_value=None))
    # apply_profile_update lazily imports STORE from each module by attribute, so
    # patching the module attribute is what the call site actually resolves.
    stack.enter_context(patch("app.services.kyc_cases.STORE", case_svc))
    stack.enter_context(patch("app.services.kyc_address_verification.STORE", addr_svc))
    return case_svc, addr_svc


class TestAddressInvalidationGap0280(unittest.TestCase):
    def test_address_change_invalidates_active_case(self):
        """Changing mailing_address invalidates an active (approved) case.

        FAILS BEFORE FIX: invalidate_verification is never called.
        """
        import app.services.profile as profile_svc

        with ExitStack() as stack:
            _, addr_svc = _patch_stores(
                stack,
                old_address={"city": "Austin", "country": "US"},
                cases=[{"kyc_case_id": "kyc_001", "status": "approved"}],
            )
            profile_svc.apply_profile_update(
                "user_001",
                {"mailing_address": {"city": "London", "country": "GB"}},
                replace=False,
            )

        addr_svc.invalidate_verification.assert_called_once_with(
            case_id="kyc_001", reason="address_changed"
        )

    def test_no_invalidation_when_address_unchanged(self):
        """A non-address field change must NOT trigger invalidation."""
        import app.services.profile as profile_svc

        addr = {"city": "Austin", "country": "US"}
        with ExitStack() as stack:
            _, addr_svc = _patch_stores(
                stack,
                old_address=addr,
                cases=[{"kyc_case_id": "kyc_001", "status": "approved"}],
            )
            profile_svc.apply_profile_update(
                "user_001",
                {"display_name": "Alice Updated"},
                replace=False,
            )

        addr_svc.invalidate_verification.assert_not_called()

    def test_sub_field_only_change_triggers_invalidation(self):
        """Changing only one address sub-key (postal_code) still invalidates."""
        import app.services.profile as profile_svc

        with ExitStack() as stack:
            _, addr_svc = _patch_stores(
                stack,
                old_address={"line1": "1 Main St", "city": "Austin", "country": "US", "postal_code": "78701"},
                cases=[{"kyc_case_id": "kyc_xyz", "status": "under_review"}],
            )
            profile_svc.apply_profile_update(
                "user_sub_x",
                {"mailing_address": {"line1": "1 Main St", "city": "Austin", "country": "US", "postal_code": "78702"}},
                replace=False,
            )

        addr_svc.invalidate_verification.assert_called_once_with(
            case_id="kyc_xyz", reason="address_changed"
        )

    def test_invalidation_skips_terminal_cases(self):
        """Cases in terminal statuses (rejected/expired) are not invalidated."""
        import app.services.profile as profile_svc

        with ExitStack() as stack:
            _, addr_svc = _patch_stores(
                stack,
                old_address={"city": "Austin", "country": "US"},
                cases=[
                    {"kyc_case_id": "kyc_rej", "status": "rejected"},
                    {"kyc_case_id": "kyc_exp", "status": "expired"},
                ],
            )
            profile_svc.apply_profile_update(
                "user_002",
                {"mailing_address": {"city": "Berlin", "country": "DE"}},
                replace=False,
            )

        addr_svc.invalidate_verification.assert_not_called()

    def test_only_active_cases_among_mixed(self):
        """Only non-terminal cases are invalidated when statuses are mixed."""
        import app.services.profile as profile_svc

        with ExitStack() as stack:
            _, addr_svc = _patch_stores(
                stack,
                old_address={"city": "Austin", "country": "US"},
                cases=[
                    {"kyc_case_id": "kyc_a", "status": "submitted"},
                    {"kyc_case_id": "kyc_b", "status": "rejected"},
                    {"kyc_case_id": "kyc_c", "status": "needs_more_info"},
                ],
            )
            profile_svc.apply_profile_update(
                "user_003",
                {"mailing_address": {"city": "London", "country": "GB"}},
                replace=False,
            )

        called = {
            c.kwargs["case_id"]
            for c in addr_svc.invalidate_verification.call_args_list
        }
        self.assertEqual(called, {"kyc_a", "kyc_c"})

    def test_invalidation_error_does_not_block_profile_save(self):
        """A raising invalidate_verification must not propagate; update succeeds."""
        import app.services.profile as profile_svc

        saved: dict = {}

        def fake_save(user_sub, profile, audit_entries):
            saved["profile"] = profile

        case_svc = MagicMock()
        case_svc.list_cases_by_owner.return_value = [
            {"kyc_case_id": "kyc_001", "status": "submitted"},
        ]
        addr_svc = MagicMock()
        addr_svc.invalidate_verification.side_effect = RuntimeError("DDB unreachable")

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    profile_svc,
                    "get_profile",
                    return_value={"mailing_address": {"city": "Austin", "country": "US"}},
                )
            )
            stack.enter_context(patch.object(profile_svc, "save_profile", side_effect=fake_save))
            stack.enter_context(patch("app.services.kyc_cases.STORE", case_svc))
            stack.enter_context(patch("app.services.kyc_address_verification.STORE", addr_svc))

            result = profile_svc.apply_profile_update(
                "user_004",
                {"mailing_address": {"city": "Berlin", "country": "DE"}},
                replace=False,
            )

        self.assertIsNotNone(result, "profile update must succeed even if invalidation raises")
        self.assertIn("profile", saved, "save_profile must have been called")
        addr_svc.invalidate_verification.assert_called_once()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

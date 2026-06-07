"""Offline regression test for GAP-0270 (KYC-010).

Bug: ``app/services/kyc_id_scanner.py`` ``_load_crosscheck_profile`` built the
cross-check dict from ``profile.get("first_name")`` / ``profile.get("last_name")``
only. A user who registered with only a ``display_name`` (e.g. the registration
``full_name`` mapped to ``display_name`` without decomposing into structured
first/last name fields) produced ``first_name="" / last_name=""``. Then
``cross_reference_profile`` assembled ``profile_name=""``, skipped the name
comparison block (it requires both extracted and profile names to be non-empty),
and returned ``match_score=0``. A score < 50 forces ``STATUS_FLAGGED`` in
``_derive_status`` — so every display-name-only user's ID scan was falsely
flagged for manual review.

Fix: ``_load_crosscheck_profile`` now splits ``display_name`` on the first
whitespace into first/last when the structured fields are absent.

Isolation: a real in-memory DynamoDB table is created with moto and the exact
table handle used by ``get_profile`` (``app.core.tables.T.profile``) is patched
to point at it via ``object.__setattr__`` (``T`` is a frozen dataclass). No
reliance on a global, process-wide moto patch leaking to real AWS; the functions
are called directly. Fresh event loop is not needed (sync code path).
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_profile_table(ddb):
    """Mirror the ``profiles`` table key schema (PK ``user_sub``)."""
    return ddb.create_table(
        TableName="profiles_test",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestKycDisplayNameFallbackGap0270(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # mock_aws gives us an in-memory DDB; the *real* isolation is the
        # patched-handle below — get_profile only ever touches T.profile.
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_profile_table(ddb)

        from app.core.tables import T

        self.T = T
        self._orig_profile = T.profile
        # T is a frozen dataclass -> object.__setattr__ to swap the exact handle.
        object.__setattr__(T, "profile", self.table)
        self.addCleanup(lambda: object.__setattr__(self.T, "profile", self._orig_profile))

        from app.services.kyc_id_scanner import KycIdScannerStore, cross_reference_profile

        self.store = KycIdScannerStore()
        self.cross_reference_profile = cross_reference_profile

    def _seed_profile(self, user_sub: str, profile: dict):
        self.table.put_item(Item={"user_sub": user_sub, "profile": profile})

    def test_display_name_fallback_prevents_false_flag(self):
        """display_name-only user must NOT score 0 when the document name matches.

        FAILS BEFORE FIX: first_name/last_name stay "" -> profile_name "" ->
        name comparison skipped -> match_score == 0 (false flag).
        PASSES AFTER FIX: display_name "Anna Eriksson" splits into Anna/Eriksson;
        the surname matches the MRZ surname -> match_score > 0.
        """
        user_sub = "u_display_only"
        self._seed_profile(user_sub, {"display_name": "Anna Eriksson"})

        profile = self.store._load_crosscheck_profile(user_sub, None)

        self.assertEqual(
            profile["first_name"],
            "Anna",
            f"expected first_name derived from display_name, got {profile['first_name']!r}",
        )
        self.assertEqual(
            profile["last_name"],
            "Eriksson",
            f"expected last_name derived from display_name, got {profile['last_name']!r}",
        )

        extraction = {
            "given_names": "ANNA MARIA",
            "surname": "ERIKSSON",
            "date_of_birth": "1974-08-12",
            "nationality": "UTO",
        }
        result = self.cross_reference_profile(extraction, profile)

        self.assertGreater(
            result["match_score"],
            0,
            f"expected non-zero match_score, got {result['match_score']}; "
            "display_name fallback did not propagate into cross_reference_profile",
        )
        self.assertGreaterEqual(result["total_fields_checked"], 1)

    def test_genuine_name_mismatch_still_flagged(self):
        """A real name mismatch must still score < 50 (fallback cannot mask it)."""
        user_sub = "u_mismatch"
        self._seed_profile(user_sub, {"display_name": "Jane Smith"})

        extraction = {
            "given_names": "MARIA",
            "surname": "JOHNSON",
            "date_of_birth": None,
            "nationality": None,
        }
        profile = self.store._load_crosscheck_profile(user_sub, None)
        result = self.cross_reference_profile(extraction, profile)

        self.assertLess(
            result["match_score"],
            50,
            f"name mismatch should score < 50, got {result['match_score']}",
        )

    def test_structured_names_unaffected_by_fallback(self):
        """Users with structured first/last names bypass the fallback entirely."""
        user_sub = "u_structured"
        self._seed_profile(
            user_sub,
            {"display_name": "Should Not Be Used", "first_name": "Anna", "last_name": "Eriksson"},
        )

        profile = self.store._load_crosscheck_profile(user_sub, None)

        self.assertEqual(profile["first_name"], "Anna")
        self.assertEqual(profile["last_name"], "Eriksson")

    def test_single_word_display_name(self):
        """A single-word display_name becomes first_name with empty last_name."""
        user_sub = "u_single"
        self._seed_profile(user_sub, {"display_name": "Cher"})

        profile = self.store._load_crosscheck_profile(user_sub, None)

        self.assertEqual(profile["first_name"], "Cher")
        self.assertEqual(profile["last_name"], "")

        extraction = {"given_names": "", "surname": "CHER", "date_of_birth": None, "nationality": None}
        result = self.cross_reference_profile(extraction, profile)
        # extracted_name "CHER" vs profile_name "CHER" -> exact match.
        self.assertEqual(result["match_score"], 100)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

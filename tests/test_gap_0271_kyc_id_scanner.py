"""Offline regression test for GAP-0271 (KYC-010).

GAP-0271 — the default mock MRZ in ``app/services/kyc_id_scanner.py`` carried the
expiry field ``120415`` (YYMMDD = 2012-04-15). At runtime the century roll-forward
in ``_mrz_expiry_to_iso`` masked the staleness (mapping 2012 -> 2112), but the raw
value read as already-expired: a naive edit of the constant or a clock-stubbed test
could re-introduce ``status="rejected"`` for every default-MRZ scan. The fix replaces
the expiry with an unambiguous far-future date (``361231`` = 2036-12-31) and recomputes
the dependent ICAO 9303 check digits (expiry check + composite for TD3; expiry check +
composite for TD1).

Fully offline: these assertions exercise only the in-memory ``_MOCK_MRZ`` constant and
pure parsing / expiry helpers. There is NO DynamoDB, no moto, and no AWS interception —
the functions are called directly. ``now`` is injected so expiry status is deterministic
and the test does not depend on the wall clock.

Fails-before / passes-after:
  * Before the fix the raw expiry was ``120415``; with ``now`` set a few years in the
    future the once-only century roll-forward leaves the date in the past and
    ``check_document_expiry`` returns ``"expired"`` -> the assertion below fails.
  * After the fix the explicit ``2036-12-31`` expiry remains ``"valid"`` for the next
    decade regardless of the (single) century roll, so the assertion passes.
"""
from __future__ import annotations

import datetime
import unittest

from app.services.kyc_id_scanner import (
    DOCUMENT_REQUIREMENTS,
    _MOCK_MRZ,
    check_document_expiry,
    parse_mrz_lines,
)

_MRZ_DOC_TYPES = ["passport", "national_id_card", "residence_permit"]


class TestDefaultMockMrzNotExpired(unittest.TestCase):
    """The default mock MRZ must parse cleanly and never read as expired/expiring."""

    def test_default_mrz_check_digits_are_correct(self) -> None:
        for doc_type in _MRZ_DOC_TYPES:
            with self.subTest(doc_type=doc_type):
                lines = _MOCK_MRZ[doc_type]["lines"]
                fmt = DOCUMENT_REQUIREMENTS[doc_type]["mrz_format"]
                parsed = parse_mrz_lines(lines, fmt)
                self.assertIs(
                    parsed.get("valid"),
                    True,
                    f"{doc_type} MRZ check digits invalid: {parsed.get('checksums')}",
                )
                for field_name, ok in (parsed.get("checksums") or {}).items():
                    self.assertTrue(ok, f"{doc_type} MRZ checksum {field_name!r} invalid")

    def test_default_mrz_is_valid_for_next_decade(self) -> None:
        # Check expiry status from "today" and from several future years. The
        # century roll-forward is single-step, so a genuinely far-future expiry
        # must stay valid across all of these reference dates.
        base = datetime.date(2026, 1, 1)
        reference_dates = [base] + [base.replace(year=base.year + n) for n in (1, 3, 5, 9)]
        for doc_type in _MRZ_DOC_TYPES:
            lines = _MOCK_MRZ[doc_type]["lines"]
            fmt = DOCUMENT_REQUIREMENTS[doc_type]["mrz_format"]
            parsed = parse_mrz_lines(lines, fmt)
            self.assertEqual(
                parsed.get("expiry_date"),
                "2036-12-31",
                f"{doc_type} expiry parsed to {parsed.get('expiry_date')!r}, "
                f"expected 2036-12-31 (GAP-0271)",
            )
            for ref in reference_dates:
                with self.subTest(doc_type=doc_type, now=ref):
                    expiry_check = check_document_expiry(parsed["expiry_date"], now=ref)
                    self.assertEqual(
                        expiry_check["status"],
                        "valid",
                        f"{doc_type} expiry status is {expiry_check['status']!r} "
                        f"(expiry_date={parsed['expiry_date']}) when now={ref}; "
                        f"expected 'valid' (GAP-0271).",
                    )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

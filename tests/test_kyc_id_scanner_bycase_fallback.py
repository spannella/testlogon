"""Regression test for GAP-0024.

``KycIdScannerStore.list_scans_for_case`` previously fell back to an unfiltered
``self._table.scan()`` whenever the ``ByCase`` GSI query raised. That loaded
*every* user's KYC scan records into memory and returned the ones matching the
requested case (cross-user PII exposure / GDPR Art. 9 breach).

The fix fails closed: on any GSI query error it logs and returns ``[]`` and
never calls ``scan()``.

These tests are fully offline -- they inject a ``MagicMock`` table, so no real
AWS / DynamoDB / moto is required.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from app.services.kyc_id_scanner import KycIdScannerStore


@pytest.fixture
def scanner_with_failing_gsi() -> KycIdScannerStore:
    store = KycIdScannerStore()
    mock_table = MagicMock()
    # The ByCase GSI query fails (throttle / index-not-found / validation / etc.)
    mock_table.query.side_effect = Exception("GSI ByCase unavailable")
    # A bare scan() would expose other users' scan records.
    mock_table.scan.return_value = {
        "Items": [
            {"scan_id": "s1", "case_id": "other_case", "user_sub": "victim-user"},
            {"scan_id": "s2", "case_id": "target_case", "user_sub": "innocent-user"},
            {"scan_id": "s3", "case_id": "target_case", "user_sub": "innocent-user-2"},
        ]
    }
    store._table = mock_table
    return store


def test_list_scans_for_case_returns_empty_on_gsi_failure(scanner_with_failing_gsi):
    """BEFORE fix: returns filtered scan dump + calls scan(). AFTER fix: []."""
    result = scanner_with_failing_gsi.list_scans_for_case("target_case")

    assert result == [], f"Expected safe empty list, got: {result}"
    # The critical security assertion: no full-table scan fallback.
    scanner_with_failing_gsi._table.scan.assert_not_called()


def test_list_scans_for_case_does_not_leak_other_case_records(scanner_with_failing_gsi):
    """No record from any case (target or otherwise) is returned on GSI failure."""
    result = scanner_with_failing_gsi.list_scans_for_case("target_case")

    returned_scan_ids = {r.get("scan_id") for r in result}
    assert returned_scan_ids == set()
    # Explicitly: the other user's record must never surface.
    assert not any(r.get("user_sub") == "victim-user" for r in result)


def test_list_scans_for_case_logs_exception_on_gsi_failure(
    scanner_with_failing_gsi, caplog
):
    with caplog.at_level(logging.ERROR):
        scanner_with_failing_gsi.list_scans_for_case("target_case")
    assert any("ByCase GSI query failed" in r.message for r in caplog.records)


def test_list_scans_for_case_normal_path_unchanged():
    """Healthy GSI path still returns the queried scan records unchanged."""
    store = KycIdScannerStore()
    mock_table = MagicMock()
    mock_table.query.return_value = {
        "Items": [
            {"scan_id": "scan-abc", "case_id": "case-xyz", "user_sub": "user-normal"},
        ]
    }
    store._table = mock_table

    result = store.list_scans_for_case("case-xyz")

    assert any(r["scan_id"] == "scan-abc" for r in result)
    mock_table.query.assert_called_once()
    mock_table.scan.assert_not_called()

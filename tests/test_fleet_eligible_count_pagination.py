"""GAP-0083 regression: fleet eligible-count helpers must paginate LastEvaluatedKey.

Offline tests (no real AWS): the DynamoDB scan is mocked to return multiple pages,
verifying that every page is counted rather than just the first.

Fails before fix:
  - test_pagination_accumulates_count_across_pages (result == 3, not 12)
  - test_count_by_type_pagination (only first page counted)
Passes after fix: all tests pass.
"""
from unittest.mock import MagicMock, patch

from app.services import agent_fleet as svc


def _scan_page(count, last_key=None):
    resp = {"Count": count, "ScannedCount": count + 10}
    if last_key:
        resp["LastEvaluatedKey"] = last_key
    return resp


def test_pagination_accumulates_count_across_pages():
    mock_T = MagicMock()
    mock_T.tickets.scan.side_effect = [
        _scan_page(count=3, last_key={"pk": "TOKEN#page2"}),
        _scan_page(count=7, last_key={"pk": "TOKEN#page3"}),
        _scan_page(count=2, last_key=None),
    ]
    with patch.object(svc, "T", mock_T):
        result = svc._count_eligible_tickets("u1")
    assert result == 12  # 3 + 7 + 2
    assert mock_T.tickets.scan.call_count == 3


def test_pagination_passes_exclusive_start_key():
    mock_T = MagicMock()
    mock_T.tickets.scan.side_effect = [
        _scan_page(count=1, last_key={"pk": "NEXT#1"}),
        _scan_page(count=2, last_key=None),
    ]
    with patch.object(svc, "T", mock_T):
        svc._count_eligible_tickets("u1")
    calls = mock_T.tickets.scan.call_args_list
    assert len(calls) == 2
    assert calls[1][1].get("ExclusiveStartKey") == {"pk": "NEXT#1"}


def test_single_page_no_last_key():
    mock_T = MagicMock()
    mock_T.tickets.scan.return_value = _scan_page(count=5, last_key=None)
    with patch.object(svc, "T", mock_T):
        result = svc._count_eligible_tickets("u1")
    assert result == 5
    assert mock_T.tickets.scan.call_count == 1


def test_exception_returns_zero():
    mock_T = MagicMock()
    mock_T.tickets.scan.side_effect = Exception("DDB unavailable")
    with patch.object(svc, "T", mock_T):
        result = svc._count_eligible_tickets("u1")
    assert result == 0


def test_count_by_type_pagination():
    mock_T = MagicMock()
    mock_T.tickets.scan.side_effect = [
        {
            "Items": [{"type": "bug"}, {"type": "feature"}, {"type": "bug"}],
            "LastEvaluatedKey": {"pk": "NEXT#1"},
        },
        {"Items": [{"type": "bug"}, {"type": "task"}]},
    ]
    with patch.object(svc, "T", mock_T):
        result = svc._count_eligible_by_type("u1")
    assert result == {"bug": 3, "feature": 1, "task": 1}
    assert mock_T.tickets.scan.call_count == 2


def test_count_by_type_exception_returns_empty():
    mock_T = MagicMock()
    mock_T.tickets.scan.side_effect = Exception("DDB unavailable")
    with patch.object(svc, "T", mock_T):
        result = svc._count_eligible_by_type("u1")
    assert result == {}

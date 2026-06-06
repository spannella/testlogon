"""GAP-0097 regression: backlog scan must follow LastEvaluatedKey / next_cursor.

`_scan_backlog_tickets` previously issued a single page (Limit<=100) query per
status bucket and ignored the store's ``next_cursor``. Status partitions with
more than one page silently dropped every ticket beyond the first page.

These tests drive `_scan_backlog_tickets` with a mock store whose
``list_tickets`` / ``list_space_tickets`` return paginated results (a non-None
``next_cursor`` until the final page). They are fully offline: the store is
patched, so no DynamoDB / AWS access occurs.

Fails before fix: only the first page (100 items) is returned.
Passes after fix: all pages are processed.
"""

from unittest.mock import patch

from app.services import agent_project as svc


def _make_ticket(i):
    return {"ticket_id": f"ticket_{i:04d}", "status": "open", "title": f"Ticket {i}"}


def _paginated_store(all_tickets, *, page_size=100):
    """Return a fake `list_tickets` that serves `all_tickets` in pages.

    The cursor is the index of the next item to serve; `next_cursor` is None on
    the final page. This mirrors the real store's `{"tickets", "next_cursor"}`
    contract.
    """

    def fake_list_tickets(*, status=None, limit=100, cursor=None, **kwargs):
        start = int(cursor) if cursor else 0
        end = start + page_size
        page = all_tickets[start:end]
        next_cursor = str(end) if end < len(all_tickets) else None
        return {"tickets": page, "next_cursor": next_cursor}

    return fake_list_tickets


def test_scan_follows_cursor_across_pages():
    """150 open tickets span two pages; all 150 must be returned."""
    all_150 = [_make_ticket(i) for i in range(150)]
    fake = _paginated_store(all_150)

    with patch.object(svc.tickets_svc.STORE, "list_tickets", side_effect=fake):
        results = svc._scan_backlog_tickets(
            space_id=None, statuses=["open"], limit=150
        )

    assert len(results) == 150, f"Expected 150 (all pages), got {len(results)}"
    ids = {r["ticket_id"] for r in results}
    assert "ticket_0149" in ids, "Last-page ticket missing — cursor loop not followed"


def test_scan_space_follows_cursor_across_pages():
    """Space-scoped path also exhausts pages."""
    all_250 = [_make_ticket(i) for i in range(250)]

    def fake_list_space(*, space_id, status=None, limit=100, cursor=None, **kwargs):
        return _paginated_store(all_250)(status=status, limit=limit, cursor=cursor)

    with patch.object(
        svc.tickets_svc.STORE, "list_space_tickets", side_effect=fake_list_space
    ):
        results = svc._scan_backlog_tickets(
            space_id="space_1", statuses=["open"], limit=250
        )

    assert len(results) == 250, f"Expected 250 (all pages), got {len(results)}"


def test_scan_respects_limit_cap():
    """limit must cap the result even when more pages are available."""
    all_200 = [_make_ticket(i) for i in range(200)]
    fake = _paginated_store(all_200)

    with patch.object(svc.tickets_svc.STORE, "list_tickets", side_effect=fake):
        results = svc._scan_backlog_tickets(
            space_id=None, statuses=["open"], limit=100
        )

    assert len(results) == 100


def test_scan_deduplicates_across_statuses():
    """Same ticket_id appearing in two status buckets is deduplicated."""
    t = _make_ticket(1)

    def fake(*, status=None, limit=100, cursor=None, **kwargs):
        return {"tickets": [t], "next_cursor": None}

    with patch.object(svc.tickets_svc.STORE, "list_tickets", side_effect=fake):
        results = svc._scan_backlog_tickets(
            space_id=None, statuses=["open", "in_progress"], limit=10
        )

    assert len(results) == 1

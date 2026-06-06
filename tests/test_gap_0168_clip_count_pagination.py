"""Regression test for GAP-0168.

``_count_user_clips_for_session`` enforces the per-user per-broadcast clip
quota (``_MAX_CLIPS_PER_BROADCAST = 10``). It queries the ``BySession`` GSI with
``Select="COUNT"`` and a ``FilterExpression``. DynamoDB applies the
``FilterExpression`` only after reading up to 1 MB of raw items per page, so a
single ``query()`` call silently under-counts on busy sessions: this user's
clips that fall beyond the first 1 MB page are never counted, letting them
exceed the quota.

Fails-before: the function issued exactly one ``query()`` and returned only the
first page's ``Count`` (3), bypassing the quota.
Passes-after: the function loops via ``LastEvaluatedKey`` and accumulates the
count across all pages (3 + 7 = 10).

Fully offline: ``app.core.tables.T.broadcast_clips`` is replaced with a fake
whose ``query`` returns a multi-page result keyed by ``ExclusiveStartKey``. No
real AWS / DynamoDB access occurs (TestClient is not used; the function is
called directly).
"""
from __future__ import annotations

import pytest

from app.core import tables as tables_module
from app.services.broadcast_clip import _count_user_clips_for_session


@pytest.fixture
def patch_clips_table():
    """Swap ``T.broadcast_clips`` for a fake, restoring after the test.

    ``Tables`` is a frozen dataclass, so assignment must go through
    ``object.__setattr__``.
    """
    original = tables_module.T.broadcast_clips

    def _install(fake):
        object.__setattr__(tables_module.T, "broadcast_clips", fake)
        return fake

    yield _install
    object.__setattr__(tables_module.T, "broadcast_clips", original)


class _PagedQueryTable:
    """Fake DDB table whose ``query`` returns two pages via LastEvaluatedKey.

    Page 1: Count=3 plus a LastEvaluatedKey cursor.
    Page 2 (reached only when ExclusiveStartKey is supplied): Count=7, no cursor.
    """

    def __init__(self) -> None:
        self.call_count = 0

    def query(self, **kwargs):
        self.call_count += 1
        if "ExclusiveStartKey" not in kwargs:
            # First page: more items exist beyond the 1 MB boundary.
            return {"Count": 3, "LastEvaluatedKey": {"clip_id": "cursor_abc"}}
        # Second page: remaining items, no further pages.
        return {"Count": 7}


def test_count_paginates_across_pages(patch_clips_table):
    fake = patch_clips_table(_PagedQueryTable())

    result = _count_user_clips_for_session("sess_001", "user_001")

    # FAILS-BEFORE: returns 3 (only the first page's Count).
    assert result == 10, (
        f"GAP-0168: expected 10 (paginated full count), got {result} (under-counted)"
    )
    assert fake.call_count == 2, "expected exactly 2 paginated DDB query calls"


def test_count_single_page_unchanged(patch_clips_table):
    """A session whose clips fit in one page makes exactly one query call."""

    class _SinglePageTable:
        def __init__(self) -> None:
            self.call_count = 0

        def query(self, **kwargs):
            self.call_count += 1
            return {"Count": 4}

    fake = patch_clips_table(_SinglePageTable())

    result = _count_user_clips_for_session("sess_002", "user_002")

    assert result == 4
    assert fake.call_count == 1, "single-page sessions must not make extra queries"

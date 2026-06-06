"""Regression test for GAP-0169.

``delete_clip`` (``app/services/broadcast_clip.py``) authorised clip deletion
only when the calling actor matched the clip's ``creator_user_id`` or
``broadcaster_user_id``. The docstring promised "clip creator, broadcaster, or
admin", but the admin/root arm was never implemented, so platform
administrators (``Role.ADMIN``) and root operators (``Role.ROOT``) could not
moderate clips from any broadcast — every admin call hit a ``403`` because
their ``user_sub`` matched neither stored ID.

Fails-before: ``delete_clip(clip_id, actor=<admin sub>, role=Role.ADMIN)``
raises ``HTTPException(403)`` (the ``role`` parameter did not even exist, and
the auth check ignored role).
Passes-after: ADMIN/ROOT callers succeed (soft-delete), while non-admin,
non-owner callers are still rejected with ``403`` and creators/broadcasters
keep working.

Fully offline: ``app.core.tables.T.broadcast_clips`` is swapped for an
in-memory fake that records ``get_item`` / ``update_item`` calls. No real AWS /
DynamoDB access occurs and the service function is called directly (TestClient
is not used).
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.auth.roles import Role
from app.core import tables as tables_module
from app.services.broadcast_clip import delete_clip


class _FakeClipsTable:
    """Minimal in-memory stand-in for the broadcast_clips DDB table."""

    def __init__(self) -> None:
        self.items: dict[str, dict] = {}
        self.updates: list[dict] = []

    def put(self, item: dict) -> None:
        self.items[str(item["clip_id"])] = dict(item)

    def get_item(self, *, Key):
        item = self.items.get(str(Key["clip_id"]))
        return {"Item": dict(item)} if item else {}

    def update_item(self, **kwargs):
        self.updates.append(kwargs)
        clip_id = str(kwargs["Key"]["clip_id"])
        # Mirror the SET #s = :deleted soft-delete on the stored item.
        if clip_id in self.items:
            self.items[clip_id]["status"] = kwargs["ExpressionAttributeValues"][":deleted"]
        return {}


@pytest.fixture
def fake_clips_table():
    """Swap ``T.broadcast_clips`` for a fake, restoring after the test.

    ``Tables`` is a frozen dataclass, so assignment must go through
    ``object.__setattr__``.
    """
    original = tables_module.T.broadcast_clips
    fake = _FakeClipsTable()
    object.__setattr__(tables_module.T, "broadcast_clips", fake)
    try:
        yield fake
    finally:
        object.__setattr__(tables_module.T, "broadcast_clips", original)


def _seed_clip(fake, clip_id: str, *, creator: str, broadcaster: str) -> None:
    fake.put({
        "clip_id": clip_id,
        "session_id": "sess_001",
        "creator_user_id": creator,
        "broadcaster_user_id": broadcaster,
        "status": "ready",
    })


def test_admin_can_delete_any_clip(fake_clips_table):
    """An ADMIN who is neither creator nor broadcaster must succeed.

    FAILS-BEFORE: raises HTTPException(403).
    """
    _seed_clip(fake_clips_table, "clip_admin", creator="user_creator", broadcaster="user_broadcaster")

    result = delete_clip("clip_admin", actor="user_admin", role=Role.ADMIN)

    assert result == {"ok": True, "clip_id": "clip_admin", "status": "deleted"}
    assert fake_clips_table.items["clip_admin"]["status"] == "deleted"
    assert len(fake_clips_table.updates) == 1


def test_root_can_delete_any_clip(fake_clips_table):
    """ROOT (passed as the raw string value) must also succeed."""
    _seed_clip(fake_clips_table, "clip_root", creator="user_a", broadcaster="user_b")

    # Routers forward ctx["role"], which is the enum *value* string.
    result = delete_clip("clip_root", actor="user_root", role="root")

    assert result["ok"] is True
    assert fake_clips_table.items["clip_root"]["status"] == "deleted"


def test_regular_user_still_blocked(fake_clips_table):
    """A USER who is neither creator nor broadcaster must still get 403.

    Regression: the admin fix must not weaken the non-admin path.
    """
    _seed_clip(fake_clips_table, "clip_blocked", creator="user_creator", broadcaster="user_broadcaster")

    with pytest.raises(HTTPException) as exc_info:
        delete_clip("clip_blocked", actor="user_random", role=Role.USER)

    assert exc_info.value.status_code == 403
    # Nothing should have been updated.
    assert fake_clips_table.updates == []
    assert fake_clips_table.items["clip_blocked"]["status"] == "ready"


def test_default_role_blocks_non_owner(fake_clips_table):
    """Callers that omit ``role`` (default None) get USER privileges only."""
    _seed_clip(fake_clips_table, "clip_default", creator="user_creator", broadcaster="user_broadcaster")

    with pytest.raises(HTTPException) as exc_info:
        delete_clip("clip_default", actor="user_random")

    assert exc_info.value.status_code == 403


def test_creator_can_still_delete(fake_clips_table):
    """The clip creator must still be able to delete their own clip."""
    _seed_clip(fake_clips_table, "clip_creator", creator="user_creator", broadcaster="user_broadcaster")

    result = delete_clip("clip_creator", actor="user_creator", role=Role.USER)

    assert result["ok"] is True
    assert fake_clips_table.items["clip_creator"]["status"] == "deleted"


def test_broadcaster_can_still_delete(fake_clips_table):
    """The broadcaster must still be able to delete clips from their session."""
    _seed_clip(fake_clips_table, "clip_bcaster", creator="user_creator", broadcaster="user_broadcaster")

    result = delete_clip("clip_bcaster", actor="user_broadcaster", role=Role.USER)

    assert result["ok"] is True


def test_missing_clip_returns_404(fake_clips_table):
    """A non-existent clip returns 404 regardless of role."""
    with pytest.raises(HTTPException) as exc_info:
        delete_clip("clip_missing", actor="user_admin", role=Role.ADMIN)

    assert exc_info.value.status_code == 404

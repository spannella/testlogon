"""GAP-0298: GET /ui/licenses/compliance/content/{content_id} must allow
the content owner OR an admin/root, not just the owner.

Offline/hermetic: the service lookup (svc.get_compliance_status) is monkeypatched
so no DynamoDB/AWS is touched, and the route handler coroutine is invoked
directly with a fake session dict (TestClient is broken in this repo).

Fails-before: with the old owner-only check, the admin/root cases would 403.
Passes-after: admin/root callers receive the record.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from app.routers import license_compliance as router

OWNER_SUB = "user_alice"
OTHER_SUB = "user_bob"
ADMIN_SUB = "user_charlie_admin"
ROOT_SUB = "user_root"

CONTENT_ID = "c1"

# Compliance record owned by Alice — admin/root deliberately do NOT own it.
_RECORD = {
    "content_id": CONTENT_ID,
    "content_type": "video",
    "creator_id": OWNER_SUB,
    "compliance_status": "compliant",
    "issues": [],
}


@pytest.fixture(autouse=True)
def _patch_service(monkeypatch):
    monkeypatch.setattr(
        router.svc,
        "get_compliance_status",
        lambda content_id: dict(_RECORD) if content_id == CONTENT_ID else None,
    )


def _call(session: dict):
    return asyncio.run(
        router.content_compliance_detail(content_id=CONTENT_ID, session=session)
    )


def test_owner_can_view():
    out = _call({"user_sub": OWNER_SUB, "role": "user"})
    assert out.content_id == CONTENT_ID
    assert out.creator_id == OWNER_SUB


def test_other_non_admin_user_blocked():
    with pytest.raises(HTTPException) as exc:
        _call({"user_sub": OTHER_SUB, "role": "user"})
    assert exc.value.status_code == 403


def test_admin_can_view():
    # Fails-before: old code 403s admins who don't own the content.
    out = _call({"user_sub": ADMIN_SUB, "role": "admin"})
    assert out.content_id == CONTENT_ID
    assert out.creator_id == OWNER_SUB


def test_root_can_view():
    # Fails-before: old code 403s root who doesn't own the content.
    out = _call({"user_sub": ROOT_SUB, "role": "root"})
    assert out.content_id == CONTENT_ID
    assert out.creator_id == OWNER_SUB

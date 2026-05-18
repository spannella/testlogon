from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient

from app.routers import messaging


@dataclass
class _DraftRow:
    draft_id: str
    conversation_id: str
    owner_user_id: str
    text: str
    version: int
    created_at: int
    updated_at: int
    client_updated_at: int | None = None


class _InMemoryDraftStore:
    def __init__(self) -> None:
        self._seq = 0
        self._clock = 1_700_000_000
        self._rows: dict[tuple[str, str, str], _DraftRow] = {}

    def _next_id(self) -> str:
        self._seq += 1
        return f"d{self._seq}"

    def _tick(self) -> int:
        self._clock += 1
        return self._clock

    def create_draft(self, *, owner_user_id: str, conversation_id: str, text: str, client_updated_at: int | None = None) -> dict[str, Any]:
        now = self._tick()
        row = _DraftRow(
            draft_id=self._next_id(),
            conversation_id=conversation_id,
            owner_user_id=owner_user_id,
            text=text,
            version=1,
            created_at=now,
            updated_at=now,
            client_updated_at=client_updated_at,
        )
        self._rows[(owner_user_id, conversation_id, row.draft_id)] = row
        return row.__dict__.copy()

    def get_draft(self, *, owner_user_id: str, conversation_id: str, draft_id: str) -> dict[str, Any]:
        row = self._rows.get((owner_user_id, conversation_id, draft_id))
        if not row:
            raise messaging.DraftNotFoundError("missing")
        return row.__dict__.copy()

    def update_draft(
        self,
        *,
        owner_user_id: str,
        conversation_id: str,
        draft_id: str,
        text: str,
        client_updated_at: int | None = None,
    ) -> dict[str, Any]:
        row = self._rows.get((owner_user_id, conversation_id, draft_id))
        if not row:
            raise messaging.DraftNotFoundError("missing")
        row.text = text
        row.version += 1
        row.updated_at = self._tick()
        row.client_updated_at = client_updated_at
        return row.__dict__.copy()

    def delete_draft(self, *, owner_user_id: str, conversation_id: str, draft_id: str) -> None:
        if (owner_user_id, conversation_id, draft_id) not in self._rows:
            raise messaging.DraftNotFoundError("missing")
        del self._rows[(owner_user_id, conversation_id, draft_id)]

    def list_drafts(
        self,
        *,
        owner_user_id: str,
        conversation_id: str,
        limit: int,
        cursor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        start = int((cursor or {}).get("offset", 0))
        rows = [
            row.__dict__.copy()
            for (uid, cid, _), row in self._rows.items()
            if uid == owner_user_id and cid == conversation_id
        ]
        rows.sort(key=lambda r: (r["updated_at"], r["draft_id"]), reverse=True)
        items = rows[start : start + limit]
        next_cursor = {"offset": start + limit} if start + limit < len(rows) else None
        return {"items": items, "next_cursor": next_cursor}


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    app = FastAPI()
    app.include_router(messaging.router)

    store = _InMemoryDraftStore()
    monkeypatch.setattr(messaging, "create_draft", store.create_draft)
    monkeypatch.setattr(messaging, "get_draft", store.get_draft)
    monkeypatch.setattr(messaging, "update_draft", store.update_draft)
    monkeypatch.setattr(messaging, "delete_draft", store.delete_draft)
    monkeypatch.setattr(messaging, "list_drafts", store.list_drafts)

    participants = {
        "u1": {"c1", "c2"},
        "u2": {"c2"},
    }

    def _require_participant_active(user_id: str, conversation_id: str) -> dict[str, str]:
        if conversation_id not in participants.get(user_id, set()):
            raise HTTPException(status_code=403, detail="Not an active participant")
        return {"user_id": user_id, "conversation_id": conversation_id}

    monkeypatch.setattr(messaging, "require_participant_active", _require_participant_active)

    async def _get_user_id(authorization: str | None = Header(default=None)) -> str:
        token = (authorization or "").replace("Bearer", "").strip()
        if not token:
            raise HTTPException(status_code=401, detail="Unauthorized")
        return token

    app.dependency_overrides[messaging.get_messaging_user_id] = _get_user_id
    return TestClient(app)


def _auth(user_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {user_id}"}


def test_draft_endpoints_full_lifecycle_with_pagination_and_ordering(client: TestClient) -> None:
    create_1 = client.post(
        "/messaging/conversations/c1/drafts",
        headers={**_auth("u1"), "Idempotency-Key": "k1"},
        json={"text": "alpha"},
    )
    assert create_1.status_code == 201
    draft_1_id = create_1.json()["draft"]["draft_id"]

    create_2 = client.post(
        "/messaging/conversations/c1/drafts",
        headers={**_auth("u1"), "Idempotency-Key": "k2"},
        json={"text": "beta"},
    )
    assert create_2.status_code == 201
    draft_2_id = create_2.json()["draft"]["draft_id"]

    page_1 = client.get("/messaging/conversations/c1/drafts?limit=1", headers=_auth("u1"))
    assert page_1.status_code == 200
    body_1 = page_1.json()
    assert [d["draft_id"] for d in body_1["items"]] == [draft_2_id]
    assert body_1["next_cursor"]

    page_2 = client.get(
        f"/messaging/conversations/c1/drafts?limit=1&cursor={body_1['next_cursor']}",
        headers=_auth("u1"),
    )
    assert page_2.status_code == 200
    body_2 = page_2.json()
    assert [d["draft_id"] for d in body_2["items"]] == [draft_1_id]
    assert body_2["next_cursor"] is None

    fetched = client.get(f"/messaging/conversations/c1/drafts/{draft_1_id}", headers=_auth("u1"))
    assert fetched.status_code == 200
    assert fetched.json()["draft"]["text"] == "alpha"

    patched = client.patch(
        f"/messaging/conversations/c1/drafts/{draft_1_id}",
        headers=_auth("u1"),
        json={"text": "alpha-updated"},
    )
    assert patched.status_code == 200
    assert patched.json()["draft"]["version"] == 2

    list_after_patch = client.get("/messaging/conversations/c1/drafts", headers=_auth("u1"))
    assert list_after_patch.status_code == 200
    assert [d["draft_id"] for d in list_after_patch.json()["items"][:2]] == [draft_1_id, draft_2_id]

    deleted = client.delete(f"/messaging/conversations/c1/drafts/{draft_2_id}", headers=_auth("u1"))
    assert deleted.status_code == 204

    after_delete = client.get("/messaging/conversations/c1/drafts", headers=_auth("u1"))
    assert after_delete.status_code == 200
    assert [d["draft_id"] for d in after_delete.json()["items"]] == [draft_1_id]


def test_draft_endpoints_reject_malformed_input(client: TestClient) -> None:
    missing_idem = client.post(
        "/messaging/conversations/c1/drafts",
        headers=_auth("u1"),
        json={"text": "hello"},
    )
    assert missing_idem.status_code == 422

    empty_text = client.post(
        "/messaging/conversations/c1/drafts",
        headers={**_auth("u1"), "Idempotency-Key": "k-empty"},
        json={"text": ""},
    )
    assert empty_text.status_code == 422

    too_long = client.patch(
        "/messaging/conversations/c1/drafts/non-existent",
        headers=_auth("u1"),
        json={"text": "x" * (messaging.MESSAGE_TEXT_MAX_CHARS + 1)},
    )
    assert too_long.status_code == 422

    invalid_cursor = client.get("/messaging/conversations/c1/drafts?cursor=not_base64", headers=_auth("u1"))
    assert invalid_cursor.status_code == 422


def test_draft_endpoints_enforce_authz_and_cross_user_isolation(client: TestClient) -> None:
    created = client.post(
        "/messaging/conversations/c2/drafts",
        headers={**_auth("u1"), "Idempotency-Key": "k-isolation"},
        json={"text": "owner-only"},
    )
    assert created.status_code == 201
    draft_id = created.json()["draft"]["draft_id"]

    forbidden = client.get("/messaging/conversations/c1/drafts", headers=_auth("u2"))
    assert forbidden.status_code == 403

    cross_user_get = client.get(f"/messaging/conversations/c2/drafts/{draft_id}", headers=_auth("u2"))
    assert cross_user_get.status_code == 404

    list_other_user = client.get("/messaging/conversations/c2/drafts", headers=_auth("u2"))
    assert list_other_user.status_code == 200
    assert list_other_user.json()["items"] == []

    cross_user_delete = client.delete(f"/messaging/conversations/c2/drafts/{draft_id}", headers=_auth("u2"))
    assert cross_user_delete.status_code == 404

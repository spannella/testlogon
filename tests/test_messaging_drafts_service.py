from __future__ import annotations

import copy

import pytest

from app.services.messaging_drafts import (
    DRAFTS_RETENTION_DAYS,
    DRAFTS_TTL_ATTR,
    DraftNotFoundError,
    DraftValidationError,
    create_draft,
    delete_draft,
    get_draft,
    list_drafts,
    update_draft,
)


class FakeDraftTable:
    def __init__(self):
        self.rows: dict[tuple[str, str], dict] = {}

    def put_item(self, Item, ConditionExpression=None):
        key = (Item["owner_user_id"], Item["draft_id"])
        if key in self.rows:
            raise RuntimeError("conditional failed")
        self.rows[key] = copy.deepcopy(Item)

    def get_item(self, Key):
        return {"Item": copy.deepcopy(self.rows.get((Key["owner_user_id"], Key["draft_id"])))}

    def update_item(self, Key, **kwargs):
        key = (Key["owner_user_id"], Key["draft_id"])
        if key not in self.rows:
            raise RuntimeError("not found")
        row = self.rows[key]
        values = kwargs["ExpressionAttributeValues"]
        row["text"] = values[":text"]
        row["updated_at"] = values[":updated_at"]
        row["version"] = int(row.get("version", 1)) + int(values[":inc"])
        if ":ttl_attr" in values:
            row[DRAFTS_TTL_ATTR] = values[":ttl_attr"]
        if ":client_updated_at" in values:
            row["client_updated_at"] = values[":client_updated_at"]
        self.rows[key] = row
        return {"Attributes": copy.deepcopy(row)}

    def delete_item(self, Key):
        self.rows.pop((Key["owner_user_id"], Key["draft_id"]), None)

    def query(self, **kwargs):
        assert kwargs["IndexName"] == "ByConversationUpdatedAt"
        cok = kwargs["ExpressionAttributeValues"][":cok"]
        items = [
            copy.deepcopy(v)
            for v in self.rows.values()
            if v.get("conversation_owner_key") == cok
        ]
        items.sort(key=lambda x: int(x.get("updated_at", 0)), reverse=not kwargs.get("ScanIndexForward", True))
        limit = kwargs.get("Limit", len(items))
        return {"Items": items[:limit]}


def test_crud_and_ordering_and_ownership_guards():
    tbl = FakeDraftTable()

    d1 = create_draft(
        owner_user_id="u1",
        conversation_id="c1",
        text="first",
        draft_id="d1",
        now=100,
        table=tbl,
    )
    d2 = create_draft(
        owner_user_id="u1",
        conversation_id="c1",
        text="second",
        draft_id="d2",
        now=200,
        table=tbl,
    )

    assert d1["draft_id"] == "d1"
    assert d2["draft_id"] == "d2"

    listed = list_drafts(owner_user_id="u1", conversation_id="c1", table=tbl)
    assert [d["draft_id"] for d in listed["items"]] == ["d2", "d1"]

    got = get_draft(owner_user_id="u1", conversation_id="c1", draft_id="d1", table=tbl)
    assert got["text"] == "first"

    updated = update_draft(
        owner_user_id="u1",
        conversation_id="c1",
        draft_id="d1",
        text="first updated",
        now=300,
        table=tbl,
    )
    assert updated["text"] == "first updated"
    assert updated["version"] == 2

    # strict ownership / conversation checks
    with pytest.raises(DraftNotFoundError):
        get_draft(owner_user_id="u2", conversation_id="c1", draft_id="d1", table=tbl)
    with pytest.raises(DraftNotFoundError):
        get_draft(owner_user_id="u1", conversation_id="c2", draft_id="d1", table=tbl)

    delete_draft(owner_user_id="u1", conversation_id="c1", draft_id="d2", table=tbl)
    listed_after = list_drafts(owner_user_id="u1", conversation_id="c1", table=tbl)
    assert [d["draft_id"] for d in listed_after["items"]] == ["d1"]


def test_validation_and_malformed_legacy_rows_are_handled_safely():
    tbl = FakeDraftTable()

    with pytest.raises(DraftValidationError):
        create_draft(owner_user_id="u1", conversation_id="c1", text="   ", table=tbl)

    with pytest.raises(DraftValidationError):
        create_draft(owner_user_id="u1", conversation_id="c1", text="x" * 4001, table=tbl)

    create_draft(owner_user_id="u1", conversation_id="c1", text="ok", draft_id="good", now=100, table=tbl)
    # malformed legacy row missing required fields
    tbl.rows[("u1", "bad")] = {
        "owner_user_id": "u1",
        "draft_id": "bad",
        "conversation_owner_key": "u1#c1",
        "updated_at": 999,
    }

    listed = list_drafts(owner_user_id="u1", conversation_id="c1", table=tbl)
    assert [d["draft_id"] for d in listed["items"]] == ["good"]

    with pytest.raises(DraftValidationError):
        list_drafts(owner_user_id="u1", conversation_id="c1", limit=0, table=tbl)


def test_ttl_retention_is_set_and_refreshed_on_update():
    tbl = FakeDraftTable()
    created = create_draft(
        owner_user_id="u1",
        conversation_id="c1",
        text="ttl",
        draft_id="ttl-1",
        now=1_000,
        table=tbl,
    )
    expected_created_ttl = 1_000 + (DRAFTS_RETENTION_DAYS * 86_400)
    assert tbl.rows[("u1", "ttl-1")][DRAFTS_TTL_ATTR] == expected_created_ttl
    assert created["updated_at"] == 1_000

    updated = update_draft(
        owner_user_id="u1",
        conversation_id="c1",
        draft_id="ttl-1",
        text="ttl updated",
        now=2_000,
        table=tbl,
    )
    expected_updated_ttl = 2_000 + (DRAFTS_RETENTION_DAYS * 86_400)
    assert tbl.rows[("u1", "ttl-1")][DRAFTS_TTL_ATTR] == expected_updated_ttl
    assert updated["updated_at"] == 2_000

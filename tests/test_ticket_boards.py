"""Hermetic offline tests for the ticket-boards rename + columns (TKB-001..009).

No real AWS / no network. Uses an in-memory fake DynamoDB table bound to the
TicketStore via STORE._table, mirroring tests/test_ticketing_routes.py. Route
handlers are called directly (TestClient is broken in this env).
"""
from __future__ import annotations

import asyncio
from copy import deepcopy

import pytest
from botocore.exceptions import ClientError

from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role
from app.core.settings import S
from app.services import tickets as tickets_svc
from app.services.tickets import STORE, BoardColumnError


# --------------------------------------------------------------------------
# In-memory fake table (covers the access patterns boards/columns exercise:
# put/get/delete, begins_with partition queries, the member-spaces GSI, and
# a SET update_item used by update_board_columns / assign / status).
# --------------------------------------------------------------------------
class FakeTicketTable:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict] = {}

    def reset(self) -> None:
        self.items.clear()

    def put_item(self, *, Item: dict, **kwargs):
        self.items[(Item["pk"], Item["sk"])] = deepcopy(Item)
        return {}

    def get_item(self, *, Key: dict, **kwargs):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": deepcopy(item)} if item else {}

    def delete_item(self, *, Key: dict, **kwargs):
        self.items.pop((Key["pk"], Key["sk"]), None)
        return {}

    def query(self, **kwargs):
        expr = kwargs.get("KeyConditionExpression", "")
        vals = kwargs.get("ExpressionAttributeValues", {})
        index_name = kwargs.get("IndexName")
        reverse = not kwargs.get("ScanIndexForward", True)
        if index_name:
            pk = vals[":pk"]
            if "gsi_member_pk" in expr:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi_member_pk") == pk]
                out.sort(key=lambda x: x.get("gsi_member_sk", ""), reverse=reverse)
            elif "gsi_space_status_pk" in expr:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi_space_status_pk") == pk and v.get("sk") == "META"]
                out.sort(key=lambda x: x.get("gsi_space_status_sk", ""), reverse=reverse)
            elif "gsi_space_assignee_pk" in expr:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi_space_assignee_pk") == pk and v.get("sk") == "META"]
                out.sort(key=lambda x: x.get("gsi_space_assignee_sk", ""), reverse=reverse)
            elif "gsi_space_pk" in expr:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi_space_pk") == pk and v.get("sk") == "META"]
                out.sort(key=lambda x: x.get("gsi_space_sk", ""), reverse=reverse)
            else:
                out = []
            return {"Items": out}
        if "begins_with" in expr:
            pk = vals[":pk"]
            prefix = vals[":sk_prefix"]
            out = [deepcopy(v) for (p, _), v in self.items.items() if p == pk and v.get("sk", "").startswith(prefix)]
            out.sort(key=lambda x: x.get("sk", ""), reverse=reverse)
            return {"Items": out}
        return {"Items": []}

    def update_item(self, *, Key: dict, UpdateExpression: str, ConditionExpression: str | None = None,
                    ExpressionAttributeNames: dict | None = None, ExpressionAttributeValues: dict | None = None, **kwargs):
        item = self.items.get((Key["pk"], Key["sk"]))
        if not item:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "missing"}}, "UpdateItem")
        names = ExpressionAttributeNames or {}
        values = ExpressionAttributeValues or {}
        if ConditionExpression and "#version = :expected_version" in ConditionExpression:
            version_attr = names["#version"]
            if item.get(version_attr) != values[":expected_version"]:
                raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "stale"}}, "UpdateItem")
        set_part = UpdateExpression
        if set_part.startswith("SET "):
            for assignment in set_part[4:].split(","):
                left, right = assignment.strip().split(" = ", 1)
                attr = names.get(left.strip(), left.strip())
                item[attr] = values.get(right.strip(), right.strip())
        self.items[(Key["pk"], Key["sk"])] = item
        return {}


FAKE = FakeTicketTable()


@pytest.fixture(autouse=True)
def _bind_table():
    prev = STORE._table
    STORE._table = FAKE
    FAKE.reset()
    yield
    STORE._table = prev


@pytest.fixture
def boards_on():
    prev = S.ticket_boards_enabled
    object.__setattr__(S, "ticket_boards_enabled", True)
    yield
    object.__setattr__(S, "ticket_boards_enabled", prev)


def _user(sub: str, role: Role = Role.USER) -> AuthenticatedUser:
    return AuthenticatedUser(sub=sub, role=role)


# --------------------------------------------------------------------------
# TKB-001 + TKB-002 — store-level parity
# --------------------------------------------------------------------------
def test_get_board_and_get_space_return_same_object(boards_on):
    created = STORE.create_board(owner_sub="alice", name="My Board")
    bid = created["board_id"]
    assert created["board_id"] == created["space_id"]

    via_board = STORE.get_board(bid)
    via_space = STORE.get_space(bid)
    assert via_board == via_space
    assert via_board["space_id"] == via_board["board_id"] == bid
    assert len(via_board["members"]) == 1
    assert via_board["members"][0]["board_id"] == bid


def test_entity_type_parity_attributes(boards_on):
    created = STORE.create_board(owner_sub="alice", name="B")
    bid = created["board_id"]
    meta = FAKE.items[(f"SPACE#{bid}", "META")]
    member = FAKE.items[(f"SPACE#{bid}", "MEMBER#alice")]
    assert meta["entity_type"] == "ticket_space"
    assert meta["board_entity_type"] == "ticket_board"
    assert member["entity_type"] == "space_membership"
    assert member["board_entity_type"] == "board_membership"


def test_create_ticket_board_id_and_space_id_equivalent(boards_on):
    b = STORE.create_board(owner_sub="alice", name="B")
    bid = b["board_id"]
    t_by_board = STORE.create_ticket(owner_sub="alice", subject="via board", description="x", board_id=bid)
    t_by_space = STORE.create_ticket(owner_sub="alice", subject="via space", description="y", space_id=bid)
    assert t_by_board["space_id"] == bid
    assert t_by_board["board_id"] == bid
    assert t_by_space["space_id"] == bid
    # Both reachable via board ticket listing.
    listed = STORE.list_board_tickets(board_id=bid)["tickets"]
    assert {t["ticket_id"] for t in listed} == {t_by_board["ticket_id"], t_by_space["ticket_id"]}


def test_legacy_shaped_meta_resolves_via_get_board():
    # Write a pre-rename META row directly: only space_id + entity_type, no
    # board_entity_type, no columns. Must still resolve with board_id populated.
    bid = "spc_legacy123456"
    FAKE.put_item(Item={
        "pk": f"SPACE#{bid}", "sk": "META",
        "entity_type": "ticket_space", "space_id": bid,
        "owner_sub": "alice", "name": "Legacy", "visibility": "private",
        "created_at": 1, "updated_at": 1,
    })
    FAKE.put_item(Item={
        "pk": f"SPACE#{bid}", "sk": "MEMBER#alice",
        "entity_type": "space_membership", "space_id": bid,
        "member_sub": "alice", "role": "owner", "created_at": 1, "updated_at": 1,
    })
    board = STORE.get_board(bid)
    assert board is not None
    assert board["board_id"] == bid == board["space_id"]
    # Read-time back-fill: default columns even though none were stored.
    assert [c["status_key"] for c in board["columns"]] == ["open", "in_progress", "waiting_on_user", "done"]


# --------------------------------------------------------------------------
# TKB-006 / TKB-007 — columns
# --------------------------------------------------------------------------
def test_new_board_seeds_default_columns(boards_on):
    b = STORE.create_board(owner_sub="alice", name="B")
    keys = [c["status_key"] for c in b["columns"]]
    assert keys == ["open", "in_progress", "waiting_on_user", "done"]
    # Persisted on the row when flag on.
    meta = FAKE.items[(f"SPACE#{b['board_id']}", "META")]
    assert "columns" in meta


def test_update_board_columns_custom_title_maps_to_valid_status(boards_on):
    b = STORE.create_board(owner_sub="alice", name="B")
    bid = b["board_id"]
    updated = STORE.update_board_columns(board_id=bid, columns=[
        {"column_id": "c1", "title": "Backlog", "status_key": "open"},
        {"column_id": "c2", "title": "Needs review", "status_key": "waiting_on_user"},
        {"column_id": "c3", "title": "Done", "status_key": "done"},
    ])
    assert [c["title"] for c in updated["columns"]] == ["Backlog", "Needs review", "Done"]
    # Custom label re-skins a real underlying status.
    assert updated["columns"][1]["status_key"] == "waiting_on_user"
    assert [c["order"] for c in updated["columns"]] == [0, 1, 2]


def test_update_board_columns_rejects_unknown_status_key(boards_on):
    b = STORE.create_board(owner_sub="alice", name="B")
    with pytest.raises(BoardColumnError) as exc:
        STORE.update_board_columns(board_id=b["board_id"], columns=[
            {"column_id": "c1", "title": "Bad", "status_key": "not_a_status"},
        ])
    assert exc.value.detail["code"] == "invalid_status_key"


def test_update_board_columns_rejects_duplicate_column_id(boards_on):
    b = STORE.create_board(owner_sub="alice", name="B")
    with pytest.raises(BoardColumnError) as exc:
        STORE.update_board_columns(board_id=b["board_id"], columns=[
            {"column_id": "dup", "title": "A", "status_key": "open"},
            {"column_id": "dup", "title": "B", "status_key": "done"},
        ])
    assert exc.value.detail["code"] == "duplicate_column_id"


def test_update_board_columns_unknown_board_returns_none(boards_on):
    assert STORE.update_board_columns(board_id="spc_missing", columns=[
        {"column_id": "c1", "title": "Open", "status_key": "open"},
    ]) is None


# --------------------------------------------------------------------------
# TKB-003 / TKB-008 — router handlers (called directly)
# --------------------------------------------------------------------------
def test_boards_router_create_visible_via_spaces(boards_on):
    from app.routers import ticket_boards as br
    from app.routers import ticket_spaces as sp

    env = br.create_board(br.CreateBoardReq(name="Cross"), _ctx={}, user=_user("alice"))
    bid = env.board.board_id
    assert env.board.board_id == env.board.space_id

    # Visible via the legacy /ticket-spaces GET handler.
    sp_env = sp.get_ticket_space(bid, _ctx={}, user=_user("alice"))
    assert sp_env.space.space_id == bid


def test_spaces_router_create_visible_via_boards(boards_on):
    from app.routers import ticket_boards as br
    from app.routers import ticket_spaces as sp

    sp_env = sp.create_ticket_space(sp.CreateSpaceReq(name="FromSpace"), _ctx={}, user=_user("bob"))
    sid = sp_env.space.space_id
    br_env = br.get_board(sid, _ctx={}, user=_user("bob"))
    assert br_env.board.board_id == sid
    assert br_env.board.columns  # default columns surfaced


def test_boards_router_not_found_uses_board_code(boards_on):
    from app.routers import ticket_boards as br
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        br.get_board("spc_nope", _ctx={}, user=_user("alice"))
    assert exc.value.status_code == 404
    assert exc.value.detail["error"]["code"] == "board_not_found"


def test_update_columns_viewer_forbidden_editor_ok(boards_on):
    from app.routers import ticket_boards as br
    from fastapi import HTTPException

    owner = _user("alice")
    env = br.create_board(br.CreateBoardReq(name="Roles"), _ctx={}, user=owner)
    bid = env.board.board_id
    # Add a viewer.
    br.add_board_member(bid, br.AddBoardMemberReq(member_sub="viewer1", role="viewer"), _ctx={}, user=owner)

    cols_req = br.UpdateBoardColumnsReq(columns=[
        br.BoardColumnIn(column_id="c1", title="Open", status_key="open"),
        br.BoardColumnIn(column_id="c2", title="Done", status_key="done"),
    ])
    with pytest.raises(HTTPException) as exc:
        br.update_board_columns(bid, cols_req, _ctx={}, user=_user("viewer1"))
    assert exc.value.status_code == 403
    assert exc.value.detail["error"]["code"] == "board_write_forbidden"

    # Owner succeeds.
    res = br.update_board_columns(bid, cols_req, _ctx={}, user=owner)
    assert [c.title for c in res.board.columns] == ["Open", "Done"]


def test_update_columns_invalid_status_key_returns_400(boards_on):
    from app.routers import ticket_boards as br
    from fastapi import HTTPException

    env = br.create_board(br.CreateBoardReq(name="B"), _ctx={}, user=_user("alice"))
    bid = env.board.board_id
    req = br.UpdateBoardColumnsReq(columns=[br.BoardColumnIn(column_id="c1", title="X", status_key="bogus")])
    with pytest.raises(HTTPException) as exc:
        br.update_board_columns(bid, req, _ctx={}, user=_user("alice"))
    assert exc.value.status_code == 400
    assert exc.value.detail["error"]["code"] == "invalid_status_key"


def test_get_board_columns_handler(boards_on):
    from app.routers import ticket_boards as br
    env = br.create_board(br.CreateBoardReq(name="B"), _ctx={}, user=_user("alice"))
    bid = env.board.board_id
    cols_env = br.get_board_columns(bid, _ctx={}, user=_user("alice"))
    assert cols_env.board_id == bid
    assert [c.status_key for c in cols_env.columns] == ["open", "in_progress", "waiting_on_user", "done"]


def test_board_ticket_status_drag_to_custom_column_persists_real_status(boards_on):
    from app.routers import ticket_boards as br
    owner = _user("alice")
    env = br.create_board(br.CreateBoardReq(name="B"), _ctx={}, user=owner)
    bid = env.board.board_id
    # Re-skin: a "Needs review" column mapped to waiting_on_user.
    br.update_board_columns(bid, br.UpdateBoardColumnsReq(columns=[
        br.BoardColumnIn(column_id="c1", title="Open", status_key="open"),
        br.BoardColumnIn(column_id="c2", title="Needs review", status_key="waiting_on_user"),
    ]), _ctx={}, user=owner)
    t_env = br.create_board_ticket(bid, br.CreateBoardTicketReq(subject="hello world", description="d"), _ctx={}, user=owner)
    tid = t_env.ticket.ticket_id
    # open -> in_progress -> waiting_on_user (valid transitions)
    br.update_board_ticket_status(bid, tid, br.BoardTicketStatusReq(status="in_progress"), _ctx={}, user=owner)
    res = br.update_board_ticket_status(bid, tid, br.BoardTicketStatusReq(status="waiting_on_user"), _ctx={}, user=owner)
    assert res.ticket.status == "waiting_on_user"


# --------------------------------------------------------------------------
# Flag-off safety — store output without seeding still legacy-shaped on disk
# --------------------------------------------------------------------------
def test_flag_off_does_not_persist_columns_attribute():
    # No boards_on fixture → flag stays at its default (off).
    b = STORE.create_space(owner_sub="alice", name="B")
    meta = FAKE.items[(f"SPACE#{b['space_id']}", "META")]
    assert "columns" not in meta  # stored row byte-for-byte legacy
    # But read-time still surfaces defaults for the API layer.
    assert len(b["columns"]) == 4

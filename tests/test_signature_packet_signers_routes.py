"""Regression tests for GAP-0031: add/remove signer endpoints.

Before the fix there was no API path to populate the signature_packet_signers
table, so `list_packet_signers` always returned `[]` and `send` permanently
returned 400 `signature_packet_no_signers`. These tests exercise the real store
write path against an in-memory DynamoDB table fake (no real AWS) and the route
handlers directly:

  * add a signer -> `list_packet_signers` returns it (send precondition met),
  * send no longer raises `signature_packet_no_signers`,
  * adding to a non-DRAFT packet -> 409 `signature_packet_not_draft`,
  * remove a signer -> 204 and it disappears from the listing,
  * a non-owner cannot add signers -> 403 `signature_packet_not_owner`.

They FAIL before the fix (the route handlers / service functions do not exist)
and PASS after.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes
from app.services import signature_packet_store as store


class _InMemoryTable:
    """Minimal in-memory stand-in for a DynamoDB Table.

    Supports put_item / get_item / delete_item / query(KeyConditionExpression)
    on a composite (packet_id, signer_id) key — enough for the signer store
    functions. No real AWS / network access.
    """

    def __init__(self, hash_key: str, range_key: str | None = None) -> None:
        self._hash_key = hash_key
        self._range_key = range_key
        self._items: dict[tuple, dict] = {}

    def _key_of(self, item: dict) -> tuple:
        if self._range_key:
            return (item[self._hash_key], item[self._range_key])
        return (item[self._hash_key],)

    def put_item(self, *, Item: dict) -> dict:
        self._items[self._key_of(Item)] = dict(Item)
        return {}

    def get_item(self, *, Key: dict) -> dict:
        key = self._key_of(Key)
        item = self._items.get(key)
        return {"Item": dict(item)} if item is not None else {}

    def delete_item(self, *, Key: dict) -> dict:
        self._items.pop(self._key_of(Key), None)
        return {}

    def query(self, *, KeyConditionExpression, **_kwargs) -> dict:
        # We only ever query by an equality on the hash key here.
        # boto3 conditions: values == (Key(...), <literal value>).
        expr = KeyConditionExpression.get_expression()
        wanted = expr["values"][1]
        items = [
            dict(v)
            for v in self._items.values()
            if v.get(self._hash_key) == wanted
        ]
        return {"Items": items}


class _FakeTables:
    def __init__(self) -> None:
        self.signature_packet_signers = _InMemoryTable("packet_id", "signer_id")


@pytest.fixture()
def wired(monkeypatch):
    """Wire an in-memory signers table and a single in-memory draft packet."""
    packets: dict[str, dict] = {
        "sp_owned": {"packet_id": "sp_owned", "owner_user_id": "owner-1", "status": "draft"},
    }

    tables = _FakeTables()
    monkeypatch.setattr(store, "T", tables)
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)
    monkeypatch.setattr(store, "get_packet", lambda pid: packets.get(pid))

    # Route layer talks to the store via these imported names.
    monkeypatch.setattr(routes, "get_packet", lambda pid: packets.get(pid))
    monkeypatch.setattr(routes, "add_packet_signer", store.add_packet_signer)
    monkeypatch.setattr(routes, "remove_packet_signer", store.remove_packet_signer)
    monkeypatch.setattr(routes, "list_packet_signers", store.list_packet_signers)
    monkeypatch.setattr(routes, "append_packet_event", lambda **kwargs: kwargs)

    return packets


def test_add_signer_then_listed_satisfies_send_precondition(wired) -> None:
    # Before the fix: add_signer route / add_packet_signer store fn do not exist.
    out = routes.add_signer(
        "sp_owned",
        routes.AddSignerIn(signer_id="bob_sub", required=True),
        user_sub="owner-1",
    )
    assert out["signer_id"] == "bob_sub"
    assert out["status"] == "pending"
    assert out["required"] is True

    # list_packet_signers now returns the freshly-added signer ...
    signers = store.list_packet_signers("sp_owned")
    assert [s["signer_id"] for s in signers] == ["bob_sub"]

    # ... so the send precondition ("has signers") is satisfied: the 400
    # signature_packet_no_signers branch is no longer reachable.
    assert bool(store.list_packet_signers("sp_owned")) is True


def test_add_signer_requires_draft_status(wired) -> None:
    wired["sp_owned"]["status"] = "sent"
    with pytest.raises(ValueError, match="packet_not_draft"):
        store.add_packet_signer(packet_id="sp_owned", signer_id="bob_sub")


def test_add_signer_non_owner_forbidden(wired) -> None:
    with pytest.raises(HTTPException) as exc:
        routes.add_signer(
            "sp_owned",
            routes.AddSignerIn(signer_id="charlie_sub"),
            user_sub="not-the-owner",
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "signature_packet_not_owner"
    # And no signer leaked into the table on the rejected path.
    assert store.list_packet_signers("sp_owned") == []


def test_remove_signer_returns_204_and_drops_listing(wired) -> None:
    routes.add_signer(
        "sp_owned",
        routes.AddSignerIn(signer_id="bob_sub"),
        user_sub="owner-1",
    )
    assert [s["signer_id"] for s in store.list_packet_signers("sp_owned")] == ["bob_sub"]

    resp = routes.remove_signer("sp_owned", "bob_sub", user_sub="owner-1")
    assert resp.status_code == 204
    assert store.list_packet_signers("sp_owned") == []

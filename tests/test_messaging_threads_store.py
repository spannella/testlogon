from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from botocore.exceptions import ClientError

from app.services import messaging_threads_store as store


class _FakeTable:
    def __init__(self) -> None:
        self.put_calls = []
        self.get_calls = []
        self.query_calls = []
        self.get_item_response = {}
        self.query_response = {"Items": []}
        self.raise_conditional = False

    def put_item(self, **kwargs):
        self.put_calls.append(kwargs)
        if self.raise_conditional:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate"}},
                "PutItem",
            )
        return {}

    def get_item(self, **kwargs):
        self.get_calls.append(kwargs)
        return self.get_item_response

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        return self.query_response


def test_create_thread_record_persists_required_fields() -> None:
    fake = _FakeTable()
    with patch.object(store, "tbl_message_threads", fake):
        out = store.create_message_thread_record(
            thread_id="thr_1",
            conversation_id="c1",
            root_message_id="m_root",
            created_at=123,
            created_by="u1",
        )

    assert out.id == "thr_1"
    write = fake.put_calls[0]
    assert write["Item"] == {
        "id": "thr_1",
        "conversation_id": "c1",
        "root_message_id": "m_root",
        "created_at": 123,
        "created_by": "u1",
    }
    assert write["ConditionExpression"] == "attribute_not_exists(id)"


def test_create_thread_record_returns_existing_on_conditional_conflict() -> None:
    fake = _FakeTable()
    fake.raise_conditional = True
    fake.get_item_response = {
        "Item": {
            "id": "thr_1",
            "conversation_id": "c1",
            "root_message_id": "m_root",
            "created_at": Decimal("123"),
            "created_by": "u2",
        }
    }
    with patch.object(store, "tbl_message_threads", fake):
        out = store.create_message_thread_record(
            thread_id="thr_1",
            conversation_id="c1",
            root_message_id="m_root",
            created_at=123,
            created_by="u1",
        )

    assert out.created_by == "u2"
    assert out.created_at == 123


def test_list_threads_for_conversation_queries_conversation_index() -> None:
    fake = _FakeTable()
    fake.query_response = {
        "Items": [
            {
                "id": "thr_1",
                "conversation_id": "c1",
                "root_message_id": "m_root",
                "created_at": Decimal("100"),
                "created_by": "u1",
            }
        ]
    }
    with patch.object(store, "tbl_message_threads", fake):
        out = store.list_threads_for_conversation("c1", limit=20)

    assert len(out) == 1
    assert out[0].id == "thr_1"
    query = fake.query_calls[0]
    assert query["IndexName"] == "ByConversationCreatedAt"
    assert query["Limit"] == 20
    assert query["ScanIndexForward"] is False


def test_find_thread_for_root_message_queries_root_index() -> None:
    fake = _FakeTable()
    fake.query_response = {
        "Items": [
            {
                "id": "thr_2",
                "conversation_id": "c2",
                "root_message_id": "m42",
                "created_at": Decimal("500"),
                "created_by": "u9",
            }
        ]
    }
    with patch.object(store, "tbl_message_threads", fake):
        out = store.find_thread_for_root_message("m42")

    assert out is not None
    assert out.id == "thr_2"
    assert fake.query_calls[0]["IndexName"] == "ByRootMessage"

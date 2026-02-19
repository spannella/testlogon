from unittest.mock import Mock

from app.services.messaging_gallery_index import (
    backfill_conversation_gallery_index,
    check_gallery_index_consistency,
    fetch_gallery_index_page,
    gallery_index_partition_key,
    gallery_index_sort_key,
)


def test_fetch_gallery_index_page_uses_conversation_type_partition():
    table = Mock()
    table.query.return_value = {"Items": [], "LastEvaluatedKey": None}

    fetch_gallery_index_page(
        table=table,
        conversation_id="c1",
        gallery_type="image",
        limit=20,
        cursor_sort_key=None,
    )

    kwargs = table.query.call_args.kwargs
    assert kwargs["ScanIndexForward"] is False
    assert kwargs["Limit"] == 20


def test_backfill_conversation_gallery_index_upserts_projected_rows():
    messages_table = Mock()
    messages_table.query.return_value = {
        "Items": [
            {"conversation_id": "c1", "message_id": "m1", "created_at": 101, "kind": "image"},
            {"conversation_id": "c1", "message_id": "m2", "created_at": 100, "kind": "text"},
        ]
    }

    class _Writer:
        def __init__(self):
            self.deletes = []
            self.puts = []

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def delete_item(self, Key):
            self.deletes.append(Key)

        def put_item(self, Item):
            self.puts.append(Item)

    writer = _Writer()
    index_table = Mock()
    index_table.batch_writer.return_value = writer

    def project_entries(msg):
        if msg["kind"] == "image":
            return [{"type": "image", "url": "u"}]
        return []

    out = backfill_conversation_gallery_index(
        messages_table=messages_table,
        index_table=index_table,
        conversation_id="c1",
        project_entries=project_entries,
        page_size=50,
    )

    assert out == {"messages_scanned": 2, "entries_upserted": 1}
    assert len(writer.puts) == 1


def test_gallery_index_consistency_reports_missing_rows():
    messages = [
        {"conversation_id": "c1", "message_id": "m1", "created_at": 101, "kind": "image"},
    ]
    index_items = []

    def project_entries(_msg):
        return [{"type": "image"}]

    report = check_gallery_index_consistency(
        messages=messages,
        index_items=index_items,
        project_entries=project_entries,
    )

    assert report["expected_count"] == 1
    assert report["actual_count"] == 0
    assert report["missing_count"] == 1
    assert report["ok"] is False


def test_index_key_helpers_are_stable():
    assert gallery_index_partition_key("c1", "image") == "c1#image"
    assert gallery_index_sort_key(101, "m1") == "0000000000101#m1"

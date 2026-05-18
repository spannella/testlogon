from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_reply_threads", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _table_for(mod, resolved_name: str, fallback: str):
    defs = mod._table_defs()
    target = mod._resolve_table_name(resolved_name, fallback)
    return next(t for t in defs if t.name in {target, fallback})


def test_messages_table_has_threading_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, "", "Messages")

    assert table.partition_key == "conversation_id"
    assert table.sort_key == "message_id"

    indexes = {g["index_name"]: g for g in table.gsi}
    assert indexes["ByConversationCreatedAt"] == {
        "index_name": "ByConversationCreatedAt",
        "partition_key": "conversation_id",
        "sort_key": "created_at",
    }
    assert indexes["ByParentMessageId"] == {
        "index_name": "ByParentMessageId",
        "partition_key": "parent_message_id",
    }
    assert indexes["ByThreadCreatedAt"] == {
        "index_name": "ByThreadCreatedAt",
        "partition_key": "thread_id",
        "sort_key": "created_at",
    }
    assert indexes["ByThreadRootMessageId"] == {
        "index_name": "ByThreadRootMessageId",
        "partition_key": "thread_root_message_id",
    }


def test_message_threads_table_exists_with_required_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.message_threads_table_name, "MessageThreads")

    assert table.partition_key == "id"
    assert table.sort_key is None
    indexes = {g["index_name"]: g for g in table.gsi}
    assert indexes["ByConversationCreatedAt"] == {
        "index_name": "ByConversationCreatedAt",
        "partition_key": "conversation_id",
        "sort_key": "created_at",
    }
    assert indexes["ByRootMessage"] == {
        "index_name": "ByRootMessage",
        "partition_key": "root_message_id",
    }

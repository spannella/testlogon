from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_message_visibility", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _table_for(mod):
    defs = mod._table_defs()
    target = mod._resolve_table_name(
        mod.S.message_visibility_overrides_table_name,
        "MessageVisibilityOverrides",
    )
    return next(t for t in defs if t.name in {target, "MessageVisibilityOverrides"})


def test_message_visibility_overrides_table_schema() -> None:
    mod = _load_module()
    table = _table_for(mod)

    assert table.partition_key == "conversation_id"
    assert table.sort_key == "message_user"

    indexes = {g["index_name"]: g for g in table.gsi}
    assert "ByConversationUserUpdatedAt" in indexes
    by_conversation_user = indexes["ByConversationUserUpdatedAt"]

    assert by_conversation_user["partition_key"] == "conversation_user"
    assert by_conversation_user["sort_key"] == "updated_at"

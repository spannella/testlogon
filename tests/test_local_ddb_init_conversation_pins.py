from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_conversation_pins", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _table_for(mod):
    defs = mod._table_defs()
    target = mod._resolve_table_name(
        mod.S.conversation_pins_table_name,
        "ConversationPins",
    )
    return next(t for t in defs if t.name in {target, "ConversationPins"})


def test_conversation_pins_table_schema_and_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod)

    assert table.partition_key == "conversation_id"
    assert table.sort_key == "message_id"

    indexes = {g["index_name"]: g for g in table.gsi}

    active_pins = indexes["ByConversationActivePinnedAt"]
    assert active_pins["partition_key"] == "conversation_active"
    assert active_pins["sort_key"] == "pinned_at"

    latest_active_pin = indexes["ByConversationLatestActivePin"]
    assert latest_active_pin["partition_key"] == "conversation_active"
    assert latest_active_pin["sort_key"] == "latest_pin_sort"

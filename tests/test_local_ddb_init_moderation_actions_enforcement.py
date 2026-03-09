from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_moderation_actions_enforcement", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _table_for(mod, table_name: str, fallback_name: str):
    for t in mod._table_defs():
        if t.name in {table_name, fallback_name}:
            return t
    raise AssertionError(f"table not found: {table_name} / {fallback_name}")


def test_moderation_actions_table_schema_and_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.moderation_actions_table_name, "ModerationActions")

    assert table.partition_key == "action_id"
    assert table.sort_key is None

    gsis = {g["index_name"]: g for g in table.gsi}
    assert gsis["ByTicketCreatedAt"]["partition_key"] == "ticket_id"
    assert gsis["ByTicketCreatedAt"]["sort_key"] == "created_at"
    assert gsis["ByActionTypeCreatedAt"]["partition_key"] == "action_type"
    assert gsis["ByActionTypeCreatedAt"]["sort_key"] == "created_at"
    assert gsis["ByTargetUserCreatedAt"]["partition_key"] == "target_user_id"
    assert gsis["ByTargetUserCreatedAt"]["sort_key"] == "created_at"


def test_user_enforcement_history_table_schema_and_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.user_enforcement_history_table_name, "UserEnforcementHistory")

    assert table.partition_key == "user_id"
    assert table.sort_key == "enforcement_id"

    gsis = {g["index_name"]: g for g in table.gsi}
    assert gsis["ByStatusCreatedAt"]["partition_key"] == "status"
    assert gsis["ByStatusCreatedAt"]["sort_key"] == "created_at"
    assert gsis["BySourceTicketCreatedAt"]["partition_key"] == "source_ticket_id"
    assert gsis["BySourceTicketCreatedAt"]["sort_key"] == "created_at"

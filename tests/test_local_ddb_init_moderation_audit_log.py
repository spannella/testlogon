from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_moderation_audit_log", path)
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


def test_moderation_audit_log_table_schema_and_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.moderation_audit_log_table_name, "ModerationAuditLog")

    assert table.partition_key == "audit_id"
    assert table.sort_key is None

    gsis = {g["index_name"]: g for g in table.gsi}
    assert gsis["ByTicketCreatedAt"]["partition_key"] == "ticket_id"
    assert gsis["ByTicketCreatedAt"]["sort_key"] == "created_at"
    assert gsis["ByActorCreatedAt"]["partition_key"] == "actor_user_id"
    assert gsis["ByActorCreatedAt"]["sort_key"] == "created_at"
    assert gsis["ByActionCreatedAt"]["partition_key"] == "action"
    assert gsis["ByActionCreatedAt"]["sort_key"] == "created_at"

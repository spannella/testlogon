from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_message_compliance_exports", path)
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


def test_message_compliance_exports_table_schema_and_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.message_compliance_exports_table_name, "MessageComplianceExports")

    assert table.partition_key == "export_id"
    assert table.sort_key is None

    gsis = {g["index_name"]: g for g in table.gsi}
    assert "ByCaseCreatedAt" in gsis
    assert gsis["ByCaseCreatedAt"]["partition_key"] == "case_id"
    assert gsis["ByCaseCreatedAt"]["sort_key"] == "created_at"

    assert "ByStatusCreatedAt" in gsis
    assert gsis["ByStatusCreatedAt"]["partition_key"] == "status"
    assert gsis["ByStatusCreatedAt"]["sort_key"] == "created_at"

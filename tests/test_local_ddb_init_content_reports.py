from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_content_reports", path)
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


def test_content_reports_table_schema_and_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.content_reports_table_name, "ContentReports")

    assert table.partition_key == "report_id"
    assert table.sort_key is None

    gsis = {g["index_name"]: g for g in table.gsi}
    assert gsis["ByContentCreatedAt"]["partition_key"] == "content_ref"
    assert gsis["ByContentCreatedAt"]["sort_key"] == "created_at"

    assert gsis["ByReporterCreatedAt"]["partition_key"] == "reporter_user_id"
    assert gsis["ByReporterCreatedAt"]["sort_key"] == "created_at"

    assert gsis["ByCreatedAt"]["partition_key"] == "created_scope"
    assert gsis["ByCreatedAt"]["sort_key"] == "created_at"

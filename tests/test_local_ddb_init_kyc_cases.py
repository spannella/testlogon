from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_kyc_cases", path)
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


def test_kyc_cases_table_schema_and_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.kyc_cases_table_name, "kyc_cases")

    assert table.partition_key == "pk"
    assert table.sort_key == "sk"

    gsis = {g["index_name"]: g for g in table.gsi}
    assert gsis[mod.S.kyc_cases_owner_index_name]["partition_key"] == "gsi_owner_pk"
    assert gsis[mod.S.kyc_cases_owner_index_name]["sort_key"] == "gsi_owner_sk"

    assert gsis[mod.S.kyc_cases_status_index_name]["partition_key"] == "gsi_status_pk"
    assert gsis[mod.S.kyc_cases_status_index_name]["sort_key"] == "gsi_status_sk"

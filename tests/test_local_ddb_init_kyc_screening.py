"""Regression guard for GAP-0260 (KYC-006).

The kyc_screening_results table has two GSIs (ByUserSub, ByStatus) that both use
``created_at`` as their numeric sort key. If ``attr_types={"created_at": "N"}`` is
removed from the TableDef, DynamoDB Local stores ``created_at`` as a String, which
silently corrupts numeric ``ScanIndexForward`` ordering and breaks range queries
(and raises a ValidationException on integer writes in real DynamoDB).

This test fails if the declaration is ever removed or changed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_kyc_screening", path)
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


def test_kyc_screening_results_created_at_declared_as_number() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.kyc_screening_results_table_name, "kyc_screening_results")

    # PK/SK are string-typed and need no attr_types override.
    assert table.partition_key == "case_id"
    assert table.sort_key == "screen_key"

    # Both GSIs use created_at as their numeric sort key.
    gsis = {g["index_name"]: g for g in table.gsi}
    assert gsis[mod.S.kyc_screening_user_index_name]["partition_key"] == "user_sub"
    assert gsis[mod.S.kyc_screening_user_index_name]["sort_key"] == "created_at"
    assert gsis[mod.S.kyc_screening_status_index_name]["partition_key"] == "result"
    assert gsis[mod.S.kyc_screening_status_index_name]["sort_key"] == "created_at"

    # The numeric GSI sort key must be declared as Number ("N").
    assert "created_at" in table.attr_types, (
        "kyc_screening_results TableDef missing attr_types for created_at; "
        "add attr_types={'created_at': 'N'} to prevent GSI sort-key type mismatch"
    )
    assert table.attr_types["created_at"] == "N"

    # attr_types must list ONLY key attrs (here, the single numeric GSI sort key).
    assert set(table.attr_types) == {"created_at"}

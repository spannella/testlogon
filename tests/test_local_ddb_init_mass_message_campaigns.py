from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_mass_message_campaigns", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
    except ModuleNotFoundError as exc:
        if exc.name == "boto3":
            pytest.skip("boto3 not installed in test environment")
        raise
    return mod


def _table_for(mod, table_name: str, fallback_name: str):
    for t in mod._table_defs():
        if t.name in {table_name, fallback_name}:
            return t
    raise AssertionError(f"table not found: {table_name} / {fallback_name}")


def test_mass_message_campaigns_table_schema_and_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.mass_message_campaigns_table_name, "MassMessageCampaigns")

    assert table.partition_key == "campaign_id"
    assert table.sort_key is None

    gsis = {g["index_name"]: g for g in table.gsi}
    assert gsis["BySenderCreatedAt"]["partition_key"] == "sender_id"
    assert gsis["BySenderCreatedAt"]["sort_key"] == "created_at"

    assert gsis["ByStatusSendAt"]["partition_key"] == "status"
    assert gsis["ByStatusSendAt"]["sort_key"] == "send_at"

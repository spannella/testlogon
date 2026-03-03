from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_message_archive_chain_heads", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _table_for(mod, resolved_name: str, fallback: str):
    defs = mod._table_defs()
    target = mod._resolve_table_name(resolved_name, fallback)
    return next(t for t in defs if t.name in {target, fallback})


def test_chain_heads_table_def_exists_with_partition_only_key():
    mod = _load_module()
    table = _table_for(mod, mod.S.message_archive_chain_heads_table_name, "MessageArchiveChainHeads")

    assert table.partition_key == "partition_key"
    assert table.sort_key is None


def test_chain_heads_table_has_no_gsi_requirements():
    mod = _load_module()
    table = _table_for(mod, mod.S.message_archive_chain_heads_table_name, "MessageArchiveChainHeads")

    assert table.gsi == []

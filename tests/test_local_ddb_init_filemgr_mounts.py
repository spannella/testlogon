from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_filemgr_mounts_table_has_owner_path_index() -> None:
    mod = _load_module()
    defs = mod._table_defs()
    mount_tbl_name = mod._resolve_table_name(mod.S.filemgr_mounts_table_name, "filemgr_mounts")
    table = next(t for t in defs if t.name in {mount_tbl_name, "filemgr_mounts"})
    idx = {g["index_name"] for g in table.gsi}
    assert "GSI1" in idx
    gsi1 = next(g for g in table.gsi if g["index_name"] == "GSI1")
    assert gsi1["partition_key"] == "gsi_owner_pk"
    assert gsi1["sort_key"] == "gsi_owner_sk"

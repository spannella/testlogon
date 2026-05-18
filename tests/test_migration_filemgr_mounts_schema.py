from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


def _load_module():
    path = Path("scripts/migrations/20260306_filemgr_mounts_schema.py").resolve()
    spec = importlib.util.spec_from_file_location("mig_filemgr_mounts", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_migration_creates_table_with_owner_path_index() -> None:
    mod = _load_module()

    class _Client:
        def __init__(self):
            self.created = None

        def list_tables(self):
            return {"TableNames": []}

        def create_table(self, **kwargs):
            self.created = kwargs

    class _Meta:
        def __init__(self):
            self.client = _Client()

    class _Ddb:
        def __init__(self):
            self.meta = _Meta()

    fake_ddb = _Ddb()
    mod.ddb = fake_ddb
    mod.S = SimpleNamespace(filemgr_mounts_table_name="filemgr_mounts")

    mod.migrate()

    created = fake_ddb.meta.client.created
    assert created is not None
    assert created["TableName"] == "filemgr_mounts"
    assert any(g["IndexName"] == "GSI1" for g in created["GlobalSecondaryIndexes"])

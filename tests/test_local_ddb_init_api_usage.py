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


def test_api_usage_table_def_has_required_indexes() -> None:
    mod = _load_module()
    defs = mod._table_defs()
    api = next(t for t in defs if t.name in {mod._resolve_table_name(mod.S.api_usage_table_name, "api_usage_events"), "api_usage_events"})
    idx = {g["index_name"] for g in api.gsi}
    assert {"GSI_PERIOD", "GSI_API_KEY", "GSI_ROUTE"}.issubset(idx)


def test_enable_ttl_is_safe_when_api_not_supported() -> None:
    mod = _load_module()

    class _Client:
        def describe_time_to_live(self, **_kwargs):
            raise mod.ClientError({"Error": {"Code": "UnknownOperationException"}}, "DescribeTimeToLive")

        def update_time_to_live(self, **_kwargs):
            raise mod.ClientError({"Error": {"Code": "UnknownOperationException"}}, "UpdateTimeToLive")

    class _Meta:
        client = _Client()

    class _Ddb:
        meta = _Meta()

    mod._enable_ttl_if_needed(_Ddb(), "api_usage_events")

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_commercialization", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _table_for(mod, resolved_name: str, fallback: str):
    target = mod._resolve_table_name(resolved_name, fallback)
    defs = mod._table_defs()
    return next(t for t in defs if t.name in {target, fallback})


def test_commercialization_table_defs_exist() -> None:
    mod = _load_module()
    assert _table_for(mod, mod.S.catalog_products_table_name, "catalog_products")
    assert _table_for(mod, mod.S.catalog_product_versions_table_name, "catalog_product_versions")
    assert _table_for(mod, mod.S.orders_table_name, "orders")
    assert _table_for(mod, mod.S.order_items_table_name, "order_items")
    assert _table_for(mod, mod.S.payments_table_name, "payments")
    assert _table_for(mod, mod.S.entitlements_table_name, "entitlements")
    assert _table_for(mod, mod.S.entitlement_usage_events_table_name, "entitlement_usage_events")


def test_critical_gsis_and_idempotency_indexes_present() -> None:
    mod = _load_module()

    payments = _table_for(mod, mod.S.payments_table_name, "payments")
    p_idx = {g["index_name"] for g in payments.gsi}
    assert {"GSI_ORDER", "GSI_PROVIDER_EVENT_IDEMPOTENCY"}.issubset(p_idx)

    entitlements = _table_for(mod, mod.S.entitlements_table_name, "entitlements")
    e_idx = {g["index_name"] for g in entitlements.gsi}
    assert {"GSI_STATUS", "GSI_SKU"}.issubset(e_idx)

    usage = _table_for(mod, mod.S.entitlement_usage_events_table_name, "entitlement_usage_events")
    u_idx = {g["index_name"] for g in usage.gsi}
    assert {"GSI_IDEMPOTENCY", "GSI_TIMESTAMP"}.issubset(u_idx)

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_moderation_tickets", path)
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


def test_moderation_tickets_table_schema_and_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.moderation_tickets_table_name, "ModerationTickets")

    assert table.partition_key == "ticket_id"
    assert table.sort_key is None

    gsis = {g["index_name"]: g for g in table.gsi}
    assert gsis["ByStatusLatestReportAt"]["partition_key"] == "status"
    assert gsis["ByStatusLatestReportAt"]["sort_key"] == "latest_report_at"

    assert gsis["ByQueueLatestReportAt"]["partition_key"] == "queue"
    assert gsis["ByQueueLatestReportAt"]["sort_key"] == "latest_report_at"

    assert gsis["ByAssignedAdminLatestReportAt"]["partition_key"] == "assigned_admin_user_id"
    assert gsis["ByAssignedAdminLatestReportAt"]["sort_key"] == "latest_report_at"

    assert gsis["ByLatestReportAt"]["partition_key"] == "latest_report_scope"
    assert gsis["ByLatestReportAt"]["sort_key"] == "latest_report_at"


    assert gsis["ByContentStatusLatestReportAt"]["partition_key"] == "content_ref_status"
    assert gsis["ByContentStatusLatestReportAt"]["sort_key"] == "latest_report_at"

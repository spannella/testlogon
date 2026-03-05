from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_message_reports", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _table_for(mod, resolved_name: str, fallback: str):
    defs = mod._table_defs()
    target = mod._resolve_table_name(resolved_name, fallback)
    return next(t for t in defs if t.name in {target, fallback})


def test_message_reports_table_schema_and_indexes() -> None:
    mod = _load_module()
    table = _table_for(mod, mod.S.message_reports_table_name, "MessageReports")

    assert table.partition_key == "report_id"
    assert table.sort_key is None

    indexes = {g["index_name"]: g for g in table.gsi}

    by_conversation = indexes["ByConversationCreatedAt"]
    assert by_conversation["partition_key"] == "conversation_id"
    assert by_conversation["sort_key"] == "created_at"

    by_status = indexes["ByStatusCreatedAt"]
    assert by_status["partition_key"] == "status"
    assert by_status["sort_key"] == "created_at"

    by_reporter = indexes["ByReporterCreatedAt"]
    assert by_reporter["partition_key"] == "reported_by_user_id"
    assert by_reporter["sort_key"] == "created_at"


def test_message_report_context_linkage_table_exists() -> None:
    mod = _load_module()
    context = _table_for(mod, mod.S.message_report_context_table_name, "MessageReportContext")

    assert context.partition_key == "report_id"
    assert context.sort_key == "message_id"

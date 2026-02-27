from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from app.services import signature_packet_store as store
from app.services.signature_packet_domain import SignatureSignerStatus


def _load_local_ddb_init_module():
    path = Path("scripts/local-ddb-init.py").resolve()
    spec = importlib.util.spec_from_file_location("local_ddb_init_signature", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_signature_packet_table_defs_have_required_indexes() -> None:
    mod = _load_local_ddb_init_module()
    defs = mod._table_defs()

    packets = next(
        t
        for t in defs
        if t.name in {mod._resolve_table_name(mod.S.signature_packets_table_name, "signature_packets"), "signature_packets"}
    )
    signers = next(
        t
        for t in defs
        if t.name
        in {
            mod._resolve_table_name(mod.S.signature_packet_signers_table_name, "signature_packet_signers"),
            "signature_packet_signers",
        }
    )

    packet_indexes = {g["index_name"] for g in packets.gsi}
    signer_indexes = {g["index_name"] for g in signers.gsi}

    assert "OWNER_CREATED_INDEX" in packet_indexes
    assert "SIGNER_STATUS_INDEX" in signer_indexes


def test_load_packet_aggregate_queries_all_packet_tables(monkeypatch) -> None:
    class _QueryTable:
        def __init__(self, items):
            self._items = items

        def query(self, **_kwargs):
            return {"Items": self._items}

    class _GetTable:
        def __init__(self, item):
            self._item = item

        def get_item(self, **_kwargs):
            return {"Item": self._item}

    class _Tables:
        signature_packets = _GetTable({"packet_id": "pkt-1"})
        signature_packet_signers = _QueryTable([{"packet_id": "pkt-1", "signer_id": "user-2"}])
        signature_packet_fields = _QueryTable([{"packet_id": "pkt-1", "field_id": "field-1"}])
        signature_packet_events = _QueryTable([{"packet_id": "pkt-1", "event_id": "evt-1"}])
        signature_packet_artifacts = _GetTable({"packet_id": "pkt-1", "final_pdf_file_id": "file-99"})

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    result = store.load_packet_aggregate("pkt-1")

    assert result["packet"]["packet_id"] == "pkt-1"
    assert result["signers"][0]["signer_id"] == "user-2"
    assert result["fields"][0]["field_id"] == "field-1"
    assert result["events"][0]["event_id"] == "evt-1"
    assert result["artifact"]["final_pdf_file_id"] == "file-99"


def test_list_packets_for_signer_uses_canonical_signer_status(monkeypatch) -> None:
    captured = {}

    class _SignerTable:
        def query(self, **kwargs):
            captured.update(kwargs)
            return {"Items": []}

    class _Tables:
        signature_packet_signers = _SignerTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)
    store.list_packets_for_signer("user-2", SignatureSignerStatus.PENDING)

    assert captured["IndexName"] == store.SIGNER_STATUS_INDEX
    expr = captured["KeyConditionExpression"]
    equals_expr, begins_with_expr = expr._values
    assert equals_expr._values[0].name == "signer_id"
    assert equals_expr._values[1] == "user-2"
    assert begins_with_expr._values[0].name == "status_key"
    assert begins_with_expr._values[1] == "pending#"

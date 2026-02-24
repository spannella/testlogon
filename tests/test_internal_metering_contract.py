from __future__ import annotations

import pytest

from app.services import internal_metering_contract as contract


def test_namespace_action_mapping_is_deterministic() -> None:
    m = contract.resolve_meter_binding("messaging", "send_message")
    assert m.meter == "messaging.message.send.count"

    f = contract.resolve_meter_binding("filemanager", "download_file")
    assert f.meter == "filemanager.file.download.bytes"


def test_unknown_namespace_action_rejected() -> None:
    with pytest.raises(ValueError, match="unknown internal metering action"):
        contract.resolve_meter_binding("messaging", "unknown")


def test_route_mapping_for_messaging_and_filemanager() -> None:
    m = contract.resolve_route_meter_binding("POST:/messaging/conversations/{conversation_id}/messages")
    assert m is not None
    assert m.namespace == "messaging"
    assert m.action == "send_message"

    f = contract.resolve_route_meter_binding("GET:/v1/fs/download")
    assert f is not None
    assert f.namespace == "filemanager"
    assert f.action == "download_file"


def test_identity_propagation_validation() -> None:
    ok = contract.validate_identity_propagation(
        {
            "x-user-sub": "u1",
            "x-service-name": "gateway",
            "x-service-request-id": "req-1",
        }
    )
    assert ok["ok"] is True
    assert ok["missing"] == []

    bad = contract.validate_identity_propagation({"x-user-sub": "u1"})
    assert bad["ok"] is False
    assert set(bad["missing"]) == {"x-service-name", "x-service-request-id"}


def test_contract_snapshot_contains_expected_namespaces() -> None:
    snap = contract.contract_snapshot()
    meters = {row["meter"] for row in snap["operation_bindings"]}
    assert "messaging.message.send.count" in meters
    assert "filemanager.file.download.bytes" in meters

from __future__ import annotations

import ast
from pathlib import Path


def _load_turn_status_map() -> dict[str, int]:
    source = Path("app/routers/messaging.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "TURN_CREDENTIAL_ERROR_STATUS_MAP":
                    return ast.literal_eval(node.value)
    raise AssertionError("TURN_CREDENTIAL_ERROR_STATUS_MAP was not found")


def _load_turn_response_statuses() -> set[int]:
    source = Path("app/routers/messaging.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "TURN_CREDENTIAL_ENDPOINT_RESPONSES":
                    if not isinstance(node.value, ast.Dict):
                        raise AssertionError("TURN_CREDENTIAL_ENDPOINT_RESPONSES must be a dict")
                    statuses: set[int] = set()
                    for key_node in node.value.keys:
                        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, int):
                            statuses.add(key_node.value)
                    return statuses
    raise AssertionError("TURN_CREDENTIAL_ENDPOINT_RESPONSES was not found")


def test_turn_credential_error_status_map_includes_extended_error_codes():
    status_map = _load_turn_status_map()
    assert status_map["turn_invalid_url"] == 503
    assert status_map["turn_invalid_ttl"] == 503
    assert status_map["participant_lookup_failed"] == 503
    assert status_map["call_participant_mismatch"] == 409
    assert status_map["validation_error"] == 400


def test_turn_credential_endpoint_responses_cover_all_mapped_status_codes():
    statuses = _load_turn_response_statuses()
    assert {400, 403, 404, 409, 503}.issubset(statuses)

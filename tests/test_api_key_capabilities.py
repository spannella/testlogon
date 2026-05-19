from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.api_key_capabilities import (
    CAPABILITY_IMPLICATIONS,
    CANONICAL_API_KEY_CAPABILITIES,
    expand_api_key_capabilities,
    is_known_api_key_capability,
    normalize_api_key_capabilities,
    normalize_capability_name,
)


def test_canonical_api_key_capability_list_is_deterministic() -> None:
    assert CANONICAL_API_KEY_CAPABILITIES == tuple(sorted(CANONICAL_API_KEY_CAPABILITIES))
    assert len(CANONICAL_API_KEY_CAPABILITIES) == len(set(CANONICAL_API_KEY_CAPABILITIES))


def test_normalize_capability_name_trims_and_lowercases() -> None:
    assert normalize_capability_name("  Shopping:Orders:Read  ") == "shopping:orders:read"
    assert normalize_capability_name(None) == ""


def test_is_known_api_key_capability() -> None:
    assert is_known_api_key_capability("tickets:read")
    assert is_known_api_key_capability("  TICKETS:READ  ")
    assert not is_known_api_key_capability("tickets:delete")


def test_normalize_api_key_capabilities_returns_unique_sorted_values() -> None:
    assert normalize_api_key_capabilities(["tickets:read", " TICKETS:READ ", "messager:write"]) == [
        "messager:write",
        "tickets:read",
    ]


def test_normalize_api_key_capabilities_rejects_unknown_values() -> None:
    with pytest.raises(ValueError, match="unknown api key capability"):
        normalize_api_key_capabilities(["shopping:refund:write"])


def test_expand_api_key_capabilities_applies_broader_scope_implications() -> None:
    expanded = expand_api_key_capabilities(["filemanager:admin", "tickets:admin"])
    assert "filemanager:read" in expanded
    assert "filemanager:write" in expanded
    assert "filemanager:share" in expanded
    assert "tickets:read" in expanded
    assert "tickets:write" in expanded


def test_capability_contract_file_matches_python_constants() -> None:
    contract = json.loads(Path("docs/api-key-capability-contract-v1.json").read_text())
    assert contract["capabilities"] == list(CANONICAL_API_KEY_CAPABILITIES)
    assert contract["deny_by_default_unmapped_routes"] is True
    assert contract["implications"] == {k: list(v) for k, v in CAPABILITY_IMPLICATIONS.items()}

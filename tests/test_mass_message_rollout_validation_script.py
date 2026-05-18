from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import Mock, patch


def _load_module():
    path = Path("scripts/check_mass_message_rollout_validation.py")
    spec = importlib.util.spec_from_file_location("check_mass_message_rollout_validation", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_validate_schema_passes_when_required_indexes_exist():
    mod = _load_module()
    client = Mock()
    client.describe_table.side_effect = [
        {
            "Table": {
                "KeySchema": [{"AttributeName": "campaign_id", "KeyType": "HASH"}],
                "GlobalSecondaryIndexes": [{"IndexName": "BySenderCreatedAt"}, {"IndexName": "ByStatusSendAt"}],
            }
        },
        {
            "Table": {
                "KeySchema": [
                    {"AttributeName": "campaign_id", "KeyType": "HASH"},
                    {"AttributeName": "conversation_id", "KeyType": "RANGE"},
                ],
                "GlobalSecondaryIndexes": [{"IndexName": "ByCampaignStateUpdatedAt"}],
            }
        },
    ]
    with patch.object(mod, "_ddb_client", return_value=client):
        failures = mod.validate_schema()
    assert failures == []


def test_validate_schema_reports_missing_index():
    mod = _load_module()
    client = Mock()
    client.describe_table.side_effect = [
        {
            "Table": {
                "KeySchema": [{"AttributeName": "campaign_id", "KeyType": "HASH"}],
                "GlobalSecondaryIndexes": [{"IndexName": "BySenderCreatedAt"}],
            }
        },
        {
            "Table": {
                "KeySchema": [
                    {"AttributeName": "campaign_id", "KeyType": "HASH"},
                    {"AttributeName": "conversation_id", "KeyType": "RANGE"},
                ],
                "GlobalSecondaryIndexes": [{"IndexName": "ByCampaignStateUpdatedAt"}],
            }
        },
    ]
    with patch.object(mod, "_ddb_client", return_value=client):
        failures = mod.validate_schema()
    assert len(failures) == 1
    assert failures[0].check.startswith("table:")
    assert "ByStatusSendAt" in failures[0].reason


def test_main_passes_when_schema_ok_and_endpoint_checks_skipped():
    mod = _load_module()
    with (
        patch.object(mod, "validate_schema", return_value=[]),
        patch("sys.argv", ["check_mass_message_rollout_validation.py", "--skip-endpoint-checks"]),
    ):
        code = mod.main()
    assert code == 0

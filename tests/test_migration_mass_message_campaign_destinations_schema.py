from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _load_module():
    path = Path("scripts/migrations/20260405_mass_message_campaign_destinations_schema.py").resolve()
    spec = importlib.util.spec_from_file_location("migration_mass_message_campaign_destinations_schema", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_migrate_creates_table_with_required_keys_and_gsi() -> None:
    mod = _load_module()
    client = MagicMock()
    client.list_tables.return_value = {"TableNames": []}
    with patch.object(mod, "_ddb_client", return_value=client), patch.object(
        mod, "_table_name", return_value="MassMessageCampaignDestinations"
    ):
        mod.migrate()

    client.create_table.assert_called_once()
    kwargs = client.create_table.call_args.kwargs
    assert kwargs["TableName"] == "MassMessageCampaignDestinations"
    assert kwargs["KeySchema"] == [
        {"AttributeName": "campaign_id", "KeyType": "HASH"},
        {"AttributeName": "conversation_id", "KeyType": "RANGE"},
    ]
    gsi_names = {g["IndexName"] for g in kwargs["GlobalSecondaryIndexes"]}
    assert "ByCampaignStateUpdatedAt" in gsi_names


def test_migrate_is_noop_when_table_exists() -> None:
    mod = _load_module()
    client = MagicMock()
    client.list_tables.return_value = {"TableNames": ["MassMessageCampaignDestinations"]}
    with patch.object(mod, "_ddb_client", return_value=client), patch.object(
        mod, "_table_name", return_value="MassMessageCampaignDestinations"
    ):
        mod.migrate()
    client.create_table.assert_not_called()


def test_rollback_requires_opt_in() -> None:
    mod = _load_module()
    client = MagicMock()
    client.list_tables.return_value = {"TableNames": ["MassMessageCampaignDestinations"]}
    with patch.object(mod, "_ddb_client", return_value=client), patch.object(
        mod, "_table_name", return_value="MassMessageCampaignDestinations"
    ):
        with pytest.raises(RuntimeError, match="explicit opt-in"):
            mod.rollback()


def test_rollback_deletes_table_when_allowed_non_prod() -> None:
    mod = _load_module()
    client = MagicMock()
    client.list_tables.return_value = {"TableNames": ["MassMessageCampaignDestinations"]}
    env = {"APP_ENV": "staging", "MASS_MESSAGE_MIGRATION_ALLOW_ROLLBACK": "1"}
    with patch.dict(os.environ, env, clear=False), patch.object(
        mod, "_ddb_client", return_value=client
    ), patch.object(mod, "_table_name", return_value="MassMessageCampaignDestinations"):
        mod.rollback()
    client.delete_table.assert_called_once_with(TableName="MassMessageCampaignDestinations")


def test_rollback_blocked_in_production() -> None:
    mod = _load_module()
    client = MagicMock()
    client.list_tables.return_value = {"TableNames": ["MassMessageCampaignDestinations"]}
    env = {"APP_ENV": "production", "MASS_MESSAGE_MIGRATION_ALLOW_ROLLBACK": "1"}
    with patch.dict(os.environ, env, clear=False), patch.object(
        mod, "_ddb_client", return_value=client
    ), patch.object(mod, "_table_name", return_value="MassMessageCampaignDestinations"):
        with pytest.raises(RuntimeError, match="blocked in production"):
            mod.rollback()

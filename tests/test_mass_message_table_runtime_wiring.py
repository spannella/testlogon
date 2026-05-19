from __future__ import annotations

import importlib
import os
import sys
import types
from unittest.mock import patch


def _reload_settings_module():
    mod = importlib.import_module("app.core.settings")
    original_S = mod.S
    reloaded = importlib.reload(mod)
    try:
        return reloaded
    finally:
        mod.S = original_S


def test_settings_defaults_mass_message_table_names() -> None:
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("DDB_MASS_MESSAGE_CAMPAIGNS", None)
        os.environ.pop("DDB_MASS_MESSAGE_CAMPAIGN_DESTINATIONS", None)
        mod = importlib.import_module("app.core.settings")
        original_S = mod.S
        reloaded = importlib.reload(mod)
        try:
            settings = reloaded.Settings()
            assert settings.mass_message_campaigns_table_name == "MassMessageCampaigns"
            assert settings.mass_message_campaign_destinations_table_name == "MassMessageCampaignDestinations"
        finally:
            mod.S = original_S


def test_settings_override_mass_message_table_names() -> None:
    env = {
        "DDB_MASS_MESSAGE_CAMPAIGNS": "CampaignsCustom",
        "DDB_MASS_MESSAGE_CAMPAIGN_DESTINATIONS": "DestinationsCustom",
    }
    with patch.dict(os.environ, env, clear=False):
        mod = importlib.import_module("app.core.settings")
        original_S = mod.S
        reloaded = importlib.reload(mod)
        try:
            settings = reloaded.Settings()
            assert settings.mass_message_campaigns_table_name == "CampaignsCustom"
            assert settings.mass_message_campaign_destinations_table_name == "DestinationsCustom"
        finally:
            mod.S = original_S


def test_table_registry_exposes_mass_message_handles() -> None:
    class DummyS:
        def __getattr__(self, name: str):
            return name

    class DummyDdb:
        @staticmethod
        def Table(name: str):
            return f"table::{name}"

    fake_settings = types.ModuleType("app.core.settings")
    fake_settings.S = DummyS()
    fake_aws = types.ModuleType("app.core.aws")
    fake_aws.ddb = DummyDdb()

    original_tables_mod = sys.modules.get("app.core.tables")
    with patch.dict(sys.modules, {"app.core.settings": fake_settings, "app.core.aws": fake_aws}, clear=False):
        sys.modules.pop("app.core.tables", None)
        tables_mod = importlib.import_module("app.core.tables")
        assert hasattr(tables_mod.T, "mass_message_campaigns")
        assert hasattr(tables_mod.T, "mass_message_campaign_destinations")
        assert tables_mod.T.mass_message_campaigns == "table::mass_message_campaigns_table_name"
        assert tables_mod.T.mass_message_campaign_destinations == "table::mass_message_campaign_destinations_table_name"
    if original_tables_mod is not None:
        sys.modules["app.core.tables"] = original_tables_mod
        importlib.reload(original_tables_mod)

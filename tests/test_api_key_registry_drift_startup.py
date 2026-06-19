from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from app.main import create_app

# All boolean feature flags that create_app() reads from _S; set to False so the
# SimpleNamespace mock doesn't raise AttributeError as main.py adds new flag checks.
_ALL_FLAGS_OFF: dict = {
    "multi_tenancy_enabled": False,
    "open_bank_project_enabled": False,
    "oauth_provider_enabled": False,
    "oauth_provider_oidc_enabled": False,
    "psd2_consents_enabled": False,
    "dynamic_entities_enabled": False,
    "dynamic_endpoints_enabled": False,
    "open_data_enabled": False,
    "banking_accounts_enabled": False,
    "ticket_boards_enabled": False,
    "crm_workflow_enabled": False,
    "crm_acl_enabled": False,
    "crm_studio_enabled": False,
    "ats_pipeline_enabled": False,
    "broadcast_devtools_enabled": False,
    "filemgr_bucket": "test-bucket",
    "video_upload_bucket": "test-video",
    "vod_output_bucket": "test-vod",
}


def test_create_app_registry_drift_threshold_state_and_warning() -> None:
    with (
        patch("app.main.validate_api_key_rollout_settings"),
        patch("app.main.is_route_registered_or_exempt", return_value=True),
        patch(
            "app.main.summarize_registry_drift",
            return_value={
                "stale_route_count": 4,
                "stale_route_preview": ["GET:/old"],
                "unregistered_live_route_count": 2,
                "unregistered_live_route_preview": ["GET:/v1/fs/unknown"],
            },
        ),
        patch("app.main.record_api_key_registry_drift") as record,
        patch("app.main._S", SimpleNamespace(dev_mode=False, api_key_registry_drift_warn_threshold=2, **_ALL_FLAGS_OFF)),
        patch("app.main.logger.warning") as warn,
    ):
        app = create_app()

    assert app.state.api_key_registry_drift["stale_route_count"] == 4
    assert app.state.api_key_registry_drift["unregistered_live_route_count"] == 2
    assert app.state.api_key_registry_drift["warn_threshold"] == 2
    assert app.state.api_key_registry_drift["warn_threshold_exceeded"] is True
    assert app.state.api_key_registry_drift["status"] == "critical"
    record.assert_called_once_with(stale_route_count=4, unregistered_live_route_count=2)
    assert warn.call_count >= 1


def test_create_app_registry_drift_threshold_not_exceeded() -> None:
    with (
        patch("app.main.validate_api_key_rollout_settings"),
        patch("app.main.is_route_registered_or_exempt", return_value=True),
        patch(
            "app.main.summarize_registry_drift",
            return_value={
                "stale_route_count": 1,
                "stale_route_preview": [],
                "unregistered_live_route_count": 0,
                "unregistered_live_route_preview": [],
            },
        ),
        patch("app.main._S", SimpleNamespace(dev_mode=False, api_key_registry_drift_warn_threshold=3, **_ALL_FLAGS_OFF)),
        patch("app.main.logger.warning") as warn,
    ):
        app = create_app()

    assert app.state.api_key_registry_drift["warn_threshold"] == 3
    assert app.state.api_key_registry_drift["warn_threshold_exceeded"] is False
    assert app.state.api_key_registry_drift["status"] == "ok"
    warn.assert_not_called()

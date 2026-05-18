import json
from pathlib import Path
from unittest.mock import MagicMock

from app import metrics


def test_record_filemgr_provider_operation_includes_mount_and_error_class_labels(monkeypatch):
    total = MagicMock()
    total_labels = MagicMock()
    total.labels.return_value = total_labels

    latency = MagicMock()
    latency_labels = MagicMock()
    latency.labels.return_value = latency_labels
    provider_errors = MagicMock()
    provider_errors_labels = MagicMock()
    provider_errors.labels.return_value = provider_errors_labels

    monkeypatch.setattr(metrics, "FILEMGR_PROVIDER_OPERATION_TOTAL", total)
    monkeypatch.setattr(metrics, "FILEMGR_PROVIDER_OPERATION_LATENCY", latency)
    monkeypatch.setattr(metrics, "FILEMGR_PROVIDER_ERRORS_TOTAL", provider_errors)

    metrics.record_filemgr_provider_operation(
        operation="read",
        provider="icloud",
        mount_id="m-123",
        mounted=True,
        elapsed_seconds=0.25,
        outcome="failure",
        error_class="server_error",
    )

    total.labels.assert_called_once_with(
        operation="read",
        provider="icloud",
        mount_id="m-123",
        mounted="true",
        outcome="failure",
        error_class="server_error",
    )
    total_labels.inc.assert_called_once()

    latency.labels.assert_called_once_with(
        operation="read",
        provider="icloud",
        mount_id="m-123",
        mounted="true",
        error_class="server_error",
    )
    latency_labels.observe.assert_called_once_with(0.25)
    provider_errors.labels.assert_called_once_with(
        operation="read",
        provider="icloud",
        mount_id="m-123",
        error_class="server_error",
    )
    provider_errors_labels.inc.assert_called_once()


def test_provider_dashboard_contains_latency_error_alerts_and_runbooks():
    doc = json.loads(Path("docs/dashboards/filemanager-provider-ops-dashboard.json").read_text(encoding="utf-8"))
    blob = json.dumps(doc)

    assert "histogram_quantile(0.50" in blob
    assert "histogram_quantile(0.95" in blob
    assert "filemgr_provider_auth_failures_total" in blob
    assert "filemgr_mount_rollout_decisions_total" in blob
    assert "filemgr_mount_reconcile_runs_total" in blob
    assert "filemgr_mount_reconcile_duration_seconds_bucket" in blob
    assert "error_class=\\\"server_error\\\"" in blob

    alerts = doc.get("alerts") or []
    assert any(a.get("name") == "FilemanagerProviderSustainedAuthFailures" for a in alerts)
    assert any(a.get("name") == "FilemanagerProviderHigh5xxRate" for a in alerts)
    assert any(a.get("name") == "FilemanagerICloudRolloutDenySpike" for a in alerts)
    assert any(a.get("name") == "FilemanagerMountReconcileErrorRate" for a in alerts)

    assert "runbook" in (doc.get("description") or "").lower()
    assert doc.get("runbook_url")
    for panel in doc.get("panels", []):
        if panel.get("title") in {
            "Operation volume by provider/mount",
            "Provider latency p50 by operation/mount",
            "Provider latency p95 by operation/mount",
            "Provider error rate by class",
            "Provider 5xx rate",
            "Provider auth failures",
            "iCloud rollout decisions by reason/cohort",
            "iCloud rollout deny ratio",
            "Mount reconcile batch outcomes",
            "Mount reconcile drift items by type",
            "Mount reconcile p95 duration",
        }:
            assert "runbook" in (panel.get("description") or "").lower()


def test_record_filemgr_mount_rollout_decision_labels(monkeypatch):
    rollout = MagicMock()
    rollout_labels = MagicMock()
    rollout.labels.return_value = rollout_labels
    monkeypatch.setattr(metrics, "FILEMGR_MOUNT_ROLLOUT_DECISIONS", rollout)

    metrics.record_filemgr_mount_rollout_decision(
        provider="icloud",
        environment="prod",
        mode="beta",
        cohort="tenant_override",
        reason="tenant_allowlist",
    )

    rollout.labels.assert_called_once_with(
        provider="icloud",
        environment="prod",
        mode="beta",
        cohort="tenant_override",
        reason="tenant_allowlist",
    )
    rollout_labels.inc.assert_called_once()

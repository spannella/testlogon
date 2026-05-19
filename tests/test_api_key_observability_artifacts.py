from __future__ import annotations

import json
from pathlib import Path


def test_api_key_dashboard_contract_contains_required_segment_panels() -> None:
    path = Path("docs/dashboards/api-key-product-usage-dashboard.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    dashboard = payload["dashboard"]
    panels = dashboard["panels"]
    exprs = "\n".join(str(panel.get("expr") or "") for panel in panels)

    assert "product" in exprs
    assert "route_id" in exprs
    assert "api_key_id" in exprs
    assert "status_class" in exprs
    assert "api_key_registry_drift_routes" in exprs
    assert "api_key_registry_unregistered_live_routes" in exprs


def test_api_key_alert_rules_include_401_403_and_suspicious_activity() -> None:
    path = Path("docs/alerts/api-key-observability-alerts.yaml")
    text = path.read_text(encoding="utf-8")

    assert "alert: ApiKey401Spike" in text
    assert "alert: ApiKey403Spike" in text
    assert "alert: ApiKeySuspiciousActivity" in text
    assert "alert: ApiKeyRegistryCoverageDrift" in text
    assert "runbook: \"docs/api-key-observability-runbook.md" in text


def test_api_key_runbook_includes_triage_and_rollback_guidance() -> None:
    path = Path("docs/api-key-observability-runbook.md")
    text = path.read_text(encoding="utf-8")

    assert "## Triage: authentication spike (401)" in text
    assert "## Triage: authorization/entitlement spike (403)" in text
    assert "## Triage: suspicious key activity" in text
    assert "## Rollback guidance" in text

from __future__ import annotations

from pathlib import Path


def test_broadcast_alert_rules_include_nonprod_route_label() -> None:
    p = Path("docs/alerts/broadcast-health-alerts.yml")
    text = p.read_text(encoding="utf-8")
    assert "route: nonprod-oncall" in text
    assert "BroadcastProvisioningLatencyHigh" in text


def test_broadcast_dashboard_includes_provider_dimension_queries() -> None:
    p = Path("docs/dashboards/broadcast-health-dashboard.json")
    text = p.read_text(encoding="utf-8")
    assert "provider" in text
    assert "broadcast_provision_latency_seconds" in text

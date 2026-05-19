from __future__ import annotations

from pathlib import Path


MODULE_DIR = Path("infra/terraform/video_observability")


def test_video_observability_module_files_exist() -> None:
    for name in ("main.tf", "variables.tf", "outputs.tf", "README.md"):
        assert (MODULE_DIR / name).exists()


def test_main_tf_contains_dashboard_alarms_and_alert_routing() -> None:
    text = (MODULE_DIR / "main.tf").read_text(encoding="utf-8")
    assert "resource \"aws_cloudwatch_dashboard\" \"video_health\"" in text
    assert "resource \"aws_cloudwatch_metric_alarm\" \"channel_state_alarm\"" in text
    assert "resource \"aws_cloudwatch_metric_alarm\" \"input_loss_alarm\"" in text
    assert "resource \"aws_cloudwatch_metric_alarm\" \"output_error_alarm\"" in text
    assert "resource \"aws_cloudwatch_metric_alarm\" \"drm_key_error_alarm\"" in text
    assert "resource \"aws_sns_topic\" \"video_alerts_warning\"" in text
    assert "resource \"aws_sns_topic\" \"video_alerts_critical\"" in text
    assert "resource \"aws_sns_topic_subscription\" \"critical_escalation_webhook\"" in text


def test_alarm_descriptions_include_runbook_and_escalation_links() -> None:
    text = (MODULE_DIR / "main.tf").read_text(encoding="utf-8")
    assert "Runbook:" in text
    assert "Escalation:" in text
    assert "escalation_policy_url" in text


def test_readme_mentions_actionable_oncall_alerting() -> None:
    text = (MODULE_DIR / "README.md").read_text(encoding="utf-8")
    assert "runbook links" in text.lower()
    assert "escalation" in text.lower()
    assert "critical" in text.lower()

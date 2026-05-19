from __future__ import annotations

from pathlib import Path


def test_video_ops_runbook_contains_critical_playbooks() -> None:
    text = Path("docs/video-ops-runbook.md").read_text(encoding="utf-8")
    assert "Channel restart runbook" in text
    assert "Input failover runbook" in text
    assert "DRM key/license fallback runbook" in text
    assert "Recovery target" in text
    assert "Escalation" in text


def test_video_rollout_checklist_contains_staged_gates_and_rollback() -> None:
    text = Path("docs/video-rollout-checklist.md").read_text(encoding="utf-8")
    assert "Phase A — Internal" in text
    assert "Phase B — Pilot tenants" in text
    assert "Phase C — General Availability (GA)" in text
    assert "Rollback criteria" in text
    assert "Rollback actions" in text
    assert "Sign-off checklist" in text

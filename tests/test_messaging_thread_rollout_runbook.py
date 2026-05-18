from __future__ import annotations

from pathlib import Path


def test_runbook_includes_thr020_flags_and_rollback_steps() -> None:
    text = Path("docs/messaging-thread-rollout-runbook.md").read_text(encoding="utf-8")
    assert "MESSAGING_THREAD_PROMOTION_MODE" in text
    assert "MESSAGING_THREAD_PROMOTION_INTERNAL_TENANT_IDS" in text
    assert "MESSAGING_THREAD_PROMOTION_ENABLED_TENANT_IDS" in text
    assert "MESSAGING_THREAD_PROMOTION_MODE=disabled" in text
    assert "messaging-thread-ops-dashboard.json" in text

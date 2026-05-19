from __future__ import annotations

from pathlib import Path


def test_broadcast_incident_runbook_covers_required_incident_classes() -> None:
    text = Path("docs/broadcast-live-incident-runbook.md").read_text(encoding="utf-8").lower()
    assert "ingest failure" in text
    assert "no output playback" in text
    assert "drm key issues" in text
    assert "watermark misconfiguration" in text
    assert "escalation matrix" in text


def test_broadcast_postmortem_template_has_prevention_tracking() -> None:
    text = Path("docs/templates/broadcast-postmortem-template.md").read_text(encoding="utf-8").lower()
    assert "prevention action tracking" in text
    assert "owner" in text
    assert "due date" in text

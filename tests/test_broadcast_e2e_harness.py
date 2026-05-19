from __future__ import annotations

from pathlib import Path


def test_broadcast_e2e_harness_contains_required_assertions() -> None:
    text = Path("scripts/e2e/broadcast_local_e2e.py").read_text(encoding="utf-8")
    assert "assert_watermark_present" in text
    assert "assert_encrypted_hls" in text
    assert "assert_archive_persistence" in text
    assert "report.json" in text


def test_broadcast_synthetic_expected_markers_file_exists() -> None:
    text = Path("assets/broadcast-synthetic/expected-output-markers.txt").read_text(encoding="utf-8")
    assert "ENCRYPTION_MARKER=#EXT-X-KEY" in text

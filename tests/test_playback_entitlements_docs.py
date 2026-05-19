from __future__ import annotations

from pathlib import Path


def test_playback_entitlements_api_doc_contains_endpoints_and_error_matrix() -> None:
    text = Path("docs/playback-entitlements-api.md").read_text(encoding="utf-8")
    assert "POST /v1/playback/entitlements/issue" in text
    assert "POST /v1/playback/entitlements/revoke" in text
    assert "GET /v1/playback/protected/ping" in text
    assert "invalid_revocation_expiry" in text
    assert "invalid_header_alg" in text
    assert "token_too_large" in text
    assert "replay_detected" in text

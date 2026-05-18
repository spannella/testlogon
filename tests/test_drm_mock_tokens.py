from __future__ import annotations

import pytest

from app.services.drm_mock_tokens import issue_mock_token, verify_mock_token


def test_issue_and_verify_mock_token() -> None:
    token = issue_mock_token(claims={"asset_id": "a1"}, secret="s", ttl_seconds=60, now_epoch=100)
    payload = verify_mock_token(token=token, secret="s", now_epoch=120)
    assert payload["asset_id"] == "a1"


def test_expired_mock_token_rejected() -> None:
    token = issue_mock_token(claims={"asset_id": "a1"}, secret="s", ttl_seconds=1, now_epoch=100)
    with pytest.raises(ValueError) as exc:
        verify_mock_token(token=token, secret="s", now_epoch=102)
    assert "expired" in str(exc.value)


def test_invalid_signature_rejected() -> None:
    token = issue_mock_token(claims={"asset_id": "a1"}, secret="s", ttl_seconds=60, now_epoch=100)
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(ValueError) as exc:
        verify_mock_token(token=tampered, secret="s", now_epoch=101)
    assert "signature" in str(exc.value)

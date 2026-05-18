from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.services.broadcast_secrets import enforce_secret_reference_only, is_secret_reference


def test_is_secret_reference_patterns() -> None:
    assert is_secret_reference("secret://broadcast/stream/key")
    assert is_secret_reference("arn:aws:secretsmanager:us-east-1:123456789012:secret:abc")
    assert is_secret_reference("arn:aws:ssm:us-east-1:123456789012:parameter/broadcast/dev/key")
    assert is_secret_reference("/broadcast/dev/stream-key")


def test_enforce_secret_reference_only_rejects_raw_secret() -> None:
    with pytest.raises(HTTPException) as exc:
        enforce_secret_reference_only("stream_key_ref", "plain-text-secret")
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "BROADCAST_SECRET_REFERENCE_REQUIRED"

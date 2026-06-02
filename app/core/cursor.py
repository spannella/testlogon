from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from decimal import Decimal
from typing import Any, Dict, Optional


def _json_default(o: Any) -> Any:
    """Serialize DynamoDB ``Decimal`` (from numeric GSI keys in a
    LastEvaluatedKey) as a plain JSON number so the cursor encodes cleanly.
    Integral values become ``int`` so they round-trip as a valid
    ExclusiveStartKey for ``N``-typed attributes."""
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")

_CURSOR_VERSION = "v2"
_DEFAULT_CURSOR_SECRET = "dev-cursor-secret"
_PREVIOUS_CURSOR_SECRET_ENV = "CURSOR_SIGNING_SECRET_PREVIOUS"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(token: str) -> bytes:
    pad = "=" * ((4 - (len(token) % 4)) % 4)
    return base64.urlsafe_b64decode((token + pad).encode("utf-8"))


def _cursor_secrets() -> list[str]:
    current = os.environ.get("CURSOR_SIGNING_SECRET", _DEFAULT_CURSOR_SECRET).strip() or _DEFAULT_CURSOR_SECRET
    previous = os.environ.get(_PREVIOUS_CURSOR_SECRET_ENV, "").strip()
    out = [current]
    if previous and previous != current:
        out.append(previous)
    return out


def _sign_payload(payload_b64: str, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)


def _active_signing_secret() -> str:
    return _cursor_secrets()[0]


def _record_decode_metric(*, format_name: str, outcome: str, key_source: str = "none") -> None:
    try:
        from app.metrics import record_cursor_decode_result
    except Exception:
        return
    record_cursor_decode_result(format_name=format_name, outcome=outcome, key_source=key_source)


def _signature_key_source(payload_b64: str, signature: str) -> str | None:
    for idx, secret in enumerate(_cursor_secrets()):
        expected_sig = _sign_payload(payload_b64, secret)
        if hmac.compare_digest(signature, expected_sig):
            return "current" if idx == 0 else "previous"
    return None


def _encode_legacy_cursor(last_evaluated_key: Optional[Dict[str, Any]]) -> Optional[str]:
    if not last_evaluated_key:
        return None
    raw = json.dumps(last_evaluated_key, separators=(",", ":")).encode("utf-8")
    return _b64url_encode(raw)


def _decode_legacy_cursor(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    s = cursor.strip()
    try:
        raw = _b64url_decode(s)
        obj = json.loads(raw.decode("utf-8"))
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def encode_cursor(last_evaluated_key: Optional[Dict[str, Any]]) -> Optional[str]:
    if not last_evaluated_key:
        return None
    envelope = {"v": _CURSOR_VERSION, "k": last_evaluated_key}
    payload = json.dumps(envelope, separators=(",", ":"), default=_json_default).encode("utf-8")
    payload_b64 = _b64url_encode(payload)
    signature = _sign_payload(payload_b64, _active_signing_secret())
    return f"{_CURSOR_VERSION}.{payload_b64}.{signature}"

def decode_cursor(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    s = cursor.strip()
    parts = s.split(".")
    if len(parts) == 3 and parts[0] == _CURSOR_VERSION:
        _, payload_b64, sig = parts
        key_source = _signature_key_source(payload_b64, sig)
        if not key_source:
            _record_decode_metric(format_name="v2", outcome="failure", key_source="none")
            return None
        try:
            raw = _b64url_decode(payload_b64)
            obj = json.loads(raw.decode("utf-8"))
            if isinstance(obj, dict) and obj.get("v") == _CURSOR_VERSION and isinstance(obj.get("k"), dict):
                _record_decode_metric(format_name="v2", outcome="success", key_source=key_source)
                return obj["k"]
        except Exception:
            _record_decode_metric(format_name="v2", outcome="failure", key_source=key_source)
            return None
        _record_decode_metric(format_name="v2", outcome="failure", key_source=key_source)
        return None
    # Backward compatibility for legacy unsigned cursors.
    legacy = _decode_legacy_cursor(s)
    if legacy is not None:
        _record_decode_metric(format_name="legacy", outcome="success", key_source="legacy")
        return legacy
    _record_decode_metric(format_name="legacy", outcome="failure", key_source="none")
    return None

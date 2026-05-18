from __future__ import annotations

from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEY_MARKERS = (
    "password",
    "secret",
    "token",
    "authorization",
    "auth_header",
    "auth",
    "credential_ct_b64",
    "secret_ct_b64",
    "ical_auth_payload",
)


def _is_sensitive_key(key: str) -> bool:
    normalized = (key or "").strip().lower()
    if not normalized:
        return False
    return any(marker in normalized for marker in _SENSITIVE_KEY_MARKERS)


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if _is_sensitive_key(key):
                out[key] = REDACTED
            else:
                out[key] = redact_sensitive(raw_value)
        return out

    if isinstance(value, list):
        return [redact_sensitive(v) for v in value]

    if isinstance(value, tuple):
        return tuple(redact_sensitive(v) for v in value)

    return value


def redacted_log_payload(**kwargs: Any) -> dict[str, Any]:
    return redact_sensitive(kwargs)

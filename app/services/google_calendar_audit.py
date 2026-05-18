from __future__ import annotations

import re
from typing import Any, Dict

from app.services.alerts import audit_event

_SENSITIVE_MARKERS = (
    "token",
    "secret",
    "password",
    "authorization",
    "ciphertext",
    "nonce",
    "aad",
    "kms",
)

_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[a-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)\b(refresh|access|id)_token\b[\s:=]+[a-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)\bya29\.[a-z0-9\-_]+"),
)


def _is_sensitive_key(key: str) -> bool:
    lowered = str(key or "").lower()
    return any(marker in lowered for marker in _SENSITIVE_MARKERS)


def _sanitize_text_value(text: str) -> str:
    value = str(text or "")
    redacted = value
    for pattern in _SENSITIVE_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted[:500]


def sanitize_audit_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    def _sanitize(value: Any, *, key: str = "") -> Any:
        if _is_sensitive_key(key):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {str(k): _sanitize(v, key=str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [_sanitize(v, key=key) for v in value]
        if isinstance(value, tuple):
            return tuple(_sanitize(v, key=key) for v in value)
        if value is None:
            return None
        if isinstance(value, (bool, int, float)):
            return value
        return _sanitize_text_value(str(value))

    return {str(k): _sanitize(v, key=str(k)) for k, v in (data or {}).items()}


def emit_google_calendar_audit_event(
    *,
    event: str,
    actor_user_sub: str,
    outcome: str,
    target_type: str,
    target_id: str,
    **fields: Any,
) -> None:
    safe_fields = sanitize_audit_payload(fields)
    audit_event(
        event,
        actor_user_sub,
        None,
        outcome=outcome,
        actor_sub=actor_user_sub,
        target_type=target_type,
        target_id=target_id,
        integration="google_calendar",
        compliance_domain="calendar_sync",
        **safe_fields,
    )

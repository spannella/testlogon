from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any
from uuid import uuid4

from app.core.settings import S
try:
    from app.metrics import record_playback_entitlement_event, record_playback_entitlement_latency
except Exception:  # pragma: no cover - metrics stack may be unavailable in minimal test envs
    def record_playback_entitlement_event(*, operation: str, outcome: str, reason: str = "") -> None:
        return None

    def record_playback_entitlement_latency(*, operation: str, elapsed_seconds: float) -> None:
        return None


class PlaybackEntitlementError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _unb64url(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _token_secret() -> str:
    secret = (S.playback_entitlement_secret or "").strip()
    if not secret:
        raise PlaybackEntitlementError("secret_not_configured", "playback entitlement secret is not configured")
    return secret


_SEEN_JTI: dict[str, int] = {}
_REVOKED_JTI: dict[str, int] = {}
_REVOKED_SESSIONS: dict[str, int] = {}


def _safe_max_entries(raw: Any, *, default: int) -> int:
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return default


def _safe_setting_int(raw: Any, *, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(raw))
    except (TypeError, ValueError):
        return max(minimum, default)


def _enforce_cache_size(cache: dict[str, int], *, max_entries: int) -> None:
    if len(cache) <= max_entries:
        return
    overflow = len(cache) - max_entries
    for _ in range(overflow):
        oldest = min(cache, key=cache.get)
        cache.pop(oldest, None)


def reset_replay_cache() -> None:
    _SEEN_JTI.clear()


def reset_revocation_cache() -> None:
    _REVOKED_JTI.clear()
    _REVOKED_SESSIONS.clear()


def revoke_playback_entitlement(*, jti: str | None = None, session_id: str | None = None, tenant_id: str | None = None, expires_at_epoch: int) -> None:
    started = time.perf_counter()
    try:
        exp = _coerce_int(expires_at_epoch, code="invalid_revocation_expiry", message="expires_at_epoch must be an integer epoch")
        now = int(time.time())
        if exp <= now:
            raise PlaybackEntitlementError("invalid_revocation_expiry", "expires_at_epoch must be in the future")

        normalized_jti = str(jti or "").strip()
        normalized_session_id = str(session_id or "").strip()
        if not normalized_jti and not normalized_session_id:
            raise PlaybackEntitlementError("invalid_revocation_request", "either jti or session_id is required")

        _cleanup_revocations(now)
        if normalized_jti:
            _REVOKED_JTI[normalized_jti] = exp
            max_jti_revocations = _safe_max_entries(
                getattr(S, "playback_entitlement_revocation_jti_cache_max_entries", 100_000),
                default=100_000,
            )
            _enforce_cache_size(_REVOKED_JTI, max_entries=max_jti_revocations)
        if normalized_session_id:
            tenant = str(tenant_id or "").strip()
            if not tenant:
                raise PlaybackEntitlementError("invalid_revocation_request", "tenant_id is required when revoking by session_id")
            key = f"{tenant}:{normalized_session_id}"
            _REVOKED_SESSIONS[key] = exp
            max_session_revocations = _safe_max_entries(
                getattr(S, "playback_entitlement_revocation_session_cache_max_entries", 100_000),
                default=100_000,
            )
            _enforce_cache_size(_REVOKED_SESSIONS, max_entries=max_session_revocations)
        record_playback_entitlement_event(operation="revoke", outcome="success")
    except PlaybackEntitlementError as exc:
        record_playback_entitlement_event(operation="revoke", outcome="error", reason=exc.code)
        raise
    finally:
        record_playback_entitlement_latency(operation="revoke", elapsed_seconds=time.perf_counter() - started)


def _cleanup_seen_jti(now_epoch: int) -> None:
    expired = [jti for jti, exp in _SEEN_JTI.items() if exp <= now_epoch]
    for jti in expired:
        _SEEN_JTI.pop(jti, None)


def _cleanup_revocations(now_epoch: int) -> None:
    expired_jti = [jti for jti, exp in _REVOKED_JTI.items() if exp <= now_epoch]
    for jti in expired_jti:
        _REVOKED_JTI.pop(jti, None)

    expired_sessions = [session_id for session_id, exp in _REVOKED_SESSIONS.items() if exp <= now_epoch]
    for session_id in expired_sessions:
        _REVOKED_SESSIONS.pop(session_id, None)


def _enforce_revocation_policy(*, jti: str, session_id: str, tenant_id: str, now_epoch: int) -> None:
    _cleanup_revocations(now_epoch)
    if jti in _REVOKED_JTI:
        raise PlaybackEntitlementError("token_revoked", "playback entitlement token was revoked")
    session_key = f"{tenant_id}:{session_id}"
    if session_key in _REVOKED_SESSIONS:
        raise PlaybackEntitlementError("session_revoked", "playback session was revoked")


def _enforce_replay_policy(*, jti: str, exp: int, now_epoch: int) -> None:
    if not bool(getattr(S, "playback_entitlement_replay_protection_enabled", False)):
        return
    _cleanup_seen_jti(now_epoch)
    if jti in _SEEN_JTI:
        raise PlaybackEntitlementError("replay_detected", "playback entitlement replay detected")
    _SEEN_JTI[jti] = exp
    max_replay_entries = _safe_max_entries(
        getattr(S, "playback_entitlement_replay_cache_max_entries", 100_000),
        default=100_000,
    )
    _enforce_cache_size(_SEEN_JTI, max_entries=max_replay_entries)


def _parse_epoch_claim(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise PlaybackEntitlementError("invalid_claim_type", f"claim '{key}' must be an integer epoch")
    return value


def _parse_string_claim(payload: dict[str, Any], key: str, *, require_non_empty: bool = True) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise PlaybackEntitlementError("invalid_claim_type", f"claim '{key}' must be a string")
    normalized = value.strip()
    if require_non_empty and not normalized:
        raise PlaybackEntitlementError("invalid_claims", f"{key} must be non-empty")
    return normalized


def _max_claim_length() -> int:
    return _safe_setting_int(getattr(S, "playback_entitlement_max_claim_length", 256), default=256, minimum=1)


def _require_non_empty_claim(value: str, *, field: str, max_length: int) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise PlaybackEntitlementError("invalid_claims", f"{field} must be non-empty")
    if len(normalized) > max_length:
        raise PlaybackEntitlementError("invalid_claims", f"{field} exceeds maximum allowed length")
    return normalized


def _coerce_int(value: Any, *, code: str, message: str) -> int:
    if isinstance(value, bool):
        raise PlaybackEntitlementError(code, message)
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise PlaybackEntitlementError(code, message) from exc


def issue_playback_entitlement(
    *,
    tenant_id: str,
    asset_id: str,
    session_id: str,
    device_id: str,
    profile: str,
    audience: str,
    ttl_seconds: int,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        now = int(time.time()) if now_epoch is None else _coerce_int(now_epoch, code="invalid_timestamp", message="now_epoch must be an integer epoch")
        ttl = _coerce_int(ttl_seconds, code="invalid_ttl", message="ttl_seconds must be an integer")
        if ttl < 1:
            raise PlaybackEntitlementError("invalid_ttl", "ttl_seconds must be greater than 0")

        max_ttl = _safe_setting_int(getattr(S, "playback_entitlement_max_ttl_seconds", 300), default=300, minimum=1)
        if ttl > max_ttl:
            raise PlaybackEntitlementError("ttl_exceeds_max", f"ttl_seconds exceeds max allowed ({max_ttl})")

        aud = (audience or "").strip()
        if not aud:
            raise PlaybackEntitlementError("invalid_audience", "audience is required")
        max_claim_length = _max_claim_length()
        if len(aud) > max_claim_length:
            raise PlaybackEntitlementError("invalid_audience", "audience exceeds maximum allowed length")
        tenant = _require_non_empty_claim(tenant_id, field="tenant_id", max_length=max_claim_length)
        asset = _require_non_empty_claim(asset_id, field="asset_id", max_length=max_claim_length)
        session = _require_non_empty_claim(session_id, field="session_id", max_length=max_claim_length)
        device = _require_non_empty_claim(device_id, field="device_id", max_length=max_claim_length)
        selected_profile = _require_non_empty_claim(profile, field="profile", max_length=max_claim_length)

        header = {"alg": "HS256", "typ": "PLAYBACKJWT"}
        payload = {
            "tenant_id": tenant,
            "asset_id": asset,
            "session_id": session,
            "device_id": device,
            "profile": selected_profile,
            "aud": aud,
            "iat": now,
            "exp": now + ttl,
            "jti": uuid4().hex,
        }

        encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        sig = hmac.new(_token_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()

        token = f"{encoded_header}.{encoded_payload}.{_b64url(sig)}"
        out = {
            "token": token,
            "expires_at_epoch": payload["exp"],
            "audience": aud,
            "ttl_seconds": ttl,
            "jti": payload["jti"],
        }
        record_playback_entitlement_event(operation="issue", outcome="success")
        return out
    except PlaybackEntitlementError as exc:
        record_playback_entitlement_event(operation="issue", outcome="error", reason=exc.code)
        raise
    finally:
        record_playback_entitlement_latency(operation="issue", elapsed_seconds=time.perf_counter() - started)


def validate_playback_entitlement(
    *,
    token: str,
    expected_audience: str,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        max_token_length = _safe_setting_int(getattr(S, "playback_entitlement_max_token_length", 4096), default=4096, minimum=1)
        if len(token or "") > max_token_length:
            raise PlaybackEntitlementError("token_too_large", "playback entitlement token exceeds maximum allowed length")
        expected_aud = str(expected_audience or "").strip()
        if not expected_aud:
            raise PlaybackEntitlementError("invalid_audience", "expected audience is required")
        now = int(time.time()) if now_epoch is None else _coerce_int(now_epoch, code="invalid_timestamp", message="now_epoch must be an integer epoch")
        parts = token.split(".")
        if len(parts) != 3:
            raise PlaybackEntitlementError("invalid_format", "invalid token format")
        encoded_header, encoded_payload, encoded_sig = parts
        try:
            header = json.loads(_unb64url(encoded_header).decode("utf-8"))
        except Exception as exc:
            raise PlaybackEntitlementError("invalid_header", "invalid token header") from exc
        if not isinstance(header, dict):
            raise PlaybackEntitlementError("invalid_header", "invalid token header")

        alg = str(header.get("alg") or "")
        typ = str(header.get("typ") or "")
        if alg != "HS256":
            raise PlaybackEntitlementError("invalid_header_alg", "invalid token header alg")
        if typ != "PLAYBACKJWT":
            raise PlaybackEntitlementError("invalid_header_typ", "invalid token header typ")

        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        expected_sig = hmac.new(_token_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()

        try:
            provided_sig = _unb64url(encoded_sig)
        except Exception as exc:
            raise PlaybackEntitlementError("invalid_signature", "invalid token signature encoding") from exc

        if not hmac.compare_digest(expected_sig, provided_sig):
            raise PlaybackEntitlementError("invalid_signature", "invalid token signature")

        try:
            payload = json.loads(_unb64url(encoded_payload).decode("utf-8"))
        except Exception as exc:
            raise PlaybackEntitlementError("invalid_payload", "invalid token payload") from exc
        if not isinstance(payload, dict):
            raise PlaybackEntitlementError("invalid_payload", "invalid token payload")

        required = ("tenant_id", "asset_id", "session_id", "device_id", "profile", "iat", "exp", "aud", "jti")
        missing = [field for field in required if field not in payload]
        if missing:
            raise PlaybackEntitlementError("missing_claims", f"missing claim(s): {', '.join(missing)}")

        exp = _parse_epoch_claim(payload, "exp")
        iat = _parse_epoch_claim(payload, "iat")
        if exp <= now:
            raise PlaybackEntitlementError("token_expired", "playback entitlement token expired")

        max_ttl = _safe_setting_int(getattr(S, "playback_entitlement_max_ttl_seconds", 300), default=300, minimum=1)
        if exp - iat > max_ttl:
            raise PlaybackEntitlementError("invalid_ttl", "playback entitlement token ttl exceeds policy")

        max_clock_skew = _safe_setting_int(getattr(S, "playback_entitlement_max_clock_skew_seconds", 30), default=30, minimum=0)
        if iat > now + max_clock_skew:
            raise PlaybackEntitlementError("token_not_yet_valid", "playback entitlement token iat is in the future")

        aud = _parse_string_claim(payload, "aud")
        if aud != expected_aud:
            raise PlaybackEntitlementError("invalid_audience", f"invalid audience: expected '{expected_aud}'")

        max_claim_length = _max_claim_length()
        if len(aud) > max_claim_length:
            raise PlaybackEntitlementError("invalid_claims", "aud exceeds maximum allowed length")

        tenant_id = _parse_string_claim(payload, "tenant_id")
        asset_id = _parse_string_claim(payload, "asset_id")
        session_id = _parse_string_claim(payload, "session_id")
        device_id = _parse_string_claim(payload, "device_id")
        profile = _parse_string_claim(payload, "profile")
        jti = _parse_string_claim(payload, "jti")
        for key, value in (
            ("tenant_id", tenant_id),
            ("asset_id", asset_id),
            ("session_id", session_id),
            ("device_id", device_id),
            ("profile", profile),
            ("jti", jti),
        ):
            if len(value) > max_claim_length:
                raise PlaybackEntitlementError("invalid_claims", f"{key} exceeds maximum allowed length")

        _enforce_revocation_policy(jti=jti, session_id=session_id, tenant_id=tenant_id, now_epoch=now)
        _enforce_replay_policy(jti=jti, exp=exp, now_epoch=now)
        record_playback_entitlement_event(operation="validate", outcome="success")
        return payload
    except PlaybackEntitlementError as exc:
        record_playback_entitlement_event(operation="validate", outcome="error", reason=exc.code)
        raise
    finally:
        record_playback_entitlement_latency(operation="validate", elapsed_seconds=time.perf_counter() - started)

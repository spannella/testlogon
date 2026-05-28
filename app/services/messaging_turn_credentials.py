from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from app.core.settings import S
from app.core.time import now_ts
from app.services.messaging_call_sessions import get_call_session

ELIGIBLE_STATES = {"invited", "accepted", "connected"}
MIN_TURN_TTL_SECONDS = 60
MAX_TURN_TTL_SECONDS = 3600
MAX_IDENTIFIER_LENGTH = 128


class TurnCredentialIssueError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class TurnCredentials:
    ttl_seconds: int
    expires_at: int
    ice_servers: list[dict[str, Any]]


def _csv(raw: str) -> list[str]:
    return [x.strip() for x in str(raw or "").split(",") if x.strip()]


def _hmac_credential(*, username: str, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("utf-8")


def _validate_turn_urls(*, urls: list[str]) -> None:
    for raw_url in urls:
        parsed = urlparse(raw_url)
        host_segment = (parsed.netloc or parsed.path or "").strip()
        if parsed.scheme not in {"turn", "turns"} or not host_segment:
            raise ValueError(f"invalid TURN URL: {raw_url}")


def _load_conversation_participants(conversation_id: str) -> set[str]:
    import os
    from app.core.aws import ddb
    from boto3.dynamodb.conditions import Key as DDBKey

    table_name = os.getenv("DDB_PARTICIPANTS", "Participants")
    items = ddb.Table(table_name).query(
        IndexName="GSI1",
        KeyConditionExpression=DDBKey("GSI1PK").eq(conversation_id),
    ).get("Items", [])
    return {str(item["user_id"]).strip() for item in items if item.get("user_id")}


def _record_issue(*, outcome: str, reason: str) -> None:
    try:
        from app.metrics import record_turn_credential_issue

        record_turn_credential_issue(outcome=outcome, reason=reason)
    except Exception:
        return


def _record_issue_latency(*, outcome: str, reason: str, elapsed_seconds: float) -> None:
    try:
        from app.metrics import record_turn_credential_issue_latency

        record_turn_credential_issue_latency(outcome=outcome, reason=reason, elapsed_seconds=elapsed_seconds)
    except Exception:
        return


def _raise_issue(*, code: str, message: str, reason: str, started_at: float) -> None:
    _record_issue(outcome="error", reason=reason)
    _record_issue_latency(outcome="error", reason=reason, elapsed_seconds=(time.perf_counter() - started_at))
    raise TurnCredentialIssueError(code, message)


def issue_turn_credentials(*, call_id: str, actor_user_id: str) -> TurnCredentials:
    started_at = time.perf_counter()
    normalized_call_id = str(call_id or "").strip()
    normalized_actor_user_id = str(actor_user_id or "").strip()
    if not normalized_call_id or not normalized_actor_user_id:
        _raise_issue(
            code="validation_error",
            message="call_id and actor_user_id are required",
            reason="validation_error",
            started_at=started_at,
        )
    if len(normalized_call_id) > MAX_IDENTIFIER_LENGTH or len(normalized_actor_user_id) > MAX_IDENTIFIER_LENGTH:
        _raise_issue(
            code="validation_error",
            message=f"identifiers must be at most {MAX_IDENTIFIER_LENGTH} characters",
            reason="validation_error",
            started_at=started_at,
        )

    if not bool(getattr(S, "messaging_webrtc_turn_enabled", False)):
        _raise_issue(
            code="feature_disabled",
            message="TURN credential issuance is disabled",
            reason="turn_disabled",
            started_at=started_at,
        )

    urls = _csv(getattr(S, "messaging_webrtc_turn_urls", ""))
    secret = str(getattr(S, "messaging_webrtc_turn_secret", "") or "").strip()
    ttl_raw = getattr(S, "messaging_webrtc_turn_ttl_seconds", 600)

    if not urls or not secret:
        _raise_issue(
            code="turn_not_configured",
            message="TURN server is not configured",
            reason="turn_not_configured",
            started_at=started_at,
        )
    try:
        _validate_turn_urls(urls=urls)
    except Exception:
        _raise_issue(
            code="turn_invalid_url",
            message="TURN server URL configuration is invalid",
            reason="turn_invalid_url",
            started_at=started_at,
        )
    try:
        ttl = int(ttl_raw or 0)
    except Exception:
        _raise_issue(
            code="turn_invalid_ttl",
            message="TURN credential TTL configuration is invalid",
            reason="turn_invalid_ttl",
            started_at=started_at,
        )
    if ttl < MIN_TURN_TTL_SECONDS or ttl > MAX_TURN_TTL_SECONDS:
        _raise_issue(
            code="turn_invalid_ttl",
            message=f"TURN credential TTL must be between {MIN_TURN_TTL_SECONDS} and {MAX_TURN_TTL_SECONDS} seconds",
            reason="turn_invalid_ttl",
            started_at=started_at,
        )

    record = get_call_session(normalized_call_id)
    if not record:
        _raise_issue(
            code="call_not_found",
            message="call session not found",
            reason="call_not_found",
            started_at=started_at,
        )

    if normalized_actor_user_id not in {record.caller_user_id, record.callee_user_id}:
        _raise_issue(
            code="forbidden",
            message="user is not a participant of this call",
            reason="forbidden",
            started_at=started_at,
        )

    conversation_id = str(getattr(record, "conversation_id", "") or "").strip()
    if conversation_id:
        try:
            participants = _load_conversation_participants(conversation_id)
        except Exception:
            _raise_issue(
                code="participant_lookup_failed",
                message="failed to load conversation participants",
                reason="participant_lookup_failed",
                started_at=started_at,
            )
        if normalized_actor_user_id not in participants:
            _raise_issue(
                code="forbidden",
                message="user is no longer a participant of this conversation",
                reason="forbidden",
                started_at=started_at,
            )
        call_participants = {
            str(getattr(record, "caller_user_id", "") or "").strip(),
            str(getattr(record, "callee_user_id", "") or "").strip(),
        }
        if not call_participants.issubset(participants):
            _raise_issue(
                code="call_participant_mismatch",
                message="call participants do not match current conversation membership",
                reason="call_participant_mismatch",
                started_at=started_at,
            )

    if record.state not in ELIGIBLE_STATES:
        _raise_issue(
            code="invalid_state",
            message=f"TURN credentials cannot be issued in state {record.state}",
            reason="invalid_state",
            started_at=started_at,
        )

    expires_at = int(now_ts()) + ttl
    username = f"{expires_at}:{normalized_actor_user_id}"
    credential = _hmac_credential(username=username, secret=secret)

    result = TurnCredentials(
        ttl_seconds=ttl,
        expires_at=expires_at,
        ice_servers=[
            {
                "urls": urls,
                "username": username,
                "credential": credential,
            }
        ],
    )
    _record_issue(outcome="success", reason="issued")
    _record_issue_latency(outcome="success", reason="issued", elapsed_seconds=(time.perf_counter() - started_at))
    return result


__all__ = ["TurnCredentials", "TurnCredentialIssueError", "issue_turn_credentials"]

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import threading
import time
import uuid
from typing import Any

from app.core.settings import S

logger = logging.getLogger(__name__)

SUPPORTED_JIRA_WEBHOOK_EVENTS = {
    "jira:issue_created",
    "jira:issue_updated",
    "jira:issue_deleted",
    "comment_created",
    "comment_updated",
    "comment_deleted",
}


@dataclass(frozen=True)
class JiraWebhookDispatchResult:
    accepted: bool
    enqueued: bool
    deduplicated: bool
    trace_id: str


@dataclass(frozen=True)
class JiraWebhookAuthError(Exception):
    message: str
    status_code: int


_REPLAY_LOCK = threading.Lock()
_REPLAY_KEYS: dict[str, int] = {}
_SOURCE_IP_POLICY_LOCK = threading.Lock()
_SOURCE_IP_POLICY_VIOLATIONS: dict[str, int] = {}
_SOURCE_IP_POLICY_VIOLATIONS_BY_MODE: dict[str, int] = {}


def _queue_url() -> str:
    return str(os.getenv("JIRA_WEBHOOK_QUEUE_URL", "")).strip()


def _signature_secret() -> str:
    return str(os.getenv("JIRA_WEBHOOK_SIGNING_SECRET", "")).strip()


def _replay_ttl_seconds() -> int:
    raw = str(os.getenv("JIRA_WEBHOOK_REPLAY_TTL_SECONDS", "600")).strip() or "600"
    try:
        return max(60, int(raw))
    except ValueError:
        return 600


def _replay_max_keys() -> int:
    raw = str(os.getenv("JIRA_WEBHOOK_REPLAY_MAX_KEYS", "50000")).strip() or "50000"
    try:
        return max(100, int(raw))
    except ValueError:
        return 50000


def _allowed_ip_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw = str(os.getenv("JIRA_WEBHOOK_ALLOWED_IPS", "")).strip()
    if not raw:
        return []
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for token in (part.strip() for part in raw.split(",")):
        if not token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            logger.warning("jira webhook allowed ip entry ignored: invalid cidr", extra={"cidr": token})
    return networks


def _has_configured_allowed_ips() -> bool:
    raw = str(os.getenv("JIRA_WEBHOOK_ALLOWED_IPS", "")).strip()
    if not raw:
        return False
    return any(part.strip() for part in raw.split(","))


def _ip_policy_mode() -> tuple[str, bool]:
    raw = str(os.getenv("JIRA_WEBHOOK_IP_POLICY_MODE", "enforce")).strip().lower()
    if raw in {"off", "monitor", "enforce"}:
        return raw, True
    return "enforce", False


def _validate_source_ip(remote_ip: str | None, *, allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> str | None:
    resolved_remote_ip = str(remote_ip or "").strip()
    if not resolved_remote_ip:
        return "jira webhook source ip required"
    try:
        ip_obj = ipaddress.ip_address(resolved_remote_ip)
    except ValueError:
        return "jira webhook source ip invalid"
    if any(ip_obj in network for network in allowed_networks):
        return None
    return "jira webhook source ip not allowed"


def _verify_source_ip(remote_ip: str | None) -> None:
    allowed_networks = _allowed_ip_networks()
    has_allowed_ip_config = _has_configured_allowed_ips()
    if not has_allowed_ip_config:
        return
    mode, mode_is_valid = _ip_policy_mode()
    if not mode_is_valid:
        source_ip_error = "jira webhook source ip policy mode invalid"
        _record_source_ip_policy_violation(source_ip_error, mode="invalid")
        raise JiraWebhookAuthError(message=source_ip_error, status_code=503)
    if mode == "off":
        return
    if not allowed_networks:
        source_ip_error = "jira webhook source ip policy misconfigured"
        _record_source_ip_policy_violation(source_ip_error, mode=mode)
        if mode == "monitor":
            logger.warning("jira webhook source ip policy misconfigured; monitor mode allows request")
            return
        raise JiraWebhookAuthError(message=source_ip_error, status_code=503)
    source_ip_error = _validate_source_ip(remote_ip, allowed_networks=allowed_networks)
    if not source_ip_error:
        return
    _record_source_ip_policy_violation(source_ip_error, mode=mode)
    if mode == "monitor":
        logger.warning(
            "jira webhook source ip policy violation observed in monitor mode",
            extra={"remote_ip": str(remote_ip or ""), "reason": source_ip_error},
        )
        return
    raise JiraWebhookAuthError(message=source_ip_error, status_code=403)


def _record_source_ip_policy_violation(reason: str, *, mode: str) -> None:
    key = str(reason or "unknown").strip().lower() or "unknown"
    mode_key = str(mode or "unknown").strip().lower() or "unknown"
    with _SOURCE_IP_POLICY_LOCK:
        _SOURCE_IP_POLICY_VIOLATIONS[key] = int(_SOURCE_IP_POLICY_VIOLATIONS.get(key) or 0) + 1
        composite = f"{mode_key}:{key}"
        _SOURCE_IP_POLICY_VIOLATIONS_BY_MODE[composite] = int(_SOURCE_IP_POLICY_VIOLATIONS_BY_MODE.get(composite) or 0) + 1


def get_source_ip_policy_violation_counts() -> dict[str, int]:
    with _SOURCE_IP_POLICY_LOCK:
        return {k: int(v) for k, v in _SOURCE_IP_POLICY_VIOLATIONS.items()}


def get_source_ip_policy_violation_counts_by_mode() -> dict[str, int]:
    with _SOURCE_IP_POLICY_LOCK:
        return {k: int(v) for k, v in _SOURCE_IP_POLICY_VIOLATIONS_BY_MODE.items()}


def consume_source_ip_policy_violation_counts_by_mode() -> dict[str, int]:
    with _SOURCE_IP_POLICY_LOCK:
        snapshot = {k: int(v) for k, v in _SOURCE_IP_POLICY_VIOLATIONS_BY_MODE.items()}
        _SOURCE_IP_POLICY_VIOLATIONS_BY_MODE.clear()
        return snapshot


def get_source_ip_policy_violation_snapshot(*, drain_mode_counts: bool = False) -> dict[str, Any]:
    with _SOURCE_IP_POLICY_LOCK:
        aggregate = {k: int(v) for k, v in _SOURCE_IP_POLICY_VIOLATIONS.items()}
        by_mode = {k: int(v) for k, v in _SOURCE_IP_POLICY_VIOLATIONS_BY_MODE.items()}
        if drain_mode_counts:
            _SOURCE_IP_POLICY_VIOLATIONS_BY_MODE.clear()
    return {
        "captured_at": int(time.time()),
        "aggregate": aggregate,
        "by_mode": by_mode,
        "total_aggregate": int(sum(aggregate.values())),
        "total_by_mode": int(sum(by_mode.values())),
        "drained_mode_counts": bool(drain_mode_counts),
    }


def _reset_source_ip_policy_violation_counts_for_tests() -> None:
    with _SOURCE_IP_POLICY_LOCK:
        _SOURCE_IP_POLICY_VIOLATIONS.clear()
        _SOURCE_IP_POLICY_VIOLATIONS_BY_MODE.clear()


def _payload_signature(payload: dict[str, Any], *, secret: str) -> str:
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def _normalize_signature(sig: str | None) -> str:
    raw = str(sig or "").strip()
    if raw.startswith("sha256="):
        return raw.split("=", 1)[1].strip()
    return raw


def _verify_signature(*, payload: dict[str, Any], signature_header: str | None) -> None:
    secret = _signature_secret()
    if not secret:
        return
    provided = _normalize_signature(signature_header)
    if not provided:
        raise JiraWebhookAuthError(message="jira webhook signature required", status_code=401)
    expected = _payload_signature(payload, secret=secret)
    if not hmac.compare_digest(expected, provided):
        raise JiraWebhookAuthError(message="jira webhook signature invalid", status_code=403)


def _check_and_mark_replay(replay_key: str) -> bool:
    now = int(time.time())
    ttl = _replay_ttl_seconds()
    max_keys = _replay_max_keys()
    with _REPLAY_LOCK:
        cutoff = now - ttl
        stale = [key for key, ts in _REPLAY_KEYS.items() if ts < cutoff]
        for key in stale:
            _REPLAY_KEYS.pop(key, None)
        if len(_REPLAY_KEYS) >= max_keys:
            # Evict oldest entries to bound memory and preserve recent dedupe protection.
            overflow = (len(_REPLAY_KEYS) - max_keys) + 1
            for key, _ts in sorted(_REPLAY_KEYS.items(), key=lambda item: item[1])[:overflow]:
                _REPLAY_KEYS.pop(key, None)
        if replay_key in _REPLAY_KEYS:
            return True
        _REPLAY_KEYS[replay_key] = now
        return False


def _enqueue_to_sqs(*, envelope: dict[str, Any]) -> bool:
    queue_url = _queue_url()
    if not queue_url:
        return False
    import boto3

    boto3.client("sqs", region_name=S.aws_region or "us-east-1").send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(envelope, separators=(",", ":"), sort_keys=True),
    )
    return True


def process_jira_webhook(
    *,
    event_type: str,
    cloud_id: str,
    issue_id: str | None,
    issue_key: str | None,
    payload: dict[str, Any],
    header_event_type: str,
    webhook_identifier: str | None,
    signature_header: str | None,
    remote_ip: str | None = None,
) -> JiraWebhookDispatchResult:
    trace_id = f"jira-webhook-{uuid.uuid4().hex[:12]}"
    _verify_source_ip(remote_ip)
    try:
        _verify_signature(payload=payload, signature_header=signature_header)
    except JiraWebhookAuthError:
        logger.warning(
            "jira webhook rejected: signature validation failed",
            extra={"trace_id": trace_id, "event_type": header_event_type or event_type or "", "cloud_id": cloud_id},
        )
        raise

    resolved_event_type = (header_event_type or event_type or "").strip()
    if not resolved_event_type:
        raise ValueError("jira webhook event type is required")
    if not cloud_id.strip():
        raise ValueError("jira webhook cloud_id is required")

    if resolved_event_type not in SUPPORTED_JIRA_WEBHOOK_EVENTS:
        logger.info(
            "jira webhook event ignored: unsupported event",
            extra={
                "trace_id": trace_id,
                "event_type": resolved_event_type,
                "cloud_id": cloud_id,
                "webhook_id": webhook_identifier or "",
            },
        )
        return JiraWebhookDispatchResult(accepted=True, enqueued=False, deduplicated=False, trace_id=trace_id)

    resolved_issue_id = str(issue_id or payload.get("issue_id") or payload.get("issue", {}).get("id") or "").strip()
    resolved_issue_key = str(issue_key or payload.get("issue_key") or payload.get("issue", {}).get("key") or "").strip()
    if not resolved_issue_id and not resolved_issue_key:
        raise ValueError("jira webhook payload requires issue_id or issue_key")

    replay_key = str(webhook_identifier or "").strip()
    if not replay_key:
        signature_token = _normalize_signature(signature_header)
        replay_key = f"{resolved_event_type}:{cloud_id}:{resolved_issue_id or resolved_issue_key}:{signature_token or _payload_signature(payload, secret='no-secret')}"
    if _check_and_mark_replay(replay_key):
        logger.info(
            "jira webhook deduplicated by replay key",
            extra={"trace_id": trace_id, "replay_key": replay_key[:128], "event_type": resolved_event_type, "cloud_id": cloud_id},
        )
        return JiraWebhookDispatchResult(accepted=True, enqueued=False, deduplicated=True, trace_id=trace_id)

    envelope = {
        "trace_id": trace_id,
        "provider": "jira",
        "event_type": resolved_event_type,
        "cloud_id": cloud_id,
        "issue_id": resolved_issue_id,
        "issue_key": resolved_issue_key,
        "webhook_id": webhook_identifier or "",
        "received_at": int(time.time()),
        "payload": payload,
    }
    enqueued = _enqueue_to_sqs(envelope=envelope)
    if not enqueued:
        raise RuntimeError("jira webhook queue is not configured")
    return JiraWebhookDispatchResult(accepted=True, enqueued=True, deduplicated=False, trace_id=trace_id)

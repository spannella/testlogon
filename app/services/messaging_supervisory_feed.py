from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Mapping

import boto3

from app.core.settings import S

logger = logging.getLogger(__name__)


DEFAULT_RULES = {
    "report.": {"priority": "high", "assignment_queue": "moderation"},
    "message.deleted": {"priority": "medium", "assignment_queue": "supervision"},
    "message.revoked": {"priority": "medium", "assignment_queue": "supervision"},
    "legal_hold.": {"priority": "high", "assignment_queue": "compliance"},
}


def _feed_enabled() -> bool:
    return os.getenv(
        "MESSAGING_SUPERVISORY_FEED_ENABLED",
        "true" if S.messaging_supervisory_feed_enabled else "false",
    ) not in ("0", "false", "False")


def _feed_mode() -> str:
    return str(os.getenv("MESSAGING_SUPERVISORY_FEED_MODE", S.messaging_supervisory_feed_mode).strip().lower() or "log")


def _feed_queue_url() -> str:
    return str(os.getenv("MESSAGING_SUPERVISORY_FEED_QUEUE_URL", S.messaging_supervisory_feed_queue_url).strip())


def _feed_file_path() -> str:
    return str(os.getenv("MESSAGING_SUPERVISORY_FEED_FILE_PATH", S.messaging_supervisory_feed_file_path).strip() or ".supervisory_feed/events.jsonl")


def _feed_rules() -> dict[str, dict[str, str]]:
    raw = str(os.getenv("MESSAGING_SUPERVISORY_FEED_RULES_JSON", S.messaging_supervisory_feed_rules_json).strip() or "")
    if not raw:
        return dict(DEFAULT_RULES)
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return dict(DEFAULT_RULES)
        out: dict[str, dict[str, str]] = {}
        for k, v in parsed.items():
            if isinstance(k, str) and isinstance(v, dict):
                out[k] = {
                    "priority": str(v.get("priority") or "medium"),
                    "assignment_queue": str(v.get("assignment_queue") or "supervision"),
                }
        return out or dict(DEFAULT_RULES)
    except Exception:  # noqa: BLE001
        return dict(DEFAULT_RULES)


def _match_rule(event_type: str) -> dict[str, str] | None:
    for prefix, metadata in _feed_rules().items():
        if str(event_type).startswith(prefix):
            return metadata
    return None


def build_supervisory_review_message(*, archive_object_key: str, event: Mapping[str, Any]) -> dict[str, Any] | None:
    event_type = str(event.get("event_type") or "")
    rule = _match_rule(event_type)
    if not rule:
        return None

    return {
        "source": "messaging_compliance_archive",
        "version": 1,
        "event_id": str(event.get("event_id") or ""),
        "event_ts": int(event.get("event_ts", 0) or 0),
        "event_type": event_type,
        "tenant_id": str(event.get("tenant_id") or "default"),
        "conversation_id": str(event.get("conversation_id") or ""),
        "message_id": str(event.get("message_id") or ""),
        "actor_user_id": str(event.get("actor_user_id") or ""),
        "effective_user_id": str(event.get("effective_user_id") or ""),
        "archive_object_key": archive_object_key,
        "review_assignment": {
            "priority": rule["priority"],
            "assignment_queue": rule["assignment_queue"],
            "rule_trigger": f"event_type_prefix:{next(p for p in _feed_rules().keys() if event_type.startswith(p))}",
        },
    }


def publish_supervisory_review_message(*, archive_object_key: str, event: Mapping[str, Any]) -> bool:
    if not _feed_enabled():
        return False

    message = build_supervisory_review_message(archive_object_key=archive_object_key, event=event)
    if not message:
        return False

    mode = _feed_mode()
    if mode == "sqs":
        queue_url = _feed_queue_url()
        if not queue_url:
            raise RuntimeError("supervisory feed queue url is not configured")
        boto3.client("sqs", region_name=S.aws_region or "us-east-1").send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(message, separators=(",", ":"), sort_keys=True),
            MessageAttributes={
                "event_type": {"DataType": "String", "StringValue": str(message.get("event_type") or "")},
                "priority": {"DataType": "String", "StringValue": str(message["review_assignment"].get("priority") or "")},
                "assignment_queue": {
                    "DataType": "String",
                    "StringValue": str(message["review_assignment"].get("assignment_queue") or ""),
                },
            },
        )
        return True

    if mode == "file":
        p = Path(_feed_file_path())
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        return True

    logger.info("messaging.supervisory_feed.publish", extra={"message": message})
    return True

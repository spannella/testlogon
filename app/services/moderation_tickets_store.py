from __future__ import annotations

import hashlib
import time
from typing import Any, Iterable

from botocore.exceptions import ClientError

from app.core.tables import T

DEFAULT_STATUS = "open"
DEFAULT_PRIORITY = "medium"

PRIORITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
TOPIC_PRIORITY_RULES = {
    "extortion": "critical",
    "criminal": "high",
    "sexual": "high",
    "racist": "high",
    "spam": "medium",
}
DEFAULT_QUEUE = "general"

QUEUE_BY_CONTENT_TYPE = {
    "feed_post": "newsfeed",
    "feed_comment": "newsfeed",
    "feed_media": "newsfeed",
    "message": "messages",
    "message_media": "messages",
    "profile_photo": "profile",
}
DEFAULT_UNASSIGNED_ADMIN = "UNASSIGNED"


def _content_ref(content_type: str, content_id: str) -> str:
    return f"{content_type}#{content_id}"


def score_initial_priority(*, topics: Iterable[str]) -> str:
    normalized = {str(t).strip().lower() for t in topics if str(t).strip()}
    if not normalized:
        return DEFAULT_PRIORITY

    best = DEFAULT_PRIORITY
    for topic in sorted(normalized):
        candidate = TOPIC_PRIORITY_RULES.get(topic, DEFAULT_PRIORITY)
        if PRIORITY_RANK[candidate] > PRIORITY_RANK[best]:
            best = candidate
    return best


def queue_for_content_type(content_type: str) -> str:
    return QUEUE_BY_CONTENT_TYPE.get(str(content_type or "").strip().lower(), DEFAULT_QUEUE)


def _open_ticket_id(content_type: str, content_id: str) -> str:
    digest = hashlib.sha256(f"{content_type}:{content_id}".encode("utf-8")).hexdigest()[:20]
    return f"modtk_{digest}"


def upsert_open_ticket_for_report(*, content_type: str, content_id: str, topics: Iterable[str], now_ts: int | None = None) -> dict[str, Any]:
    """Create or update the open moderation ticket for a piece of content.

    This keeps one open ticket per content reference and performs atomic aggregation
    updates (`report_count`, `aggregated_topics`, latest timestamps) to reduce
    race-condition risk under concurrent report submissions.
    """

    ts = int(now_ts or time.time())
    ticket_id = _open_ticket_id(content_type, content_id)
    content_ref = _content_ref(content_type, content_id)
    topic_set = {str(t).strip().lower() for t in topics if str(t).strip()}
    if not topic_set:
        topic_set = {"spam"}

    priority = score_initial_priority(topics=topic_set)
    queue = queue_for_content_type(content_type)

    item = {
        "ticket_id": ticket_id,
        "entity_type": "moderation_ticket",
        "content_type": content_type,
        "content_id": content_id,
        "content_ref": content_ref,
        "content_ref_status": f"{content_ref}#{DEFAULT_STATUS}",
        "status": DEFAULT_STATUS,
        "priority": priority,
        "queue": queue,
        "assigned_admin_user_id": DEFAULT_UNASSIGNED_ADMIN,
        "report_count": 1,
        "aggregated_topics": topic_set,
        "latest_report_scope": "ALL",
        "latest_report_at": str(ts),
        "created_at": str(ts),
        "updated_at": str(ts),
    }

    try:
        T.moderation_tickets.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(ticket_id)",
        )
        return {"ticket_id": ticket_id, "status": DEFAULT_STATUS, "created": True}
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "ConditionalCheckFailedException":
            raise

    # Existing ticket path: aggregate only if the ticket is still open.
    try:
        T.moderation_tickets.update_item(
            Key={"ticket_id": ticket_id},
            ConditionExpression="#status = :open",
            UpdateExpression=(
                "SET #updated_at = :updated_at, #latest_report_at = :latest_report_at, "
                "#latest_report_scope = :latest_report_scope, #content_ref_status = :content_ref_status, "
                "#priority = if_not_exists(#priority, :priority) "
                "ADD #report_count :inc, #aggregated_topics :topics"
            ),
            ExpressionAttributeNames={
                "#status": "status",
                "#updated_at": "updated_at",
                "#latest_report_at": "latest_report_at",
                "#latest_report_scope": "latest_report_scope",
                "#content_ref_status": "content_ref_status",
                "#report_count": "report_count",
                "#aggregated_topics": "aggregated_topics",
                "#priority": "priority",
            },
            ExpressionAttributeValues={
                ":open": DEFAULT_STATUS,
                ":updated_at": str(ts),
                ":latest_report_at": str(ts),
                ":latest_report_scope": "ALL",
                ":content_ref_status": f"{content_ref}#{DEFAULT_STATUS}",
                ":inc": 1,
                ":topics": topic_set,
                ":priority": priority,
            },
        )
    except ClientError as exc:
        # If status is no longer open we fall back to a timestamp-suffixed ticket.
        code = exc.response.get("Error", {}).get("Code")
        if code != "ConditionalCheckFailedException":
            raise

        new_ticket_id = f"{ticket_id}_{ts}"
        item["ticket_id"] = new_ticket_id
        T.moderation_tickets.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(ticket_id)",
        )
        return {"ticket_id": new_ticket_id, "status": DEFAULT_STATUS, "created": True}

    return {"ticket_id": ticket_id, "status": DEFAULT_STATUS, "created": False}

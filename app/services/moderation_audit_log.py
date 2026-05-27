from __future__ import annotations

import time
import uuid
from typing import Any

from app.core.tables import T


def write_moderation_audit_event(
    *,
    action: str,
    actor_user_id: str,
    ticket_id: str = "",
    report_id: str = "",
    content_type: str = "",
    content_id: str = "",
    target_user_id: str = "",
    metadata: dict[str, Any] | None = None,
) -> str:
    now = str(int(time.time()))
    audit_id = f"modaudit_{uuid.uuid4().hex[:24]}"
    item: dict[str, Any] = {
        "audit_id": audit_id,
        "entity_type": "moderation_audit_event",
        "action": action,
        "actor_user_id": actor_user_id,
        "content_type": content_type,
        "content_id": content_id,
        "target_user_id": target_user_id,
        "created_at": now,
        "metadata": metadata or {},
    }
    # Only include GSI key attributes when non-empty to avoid DDB
    # ValidationException ("empty string value not supported for key attribute").
    if ticket_id:
        item["ticket_id"] = ticket_id
    if report_id:
        item["report_id"] = report_id
    T.moderation_audit_log.put_item(Item=item)
    return audit_id

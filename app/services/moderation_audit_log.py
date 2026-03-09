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
    T.moderation_audit_log.put_item(
        Item={
            "audit_id": audit_id,
            "entity_type": "moderation_audit_event",
            "action": action,
            "actor_user_id": actor_user_id,
            "ticket_id": ticket_id,
            "report_id": report_id,
            "content_type": content_type,
            "content_id": content_id,
            "target_user_id": target_user_id,
            "created_at": now,
            "metadata": metadata or {},
        }
    )
    return audit_id

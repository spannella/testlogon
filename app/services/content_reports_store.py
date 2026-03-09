from __future__ import annotations

import time
import uuid
from typing import Any, Iterable

from app.core.aws import ddb
from app.core.settings import S


def create_content_report(
    *,
    reporter_user_id: str,
    content_type: str,
    content_id: str,
    topics: Iterable[str],
    reason_text: str,
    linked_ticket_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Persist a moderation content report with DB-level topic checks via transaction condition checks."""
    report_id = str(uuid.uuid4())
    created_at = str(int(time.time()))
    topics_list = [t.strip().lower() for t in topics if t and t.strip()]

    extra_metadata = {k: v for k, v in (metadata or {}).items() if v is not None}

    transact_items = [
        {
            "Put": {
                "TableName": S.content_reports_table_name,
                "Item": {
                    "report_id": {"S": report_id},
                    "entity_type": {"S": "content_report"},
                    "reporter_user_id": {"S": reporter_user_id},
                    "content_type": {"S": content_type},
                    "content_id": {"S": content_id},
                    "content_ref": {"S": f"{content_type}#{content_id}"},
                    "created_scope": {"S": "ALL"},
                    "created_at": {"S": created_at},
                    "reason_text": {"S": reason_text},
                    "topics": {"SS": topics_list},
                    **({"ticket_id": {"S": linked_ticket_id}} if linked_ticket_id else {}),
                    **({k: {"S": str(v)} for k, v in extra_metadata.items()}),
                },
                "ConditionExpression": "attribute_not_exists(report_id)",
            }
        }
    ]

    for topic in topics_list:
        transact_items.append(
            {
                "ConditionCheck": {
                    "TableName": S.content_reports_table_name,
                    "Key": {"report_id": {"S": f"TOPIC#{topic}"}},
                    "ConditionExpression": "attribute_exists(report_id)",
                }
            }
        )

    ddb.meta.client.transact_write_items(TransactItems=transact_items)
    return report_id

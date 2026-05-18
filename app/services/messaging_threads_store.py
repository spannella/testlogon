from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from pydantic import BaseModel, Field

from app.core.tables import T
from app.services.messaging_thread_contract import (
    INDEX_BY_CONVERSATION_CREATED_AT,
    INDEX_BY_ROOT_MESSAGE,
    THREAD_FIELD_CONVERSATION_ID,
    THREAD_FIELD_CREATED_AT,
    THREAD_FIELD_CREATED_BY,
    THREAD_FIELD_ID,
    THREAD_FIELD_ROOT_MESSAGE_ID,
)

tbl_message_threads = T.message_threads


class MessageThreadRecord(BaseModel):
    id: str
    conversation_id: str
    root_message_id: str
    created_at: int = Field(ge=0)
    created_by: str


def _coerce_ddb_numbers(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    for key, value in out.items():
        if isinstance(value, Decimal):
            out[key] = int(value)
    return out


def _from_ddb_item(item: Optional[Dict[str, Any]]) -> Optional[MessageThreadRecord]:
    if not item:
        return None
    return MessageThreadRecord.model_validate(_coerce_ddb_numbers(item))


def create_message_thread_record(
    *,
    thread_id: str,
    conversation_id: str,
    root_message_id: str,
    created_at: int,
    created_by: str,
) -> MessageThreadRecord:
    item = {
        THREAD_FIELD_ID: thread_id,
        THREAD_FIELD_CONVERSATION_ID: conversation_id,
        THREAD_FIELD_ROOT_MESSAGE_ID: root_message_id,
        THREAD_FIELD_CREATED_AT: int(created_at),
        THREAD_FIELD_CREATED_BY: created_by,
    }
    try:
        tbl_message_threads.put_item(
            Item=item,
            ConditionExpression=f"attribute_not_exists({THREAD_FIELD_ID})",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            existing = get_message_thread_record(thread_id)
            if existing:
                return existing
        raise
    return MessageThreadRecord.model_validate(item)


def get_message_thread_record(thread_id: str) -> Optional[MessageThreadRecord]:
    resp = tbl_message_threads.get_item(Key={THREAD_FIELD_ID: thread_id})
    return _from_ddb_item(resp.get("Item"))


def list_threads_for_conversation(conversation_id: str, *, limit: int = 50) -> List[MessageThreadRecord]:
    query_limit = max(1, min(int(limit), 200))
    resp = tbl_message_threads.query(
        IndexName=INDEX_BY_CONVERSATION_CREATED_AT,
        KeyConditionExpression=Key(THREAD_FIELD_CONVERSATION_ID).eq(conversation_id),
        ScanIndexForward=False,
        Limit=query_limit,
    )
    items = resp.get("Items", [])
    return [MessageThreadRecord.model_validate(_coerce_ddb_numbers(item)) for item in items]


def find_thread_for_root_message(root_message_id: str) -> Optional[MessageThreadRecord]:
    resp = tbl_message_threads.query(
        IndexName=INDEX_BY_ROOT_MESSAGE,
        KeyConditionExpression=Key(THREAD_FIELD_ROOT_MESSAGE_ID).eq(root_message_id),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return MessageThreadRecord.model_validate(_coerce_ddb_numbers(items[0]))

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Key

from app.metrics import record_messaging_thread_reconciliation_anomaly
from app.routers import messaging
from app.services.messaging_thread_contract import (
    MESSAGE_FIELD_PARENT_ID,
    MESSAGE_FIELD_REPLY_TO_ID,
    MESSAGE_FIELD_THREAD_ID,
    MESSAGE_FIELD_THREAD_ROOT_ID,
)
from app.services.messaging_threads_store import (
    create_message_thread_record,
    find_thread_for_root_message,
)


@dataclass
class ThreadBackfillStats:
    conversations_scanned: int = 0
    eligible_roots: int = 0
    threads_created: int = 0
    messages_updated: int = 0


def _parent_id(item: dict) -> str:
    return str(item.get(MESSAGE_FIELD_PARENT_ID) or item.get(MESSAGE_FIELD_REPLY_TO_ID) or "").strip()


def _root_for_message(message_id: str, by_id: Dict[str, dict]) -> str:
    cursor = message_id
    seen: Set[str] = set()
    while cursor and cursor not in seen:
        seen.add(cursor)
        item = by_id.get(cursor)
        if not item:
            record_messaging_thread_reconciliation_anomaly(reason="missing_ancestor")
            break
        parent = _parent_id(item)
        if not parent:
            return cursor
        cursor = parent
    return message_id


def _eligible_roots(items: List[dict]) -> Tuple[Set[str], Dict[str, List[str]], Dict[str, dict]]:
    by_id = {str(item.get("message_id")): item for item in items if item.get("message_id")}
    children: Dict[str, List[str]] = {}
    for item in items:
        message_id = str(item.get("message_id") or "")
        parent = _parent_id(item)
        if message_id and parent:
            children.setdefault(parent, []).append(message_id)

    roots: Set[str] = set()
    for parent_id, direct_children in children.items():
        if len(direct_children) > 1:
            roots.add(_root_for_message(parent_id, by_id))

    for item in items:
        message_id = str(item.get("message_id") or "")
        parent = _parent_id(item)
        if not message_id or not parent:
            continue
        parent_item = by_id.get(parent) or {}
        if _parent_id(parent_item):
            roots.add(_root_for_message(parent, by_id))
    roots = {r for r in roots if r in by_id}
    return roots, children, by_id


def _subtree_ids(root_message_id: str, children: Dict[str, List[str]]) -> Set[str]:
    stack = [root_message_id]
    out: Set[str] = set()
    while stack:
        current = stack.pop()
        if current in out:
            continue
        out.add(current)
        stack.extend(children.get(current, []))
    return out


def _deterministic_thread_id(root_message_id: str) -> str:
    return f"thr_{root_message_id}"


def reconcile_conversation_reply_threads(conversation_id: str, items: List[dict]) -> ThreadBackfillStats:
    stats = ThreadBackfillStats(conversations_scanned=1)
    roots, children, by_id = _eligible_roots(items)
    stats.eligible_roots = len(roots)

    for root in sorted(roots):
        thread = find_thread_for_root_message(root)
        if not thread:
            root_item = by_id.get(root) or {}
            if not root_item:
                record_messaging_thread_reconciliation_anomaly(reason="missing_root_item")
            thread = create_message_thread_record(
                thread_id=_deterministic_thread_id(root),
                conversation_id=conversation_id,
                root_message_id=root,
                created_at=int(root_item.get("created_at") or 0),
                created_by=str(root_item.get("sender_id") or "system"),
            )
            stats.threads_created += 1

        for message_id in _subtree_ids(root, children):
            item = by_id.get(message_id) or {}
            if (
                str(item.get(MESSAGE_FIELD_THREAD_ID) or "") == thread.id
                and str(item.get(MESSAGE_FIELD_THREAD_ROOT_ID) or "") == root
            ):
                continue
            messaging.tbl_msgs.update_item(
                Key={"conversation_id": conversation_id, "message_id": message_id},
                UpdateExpression=f"SET {MESSAGE_FIELD_THREAD_ID} = :tid, {MESSAGE_FIELD_THREAD_ROOT_ID} = :rid",
                ExpressionAttributeValues={":tid": thread.id, ":rid": root},
            )
            stats.messages_updated += 1
    return stats


def run_thread_backfill_for_conversation(conversation_id: str) -> ThreadBackfillStats:
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("conversation_id").eq(conversation_id),
    }
    items: List[dict] = []
    while True:
        resp = messaging.tbl_msgs.query(**query_kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        query_kwargs["ExclusiveStartKey"] = lek
    return reconcile_conversation_reply_threads(conversation_id, items)

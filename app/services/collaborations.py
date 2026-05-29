"""Collaboration Requests (CREATOR-001) — core CRUD and state machine."""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_MAX_REVISIONS = 10


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def get_collaboration(collaboration_id: str) -> Optional[Dict[str, Any]]:
    """Fetch the CURRENT record for a collaboration."""
    resp = T.collaboration_agreements.get_item(
        Key={"collaboration_id": collaboration_id, "sk": "CURRENT"},
    )
    return resp.get("Item")


def list_collaborations(
    user_sub: str,
    *,
    role: str = "any",
    status: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """List collaborations where user_sub is initiator and/or recipient.

    *role*: ``"initiator"``, ``"recipient"``, or ``"any"`` (both).
    *status*: comma-separated status filter (e.g. ``"pending,counter"``).

    Returns ``{"items": [...], "next_cursor": str|None}``.
    """
    items_by_id: Dict[str, Dict[str, Any]] = {}

    def _query_gsi(index: str, pk_attr: str) -> None:
        kwargs: Dict[str, Any] = {
            "IndexName": index,
            "KeyConditionExpression": Key(pk_attr).eq(f"USER#{user_sub}"),
            "ScanIndexForward": False,
            "Limit": 500,
        }
        last_key = None
        while True:
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.collaboration_agreements.query(**kwargs)
            for item in resp.get("Items", []):
                if item.get("sk") != "CURRENT":
                    continue
                items_by_id[item["collaboration_id"]] = item
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

    if role in ("any", "initiator"):
        _query_gsi("ByInitiator", "GSI1PK")
    if role in ("any", "recipient"):
        _query_gsi("ByRecipient", "GSI2PK")

    items = list(items_by_id.values())

    # Filter by status if requested
    if status:
        allowed = {s.strip() for s in status.split(",")}
        items = [i for i in items if i.get("status") in allowed]

    # Sort newest first
    items.sort(key=lambda x: int(x.get("created_at", 0)), reverse=True)

    # Paginate
    items = items[: limit]

    return {"items": items, "next_cursor": None}


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def create_collaboration(
    *,
    initiator_id: str,
    recipient_id: str,
    title: str,
    description: Optional[str] = None,
    split_pct_initiator: int,
    content_types: List[str],
    terms_text: Optional[str] = None,
    valid_from: Optional[int] = None,
    valid_until: Optional[int] = None,
    max_content_items: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a new collaboration request with status=pending."""
    collab_id = f"collab_{uuid.uuid4().hex}"
    now = now_ts()
    split_pct_recipient = 100 - split_pct_initiator
    item: Dict[str, Any] = {
        "collaboration_id": collab_id,
        "sk": "CURRENT",
        "initiator_id": initiator_id,
        "recipient_id": recipient_id,
        "status": "pending",
        "content_types": content_types,
        "split": {initiator_id: split_pct_initiator, recipient_id: split_pct_recipient},
        "title": title,
        "description": description,
        "terms_text": terms_text,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "max_content_items": max_content_items,
        "content_count": 0,
        "total_revenue_cents": 0,
        "revision": 1,
        "last_proposed_by": initiator_id,
        "created_at": now,
        "updated_at": now,
        "accepted_at": None,
        "terminated_at": None,
        "terminated_by": None,
        "termination_reason": None,
        # GSI keys
        "GSI1PK": f"USER#{initiator_id}",
        "GSI1SK": now,
        "GSI2PK": f"USER#{recipient_id}",
        "GSI2SK": now,
        "GSI3PK": "STATUS#pending",
        "GSI3SK": now,
    }
    # Remove None values that DynamoDB cannot store
    item = {k: v for k, v in item.items() if v is not None}
    T.collaboration_agreements.put_item(Item=item)
    return item


def accept_collaboration(collaboration_id: str, user_sub: str) -> Dict[str, Any]:
    """Transition pending/counter -> accepted."""
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError("not_found")
    _assert_participant(collab, user_sub)
    _assert_not_proposer(collab, user_sub)
    if collab["status"] not in ("pending", "counter"):
        raise ValueError(f"Cannot accept a collaboration with status '{collab['status']}'")
    now = now_ts()
    _update_status(collaboration_id, collab["status"], "accepted", {
        "accepted_at": now,
        "GSI3PK": "STATUS#accepted",
        "updated_at": now,
    })
    return get_collaboration(collaboration_id)  # type: ignore


def reject_collaboration(collaboration_id: str, user_sub: str) -> Dict[str, Any]:
    """Transition pending/counter -> rejected."""
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError("not_found")
    _assert_participant(collab, user_sub)
    _assert_not_proposer(collab, user_sub)
    if collab["status"] not in ("pending", "counter"):
        raise ValueError(f"Cannot reject a collaboration with status '{collab['status']}'")
    now = now_ts()
    _update_status(collaboration_id, collab["status"], "rejected", {
        "GSI3PK": "STATUS#rejected",
        "updated_at": now,
    })
    return get_collaboration(collaboration_id)  # type: ignore


def cancel_collaboration(collaboration_id: str, user_sub: str) -> Dict[str, Any]:
    """Cancel a pending collaboration (initiator only)."""
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError("not_found")
    if user_sub != collab["initiator_id"]:
        raise PermissionError("Only the initiator can cancel")
    if collab["status"] not in ("pending", "counter"):
        raise ValueError(f"Cannot cancel a collaboration with status '{collab['status']}'")
    now = now_ts()
    _update_status(collaboration_id, collab["status"], "cancelled", {
        "GSI3PK": "STATUS#cancelled",
        "updated_at": now,
    })
    return get_collaboration(collaboration_id)  # type: ignore


def terminate_collaboration(collaboration_id: str, user_sub: str, reason: Optional[str] = None) -> Dict[str, Any]:
    """Terminate an accepted collaboration (either party)."""
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError("not_found")
    _assert_participant(collab, user_sub)
    if collab["status"] != "accepted":
        raise ValueError("Can only terminate an active collaboration")
    now = now_ts()
    _update_status(collaboration_id, "accepted", "terminated", {
        "terminated_at": now,
        "terminated_by": user_sub,
        "termination_reason": reason,
        "GSI3PK": "STATUS#terminated",
        "updated_at": now,
    })
    return get_collaboration(collaboration_id)  # type: ignore


def counter_propose(
    collaboration_id: str,
    user_sub: str,
    *,
    counter_split_pct: int,
    counter_terms_text: Optional[str] = None,
    counter_valid_until: Optional[int] = None,
) -> Dict[str, Any]:
    """Counter-propose with new terms. Snapshots current as REV#NNNN."""
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError("not_found")
    _assert_participant(collab, user_sub)
    _assert_not_proposer(collab, user_sub)
    if collab["status"] not in ("pending", "counter"):
        raise ValueError(f"Cannot counter a collaboration with status '{collab['status']}'")
    current_revision = int(collab.get("revision", 1))
    if current_revision >= _MAX_REVISIONS:
        raise ValueError("max_revisions")
    # Snapshot current revision
    _save_revision(collab, current_revision)
    # Build new split
    initiator_id = collab["initiator_id"]
    recipient_id = collab["recipient_id"]
    new_split = {initiator_id: counter_split_pct, recipient_id: 100 - counter_split_pct}
    now = now_ts()
    extra: Dict[str, Any] = {
        "split": new_split,
        "revision": current_revision + 1,
        "last_proposed_by": user_sub,
        "GSI3PK": "STATUS#counter",
        "updated_at": now,
    }
    if counter_terms_text is not None:
        extra["terms_text"] = counter_terms_text
    if counter_valid_until is not None:
        extra["valid_until"] = counter_valid_until
    _update_status(collaboration_id, collab["status"], "counter", extra)
    return get_collaboration(collaboration_id)  # type: ignore


def get_revision_history(collaboration_id: str) -> List[Dict[str, Any]]:
    """Return all REV# items for a collaboration."""
    resp = T.collaboration_agreements.query(
        KeyConditionExpression=(
            Key("collaboration_id").eq(collaboration_id) & Key("sk").begins_with("REV#")
        ),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: x.get("sk", ""))
    return items


def find_pending_between(user_a: str, user_b: str) -> Optional[Dict[str, Any]]:
    """Check if there's already a pending collaboration between two users."""
    # Check user_a as initiator
    resp = T.collaboration_agreements.query(
        IndexName="ByInitiator",
        KeyConditionExpression=Key("GSI1PK").eq(f"USER#{user_a}"),
        FilterExpression=Attr("recipient_id").eq(user_b) & Attr("status").is_in(["pending", "counter"]),
        Limit=50,
    )
    if resp.get("Items"):
        return resp["Items"][0]
    # Check user_b as initiator
    resp = T.collaboration_agreements.query(
        IndexName="ByInitiator",
        KeyConditionExpression=Key("GSI1PK").eq(f"USER#{user_b}"),
        FilterExpression=Attr("recipient_id").eq(user_a) & Attr("status").is_in(["pending", "counter"]),
        Limit=50,
    )
    if resp.get("Items"):
        return resp["Items"][0]
    return None


def count_pending_outgoing(user_id: str) -> int:
    """Count pending outgoing collaboration requests."""
    resp = T.collaboration_agreements.query(
        IndexName="ByInitiator",
        KeyConditionExpression=Key("GSI1PK").eq(f"USER#{user_id}"),
        FilterExpression=Attr("status").eq("pending"),
        Select="COUNT",
    )
    return int(resp.get("Count", 0))


# ---------------------------------------------------------------------------
# Per-creator collaboration settings (stored in app_single_table)
# ---------------------------------------------------------------------------

def _app_table():
    import os
    from app.core.aws import ddb
    return ddb.Table(os.environ.get("APP_TABLE", "app_single_table"))


def get_collab_settings(user_sub: str) -> Dict[str, Any]:
    """Return collaboration settings for a user, with defaults."""
    tbl = _app_table()
    resp = tbl.get_item(Key={"pk": f"USER#{user_sub}", "sk": "COLLAB_SETTINGS"})
    item = resp.get("Item", {})
    return {
        "accepting_requests": item.get("accepting_requests", True),
        "min_split_pct": int(item.get("min_split_pct", 1)),
        "allowed_content_types": item.get("allowed_content_types", ["broadcast", "post", "vod"]),
        "auto_expire_days": int(item.get("auto_expire_days", 7)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def update_collab_settings(user_sub: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Upsert per-creator collaboration settings."""
    tbl = _app_table()
    now = now_ts()
    item: Dict[str, Any] = {
        "pk": f"USER#{user_sub}",
        "sk": "COLLAB_SETTINGS",
        "updated_at": now,
    }
    for key in ("accepting_requests", "min_split_pct", "allowed_content_types", "auto_expire_days"):
        if key in updates and updates[key] is not None:
            item[key] = updates[key]
    # Merge with existing
    existing = get_collab_settings(user_sub)
    for key in ("accepting_requests", "min_split_pct", "allowed_content_types", "auto_expire_days"):
        if key not in item:
            item[key] = existing[key]
    tbl.put_item(Item=item)
    return {
        "accepting_requests": item.get("accepting_requests", True),
        "min_split_pct": int(item.get("min_split_pct", 1)),
        "allowed_content_types": item.get("allowed_content_types", ["broadcast", "post", "vod"]),
        "auto_expire_days": int(item.get("auto_expire_days", 7)),
        "updated_at": now,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _assert_participant(collab: Dict[str, Any], user_sub: str) -> None:
    if user_sub not in (collab["initiator_id"], collab["recipient_id"]):
        raise PermissionError("not_participant")


def _assert_not_proposer(collab: Dict[str, Any], user_sub: str) -> None:
    last_proposed_by = collab.get("last_proposed_by", collab["initiator_id"])
    if user_sub == last_proposed_by:
        raise PermissionError("cannot_act_on_own_proposal")


def _update_status(
    collaboration_id: str,
    expected_status: str,
    new_status: str,
    extra_attrs: Dict[str, Any],
) -> None:
    """Conditionally update status with extra attributes."""
    expr_parts = ["#s = :new_status"]
    names: Dict[str, str] = {"#s": "status"}
    values: Dict[str, Any] = {":new_status": new_status, ":expected": expected_status}

    for key, val in extra_attrs.items():
        safe_key = f"#{key.replace('.', '_')}"
        val_key = f":{key.replace('.', '_')}"
        names[safe_key] = key
        values[val_key] = val
        expr_parts.append(f"{safe_key} = {val_key}")

    T.collaboration_agreements.update_item(
        Key={"collaboration_id": collaboration_id, "sk": "CURRENT"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ConditionExpression="#s = :expected",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def _save_revision(collab: Dict[str, Any], revision_number: int) -> None:
    """Snapshot the current state as a revision item."""
    rev_item: Dict[str, Any] = {
        "collaboration_id": collab["collaboration_id"],
        "sk": f"REV#{revision_number:04d}",
        "revision": revision_number,
        "split": collab.get("split", {}),
        "terms_text": collab.get("terms_text"),
        "proposed_by": collab.get("last_proposed_by", collab["initiator_id"]),
        "proposed_at": int(collab.get("updated_at", collab.get("created_at", 0))),
        "status": "superseded",
    }
    rev_item = {k: v for k, v in rev_item.items() if v is not None}
    T.collaboration_agreements.put_item(Item=rev_item)

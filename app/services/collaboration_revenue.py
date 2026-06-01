"""Collaboration Revenue Splitting (FIN-011).

Layers content assignment, automatic revenue-split triggering, split history /
audit trail, and a dispute mechanism ON TOP of the existing collaboration
agreement system (``app/services/collaborations.py``) and the existing split
ledger writer (``app/services/collaboration_splits.py``).

Storage reuses the ``collaboration_agreements`` DynamoDB table (single-table
pattern) with new SK sub-entities:

  * Content assignment:  PK=collaboration_id  SK=CONTENT#{content_id}
  * Split execution:     PK=collaboration_id  SK=SPLIT#{ts}#{split_id}
  * Dispute record:      PK=collaboration_id  SK=DISPUTE#{ts}#{dispute_id}

A ``ByContentId`` GSI (gsi_content_pk=COLLAB_CONTENT#{content_id},
gsi_content_sk=collaboration_id) lets the billing pipeline answer
"does content X belong to any active collaboration?" with one query.

All money is integer cents; split percentages are whole-number percent (as
stored on the agreement's ``split`` map).
"""

from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.collaborations import get_collaboration
from app.services.collaboration_splits import write_collaboration_split_ledger

logger = logging.getLogger(__name__)

_CONTENT_PREFIX = "CONTENT#"
_SPLIT_PREFIX = "SPLIT#"
_DISPUTE_PREFIX = "DISPUTE#"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class NotActiveError(Exception):
    """Collaboration is not in the accepted/active state."""


class AlreadyAssignedError(Exception):
    """Content is already assigned to another active collaboration."""


class AlreadyDisputedError(Exception):
    """A dispute has already been filed on this split."""


# ---------------------------------------------------------------------------
# Participant helpers
# ---------------------------------------------------------------------------

def is_participant(collab: Dict[str, Any], user_id: str) -> bool:
    return user_id in (collab.get("initiator_id"), collab.get("recipient_id"))


def _require_participant(collab: Dict[str, Any], user_id: str) -> None:
    if not is_participant(collab, user_id):
        raise PermissionError("forbidden")


def _to_int(v: Any) -> int:
    if v is None:
        return 0
    return int(v)


# ---------------------------------------------------------------------------
# Content assignment
# ---------------------------------------------------------------------------

def find_collaboration_for_content(content_id: str) -> Optional[Dict[str, Any]]:
    """Return the active (accepted) collaboration that owns ``content_id``.

    Uses the ByContentId GSI. Returns the collaboration CURRENT record if the
    assignment exists and the owning collaboration is still accepted, else None.
    """
    try:
        resp = T.collaboration_agreements.query(
            IndexName="ByContentId",
            KeyConditionExpression=Key("gsi_content_pk").eq(f"COLLAB_CONTENT#{content_id}"),
            Limit=10,
        )
    except Exception:
        logger.warning("find_collaboration_for_content query failed", exc_info=True)
        return None
    for assign in resp.get("Items", []):
        collab_id = assign.get("collaboration_id")
        if not collab_id:
            continue
        collab = get_collaboration(collab_id)
        if collab and collab.get("status") == "accepted":
            return collab
    return None


def get_content_assignment(collaboration_id: str, content_id: str) -> Optional[Dict[str, Any]]:
    resp = T.collaboration_agreements.get_item(
        Key={"collaboration_id": collaboration_id, "sk": f"{_CONTENT_PREFIX}{content_id}"},
    )
    return resp.get("Item")


def assign_content(
    collaboration_id: str,
    content_id: str,
    content_type: str,
    assigned_by: str,
    title: str = "",
) -> Dict[str, Any]:
    """Assign a content item to a collaboration for automatic revenue splitting.

    Validates:
      * Collaboration exists and is accepted (else NotActiveError).
      * Assigner is a participant (else PermissionError).
      * content_type is in the collaboration's allowed content_types.
      * max_content_items limit not exceeded.
      * Content is not already assigned to another active collaboration
        (else AlreadyAssignedError).
    """
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError("not_found")
    _require_participant(collab, assigned_by)
    if collab.get("status") != "accepted":
        raise NotActiveError("not_active")

    allowed_types = collab.get("content_types") or []
    if allowed_types and content_type not in allowed_types:
        raise ValueError(f"content_type '{content_type}' not allowed for this collaboration")

    # Idempotent: already assigned to THIS collaboration -> return existing.
    existing = get_content_assignment(collaboration_id, content_id)
    if existing:
        return existing

    # Exclusivity: not assigned to any OTHER active collaboration.
    other = find_collaboration_for_content(content_id)
    if other and other.get("collaboration_id") != collaboration_id:
        raise AlreadyAssignedError("already_assigned")

    # max_content_items limit
    max_items = collab.get("max_content_items")
    if max_items is not None:
        current_count = _to_int(collab.get("content_count", 0))
        if current_count >= int(max_items):
            raise ValueError("max_content_items limit reached")

    now = now_ts()
    item: Dict[str, Any] = {
        "collaboration_id": collaboration_id,
        "sk": f"{_CONTENT_PREFIX}{content_id}",
        "content_id": content_id,
        "content_type": content_type,
        "title": title or "",
        "assigned_by": assigned_by,
        "assigned_at": now,
        "total_revenue_cents": 0,
        "split_count": 0,
        # ByContentId GSI keys
        "gsi_content_pk": f"COLLAB_CONTENT#{content_id}",
        "gsi_content_sk": collaboration_id,
    }
    T.collaboration_agreements.put_item(Item=item)

    # Bump content_count on the agreement (best-effort).
    try:
        T.collaboration_agreements.update_item(
            Key={"collaboration_id": collaboration_id, "sk": "CURRENT"},
            UpdateExpression="SET content_count = if_not_exists(content_count, :z) + :one, updated_at = :now",
            ExpressionAttributeValues={":one": 1, ":z": 0, ":now": now},
        )
    except Exception:
        logger.warning("Failed to bump content_count for %s", collaboration_id, exc_info=True)

    return item


def unassign_content(collaboration_id: str, content_id: str, user_id: str) -> bool:
    """Remove a content item from a collaboration. Participants only."""
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError("not_found")
    _require_participant(collab, user_id)

    existing = get_content_assignment(collaboration_id, content_id)
    if not existing:
        return False

    T.collaboration_agreements.delete_item(
        Key={"collaboration_id": collaboration_id, "sk": f"{_CONTENT_PREFIX}{content_id}"},
    )
    try:
        T.collaboration_agreements.update_item(
            Key={"collaboration_id": collaboration_id, "sk": "CURRENT"},
            UpdateExpression="SET content_count = if_not_exists(content_count, :z) - :one, updated_at = :now",
            ConditionExpression="content_count > :z",
            ExpressionAttributeValues={":one": 1, ":z": 0, ":now": now_ts()},
        )
    except Exception:
        # ConditionExpression may legitimately fail if count is already 0.
        pass
    return True


def list_collaboration_content(collaboration_id: str) -> List[Dict[str, Any]]:
    """List all content items assigned to a collaboration."""
    resp = T.collaboration_agreements.query(
        KeyConditionExpression=(
            Key("collaboration_id").eq(collaboration_id) & Key("sk").begins_with(_CONTENT_PREFIX)
        ),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: _to_int(x.get("assigned_at", 0)), reverse=True)
    return items


# ---------------------------------------------------------------------------
# Split execution (auto-trigger)
# ---------------------------------------------------------------------------

def _record_split_execution(
    *,
    collaboration_id: str,
    content_id: str,
    content_type: str,
    gross_amount_cents: int,
    source: str,
    split_map: Dict[str, int],
    distributions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    now = now_ts()
    split_id = f"csplit_{uuid.uuid4().hex}"
    item: Dict[str, Any] = {
        "collaboration_id": collaboration_id,
        "sk": f"{_SPLIT_PREFIX}{now}#{split_id}",
        "split_id": split_id,
        "content_id": content_id,
        "content_type": content_type,
        "gross_amount_cents": int(gross_amount_cents),
        "source": source,
        "distributions": distributions,
        "created_at": now,
        "dispute_status": None,
    }
    item = {k: v for k, v in item.items() if v is not None}
    T.collaboration_agreements.put_item(Item=item)
    return item


def execute_content_split(
    content_id: str,
    amount_cents: int,
    source: str,
    payer_user_id: str,
    *,
    content_type: str = "",
    currency: str = "USD",
) -> Optional[Dict[str, Any]]:
    """If ``content_id`` belongs to an active collaboration, execute the split.

    Reuses ``write_collaboration_split_ledger`` to write the per-collaborator
    ledger entries, then records an immutable split execution row and bumps the
    per-content + agreement revenue totals.

    Returns the split execution record, or None if the content is not assigned
    to any active collaboration (or amount is non-positive).
    """
    if amount_cents <= 0:
        return None

    collab = find_collaboration_for_content(content_id)
    if not collab:
        return None

    collaboration_id = collab["collaboration_id"]
    split_map = {k: int(v) for k, v in (collab.get("split") or {}).items()}

    # Resolve the content_type from the assignment record if not provided.
    resolved_type = content_type
    if not resolved_type:
        assign = get_content_assignment(collaboration_id, content_id)
        resolved_type = (assign or {}).get("content_type", "") or "collaboration"

    # Reuse the existing split ledger writer (also updates total_revenue_cents).
    credited = write_collaboration_split_ledger(
        collaboration_id=collaboration_id,
        payer_user_id=payer_user_id,
        amount_cents=amount_cents,
        currency=currency,
        content_type=resolved_type,
        content_id=content_id,
    )

    distributions: List[Dict[str, Any]] = []
    for user_id, pct in sorted(split_map.items()):
        distributions.append({
            "user_id": user_id,
            "amount_cents": int(credited.get(user_id, 0)),
            "percentage": int(pct),
        })
    # Include any credited party not in the split map (e.g. remainder to initiator).
    for user_id, amt in credited.items():
        if not any(d["user_id"] == user_id for d in distributions):
            distributions.append({
                "user_id": user_id,
                "amount_cents": int(amt),
                "percentage": int(split_map.get(user_id, 0)),
            })

    record = _record_split_execution(
        collaboration_id=collaboration_id,
        content_id=content_id,
        content_type=resolved_type,
        gross_amount_cents=amount_cents,
        source=source,
        split_map=split_map,
        distributions=distributions,
    )

    # Bump per-content revenue + split_count (best-effort).
    try:
        T.collaboration_agreements.update_item(
            Key={"collaboration_id": collaboration_id, "sk": f"{_CONTENT_PREFIX}{content_id}"},
            UpdateExpression=(
                "SET total_revenue_cents = if_not_exists(total_revenue_cents, :z) + :amt, "
                "split_count = if_not_exists(split_count, :z) + :one"
            ),
            ExpressionAttributeValues={":amt": int(amount_cents), ":one": 1, ":z": 0},
        )
    except Exception:
        logger.warning("Failed to bump per-content revenue for %s", content_id, exc_info=True)

    return record


def maybe_split_content_revenue(
    *,
    content_id: str,
    amount_cents: int,
    source: str,
    payer_user_id: str,
    content_type: str = "",
    currency: str = "USD",
) -> Optional[Dict[str, Any]]:
    """Billing-hook entry point. Safe to call from any revenue flow.

    Returns the split record if a split was executed (caller should then SKIP
    its normal single-creator credit), else None (caller proceeds normally).
    Never raises -- failures degrade to "no split".
    """
    try:
        return execute_content_split(
            content_id,
            amount_cents,
            source,
            payer_user_id,
            content_type=content_type,
            currency=currency,
        )
    except Exception:
        logger.warning("maybe_split_content_revenue failed for content %s", content_id, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Split history
# ---------------------------------------------------------------------------

def get_split(collaboration_id: str, split_id: str) -> Optional[Dict[str, Any]]:
    resp = T.collaboration_agreements.query(
        KeyConditionExpression=(
            Key("collaboration_id").eq(collaboration_id) & Key("sk").begins_with(_SPLIT_PREFIX)
        ),
    )
    for item in resp.get("Items", []):
        if item.get("split_id") == split_id:
            return item
    return None


def get_split_history(
    collaboration_id: str,
    user_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Return split execution history for a collaboration (participants only)."""
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError("not_found")
    _require_participant(collab, user_id)

    resp = T.collaboration_agreements.query(
        KeyConditionExpression=(
            Key("collaboration_id").eq(collaboration_id) & Key("sk").begins_with(_SPLIT_PREFIX)
        ),
        ScanIndexForward=False,
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: _to_int(x.get("created_at", 0)), reverse=True)
    items = items[: int(limit)]
    return {"items": items, "next_cursor": None}


# ---------------------------------------------------------------------------
# Disputes
# ---------------------------------------------------------------------------

def _get_dispute(collaboration_id: str, dispute_id: str) -> Optional[Dict[str, Any]]:
    resp = T.collaboration_agreements.query(
        KeyConditionExpression=(
            Key("collaboration_id").eq(collaboration_id) & Key("sk").begins_with(_DISPUTE_PREFIX)
        ),
    )
    for item in resp.get("Items", []):
        if item.get("dispute_id") == dispute_id:
            return item
    return None


def file_dispute(
    collaboration_id: str,
    split_id: str,
    filed_by: str,
    reason: str,
    proposed_split: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """File a dispute on a specific split. Participants only.

    Marks the split record dispute_status="disputed". Raises AlreadyDisputedError
    if the split is already disputed.
    """
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError("not_found")
    _require_participant(collab, filed_by)

    split = get_split(collaboration_id, split_id)
    if not split:
        raise KeyError("split_not_found")
    if split.get("dispute_status") == "disputed":
        raise AlreadyDisputedError("already_disputed")

    now = now_ts()
    dispute_id = f"disp_{uuid.uuid4().hex}"
    item: Dict[str, Any] = {
        "collaboration_id": collaboration_id,
        "sk": f"{_DISPUTE_PREFIX}{now}#{dispute_id}",
        "dispute_id": dispute_id,
        "split_id": split_id,
        "filed_by": filed_by,
        "reason": reason,
        "proposed_split": {k: int(v) for k, v in (proposed_split or {}).items()} or None,
        "status": "open",
        "resolution": "",
        "resolved_by": "",
        "resolved_at": 0,
        "created_at": now,
        # ByStatus-ish GSI keys for admin queue
        "gsi_dispute_pk": "DISPUTE_STATUS#open",
        "gsi_dispute_sk": now,
    }
    item = {k: v for k, v in item.items() if v is not None}
    T.collaboration_agreements.put_item(Item=item)

    # Mark the split record as disputed.
    try:
        T.collaboration_agreements.update_item(
            Key={"collaboration_id": collaboration_id, "sk": split["sk"]},
            UpdateExpression="SET dispute_status = :d",
            ExpressionAttributeValues={":d": "disputed"},
        )
    except Exception:
        logger.warning("Failed to mark split %s disputed", split_id, exc_info=True)

    return item


def resolve_dispute(
    dispute_id: str,
    collaboration_id: str,
    resolved_by: str,
    resolution: str,
    accept: bool = True,
    *,
    is_admin: bool = False,
) -> Dict[str, Any]:
    """Resolve a dispute (accept or counter). Participants or admin.

    When ``accept`` is True the dispute is closed (status="resolved") and the
    associated split record's dispute_status is set to "resolved". When False
    the dispute moves to "counter" (or "admin_review" if filed by the resolver).
    """
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError("not_found")
    if not is_admin:
        _require_participant(collab, resolved_by)

    dispute = _get_dispute(collaboration_id, dispute_id)
    if not dispute:
        raise KeyError("dispute_not_found")

    now = now_ts()
    new_status = "resolved" if accept else "counter"
    if is_admin:
        new_status = "resolved"

    T.collaboration_agreements.update_item(
        Key={"collaboration_id": collaboration_id, "sk": dispute["sk"]},
        UpdateExpression=(
            "SET #s = :s, resolution = :r, resolved_by = :rb, resolved_at = :ra, "
            "gsi_dispute_pk = :gp"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": new_status,
            ":r": resolution,
            ":rb": resolved_by,
            ":ra": now,
            ":gp": f"DISPUTE_STATUS#{new_status}",
        },
    )

    if new_status == "resolved":
        split_id = dispute.get("split_id")
        split = get_split(collaboration_id, split_id) if split_id else None
        if split:
            try:
                T.collaboration_agreements.update_item(
                    Key={"collaboration_id": collaboration_id, "sk": split["sk"]},
                    UpdateExpression="SET dispute_status = :d",
                    ExpressionAttributeValues={":d": "resolved"},
                )
            except Exception:
                logger.warning("Failed to mark split %s resolved", split_id, exc_info=True)

    return _get_dispute(collaboration_id, dispute_id)  # type: ignore


def list_disputes(
    collaboration_id: Optional[str] = None,
    status: Optional[str] = "open",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List disputes.

    If ``collaboration_id`` is given, return disputes for that collaboration
    (optionally filtered by status). If None, list across all collaborations
    via the gsi_dispute_pk GSI (admin queue).
    """
    items: List[Dict[str, Any]]
    if collaboration_id:
        resp = T.collaboration_agreements.query(
            KeyConditionExpression=(
                Key("collaboration_id").eq(collaboration_id) & Key("sk").begins_with(_DISPUTE_PREFIX)
            ),
        )
        items = resp.get("Items", [])
        if status:
            items = [i for i in items if i.get("status") == status]
    else:
        target_status = status or "open"
        resp = T.collaboration_agreements.query(
            IndexName="ByDisputeStatus",
            KeyConditionExpression=Key("gsi_dispute_pk").eq(f"DISPUTE_STATUS#{target_status}"),
            ScanIndexForward=False,
            Limit=int(limit),
        )
        items = resp.get("Items", [])

    items.sort(key=lambda x: _to_int(x.get("created_at", 0)), reverse=True)
    return items[: int(limit)]

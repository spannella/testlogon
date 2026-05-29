"""Collaboration Requests router (CREATOR-001)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.models import (
    CollaborationCreateIn,
    CollaborationCounterIn,
    CollaborationListOut,
    CollaborationOut,
    CollaborationRevisionOut,
    CollaborationSettingsIn,
    CollaborationSettingsOut,
    CollaborationSplitIn,
    CollaborationTerminateIn,
)
from app.services.collaborations import (
    accept_collaboration,
    cancel_collaboration,
    count_pending_outgoing,
    counter_propose,
    create_collaboration,
    find_pending_between,
    get_collab_settings,
    get_collaboration,
    get_revision_history,
    list_collaborations,
    reject_collaboration,
    terminate_collaboration,
    update_collab_settings,
)
from app.services.collaboration_splits import write_collaboration_split_ledger
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/collaborations", tags=["collaborations"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _item_to_out(item: Dict[str, Any]) -> CollaborationOut:
    """Convert a DDB item to a CollaborationOut model."""
    return CollaborationOut(
        collaboration_id=item["collaboration_id"],
        initiator_id=item.get("initiator_id", ""),
        recipient_id=item.get("recipient_id", ""),
        status=item.get("status", ""),
        content_types=item.get("content_types", []),
        split={k: int(v) for k, v in (item.get("split") or {}).items()},
        title=item.get("title", ""),
        description=item.get("description"),
        terms_text=item.get("terms_text"),
        valid_from=int(item["valid_from"]) if item.get("valid_from") is not None else None,
        valid_until=int(item["valid_until"]) if item.get("valid_until") is not None else None,
        max_content_items=int(item["max_content_items"]) if item.get("max_content_items") is not None else None,
        content_count=int(item.get("content_count", 0)),
        total_revenue_cents=int(item.get("total_revenue_cents", 0)),
        revision=int(item.get("revision", 1)),
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
        accepted_at=int(item["accepted_at"]) if item.get("accepted_at") is not None else None,
        terminated_at=int(item["terminated_at"]) if item.get("terminated_at") is not None else None,
        terminated_by=item.get("terminated_by"),
        termination_reason=item.get("termination_reason"),
        last_proposed_by=item.get("last_proposed_by"),
    )


def _check_enabled():
    if not S.collaborations_enabled:
        raise HTTPException(503, "Collaborations feature is disabled")


# ---------------------------------------------------------------------------
# CRUD endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=CollaborationOut, status_code=201)
def create_collab(body: CollaborationCreateIn, ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    user_id = ctx["user_sub"]

    if user_id == body.recipient_id:
        raise HTTPException(400, "Cannot create a collaboration with yourself")

    # Check recipient settings
    recipient_settings = get_collab_settings(body.recipient_id)
    if not recipient_settings.get("accepting_requests", True):
        raise HTTPException(403, "This creator is not accepting collaboration requests")

    recipient_share = 100 - body.split_pct
    min_split = int(recipient_settings.get("min_split_pct", 1))
    if recipient_share < min_split:
        raise HTTPException(400, f"Recipient requires at least {min_split}% share")

    # Check no duplicate pending
    existing = find_pending_between(user_id, body.recipient_id)
    if existing:
        raise HTTPException(409, "A pending collaboration request already exists between you and this creator")

    # Check outgoing limit
    pending_count = count_pending_outgoing(user_id)
    if pending_count >= 10:
        raise HTTPException(429, "Maximum 10 pending outgoing collaboration requests")

    item = create_collaboration(
        initiator_id=user_id,
        recipient_id=body.recipient_id,
        title=body.title,
        description=body.description,
        split_pct_initiator=body.split_pct,
        content_types=body.content_types,
        terms_text=body.terms_text,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
        max_content_items=body.max_content_items,
    )
    return _item_to_out(item)


@router.get("", response_model=CollaborationListOut)
def list_collabs(
    role: str = Query("any"),
    status: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    ctx: Dict = Depends(require_ui_session),
):
    _check_enabled()
    user_id = ctx["user_sub"]
    result = list_collaborations(user_id, role=role, status=status, cursor=cursor, limit=limit)
    return CollaborationListOut(
        items=[_item_to_out(i) for i in result["items"]],
        next_cursor=result.get("next_cursor"),
    )


@router.get("/settings", response_model=CollaborationSettingsOut)
def get_settings(ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    settings = get_collab_settings(ctx["user_sub"])
    return CollaborationSettingsOut(**settings)


@router.put("/settings", response_model=CollaborationSettingsOut)
def update_settings(body: CollaborationSettingsIn, ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    updates = body.model_dump(exclude_none=True)
    result = update_collab_settings(ctx["user_sub"], updates)
    return CollaborationSettingsOut(**result)


@router.get("/{collab_id}", response_model=CollaborationOut)
def get_collab(collab_id: str, ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    item = get_collaboration(collab_id)
    if not item:
        raise HTTPException(404, "Collaboration not found")
    user_id = ctx["user_sub"]
    if user_id not in (item.get("initiator_id"), item.get("recipient_id")):
        raise HTTPException(403, "You are not a participant in this collaboration")
    return _item_to_out(item)


@router.post("/{collab_id}/accept", response_model=CollaborationOut)
def accept_collab(collab_id: str, ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    try:
        result = accept_collaboration(collab_id, ctx["user_sub"])
    except KeyError:
        raise HTTPException(404, "Collaboration not found")
    except PermissionError as e:
        if "not_participant" in str(e):
            raise HTTPException(403, "You are not a participant in this collaboration")
        raise HTTPException(403, "You cannot accept your own proposal")
    except ValueError as e:
        raise HTTPException(409, str(e))
    return _item_to_out(result)


@router.post("/{collab_id}/reject", response_model=CollaborationOut)
def reject_collab(collab_id: str, ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    try:
        result = reject_collaboration(collab_id, ctx["user_sub"])
    except KeyError:
        raise HTTPException(404, "Collaboration not found")
    except PermissionError as e:
        if "not_participant" in str(e):
            raise HTTPException(403, "You are not a participant in this collaboration")
        raise HTTPException(403, "You cannot reject your own proposal")
    except ValueError as e:
        raise HTTPException(409, str(e))
    return _item_to_out(result)


@router.post("/{collab_id}/counter", response_model=CollaborationOut)
def counter_collab(collab_id: str, body: CollaborationCounterIn, ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    try:
        result = counter_propose(
            collab_id,
            ctx["user_sub"],
            counter_split_pct=body.counter_split_pct,
            counter_terms_text=body.counter_terms_text,
            counter_valid_until=body.counter_valid_until,
        )
    except KeyError:
        raise HTTPException(404, "Collaboration not found")
    except PermissionError as e:
        if "not_participant" in str(e):
            raise HTTPException(403, "You are not a participant in this collaboration")
        raise HTTPException(403, "You cannot counter your own proposal")
    except ValueError as e:
        if "max_revisions" in str(e):
            raise HTTPException(409, "Maximum negotiation revisions reached")
        raise HTTPException(409, str(e))
    return _item_to_out(result)


@router.post("/{collab_id}/cancel", response_model=CollaborationOut)
def cancel_collab(collab_id: str, ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    try:
        result = cancel_collaboration(collab_id, ctx["user_sub"])
    except KeyError:
        raise HTTPException(404, "Collaboration not found")
    except PermissionError:
        raise HTTPException(403, "Only the initiator can cancel")
    except ValueError as e:
        raise HTTPException(409, str(e))
    return _item_to_out(result)


@router.post("/{collab_id}/terminate", response_model=CollaborationOut)
def terminate_collab(collab_id: str, body: CollaborationTerminateIn = CollaborationTerminateIn(), ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    try:
        result = terminate_collaboration(collab_id, ctx["user_sub"], reason=body.reason)
    except KeyError:
        raise HTTPException(404, "Collaboration not found")
    except PermissionError:
        raise HTTPException(403, "You are not a participant in this collaboration")
    except ValueError as e:
        raise HTTPException(409, str(e))
    return _item_to_out(result)


@router.get("/{collab_id}/revisions", response_model=List[CollaborationRevisionOut])
def list_revisions(collab_id: str, ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    # Verify participation
    item = get_collaboration(collab_id)
    if not item:
        raise HTTPException(404, "Collaboration not found")
    user_id = ctx["user_sub"]
    if user_id not in (item.get("initiator_id"), item.get("recipient_id")):
        raise HTTPException(403, "You are not a participant in this collaboration")

    revisions = get_revision_history(collab_id)
    return [
        CollaborationRevisionOut(
            revision=int(r.get("revision", 0)),
            split={k: int(v) for k, v in (r.get("split") or {}).items()},
            terms_text=r.get("terms_text"),
            proposed_by=r.get("proposed_by", ""),
            proposed_at=int(r.get("proposed_at", 0)),
            status=r.get("status", "superseded"),
        )
        for r in revisions
    ]


# ---------------------------------------------------------------------------
# Revenue split endpoint (for testing)
# ---------------------------------------------------------------------------

@router.post("/{collab_id}/split")
def split_revenue(collab_id: str, body: CollaborationSplitIn, ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    try:
        results = write_collaboration_split_ledger(
            collaboration_id=collab_id,
            payer_user_id=ctx["user_sub"],
            amount_cents=body.amount_cents,
            currency=body.currency,
            content_type=body.content_type,
            content_id=body.content_id,
        )
    except KeyError:
        raise HTTPException(404, "Collaboration not found")
    except ValueError as e:
        raise HTTPException(409, str(e))
    return {"ok": True, "splits": {k: int(v) for k, v in results.items()}}

"""Collaboration Requests router (CREATOR-001)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.models import (
    CollabContentAssignIn,
    CollabContentItem,
    CollabContentListOut,
    CollabContentSplitTriggerIn,
    CollabDisputeIn,
    CollabDisputeListOut,
    CollabDisputeOut,
    CollabDisputeResolveIn,
    CollabSplitHistoryOut,
    CollabSplitRecord,
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
from app.services import collaboration_revenue as cr
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


# ---------------------------------------------------------------------------
# Collaboration Revenue Splitting (FIN-011)
# ---------------------------------------------------------------------------

def _content_item_out(item: Dict[str, Any]) -> CollabContentItem:
    return CollabContentItem(
        content_id=item.get("content_id", ""),
        content_type=item.get("content_type", ""),
        title=item.get("title", ""),
        assigned_by=item.get("assigned_by", ""),
        assigned_at=item.get("assigned_at", 0),
        total_revenue_cents=item.get("total_revenue_cents", 0),
        split_count=item.get("split_count", 0),
    )


def _split_record_out(item: Dict[str, Any]) -> CollabSplitRecord:
    return CollabSplitRecord(
        split_id=item.get("split_id", ""),
        content_id=item.get("content_id", ""),
        content_type=item.get("content_type", ""),
        gross_amount_cents=item.get("gross_amount_cents", 0),
        source=item.get("source", ""),
        distributions=item.get("distributions", []) or [],
        created_at=item.get("created_at", 0),
        dispute_status=item.get("dispute_status"),
    )


def _dispute_out(item: Dict[str, Any]) -> CollabDisputeOut:
    proposed = item.get("proposed_split")
    return CollabDisputeOut(
        dispute_id=item.get("dispute_id", ""),
        split_id=item.get("split_id", ""),
        collaboration_id=item.get("collaboration_id", ""),
        filed_by=item.get("filed_by", ""),
        reason=item.get("reason", ""),
        proposed_split={k: int(v) for k, v in proposed.items()} if proposed else None,
        status=item.get("status", ""),
        resolution=item.get("resolution", "") or "",
        resolved_by=item.get("resolved_by", "") or "",
        resolved_at=item.get("resolved_at", 0),
        created_at=item.get("created_at", 0),
    )


def _is_admin(ctx: Dict) -> bool:
    return str(ctx.get("role", "")).lower() in ("admin", "root")


@router.post("/{collab_id}/content", status_code=200)
def assign_content_to_collab(
    collab_id: str, body: CollabContentAssignIn, ctx: Dict = Depends(require_ui_session),
):
    _check_enabled()
    try:
        cr.assign_content(
            collaboration_id=collab_id,
            content_id=body.content_id,
            content_type=body.content_type,
            assigned_by=ctx["user_sub"],
            title=body.title,
            skip_ownership_check=_is_admin(ctx),
        )
    except KeyError:
        raise HTTPException(404, "Collaboration not found")
    except PermissionError as exc:
        detail = (
            "You do not own this content"
            if "content_not_owned" in str(exc)
            else "Not a collaboration participant"
        )
        raise HTTPException(403, detail)
    except cr.NotActiveError:
        raise HTTPException(400, "Collaboration is not active")
    except cr.AlreadyAssignedError:
        raise HTTPException(409, "Content already in another collaboration")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "content_id": body.content_id, "collaboration_id": collab_id}


@router.get("/{collab_id}/content", response_model=CollabContentListOut)
def list_collab_content(collab_id: str, ctx: Dict = Depends(require_ui_session)):
    _check_enabled()
    collab = get_collaboration(collab_id)
    if not collab:
        raise HTTPException(404, "Collaboration not found")
    if not cr.is_participant(collab, ctx["user_sub"]):
        raise HTTPException(403, "Not a collaboration participant")
    items = cr.list_collaboration_content(collab_id)
    return CollabContentListOut(
        items=[_content_item_out(i) for i in items],
        collaboration_id=collab_id,
    )


@router.delete("/{collab_id}/content/{content_id}", status_code=200)
def unassign_content_from_collab(
    collab_id: str, content_id: str, ctx: Dict = Depends(require_ui_session),
):
    _check_enabled()
    try:
        removed = cr.unassign_content(collab_id, content_id, ctx["user_sub"])
    except KeyError:
        raise HTTPException(404, "Collaboration not found")
    except PermissionError:
        raise HTTPException(403, "Not a collaboration participant")
    if not removed:
        raise HTTPException(404, "Content not assigned to this collaboration")
    return {"ok": True, "content_id": content_id, "collaboration_id": collab_id}


@router.post("/{collab_id}/content/{content_id}/revenue-event", status_code=200)
def record_content_revenue_event(
    collab_id: str, content_id: str, body: CollabContentSplitTriggerIn,
    ctx: Dict = Depends(require_ui_session),
):
    """Deterministically trigger an auto-split for a revenue event on assigned
    content (used by billing hooks and E2E). Splits per the agreement."""
    _check_enabled()
    collab = get_collaboration(collab_id)
    if not collab:
        raise HTTPException(404, "Collaboration not found")
    if not cr.is_participant(collab, ctx["user_sub"]):
        raise HTTPException(403, "Not a collaboration participant")
    if body.content_id != content_id:
        raise HTTPException(400, "content_id mismatch")
    record = cr.execute_content_split(
        content_id=content_id,
        amount_cents=body.amount_cents,
        source=body.source,
        payer_user_id=ctx["user_sub"],
        currency=body.currency,
    )
    if record is None:
        raise HTTPException(400, "Content is not assigned to an active collaboration")
    return {"ok": True, "split": _split_record_out(record).model_dump()}


@router.get("/{collab_id}/splits", response_model=CollabSplitHistoryOut)
def get_collab_split_history(
    collab_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
    ctx: Dict = Depends(require_ui_session),
):
    _check_enabled()
    try:
        result = cr.get_split_history(collab_id, ctx["user_sub"], limit=limit, cursor=cursor)
    except KeyError:
        raise HTTPException(404, "Collaboration not found")
    except PermissionError:
        raise HTTPException(403, "Not a collaboration participant")
    return CollabSplitHistoryOut(
        items=[_split_record_out(i) for i in result["items"]],
        next_cursor=result.get("next_cursor"),
    )


@router.post("/{collab_id}/splits/{split_id}/dispute", status_code=200)
def file_split_dispute(
    collab_id: str, split_id: str, body: CollabDisputeIn,
    ctx: Dict = Depends(require_ui_session),
):
    _check_enabled()
    try:
        cr.file_dispute(
            collaboration_id=collab_id,
            split_id=split_id,
            filed_by=ctx["user_sub"],
            reason=body.reason,
            proposed_split=body.proposed_split,
        )
    except KeyError as e:
        if "split" in str(e):
            raise HTTPException(404, "Split record not found")
        raise HTTPException(404, "Collaboration not found")
    except PermissionError:
        raise HTTPException(403, "Not a collaboration participant")
    except cr.AlreadyDisputedError:
        raise HTTPException(409, "Dispute already filed on this split")
    return {"ok": True, "dispute_status": "disputed"}


@router.get("/{collab_id}/disputes", response_model=CollabDisputeListOut)
def list_collab_disputes(
    collab_id: str,
    status: Optional[str] = Query(None),
    ctx: Dict = Depends(require_ui_session),
):
    _check_enabled()
    collab = get_collaboration(collab_id)
    if not collab:
        raise HTTPException(404, "Collaboration not found")
    if not cr.is_participant(collab, ctx["user_sub"]) and not _is_admin(ctx):
        raise HTTPException(403, "Not a collaboration participant")
    items = cr.list_disputes(collaboration_id=collab_id, status=status)
    return CollabDisputeListOut(items=[_dispute_out(i) for i in items])


@router.post("/{collab_id}/disputes/{dispute_id}/resolve", status_code=200)
def resolve_collab_dispute(
    collab_id: str, dispute_id: str, body: CollabDisputeResolveIn,
    ctx: Dict = Depends(require_ui_session),
):
    _check_enabled()
    admin = _is_admin(ctx)
    try:
        result = cr.resolve_dispute(
            dispute_id=dispute_id,
            collaboration_id=collab_id,
            resolved_by=ctx["user_sub"],
            resolution=body.resolution,
            accept=body.accept,
            is_admin=admin,
        )
    except KeyError as e:
        if "dispute" in str(e):
            raise HTTPException(404, "Dispute not found")
        raise HTTPException(404, "Collaboration not found")
    except PermissionError:
        raise HTTPException(403, "Not a collaboration participant")
    return {"ok": True, "status": result.get("status", ""), "dispute": _dispute_out(result).model_dump()}


# ---------------------------------------------------------------------------
# Admin-global dispute arbitration (FIN-011 / GAP-0199)
# ---------------------------------------------------------------------------

admin_router = APIRouter(
    prefix="/ui/admin/collaboration-disputes", tags=["admin-collaborations"]
)


def _require_admin(ctx: Dict) -> None:
    if not _is_admin(ctx):
        raise HTTPException(403, "Admin access required")


@admin_router.get("", response_model=CollabDisputeListOut)
def admin_list_all_disputes(
    status: Optional[str] = Query("open"),
    limit: int = Query(50, ge=1, le=200),
    ctx: Dict = Depends(require_ui_session),
):
    """List all disputes across every collaboration (admin queue, GAP-0199)."""
    _check_enabled()
    _require_admin(ctx)
    items = cr.list_disputes(collaboration_id=None, status=status, limit=limit)
    return CollabDisputeListOut(items=[_dispute_out(i) for i in items])


@admin_router.post("/{dispute_id}/arbitrate", status_code=200)
def admin_arbitrate_dispute(
    dispute_id: str,
    body: CollabDisputeResolveIn,
    ctx: Dict = Depends(require_ui_session),
):
    """Admin force-resolve any dispute by dispute_id without needing collab_id
    (GAP-0199). Looks up the dispute's own collaboration_id from the record."""
    _check_enabled()
    _require_admin(ctx)

    dispute = cr.get_dispute_global(dispute_id)
    if not dispute:
        raise HTTPException(404, "Dispute not found")
    collab_id = dispute.get("collaboration_id")
    if not collab_id:
        raise HTTPException(500, "Dispute record missing collaboration_id")

    logger.info(
        "Admin arbitration: dispute=%s collab=%s admin=%s accept=%s",
        dispute_id, collab_id, ctx.get("user_sub"), body.accept,
    )
    try:
        result = cr.resolve_dispute(
            dispute_id=dispute_id,
            collaboration_id=collab_id,
            resolved_by=ctx["user_sub"],
            resolution=body.resolution,
            accept=body.accept,
            is_admin=True,
        )
    except KeyError as e:
        if "dispute" in str(e):
            raise HTTPException(404, "Dispute not found")
        raise HTTPException(404, "Collaboration not found")
    return {
        "ok": True,
        "status": result.get("status", ""),
        "dispute": _dispute_out(result).model_dump(),
    }

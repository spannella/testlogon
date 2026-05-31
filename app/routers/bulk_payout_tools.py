"""Bulk payout & refund tools router (FIN-017).

Admin/root-only tooling to bulk-process pending payouts or refund requests.
Orchestrates the existing single-item services in bulk via
``app.services.bulk_payout_tools``.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.policy import require_admin_or_root
from app.models import (
    BulkEligibleItem,
    BulkPreviewIn,
    BulkExecuteIn,
    BulkBatchOut,
)
from app.services.bulk_payout_tools import (
    list_eligible,
    preview_batch,
    execute_batch,
    list_batches,
    get_batch,
)
from app.services.alerts import audit_event


bulk_payout_tools_router = APIRouter(
    prefix="/ui/admin/bulk-payouts", tags=["admin-bulk-payouts"]
)


@bulk_payout_tools_router.get("/eligible", response_model=list[BulkEligibleItem])
def bulk_list_eligible(
    kind: str = "payout",
    _admin=Depends(require_admin_or_root),
):
    try:
        return list_eligible(kind)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@bulk_payout_tools_router.post("/preview", response_model=BulkBatchOut)
def bulk_preview(
    body: BulkPreviewIn,
    request: Request,
    _admin=Depends(require_admin_or_root),
):
    try:
        out = preview_batch(_admin["user_sub"], body.kind, body.ref_ids)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_event(
        "bulk_payout.preview",
        _admin["user_sub"],
        request,
        batch_id=out["batch_id"],
        kind=out["kind"],
        item_count=out["item_count"],
    )
    return out


@bulk_payout_tools_router.post("/execute", response_model=BulkBatchOut)
def bulk_execute(
    body: BulkExecuteIn,
    request: Request,
    _admin=Depends(require_admin_or_root),
):
    try:
        out = execute_batch(
            _admin["user_sub"],
            kind=body.kind,
            ref_ids=body.ref_ids,
            batch_id=body.batch_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_event(
        "bulk_payout.execute",
        _admin["user_sub"],
        request,
        batch_id=out["batch_id"],
        kind=out["kind"],
        status=out["status"],
        success_count=out["success_count"],
        failure_count=out["failure_count"],
    )
    return out


@bulk_payout_tools_router.get("/batches", response_model=list[BulkBatchOut])
def bulk_list_batches(
    _admin=Depends(require_admin_or_root),
):
    return list_batches()


@bulk_payout_tools_router.get("/batches/{batch_id}", response_model=BulkBatchOut)
def bulk_get_batch(
    batch_id: str,
    _admin=Depends(require_admin_or_root),
):
    out = get_batch(batch_id)
    if not out:
        raise HTTPException(status_code=404, detail="batch not found")
    return out

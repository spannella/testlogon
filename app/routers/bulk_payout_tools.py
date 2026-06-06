"""Bulk payout & refund tools router (FIN-017).

Admin/root-only tooling to bulk-process pending payouts or refund requests.
Orchestrates the existing single-item services in bulk via
``app.services.bulk_payout_tools``.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile

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
    undo_batch,
    parse_payout_csv,
    CsvImportError,
    _CSV_MAX_BYTES,
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
        out = preview_batch(_admin.sub, body.kind, body.ref_ids)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_event(
        "bulk_payout.preview",
        _admin.sub,
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
            _admin.sub,
            kind=body.kind,
            ref_ids=body.ref_ids,
            batch_id=body.batch_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_event(
        "bulk_payout.execute",
        _admin.sub,
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


@bulk_payout_tools_router.post("/batches/{batch_id}/undo", response_model=BulkBatchOut)
def bulk_undo_batch(
    batch_id: str,
    request: Request,
    _admin=Depends(require_admin_or_root),
):
    """GAP-0212: reverse a completed batch within the 5-minute undo window."""
    try:
        out = undo_batch(batch_id, _admin.sub)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_event(
        "bulk_payout.undo",
        _admin.sub,
        request,
        batch_id=batch_id,
        status=out["status"],
    )
    return out


@bulk_payout_tools_router.post("/import-csv", response_model=BulkBatchOut)
async def bulk_import_csv(
    request: Request,
    file: UploadFile = File(...),
    kind: str = Form(...),
    dry_run: bool = Form(default=False),
    _admin=Depends(require_admin_or_root),
):
    """GAP-0213: import a payout/refund CSV, then preview (dry_run) or execute.

    Form fields: ``file`` (CSV, UTF-8 / UTF-8-BOM, max 5 MB / 500 data rows),
    ``kind`` (``payout`` or ``refund``), ``dry_run`` (stop at preview; default
    false).
    """
    if file.content_type and file.content_type not in (
        "text/csv",
        "application/csv",
        "application/vnd.ms-excel",
        "text/plain",
        "application/octet-stream",
    ):
        raise HTTPException(
            status_code=415,
            detail=f"unsupported content type: {file.content_type}. Upload a CSV file.",
        )

    file_bytes = await file.read()
    if len(file_bytes) > _CSV_MAX_BYTES:
        raise HTTPException(status_code=413, detail="file too large (max 5 MB)")

    try:
        ref_ids = parse_payout_csv(file_bytes, kind)
    except CsvImportError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if dry_run:
        out = preview_batch(_admin.sub, kind, ref_ids)
        audit_event(
            "bulk_payout.csv_import_preview",
            _admin.sub,
            request,
            kind=kind,
            ref_count=len(ref_ids),
            batch_id=out["batch_id"],
        )
        return out

    out = execute_batch(_admin.sub, kind=kind, ref_ids=ref_ids)
    audit_event(
        "bulk_payout.csv_import_execute",
        _admin.sub,
        request,
        kind=kind,
        ref_count=len(ref_ids),
        batch_id=out["batch_id"],
        status=out["status"],
    )
    return out

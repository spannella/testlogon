from __future__ import annotations

from typing import Optional, Literal, Dict, Any

from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel, Field

from app.core.settings import S
from app.services.filemanager import (
    finalize_billing_period_admin,
    recompute_usage_aggregates_admin,
    get_admin_user_usage_detail,
    generate_invoice_line_items_for_snapshot_admin,
    create_billing_adjustment_admin,
)
from app.services.sessions import require_ui_session
from app.services.api_usage_metering import (
    _api_usage_table,
    generate_api_invoice_line_items_for_snapshot,
    create_api_billing_adjustment,
    export_api_billing_reconciliation_report,
    run_api_billing_shadow_validation,
    record_api_billing_cutover_signoff,
)
from app.services.alerts import audit_event
from app.services.api_key_rollout import get_api_key_rollout_state

router = APIRouter(prefix="/v1/admin", tags=["admin-usage"])


def _current_user(ctx=Depends(require_ui_session)) -> str:
    return ctx["user_sub"]


def _require_admin_user(user_sub: str = Depends(_current_user)) -> str:
    raw = str(getattr(S, "filemgr_admin_users", "") or "")
    allow = {u.strip() for u in raw.split(",") if u.strip()}
    if allow and user_sub not in allow:
        raise HTTPException(status_code=403, detail="admin privileges required")
    if not allow:
        raise HTTPException(status_code=403, detail="admin privileges not configured")
    return user_sub




def _surface_segments_from_summary(summary: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    upload = int((summary.get("upload") or {}).get("used_bytes") or 0)
    download = int((summary.get("download") or {}).get("used_bytes") or 0)
    storage = int((summary.get("storage") or {}).get("used_bytes") or 0)
    message_send = int((summary.get("message_send") or {}).get("used_count") or 0)
    post_publish = int((summary.get("post_publish") or {}).get("used_count") or 0)

    messaging_transfer = summary.get("messaging_transfer") or {}
    newsfeed_transfer = summary.get("newsfeed_transfer") or {}

    messaging_upload = int(messaging_transfer.get("upload_bytes_total") or summary.get("messaging_upload_bytes_total") or 0)
    messaging_download = int(messaging_transfer.get("download_bytes_total") or summary.get("messaging_download_bytes_total") or 0)
    newsfeed_upload = int(newsfeed_transfer.get("upload_bytes_total") or summary.get("newsfeed_upload_bytes_total") or 0)
    newsfeed_download = int(newsfeed_transfer.get("download_bytes_total") or summary.get("newsfeed_download_bytes_total") or 0)

    return {
        "filemanager": {
            "upload_bytes_total": upload,
            "download_bytes_total": download,
            "storage_bytes_current": storage,
            "message_send_count_total": 0,
            "post_publish_count_total": 0,
        },
        "messaging": {
            "upload_bytes_total": messaging_upload,
            "download_bytes_total": messaging_download,
            "storage_bytes_current": 0,
            "message_send_count_total": message_send,
            "post_publish_count_total": 0,
        },
        "newsfeed": {
            "upload_bytes_total": newsfeed_upload,
            "download_bytes_total": newsfeed_download,
            "storage_bytes_current": 0,
            "message_send_count_total": 0,
            "post_publish_count_total": post_publish,
        },
    }


def _snapshot_row_for_surface(row: Dict[str, Any], source_family: Literal["filemanager", "messaging", "newsfeed"]) -> Dict[str, Any]:
    base = dict(row)
    if source_family == "filemanager":
        base["message_send_count_total"] = 0
        base["post_publish_count_total"] = 0
        base["messaging_upload_bytes_total"] = 0
        base["messaging_download_bytes_total"] = 0
        base["newsfeed_upload_bytes_total"] = 0
        base["newsfeed_download_bytes_total"] = 0
        return base
    if source_family == "messaging":
        base["upload_bytes_total"] = 0
        base["download_bytes_total"] = 0
        base["storage_bytes_peak"] = 0
        base["post_publish_count_total"] = 0
        base["newsfeed_upload_bytes_total"] = 0
        base["newsfeed_download_bytes_total"] = 0
        return base
    if source_family == "newsfeed":
        base["upload_bytes_total"] = 0
        base["download_bytes_total"] = 0
        base["storage_bytes_peak"] = 0
        base["message_send_count_total"] = 0
        base["messaging_upload_bytes_total"] = 0
        base["messaging_download_bytes_total"] = 0
        return base
    return base

class FinalizePeriodIn(BaseModel):
    period_id: str = Field(..., description="Billing period in YYYY-MM")
    user_id: Optional[str] = Field(default=None, description="Optional single user finalization target")




class GenerateInvoiceLinesIn(BaseModel):
    user_id: str
    period_id: str
    snapshot_version: int = Field(..., ge=1)
    pricing_catalog_version: Optional[str] = None


class CreateBillingAdjustmentIn(BaseModel):
    user_id: str
    period_id: str
    snapshot_version: int = Field(..., ge=1)
    adjustment_type: Literal["credit", "debit"]
    amount_cents: int = Field(..., gt=0)
    reason: str
    reference_id: Optional[str] = None



class GenerateApiInvoiceLinesIn(BaseModel):
    user_sub: str
    period_id: str
    snapshot_version: int = Field(..., ge=1)
    include_key_sublines: bool = False


class CreateApiBillingAdjustmentIn(BaseModel):
    user_sub: str
    period_id: str
    snapshot_version: int = Field(..., ge=1)
    adjustment_type: Literal["credit", "debit"]
    amount_micros: int = Field(..., gt=0)
    reason: str
    reference_id: Optional[str] = None


class RunApiBillingShadowValidationIn(BaseModel):
    user_sub: str
    period_id: str
    snapshot_version: int = Field(..., ge=1)
    expected_total_micros: Optional[int] = None
    variance_threshold_micros: int = Field(default=0, ge=0)
    sample_expected_by_route: dict[str, int] = Field(default_factory=dict)
    cycle_id: Optional[str] = None


class ApiBillingCutoverSignoffIn(BaseModel):
    user_sub: str
    period_id: str
    snapshot_version: int = Field(..., ge=1)
    shadow_report_sk: str
    product_approved_by: str
    finance_approved_by: str
    engineering_approved_by: str
    cutover_criteria: str
    rollback_criteria: str

class RecomputeUsageIn(BaseModel):
    scope: Literal["user", "all"] = Field(default="all")
    period_id: Optional[str] = Field(default=None, description="Optional period in YYYY-MM")
    user_id: Optional[str] = Field(default=None, description="Required when scope=user")
    apply: bool = Field(default=True, description="Write recomputed values when true")


@router.post("/billing/finalize-period")
def finalize_billing_period(inp: FinalizePeriodIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    out = finalize_billing_period_admin(period_id=inp.period_id, user_id=inp.user_id)
    audit_event(
        "usage_period_finalize",
        admin_user,
        req,
        outcome="success",
        period_id=inp.period_id,
        target_user=inp.user_id,
        finalized_count=out.get("finalized_count", 0),
        snapshot_versions=[s.get("version") for s in out.get("snapshots", [])],
    )
    return out


@router.post("/usage/recompute")
def recompute_usage(inp: RecomputeUsageIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    out = recompute_usage_aggregates_admin(
        scope=inp.scope,
        period_id=inp.period_id,
        user_id=inp.user_id,
        apply=inp.apply,
    )
    audit_event(
        "usage_recompute_run",
        admin_user,
        req,
        outcome="success",
        scope=inp.scope,
        period_id=inp.period_id,
        target_user=inp.user_id,
        applied=inp.apply,
        events_scanned=out.get("events_scanned", 0),
        mismatches=out.get("mismatches", 0),
    )
    return out


@router.get("/usage/user/{user_id}")
def admin_user_usage_detail(
    user_id: str,
    period_id: Optional[str] = None,
    top_n: int = 10,
    include_paths: bool = False,
    source_family: Literal["all", "filemanager", "messaging", "newsfeed"] = "all",
    admin_user: str = Depends(_require_admin_user),
):
    out = get_admin_user_usage_detail(user_id, period_id=period_id, top_n=top_n, include_resource_paths=include_paths)
    segments = _surface_segments_from_summary(out.get("summary") or {})
    out["available_source_families"] = ["all", "filemanager", "messaging", "newsfeed"]
    out["source_family"] = source_family
    out["surface_segments"] = segments
    if source_family != "all":
        out["summary_surface"] = segments[source_family]
        out["snapshots"] = [_snapshot_row_for_surface(row, source_family) for row in out.get("snapshots", [])]
    return out


@router.post("/billing/generate-invoice-lines")
def generate_invoice_lines(inp: GenerateInvoiceLinesIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    out = generate_invoice_line_items_for_snapshot_admin(
        user_id=inp.user_id,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        pricing_catalog_version=inp.pricing_catalog_version,
    )
    audit_event(
        "usage_snapshot_invoice_lines_generated",
        admin_user,
        req,
        outcome="success",
        target_user=inp.user_id,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        pricing_catalog_version=out.get("pricing_catalog_version"),
        total_amount_cents=out.get("total_amount_cents", 0),
    )
    return out


@router.post("/billing/adjustments")
def create_billing_adjustment(inp: CreateBillingAdjustmentIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    out = create_billing_adjustment_admin(
        user_id=inp.user_id,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        adjustment_type=inp.adjustment_type,
        amount_cents=inp.amount_cents,
        reason=inp.reason,
        reference_id=inp.reference_id,
    )
    audit_event(
        "usage_billing_adjustment_created",
        admin_user,
        req,
        outcome="success",
        target_user=inp.user_id,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        adjustment_type=inp.adjustment_type,
        amount_cents=out.get("amount_cents", 0),
        adjustment_id=out.get("adjustment_id"),
    )
    return out


@router.post("/api-usage/billing/generate-invoice-lines")
def generate_api_usage_invoice_lines(inp: GenerateApiInvoiceLinesIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    table = _api_usage_table()
    if table is None:
        raise HTTPException(400, "API usage table not configured")
    out = generate_api_invoice_line_items_for_snapshot(
        table,
        user_sub=inp.user_sub,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        include_key_sublines=inp.include_key_sublines,
    )
    audit_event(
        "api_usage_invoice_lines_generated",
        admin_user,
        req,
        outcome="success",
        target_user=inp.user_sub,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        total_amount_micros=out.get("total_amount_micros", 0),
    )
    return out


@router.post("/api-usage/billing/adjustments")
def create_api_usage_billing_adjustment(inp: CreateApiBillingAdjustmentIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    table = _api_usage_table()
    if table is None:
        raise HTTPException(400, "API usage table not configured")
    out = create_api_billing_adjustment(
        table,
        user_sub=inp.user_sub,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        adjustment_type=inp.adjustment_type,
        amount_micros=inp.amount_micros,
        reason=inp.reason,
        reference_id=inp.reference_id,
    )
    audit_event(
        "api_usage_billing_adjustment_created",
        admin_user,
        req,
        outcome="success",
        target_user=inp.user_sub,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        adjustment_type=inp.adjustment_type,
        signed_amount_micros=out.get("signed_amount_micros", 0),
        adjustment_id=out.get("adjustment_id"),
    )
    return out


@router.get("/api-usage/billing/reconciliation")
def export_api_usage_reconciliation(user_sub: str, period_id: str, snapshot_version: int, admin_user: str = Depends(_require_admin_user)):
    table = _api_usage_table()
    if table is None:
        raise HTTPException(400, "API usage table not configured")
    return export_api_billing_reconciliation_report(
        table,
        user_sub=user_sub,
        period_id=period_id,
        snapshot_version=int(snapshot_version),
    )


@router.post("/api-usage/billing/shadow-validation")
def run_api_usage_shadow_validation(inp: RunApiBillingShadowValidationIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    table = _api_usage_table()
    if table is None:
        raise HTTPException(400, "API usage table not configured")
    out = run_api_billing_shadow_validation(
        table,
        user_sub=inp.user_sub,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        expected_total_micros=inp.expected_total_micros,
        variance_threshold_micros=inp.variance_threshold_micros,
        sample_expected_by_route=inp.sample_expected_by_route,
        cycle_id=inp.cycle_id,
    )
    audit_event(
        "api_usage_shadow_billing_validation_run",
        admin_user,
        req,
        outcome="success" if out.get("within_threshold") else "warn",
        target_user=inp.user_sub,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        within_threshold=bool(out.get("within_threshold")),
        variance_vs_expected_micros=int(out.get("variance_vs_expected_micros") or 0),
    )
    return out


@router.post("/api-usage/billing/cutover-signoff")
def create_api_usage_cutover_signoff(inp: ApiBillingCutoverSignoffIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    table = _api_usage_table()
    if table is None:
        raise HTTPException(400, "API usage table not configured")
    out = record_api_billing_cutover_signoff(
        table,
        user_sub=inp.user_sub,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        shadow_report_sk=inp.shadow_report_sk,
        product_approved_by=inp.product_approved_by,
        finance_approved_by=inp.finance_approved_by,
        engineering_approved_by=inp.engineering_approved_by,
        cutover_criteria=inp.cutover_criteria,
        rollback_criteria=inp.rollback_criteria,
    )
    audit_event(
        "api_usage_billing_cutover_signoff_created",
        admin_user,
        req,
        outcome="success",
        target_user=inp.user_sub,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        signoff_sk=out.get("signoff_sk"),
        shadow_report_sk=inp.shadow_report_sk,
    )
    return out


@router.get("/api-keys/rollout-state")
def admin_api_keys_rollout_state(
    req: Request,
    include_subjects: bool = False,
    admin_user: str = Depends(_require_admin_user),
):
    if include_subjects and not bool(getattr(S, "api_key_rollout_state_allow_subjects", False)):
        audit_event(
            "api_key_rollout_state_view",
            admin_user,
            req,
            outcome="denied",
            reason="include_subjects_disabled",
            include_subjects=True,
        )
        raise HTTPException(
            status_code=403,
            detail="include_subjects is disabled; set API_KEY_ROLLOUT_STATE_ALLOW_SUBJECTS=1 to enable",
        )

    out = get_api_key_rollout_state(include_subjects=include_subjects)
    drift = getattr(getattr(req, "app", None), "state", None)
    drift_payload = getattr(drift, "api_key_registry_drift", None) if drift is not None else None
    if isinstance(drift_payload, dict):
        out["registry_drift"] = {
            "stale_route_count": int(drift_payload.get("stale_route_count") or 0),
            "stale_route_preview": list(drift_payload.get("stale_route_preview") or []),
            "unregistered_live_route_count": int(drift_payload.get("unregistered_live_route_count") or 0),
            "unregistered_live_route_preview": list(drift_payload.get("unregistered_live_route_preview") or []),
            "warn_threshold": int(drift_payload.get("warn_threshold") or 0),
            "warn_threshold_exceeded": bool(drift_payload.get("warn_threshold_exceeded")),
            "status": str(drift_payload.get("status") or "ok"),
        }
    products = out.get("products") if isinstance(out.get("products"), dict) else {}
    audit_event(
        "api_key_rollout_state_view",
        admin_user,
        req,
        outcome="success",
        dual_credential_mode=str(out.get("dual_credential_mode") or ""),
        products=",".join(sorted(products.keys())),
        include_subjects=bool(include_subjects),
        stale_route_count=int(((out.get("registry_drift") or {}).get("stale_route_count") or 0)),
        unregistered_live_route_count=int(((out.get("registry_drift") or {}).get("unregistered_live_route_count") or 0)),
        stale_route_warn_threshold=int(((out.get("registry_drift") or {}).get("warn_threshold") or 0)),
        stale_route_warn_threshold_exceeded=bool(((out.get("registry_drift") or {}).get("warn_threshold_exceeded"))),
        stale_route_status=str(((out.get("registry_drift") or {}).get("status") or "ok")),
    )
    return out

"""KYC-012: Compliance Reporting & Export router.

Admin/root-gated compliance reporting on top of existing KYC data.  Provides
JSON report endpoints plus CSV/PDF export endpoints (returning proper
Content-Type + Content-Disposition).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.core.time import now_ts
from app.models import (
    KycAuditTrailOut,
    KycDeadlineReportOut,
    KycProcessingTimeReportOut,
    KycReportExportRequest,
    KycRetentionReportOut,
    KycSarOut,
    KycSarRequest,
    KycScreeningComplianceReportOut,
    KycVolumeReportOut,
)
from app.services import kyc_compliance_reports as reports

router = APIRouter(prefix="/v1/kyc/compliance", tags=["kyc-compliance-reports"])


@router.get("/reports/volume", response_model=KycVolumeReportOut)
async def get_volume_report(
    start_date: int | None = Query(None, ge=0),
    end_date: int | None = Query(None, ge=0),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return reports.volume_report(start_date=start_date, end_date=end_date)


@router.get("/reports/screening", response_model=KycScreeningComplianceReportOut)
async def get_screening_report(
    start_date: int | None = Query(None, ge=0),
    end_date: int | None = Query(None, ge=0),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return reports.screening_report(start_date=start_date, end_date=end_date)


@router.get("/reports/processing-time", response_model=KycProcessingTimeReportOut)
async def get_processing_time_report(
    start_date: int | None = Query(None, ge=0),
    end_date: int | None = Query(None, ge=0),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return reports.processing_time_report(start_date=start_date, end_date=end_date)


@router.get("/reports/deadlines", response_model=KycDeadlineReportOut)
async def get_deadline_report(
    warn_after_hours: int = Query(48, ge=1),
    critical_after_hours: int = Query(120, ge=1),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return reports.deadline_tracker(
        warn_after_hours=warn_after_hours,
        critical_after_hours=critical_after_hours,
    )


@router.get("/reports/retention", response_model=KycRetentionReportOut)
async def get_retention_report(
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return reports.retention_report()


@router.get("/reports/audit-trail/{user_sub}", response_model=KycAuditTrailOut)
async def get_audit_trail(
    user_sub: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return reports.audit_trail_for_user(user_sub)


@router.post("/sar", response_model=KycSarOut)
async def create_sar(
    body: KycSarRequest,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return reports.generate_sar(
        user_sub=body.user_sub,
        reason=body.reason,
        transaction_ids=body.transaction_ids,
        admin_sub=user.sub,
    )


@router.post("/reports/{report_type}/export")
async def export_report(
    report_type: str,
    body: KycReportExportRequest,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Response:
    generator = reports.REPORT_GENERATORS.get(report_type)
    if generator is None:
        raise HTTPException(status_code=400, detail=f"Unknown report type: {report_type}")

    report_data = generator(start_date=body.start_date, end_date=body.end_date)
    filename_base = f"kyc_{report_type.replace('-', '_')}_{now_ts()}"

    if body.format == "pdf":
        pdf_bytes = reports.render_report_pdf(report_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.pdf"'},
        )

    csv_content = reports.render_report_csv(report_data)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename_base}.csv"'},
    )

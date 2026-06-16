"""PLT-004: Sandbox data import router — admin endpoint for bulk-seeding test data."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.models import SandboxImportIn, SandboxImportResult
from app.routers.admin_usage import _require_admin_user
from app.services.alerts import audit_event
from app.services.sandbox_import import import_sandbox_payload

router = APIRouter(prefix="/v1/admin/sandbox", tags=["sandbox"])


@router.post("/data-import", response_model=SandboxImportResult)
async def data_import(
    body: SandboxImportIn,
    req: Request,
    admin_sub: str = Depends(_require_admin_user),
) -> SandboxImportResult:
    """Bulk-seed test accounts/transactions/customers. Requires SANDBOX_IMPORT_ENABLED=1 and DEV_MODE=1."""
    if not (getattr(S, "open_bank_project_enabled", False) and getattr(S, "sandbox_import_enabled", False) and getattr(S, "dev_mode", False)):
        raise HTTPException(status_code=404, detail="not found")
    result = import_sandbox_payload(body, actor_sub=admin_sub)
    audit_event(
        "sandbox_data_import",
        admin_sub,
        req,
        customers_created=result.customers_created,
        accounts_created=result.accounts_created,
        transactions_created=result.transactions_created,
        errors_total=len(result.errors),
    )
    return result

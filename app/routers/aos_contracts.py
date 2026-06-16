"""AOS CRM Contract router (QUO-004)."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    ContractCreateIn,
    ContractListOut,
    ContractOut,
    ContractPatchIn,
    ContractStageTransitionIn,
)
from app.services import aos_contracts as contract_service
from app.services.sessions import require_ui_session

aos_contracts_router = APIRouter(prefix="/ui/contracts", tags=["aos-contracts"])
aos_contracts_admin_router = APIRouter(prefix="/ui/admin/contracts", tags=["aos-contracts-admin"])


def _require_enabled() -> None:
    from app.core.settings import S
    if not S.aos_contracts_enabled:
        raise HTTPException(404, "contracts not enabled")


@aos_contracts_router.post("", response_model=ContractOut, status_code=201)
@aos_contracts_router.post("/", response_model=ContractOut, status_code=201)
def create_contract(
    body: ContractCreateIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ContractOut:
    _require_enabled()
    try:
        result = contract_service.create_contract(
            ctx["user_sub"],
            title=body.title,
            start_date=body.start_date,
            end_date=body.end_date,
            value_cents=body.value_cents,
            currency=body.currency,
            description=body.description,
            account_id=body.account_id,
            contact_id=body.contact_id,
            renewal_notice_days=body.renewal_notice_days,
            billing_address=body.billing_address.model_dump(),
            shipping_address=body.shipping_address.model_dump(),
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    if result is None:
        raise HTTPException(404, "contracts not enabled")
    return ContractOut(**result)


@aos_contracts_router.get("", response_model=ContractListOut)
@aos_contracts_router.get("/", response_model=ContractListOut)
def list_contracts(
    stage: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ContractListOut:
    _require_enabled()
    result = contract_service.list_contracts(ctx["user_sub"], stage=stage, limit=limit, cursor=cursor)
    if result is None:
        raise HTTPException(404, "contracts not enabled")
    return ContractListOut(
        contracts=[ContractOut(**c) for c in result["contracts"]],
        count=result.get("count", 0),
        next_cursor=result.get("next_cursor"),
    )


@aos_contracts_router.get("/{contract_id}", response_model=ContractOut)
def get_contract(
    contract_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ContractOut:
    _require_enabled()
    result = contract_service.get_contract(ctx["user_sub"], contract_id)
    if not result:
        raise HTTPException(404, "Contract not found")
    return ContractOut(**result)


@aos_contracts_router.patch("/{contract_id}", response_model=ContractOut)
def patch_contract(
    contract_id: str,
    body: ContractPatchIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ContractOut:
    _require_enabled()
    patch = body.model_dump(exclude_unset=True)
    result = contract_service.update_contract(ctx["user_sub"], contract_id, **patch)
    if result is None:
        raise HTTPException(404, "Contract not found")
    return ContractOut(**result)


@aos_contracts_router.post("/{contract_id}/stage", response_model=ContractOut)
def transition_contract_stage(
    contract_id: str,
    body: ContractStageTransitionIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ContractOut:
    _require_enabled()
    result = contract_service.transition_stage(ctx["user_sub"], contract_id, body.stage)
    if result is None:
        raise HTTPException(404, "Contract not found")
    return ContractOut(**result)


@aos_contracts_admin_router.get("", response_model=ContractListOut)
@aos_contracts_admin_router.get("/", response_model=ContractListOut)
def admin_list_contracts(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> ContractListOut:
    _require_enabled()
    result = contract_service.admin_list_contracts(limit=limit, cursor=cursor)
    if result is None:
        raise HTTPException(404, "contracts not enabled")
    return ContractListOut(
        contracts=[ContractOut(**c) for c in result["contracts"]],
        count=result.get("count", 0),
        next_cursor=result.get("next_cursor"),
    )

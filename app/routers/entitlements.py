from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.services.entitlements_visibility import list_user_entitlements
from app.services.api_package_usage import list_api_package_usage
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/v1", tags=["entitlements"])


@router.get("/entitlements")
def get_entitlements(
    product_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    source_system: Optional[str] = Query(default=None),
    lifecycle_status: Optional[str] = Query(default=None),
    ctx=Depends(require_ui_session),
):
    return list_user_entitlements(
        ctx["user_sub"],
        product_type=product_type,
        status=status,
        source_system=source_system,
        lifecycle_status=lifecycle_status,
    )


@router.get("/entitlements/usage")
def get_entitlement_usage(
    status: Optional[str] = Query(default=None),
    ctx=Depends(require_ui_session),
):
    return list_api_package_usage(ctx["user_sub"], status=status)

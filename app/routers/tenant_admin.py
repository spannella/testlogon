"""
Tenant administration router (ENTERPRISE-001).

Root-only CRUD endpoints for multi-tenant management, plus public
branding/info endpoints that require no authentication.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.deps import require_root_session
from app.models import (
    TenantBrandingOut,
    TenantCreateReq,
    TenantDomainAddReq,
    TenantInfoOut,
    TenantOut,
    TenantUpdateReq,
)
from app.services.alerts import audit_event
from app.services.tenant_service import (
    add_domain,
    create_tenant,
    get_tenant,
    get_tenant_branding,
    get_tenant_info,
    list_tenants,
    remove_domain,
    soft_delete_tenant,
    update_tenant,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/admin/tenants", tags=["tenant-admin"])

# ── Public endpoints (no auth) ──────────────────────────────────────────────

public_router = APIRouter(tags=["tenant-public"])


@public_router.get("/ui/tenant/branding")
async def tenant_branding(request: Request) -> TenantBrandingOut:
    """Return branding for the current tenant (or default)."""
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", "default")
    data = get_tenant_branding(tenant_id)
    return TenantBrandingOut(**data)


@public_router.get("/ui/tenant/info")
async def tenant_info(request: Request) -> TenantInfoOut:
    """Return public tenant info for the current tenant (or default)."""
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", "default")
    data = get_tenant_info(tenant_id)
    if not data:
        data = {
            "tenant_id": "default",
            "slug": "default",
            "display_name": "Default",
            "status": "active",
            "plan": "starter",
        }
    return TenantInfoOut(**data)


# ── Root-only admin CRUD ─────────────────────────────────────────────────────

@router.post("", status_code=201)
async def create_tenant_endpoint(
    body: TenantCreateReq,
    request: Request,
    session=Depends(require_root_session),
):
    try:
        tenant = create_tenant(
            slug=body.slug,
            display_name=body.display_name,
            plan=body.plan,
            primary_domain=body.primary_domain,
            created_by=session.sub,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    audit_event("tenant_created", session.sub, request, tenant_id=tenant["tenant_id"], slug=body.slug)
    return TenantOut(**tenant)


@router.get("")
async def list_tenants_endpoint(
    limit: int = 50,
    cursor: Optional[str] = None,
    status: Optional[str] = None,
    session=Depends(require_root_session),
):
    items, next_cursor = list_tenants(limit=limit, cursor=cursor, status_filter=status)
    return {
        "tenants": [TenantOut(**t) for t in items],
        "next_cursor": next_cursor,
    }


@router.get("/{tenant_id}")
async def get_tenant_endpoint(
    tenant_id: str,
    session=Depends(require_root_session),
):
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return TenantOut(**tenant)


@router.patch("/{tenant_id}")
async def update_tenant_endpoint(
    tenant_id: str,
    body: TenantUpdateReq,
    request: Request,
    session=Depends(require_root_session),
):
    updated = update_tenant(
        tenant_id,
        display_name=body.display_name,
        plan=body.plan,
        status=body.status,
        branding=body.branding,
        settings_overrides=body.settings_overrides,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Tenant not found")

    audit_event("tenant_updated", session.sub, request, tenant_id=tenant_id)
    return TenantOut(**updated)


@router.delete("/{tenant_id}", status_code=200)
async def delete_tenant_endpoint(
    tenant_id: str,
    request: Request,
    session=Depends(require_root_session),
):
    result = soft_delete_tenant(tenant_id)
    if not result:
        raise HTTPException(status_code=404, detail="Tenant not found")

    audit_event("tenant_deleted", session.sub, request, tenant_id=tenant_id)
    return TenantOut(**result)


@router.post("/{tenant_id}/domains", status_code=201)
async def add_domain_endpoint(
    tenant_id: str,
    body: TenantDomainAddReq,
    request: Request,
    session=Depends(require_root_session),
):
    try:
        tenant = add_domain(tenant_id, body.domain)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    audit_event("tenant_domain_added", session.sub, request, tenant_id=tenant_id, domain=body.domain)
    return {"ok": True, "tenant_id": tenant_id, "domain": body.domain}


@router.delete("/{tenant_id}/domains/{domain}", status_code=204)
async def remove_domain_endpoint(
    tenant_id: str,
    domain: str,
    request: Request,
    session=Depends(require_root_session),
):
    remove_domain(tenant_id, domain)
    audit_event("tenant_domain_removed", session.sub, request, tenant_id=tenant_id, domain=domain)
    return None

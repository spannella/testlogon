"""BRAND-001 — Platform branding router (decision D6).

GET  /ui/admin/branding  — admin-readable (ADMIN or ROOT)
PUT  /ui/admin/branding  — ROOT only; CSRF-enforced for cookie-auth
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.auth.policy import enforce_cookie_csrf, require_admin_or_root, require_root
from app.models import BrandingOut, BrandingUpdateIn
from app.services import branding as branding_svc

router = APIRouter(prefix="/ui/admin", tags=["branding"])


@router.get("/branding", response_model=BrandingOut)
async def get_branding_endpoint(user=Depends(require_admin_or_root)):
    """Return the current platform branding.  Admins and root may read."""
    b = branding_svc.get_branding()
    return BrandingOut(
        platform_name=b["platform_name"],
        logo_url=b["logo_url"],
        support_email=b["support_email"],
        updated_at=b["updated_at"],
        updated_by=b["updated_by"],
    )


@router.put("/branding", response_model=BrandingOut)
async def put_branding_endpoint(
    body: BrandingUpdateIn,
    request: Request,
    user=Depends(require_root),
):
    """Update platform branding.  ROOT only; CSRF enforced for cookie-auth."""
    enforce_cookie_csrf(request)
    b = branding_svc.set_branding(
        name=body.name,
        logo_url=body.logo_url,
        support_email=body.support_email,
        actor_sub=user.sub,
    )
    return BrandingOut(
        platform_name=b["platform_name"],
        logo_url=b["logo_url"],
        support_email=b["support_email"],
        updated_at=b["updated_at"],
        updated_by=b["updated_by"],
    )

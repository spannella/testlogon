from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.models import (
    ApiPackageSkuCreateIn,
    ApiPackageSkuOut,
    FileBundleCheckoutSessionIn,
    FileBundleCheckoutSessionOut,
    FileBundleSkuCreateIn,
    FileBundleSkuOut,
    UnifiedCheckoutSessionIn,
    UnifiedCheckoutSessionOut,
)
from app.services.alerts import audit_event
from app.services.file_bundle_checkout import create_file_bundle_sku
from app.services.api_package_catalog import create_api_package_sku_version
from app.services.unified_checkout import create_file_bundle_checkout_via_unified, create_unified_checkout_session
from app.services.sessions import require_ui_session

router = APIRouter(tags=["commercialization"])


@router.post("/ui/catalog/file-bundles", response_model=FileBundleSkuOut)
async def ui_create_file_bundle_sku(body: FileBundleSkuCreateIn, req: Request = None, ctx=Depends(require_ui_session)):
    out = create_file_bundle_sku(ctx["user_sub"], body)
    audit_event(
        "catalog_file_bundle_sku_created",
        ctx["user_sub"],
        req,
        outcome="success",
        sku=out.get("sku"),
        access_mode=out.get("access_mode"),
        date_start=out.get("date_start"),
        date_end=out.get("date_end"),
    )
    return out




@router.post("/ui/checkout/session", response_model=UnifiedCheckoutSessionOut)
async def ui_create_checkout_session(body: UnifiedCheckoutSessionIn, req: Request = None, ctx=Depends(require_ui_session)):
    afl_ref = req.cookies.get("afl_ref") if req else None
    out = create_unified_checkout_session(ctx["user_sub"], body, afl_ref=afl_ref)
    audit_event(
        "checkout_session_created",
        ctx["user_sub"],
        req,
        outcome="success",
        order_id=out.get("order_id"),
        checkout_session_id=out.get("checkout_session_id"),
        source=out.get("source"),
        line_item_count=len(out.get("line_items") or []),
        afl_ref=afl_ref,
    )
    return out

@router.post("/ui/checkout/session/file-bundle", response_model=FileBundleCheckoutSessionOut)
async def ui_create_file_bundle_checkout_session(body: FileBundleCheckoutSessionIn, req: Request = None, ctx=Depends(require_ui_session)):
    afl_ref = req.cookies.get("afl_ref") if req else None
    out = create_file_bundle_checkout_via_unified(ctx["user_sub"], body, afl_ref=afl_ref)
    audit_event(
        "file_bundle_checkout_session_created",
        ctx["user_sub"],
        req,
        outcome="success",
        order_id=out.get("order_id"),
        checkout_session_id=out.get("checkout_session_id"),
        sku=out.get("sku"),
        afl_ref=afl_ref,
    )
    return out


@router.post("/ui/catalog/api-packages", response_model=ApiPackageSkuOut)
async def ui_create_api_package_sku(body: ApiPackageSkuCreateIn, req: Request = None, ctx=Depends(require_ui_session)):
    out = create_api_package_sku_version(ctx["user_sub"], body)
    audit_event(
        "catalog_api_package_sku_version_created",
        ctx["user_sub"],
        req,
        outcome="success",
        sku=out.get("sku"),
        effective_at=out.get("effective_at"),
        billing_model=out.get("billing_model"),
    )
    return out

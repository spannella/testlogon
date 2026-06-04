"""Admin Subscription Tier Manager API (ADMIN-001).

CRUD + lifecycle + analytics for subscription tiers. All endpoints require an
admin or root session (``require_admin_or_root``). Tiers are scoped to the
authenticated operator's ``sub`` (treated as the ``creator_id``).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.models import (
    AdminSubscriptionTierAnalytics,
    AdminSubscriptionTierCreate,
    AdminSubscriptionTierOut,
    AdminSubscriptionTierPreviewOut,
    AdminSubscriptionTierReorder,
    AdminSubscriptionTierUpdate,
)
from app.services import admin_subscription_tiers as svc
from app.services.alerts import audit_event

admin_subscription_tiers_router = APIRouter(
    prefix="/ui/admin/subscription-tiers", tags=["admin-subscription-tiers"]
)


@admin_subscription_tiers_router.post("", response_model=AdminSubscriptionTierOut, status_code=201)
def create_subscription_tier(
    inp: AdminSubscriptionTierCreate,
    req: Request,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    out = svc.create_tier(
        creator_id=actor.sub,
        name=inp.name,
        price_cents=inp.price_cents,
        billing_cycle=inp.billing_cycle,
        description=inp.description,
        benefits=inp.benefits,
        access_level=inp.access_level,
        plan_id=inp.plan_id,
    )
    audit_event(
        "admin_subscription_tier_create",
        actor.sub,
        req,
        outcome="success",
        tier_id=out["tier_id"],
        billing_cycle=out["billing_cycle"],
    )
    return out


@admin_subscription_tiers_router.get("", response_model=list[AdminSubscriptionTierOut])
def list_subscription_tiers(
    include_archived: bool = False,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    return svc.list_tiers(actor.sub, include_archived=include_archived)


@admin_subscription_tiers_router.put(
    "/reorder", response_model=list[dict]
)
def reorder_subscription_tiers(
    inp: AdminSubscriptionTierReorder,
    req: Request,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    out = svc.reorder_tiers(creator_id=actor.sub, tier_ids=inp.tier_ids)
    audit_event(
        "admin_subscription_tier_reorder",
        actor.sub,
        req,
        outcome="success",
        new_order=inp.tier_ids,
    )
    return out


@admin_subscription_tiers_router.get(
    "/analytics", response_model=AdminSubscriptionTierAnalytics
)
def subscription_tier_analytics(
    start_date: str | None = None,
    end_date: str | None = None,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    return svc.get_tier_analytics(actor.sub, start_date=start_date, end_date=end_date)


@admin_subscription_tiers_router.get(
    "/preview", response_model=AdminSubscriptionTierPreviewOut
)
def preview_subscription_tiers(
    actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    return svc.preview_tiers(actor.sub)


@admin_subscription_tiers_router.get(
    "/{tier_id}", response_model=AdminSubscriptionTierOut
)
def get_subscription_tier(
    tier_id: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    return svc.get_tier(actor.sub, tier_id)


@admin_subscription_tiers_router.patch(
    "/{tier_id}", response_model=AdminSubscriptionTierOut
)
def update_subscription_tier(
    tier_id: str,
    inp: AdminSubscriptionTierUpdate,
    req: Request,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    out = svc.update_tier(
        creator_id=actor.sub,
        tier_id=tier_id,
        **inp.model_dump(exclude_none=True),
    )
    audit_event(
        "admin_subscription_tier_update",
        actor.sub,
        req,
        outcome="success",
        tier_id=tier_id,
    )
    return out


@admin_subscription_tiers_router.post(
    "/{tier_id}/archive", response_model=AdminSubscriptionTierOut
)
def archive_subscription_tier(
    tier_id: str,
    req: Request,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    out = svc.archive_tier(creator_id=actor.sub, tier_id=tier_id)
    audit_event(
        "admin_subscription_tier_archive",
        actor.sub,
        req,
        outcome="success",
        tier_id=tier_id,
    )
    return out


@admin_subscription_tiers_router.post(
    "/{tier_id}/unarchive", response_model=AdminSubscriptionTierOut
)
def unarchive_subscription_tier(
    tier_id: str,
    req: Request,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    out = svc.unarchive_tier(creator_id=actor.sub, tier_id=tier_id)
    audit_event(
        "admin_subscription_tier_unarchive",
        actor.sub,
        req,
        outcome="success",
        tier_id=tier_id,
    )
    return out


@admin_subscription_tiers_router.delete("/{tier_id}")
def delete_subscription_tier(
    tier_id: str,
    req: Request,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    out = svc.delete_tier(creator_id=actor.sub, tier_id=tier_id)
    audit_event(
        "admin_subscription_tier_delete",
        actor.sub,
        req,
        outcome="success",
        tier_id=tier_id,
    )
    return out

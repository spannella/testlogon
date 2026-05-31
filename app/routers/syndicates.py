"""Syndicate management router (SYND-001 + SYND-002)."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query

from app.services.sessions import require_ui_session
from app.models import (
    BundlePlanCreateIn,
    BundlePlanOut,
    BundlePlanUpdateIn,
    BundleSubscribeIn,
    BundleSubscriptionOut,
    SyndicateAuditOut,
    SyndicateCreateIn,
    SyndicateInviteIn,
    SyndicateInviteOut,
    SyndicateInviteRespondIn,
    SyndicateJoinRequestIn,
    SyndicateMemberOut,
    SyndicateOut,
    SyndicateRequestOut,
    SyndicateTransferAdminIn,
    SyndicateUpdateIn,
)
from app.services import syndicates as svc
from app.services import syndicate_subscriptions as bundle_svc

router = APIRouter(prefix="/ui/syndicates", tags=["syndicates"])


# ---------------------------------------------------------------------------
# Syndicate CRUD
# ---------------------------------------------------------------------------

@router.post("", status_code=201)
def create_syndicate(body: SyndicateCreateIn, session=Depends(require_ui_session)):
    meta = svc.create_syndicate(
        creator_sub=session["user_sub"],
        name=body.name,
        description=body.description,
    )
    return _meta_to_out(meta)


@router.get("")
def list_my_syndicates(session=Depends(require_ui_session)):
    items = svc.list_user_syndicates(session["user_sub"])
    return [
        {
            "syndicate_id": i["syndicate_id"],
            "syndicate_name": i.get("syndicate_name", ""),
            "role": i.get("role", "member"),
            "joined_at": int(i.get("joined_at", 0)),
        }
        for i in items
    ]


@router.get("/invites")
def list_my_invites(session=Depends(require_ui_session)):
    items = svc.list_pending_invites(session["user_sub"])
    return [
        SyndicateInviteOut(
            syndicate_id=i.get("syndicate_id", ""),
            syndicate_name=i.get("syndicate_name", ""),
            user_id=i.get("user_id", ""),
            invited_by=i.get("invited_by", ""),
            invited_at=int(i.get("invited_at", 0)),
            status=i.get("status", "pending"),
        )
        for i in items
    ]


@router.get("/my-bundles")
def list_my_bundles(session=Depends(require_ui_session)):
    """List the calling user's active bundle subscriptions."""
    bundles = bundle_svc.list_subscriber_bundles(session["user_sub"])
    return [
        BundleSubscriptionOut(
            subscription_id=b.get("subscription_id", ""),
            plan_id=b.get("plan_id", ""),
            plan_type="syndicate_bundle",
            syndicate_id=b.get("syndicate_id", ""),
            syndicate_name=b.get("syndicate_name", ""),
            status=b.get("status", "active"),
            price_cents=int(b.get("price_cents", 0)),
            interval=b.get("interval", "month"),
            current_period_start=int(b.get("current_period_start", 0)),
            current_period_end=int(b.get("current_period_end", 0)),
            created_at=int(b.get("created_at", 0)),
            cancelled_at=b.get("cancelled_at"),
            included_creators=[
                SyndicateMemberOut(
                    user_id=m.get("user_id", ""),
                    display_name=m.get("display_name", ""),
                    role=m.get("role", "member"),
                    joined_at=int(m.get("joined_at", 0)),
                )
                for m in b.get("included_creators", [])
            ],
        )
        for b in bundles
    ]


@router.get("/discover")
def discover_syndicates(
    limit: int = Query(default=50, ge=1, le=100),
    session=Depends(require_ui_session),
):
    items = svc.list_active_syndicates(limit=limit)
    return [_meta_to_out(i) for i in items]


@router.get("/{syndicate_id}")
def get_syndicate(syndicate_id: str, session=Depends(require_ui_session)):
    detail = svc.get_syndicate_detail(syndicate_id)
    return _detail_to_out(detail)


# ---------------------------------------------------------------------------
# Membership management
# ---------------------------------------------------------------------------

@router.post("/{syndicate_id}/invite", status_code=201)
def invite_member(
    syndicate_id: str,
    body: SyndicateInviteIn,
    session=Depends(require_ui_session),
):
    invite = svc.invite_member(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        invitee_user_id=body.user_id,
    )
    return SyndicateInviteOut(
        syndicate_id=invite.get("syndicate_id", syndicate_id),
        syndicate_name=invite.get("syndicate_name", ""),
        user_id=invite.get("user_id", ""),
        invited_by=invite.get("invited_by", ""),
        invited_at=int(invite.get("invited_at", 0)),
        status=invite.get("status", "pending"),
    )


@router.post("/{syndicate_id}/invite/respond")
def respond_to_invite(
    syndicate_id: str,
    body: SyndicateInviteRespondIn,
    session=Depends(require_ui_session),
):
    result = svc.respond_to_invite(
        syndicate_id=syndicate_id,
        user_id=session["user_sub"],
        accept=body.accept,
    )
    return {"ok": True, "status": result.get("status", "")}


@router.post("/{syndicate_id}/request", status_code=201)
def request_to_join(
    syndicate_id: str,
    body: SyndicateJoinRequestIn,
    session=Depends(require_ui_session),
):
    req = svc.request_to_join(
        syndicate_id=syndicate_id,
        user_id=session["user_sub"],
        message=body.message,
    )
    return SyndicateRequestOut(
        syndicate_id=req.get("syndicate_id", syndicate_id),
        user_id=req.get("user_id", ""),
        requested_at=int(req.get("requested_at", 0)),
        message=req.get("message", ""),
        status=req.get("status", "pending"),
    )


@router.post("/{syndicate_id}/request/{user_id}/approve")
def approve_request(
    syndicate_id: str,
    user_id: str,
    session=Depends(require_ui_session),
):
    svc.approve_request(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        requester_user_id=user_id,
    )
    return {"ok": True}


@router.post("/{syndicate_id}/request/{user_id}/reject")
def reject_request(
    syndicate_id: str,
    user_id: str,
    session=Depends(require_ui_session),
):
    svc.reject_request(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        requester_user_id=user_id,
    )
    return {"ok": True}


@router.post("/{syndicate_id}/transfer-admin")
def transfer_admin(
    syndicate_id: str,
    body: SyndicateTransferAdminIn,
    session=Depends(require_ui_session),
):
    meta = svc.transfer_admin(
        syndicate_id=syndicate_id,
        current_admin_sub=session["user_sub"],
        new_admin_user_id=body.new_admin_user_id,
    )
    return _meta_to_out(meta)


@router.post("/{syndicate_id}/leave")
def leave_syndicate(syndicate_id: str, session=Depends(require_ui_session)):
    result = svc.leave_syndicate(
        syndicate_id=syndicate_id,
        user_id=session["user_sub"],
    )
    return result


@router.post("/{syndicate_id}/remove/{user_id}")
def remove_member(
    syndicate_id: str,
    user_id: str,
    session=Depends(require_ui_session),
):
    svc.remove_member(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        target_user_id=user_id,
    )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

@router.get("/{syndicate_id}/members")
def list_members(syndicate_id: str, session=Depends(require_ui_session)):
    items = svc.list_members(syndicate_id)
    return [
        SyndicateMemberOut(
            user_id=m.get("user_id", ""),
            display_name=m.get("display_name", ""),
            role=m.get("role", "member"),
            joined_at=int(m.get("joined_at", 0)),
        )
        for m in items
    ]


@router.get("/{syndicate_id}/requests")
def list_requests(syndicate_id: str, session=Depends(require_ui_session)):
    # Admin-only check done in service
    items = svc.list_pending_requests(syndicate_id)
    return [
        SyndicateRequestOut(
            syndicate_id=r.get("syndicate_id", syndicate_id),
            user_id=r.get("user_id", ""),
            requested_at=int(r.get("requested_at", 0)),
            message=r.get("message", ""),
            status=r.get("status", "pending"),
        )
        for r in items
    ]


@router.get("/{syndicate_id}/audit")
def get_audit(
    syndicate_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    session=Depends(require_ui_session),
):
    items = svc.get_audit_log(syndicate_id, limit=limit)
    return [
        SyndicateAuditOut(
            event_id=a.get("event_id", ""),
            actor_id=a.get("actor_id", ""),
            action=a.get("action", ""),
            target_id=a.get("target_id", ""),
            details=a.get("details"),
            ts=int(a.get("ts", 0)),
        )
        for a in items
    ]


# ---------------------------------------------------------------------------
# Bundle Plans (SYND-002)
# ---------------------------------------------------------------------------

@router.post("/{syndicate_id}/plans", status_code=201)
def create_bundle_plan(
    syndicate_id: str,
    body: BundlePlanCreateIn,
    session=Depends(require_ui_session),
):
    plan = bundle_svc.create_bundle_plan(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        name=body.name,
        description=body.description,
        price_cents=body.price_cents,
        interval=body.interval,
    )
    return _plan_to_out(plan)


@router.get("/{syndicate_id}/plans")
def list_bundle_plans(syndicate_id: str, session=Depends(require_ui_session)):
    # Verify syndicate exists
    svc.get_syndicate_detail(syndicate_id)
    items = bundle_svc.list_bundle_plans(syndicate_id)
    return [
        BundlePlanOut(
            plan_id=p.get("plan_id", ""),
            plan_type="syndicate_bundle",
            syndicate_id=syndicate_id,
            name=p.get("name", ""),
            price_cents=int(p.get("price_cents", 0)),
            status=p.get("status", "active"),
            created_at=int(p.get("created_at", 0)),
        )
        for p in items
    ]


@router.get("/{syndicate_id}/plans/{plan_id}")
def get_bundle_plan_detail(
    syndicate_id: str,
    plan_id: str,
    session=Depends(require_ui_session),
):
    plan = bundle_svc.get_bundle_details(plan_id)
    return _plan_to_out(plan)


@router.put("/{syndicate_id}/plans/{plan_id}")
def update_bundle_plan(
    syndicate_id: str,
    plan_id: str,
    body: BundlePlanUpdateIn,
    session=Depends(require_ui_session),
):
    plan = bundle_svc.update_bundle_plan(
        syndicate_id=syndicate_id,
        plan_id=plan_id,
        admin_sub=session["user_sub"],
        name=body.name,
        description=body.description,
        price_cents=body.price_cents,
    )
    return _plan_to_out(plan)


@router.delete("/{syndicate_id}/plans/{plan_id}")
def archive_bundle_plan(
    syndicate_id: str,
    plan_id: str,
    session=Depends(require_ui_session),
):
    return bundle_svc.archive_bundle_plan(
        syndicate_id=syndicate_id,
        plan_id=plan_id,
        admin_sub=session["user_sub"],
    )


@router.post("/{syndicate_id}/plans/{plan_id}/subscribe")
def subscribe_to_bundle(
    syndicate_id: str,
    plan_id: str,
    body: BundleSubscribeIn,
    session=Depends(require_ui_session),
):
    sub = bundle_svc.subscribe_to_bundle(
        subscriber_id=session["user_sub"],
        plan_id=plan_id,
        payment_method_id=body.payment_method_id,
    )
    # Enrich with syndicate name
    syndicate = svc.get_syndicate(syndicate_id) or {}
    members = svc.list_members(syndicate_id)
    return BundleSubscriptionOut(
        subscription_id=sub.get("subscription_id", ""),
        plan_id=sub.get("plan_id", ""),
        plan_type="syndicate_bundle",
        syndicate_id=syndicate_id,
        syndicate_name=syndicate.get("name", ""),
        status=sub.get("status", "active"),
        price_cents=int(sub.get("price_cents", 0)),
        interval=sub.get("interval", "month"),
        current_period_start=int(sub.get("current_period_start", 0)),
        current_period_end=int(sub.get("current_period_end", 0)),
        created_at=int(sub.get("created_at", 0)),
        included_creators=[
            SyndicateMemberOut(
                user_id=m.get("user_id", ""),
                display_name=m.get("display_name", ""),
                role=m.get("role", "member"),
                joined_at=int(m.get("joined_at", 0)),
            )
            for m in members
        ],
    )


@router.post("/{syndicate_id}/subscriptions/{subscription_id}/cancel")
def cancel_bundle_subscription(
    syndicate_id: str,
    subscription_id: str,
    session=Depends(require_ui_session),
):
    return bundle_svc.cancel_bundle_subscription(
        subscriber_id=session["user_sub"],
        subscription_id=subscription_id,
    )


# ---------------------------------------------------------------------------
# Bundle access check (SYND-002)
# ---------------------------------------------------------------------------

@router.get("/{syndicate_id}/access/{creator_id}")
def check_bundle_access(
    syndicate_id: str,
    creator_id: str,
    session=Depends(require_ui_session),
):
    """Check if the calling user has bundle access to a specific creator."""
    has_access = bundle_svc.has_bundle_access(session["user_sub"], creator_id)
    return {"has_access": has_access, "creator_id": creator_id}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _meta_to_out(meta: dict) -> SyndicateOut:
    return SyndicateOut(
        syndicate_id=meta.get("syndicate_id", ""),
        name=meta.get("name", ""),
        description=meta.get("description", ""),
        admin_user_id=meta.get("admin_user_id", ""),
        status=meta.get("status", "active"),
        member_count=int(meta.get("member_count", 0)),
        created_at=int(meta.get("created_at", 0)),
        updated_at=int(meta.get("updated_at", 0)),
    )


def _plan_to_out(plan: dict) -> BundlePlanOut:
    members = [
        SyndicateMemberOut(
            user_id=m.get("user_id", ""),
            display_name=m.get("display_name", ""),
            role=m.get("role", "member"),
            joined_at=int(m.get("joined_at", 0)),
        )
        for m in plan.get("current_members", [])
    ]
    return BundlePlanOut(
        plan_id=plan.get("plan_id", ""),
        plan_type=plan.get("plan_type", "syndicate_bundle"),
        syndicate_id=plan.get("syndicate_id", ""),
        name=plan.get("name", ""),
        description=plan.get("description", ""),
        price_cents=int(plan.get("price_cents", 0)),
        interval=plan.get("interval", "month"),
        status=plan.get("status", "active"),
        included_creator_ids=plan.get("included_creator_ids", []),
        current_members=members,
        created_at=int(plan.get("created_at", 0)),
    )


def _detail_to_out(detail: dict) -> SyndicateOut:
    members = [
        SyndicateMemberOut(
            user_id=m.get("user_id", ""),
            display_name=m.get("display_name", ""),
            role=m.get("role", "member"),
            joined_at=int(m.get("joined_at", 0)),
        )
        for m in detail.get("members", [])
    ]
    return SyndicateOut(
        syndicate_id=detail.get("syndicate_id", ""),
        name=detail.get("name", ""),
        description=detail.get("description", ""),
        admin_user_id=detail.get("admin_user_id", ""),
        status=detail.get("status", "active"),
        member_count=int(detail.get("member_count", 0)),
        created_at=int(detail.get("created_at", 0)),
        updated_at=int(detail.get("updated_at", 0)),
        members=members,
    )

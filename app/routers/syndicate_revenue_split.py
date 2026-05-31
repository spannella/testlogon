"""Syndicate revenue splitting router (SYND-003).

Endpoints for defining/editing per-member split rules, viewing split history and
per-member earnings, and (internal) triggering revenue attribution after a
payment. Split-rule edits are syndicate-admin-scoped (verified against the
syndicate record); viewing is open to any syndicate member.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends

from app.auth.policy import require_admin_or_root
from app.models import (
    ExecuteSplitIn,
    MemberEarningsOut,
    PerformanceScoresIn,
    SplitConfigIn,
    SplitConfigOut,
    SplitExecutionOut,
)
from app.services import syndicate_revenue_split as svc
from app.services import syndicates as syndicate_svc
from app.services.sessions import require_ui_session

syndicate_revenue_split_router = APIRouter(
    prefix="/ui/syndicates/revenue-split", tags=["syndicate-revenue-split"]
)


def _require_member(syndicate_id: str, user_sub: str) -> None:
    """Viewing split data requires syndicate membership (raises 404 otherwise)."""
    syndicate_svc._require_is_member(syndicate_id, user_sub)


# ---------------------------------------------------------------------------
# Split configuration
# ---------------------------------------------------------------------------

@syndicate_revenue_split_router.get(
    "/{syndicate_id}/config", response_model=SplitConfigOut
)
def get_config(syndicate_id: str, session=Depends(require_ui_session)):
    _require_member(syndicate_id, session["user_sub"])
    return svc.get_split_config(syndicate_id)


@syndicate_revenue_split_router.post(
    "/{syndicate_id}/config", response_model=SplitConfigOut
)
def set_config(
    syndicate_id: str, body: SplitConfigIn, session=Depends(require_ui_session)
):
    return svc.set_split_config(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        mode=body.mode,
        weights_bps=body.weights_bps,
        performance_metric=body.performance_metric,
        performance_window_days=body.performance_window_days,
        platform_fee_bps=body.platform_fee_bps,
    )


@syndicate_revenue_split_router.post(
    "/{syndicate_id}/performance-scores"
)
def set_performance_scores(
    syndicate_id: str, body: PerformanceScoresIn, session=Depends(require_ui_session)
):
    return svc.set_performance_scores(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        metric=body.metric,
        scores=body.scores,
    )


# ---------------------------------------------------------------------------
# Split history / earnings
# ---------------------------------------------------------------------------

@syndicate_revenue_split_router.get(
    "/{syndicate_id}/splits", response_model=List[SplitExecutionOut]
)
def list_splits(syndicate_id: str, session=Depends(require_ui_session)):
    _require_member(syndicate_id, session["user_sub"])
    return svc.get_split_history(syndicate_id, limit=100)


@syndicate_revenue_split_router.get(
    "/{syndicate_id}/splits/{split_id}", response_model=SplitExecutionOut
)
def get_split(syndicate_id: str, split_id: str, session=Depends(require_ui_session)):
    _require_member(syndicate_id, session["user_sub"])
    return svc.get_split(syndicate_id, split_id)


@syndicate_revenue_split_router.get(
    "/{syndicate_id}/my-earnings", response_model=MemberEarningsOut
)
def my_earnings(syndicate_id: str, session=Depends(require_ui_session)):
    _require_member(syndicate_id, session["user_sub"])
    return svc.get_member_earnings(syndicate_id, session["user_sub"])


# ---------------------------------------------------------------------------
# Split execution
# ---------------------------------------------------------------------------

@syndicate_revenue_split_router.post(
    "/{syndicate_id}/execute", response_model=SplitExecutionOut
)
def execute_split(
    syndicate_id: str, body: ExecuteSplitIn, session=Depends(require_ui_session)
):
    """Trigger a revenue split for a payment event (syndicate admin only).

    Deterministic and directly callable for testing/seeding. The subscription
    payment flow calls :func:`svc.execute_split` directly after a bundle payment.
    """
    syndicate_svc._require_admin(syndicate_id, session["user_sub"])
    return svc.execute_split(
        syndicate_id=syndicate_id,
        source_type=body.source_type,
        subscription_id=body.subscription_id,
        invoice_id=body.invoice_id,
        gross_amount_cents=body.gross_amount_cents,
        currency=body.currency,
    )


@syndicate_revenue_split_router.post(
    "/internal/{syndicate_id}/execute", response_model=SplitExecutionOut
)
def execute_split_internal(
    syndicate_id: str,
    body: ExecuteSplitIn,
    _admin=Depends(require_admin_or_root),
):
    """Internal split trigger for the payment system (admin/root scoped)."""
    return svc.execute_split(
        syndicate_id=syndicate_id,
        source_type=body.source_type,
        subscription_id=body.subscription_id,
        invoice_id=body.invoice_id,
        gross_amount_cents=body.gross_amount_cents,
        currency=body.currency,
    )

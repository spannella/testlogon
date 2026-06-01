"""Syndicate treasury / fund management router (SYND-004)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.models import (
    SyndicateTreasuryBalanceOut,
    SyndicateTreasuryContributorOut,
    SyndicateTreasuryDepositIn,
    SyndicateTreasuryDepositOut,
    SyndicateTreasuryDisburseIn,
    SyndicateTreasuryDisburseOut,
    SyndicateTreasuryLedgerEntryOut,
    SyndicateTreasuryLedgerOut,
)
from app.services import syndicate_treasury as svc
from app.services import syndicates as syndicate_svc
from app.services.sessions import require_ui_session

syndicate_treasury_router = APIRouter(
    prefix="/ui/syndicates/treasury", tags=["syndicate-treasury"]
)


@syndicate_treasury_router.get("/{syndicate_id}", response_model=SyndicateTreasuryBalanceOut)
def get_balance(syndicate_id: str, session=Depends(require_ui_session)):
    """Treasury balance + lifetime totals (members only)."""
    syndicate_svc._require_is_member(syndicate_id, session["user_sub"])
    b = svc.get_treasury_balance(syndicate_id)
    return SyndicateTreasuryBalanceOut(
        syndicate_id=b["syndicate_id"],
        balance_cents=b["balance_cents"],
        total_deposited_cents=b["total_deposited_cents"],
        total_disbursed_cents=b["total_disbursed_cents"],
        currency=b["currency"],
        updated_at=b["updated_at"],
    )


@syndicate_treasury_router.post(
    "/{syndicate_id}/deposit", response_model=SyndicateTreasuryDepositOut
)
def deposit(
    syndicate_id: str,
    body: SyndicateTreasuryDepositIn,
    session=Depends(require_ui_session),
):
    """Member deposits from personal wallet into the treasury."""
    result = svc.deposit(
        syndicate_id=syndicate_id,
        user_id=session["user_sub"],
        amount_cents=body.amount_cents,
    )
    return SyndicateTreasuryDepositOut(**result)


@syndicate_treasury_router.post(
    "/{syndicate_id}/disburse", response_model=SyndicateTreasuryDisburseOut
)
def disburse(
    syndicate_id: str,
    body: SyndicateTreasuryDisburseIn,
    session=Depends(require_ui_session),
):
    """Admin disburses/withdraws treasury funds to a member's wallet (admin only)."""
    result = svc.disburse(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        recipient_user_id=body.recipient_user_id,
        amount_cents=body.amount_cents,
        note=body.note,
    )
    return SyndicateTreasuryDisburseOut(**result)


@syndicate_treasury_router.get(
    "/{syndicate_id}/ledger", response_model=SyndicateTreasuryLedgerOut
)
def list_ledger(
    syndicate_id: str,
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    session=Depends(require_ui_session),
):
    """Treasury transaction history (members only)."""
    syndicate_svc._require_is_member(syndicate_id, session["user_sub"])
    result = svc.list_treasury_ledger(syndicate_id, cursor=cursor, limit=limit)
    return SyndicateTreasuryLedgerOut(
        entries=[SyndicateTreasuryLedgerEntryOut(**e) for e in result["entries"]],
        cursor=result["cursor"],
        has_more=result["has_more"],
    )


@syndicate_treasury_router.get(
    "/{syndicate_id}/contributions",
    response_model=list[SyndicateTreasuryContributorOut],
)
def list_contributions(syndicate_id: str, session=Depends(require_ui_session)):
    """Per-member contribution breakdown (members only)."""
    syndicate_svc._require_is_member(syndicate_id, session["user_sub"])
    items = svc.list_contributions(syndicate_id)
    return [SyndicateTreasuryContributorOut(**c) for c in items]


@syndicate_treasury_router.get(
    "/{syndicate_id}/my-contributions",
    response_model=SyndicateTreasuryContributorOut,
)
def my_contributions(syndicate_id: str, session=Depends(require_ui_session)):
    """The caller's own contribution summary (members only)."""
    syndicate_svc._require_is_member(syndicate_id, session["user_sub"])
    return SyndicateTreasuryContributorOut(
        **svc.get_my_contributions(syndicate_id, session["user_sub"])
    )

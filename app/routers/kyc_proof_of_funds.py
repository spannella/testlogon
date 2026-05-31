"""KYC-005: Proof of Funds / Source of Funds router.

Self-scoped submission endpoints for users + reviewer endpoints (admin/root) to
list-by-status and adjudicate. Mirrors KYC-004 (kyc_residency) patterns.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth.policy import require_admin_or_root
from app.services import kyc_proof_of_funds
from app.services.sessions import require_ui_session

kyc_proof_of_funds_router = APIRouter(
    prefix="/ui/kyc/proof-of-funds",
    tags=["kyc-proof-of-funds"],
)


class CreateProofOfFundsSubmissionIn(BaseModel):
    source_category: Optional[str] = None
    declared_amount_cents: Optional[int] = Field(default=None, ge=0)
    currency: Optional[str] = None
    document_s3_key: Optional[str] = None
    note: Optional[str] = None


class AdjudicateIn(BaseModel):
    decision: str = Field(...)
    reviewer_note: Optional[str] = None


def _is_reviewer(session: dict) -> bool:
    role = (session or {}).get("role")
    return role in ("admin", "root")


@kyc_proof_of_funds_router.post("/submissions")
def create_submission(
    body: CreateProofOfFundsSubmissionIn,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    sub = kyc_proof_of_funds.create_submission(
        user_sub=user_sub,
        source_category=body.source_category,
        declared_amount_cents=body.declared_amount_cents,
        currency=body.currency,
        document_s3_key=body.document_s3_key,
        note=body.note,
    )
    return sub


@kyc_proof_of_funds_router.get("/submissions")
def list_my_submissions(session: dict = Depends(require_ui_session)):
    return {"submissions": kyc_proof_of_funds.list_submissions_for_user(session["user_sub"])}


@kyc_proof_of_funds_router.get("/summary")
def my_summary(session: dict = Depends(require_ui_session)):
    return kyc_proof_of_funds.summarize_proof_of_funds(session["user_sub"])


@kyc_proof_of_funds_router.get("/submissions/{submission_id}")
def get_one(submission_id: str, session: dict = Depends(require_ui_session)):
    sub = kyc_proof_of_funds.get_submission(submission_id)
    if not sub:
        raise HTTPException(status_code=404, detail="not found")
    if sub["user_sub"] != session["user_sub"] and not _is_reviewer(session):
        raise HTTPException(status_code=403, detail="forbidden")
    return sub


@kyc_proof_of_funds_router.get("/review/by-status/{status}")
def review_by_status(
    status: str,
    session: dict = Depends(require_admin_or_root),
):
    return {"submissions": kyc_proof_of_funds.list_by_status(status)}


@kyc_proof_of_funds_router.post("/review/{submission_id}/adjudicate")
def adjudicate(
    submission_id: str,
    body: AdjudicateIn,
    session: dict = Depends(require_admin_or_root),
):
    if body.decision not in ("verified", "rejected", "needs_more_info"):
        raise HTTPException(status_code=400, detail="invalid decision")
    updated = kyc_proof_of_funds.adjudicate(
        submission_id,
        decision=body.decision,
        reviewer_sub=session["user_sub"],
        reviewer_note=body.reviewer_note,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="not found")
    return updated

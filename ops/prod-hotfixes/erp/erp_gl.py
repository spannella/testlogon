"""ERP General-Ledger admin router (P1: mount the ERP finance surfaces).

Exposes the existing, previously-unmounted GL services over an operator/admin
HTTP surface:

  * gl_accounts  -> chart-of-accounts CRUD + enable/disable
  * gl_posting   -> journal entry read (list by date range, get one), + a
                    guarded manual balanced journal post.

Admin/root only (require_admin_or_root). Flag-gated: the underlying services
raise 404/503 when S.gl_double_entry_enabled is off, so this router surfaces a
clean Forbidden/Not-enabled rather than exposing anything when the ERP is off.

These routes use role-based auth (NOT the API-key policy dependency), so they
do not need an api_key_route_scope_registry entry and never trip the boot-time
uncovered-policy-route RuntimeError.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.services import gl_accounts as gl_accounts_svc
from app.services import gl_posting as gl_posting_svc

router = APIRouter(prefix="/v1/admin/gl", tags=["admin-gl"])


# -- Chart of accounts --------------------------------------------------------
class CreateAccountIn(BaseModel):
    account_code: str = Field(..., min_length=1, max_length=32)
    name: str = Field(..., min_length=1, max_length=200)
    account_class: str = Field(..., min_length=1, max_length=32)
    description: Optional[str] = Field(default=None, max_length=1000)


class UpdateAccountIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=1000)


@router.get("/accounts")
def list_accounts(
    account_class: Optional[str] = Query(default=None),
    active_only: bool = Query(default=True),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    rows = gl_accounts_svc.list_accounts(account_class=account_class, active_only=active_only)
    return {"accounts": rows, "count": len(rows)}


@router.get("/accounts/{account_code}")
def get_account(
    account_code: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    rec = gl_accounts_svc.get_account(account_code)
    if rec is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return rec


@router.post("/accounts", status_code=201)
def create_account(
    inp: CreateAccountIn,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    return gl_accounts_svc.create_account(
        account_code=inp.account_code.strip(),
        name=inp.name,
        account_class=inp.account_class.strip().lower(),
        description=inp.description,
        actor_sub=actor.sub,
    )


@router.patch("/accounts/{account_code}")
def update_account(
    account_code: str,
    inp: UpdateAccountIn,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    return gl_accounts_svc.update_account(
        account_code=account_code,
        name=inp.name,
        description=inp.description,
        actor_sub=actor.sub,
    )


@router.post("/accounts/{account_code}/disable")
def disable_account(
    account_code: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    return gl_accounts_svc.disable_account(account_code, actor.sub)


@router.post("/accounts/{account_code}/enable")
def enable_account(
    account_code: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    return gl_accounts_svc.enable_account(account_code, actor.sub)


# -- Journal (GL posting) -----------------------------------------------------
class JournalLineIn(BaseModel):
    account_code: str = Field(..., min_length=1, max_length=32)
    side: str = Field(..., pattern="^(debit|credit)$")
    amount_cents: int = Field(..., gt=0)


class PostJournalIn(BaseModel):
    lines: List[JournalLineIn] = Field(..., min_length=2)
    source_type: str = Field(default="manual_admin", min_length=1, max_length=64)
    source_entity_id: str = Field(..., min_length=1, max_length=128)
    memo: str = Field(default="", max_length=500)
    gl_date: str = Field(..., min_length=8, max_length=10)
    journal_id: Optional[str] = Field(default=None, max_length=128)


@router.get("/journal")
def list_journal(
    start_date: str = Query(..., min_length=8, max_length=10),
    end_date: str = Query(..., min_length=8, max_length=10),
    limit: int = Query(default=50, ge=1, le=200),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    return gl_posting_svc.list_journal_entries(
        start_date=start_date, end_date=end_date, limit=limit
    )


@router.get("/journal/{journal_entry_id}")
def get_journal(
    journal_entry_id: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    rec = gl_posting_svc.get_journal_entry_header(journal_entry_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Journal entry not found")
    return rec


@router.post("/journal", status_code=201)
def post_journal(
    inp: PostJournalIn,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    lines = [
        gl_posting_svc.JournalLine(
            account_code=l.account_code, side=l.side, amount_cents=l.amount_cents
        )
        for l in inp.lines
    ]
    try:
        jid = gl_posting_svc.post_journal_entry(
            lines,
            source_type=inp.source_type,
            source_entity_id=inp.source_entity_id,
            memo=inp.memo,
            gl_date=inp.gl_date,
            journal_id=inp.journal_id,
        )
    except gl_posting_svc.GLUnbalancedEntryError as exc:
        raise HTTPException(status_code=400, detail=f"Unbalanced journal entry: {exc}")
    return gl_posting_svc.get_journal_entry_header(jid) or {"journal_entry_id": jid}

"""OpenBankProject — banking accounts router (ACC-001..ACC-004).

Prefix ``/ui/banking``. All endpoints use cookie-based session auth
(``require_ui_session``) and are owner/co-owner scoped. Registered in
``app/main.py`` only when ``open_bank_project_enabled AND banking_accounts_enabled``
(decision D4 umbrella gate). When unregistered, all ``/ui/banking/*`` routes
return a true FastAPI 404 from the route resolver.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from app.core.settings import S
from app.models import (
    AccountBalanceOut,
    AccountCreateIn,
    AccountHolderOut,
    AccountHoldersOut,
    AccountListOut,
    AccountOut,
    AccountUpdateIn,
    AddAccountHolderIn,
    AddCommentIn,
    AddTagIn,
    BankListOut,
    BankOut,
    PutGeotagIn,
    PutNarrativeIn,
    TransactionListOut,
    TransactionMetadataOut,
    TransactionOut,
)
from app.services import banking_accounts as svc
from app.services.rate_limit import _bucket_limit
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/banking", tags=["banking"])


def _metadata_rate_limit(user_sub: str) -> None:
    if not _bucket_limit(
        user_sub, "rl#txn_meta_write", S.banking_metadata_write_rate_limit, 3600
    ):
        raise HTTPException(status_code=429, detail={"code": "rate_limited"})


def _coerce_ts(raw: Optional[str], field: str) -> Optional[int]:
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        pass
    try:
        return int(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())
    except Exception:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid date format for '{field}'; use Unix timestamp or ISO-8601",
        )


# ─── Banks ──────────────────────────────────────────────────────────────────


@router.get("/banks", response_model=BankListOut)
async def list_banks_endpoint(session: Dict = Depends(require_ui_session)):
    return BankListOut(banks=[BankOut(**b) for b in svc.list_banks()])


# ─── Accounts ─────────────────────────────────────────────────────────────────


@router.get("/accounts", response_model=AccountListOut)
async def list_accounts_endpoint(session: Dict = Depends(require_ui_session)):
    accounts = svc.list_accounts(session["user_sub"])
    return AccountListOut(accounts=[AccountOut(**a) for a in accounts])


@router.post("/accounts", status_code=201, response_model=AccountOut)
async def create_account_endpoint(
    body: AccountCreateIn,
    session: Dict = Depends(require_ui_session),
):
    acc = svc.create_account(
        session["user_sub"],
        label=body.label,
        account_type=body.account_type,
        bank_id=body.bank_id,
        product_code=body.product_code,
        currency=body.currency,
        attributes=[a.model_dump() for a in body.attributes],
        iban=body.iban,
        routing_number=body.routing_number,
        account_number_masked=body.account_number_masked,
    )
    return AccountOut(**acc)


@router.get("/accounts/{account_id}", response_model=AccountOut)
async def get_account_endpoint(
    account_id: str,
    session: Dict = Depends(require_ui_session),
):
    return AccountOut(**svc.get_account(account_id, requester_sub=session["user_sub"]))


@router.patch("/accounts/{account_id}", response_model=AccountOut)
async def update_account_endpoint(
    account_id: str,
    body: AccountUpdateIn,
    session: Dict = Depends(require_ui_session),
):
    acc = svc.update_account(
        account_id,
        session["user_sub"],
        label=body.label,
        attributes=(
            [a.model_dump() for a in body.attributes]
            if body.attributes is not None
            else None
        ),
        iban=body.iban,
        routing_number=body.routing_number,
        account_number_masked=body.account_number_masked,
    )
    return AccountOut(**acc)


@router.delete("/accounts/{account_id}", status_code=204)
async def delete_account_endpoint(
    account_id: str,
    session: Dict = Depends(require_ui_session),
):
    svc.delete_account(account_id, session["user_sub"])
    return None


@router.get("/accounts/{account_id}/balance", response_model=AccountBalanceOut)
async def get_account_balance_endpoint(
    account_id: str,
    session: Dict = Depends(require_ui_session),
):
    return AccountBalanceOut(
        **svc.get_account_balance(account_id, requester_sub=session["user_sub"])
    )


# ─── Transactions (ACC-002) ───────────────────────────────────────────────────


@router.get("/accounts/{account_id}/transactions", response_model=TransactionListOut)
async def list_transactions_endpoint(
    account_id: str,
    from_: Optional[str] = Query(default=None, alias="from"),
    to: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    order: str = Query(default="desc"),
    session: Dict = Depends(require_ui_session),
):
    from_ts = _coerce_ts(from_, "from")
    to_ts = _coerce_ts(to, "to")
    result = svc.list_account_transactions(
        account_id,
        requester_sub=session["user_sub"],
        from_ts=from_ts,
        to_ts=to_ts,
        limit=limit,
        cursor=cursor,
        order=order if order in ("asc", "desc") else "desc",
    )
    # Set has_metadata only when the metadata sub-feature is on.
    if S.banking_account_metadata_enabled:
        for txn in result["transactions"]:
            try:
                txn["has_metadata"] = svc.transaction_has_metadata(
                    account_id, txn["transaction_id"]
                )
            except Exception:
                txn["has_metadata"] = False
    return TransactionListOut(
        transactions=[TransactionOut(**t) for t in result["transactions"]],
        cursor=result["cursor"],
    )


@router.get(
    "/accounts/{account_id}/transactions/{transaction_id}",
    response_model=TransactionOut,
)
async def get_transaction_endpoint(
    account_id: str,
    transaction_id: str,
    session: Dict = Depends(require_ui_session),
):
    txn = svc.get_account_transaction(
        account_id, transaction_id, requester_sub=session["user_sub"]
    )
    if S.banking_account_metadata_enabled:
        try:
            txn["has_metadata"] = svc.transaction_has_metadata(
                account_id, transaction_id
            )
        except Exception:
            txn["has_metadata"] = False
    return TransactionOut(**txn)


# ─── Transaction metadata (ACC-003) ───────────────────────────────────────────


@router.get(
    "/accounts/{account_id}/transactions/{transaction_id}/metadata",
    response_model=TransactionMetadataOut,
)
async def get_transaction_metadata_endpoint(
    account_id: str,
    transaction_id: str,
    session: Dict = Depends(require_ui_session),
):
    return TransactionMetadataOut(
        **svc.get_transaction_metadata(
            account_id, transaction_id, requester_sub=session["user_sub"]
        )
    )


@router.put("/accounts/{account_id}/transactions/{transaction_id}/narrative")
async def put_narrative_endpoint(
    account_id: str,
    transaction_id: str,
    body: PutNarrativeIn,
    session: Dict = Depends(require_ui_session),
):
    _metadata_rate_limit(session["user_sub"])
    return svc.put_transaction_narrative(
        account_id, transaction_id, requester_sub=session["user_sub"], text=body.text
    )


@router.put("/accounts/{account_id}/transactions/{transaction_id}/geotag")
async def put_geotag_endpoint(
    account_id: str,
    transaction_id: str,
    body: PutGeotagIn,
    session: Dict = Depends(require_ui_session),
):
    _metadata_rate_limit(session["user_sub"])
    return svc.put_transaction_geotag(
        account_id,
        transaction_id,
        requester_sub=session["user_sub"],
        lat=body.lat,
        lon=body.lon,
        label=body.label,
    )


@router.post(
    "/accounts/{account_id}/transactions/{transaction_id}/image", status_code=201
)
async def post_image_endpoint(
    account_id: str,
    transaction_id: str,
    file: UploadFile = File(...),
    session: Dict = Depends(require_ui_session),
):
    _metadata_rate_limit(session["user_sub"])
    data = await file.read()
    return svc.set_transaction_image(
        account_id,
        transaction_id,
        requester_sub=session["user_sub"],
        image_bytes=data,
        content_type=file.content_type or "",
        filename=file.filename or "image",
    )


@router.post(
    "/accounts/{account_id}/transactions/{transaction_id}/tags", status_code=201
)
async def add_tag_endpoint(
    account_id: str,
    transaction_id: str,
    body: AddTagIn,
    session: Dict = Depends(require_ui_session),
):
    _metadata_rate_limit(session["user_sub"])
    return svc.add_transaction_tag(
        account_id, transaction_id, requester_sub=session["user_sub"], value=body.value
    )


@router.delete(
    "/accounts/{account_id}/transactions/{transaction_id}/tags/{tag_id}"
)
async def remove_tag_endpoint(
    account_id: str,
    transaction_id: str,
    tag_id: str,
    session: Dict = Depends(require_ui_session),
):
    _metadata_rate_limit(session["user_sub"])
    svc.remove_transaction_tag(
        account_id, transaction_id, tag_id, requester_sub=session["user_sub"]
    )
    return {"ok": True}


@router.post(
    "/accounts/{account_id}/transactions/{transaction_id}/comments", status_code=201
)
async def add_comment_endpoint(
    account_id: str,
    transaction_id: str,
    body: AddCommentIn,
    session: Dict = Depends(require_ui_session),
):
    _metadata_rate_limit(session["user_sub"])
    return svc.add_transaction_comment(
        account_id, transaction_id, requester_sub=session["user_sub"], text=body.text
    )


@router.delete(
    "/accounts/{account_id}/transactions/{transaction_id}/comments/{comment_id}"
)
async def delete_comment_endpoint(
    account_id: str,
    transaction_id: str,
    comment_id: str,
    session: Dict = Depends(require_ui_session),
):
    _metadata_rate_limit(session["user_sub"])
    svc.delete_transaction_comment(
        account_id, transaction_id, comment_id, requester_sub=session["user_sub"]
    )
    return {"ok": True}


# ─── Account-holder co-access (ACC-004) ────────────────────────────────────────


@router.get("/accounts/{account_id}/holders", response_model=AccountHoldersOut)
async def list_holders_endpoint(
    account_id: str,
    session: Dict = Depends(require_ui_session),
):
    holders = svc.list_account_holders(account_id, session["user_sub"])
    return AccountHoldersOut(holders=[AccountHolderOut(**h) for h in holders])


@router.post("/accounts/{account_id}/holders")
async def add_holder_endpoint(
    account_id: str,
    body: AddAccountHolderIn,
    session: Dict = Depends(require_ui_session),
):
    acc = svc.add_account_owner(account_id, session["user_sub"], body.user_sub)
    return {"account": AccountOut(**acc)}


@router.delete("/accounts/{account_id}/holders/{user_sub}")
async def remove_holder_endpoint(
    account_id: str,
    user_sub: str,
    session: Dict = Depends(require_ui_session),
):
    acc = svc.remove_account_owner(account_id, session["user_sub"], user_sub)
    return {"account": AccountOut(**acc)}

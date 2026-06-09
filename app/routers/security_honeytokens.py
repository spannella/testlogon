"""Honeytoken admin CRUD API (HNY-007).

DEFENSIVE-only. Root-gated management of decoy credentials. Mint returns the
plaintext secret ONCE; list/get/hits never echo a stored secret or hash.

Prefix ``/v1/admin/security/honeytokens``.
"""

from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser, require_root_session
from app.models import HoneytokenMintIn, HoneytokenMintOut, HoneytokenOut
from app.services import honeytokens, security_events

router = APIRouter(prefix="/v1/admin/security/honeytokens", tags=["security-honeytokens"])
logger = logging.getLogger(__name__)


@router.post("", response_model=HoneytokenMintOut)
@router.post("/", response_model=HoneytokenMintOut)
async def mint(
    body: HoneytokenMintIn,
    user: AuthenticatedUser = Depends(require_root_session),
) -> HoneytokenMintOut:
    try:
        result = honeytokens.mint_honeytoken(
            kind=body.kind,
            label=body.label,
            admin_sub=user.sub,
            placement=body.placement,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return HoneytokenMintOut(**result)


@router.get("", response_model=List[HoneytokenOut])
@router.get("/", response_model=List[HoneytokenOut])
async def list_tokens(
    _user: AuthenticatedUser = Depends(require_root_session),
) -> List[HoneytokenOut]:
    return [HoneytokenOut(**ht) for ht in honeytokens.list_honeytokens()]


@router.delete("/{token_id}")
async def retire(
    token_id: str,
    _user: AuthenticatedUser = Depends(require_root_session),
) -> dict:
    ok = honeytokens.retire_honeytoken(token_id)
    if not ok:
        raise HTTPException(404, "Honeytoken not found")
    return {"ok": True, "token_id": token_id, "retired": True}


@router.get("/{token_id}/hits")
async def hits(
    token_id: str,
    _user: AuthenticatedUser = Depends(require_root_session),
) -> dict:
    ht = honeytokens.get_honeytoken(token_id)
    if not ht:
        raise HTTPException(404, "Honeytoken not found")
    events = security_events.list_events_for_token(token_id)
    return {"token_id": token_id, "count": len(events), "events": events}

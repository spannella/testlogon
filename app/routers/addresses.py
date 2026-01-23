from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.models import AddressIn, AddressOut, AddressPrimaryReq, AddressSearchReq, AddressSearchResp
from app.services.addresses import (
    create_address,
    delete_address,
    list_addresses,
    search_addresses,
    set_primary_address,
    update_address,
)
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/addresses", tags=["addresses"])


@router.get("", response_model=list[AddressOut])
async def ui_list_addresses(ctx=Depends(require_ui_session)):
    return list_addresses(ctx["user_sub"])


@router.post("", response_model=AddressOut)
async def ui_create_address(req: Request, body: AddressIn, ctx=Depends(require_ui_session)):
    address = create_address(ctx["user_sub"], body.model_dump())
    audit_event("address_create", ctx["user_sub"], req, outcome="success", address_id=address["address_id"])
    return address


@router.patch("/{address_id}", response_model=AddressOut)
async def ui_update_address(
    req: Request,
    address_id: str,
    body: AddressIn,
    ctx=Depends(require_ui_session),
):
    address = update_address(ctx["user_sub"], address_id, body.model_dump(exclude_unset=True))
    audit_event("address_update", ctx["user_sub"], req, outcome="success", address_id=address_id)
    return address


@router.delete("/{address_id}")
async def ui_delete_address(req: Request, address_id: str, ctx=Depends(require_ui_session)):
    address = delete_address(ctx["user_sub"], address_id)
    audit_event("address_delete", ctx["user_sub"], req, outcome="success", address_id=address_id)
    return {"deleted": True, "address": address}


@router.post("/search", response_model=AddressSearchResp)
async def ui_search_addresses(body: AddressSearchReq, ctx=Depends(require_ui_session)):
    matches = search_addresses(ctx["user_sub"], body.query)
    return {"query": body.query, "matches": matches}


@router.put("/primary", response_model=AddressOut)
async def ui_set_primary_address(req: Request, body: AddressPrimaryReq, ctx=Depends(require_ui_session)):
    address = set_primary_address(ctx["user_sub"], body.address_id)
    audit_event("address_primary_set", ctx["user_sub"], req, outcome="success", address_id=body.address_id)
    return address

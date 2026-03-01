from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.tables import T
from app.services.profile import get_profile_identity
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/contacts", tags=["contacts"])


# ── Models ─────────────────────────────────────────────────────────────────

class AddContactIn(BaseModel):
    user_id: str


class UpdateContactIn(BaseModel):
    is_favorite: Optional[bool] = None
    is_blocked: Optional[bool] = None


class ContactEntry(BaseModel):
    owner_id: str
    contact_id: str
    display_name: str
    profile_photo_url: Optional[str] = None
    is_favorite: bool
    is_blocked: bool
    added_at: str


# ── Helpers ────────────────────────────────────────────────────────────────

def _item_to_contact(item: Dict[str, Any]) -> ContactEntry:
    return ContactEntry(
        owner_id=item["owner_id"],
        contact_id=item["contact_id"],
        display_name=item.get("display_name") or item["contact_id"],
        profile_photo_url=item.get("profile_photo_url") or None,
        is_favorite=bool(item.get("is_favorite", False)),
        is_blocked=bool(item.get("is_blocked", False)),
        added_at=item.get("added_at", ""),
    )


def _sort_contacts(contacts: List[ContactEntry]) -> List[ContactEntry]:
    """Favorites first, then alphabetical by display_name (case-insensitive)."""
    return sorted(
        contacts,
        key=lambda c: (not c.is_favorite, c.display_name.lower()),
    )


# ── Endpoints ──────────────────────────────────────────────────────────────

@router.get("", response_model=Dict[str, List[ContactEntry]])
def list_contacts(ctx: Dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("owner_id").eq(user_sub),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.contacts.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    contacts = _sort_contacts([_item_to_contact(i) for i in items])
    return {"contacts": contacts}


@router.post("", response_model=ContactEntry, status_code=201)
def add_contact(inp: AddContactIn, ctx: Dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]

    if inp.user_id == user_sub:
        raise HTTPException(400, "Cannot add yourself as a contact")

    # Load display name + photo from profile
    try:
        identity = get_profile_identity(inp.user_id)
        display_name = identity.get("display_name") or inp.user_id
        profile_photo_url = identity.get("profile_photo_url") or None
    except Exception:
        display_name = inp.user_id
        profile_photo_url = None

    now = datetime.now(timezone.utc).isoformat()
    item: Dict[str, Any] = {
        "owner_id": user_sub,
        "contact_id": inp.user_id,
        "display_name": display_name,
        "profile_photo_url": profile_photo_url,
        "is_favorite": False,
        "is_blocked": False,
        "added_at": now,
    }
    T.contacts.put_item(Item=item)
    return _item_to_contact(item)


@router.delete("/{contact_id}", status_code=204)
def remove_contact(contact_id: str, ctx: Dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    T.contacts.delete_item(Key={"owner_id": user_sub, "contact_id": contact_id})


@router.patch("/{contact_id}", response_model=ContactEntry)
def update_contact(contact_id: str, inp: UpdateContactIn, ctx: Dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]

    if inp.is_favorite is None and inp.is_blocked is None:
        raise HTTPException(400, "Nothing to update")

    # Build update expression
    set_parts: List[str] = []
    expr_names: Dict[str, str] = {}
    expr_values: Dict[str, Any] = {}

    if inp.is_favorite is not None:
        set_parts.append("#fav = :fav")
        expr_names["#fav"] = "is_favorite"
        expr_values[":fav"] = inp.is_favorite

    if inp.is_blocked is not None:
        set_parts.append("#blk = :blk")
        expr_names["#blk"] = "is_blocked"
        expr_values[":blk"] = inp.is_blocked

    update_expr = "SET " + ", ".join(set_parts)

    try:
        resp = T.contacts.update_item(
            Key={"owner_id": user_sub, "contact_id": contact_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
            ConditionExpression="attribute_exists(owner_id)",
            ReturnValues="ALL_NEW",
        )
    except T.contacts.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(404, "Contact not found")

    return _item_to_contact(resp["Attributes"])

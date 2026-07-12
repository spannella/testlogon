"""Contact list management for marketing campaigns (MKT-007)."""
from __future__ import annotations

import hashlib
from typing import Optional

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import ContactListCreateIn, ContactListUpdateIn, ContactListMemberIn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_enabled() -> None:
    if not S.marketing_campaigns_enabled:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=403,
            detail={"code": "marketing_campaigns_disabled",
                    "message": "Marketing campaigns module is not enabled."},
        )


def _make_list_id(owner_id: str, name: str, ts: int) -> str:
    created_bucket = (ts // 3600) * 3600
    raw = f"{owner_id}\x00{name}\x00{created_bucket}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def _is_opted_out(party_id: str) -> bool:
    try:
        from app.services.cart_reminders import is_user_opted_out
        return is_user_opted_out(party_id)
    except (ImportError, Exception):
        return False


# ---------------------------------------------------------------------------
# List CRUD
# ---------------------------------------------------------------------------


def create_list(owner_id: str, data: ContactListCreateIn) -> dict:
    """Create a contact list (idempotent within the hour bucket)."""
    _require_enabled()

    ts = now_ts()
    list_id = _make_list_id(owner_id, data.name, ts)

    meta: dict = {
        "pk": f"OWNER#{owner_id}",
        "sk": f"LIST#{list_id}",
        "list_id": list_id,
        "owner_id": owner_id,
        "name": data.name,
        "member_count": 0,
        "created_at": ts,
        "updated_at": ts,
    }
    if data.description is not None:
        meta["description"] = data.description

    try:
        T.contact_lists.put_item(
            Item=meta,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            existing = get_list(owner_id, list_id)
            return existing if existing is not None else meta
        raise

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.list.created", owner_id, list_id=list_id, name=data.name)
    except Exception:
        pass

    return meta


def get_list(owner_id: str, list_id: str) -> Optional[dict]:
    """Return a list META item or None."""
    resp = T.contact_lists.get_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"LIST#{list_id}"}
    )
    return resp.get("Item")


def list_lists(owner_id: str) -> list[dict]:
    """Return all lists for an owner."""
    resp = T.contact_lists.query(
        IndexName="ByOwnerCreatedAt",
        KeyConditionExpression=Key("owner_id").eq(owner_id),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def update_list(owner_id: str, list_id: str, data: ContactListUpdateIn) -> dict:
    """Update mutable list fields."""
    lst = get_list(owner_id, list_id)
    if lst is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="List not found")

    _require_enabled()

    updates: dict = {}
    if data.name is not None:
        updates["name"] = data.name
    if data.description is not None:
        updates["description"] = data.description

    if updates:
        ts = now_ts()
        updates["updated_at"] = ts
        set_parts = []
        expr_names = {}
        expr_values = {}
        for i, (k, v) in enumerate(updates.items()):
            ph = f"#f{i}"
            vph = f":v{i}"
            expr_names[ph] = k
            expr_values[vph] = v
            set_parts.append(f"{ph} = {vph}")

        T.contact_lists.update_item(
            Key={"pk": f"OWNER#{owner_id}", "sk": f"LIST#{list_id}"},
            UpdateExpression="SET " + ", ".join(set_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )

    return get_list(owner_id, list_id) or lst


def delete_list(owner_id: str, list_id: str) -> None:
    """Delete a list META row (member rows are orphaned — lightweight)."""
    _require_enabled()
    T.contact_lists.delete_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"LIST#{list_id}"}
    )


# ---------------------------------------------------------------------------
# Member management
# ---------------------------------------------------------------------------


def add_member(owner_id: str, list_id: str, data: ContactListMemberIn) -> dict:
    """Add a party to the list. Idempotent. Returns the member row."""
    lst = get_list(owner_id, list_id)
    if lst is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="List not found")

    _require_enabled()

    party_id = data.party_id

    # Validate party exists
    display_name: Optional[str] = None
    try:
        from app.services.profile import get_profile_identity
        identity = get_profile_identity(party_id)
        if not identity.get("display_name") and not identity.get("email"):
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail=f"Party '{party_id}' not found")
        display_name = identity.get("display_name") or identity.get("email")
    except (ImportError, Exception):
        pass

    suppressed = _is_opted_out(party_id)
    ts = now_ts()

    member_row: dict = {
        "pk": f"LIST#{list_id}",
        "sk": f"PARTY#{party_id}",
        "list_id": list_id,
        "party_id": party_id,
        "joined_at": ts,
        "suppressed": suppressed,
    }
    if display_name:
        member_row["display_name"] = display_name

    try:
        T.contact_lists.put_item(
            Item=member_row,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Already a member — idempotent
            existing = T.contact_lists.get_item(
                Key={"pk": f"LIST#{list_id}", "sk": f"PARTY#{party_id}"}
            ).get("Item")
            return existing if existing is not None else member_row
        raise

    # Increment member_count on META row
    try:
        T.contact_lists.update_item(
            Key={"pk": f"OWNER#{owner_id}", "sk": f"LIST#{list_id}"},
            UpdateExpression="SET member_count = if_not_exists(member_count, :zero) + :one, updated_at = :ts",
            ExpressionAttributeValues={":zero": 0, ":one": 1, ":ts": ts},
        )
    except Exception:
        pass

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.list.member_added", owner_id,
                    list_id=list_id, party_id=party_id)
    except Exception:
        pass

    return member_row


def remove_member(owner_id: str, list_id: str, party_id: str) -> None:
    """Remove a party from the list."""
    lst = get_list(owner_id, list_id)
    if lst is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="List not found")

    _require_enabled()

    # Check member exists
    existing = T.contact_lists.get_item(
        Key={"pk": f"LIST#{list_id}", "sk": f"PARTY#{party_id}"}
    ).get("Item")

    T.contact_lists.delete_item(
        Key={"pk": f"LIST#{list_id}", "sk": f"PARTY#{party_id}"}
    )

    if existing:
        # Decrement member_count
        try:
            T.contact_lists.update_item(
                Key={"pk": f"OWNER#{owner_id}", "sk": f"LIST#{list_id}"},
                UpdateExpression="SET member_count = if_not_exists(member_count, :zero) - :one, updated_at = :ts",
                ExpressionAttributeValues={":zero": 0, ":one": 1, ":ts": now_ts()},
            )
        except Exception:
            pass

        try:
            from app.services.alerts import audit_event
            audit_event("marketing.list.member_removed", owner_id,
                        list_id=list_id, party_id=party_id)
        except Exception:
            pass


def list_members(
    list_id: str,
    include_suppressed: bool = True,
    limit: int = 200,
) -> list[dict]:
    """Return members of a list. Filters suppressed by default when include_suppressed=False."""
    resp = T.contact_lists.query(
        KeyConditionExpression=Key("pk").eq(f"LIST#{list_id}"),
        Limit=limit,
    )
    items = resp.get("Items", [])
    if not include_suppressed:
        items = [m for m in items if not m.get("suppressed")]
    return items


def list_members_for_send(list_id: str) -> list[dict]:
    """Return non-suppressed members suitable for campaign send."""
    return list_members(list_id, include_suppressed=False)


def seed_from_contacts(owner_id: str, list_id: str) -> dict:
    """Import the owner's contact book entries into the list additively."""
    lst = get_list(owner_id, list_id)
    if lst is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="List not found")

    _require_enabled()

    added = 0
    skipped = 0

    # Iterate owner's contacts
    resp = T.contacts.query(
        KeyConditionExpression=Key("owner_id").eq(owner_id),
        Limit=500,
    )
    contacts = resp.get("Items", [])

    for contact in contacts:
        contact_id = contact.get("contact_id")
        if not contact_id:
            continue
        try:
            add_member(owner_id, list_id, ContactListMemberIn(party_id=contact_id))
            added += 1
        except Exception:
            skipped += 1

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.list.seeded_from_contacts", owner_id,
                    list_id=list_id, added=added, skipped=skipped)
    except Exception:
        pass

    return {"list_id": list_id, "added": added, "skipped": skipped}

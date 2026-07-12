"""Additive, back-compatible projection of legacy Contacts rows into the party graph.

Read-only against ``T.contacts``; all writes target ``T.party`` via the PTY-004/005/006
service functions. Gated by ``S.party_crm_contacts_migration_enabled`` (and the parent
``S.party_crm_enabled`` for the forward hook). With the flags off this module is never
imported on any request path.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.services.party import (
    add_role,
    create_party,
    create_relationship,
)

logger = logging.getLogger(__name__)


def _person_party_id(user_sub: str) -> str:
    corr = f"contacts-person:{user_sub}"
    return hashlib.sha256(corr.encode("utf-8")).hexdigest()[:32]


def _rel_correlation_id(owner_id: str, contact_id: str) -> str:
    return f"contacts-rel:{owner_id}:{contact_id}"


def _ensure_person_party(user_sub: str) -> str:
    result = create_party(
        "PERSON",
        user_sub=user_sub,
        correlation_id=f"contacts-person:{user_sub}",
    )
    return result["party_id"]


def _project_contact_row(
    owner_id: str,
    contact_id: str,
    contact_item: Dict[str, Any],
) -> None:
    if owner_id == contact_id:
        logger.warning(
            "party_contacts_migration: skipping self-contact owner=%s", owner_id
        )
        return

    owner_party_id = _ensure_person_party(owner_id)
    contact_party_id = _ensure_person_party(contact_id)

    add_role(contact_party_id, "CONTACT")

    create_relationship(
        owner_party_id,
        contact_party_id,
        "CONTACT_REL",
        correlation_id=_rel_correlation_id(owner_id, contact_id),
        extra={
            "is_favorite": bool(contact_item.get("is_favorite", False)),
            "is_blocked": bool(contact_item.get("is_blocked", False)),
            "display_name": contact_item.get("display_name", ""),
            "profile_photo_url": contact_item.get("profile_photo_url"),
            "migrated_from": "contacts",
        },
    )

    try:
        from app.services.alerts import audit_event

        audit_event(
            "party.contacts_migration.projected",
            owner_id,
            None,
            contact_id=contact_id,
            owner_party_id=owner_party_id,
            contact_party_id=contact_party_id,
        )
    except Exception:
        pass


def run_contacts_backfill(*, owner_id: Optional[str] = None) -> Dict[str, int]:
    if not (S.party_crm_enabled and S.party_crm_contacts_migration_enabled):
        raise RuntimeError("party_crm_contacts_migration_enabled is off")

    scanned = 0
    projected = 0
    errors = 0

    def _handle(item: Dict[str, Any]) -> None:
        nonlocal scanned, projected, errors
        scanned += 1
        oid = item.get("owner_id")
        cid = item.get("contact_id")
        if not oid or not cid:
            errors += 1
            return
        try:
            _project_contact_row(oid, cid, item)
            projected += 1
        except Exception:
            errors += 1
            logger.exception(
                "party_contacts_migration: failed owner=%s contact=%s", oid, cid
            )

    last_key = None
    if owner_id:
        while True:
            kwargs: Dict[str, Any] = {
                "KeyConditionExpression": Key("owner_id").eq(owner_id),
                "Limit": 500,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.contacts.query(**kwargs)
            for item in resp.get("Items", []):
                _handle(item)
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    else:
        while True:
            kwargs = {"Limit": 500}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.contacts.scan(**kwargs)
            for item in resp.get("Items", []):
                _handle(item)
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

    return {"scanned": scanned, "projected": projected, "errors": errors}


def maybe_project_new_contact(
    owner_id: str,
    contact_id: str,
    contact_item: Dict[str, Any],
) -> None:
    if not (S.party_crm_enabled and S.party_crm_contacts_migration_enabled):
        return
    try:
        _project_contact_row(owner_id, contact_id, contact_item)
    except Exception:
        logger.exception(
            "party_contacts_migration: forward hook failed for owner=%s contact=%s",
            owner_id,
            contact_id,
        )

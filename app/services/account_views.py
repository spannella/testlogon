"""VEW-001/002/003 — Account Views service.

Field-level access delegation for financial resources (wallet / ledger_account /
payout_destination). Mirrors the grant/revoke/audit patterns in
``app/services/delegates.py``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.crypto import b64url, b64url_decode
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.time import now_ts
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Field-grant catalog (VEW-001)
# ---------------------------------------------------------------------------

VIEW_FIELD_GRANTS: frozenset[str] = frozenset(
    {
        "can_see_balance",
        "can_see_available_balance",
        "can_see_transaction_list",
        "can_see_transaction_amount",
        "can_see_transaction_description",
        "can_see_counterparty",
        "can_see_counterparty_name",
        "can_see_owners",
        "can_see_account_label",
        "can_see_payout_destination_masked",
        "can_add_comment",
        "can_add_tag",
        "can_add_narrative",
        "can_delete_comment",
    }
)

VIEW_PRESETS: Dict[str, Dict[str, Any]] = {
    "owner": {
        "label": "Owner",
        "grants": {k: True for k in VIEW_FIELD_GRANTS},
    },
    "accountant": {
        "label": "Accountant",
        "grants": {
            "can_see_balance": True,
            "can_see_available_balance": True,
            "can_see_transaction_list": True,
            "can_see_transaction_amount": True,
            "can_see_counterparty": True,
            "can_see_counterparty_name": True,
            "can_see_account_label": True,
        },
    },
    "auditor": {
        "label": "Auditor",
        "grants": {k: True for k in VIEW_FIELD_GRANTS if k.startswith("can_see_")},
    },
    "public": {
        "label": "Public",
        "grants": {
            "can_see_account_label": True,
            "can_see_balance": True,
        },
    },
}

# Resource types allowed for View-backed access delegation
_VALID_RESOURCE_TYPES: frozenset[str] = frozenset(
    {"wallet", "ledger_account", "payout_destination"}
)

# ---------------------------------------------------------------------------
# Field-to-grant registry (VEW-003)
# ---------------------------------------------------------------------------

FIELD_TO_GRANT: Dict[str, Dict[str, str]] = {
    "wallet": {
        "wallet_balance_cents": "can_see_balance",
        "available_balance_cents": "can_see_available_balance",
        "currency": "can_see_account_label",
        "label": "can_see_account_label",
        "updated_at": "can_see_account_label",
    },
    "ledger_account": {
        "balance_summary": "can_see_balance",
        "transaction_list": "can_see_transaction_list",
    },
    "payout_destination": {
        "method": "can_see_payout_destination_masked",
        "method_id": "can_see_payout_destination_masked",
        "status": "can_see_payout_destination_masked",
        "amount_cents": "can_see_transaction_amount",
        "created_at": "can_see_account_label",
        "updated_at": "can_see_account_label",
        "notes": "can_see_transaction_description",
        "reject_reason": "can_see_transaction_description",
        "approved_by": "can_see_counterparty",
        "completed_at": "can_see_account_label",
    },
}

TRANSACTION_ROW_FIELD_TO_GRANT: Dict[str, str] = {
    "amount_cents": "can_see_transaction_amount",
    "description": "can_see_transaction_description",
    "counterparty": "can_see_counterparty",
    "counterparty_name": "can_see_counterparty_name",
    "reason": "can_see_transaction_description",
    "state": "can_see_transaction_amount",
    "ts": "can_see_transaction_amount",
    "entry_id": "can_see_transaction_amount",
}

# Envelope-identity fields always included (not subject to projection)
_IDENTITY_FIELDS: frozenset[str] = frozenset(
    {"resource_type", "resource_id", "payout_id", "user_id"}
)

# Owner view uses a deterministic, non-uuid view_id so ensure_owner_view is idempotent
_OWNER_VIEW_ID = "owner"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_enabled() -> None:
    """Raise 404 if the VEW feature is off."""
    if not (
        getattr(S, "open_bank_project_enabled", False)
        and getattr(S, "account_views_enabled", False)
    ):
        raise HTTPException(status_code=404, detail="Account views not enabled")


def _validate_grants(grants: Dict[str, bool]) -> None:
    invalid = set(grants.keys()) - VIEW_FIELD_GRANTS
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown grant keys: {sorted(invalid)}",
        )


def _detect_preset(grants: Dict[str, bool]) -> Optional[str]:
    truthy_keys = {k for k, v in grants.items() if v}
    for preset_key, preset_data in VIEW_PRESETS.items():
        preset_truthy = {k for k, v in preset_data["grants"].items() if v}
        if truthy_keys == preset_truthy:
            return preset_key
    return None


def _enforce_view_limit(resource_type: str, resource_id: str) -> None:
    max_views = int(getattr(S, "account_views_max_per_resource", 25))
    views = list_views(resource_type, resource_id)
    if len(views) >= max_views:
        raise HTTPException(status_code=400, detail="View limit reached for this resource")


def _require_owner(owner_sub: str, item: Dict[str, Any]) -> None:
    if item.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="Not the resource owner")


def _require_not_system_alias(item: Dict[str, Any], *, verb: str = "modify") -> None:
    if item.get("is_system_alias"):
        raise HTTPException(
            status_code=409,
            detail={"code": "system_view_immutable", "message": f"Cannot {verb} the system owner view"},
        )


def _require_not_self(owner_sub: str, grantee_sub: str) -> None:
    if owner_sub == grantee_sub:
        raise HTTPException(status_code=400, detail="Cannot grant to yourself")


def _write_audit(
    resource_type: str,
    resource_id: str,
    actor_sub: str,
    action: str,
    view_id: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        from app.core.tables import T  # late import keeps circular-dep safe

        ts = now_ts()
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        T.account_views.put_item(
            Item={
                "pk": f"RESOURCE#{resource_type}#{resource_id}",
                "sk": f"AUDIT#{ts:013d}#{event_id}",
                "event_id": event_id,
                "actor_sub": actor_sub,
                "action": action,
                "target_view_id": view_id,
                "details": details or {},
                "ts": ts,
            }
        )
    except Exception as exc:
        logger.warning("account_views._write_audit failed: %s", exc)


def _assert_owns_resource(owner_sub: str, resource_type: str, resource_id: str) -> None:
    if resource_type not in _VALID_RESOURCE_TYPES:
        raise HTTPException(status_code=400, detail="Unknown resource_type")
    if resource_type in ("wallet", "ledger_account"):
        if resource_id != owner_sub:
            raise HTTPException(status_code=403, detail="Not the resource owner")
    elif resource_type == "payout_destination":
        try:
            from app.core.tables import T  # late import

            item = T.creator_payouts.get_item(Key={"payout_id": resource_id}).get("Item")
        except Exception:
            item = None
        if not item or item.get("user_id") != owner_sub:
            raise HTTPException(status_code=403, detail="Not the resource owner")


def _is_resource_owner(owner_sub: str, resource_type: str, resource_id: str) -> bool:
    """Return True if caller is the resource owner (non-raising)."""
    try:
        _assert_owns_resource(owner_sub, resource_type, resource_id)
        return True
    except HTTPException:
        return False


# ---------------------------------------------------------------------------
# VEW-001 — View CRUD
# ---------------------------------------------------------------------------


def create_view(
    owner_sub: str,
    resource_type: str,
    resource_id: str,
    name: str,
    grants: Dict[str, bool],
    *,
    preset: Optional[str] = None,
    description: str = "",
    metadata_visibility: str = "",
) -> Dict[str, Any]:
    from app.core.tables import T

    if resource_type not in _VALID_RESOURCE_TYPES:
        raise HTTPException(status_code=400, detail="Unknown resource_type")
    _validate_grants(grants)
    _assert_owns_resource(owner_sub, resource_type, resource_id)
    _enforce_view_limit(resource_type, resource_id)

    detected_preset = _detect_preset(grants)
    ts = now_ts()
    view_id = uuid.uuid4().hex
    item: Dict[str, Any] = {
        "pk": f"RESOURCE#{resource_type}#{resource_id}",
        "sk": f"VIEW#{view_id}",
        "view_id": view_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "owner_sub": owner_sub,
        "name": name,
        "description": description,
        "is_system_alias": False,
        "grants": grants,
        "preset": detected_preset,
        "metadata_visibility": metadata_visibility,
        "created_at": ts,
        "updated_at": ts,
        "created_by_sub": owner_sub,
        "GSI1PK": f"OWNER#{owner_sub}",
        "GSI1SK": ts,
    }
    T.account_views.put_item(Item=item)

    try:
        audit_event(
            "account_view.created",
            owner_sub,
            resource_type=resource_type,
            resource_id=resource_id,
            view_id=view_id,
        )
    except Exception as exc:
        logger.warning("account_views: audit_event failed: %s", exc)

    _write_audit(resource_type, resource_id, owner_sub, "view_created", view_id)
    return item


def get_view(
    resource_type: str,
    resource_id: str,
    view_id: str,
) -> Optional[Dict[str, Any]]:
    from app.core.tables import T

    item = T.account_views.get_item(
        Key={
            "pk": f"RESOURCE#{resource_type}#{resource_id}",
            "sk": f"VIEW#{view_id}",
        }
    ).get("Item")
    return item


def list_views(resource_type: str, resource_id: str) -> List[Dict[str, Any]]:
    from app.core.tables import T

    items: List[Dict[str, Any]] = []
    lek = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(
                f"RESOURCE#{resource_type}#{resource_id}"
            ) & Key("sk").begins_with("VIEW#"),
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.account_views.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
    return items


def list_views_by_owner(
    owner_sub: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    from app.core.tables import T

    lek = decode_cursor(cursor) if cursor else None
    kwargs: Dict[str, Any] = {
        "IndexName": "by-owner",
        "KeyConditionExpression": Key("GSI1PK").eq(f"OWNER#{owner_sub}"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if lek:
        kwargs["ExclusiveStartKey"] = lek
    resp = T.account_views.query(**kwargs)
    raw_items = resp.get("Items", [])
    # Filter to view rows only (by-owner GSI may include audit rows in theory)
    views = [it for it in raw_items if str(it.get("sk", "")).startswith("VIEW#")]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey")) if resp.get("LastEvaluatedKey") else None
    return {"views": views, "next_cursor": next_cursor}


def update_view(
    owner_sub: str,
    resource_type: str,
    resource_id: str,
    view_id: str,
    *,
    name: Optional[str] = None,
    grants: Optional[Dict[str, bool]] = None,
    description: Optional[str] = None,
    metadata_visibility: Optional[str] = None,
) -> Dict[str, Any]:
    from app.core.tables import T

    item = get_view(resource_type, resource_id, view_id)
    if not item:
        raise HTTPException(status_code=404, detail="View not found")
    _require_owner(owner_sub, item)
    _require_not_system_alias(item)

    update_exprs = ["#ua = :ua"]
    expr_names: Dict[str, str] = {"#ua": "updated_at"}
    expr_values: Dict[str, Any] = {":ua": now_ts()}

    if name is not None:
        update_exprs.append("#nm = :nm")
        expr_names["#nm"] = "name"
        expr_values[":nm"] = name

    if grants is not None:
        _validate_grants(grants)
        detected = _detect_preset(grants)
        update_exprs.append("grants = :gr")
        update_exprs.append("preset = :pr")
        expr_values[":gr"] = grants
        expr_values[":pr"] = detected

    if description is not None:
        update_exprs.append("description = :desc")
        expr_values[":desc"] = description

    if metadata_visibility is not None:
        update_exprs.append("metadata_visibility = :mv")
        expr_values[":mv"] = metadata_visibility

    T.account_views.update_item(
        Key={
            "pk": f"RESOURCE#{resource_type}#{resource_id}",
            "sk": f"VIEW#{view_id}",
        },
        UpdateExpression="SET " + ", ".join(update_exprs),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )

    updated = get_view(resource_type, resource_id, view_id) or {}

    try:
        audit_event(
            "account_view.updated",
            owner_sub,
            resource_type=resource_type,
            resource_id=resource_id,
            view_id=view_id,
        )
    except Exception as exc:
        logger.warning("account_views: audit_event failed: %s", exc)

    _write_audit(resource_type, resource_id, owner_sub, "view_updated", view_id)
    return updated


def delete_view(
    owner_sub: str,
    resource_type: str,
    resource_id: str,
    view_id: str,
) -> None:
    from app.core.tables import T

    item = get_view(resource_type, resource_id, view_id)
    if not item:
        raise HTTPException(status_code=404, detail="View not found")
    _require_owner(owner_sub, item)
    _require_not_system_alias(item, verb="delete")

    # Cascade-delete VIEWGRANT rows (VEW-002 pre-wired stub)
    try:
        resp = T.account_views.query(
            KeyConditionExpression=Key("pk").eq(
                f"RESOURCE#{resource_type}#{resource_id}"
            ) & Key("sk").begins_with(f"VIEWGRANT#"),
            FilterExpression=Attr("view_id").eq(view_id),
        )
        for row in resp.get("Items", []):
            T.account_views.delete_item(Key={"pk": row["pk"], "sk": row["sk"]})
    except Exception as exc:
        logger.warning("account_views.delete_view: cascade-delete failed: %s", exc)

    T.account_views.delete_item(
        Key={
            "pk": f"RESOURCE#{resource_type}#{resource_id}",
            "sk": f"VIEW#{view_id}",
        }
    )

    try:
        audit_event(
            "account_view.deleted",
            owner_sub,
            resource_type=resource_type,
            resource_id=resource_id,
            view_id=view_id,
        )
    except Exception as exc:
        logger.warning("account_views: audit_event failed: %s", exc)

    _write_audit(resource_type, resource_id, owner_sub, "view_deleted", view_id)


def ensure_owner_view(
    owner_sub: str,
    resource_type: str,
    resource_id: str,
) -> Dict[str, Any]:
    from app.core.tables import T

    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"RESOURCE#{resource_type}#{resource_id}",
        "sk": f"VIEW#{_OWNER_VIEW_ID}",
        "view_id": _OWNER_VIEW_ID,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "owner_sub": owner_sub,
        "name": "Owner",
        "description": "Full-access system view for the resource owner",
        "is_system_alias": True,
        "grants": {k: True for k in VIEW_FIELD_GRANTS},
        "preset": "owner",
        "metadata_visibility": "",
        "created_at": ts,
        "updated_at": ts,
        "created_by_sub": owner_sub,
        "GSI1PK": f"OWNER#{owner_sub}",
        "GSI1SK": ts,
    }
    try:
        T.account_views.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk)",
        )
        return item
    except Exception:
        # Already exists — return existing row
        existing = get_view(resource_type, resource_id, _OWNER_VIEW_ID)
        return existing or item


def get_grant_catalog() -> Dict[str, Any]:
    return {
        "fields": sorted(VIEW_FIELD_GRANTS),
        "presets": [
            {"key": k, "label": v["label"], "grants": v["grants"]}
            for k, v in VIEW_PRESETS.items()
        ],
    }


# ---------------------------------------------------------------------------
# VEW-002 — Grant / revoke / public-link
# ---------------------------------------------------------------------------


def _public_link_secret() -> bytes:
    secret = getattr(S, "account_view_public_secret", "") or getattr(S, "ui_access_token_secret", "")
    return secret.encode("utf-8")


def _sign_public_link_token(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(_public_link_secret(), raw, hashlib.sha256).digest()
    return f"{b64url(raw)}.{b64url(sig)}"


def _verify_public_link_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = b64url_decode(raw_b64)
        sig = b64url_decode(sig_b64)
        expected = hmac.new(_public_link_secret(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            return None
        return obj
    except Exception:
        return None


def _get_resource_settings(owner_sub: str, resource_type: str, resource_id: str) -> Dict[str, Any]:
    try:
        from app.core.tables import T

        item = T.account_views.get_item(
            Key={
                "pk": f"RESOURCE#{resource_type}#{resource_id}",
                "sk": "SETTINGS",
            }
        ).get("Item")
        if item:
            return item
    except Exception:
        pass
    return {"require_acceptance": True}


def grant_view(
    owner_sub: str,
    resource_type: str,
    resource_id: str,
    view_id: str,
    grantee_sub: str,
) -> Dict[str, Any]:
    from app.core.tables import T

    _require_not_self(owner_sub, grantee_sub)

    view = get_view(resource_type, resource_id, view_id)
    if not view:
        raise HTTPException(status_code=404, detail="View not found")

    _assert_owns_resource(owner_sub, resource_type, resource_id)

    # Check for duplicate active/pending grant
    existing = T.account_views.get_item(
        Key={
            "pk": f"RESOURCE#{resource_type}#{resource_id}",
            "sk": f"VIEWGRANT#{grantee_sub}#{view_id}",
        }
    ).get("Item")
    if existing and existing.get("status") != "revoked":
        raise HTTPException(status_code=409, detail="Grant already exists")

    resource_settings = _get_resource_settings(owner_sub, resource_type, resource_id)
    require_acceptance = resource_settings.get("require_acceptance", True)
    ts = now_ts()
    grant_id = uuid.uuid4().hex

    if require_acceptance:
        status = "pending"
        accepted_at = 0
        gsi2sk = 0
    else:
        status = "active"
        accepted_at = ts
        gsi2sk = ts

    item: Dict[str, Any] = {
        "pk": f"RESOURCE#{resource_type}#{resource_id}",
        "sk": f"VIEWGRANT#{grantee_sub}#{view_id}",
        "grant_id": grant_id,
        "view_id": view_id,
        "grantee_sub": grantee_sub,
        "owner_sub": owner_sub,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "status": status,
        "invited_at": ts,
        "accepted_at": accepted_at,
        "updated_at": ts,
        "GSI2PK": f"GRANTEE#{grantee_sub}",
        "GSI2SK": gsi2sk,
    }
    T.account_views.put_item(Item=item)

    try:
        audit_event(
            "account_view.granted",
            owner_sub,
            resource_type=resource_type,
            resource_id=resource_id,
            view_id=view_id,
            grantee_sub=grantee_sub,
        )
    except Exception as exc:
        logger.warning("account_views: audit_event failed: %s", exc)

    _write_audit(
        resource_type, resource_id, owner_sub, "view_granted", view_id,
        {"grantee_sub": grantee_sub},
    )
    return item


def respond_to_view_grant(
    grantee_sub: str,
    resource_type: str,
    resource_id: str,
    view_id: str,
    accept: bool,
) -> Optional[Dict[str, Any]]:
    from app.core.tables import T

    pk = f"RESOURCE#{resource_type}#{resource_id}"
    sk = f"VIEWGRANT#{grantee_sub}#{view_id}"
    item = T.account_views.get_item(Key={"pk": pk, "sk": sk}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Grant not found")
    if item.get("status") != "pending":
        raise HTTPException(status_code=400, detail="Grant is not pending")

    if accept:
        ts = now_ts()
        T.account_views.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET #st = :st, accepted_at = :aa, GSI2SK = :gsi2sk, updated_at = :ua",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "active",
                ":aa": ts,
                ":gsi2sk": ts,
                ":ua": ts,
            },
        )
        event = "account_view.accepted"
        updated = T.account_views.get_item(Key={"pk": pk, "sk": sk}).get("Item")
    else:
        T.account_views.delete_item(Key={"pk": pk, "sk": sk})
        event = "account_view.declined"
        updated = None

    try:
        audit_event(event, grantee_sub,
                    resource_type=resource_type, resource_id=resource_id, view_id=view_id)
    except Exception as exc:
        logger.warning("account_views: audit_event failed: %s", exc)

    return updated


def revoke_view_grant(
    owner_sub: str,
    resource_type: str,
    resource_id: str,
    view_id: str,
    grantee_sub: str,
) -> None:
    from app.core.tables import T

    pk = f"RESOURCE#{resource_type}#{resource_id}"
    sk = f"VIEWGRANT#{grantee_sub}#{view_id}"
    item = T.account_views.get_item(Key={"pk": pk, "sk": sk}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Grant not found")

    T.account_views.delete_item(Key={"pk": pk, "sk": sk})

    try:
        audit_event(
            "account_view.revoked",
            owner_sub,
            resource_type=resource_type,
            resource_id=resource_id,
            view_id=view_id,
            grantee_sub=grantee_sub,
        )
    except Exception as exc:
        logger.warning("account_views: audit_event failed: %s", exc)

    _write_audit(
        resource_type, resource_id, owner_sub, "view_revoked", view_id,
        {"grantee_sub": grantee_sub},
    )


def list_grants_for_resource(
    resource_type: str,
    resource_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    from app.core.tables import T

    lek = decode_cursor(cursor) if cursor else None
    results: List[Dict[str, Any]] = []
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(
                f"RESOURCE#{resource_type}#{resource_id}"
            ) & Key("sk").begins_with("VIEWGRANT#"),
            "Limit": limit,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.account_views.query(**kwargs)
        results.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek or len(results) >= limit:
            break
    next_cursor = encode_cursor(lek) if lek else None
    return {"grants": results[:limit], "next_cursor": next_cursor}


def list_views_shared_with_me(
    grantee_sub: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    from app.core.tables import T

    lek = decode_cursor(cursor) if cursor else None
    results: List[Dict[str, Any]] = []
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "by-grantee",
            "KeyConditionExpression": Key("GSI2PK").eq(f"GRANTEE#{grantee_sub}"),
            "FilterExpression": Attr("status").eq("active"),
            "Limit": limit,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.account_views.query(**kwargs)
        results.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek or len(results) >= limit:
            break
    next_cursor = encode_cursor(lek) if lek else None
    return {"grants": results[:limit], "next_cursor": next_cursor}


def resolve_active_grant(
    grantee_sub: str,
    resource_type: str,
    resource_id: str,
    view_id: str,
) -> Optional[Dict[str, Any]]:
    from app.core.tables import T

    item = T.account_views.get_item(
        Key={
            "pk": f"RESOURCE#{resource_type}#{resource_id}",
            "sk": f"VIEWGRANT#{grantee_sub}#{view_id}",
        }
    ).get("Item")
    if item and item.get("status") == "active":
        return item
    return None


def create_public_view_link(
    owner_sub: str,
    resource_type: str,
    resource_id: str,
    view_id: str,
    *,
    ttl_days: Optional[int] = None,
) -> Dict[str, Any]:

    _assert_owns_resource(owner_sub, resource_type, resource_id)
    view = get_view(resource_type, resource_id, view_id)
    if not view:
        raise HTTPException(status_code=404, detail="View not found")
    if view.get("preset") != "public" and not view.get("is_public"):
        raise HTTPException(status_code=400, detail="View is not public")

    resolved_ttl = ttl_days or int(getattr(S, "account_view_public_link_ttl_days", 7))
    ts = now_ts()
    jti = uuid.uuid4().hex
    expires_at = ts + resolved_ttl * 86400

    payload = {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "view_id": view_id,
        "owner_sub": owner_sub,
        "jti": jti,
        "exp": expires_at,
        "iat": ts,
        "ver": 1,
        "view_name": view.get("name", ""),
        "preset": view.get("preset"),
        "metadata_visibility": view.get("metadata_visibility", ""),
    }
    token = _sign_public_link_token(payload)
    base = getattr(S, "public_base_url", "").rstrip("/")
    url = f"{base}/ui/views/public/{token}"

    try:
        audit_event(
            "account_view.public_link_created",
            owner_sub,
            view_id=view_id,
            expires_at=expires_at,
        )
    except Exception as exc:
        logger.warning("account_views: audit_event failed: %s", exc)

    return {"url": url, "token": token, "expires_at": expires_at}


def resolve_public_view(token: str) -> Dict[str, Any]:
    from app.core.tables import T

    payload = _verify_public_link_token(token)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid public view token")

    if int(payload.get("exp", 0)) < now_ts():
        raise HTTPException(status_code=400, detail="Public view token expired")

    jti = payload.get("jti", "")
    revoked = T.account_views.get_item(
        Key={"pk": f"PUBLIC_REVOKED#{jti}", "sk": "META"}
    ).get("Item")
    if revoked:
        raise HTTPException(status_code=403, detail="Public view token has been revoked")

    resource_type = payload.get("resource_type", "")
    resource_id = payload.get("resource_id", "")
    view_id = payload.get("view_id", "")
    view = get_view(resource_type, resource_id, view_id)
    if not view:
        raise HTTPException(status_code=404, detail="View not found")
    if view.get("preset") != "public" and not view.get("is_public"):
        raise HTTPException(status_code=403, detail="View is no longer public")

    return {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "view_id": view_id,
        "owner_sub": payload.get("owner_sub", ""),
        "grants": view.get("grants", {}),
        "exp": payload.get("exp"),
        "view_name": view.get("name", ""),
        "preset": view.get("preset"),
        "metadata_visibility": view.get("metadata_visibility", ""),
    }


def revoke_public_link(owner_sub: str, token: str) -> None:
    from app.core.tables import T

    payload = _verify_public_link_token(token)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid public view token")

    if payload.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="Not the link owner")

    jti = payload.get("jti", "")
    view_id = payload.get("view_id", "")
    try:
        T.account_views.put_item(
            Item={
                "pk": f"PUBLIC_REVOKED#{jti}",
                "sk": "META",
                "jti": jti,
                "view_id": view_id,
                "resource_type": payload.get("resource_type", ""),
                "resource_id": payload.get("resource_id", ""),
                "revoked_at": now_ts(),
                "revoked_by_sub": owner_sub,
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
    except Exception:
        # Already revoked — idempotent, no error
        pass

    try:
        audit_event(
            "account_view.public_link_revoked",
            owner_sub,
            view_id=view_id,
        )
    except Exception as exc:
        logger.warning("account_views: audit_event failed: %s", exc)


# ---------------------------------------------------------------------------
# VEW-003 — Field-level projection
# ---------------------------------------------------------------------------


def _assemble_resource(resource_type: str, resource_id: str) -> Dict[str, Any]:
    """Dispatch to the appropriate assembler for a given resource_type."""
    if resource_type == "wallet":
        return _assemble_wallet_resource(resource_id)
    elif resource_type == "ledger_account":
        return _assemble_ledger_resource(resource_id)
    elif resource_type == "payout_destination":
        # For payout_destination, resource_id is the payout_id; owner_sub unknown here
        return _assemble_payout_destination_resource("", resource_id)
    raise HTTPException(status_code=400, detail="Unknown resource_type")


def _assemble_wallet_resource(owner_sub: str) -> Dict[str, Any]:
    try:
        from app.services.billing_shared import get_wallet_balance, user_pk
        from app.core.tables import T

        pk = user_pk(owner_sub)
        wallet = get_wallet_balance(T.billing, pk)
        wallet["resource_type"] = "wallet"
        wallet["resource_id"] = owner_sub
        wallet["label"] = ""
        wallet["available_balance_cents"] = wallet.get("wallet_balance_cents", 0)
        return wallet
    except ImportError:
        return {"resource_type": "wallet", "resource_id": owner_sub}


def _assemble_ledger_resource(owner_sub: str, *, limit: int = 50) -> Dict[str, Any]:
    try:
        from app.core.tables import T
        from boto3.dynamodb.conditions import Key as DKey

        resp = T.billing.query(
            KeyConditionExpression=DKey("pk").eq(f"USER#{owner_sub}") & DKey("sk").begins_with("LEDGER#"),
            Limit=limit,
            ScanIndexForward=False,
        )
        rows = resp.get("Items", [])
        total = sum(int(r.get("amount_cents", 0)) for r in rows if r.get("state") == "settled")
        tx_list = [
            {
                "entry_id": r.get("entry_id", ""),
                "ts": r.get("ts"),
                "amount_cents": r.get("amount_cents"),
                "state": r.get("state"),
                "reason": r.get("reason", ""),
                "counterparty": r.get("counterparty"),
                "counterparty_name": r.get("counterparty_name"),
                "description": r.get("description"),
            }
            for r in rows
        ]
        return {
            "resource_type": "ledger_account",
            "resource_id": owner_sub,
            "balance_summary": {"total_settled_cents": total, "currency": "usd"},
            "transaction_list": tx_list,
        }
    except ImportError:
        return {"resource_type": "ledger_account", "resource_id": owner_sub}


def _assemble_payout_destination_resource(owner_sub: str, resource_id: str) -> Dict[str, Any]:
    try:
        from app.core.tables import T

        item = T.creator_payouts.get_item(Key={"payout_id": resource_id}).get("Item")
        if not item:
            raise HTTPException(status_code=404, detail="Payout destination not found")
        return {
            "resource_type": "payout_destination",
            "resource_id": resource_id,
            "payout_id": item.get("payout_id", resource_id),
            "user_id": item.get("user_id", ""),
            "method": item.get("method"),
            "method_id": item.get("method_id"),
            "status": item.get("status"),
            "amount_cents": item.get("amount_cents"),
            "created_at": item.get("created_at"),
            "updated_at": item.get("updated_at"),
            "notes": item.get("notes"),
            "reject_reason": item.get("reject_reason"),
            "approved_by": item.get("approved_by"),
            "completed_at": item.get("completed_at"),
        }
    except HTTPException:
        raise
    except ImportError:
        return {"resource_type": "payout_destination", "resource_id": resource_id}


def project_resource(
    resource: Dict[str, Any],
    grants: Dict[str, bool],
    resource_type: str,
    *,
    metadata_visibility: str = "",
) -> Dict[str, Any]:
    """Apply field-level grant filtering to a resource dict (pure function, no I/O)."""
    field_map = FIELD_TO_GRANT.get(resource_type)
    if not field_map:
        return {}

    result: Dict[str, Any] = {}

    # Always include envelope-identity fields if present
    for ifield in _IDENTITY_FIELDS:
        if ifield in resource:
            result[ifield] = resource[ifield]

    # Project fields by grant
    for field_name, grant_key in field_map.items():
        if grants.get(grant_key) and field_name in resource:
            result[field_name] = resource[field_name]

    # Apply counterparty_blur if needed
    if metadata_visibility == "counterparty_blur":
        if "counterparty" in result:
            result["counterparty"] = "••••"
        if "counterparty_name" in result:
            result["counterparty_name"] = "••••"

    # Recurse into transaction_list rows
    if "transaction_list" in result and isinstance(result["transaction_list"], list):
        projected_rows = []
        for row in result["transaction_list"]:
            prow: Dict[str, Any] = {}
            for rf, rg in TRANSACTION_ROW_FIELD_TO_GRANT.items():
                if grants.get(rg) and rf in row:
                    prow[rf] = row[rf]
            if metadata_visibility == "counterparty_blur":
                if "counterparty" in prow:
                    prow["counterparty"] = "••••"
                if "counterparty_name" in prow:
                    prow["counterparty_name"] = "••••"
            projected_rows.append(prow)
        result["transaction_list"] = projected_rows

    return result

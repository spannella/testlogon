"""Content license issuance -- per-user and blanket licenses (LICENSE-002)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.services.alerts import write_alert
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

VALID_LICENSE_MODES = {"per_user", "blanket", "syndicate_auto"}
VALID_CONTENT_TYPES = {"video", "music", "image", "post", "broadcast", "clip"}
MAX_PROFIT_SHARE_PCT = 100
MAX_REVENUE_SHARE_PCT = 100


def issue_license(
    *,
    licensor_sub: str,
    content_id: str,
    content_type: str,
    license_mode: str,
    licensee_id: Optional[str] = None,
    profit_share_pct: int = 0,
    fixed_cost_cents: int = 0,
    revenue_share_pct: int = 0,
    currency: str = "usd",
    title: str = "",
    thumbnail_url: str = "",
    expires_at: Optional[int] = None,
    syndicate_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Issue a new license for content owned by the licensor."""
    if license_mode not in VALID_LICENSE_MODES:
        raise ValueError(f"Invalid license_mode: {license_mode}")
    if content_type not in VALID_CONTENT_TYPES:
        raise ValueError(f"Invalid content_type: {content_type}")
    if license_mode in ("per_user", "syndicate_auto") and not licensee_id:
        raise ValueError("licensee_id required for this license mode")
    if license_mode == "blanket" and licensee_id:
        raise ValueError("licensee_id must be null for blanket license")
    if not (0 <= profit_share_pct <= MAX_PROFIT_SHARE_PCT):
        raise ValueError("profit_share_pct must be 0-100")
    if not (0 <= revenue_share_pct <= MAX_REVENUE_SHARE_PCT):
        raise ValueError("revenue_share_pct must be 0-100")
    if fixed_cost_cents < 0:
        raise ValueError("fixed_cost_cents must be >= 0")
    if licensee_id and licensee_id == licensor_sub:
        raise ValueError("Cannot license content to yourself")

    issued_license_id = f"il_{uuid4().hex}"
    ts = now_ts()
    profile = get_profile(licensor_sub) or {}

    # Primary record under content PK
    item: Dict[str, Any] = {
        "pk": f"CONTENT#{content_id}",
        "sk": f"LICENSE#{issued_license_id}",
        "issued_license_id": issued_license_id,
        "content_id": content_id,
        "content_type": content_type,
        "licensor_id": licensor_sub,
        "license_mode": license_mode,
        "status": "active",
        "profit_share_pct": profit_share_pct,
        "fixed_cost_cents": fixed_cost_cents,
        "revenue_share_pct": revenue_share_pct,
        "currency": currency,
        "title": title,
        "thumbnail_url": thumbnail_url,
        "created_at": ts,
        "updated_at": ts,
        "GSI2PK": f"CONTENT_STATUS#{content_id}#active",
        "GSI2SK": ts,
    }
    if licensee_id:
        item["licensee_id"] = licensee_id
    if expires_at is not None:
        item["expires_at"] = expires_at
    if syndicate_id:
        item["syndicate_id"] = syndicate_id

    T.issued_licenses.put_item(Item=item)

    # Licensor index
    licensor_index: Dict[str, Any] = {
        "pk": f"LICENSOR#{licensor_sub}",
        "sk": f"ISSUED#{issued_license_id}",
        "issued_license_id": issued_license_id,
        "content_id": content_id,
        "license_mode": license_mode,
        "status": "active",
        "created_at": ts,
    }
    if licensee_id:
        licensor_index["licensee_id"] = licensee_id
    if syndicate_id:
        licensor_index["syndicate_id"] = syndicate_id
    T.issued_licenses.put_item(Item=licensor_index)

    # Per-user / syndicate_auto: write licensee index + notify
    if license_mode in ("per_user", "syndicate_auto") and licensee_id:
        _write_licensee_index(
            issued_license_id, licensee_id, content_id,
            content_type, licensor_sub, profit_share_pct,
            fixed_cost_cents, revenue_share_pct,
            license_mode=license_mode, syndicate_id=syndicate_id,
        )
        try:
            write_alert(
                licensee_id,
                event="license_granted",
                outcome="info",
                title="License Granted",
                details={
                    "licensor_id": licensor_sub,
                    "licensor_name": profile.get("display_name", licensor_sub),
                    "content_id": content_id,
                    "issued_license_id": issued_license_id,
                },
            )
        except Exception:
            logger.warning("Failed to write license grant alert", exc_info=True)

    # Blanket: write library index
    if license_mode == "blanket":
        _write_library_index(
            issued_license_id, content_id, content_type,
            licensor_sub, profile, title, thumbnail_url,
            profit_share_pct, fixed_cost_cents, ts,
        )

    # Add display name to returned item
    item["licensor_display_name"] = profile.get("display_name", "")
    return item


def update_license_terms(
    *,
    licensor_sub: str,
    issued_license_id: str,
    content_id: str,
    updates: Dict[str, Any],
) -> Dict[str, Any]:
    """Update terms on an issued license. Only licensor can update."""
    resp = T.issued_licenses.get_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"LICENSE#{issued_license_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise LookupError("License not found")
    if item.get("licensor_id") != licensor_sub:
        raise PermissionError("Only the licensor can update this license")
    if item.get("status") != "active":
        raise ValueError("Can only update active licenses")

    ts = now_ts()
    allowed = {"profit_share_pct", "fixed_cost_cents", "revenue_share_pct", "expires_at"}
    expr_parts = ["#updated_at = :updated_at"]
    names: Dict[str, str] = {"#updated_at": "updated_at"}
    values: Dict[str, Any] = {":updated_at": ts}

    for k, v in updates.items():
        if k in allowed and v is not None:
            safe_name = f"#{k}"
            names[safe_name] = k
            values[f":{k}"] = v
            expr_parts.append(f"{safe_name} = :{k}")

    T.issued_licenses.update_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"LICENSE#{issued_license_id}"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )

    # If blanket, update library index too
    if item.get("license_mode") == "blanket":
        lib_update_parts = []
        lib_names: Dict[str, str] = {}
        lib_values: Dict[str, Any] = {}
        for k in ("profit_share_pct", "fixed_cost_cents"):
            if k in updates and updates[k] is not None:
                lib_names[f"#{k}"] = k
                lib_values[f":{k}"] = updates[k]
                lib_update_parts.append(f"#{k} = :{k}")
        if lib_update_parts:
            try:
                T.issued_licenses.update_item(
                    Key={"pk": "LIBRARY", "sk": f"CONTENT#{content_id}#{issued_license_id}"},
                    UpdateExpression="SET " + ", ".join(lib_update_parts),
                    ExpressionAttributeNames=lib_names,
                    ExpressionAttributeValues=lib_values,
                )
            except Exception:
                logger.warning("Failed to update library index", exc_info=True)

    # Re-fetch updated item
    updated = T.issued_licenses.get_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"LICENSE#{issued_license_id}"}
    ).get("Item", {})
    profile = get_profile(licensor_sub) or {}
    updated["licensor_display_name"] = profile.get("display_name", "")
    return updated


def revoke_license(
    *,
    licensor_sub: str,
    issued_license_id: str,
    content_id: str,
    reason: str = "",
) -> Dict[str, Any]:
    """Revoke an issued license. Notifies licensee, flags content for review."""
    resp = T.issued_licenses.get_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"LICENSE#{issued_license_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise LookupError("License not found")
    if item.get("licensor_id") != licensor_sub:
        raise PermissionError("Only the licensor can revoke this license")
    if item.get("status") == "revoked":
        raise ValueError("License is already revoked")

    ts = now_ts()

    # Update primary record
    T.issued_licenses.update_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"LICENSE#{issued_license_id}"},
        UpdateExpression="SET #status = :status, #updated_at = :ts, #revoke_reason = :reason, #GSI2PK = :gsi2pk",
        ExpressionAttributeNames={
            "#status": "status",
            "#updated_at": "updated_at",
            "#revoke_reason": "revoke_reason",
            "#GSI2PK": "GSI2PK",
        },
        ExpressionAttributeValues={
            ":status": "revoked",
            ":ts": ts,
            ":reason": reason,
            ":gsi2pk": f"CONTENT_STATUS#{content_id}#revoked",
        },
    )

    # Update licensor index
    try:
        T.issued_licenses.update_item(
            Key={"pk": f"LICENSOR#{licensor_sub}", "sk": f"ISSUED#{issued_license_id}"},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":status": "revoked"},
        )
    except Exception:
        logger.warning("Failed to update licensor index on revoke", exc_info=True)

    licensee_id = item.get("licensee_id")

    # Per-user / syndicate_auto: update licensee index + notify
    if item.get("license_mode") in ("per_user", "syndicate_auto") and licensee_id:
        try:
            T.issued_licenses.update_item(
                Key={"pk": f"LICENSEE#{licensee_id}", "sk": f"HELD#{issued_license_id}"},
                UpdateExpression="SET #status = :status",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":status": "revoked"},
            )
        except Exception:
            logger.warning("Failed to update licensee index on revoke", exc_info=True)
        try:
            profile = get_profile(licensor_sub) or {}
            write_alert(
                licensee_id,
                event="license_revoked",
                outcome="warning",
                title="License Revoked",
                details={
                    "licensor_id": licensor_sub,
                    "licensor_name": profile.get("display_name", licensor_sub),
                    "content_id": content_id,
                    "issued_license_id": issued_license_id,
                    "reason": reason,
                },
            )
        except Exception:
            logger.warning("Failed to write license revoke alert", exc_info=True)

    # Blanket: remove from library index
    if item.get("license_mode") == "blanket":
        _remove_library_index(content_id, issued_license_id)

    item["status"] = "revoked"
    item["updated_at"] = ts
    item["revoke_reason"] = reason
    profile = get_profile(licensor_sub) or {}
    item["licensor_display_name"] = profile.get("display_name", "")
    return item


def get_issued_license(
    *,
    content_id: str,
    issued_license_id: str,
) -> Optional[Dict[str, Any]]:
    """Get a single issued license."""
    resp = T.issued_licenses.get_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"LICENSE#{issued_license_id}"}
    )
    item = resp.get("Item")
    if item:
        profile = get_profile(item.get("licensor_id", "")) or {}
        item["licensor_display_name"] = profile.get("display_name", "")
    return item


def list_licenses_issued_by(
    *,
    licensor_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List all licenses issued by a creator."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"LICENSOR#{licensor_sub}")
                                 & Key("sk").begins_with("ISSUED#"),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.issued_licenses.query(**kwargs)
    items = resp.get("Items", [])

    if status_filter:
        items = [i for i in items if i.get("status") == status_filter]

    result: Dict[str, Any] = {"items": items}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def list_licenses_held_by(
    *,
    licensee_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List all licenses held by a creator (per-user licenses granted to them)."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"LICENSEE#{licensee_sub}")
                                 & Key("sk").begins_with("HELD#"),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.issued_licenses.query(**kwargs)
    items = resp.get("Items", [])

    if status_filter:
        items = [i for i in items if i.get("status") == status_filter]

    # Enrich with display names
    for item in items:
        licensor_id = item.get("licensor_id", "")
        if licensor_id:
            profile = get_profile(licensor_id) or {}
            item["licensor_display_name"] = profile.get("display_name", "")

    result: Dict[str, Any] = {"items": items}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def list_licenses_for_content(
    *,
    content_id: str,
    status_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List all issued licenses for a content item."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"CONTENT#{content_id}")
                                 & Key("sk").begins_with("LICENSE#"),
    }
    resp = T.issued_licenses.query(**kwargs)
    items = resp.get("Items", [])

    if status_filter:
        items = [i for i in items if i.get("status") == status_filter]

    return items


def browse_library(
    *,
    content_type: Optional[str] = None,
    licensor_id: Optional[str] = None,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Browse the Licensed Content Library (blanket-licensed content)."""
    kwargs: Dict[str, Any] = {"Limit": limit, "ScanIndexForward": False}
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    if content_type:
        kwargs["KeyConditionExpression"] = Key("GSI1PK").eq(f"LIBRARY_TYPE#{content_type}")
        kwargs["IndexName"] = "GSI1"
    elif licensor_id:
        kwargs["KeyConditionExpression"] = Key("GSI3PK").eq(f"LICENSOR_LIBRARY#{licensor_id}")
        kwargs["IndexName"] = "GSI3"
    else:
        kwargs["KeyConditionExpression"] = Key("pk").eq("LIBRARY") & Key("sk").begins_with("CONTENT#")

    resp = T.issued_licenses.query(**kwargs)
    items = resp.get("Items", [])

    result: Dict[str, Any] = {"items": items}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def check_license_for_use(
    *,
    content_id: str,
    user_id: str,
) -> Optional[Dict[str, Any]]:
    """Check if a user has a valid license to use a piece of content.
    Returns the active license (per-user for this user, or blanket) or None."""
    items = list_licenses_for_content(content_id=content_id, status_filter="active")

    # First check for per-user license
    for lic in items:
        if lic.get("license_mode") == "per_user" and lic.get("licensee_id") == user_id:
            return lic

    # Then check for blanket license
    for lic in items:
        if lic.get("license_mode") == "blanket":
            return lic

    return None


# --- Internal helpers ---

def _write_licensee_index(
    issued_license_id: str,
    licensee_id: str,
    content_id: str,
    content_type: str,
    licensor_id: str,
    psp: int,
    fcc: int,
    rsp: int,
    *,
    license_mode: str = "per_user",
    syndicate_id: Optional[str] = None,
) -> None:
    """Write LICENSEE#{id}/HELD#{license_id} index entry."""
    item = {
        "pk": f"LICENSEE#{licensee_id}",
        "sk": f"HELD#{issued_license_id}",
        "issued_license_id": issued_license_id,
        "content_id": content_id,
        "content_type": content_type,
        "licensor_id": licensor_id,
        "license_mode": license_mode,
        "status": "active",
        "terms_snapshot": {
            "profit_share_pct": psp,
            "fixed_cost_cents": fcc,
            "revenue_share_pct": rsp,
        },
    }
    if syndicate_id:
        item["syndicate_id"] = syndicate_id
    T.issued_licenses.put_item(Item=item)


def _write_library_index(
    issued_license_id: str,
    content_id: str,
    content_type: str,
    licensor_id: str,
    profile: Dict[str, Any],
    title: str,
    thumbnail_url: str,
    psp: int,
    fcc: int,
    ts: int,
) -> None:
    """Write LIBRARY/CONTENT#{content_id}#{license_id} entry + GSI projections."""
    item = {
        "pk": "LIBRARY",
        "sk": f"CONTENT#{content_id}#{issued_license_id}",
        "content_id": content_id,
        "content_type": content_type,
        "licensor_id": licensor_id,
        "licensor_display_name": profile.get("display_name", ""),
        "title": title,
        "thumbnail_url": thumbnail_url,
        "profit_share_pct": psp,
        "fixed_cost_cents": fcc,
        "created_at": ts,
        "GSI1PK": f"LIBRARY_TYPE#{content_type}",
        "GSI1SK": ts,
        "GSI3PK": f"LICENSOR_LIBRARY#{licensor_id}",
        "GSI3SK": ts,
    }
    T.issued_licenses.put_item(Item=item)


def _remove_library_index(content_id: str, issued_license_id: str) -> None:
    """Remove from library when blanket license is revoked."""
    try:
        T.issued_licenses.delete_item(
            Key={"pk": "LIBRARY", "sk": f"CONTENT#{content_id}#{issued_license_id}"}
        )
    except Exception:
        logger.warning("Failed to remove library index entry", exc_info=True)

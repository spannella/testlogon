"""License agreement template upload, metadata & content linking (LICENSE-001).

This is the foundational agreement-template management layer. Creators upload
licensing agreement documents (PDF / images) with structured metadata, version
them, activate/archive them, and link them to content items. Issued licenses
(LICENSE-002) and license requests (LICENSE-004) may reference an agreement id
via the read-only reverse-lookup record written here.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.aws_clients import s3_client
from app.core.cursor import encode_cursor, decode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

_s3 = s3_client()

LICENSE_TYPES = {
    "royalty_free",
    "creative_commons",
    "commercial",
    "custom",
    "editorial",
    "public_domain",
}
CONTENT_TYPES = {"video", "post", "broadcast"}
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/webp",
}
# Magic byte signatures keyed by mime type (first bytes of the file).
_MAGIC_BYTES = {
    "application/pdf": [b"%PDF"],
    "image/png": [b"\x89PNG"],
    "image/jpeg": [b"\xff\xd8\xff"],
    "image/webp": [b"RIFF"],
}
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
EXPIRY_WARNING_DAYS = 30
EXPIRY_WARNING_SECONDS = EXPIRY_WARNING_DAYS * 86400

# Statuses considered "linkable" (content can be attached).
LINKABLE_STATUSES = {"active", "pending_review"}

# Internal DDB attrs stripped from API responses.
_INTERNAL_KEYS = {
    "pk",
    "sk",
    "GSI1PK",
    "GSI1SK",
    "GSI2PK",
    "GSI2SK",
    "GSI3PK",
    "GSI3SK",
}


def _bucket() -> str:
    """Resolve the S3 bucket used for agreement documents."""
    return S.license_agreements_bucket or S.filemgr_bucket or "filemgr"


def _sanitize_filename(name: str) -> str:
    """Strip path separators and cap length."""
    base = (name or "agreement").replace("\\", "/").split("/")[-1].strip()
    base = base or "agreement"
    return base[:200]


def _validate_magic_bytes(mime_type: str, head: bytes) -> bool:
    """Confirm the first bytes match the declared mime type."""
    sigs = _MAGIC_BYTES.get(mime_type)
    if not sigs:
        return False
    return any(head.startswith(sig) for sig in sigs)


def _expiry_month_pk(expires_at: int) -> str:
    dt = datetime.fromtimestamp(int(expires_at), tz=timezone.utc)
    return f"EXPIRY_MONTH#{dt.strftime('%Y-%m')}"


def _agreement_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Strip internal keys + coerce Decimals for an agreement record."""
    out = {k: v for k, v in item.items() if k not in _INTERNAL_KEYS}
    for k in ("file_size", "version", "created_at", "updated_at", "expires_at"):
        if out.get(k) is not None:
            try:
                out[k] = int(out[k])
            except (TypeError, ValueError):
                pass
    return out


# ---------------------------------------------------------------------------
# File upload
# ---------------------------------------------------------------------------

def upload_agreement_file(
    *,
    creator_sub: str,
    license_id: str,
    file_name: str,
    file_bytes: bytes,
    mime_type: str,
) -> Dict[str, Any]:
    """Validate + store an agreement document in S3. Returns file metadata."""
    if mime_type not in ALLOWED_MIME_TYPES:
        raise ValueError(f"Invalid mime_type: {mime_type}")
    size = len(file_bytes)
    if size == 0:
        raise ValueError("Empty file")
    if size > MAX_FILE_SIZE:
        raise ValueError("File too large")
    if not _validate_magic_bytes(mime_type, file_bytes[:8]):
        raise ValueError("File contents do not match declared file type")

    safe_name = _sanitize_filename(file_name)
    file_key = f"licenses/{creator_sub}/{license_id}/{safe_name}"
    _s3.put_object(
        Bucket=_bucket(),
        Key=file_key,
        Body=file_bytes,
        ContentType=mime_type,
    )
    return {
        "file_key": file_key,
        "file_name": safe_name,
        "file_size": size,
        "mime_type": mime_type,
    }


def get_download_url(
    *,
    creator_sub: str,
    license_id: str,
    is_admin: bool = False,
) -> str:
    """Return a presigned (or dev /mock/s3) download URL for the agreement file."""
    agreement = get_agreement(creator_sub=creator_sub, license_id=license_id)
    if not agreement and is_admin:
        # Admin may download via reverse lookup → owner.
        reverse = _get_reverse_lookup(license_id)
        owner = reverse.get("creator_id", "")
        agreement = get_agreement(creator_sub=owner, license_id=license_id)
    if not agreement:
        raise LookupError("Agreement not found")
    file_key = agreement.get("file_key")
    if not file_key:
        raise LookupError("Agreement has no file")
    bucket = _bucket()
    if S.dev_mode:
        return f"{S.public_base_url}/mock/s3/{bucket}/{file_key}"
    return _s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": bucket, "Key": file_key},
        ExpiresIn=300,
    )


# ---------------------------------------------------------------------------
# Agreement CRUD
# ---------------------------------------------------------------------------

def create_agreement(
    *,
    creator_sub: str,
    title: str,
    licensor_name: str,
    license_type: str,
    file_key: str,
    file_name: str,
    file_size: int,
    mime_type: str,
    territory: str = "worldwide",
    expires_at: Optional[int] = None,
    notes: str = "",
) -> Dict[str, Any]:
    """Create a new license agreement record after file upload."""
    if license_type not in LICENSE_TYPES:
        raise ValueError(f"Invalid license_type: {license_type}")
    if expires_at is not None and expires_at <= now_ts():
        raise ValueError("expires_at must be in the future")

    license_id = f"lagr_{uuid4().hex}"
    ts = now_ts()
    status = "pending_review"
    version = 1

    item: Dict[str, Any] = {
        "pk": f"CREATOR#{creator_sub}",
        "sk": f"LICENSE#{license_id}",
        "license_id": license_id,
        "creator_id": creator_sub,
        "title": title.strip(),
        "licensor_name": licensor_name.strip(),
        "license_type": license_type,
        "file_key": file_key,
        "file_name": file_name,
        "file_size": file_size,
        "mime_type": mime_type,
        "status": status,
        "version": version,
        "territory": (territory or "worldwide").strip(),
        "expires_at": expires_at,
        "notes": notes or "",
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": f"STATUS#{status}",
        "GSI1SK": expires_at or 0,
    }
    if expires_at:
        item["GSI3PK"] = _expiry_month_pk(expires_at)
        item["GSI3SK"] = expires_at

    T.license_agreements.put_item(Item=item)
    _write_reverse_lookup(item)
    _enqueue_review(license_id, creator_sub, title, licensor_name, license_type, ts)
    return _agreement_to_out(item)


def get_agreement(
    *,
    creator_sub: str,
    license_id: str,
) -> Optional[Dict[str, Any]]:
    """Get a single agreement owned by the creator (None if missing/deleted)."""
    resp = T.license_agreements.get_item(
        Key={"pk": f"CREATOR#{creator_sub}", "sk": f"LICENSE#{license_id}"}
    )
    item = resp.get("Item")
    if not item or item.get("status") == "deleted":
        return None
    return _agreement_to_out(item)


def list_agreements(
    *,
    creator_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List a creator's agreements, optionally filtered by status."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"CREATOR#{creator_sub}")
        & Key("sk").begins_with("LICENSE#"),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.license_agreements.query(**kwargs)
    items = [i for i in resp.get("Items", []) if i.get("status") != "deleted"]

    now = now_ts()
    out_items: List[Dict[str, Any]] = []
    for it in items:
        out = _agreement_to_out(it)
        out["content_count"] = _count_linked_content(it.get("license_id", ""))
        # Derived UI status: expiring_soon.
        exp = out.get("expires_at")
        if (
            out.get("status") == "active"
            and exp
            and 0 < (int(exp) - now) <= EXPIRY_WARNING_SECONDS
        ):
            out["expiring_soon"] = True
        else:
            out["expiring_soon"] = False
        if status_filter:
            if status_filter == "expiring_soon":
                if not out["expiring_soon"]:
                    continue
            elif out.get("status") != status_filter:
                continue
        out_items.append(out)

    result: Dict[str, Any] = {"items": out_items}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def update_agreement(
    *,
    creator_sub: str,
    license_id: str,
    updates: Dict[str, Any],
) -> Dict[str, Any]:
    """Update agreement metadata, bumping version. Validates ownership."""
    resp = T.license_agreements.get_item(
        Key={"pk": f"CREATOR#{creator_sub}", "sk": f"LICENSE#{license_id}"}
    )
    item = resp.get("Item")
    if not item or item.get("status") == "deleted":
        raise LookupError("Agreement not found")

    allowed = {"title", "licensor_name", "license_type", "territory", "expires_at", "notes"}
    ts = now_ts()
    new_version = int(item.get("version", 1)) + 1

    expr_parts = ["#updated_at = :updated_at", "#version = :version"]
    names: Dict[str, str] = {"#updated_at": "updated_at", "#version": "version"}
    values: Dict[str, Any] = {":updated_at": ts, ":version": new_version}

    new_expires = item.get("expires_at")
    for k, v in updates.items():
        if k not in allowed or v is None:
            continue
        if k == "license_type" and v not in LICENSE_TYPES:
            raise ValueError(f"Invalid license_type: {v}")
        if k == "expires_at":
            if v <= now_ts():
                raise ValueError("expires_at must be in the future")
            new_expires = v
        if isinstance(v, str):
            v = v.strip()
        names[f"#{k}"] = k
        values[f":{k}"] = v
        expr_parts.append(f"#{k} = :{k}")

    # Keep GSI1SK / GSI3* coherent with expires_at.
    if "expires_at" in updates and updates["expires_at"] is not None:
        names["#GSI1SK"] = "GSI1SK"
        values[":GSI1SK"] = new_expires
        expr_parts.append("#GSI1SK = :GSI1SK")
        names["#GSI3PK"] = "GSI3PK"
        values[":GSI3PK"] = _expiry_month_pk(new_expires)
        expr_parts.append("#GSI3PK = :GSI3PK")
        names["#GSI3SK"] = "GSI3SK"
        values[":GSI3SK"] = new_expires
        expr_parts.append("#GSI3SK = :GSI3SK")

    T.license_agreements.update_item(
        Key={"pk": f"CREATOR#{creator_sub}", "sk": f"LICENSE#{license_id}"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )

    # Keep reverse lookup title/expires_at in sync.
    rev_updates = {}
    if "title" in updates and updates["title"] is not None:
        rev_updates["title"] = updates["title"].strip()
    if "expires_at" in updates and updates["expires_at"] is not None:
        rev_updates["expires_at"] = new_expires
    if rev_updates:
        _patch_reverse_lookup(license_id, rev_updates)

    updated = T.license_agreements.get_item(
        Key={"pk": f"CREATOR#{creator_sub}", "sk": f"LICENSE#{license_id}"}
    ).get("Item", {})
    return _agreement_to_out(updated)


def set_status(
    *,
    creator_sub: str,
    license_id: str,
    new_status: str,
) -> Dict[str, Any]:
    """Creator-driven status change: activate or archive an agreement."""
    if new_status not in {"active", "archived"}:
        raise ValueError("status must be 'active' or 'archived'")
    resp = T.license_agreements.get_item(
        Key={"pk": f"CREATOR#{creator_sub}", "sk": f"LICENSE#{license_id}"}
    )
    item = resp.get("Item")
    if not item or item.get("status") == "deleted":
        raise LookupError("Agreement not found")

    ts = now_ts()
    T.license_agreements.update_item(
        Key={"pk": f"CREATOR#{creator_sub}", "sk": f"LICENSE#{license_id}"},
        UpdateExpression="SET #status = :status, #updated_at = :ts, #g1 = :g1",
        ExpressionAttributeNames={
            "#status": "status",
            "#updated_at": "updated_at",
            "#g1": "GSI1PK",
        },
        ExpressionAttributeValues={
            ":status": new_status,
            ":ts": ts,
            ":g1": f"STATUS#{new_status}",
        },
    )
    _patch_reverse_lookup(license_id, {"status": new_status})
    if new_status == "active":
        _dequeue_review(license_id, int(item.get("created_at", ts)))

    updated = T.license_agreements.get_item(
        Key={"pk": f"CREATOR#{creator_sub}", "sk": f"LICENSE#{license_id}"}
    ).get("Item", {})
    return _agreement_to_out(updated)


def delete_agreement(
    *,
    creator_sub: str,
    license_id: str,
) -> None:
    """Soft-delete an agreement and unlink all its content."""
    resp = T.license_agreements.get_item(
        Key={"pk": f"CREATOR#{creator_sub}", "sk": f"LICENSE#{license_id}"}
    )
    item = resp.get("Item")
    if not item or item.get("status") == "deleted":
        raise LookupError("Agreement not found")

    ts = now_ts()
    T.license_agreements.update_item(
        Key={"pk": f"CREATOR#{creator_sub}", "sk": f"LICENSE#{license_id}"},
        UpdateExpression="SET #status = :status, #updated_at = :ts, #g1 = :g1",
        ExpressionAttributeNames={
            "#status": "status",
            "#updated_at": "updated_at",
            "#g1": "GSI1PK",
        },
        ExpressionAttributeValues={
            ":status": "deleted",
            ":ts": ts,
            ":g1": "STATUS#deleted",
        },
    )
    _patch_reverse_lookup(license_id, {"status": "deleted"})
    _dequeue_review(license_id, int(item.get("created_at", ts)))

    # Unlink all content.
    for link in list_content_for_license(license_id=license_id):
        try:
            unlink_content(
                creator_sub=creator_sub,
                license_id=license_id,
                content_id=link.get("content_id", ""),
            )
        except Exception:
            logger.warning("Failed to unlink content on delete", exc_info=True)


# ---------------------------------------------------------------------------
# Content linking
# ---------------------------------------------------------------------------

def link_content(
    *,
    creator_sub: str,
    license_id: str,
    content_id: str,
    content_type: str,
) -> Dict[str, Any]:
    """Link a content item to an agreement."""
    if content_type not in CONTENT_TYPES:
        raise ValueError(f"Invalid content_type: {content_type}")
    agreement = get_agreement(creator_sub=creator_sub, license_id=license_id)
    if not agreement:
        raise LookupError("Agreement not found")
    if agreement.get("status") not in LINKABLE_STATUSES:
        raise ValueError(
            f"Cannot link content to agreement in status '{agreement.get('status')}'"
        )

    ts = now_ts()
    # Mapping under creator PK.
    T.license_agreements.put_item(Item={
        "pk": f"CREATOR#{creator_sub}",
        "sk": f"CONTENT#{content_id}#{license_id}",
        "content_id": content_id,
        "content_type": content_type,
        "license_id": license_id,
        "linked_at": ts,
        "GSI2PK": f"CONTENT#{content_id}",
        "GSI2SK": ts,
    })
    # Mapping under license PK (forward lookup).
    T.license_agreements.put_item(Item={
        "pk": f"LICENSE#{license_id}",
        "sk": f"CONTENT#{content_id}",
        "content_id": content_id,
        "content_type": content_type,
        "license_id": license_id,
        "linked_at": ts,
    })
    return {
        "content_id": content_id,
        "content_type": content_type,
        "license_id": license_id,
        "linked_at": ts,
    }


def unlink_content(
    *,
    creator_sub: str,
    license_id: str,
    content_id: str,
) -> None:
    """Remove a content-license link (both mapping records)."""
    T.license_agreements.delete_item(
        Key={"pk": f"CREATOR#{creator_sub}", "sk": f"CONTENT#{content_id}#{license_id}"}
    )
    T.license_agreements.delete_item(
        Key={"pk": f"LICENSE#{license_id}", "sk": f"CONTENT#{content_id}"}
    )


def list_content_for_license(*, license_id: str) -> List[Dict[str, Any]]:
    """List content items linked to an agreement."""
    resp = T.license_agreements.query(
        KeyConditionExpression=Key("pk").eq(f"LICENSE#{license_id}")
        & Key("sk").begins_with("CONTENT#")
    )
    out = []
    for it in resp.get("Items", []):
        out.append({
            "content_id": it.get("content_id", ""),
            "content_type": it.get("content_type", ""),
            "license_id": license_id,
            "linked_at": int(it.get("linked_at", 0) or 0),
        })
    return out


def list_licenses_for_content(*, content_id: str) -> List[Dict[str, Any]]:
    """List agreements linked to a content item (via GSI2)."""
    resp = T.license_agreements.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(f"CONTENT#{content_id}"),
        ScanIndexForward=False,
    )
    out = []
    for it in resp.get("Items", []):
        out.append({
            "content_id": content_id,
            "content_type": it.get("content_type", ""),
            "license_id": it.get("license_id", ""),
            "linked_at": int(it.get("linked_at", 0) or 0),
        })
    return out


def _count_linked_content(license_id: str) -> int:
    if not license_id:
        return 0
    try:
        resp = T.license_agreements.query(
            KeyConditionExpression=Key("pk").eq(f"LICENSE#{license_id}")
            & Key("sk").begins_with("CONTENT#"),
            Select="COUNT",
        )
        return int(resp.get("Count", 0))
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Admin review
# ---------------------------------------------------------------------------

def admin_list_review_queue(
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List agreements pending admin review."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq("ADMIN_REVIEW")
        & Key("sk").begins_with("PENDING#"),
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.license_agreements.query(**kwargs)
    items = []
    for it in resp.get("Items", []):
        creator_id = it.get("creator_id", "")
        display = ""
        if creator_id:
            profile = get_profile(creator_id) or {}
            display = profile.get("display_name") or ""
        items.append({
            "license_id": it.get("license_id", ""),
            "creator_id": creator_id,
            "creator_display_name": display,
            "title": it.get("title", ""),
            "licensor_name": it.get("licensor_name", ""),
            "license_type": it.get("license_type", ""),
            "submitted_at": int(it.get("submitted_at", 0) or 0),
        })
    result: Dict[str, Any] = {"items": items}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def admin_review_agreement(
    *,
    admin_sub: str,
    license_id: str,
    verified: bool,
    rejection_reason: str = "",
) -> Dict[str, Any]:
    """Admin verifies (→ active) or rejects (→ rejected) an agreement."""
    reverse = _get_reverse_lookup(license_id)
    creator_id = reverse.get("creator_id", "")
    if not creator_id:
        raise LookupError("Agreement owner not found")

    resp = T.license_agreements.get_item(
        Key={"pk": f"CREATOR#{creator_id}", "sk": f"LICENSE#{license_id}"}
    )
    item = resp.get("Item")
    if not item or item.get("status") == "deleted":
        raise LookupError("Agreement not found")

    ts = now_ts()
    new_status = "active" if verified else "rejected"
    expr = "SET #status = :status, #updated_at = :ts, #g1 = :g1, #rb = :rb"
    names = {
        "#status": "status",
        "#updated_at": "updated_at",
        "#g1": "GSI1PK",
        "#rb": "reviewed_by",
    }
    values = {
        ":status": new_status,
        ":ts": ts,
        ":g1": f"STATUS#{new_status}",
        ":rb": admin_sub,
    }
    if not verified and rejection_reason:
        expr += ", #rr = :rr"
        names["#rr"] = "rejection_reason"
        values[":rr"] = rejection_reason
    T.license_agreements.update_item(
        Key={"pk": f"CREATOR#{creator_id}", "sk": f"LICENSE#{license_id}"},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    _patch_reverse_lookup(license_id, {"status": new_status})
    _dequeue_review(license_id, int(item.get("created_at", ts)))

    title = item.get("title", "")
    try:
        if verified:
            write_alert(
                creator_id,
                event="license_verified",
                outcome="info",
                title="License Agreement Verified",
                details={"license_id": license_id, "title": title},
                action_url=f"/licenses?highlight={license_id}",
            )
        else:
            write_alert(
                creator_id,
                event="license_rejected",
                outcome="warning",
                title="License Agreement Rejected",
                details={
                    "license_id": license_id,
                    "title": title,
                    "reason": rejection_reason,
                },
                action_url=f"/licenses?highlight={license_id}",
            )
    except Exception:
        logger.warning("Failed to write review alert", exc_info=True)

    updated = T.license_agreements.get_item(
        Key={"pk": f"CREATOR#{creator_id}", "sk": f"LICENSE#{license_id}"}
    ).get("Item", {})
    return _agreement_to_out(updated)


# ---------------------------------------------------------------------------
# Background expiry processing
# ---------------------------------------------------------------------------

def process_expiry_alerts() -> int:
    """Find active agreements expiring within 30 days; send warning alerts once."""
    now = now_ts()
    horizon = now + EXPIRY_WARNING_SECONDS
    sent = 0
    months = {_expiry_month_pk(now), _expiry_month_pk(horizon)}
    for month_pk in months:
        try:
            resp = T.license_agreements.query(
                IndexName="GSI3",
                KeyConditionExpression=Key("GSI3PK").eq(month_pk)
                & Key("GSI3SK").between(now, horizon),
            )
        except Exception:
            logger.warning("Expiry alert query failed for %s", month_pk, exc_info=True)
            continue
        for it in resp.get("Items", []):
            if it.get("status") != "active" or it.get("expiry_alert_sent"):
                continue
            creator_id = it.get("creator_id", "")
            license_id = it.get("license_id", "")
            exp = int(it.get("expires_at", 0) or 0)
            days = max(0, (exp - now) // 86400)
            try:
                write_alert(
                    creator_id,
                    event="license_expiring",
                    outcome="warning",
                    title="License Expiring Soon",
                    details={
                        "license_id": license_id,
                        "title": it.get("title", ""),
                        "expires_at": exp,
                        "days": int(days),
                    },
                    action_url=f"/licenses?highlight={license_id}",
                )
                T.license_agreements.update_item(
                    Key={"pk": f"CREATOR#{creator_id}", "sk": f"LICENSE#{license_id}"},
                    UpdateExpression="SET #f = :t",
                    ExpressionAttributeNames={"#f": "expiry_alert_sent"},
                    ExpressionAttributeValues={":t": True},
                )
                sent += 1
            except Exception:
                logger.warning("Failed to send expiry alert", exc_info=True)
    return sent


def process_expired_agreements() -> int:
    """Mark active agreements past their expiry as expired; flag linked content."""
    now = now_ts()
    processed = 0
    try:
        resp = T.license_agreements.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq("STATUS#active")
            & Key("GSI1SK").lt(now),
        )
    except Exception:
        logger.warning("Expired-agreement query failed", exc_info=True)
        return 0
    for it in resp.get("Items", []):
        exp = int(it.get("expires_at", 0) or 0)
        if not exp or exp >= now:
            continue
        creator_id = it.get("creator_id", "")
        license_id = it.get("license_id", "")
        try:
            T.license_agreements.update_item(
                Key={"pk": f"CREATOR#{creator_id}", "sk": f"LICENSE#{license_id}"},
                UpdateExpression="SET #status = :status, #g1 = :g1, #updated_at = :ts",
                ExpressionAttributeNames={
                    "#status": "status",
                    "#g1": "GSI1PK",
                    "#updated_at": "updated_at",
                },
                ExpressionAttributeValues={
                    ":status": "expired",
                    ":g1": "STATUS#expired",
                    ":ts": now,
                },
            )
            _patch_reverse_lookup(license_id, {"status": "expired"})
            # Flag linked content for compliance review (LICENSE-006).
            for link in list_content_for_license(license_id=license_id):
                try:
                    T.license_agreements.update_item(
                        Key={
                            "pk": f"LICENSE#{license_id}",
                            "sk": f"CONTENT#{link.get('content_id', '')}",
                        },
                        UpdateExpression="SET #cs = :cs",
                        ExpressionAttributeNames={"#cs": "compliance_status"},
                        ExpressionAttributeValues={":cs": "license_expired"},
                    )
                except Exception:
                    logger.warning("Failed to flag content", exc_info=True)
            write_alert(
                creator_id,
                event="license_expired",
                outcome="warning",
                title="License Agreement Expired",
                details={"license_id": license_id, "title": it.get("title", "")},
                action_url=f"/licenses?highlight={license_id}",
            )
            processed += 1
        except Exception:
            logger.warning("Failed to expire agreement", exc_info=True)
    return processed


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _write_reverse_lookup(item: Dict[str, Any]) -> None:
    T.license_agreements.put_item(Item={
        "pk": f"LICENSE#{item['license_id']}",
        "sk": "META",
        "license_id": item["license_id"],
        "creator_id": item["creator_id"],
        "title": item["title"],
        "status": item["status"],
        "expires_at": item.get("expires_at"),
        "created_at": item["created_at"],
    })


def _patch_reverse_lookup(license_id: str, updates: Dict[str, Any]) -> None:
    if not updates:
        return
    expr_parts = []
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {}
    for k, v in updates.items():
        names[f"#{k}"] = k
        values[f":{k}"] = v
        expr_parts.append(f"#{k} = :{k}")
    try:
        T.license_agreements.update_item(
            Key={"pk": f"LICENSE#{license_id}", "sk": "META"},
            UpdateExpression="SET " + ", ".join(expr_parts),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except Exception:
        logger.warning("Failed to patch reverse lookup for %s", license_id, exc_info=True)


def _get_reverse_lookup(license_id: str) -> Dict[str, Any]:
    resp = T.license_agreements.get_item(
        Key={"pk": f"LICENSE#{license_id}", "sk": "META"}
    )
    item = resp.get("Item")
    if not item:
        raise LookupError("Agreement not found")
    return item


def _enqueue_review(
    license_id: str,
    creator_id: str,
    title: str,
    licensor_name: str,
    license_type: str,
    ts: int,
) -> None:
    T.license_agreements.put_item(Item={
        "pk": "ADMIN_REVIEW",
        "sk": f"PENDING#{ts:020d}#{license_id}",
        "license_id": license_id,
        "creator_id": creator_id,
        "title": title.strip(),
        "licensor_name": licensor_name.strip(),
        "license_type": license_type,
        "submitted_at": ts,
    })


def _dequeue_review(license_id: str, created_at: int) -> None:
    try:
        T.license_agreements.delete_item(
            Key={"pk": "ADMIN_REVIEW", "sk": f"PENDING#{created_at:020d}#{license_id}"}
        )
    except Exception:
        logger.warning("Failed to dequeue review for %s", license_id, exc_info=True)

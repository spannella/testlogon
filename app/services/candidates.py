"""
ATS Candidates service (CND-002, CND-003, CND-004).

All functions are synchronous; async route handlers call them via
`asyncio.to_thread`. No `S.dev_mode` branches — DDB and S3 use the same
code path in dev (moto in-process) and prod (real AWS) per SECOPS-007.
"""
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    CANDIDATE_SOURCES,
    CANDIDATE_STATUSES,
    CandidateCreateIn,
    CandidateUpdateIn,
)

logger = logging.getLogger(__name__)


# ── module-level S3 singleton (CND-003) ──────────────────────────────────────
# Imported lazily to avoid ImportError if aws_clients is unavailable at import time.
def _get_s3():
    from app.core.aws_clients import s3_client
    return s3_client()


# ── helpers ───────────────────────────────────────────────────────────────────

_safe_filename = lambda name: re.sub(r"[^A-Za-z0-9._-]", "_", name or "resume")[:255]


def _require_enabled() -> None:
    if not S.candidates_enabled:
        raise HTTPException(
            503,
            {"code": "candidates_disabled", "message": "Candidates module is not enabled"},
        )


def _make_download_url(s3_key: str, s3_bucket: str) -> str:
    """Single allowed dev/prod branch (SECOPS-007)."""
    if S.dev_mode:
        return f"/mock/s3/{s3_bucket}/{s3_key}"
    try:
        return _get_s3().generate_presigned_url(
            "get_object",
            Params={"Bucket": s3_bucket, "Key": s3_key},
            ExpiresIn=300,
        )
    except Exception:
        logger.warning("candidate.resume.presign_failed key=%s", s3_key)
        raise HTTPException(
            503,
            detail={"code": "resume_unavailable", "message": "Résumé download temporarily unavailable"},
        )


# ── CND-002: CRUD service ─────────────────────────────────────────────────────

def create_candidate(creator_sub: str, data: CandidateCreateIn) -> dict:
    """Create a new candidate record. Returns the written DDB item."""
    _require_enabled()

    from app.core.normalize import normalize_email, normalize_phone

    email = normalize_email(data.email)
    email_raw = data.email

    phone: Optional[str] = None
    if data.phone:
        phone = normalize_phone(data.phone)

    # Duplicate short-circuit: same normalized email + not soft-deleted → 409
    existing = find_candidate_by_email(email)
    if existing and not existing.get("deleted_at"):
        raise HTTPException(
            409,
            {
                "code": "duplicate_candidate",
                "candidate_id": existing["candidate_id"],
                "message": "A candidate with this email already exists",
            },
        )

    candidate_id = "cand_" + uuid4().hex[:20]
    owner_sub = data.owner_sub or creator_sub
    source = data.source or "other"
    status = data.status or "active"

    if status not in CANDIDATE_STATUSES:
        raise HTTPException(400, {"code": "invalid_status", "message": f"Invalid status: {status}"})
    if source not in CANDIDATE_SOURCES:
        raise HTTPException(400, {"code": "invalid_source", "message": f"Invalid source: {source}"})

    if data.date_available:
        try:
            datetime.strptime(data.date_available, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(400, {"code": "invalid_date_available", "message": "date_available must be YYYY-MM-DD"})

    ts = now_ts()

    item: Dict[str, Any] = {
        "pk": f"CANDIDATE#{candidate_id}",
        "sk": "META",
        "candidate_id": candidate_id,
        "first_name": data.first_name,
        "last_name": data.last_name,
        "email": email,
        "email_raw": email_raw,
        "source": source,
        "owner_sub": owner_sub,
        "status": status,
        "can_relocate": data.can_relocate,
        "created_by": creator_sub,
        "created_at": ts,
        "updated_at": ts,
        # GSI fan-out
        "GSI1PK": f"OWNER#{owner_sub}",
        "GSI1SK": ts,
        "GSI2PK": f"STATUS#{status}",
        "GSI2SK": ts,
        "GSI3PK": f"SOURCE#{source}",
        "GSI3SK": ts,
    }

    if phone:
        item["phone"] = phone
    if data.company:
        item["company"] = data.company
    if data.title:
        item["title"] = data.title
    if data.current_pay:
        item["current_pay"] = data.current_pay[:500]
    if data.desired_pay:
        item["desired_pay"] = data.desired_pay[:500]
    if data.key_skills:
        item["key_skills"] = data.key_skills[:4000]
    if data.date_available:
        item["date_available"] = data.date_available
    if data.linkedin_url:
        item["linkedin_url"] = data.linkedin_url[:500]
    if data.web_url:
        item["web_url"] = data.web_url[:500]
    if data.address:
        item["address"] = data.address
    if data.city:
        item["city"] = data.city
    if data.state:
        item["state"] = data.state
    if data.postal_code:
        item["postal_code"] = data.postal_code
    if data.country:
        item["country"] = data.country

    T.candidates.put_item(Item=item)

    from app.services.alerts import audit_event
    try:
        audit_event("candidate.created", creator_sub, candidate_id=candidate_id, email=email)
    except Exception:
        pass

    # CND-004 fire-and-forget
    try:
        record_candidate_change(
            candidate_id, creator_sub,
            change_type="created",
            summary=f"Candidate {email} created",
        )
    except Exception:
        pass

    return item


def get_candidate(candidate_id: str) -> Optional[dict]:
    """Return the candidate META item or None if not found."""
    _require_enabled()
    resp = T.candidates.get_item(Key={"pk": f"CANDIDATE#{candidate_id}", "sk": "META"})
    return resp.get("Item")


def list_candidates(
    *,
    owner_sub: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    created_after: Optional[int] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """List candidates with optional filters. Returns {candidates, cursor}."""
    _require_enabled()
    limit = max(1, min(limit, 200))

    from boto3.dynamodb.conditions import Attr, Key

    eks = decode_cursor(cursor)

    results: List[dict] = []

    if status is not None:
        # Query ByStatus GSI
        key_cond = Key("GSI2PK").eq(f"STATUS#{status}")
        if created_after is not None:
            key_cond = key_cond & Key("GSI2SK").gte(created_after)
        index_name = "ByStatus"
        filter_expr = Attr("deleted_at").not_exists()

        last_key = eks
        while len(results) < limit:
            kwargs: Dict[str, Any] = {
                "IndexName": index_name,
                "KeyConditionExpression": key_cond,
                "FilterExpression": filter_expr,
                "Limit": limit * 2,
                "ScanIndexForward": False,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.candidates.query(**kwargs)
            results.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

        next_cursor = encode_cursor(last_key) if last_key and len(results) >= limit else None
        return {"candidates": results[:limit], "cursor": next_cursor}

    elif source is not None:
        # Query BySource GSI
        key_cond = Key("GSI3PK").eq(f"SOURCE#{source}")
        if created_after is not None:
            key_cond = key_cond & Key("GSI3SK").gte(created_after)
        index_name = "BySource"
        filter_expr = Attr("deleted_at").not_exists()

        last_key = eks
        while len(results) < limit:
            kwargs = {
                "IndexName": index_name,
                "KeyConditionExpression": key_cond,
                "FilterExpression": filter_expr,
                "Limit": limit * 2,
                "ScanIndexForward": False,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.candidates.query(**kwargs)
            results.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

        next_cursor = encode_cursor(last_key) if last_key and len(results) >= limit else None
        return {"candidates": results[:limit], "cursor": next_cursor}

    elif owner_sub is not None and owner_sub != "*":
        # Query ByOwner GSI
        key_cond = Key("GSI1PK").eq(f"OWNER#{owner_sub}")
        if created_after is not None:
            key_cond = key_cond & Key("GSI1SK").gte(created_after)
        index_name = "ByOwner"
        filter_expr = Attr("deleted_at").not_exists()

        last_key = eks
        while len(results) < limit:
            kwargs = {
                "IndexName": index_name,
                "KeyConditionExpression": key_cond,
                "FilterExpression": filter_expr,
                "Limit": limit * 2,
                "ScanIndexForward": False,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.candidates.query(**kwargs)
            results.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

        next_cursor = encode_cursor(last_key) if last_key and len(results) >= limit else None
        return {"candidates": results[:limit], "cursor": next_cursor}

    else:
        # Admin-level scan (no filter, or owner_sub=="*")
        filter_expr = Attr("sk").eq("META") & Attr("deleted_at").not_exists()
        last_key = eks
        while len(results) < limit:
            kwargs = {
                "FilterExpression": filter_expr,
                "Limit": limit * 2,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.candidates.scan(**kwargs)
            results.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

        next_cursor = encode_cursor(last_key) if last_key and len(results) >= limit else None
        return {"candidates": results[:limit], "cursor": next_cursor}


def update_candidate(candidate_id: str, actor_sub: str, data: CandidateUpdateIn) -> dict:
    """Partial update a candidate. Returns updated item."""
    _require_enabled()

    existing = get_candidate(candidate_id)
    if not existing:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if existing.get("deleted_at"):
        raise HTTPException(410, {"code": "candidate_deleted"})

    updated = dict(existing)

    # Normalize email/phone if updated
    if data.email is not None:
        from app.core.normalize import normalize_email
        updated["email"] = normalize_email(data.email)
        updated["email_raw"] = data.email

    if data.phone is not None:
        from app.core.normalize import normalize_phone
        updated["phone"] = normalize_phone(data.phone)

    # Merge non-None scalar fields
    for field in (
        "first_name", "last_name", "company", "title",
        "current_pay", "desired_pay", "key_skills", "date_available",
        "can_relocate", "linkedin_url", "web_url",
        "address", "city", "state", "postal_code", "country",
    ):
        val = getattr(data, field, None)
        if val is not None:
            if field == "key_skills":
                updated[field] = val[:4000]
            elif field in ("current_pay", "desired_pay", "linkedin_url", "web_url"):
                updated[field] = val[:500]
            else:
                updated[field] = val

    # Validate status/source before rewriting GSI keys
    if data.status is not None:
        if data.status not in CANDIDATE_STATUSES:
            raise HTTPException(400, {"code": "invalid_status"})
        old_status = existing.get("status", "active")
        updated["status"] = data.status
        updated["GSI2PK"] = f"STATUS#{data.status}"

    if data.source is not None:
        if data.source not in CANDIDATE_SOURCES:
            raise HTTPException(400, {"code": "invalid_source"})
        updated["source"] = data.source
        updated["GSI3PK"] = f"SOURCE#{data.source}"

    if data.date_available is not None:
        try:
            datetime.strptime(data.date_available, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(400, {"code": "invalid_date_available", "message": "date_available must be YYYY-MM-DD"})

    updated["updated_at"] = now_ts()

    T.candidates.put_item(Item=updated)

    from app.services.alerts import audit_event
    try:
        audit_event("candidate.updated", actor_sub, candidate_id=candidate_id)
    except Exception:
        pass

    # CND-004 fire-and-forget
    change_type = "updated"
    if data.status is not None and data.status != existing.get("status"):
        change_type = "status_changed"
    try:
        record_candidate_change(
            candidate_id, actor_sub,
            change_type=change_type,
            summary=f"Candidate updated",
        )
    except Exception:
        pass

    return updated


def delete_candidate(candidate_id: str, actor_sub: str) -> None:
    """Soft-delete a candidate (sets deleted_at + status=archived). Idempotent."""
    _require_enabled()

    existing = get_candidate(candidate_id)
    if not existing:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if existing.get("deleted_at"):
        # Already deleted — idempotent no-op
        return

    ts = now_ts()
    updated = dict(existing)
    updated["deleted_at"] = ts
    updated["status"] = "archived"
    updated["updated_at"] = ts
    updated["GSI2PK"] = "STATUS#archived"

    T.candidates.put_item(Item=updated)

    from app.services.alerts import audit_event
    try:
        audit_event("candidate.deleted", actor_sub, candidate_id=candidate_id)
    except Exception:
        pass

    try:
        record_candidate_change(
            candidate_id, actor_sub,
            change_type="deleted",
            summary="Candidate soft-deleted",
        )
    except Exception:
        pass


def set_owner(candidate_id: str, new_owner_sub: str, actor_sub: str) -> dict:
    """Reassign candidate ownership. Uses LED-010 shim fallback."""
    _require_enabled()

    existing = get_candidate(candidate_id)
    if not existing:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if existing.get("deleted_at"):
        raise HTTPException(410, {"code": "candidate_deleted"})

    # LED-010 delegation (lazy import; shim fallback when not available)
    try:
        from app.services.leads_assignment import assign_owner  # noqa: PLC0415
        return assign_owner(
            entity_type="candidate",
            entity_id=candidate_id,
            owner_sub=new_owner_sub,
            actor_sub=actor_sub,
        )
    except ImportError:
        pass  # LED-010 not yet deployed → shim below
    except Exception:
        logger.warning("LED-010 assign_owner failed; using shim", exc_info=True)

    # TODO: absorb into LED-010 when shipped
    updated = dict(existing)
    updated["owner_sub"] = new_owner_sub
    updated["GSI1PK"] = f"OWNER#{new_owner_sub}"
    updated["updated_at"] = now_ts()

    T.candidates.put_item(Item=updated)

    from app.services.alerts import audit_event
    try:
        audit_event("candidate.owner_changed", actor_sub, candidate_id=candidate_id, new_owner=new_owner_sub)
    except Exception:
        pass

    try:
        record_candidate_change(
            candidate_id, actor_sub,
            change_type="owner_changed",
            summary=f"Owner changed to {new_owner_sub}",
            metadata={"old_owner": existing.get("owner_sub"), "new_owner": new_owner_sub},
        )
    except Exception:
        pass

    return updated


def find_candidate_by_email(email: str) -> Optional[dict]:
    """Return the first non-deleted candidate with the given normalized email, or None.

    Not guarded by _require_enabled() so LED-009 can call it unconditionally.
    """
    from boto3.dynamodb.conditions import Attr

    try:
        # Note: no Limit here — FilterExpression is applied after DDB fetches items,
        # so Limit=1 may skip the actual matching item (CLAUDE.md gotcha).
        # Candidates table is expected to be small per-tenant, so a full scan is acceptable.
        resp = T.candidates.scan(
            FilterExpression=Attr("email").eq(email) & Attr("sk").eq("META"),
        )
        items = resp.get("Items", [])
        # Filter out soft-deleted
        live = [i for i in items if not i.get("deleted_at")]
        return live[0] if live else None
    except Exception:
        return None


# ── CND-003: résumé attachment service ───────────────────────────────────────

def add_resume(
    candidate_id: str,
    *,
    uploaded_by: str,
    filename: str,
    content_type: str,
    size_bytes: int,
    s3_key: str,
    s3_bucket: str,
    source: str = "upload",
    make_primary: bool = False,
) -> dict:
    """Record résumé upload sub-item. S3 put_object is done by the router before calling this."""
    _require_enabled()

    cand = get_candidate(candidate_id)
    if not cand:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if cand.get("deleted_at"):
        raise HTTPException(410, {"code": "candidate_deleted"})

    # Count active attachments
    active_count = _count_active_resumes(candidate_id)
    if active_count >= S.candidate_resume_max_per_candidate:
        raise HTTPException(400, {"code": "candidate_resume_limit_reached", "message": "Maximum résumé count reached"})

    attachment_id = "att_" + uuid4().hex
    safe_name = _safe_filename(filename)
    ts = now_ts()

    is_primary = make_primary or (active_count == 0)

    item: Dict[str, Any] = {
        "pk": f"CANDIDATE#{candidate_id}",
        "sk": f"ATTACHMENT#{attachment_id}",
        "attachment_id": attachment_id,
        "candidate_id": candidate_id,
        "filename": safe_name,
        "filename_original": filename,
        "content_type": content_type,
        "size_bytes": size_bytes,
        "s3_key": s3_key,
        "s3_bucket": s3_bucket,
        "source": source,
        "is_primary": is_primary,
        "uploaded_by": uploaded_by,
        "created_at": ts,
    }

    T.candidates.put_item(Item=item)

    if is_primary:
        set_primary_resume(candidate_id, attachment_id, uploaded_by)

    from app.services.alerts import audit_event
    try:
        audit_event(
            "candidate.resume.uploaded", uploaded_by,
            candidate_id=candidate_id, attachment_id=attachment_id,
            filename=safe_name, source=source,
        )
    except Exception:
        pass

    try:
        record_candidate_change(
            candidate_id, uploaded_by,
            change_type="resume_added",
            summary=f"Résumé '{safe_name}' uploaded",
            metadata={"filename": safe_name, "attachment_id": attachment_id},
        )
    except Exception:
        pass

    return item


def add_resume_from_filemanager(
    candidate_id: str,
    *,
    uploaded_by: str,
    node_path: str,
    recruiter_sub: str,
    make_primary: bool = False,
) -> dict:
    """Record a file-manager-linked résumé (pointer only, no byte transfer)."""
    _require_enabled()

    cand = get_candidate(candidate_id)
    if not cand:
        raise HTTPException(404, {"code": "candidate_not_found"})
    if cand.get("deleted_at"):
        raise HTTPException(410, {"code": "candidate_deleted"})

    from app.services.filemanager import get_node
    node = get_node(recruiter_sub, node_path)

    active_count = _count_active_resumes(candidate_id)
    if active_count >= S.candidate_resume_max_per_candidate:
        raise HTTPException(400, {"code": "candidate_resume_limit_reached", "message": "Maximum résumé count reached"})

    attachment_id = "att_" + uuid4().hex
    filename = node.get("name", node_path.split("/")[-1] or "resume")
    safe_name = _safe_filename(filename)
    content_type = node.get("content_type", "application/octet-stream")
    ts = now_ts()
    is_primary = make_primary or (active_count == 0)

    item: Dict[str, Any] = {
        "pk": f"CANDIDATE#{candidate_id}",
        "sk": f"ATTACHMENT#{attachment_id}",
        "attachment_id": attachment_id,
        "candidate_id": candidate_id,
        "filename": safe_name,
        "filename_original": filename,
        "content_type": content_type,
        "size_bytes": 0,
        "source": "file_manager",
        "node_path": node_path,
        "is_primary": is_primary,
        "uploaded_by": uploaded_by,
        "created_at": ts,
    }

    T.candidates.put_item(Item=item)

    if is_primary:
        set_primary_resume(candidate_id, attachment_id, uploaded_by)

    from app.services.alerts import audit_event
    try:
        audit_event(
            "candidate.resume.uploaded", uploaded_by,
            candidate_id=candidate_id, attachment_id=attachment_id,
            filename=safe_name, source="file_manager",
        )
    except Exception:
        pass

    try:
        record_candidate_change(
            candidate_id, uploaded_by,
            change_type="resume_added",
            summary=f"Résumé '{safe_name}' linked from file manager",
            metadata={"filename": safe_name, "attachment_id": attachment_id},
        )
    except Exception:
        pass

    return item


def list_resumes(candidate_id: str) -> List[dict]:
    """Return all active résumé sub-items, primary first then newest-first."""
    _require_enabled()

    from boto3.dynamodb.conditions import Attr, Key

    items: List[dict] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(f"CANDIDATE#{candidate_id}") & Key("sk").begins_with("ATTACHMENT#")
            ),
            "FilterExpression": Attr("deleted_at").not_exists(),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.candidates.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    # Primary first, then newest-first
    items.sort(key=lambda x: (0 if x.get("is_primary") else 1, -int(x.get("created_at", 0))))
    return items


def get_resume(candidate_id: str, attachment_id: str) -> dict:
    """Fetch one résumé sub-item, raising 404 if missing or soft-deleted."""
    _require_enabled()

    resp = T.candidates.get_item(
        Key={"pk": f"CANDIDATE#{candidate_id}", "sk": f"ATTACHMENT#{attachment_id}"}
    )
    item = resp.get("Item")
    if not item or item.get("deleted_at"):
        raise HTTPException(404, {"code": "resume_not_found"})
    return item


def get_primary_resume_item(candidate_id: str) -> Optional[dict]:
    """Return the primary résumé attachment sub-item, or None if absent/unset.

    Never raises on missing path (callers treat 'no primary' as normal).
    Used by PIP-005 to attach the primary résumé on submit-to-client.
    """
    _require_enabled()

    meta_resp = T.candidates.get_item(
        Key={"pk": f"CANDIDATE#{candidate_id}", "sk": "META"}
    )
    meta = meta_resp.get("Item") or {}
    primary_resume_id = meta.get("primary_resume_id")
    if not primary_resume_id:
        return None

    att_resp = T.candidates.get_item(
        Key={"pk": f"CANDIDATE#{candidate_id}", "sk": f"ATTACHMENT#{primary_resume_id}"}
    )
    att = att_resp.get("Item")
    if not att or att.get("deleted_at"):
        return None
    return att


def set_primary_resume(candidate_id: str, attachment_id: str, actor_sub: str) -> None:
    """Enforce exactly-one-primary invariant. Clears other primaries, sets target."""
    _require_enabled()

    # Validate target exists and is not deleted
    get_resume(candidate_id, attachment_id)

    # Fetch all active sub-items
    all_items = list_resumes(candidate_id)

    # Clear is_primary on any other current primary
    for sub in all_items:
        if sub.get("is_primary") and sub["attachment_id"] != attachment_id:
            T.candidates.update_item(
                Key={"pk": f"CANDIDATE#{candidate_id}", "sk": f"ATTACHMENT#{sub['attachment_id']}"},
                UpdateExpression="SET is_primary = :f",
                ExpressionAttributeValues={":f": False},
            )

    # Set is_primary on target
    T.candidates.update_item(
        Key={"pk": f"CANDIDATE#{candidate_id}", "sk": f"ATTACHMENT#{attachment_id}"},
        UpdateExpression="SET is_primary = :t",
        ExpressionAttributeValues={":t": True},
    )

    # Back-write primary_resume_id on META row
    T.candidates.update_item(
        Key={"pk": f"CANDIDATE#{candidate_id}", "sk": "META"},
        UpdateExpression="SET primary_resume_id = :id, updated_at = :ts",
        ExpressionAttributeValues={":id": attachment_id, ":ts": now_ts()},
    )

    from app.services.alerts import audit_event
    try:
        audit_event(
            "candidate.resume.primary_set", actor_sub,
            candidate_id=candidate_id, attachment_id=attachment_id,
        )
    except Exception:
        pass


def delete_resume(candidate_id: str, attachment_id: str, actor_sub: str) -> None:
    """Soft-delete a résumé sub-item. Promotes next primary if needed."""
    _require_enabled()

    item = get_resume(candidate_id, attachment_id)  # raises 404 if already deleted
    was_primary = item.get("is_primary", False)
    filename = item.get("filename", "")

    T.candidates.update_item(
        Key={"pk": f"CANDIDATE#{candidate_id}", "sk": f"ATTACHMENT#{attachment_id}"},
        UpdateExpression="SET deleted_at = :ts, is_primary = :f",
        ExpressionAttributeValues={":ts": now_ts(), ":f": False},
    )

    if was_primary:
        _promote_next_primary(candidate_id, deleted_id=attachment_id)

    from app.services.alerts import audit_event
    try:
        audit_event(
            "candidate.resume.deleted", actor_sub,
            candidate_id=candidate_id, attachment_id=attachment_id,
        )
    except Exception:
        pass

    try:
        record_candidate_change(
            candidate_id, actor_sub,
            change_type="resume_removed",
            summary=f"Résumé '{filename}' removed",
            metadata={"filename": filename, "attachment_id": attachment_id, "was_primary": was_primary},
        )
    except Exception:
        pass
    # Note: S3 object is NOT deleted — handled by S3 lifecycle policy (KB-003/CND-003 pattern)


def _count_active_resumes(candidate_id: str) -> int:
    """Count non-soft-deleted attachment sub-items for a candidate."""
    from boto3.dynamodb.conditions import Attr, Key
    count = 0
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(f"CANDIDATE#{candidate_id}") & Key("sk").begins_with("ATTACHMENT#")
            ),
            "FilterExpression": Attr("deleted_at").not_exists(),
            "Select": "COUNT",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.candidates.query(**kwargs)
        count += resp.get("Count", 0)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return count


def _promote_next_primary(candidate_id: str, deleted_id: str) -> None:
    """After deleting the primary, promote next-newest or clear pointer."""
    remaining = [
        s for s in list_resumes(candidate_id)
        if s["attachment_id"] != deleted_id
    ]
    if not remaining:
        # Clear primary_resume_id on META
        T.candidates.update_item(
            Key={"pk": f"CANDIDATE#{candidate_id}", "sk": "META"},
            UpdateExpression="REMOVE primary_resume_id SET updated_at = :ts",
            ExpressionAttributeValues={":ts": now_ts()},
        )
    else:
        # Promote most recently uploaded
        remaining.sort(key=lambda x: -int(x.get("created_at", 0)))
        next_primary = remaining[0]
        set_primary_resume(candidate_id, next_primary["attachment_id"], "system")


# ── CND-004: change-history adapter ──────────────────────────────────────────

def record_candidate_change(
    candidate_id: str,
    actor_sub: str,
    *,
    change_type: str,
    summary: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Fire-and-forget change-history row. Never raises."""
    if not S.candidates_enabled:
        return

    try:
        ts = now_ts()
        activity_id = "chg_" + uuid4().hex[:16]

        # Preferred path: ACT-009 crm_activity_timeline
        try:
            from app.services.crm_activity_timeline import record_crm_activity  # noqa: PLC0415
            record_crm_activity(
                "candidate", candidate_id,
                change_type,
                activity_id,
                actor_sub,
                summary=summary[:200],
                metadata=metadata or {},
            )
            return
        except ImportError:
            pass  # ACT-009 not yet deployed — fall through to local path
        except Exception:
            logger.warning("crm_activity_timeline unavailable; using local fallback", exc_info=True)
            # fall through

        # Fallback: ACTIVITY# sub-item on candidates table
        inverted = 9999999999999 - ts
        sk = f"ACTIVITY#{inverted:013d}#{activity_id}"
        T.candidates.put_item(Item={
            "pk": f"CANDIDATE#{candidate_id}",
            "sk": sk,
            "activity_id": activity_id,
            "candidate_id": candidate_id,
            "change_type": change_type,
            "summary": summary[:200],
            "actor_sub": actor_sub,
            "metadata": metadata or {},
            "created_at": ts,
        })
    except Exception:
        logger.warning("record_candidate_change failed", exc_info=True)


def list_candidate_history(
    candidate_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Return paginated change history for a candidate, newest-first.

    Delegates to ACT-009 when available; falls back to local ACTIVITY# query.
    Returns {"events": [...], "cursor": str|None}.
    """
    if not S.candidates_enabled:
        return {"events": [], "cursor": None}

    limit = max(1, min(limit, 100))

    # Preferred path: ACT-009
    try:
        from app.services.crm_activity_timeline import list_entity_activities  # noqa: PLC0415
        result = list_entity_activities(
            "candidate", candidate_id,
            cursor=cursor,
            limit=limit,
        )
        return {"events": result.get("items", []), "cursor": result.get("next_cursor")}
    except ImportError:
        pass
    except Exception:
        logger.warning("crm_activity_timeline read unavailable; using local fallback", exc_info=True)

    # Fallback: query ACTIVITY# sub-items on candidates table
    from boto3.dynamodb.conditions import Key

    eks = decode_cursor(cursor)
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(f"CANDIDATE#{candidate_id}") & Key("sk").begins_with("ACTIVITY#")
        ),
        "ScanIndexForward": True,  # inverted SK → ascending = newest first
        "Limit": limit,
    }
    if eks:
        kwargs["ExclusiveStartKey"] = eks
    resp = T.candidates.query(**kwargs)
    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(last_key) if last_key else None
    events = [
        {
            "event_id": i["activity_id"],
            "candidate_id": i["candidate_id"],
            "change_type": i["change_type"],
            "summary": i.get("summary", ""),
            "actor_sub": i["actor_sub"],
            "metadata": i.get("metadata") or {},
            "created_at": int(i["created_at"]),
        }
        for i in items
    ]
    return {"events": events, "cursor": next_cursor}

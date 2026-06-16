"""ATS Recruiting Pipeline service — PIP-001 through PIP-006.

All public functions call _require_flag() first so that with
ATS_PIPELINE_ENABLED=false the service is a complete no-op.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    PipelineEntryCreateIn,
    PipelineEntryOut,
    PipelineRatingIn,
    PipelineStatusChangeIn,
    PipelineStatusConfigIn,
    PipelineStatusConfigOut,
    PipelineStatusItemOut,
    PlacementIn,
    PlacementOut,
)

# ---------------------------------------------------------------------------
# Helper: feature-flag gate
# ---------------------------------------------------------------------------

def _require_flag() -> None:
    """Raise HTTP 503 when ATS pipeline feature is disabled."""
    if not S.ats_pipeline_enabled:
        raise HTTPException(
            status_code=503,
            detail={"code": "ats_pipeline_disabled"},
        )


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _entry_pk(owner_sub: str) -> str:
    return f"USER#{owner_sub}"


def _entry_sk(job_order_id: str, candidate_id: str) -> str:
    return f"PIPE#{job_order_id}#CAND#{candidate_id}"


def _placement_sk(job_order_id: str, candidate_id: str) -> str:
    return f"PIPE#{job_order_id}#CAND#{candidate_id}#PLACEMENT"


# ---------------------------------------------------------------------------
# PIP-001: Junction model CRUD
# ---------------------------------------------------------------------------

def add_to_pipeline(owner_sub: str, data: PipelineEntryCreateIn) -> PipelineEntryOut:
    """Add a candidate to a job-order pipeline (M:N junction row)."""
    _require_flag()

    # Lazy-import collaborators (soft deps; fail gracefully when not deployed)
    try:
        from app.services.job_orders import get_job_order  # type: ignore[import]
        get_job_order(data.job_order_id)
    except ImportError:
        raise HTTPException(503, detail={"code": "job_orders_not_available"})

    try:
        from app.services.candidates import get_candidate  # type: ignore[import]
        get_candidate(data.candidate_id)
    except ImportError:
        raise HTTPException(503, detail={"code": "candidates_not_available"})

    status = data.status or "100_no_contact"
    # Resolve rank from config when available; fall back to numeric prefix
    status_rank = _resolve_status_rank_safe(status)
    ts = now_ts()

    item: Dict[str, Any] = {
        "pk": _entry_pk(owner_sub),
        "sk": _entry_sk(data.job_order_id, data.candidate_id),
        "pipeline_id": f"pe_{uuid.uuid4().hex}",
        "job_order_id": data.job_order_id,
        "candidate_id": data.candidate_id,
        "owner_sub": owner_sub,
        "status": status,
        "status_rank": status_rank,
        "rating": 0,
        "created_at": ts,
        "updated_at": ts,
    }

    try:
        T.ats_pipeline.put_item(
            Item=item,
            ConditionExpression=Attr("sk").not_exists(),
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(409, detail={"code": "pipeline_entry_exists"})
        raise

    try:
        from app.services.alerts import audit_event  # type: ignore[import]
        audit_event(
            "pipeline.candidate_added",
            owner_sub,
            None,
            pipeline_id=item["pipeline_id"],
            job_order_id=data.job_order_id,
            candidate_id=data.candidate_id,
            status=status,
        )
    except Exception:
        pass

    return PipelineEntryOut(**item)


def get_pipeline_entry(owner_sub: str, job_order_id: str, candidate_id: str) -> PipelineEntryOut:
    """Fetch a specific pipeline entry by owner + job + candidate."""
    _require_flag()
    resp = T.ats_pipeline.get_item(
        Key={"pk": _entry_pk(owner_sub), "sk": _entry_sk(job_order_id, candidate_id)}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, detail={"code": "pipeline_entry_not_found"})
    return PipelineEntryOut(**_int_fields(item))


def list_pipeline_for_job(
    owner_sub: str,
    job_order_id: str,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List all pipeline entries for a given job order."""
    _require_flag()
    from boto3.dynamodb.conditions import Key as DdbKey  # local import for clarity

    sk_prefix = f"PIPE#{job_order_id}#CAND#"
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            DdbKey("pk").eq(_entry_pk(owner_sub))
            & DdbKey("sk").begins_with(sk_prefix)
        ),
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.ats_pipeline.query(**kwargs)
    items = [PipelineEntryOut(**_int_fields(i)) for i in resp.get("Items", [])]
    return {"entries": items, "cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


def list_pipeline_for_candidate(
    owner_sub: str,
    candidate_id: str,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List all pipeline entries for a given candidate across all jobs."""
    _require_flag()
    from boto3.dynamodb.conditions import Key as DdbKey

    # Because DynamoDB begins_with cannot match mid-key segments we query all
    # PIPE# items for this owner and filter by candidate_id in Python.
    # We page until we have enough results OR DynamoDB is exhausted.
    pk_val = _entry_pk(owner_sub)
    esc_key = decode_cursor(cursor) if cursor else None
    results: List[PipelineEntryOut] = []
    last_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                DdbKey("pk").eq(pk_val)
                & DdbKey("sk").begins_with("PIPE#")
            ),
            "FilterExpression": Attr("candidate_id").eq(candidate_id),
        }
        if esc_key:
            kwargs["ExclusiveStartKey"] = esc_key

        resp = T.ats_pipeline.query(**kwargs)
        for raw in resp.get("Items", []):
            results.append(PipelineEntryOut(**_int_fields(raw)))
            if len(results) >= limit:
                last_key = resp.get("LastEvaluatedKey")
                return {"entries": results, "cursor": encode_cursor(last_key)}

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        esc_key = last_key

    return {"entries": results, "cursor": None}


def remove_from_pipeline(owner_sub: str, job_order_id: str, candidate_id: str) -> None:
    """Remove a candidate from a job-order pipeline."""
    _require_flag()
    # Raises 404 if not found
    get_pipeline_entry(owner_sub, job_order_id, candidate_id)
    T.ats_pipeline.delete_item(
        Key={"pk": _entry_pk(owner_sub), "sk": _entry_sk(job_order_id, candidate_id)}
    )
    try:
        from app.services.alerts import audit_event  # type: ignore[import]
        audit_event(
            "pipeline.candidate_removed",
            owner_sub,
            None,
            job_order_id=job_order_id,
            candidate_id=candidate_id,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# PIP-002: Status config (ranked, admin-configurable)
# ---------------------------------------------------------------------------

_DEFAULT_STATUSES = [
    {"status_key": "100_no_contact",         "label": "No Contact",            "rank": 100, "order": 0, "is_submitted": False, "is_placed": False, "is_terminal": False, "color": None},
    {"status_key": "200_contacted",          "label": "Contacted",             "rank": 200, "order": 1, "is_submitted": False, "is_placed": False, "is_terminal": False, "color": None},
    {"status_key": "300_qualifying",         "label": "Qualifying",            "rank": 300, "order": 2, "is_submitted": False, "is_placed": False, "is_terminal": False, "color": None},
    {"status_key": "400_submitted",          "label": "Submitted",             "rank": 400, "order": 3, "is_submitted": True,  "is_placed": False, "is_terminal": False, "color": None},
    {"status_key": "500_interviewing",       "label": "Interviewing",          "rank": 500, "order": 4, "is_submitted": False, "is_placed": False, "is_terminal": False, "color": None},
    {"status_key": "600_offered",            "label": "Offered",               "rank": 600, "order": 5, "is_submitted": False, "is_placed": False, "is_terminal": False, "color": None},
    {"status_key": "700_not_in_consideration", "label": "Not in Consideration","rank": 700, "order": 6, "is_submitted": False, "is_placed": False, "is_terminal": True,  "color": None},
    {"status_key": "800_client_declined",    "label": "Client Declined",       "rank": 800, "order": 7, "is_submitted": False, "is_placed": False, "is_terminal": True,  "color": None},
    {"status_key": "900_placed",             "label": "Placed",                "rank": 900, "order": 8, "is_submitted": False, "is_placed": True,  "is_terminal": True,  "color": None},
]


def _default_status_config() -> PipelineStatusConfigOut:
    return PipelineStatusConfigOut(
        statuses=[PipelineStatusItemOut(**s) for s in _DEFAULT_STATUSES],
        updated_at=None,
        updated_by_sub=None,
    )


def _validate_status_config(data: PipelineStatusConfigIn) -> None:
    """Defence-in-depth re-check (Pydantic validator is the first layer)."""
    keys = [s.status_key for s in data.statuses]
    if len(keys) != len(set(keys)):
        raise HTTPException(400, detail={"code": "invalid_status_config", "reason": "duplicate_status_key"})
    placed_count = sum(1 for s in data.statuses if s.is_placed)
    if placed_count != 1:
        raise HTTPException(400, detail={"code": "invalid_status_config", "reason": "exactly_one_is_placed_required"})
    submitted_count = sum(1 for s in data.statuses if s.is_submitted)
    if submitted_count > 1:
        raise HTTPException(400, detail={"code": "invalid_status_config", "reason": "at_most_one_is_submitted_allowed"})
    if not (1 <= len(data.statuses) <= 20):
        raise HTTPException(400, detail={"code": "invalid_status_config", "reason": "statuses_count_out_of_range"})


def get_status_config() -> PipelineStatusConfigOut:
    """Return the live status config or the built-in default ladder."""
    _require_flag()
    item = T.ats_pipeline.get_item(
        Key={"pk": "PIPELINE_STATUS_CONFIG", "sk": "META"}
    ).get("Item")
    if not item:
        return _default_status_config()
    statuses = json.loads(item["statuses"])
    return PipelineStatusConfigOut(
        statuses=[PipelineStatusItemOut(**s) for s in statuses],
        updated_at=int(item.get("updated_at", 0)) or None,
        updated_by_sub=item.get("updated_by_sub"),
    )


def set_status_config(admin_sub: str, data: PipelineStatusConfigIn) -> PipelineStatusConfigOut:
    """Replace the deployment-wide pipeline status config (admin-only)."""
    _require_flag()
    _validate_status_config(data)
    now = now_ts()
    payload = {
        "pk": "PIPELINE_STATUS_CONFIG",
        "sk": "META",
        "statuses": json.dumps([s.model_dump() for s in data.statuses]),
        "updated_at": now,
        "updated_by_sub": admin_sub,
    }
    T.ats_pipeline.put_item(Item=payload)
    submitted_key = next((s.status_key for s in data.statuses if s.is_submitted), None)
    placed_key = next(s.status_key for s in data.statuses if s.is_placed)
    try:
        from app.services.alerts import audit_event  # type: ignore[import]
        audit_event(
            "ats_status_config.updated",
            admin_sub,
            None,
            status_count=len(data.statuses),
            submitted_key=submitted_key,
            placed_key=placed_key,
        )
    except Exception:
        pass
    return get_status_config()


def resolve_status_rank(status_key: str) -> int:
    """Return the integer rank for a status key from the live config."""
    try:
        config = get_status_config()
        for s in config.statuses:
            if s.status_key == status_key:
                return s.rank
    except Exception:
        pass
    return 0


def _resolve_status_rank_safe(status_key: str) -> int:
    """Like resolve_status_rank but never raises; used at entry-creation time."""
    try:
        return resolve_status_rank(status_key)
    except Exception:
        return 100  # safe default matching "100_no_contact"


# ---------------------------------------------------------------------------
# PIP-003: Status-change transitions
# ---------------------------------------------------------------------------

def change_status(
    owner_sub: str,
    job_order_id: str,
    candidate_id: str,
    new_status: str,
    *,
    note: Optional[str] = None,
    actor_sub: Optional[str] = None,
) -> PipelineEntryOut:
    """Transition a pipeline entry to a new status, log to audit + ACT-009."""
    _require_flag()
    entry = get_pipeline_entry(owner_sub, job_order_id, candidate_id)

    # Validate new_status against the live config
    cfg = get_status_config()
    valid_keys = {s.status_key for s in cfg.statuses}
    if new_status not in valid_keys:
        raise HTTPException(400, detail={"code": "invalid_status", "status_key": new_status})

    # Idempotent no-op
    if entry.status == new_status:
        return entry

    old_status = entry.status
    new_rank = resolve_status_rank(new_status)
    ts = now_ts()

    T.ats_pipeline.update_item(
        Key={"pk": _entry_pk(owner_sub), "sk": _entry_sk(job_order_id, candidate_id)},
        UpdateExpression="SET #s = :s, status_rank = :r, updated_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": new_status, ":r": new_rank, ":ts": ts},
    )

    _sub = actor_sub or owner_sub
    try:
        from app.services.alerts import audit_event  # type: ignore[import]
        audit_event(
            "pipeline.status_changed",
            _sub,
            None,
            job_order_id=job_order_id,
            candidate_id=candidate_id,
            from_status=old_status,
            to_status=new_status,
            note=note,
        )
    except Exception:
        pass

    # Dual ACT-009 timeline write (best-effort)
    activity_id = f"psc_{uuid.uuid4().hex}"
    metadata = {"from_status": old_status, "to_status": new_status, "note": note}
    try:
        from app.services.crm_activity_timeline import record_crm_activity  # type: ignore[import]
        record_crm_activity(
            "candidate", candidate_id, "pipeline_status_change", activity_id,
            _sub, summary=f"Pipeline status changed: {old_status} → {new_status}",
            metadata=metadata,
        )
        record_crm_activity(
            "job_order", job_order_id, "pipeline_status_change", activity_id,
            _sub, summary=f"Candidate status: {old_status} → {new_status}",
            metadata=metadata,
        )
    except Exception:
        pass

    # Return updated entry
    return get_pipeline_entry(owner_sub, job_order_id, candidate_id)


# ---------------------------------------------------------------------------
# PIP-004: Candidate rating (0–5) within a pipeline entry
# ---------------------------------------------------------------------------

def set_rating(
    owner_sub: str,
    job_order_id: str,
    candidate_id: str,
    data: PipelineRatingIn,
) -> PipelineEntryOut:
    """Set (or clear) a 1–5 star rating on a pipeline entry."""
    _require_flag()
    entry = get_pipeline_entry(owner_sub, job_order_id, candidate_id)
    old_rating = entry.rating
    ts = now_ts()

    T.ats_pipeline.update_item(
        Key={"pk": _entry_pk(owner_sub), "sk": _entry_sk(job_order_id, candidate_id)},
        UpdateExpression="SET #r = :r, updated_at = :ts",
        ExpressionAttributeNames={"#r": "rating"},
        ExpressionAttributeValues={":r": data.rating, ":ts": ts},
    )

    try:
        from app.services.alerts import audit_event  # type: ignore[import]
        audit_event(
            "pipeline.rating_set",
            owner_sub,
            None,
            job_order_id=job_order_id,
            candidate_id=candidate_id,
            old_rating=old_rating,
            new_rating=data.rating,
        )
    except Exception:
        pass

    try:
        from app.services.crm_activity_timeline import record_crm_activity  # type: ignore[import]
        activity_id = f"pr_{uuid.uuid4().hex}"
        record_crm_activity(
            "candidate", candidate_id, "pipeline_rating", activity_id,
            owner_sub,
            summary=f"Candidate rating set to {data.rating}",
            metadata={"old_rating": old_rating, "new_rating": data.rating},
        )
    except Exception:
        pass

    return get_pipeline_entry(owner_sub, job_order_id, candidate_id)


# ---------------------------------------------------------------------------
# PIP-006: Placement record
# ---------------------------------------------------------------------------

def record_placement(
    owner_sub: str,
    job_order_id: str,
    candidate_id: str,
    data: PlacementIn,
) -> PlacementOut:
    """Record a formal placement for a pipeline entry.

    Steps:
    1. Flag gate.
    2. Ownership gate (get_pipeline_entry raises 404 for foreign/absent entries).
    3. Resolve the is_placed status key from live config.
    4. Advance pipeline status to the placed key (idempotent if already placed).
    5. Write placement sub-row (conditional; 409 if exists).
    6. Push +1 to job-order placed_count (best-effort via lazy import).
    7. Audit + ACT-009 timeline (best-effort).
    """
    _require_flag()
    # Step 2: ownership gate
    get_pipeline_entry(owner_sub, job_order_id, candidate_id)

    # Step 3: resolve placed status key
    cfg = get_status_config()
    placed_status = next(
        (s.status_key for s in cfg.statuses if s.is_placed),
        "900_placed",  # safe fallback matching the default ladder
    )

    # Step 4: advance to placed (idempotent no-op if already there)
    change_status(owner_sub, job_order_id, candidate_id, placed_status, note="Placement recorded")

    # Step 5: write placement sub-row (conditional)
    placement_id = f"pl_{uuid.uuid4().hex}"
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"USER#{owner_sub}",
        "sk": _placement_sk(job_order_id, candidate_id),
        "placement_id": placement_id,
        "job_order_id": job_order_id,
        "candidate_id": candidate_id,
        "owner_sub": owner_sub,
        "start_date": data.start_date,
        "fee_cents": data.fee_cents,
        "status_at_placement": placed_status,
        "notes": data.notes,
        "created_at": ts,
    }
    try:
        T.ats_pipeline.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(409, detail={"code": "placement_exists"})
        raise

    # Step 6: push placed_count +1 to job order (best-effort)
    try:
        from app.services.ats_job_orders import adjust_placed_count  # type: ignore[import]
        adjust_placed_count(job_order_id, +1)
    except Exception:
        pass  # counter maintenance is best-effort; placement already committed

    # Step 7: audit + ACT-009 timeline (best-effort)
    try:
        from app.services.alerts import audit_event  # type: ignore[import]
        audit_event(
            "pipeline.placed",
            owner_sub,
            None,
            placement_id=placement_id,
            job_order_id=job_order_id,
            candidate_id=candidate_id,
            fee_cents=data.fee_cents,
        )
    except Exception:
        pass

    activity_id = f"pp_{uuid.uuid4().hex}"
    try:
        from app.services.crm_activity_timeline import record_crm_activity  # type: ignore[import]
        meta = {"placement_id": placement_id, "fee_cents": data.fee_cents, "start_date": data.start_date}
        record_crm_activity(
            "candidate", candidate_id, "placement", activity_id,
            owner_sub, summary="Candidate placed", metadata=meta,
        )
        record_crm_activity(
            "job_order", job_order_id, "placement", activity_id,
            owner_sub, summary="Candidate placed", metadata=meta,
        )
    except Exception:
        pass

    return PlacementOut(**_int_fields(item))


def get_placement(owner_sub: str, job_order_id: str, candidate_id: str) -> PlacementOut:
    """Fetch an existing placement record."""
    _require_flag()
    resp = T.ats_pipeline.get_item(
        Key={
            "pk": f"USER#{owner_sub}",
            "sk": _placement_sk(job_order_id, candidate_id),
        }
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, detail={"code": "placement_not_found"})
    return PlacementOut(**_int_fields(item))


# ---------------------------------------------------------------------------
# Utility: coerce Decimal → int for Pydantic models
# ---------------------------------------------------------------------------

def _int_fields(item: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce DynamoDB Decimal values to int/str for Pydantic model hydration."""
    from decimal import Decimal
    out: Dict[str, Any] = {}
    for k, v in item.items():
        if isinstance(v, Decimal):
            out[k] = int(v)
        else:
            out[k] = v
    return out

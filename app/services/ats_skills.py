"""RSK-001/RSK-004 — ATS skill-tag registry + assignment store + skill-based search.

Single-table DynamoDB design (ats_skills table):

  Registry META row:    pk="SKILL#{skill_id}"  sk="META"
  Forward assignment:   pk="SKILL#{skill_id}"  sk="ENTITY#{entity_type}#{entity_id}"
  Reverse index:        pk="ENTITY#{entity_type}#{entity_id}"  sk="SKILL#{skill_id}"

The forward index powers "find all entities with skill X" (RSK-004);
the reverse index powers "list skills on entity Y" (candidate detail view).
"""
from __future__ import annotations

import re
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor

# RSK-004 module-level constants (not env-driven; changing requires index rebuild)
_MAX_SKILL_QUERY_COUNT: int = 10
_MATCH_CANDIDATES_OVERSAMPLE: int = 5
_SKILL_SEARCH_PAGE_LIMIT: int = 500


# ─────────────────────────────────────────────────────────────────────────────
# Normalization
# ─────────────────────────────────────────────────────────────────────────────

def normalize_skill(name: str) -> tuple[str, str]:
    """Return (skill_id, canonical_name).

    canonical_name = name.strip().lower() with internal whitespace collapsed.
    skill_id = re.sub(r"[^a-z0-9]+", "-", canonical_name).strip("-").
    Raises HTTPException(422) if name is empty, exceeds 200 chars, or yields
    a skill_id shorter than 2 characters after normalization.
    """
    if not name or not name.strip():
        raise HTTPException(status_code=422, detail="Skill name required")

    canonical = re.sub(r"\s+", " ", name.strip().lower())

    if len(canonical) > 200:
        raise HTTPException(status_code=422, detail="Skill name too long after normalization")

    skill_id = re.sub(r"[^a-z0-9]+", "-", canonical).strip("-")

    if len(skill_id) < 2:
        raise HTTPException(
            status_code=422,
            detail="Skill name too short after normalization",
        )

    return skill_id, canonical


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────

def upsert_skill(name: str) -> dict:
    """Idempotent registry create-or-return.

    Writes SKILL#{skill_id}/META row using conditional put.
    On ConditionalCheckFailedException (row already exists), silently continues.
    Returns the registry dict.
    """
    skill_id, canonical = normalize_skill(name)
    ts = now_ts()
    item = {
        "pk": f"SKILL#{skill_id}",
        "sk": "META",
        "skill_id": skill_id,
        "name": canonical,
        "name_lc": canonical,
        "usage_count": 0,
        "created_at": ts,
        "GSI1PK": f"NAME_PREFIX#{canonical[:1]}",
        "GSI1SK": canonical,
    }
    try:
        T.ats_skills.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk)",
        )
    except T.ats_skills.meta.client.exceptions.ConditionalCheckFailedException:
        pass
    return item


def get_skill(skill_id: str) -> Optional[dict]:
    """Get SKILL#{skill_id}/META row or None."""
    resp = T.ats_skills.get_item(Key={"pk": f"SKILL#{skill_id}", "sk": "META"})
    return resp.get("Item")


def search_skills(prefix: str, limit: int = 20) -> list[dict]:
    """Autocomplete by prefix using ByName GSI.

    Returns [] for empty/whitespace prefix.
    """
    prefix = (prefix or "").strip().lower()
    if not prefix:
        return []

    bucket = f"NAME_PREFIX#{prefix[:1]}"
    resp = T.ats_skills.query(
        IndexName="ByName",
        KeyConditionExpression=(
            "GSI1PK = :pk AND begins_with(GSI1SK, :prefix)"
        ),
        ExpressionAttributeValues={":pk": bucket, ":prefix": prefix},
        Limit=min(limit, 50),
    )
    return resp.get("Items", [])


# ─────────────────────────────────────────────────────────────────────────────
# Assignment
# ─────────────────────────────────────────────────────────────────────────────

def assign_skill(
    entity_type: str,
    entity_id: str,
    name: str,
    *,
    weight: Optional[int] = None,
    required: Optional[bool] = None,
    actor_sub: str,
) -> dict:
    """Assign skill to entity (idempotent).

    Writes both forward and reverse rows via batch_writer.
    Increments usage_count on META row only for new assignments (not re-assignments).
    Emits audit event.
    """
    from app.services.alerts import audit_event

    skill_id, canonical = normalize_skill(name)
    upsert_skill(name)

    ts = now_ts()
    forward_pk = f"SKILL#{skill_id}"
    forward_sk = f"ENTITY#{entity_type}#{entity_id}"
    reverse_pk = f"ENTITY#{entity_type}#{entity_id}"
    reverse_sk = f"SKILL#{skill_id}"

    # Check for existing forward row to determine if usage_count should be incremented
    existing_resp = T.ats_skills.get_item(
        Key={"pk": forward_pk, "sk": forward_sk}
    )
    is_new = "Item" not in existing_resp

    # Build the forward and reverse items
    forward_item: Dict[str, Any] = {
        "pk": forward_pk,
        "sk": forward_sk,
        "skill_id": skill_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "created_at": ts,
    }
    if weight is not None:
        forward_item["weight"] = weight
    if required is not None:
        forward_item["required"] = required

    reverse_item: Dict[str, Any] = {
        "pk": reverse_pk,
        "sk": reverse_sk,
        "skill_id": skill_id,
        "name": canonical,
        "created_at": ts,
    }
    if weight is not None:
        reverse_item["weight"] = weight
    if required is not None:
        reverse_item["required"] = required

    with T.ats_skills.batch_writer() as batch:
        batch.put_item(Item=forward_item)
        batch.put_item(Item=reverse_item)

    if is_new:
        T.ats_skills.update_item(
            Key={"pk": f"SKILL#{skill_id}", "sk": "META"},
            UpdateExpression="SET usage_count = if_not_exists(usage_count, :z) + :one",
            ExpressionAttributeValues={":z": 0, ":one": 1},
        )

    try:
        audit_event(
            "ats.skill.assigned",
            actor_sub,
            entity_type=entity_type,
            entity_id=entity_id,
            skill_id=skill_id,
        )
    except Exception:
        pass

    result = {
        "skill_id": skill_id,
        "name": canonical,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "weight": weight,
        "required": required,
        "created_at": ts,
    }
    return result


def unassign_skill(
    entity_type: str,
    entity_id: str,
    skill_id: str,
    actor_sub: str,
) -> None:
    """Remove skill from entity.

    Deletes both forward and reverse rows.
    Decrements usage_count with floor 0.
    Emits audit event.
    """
    from app.services.alerts import audit_event

    with T.ats_skills.batch_writer() as batch:
        batch.delete_item(
            Key={
                "pk": f"SKILL#{skill_id}",
                "sk": f"ENTITY#{entity_type}#{entity_id}",
            }
        )
        batch.delete_item(
            Key={
                "pk": f"ENTITY#{entity_type}#{entity_id}",
                "sk": f"SKILL#{skill_id}",
            }
        )

    # Decrement usage_count with floor at 0
    try:
        T.ats_skills.update_item(
            Key={"pk": f"SKILL#{skill_id}", "sk": "META"},
            UpdateExpression="SET usage_count = if_not_exists(usage_count, :z) - :one",
            ConditionExpression="usage_count > :z",
            ExpressionAttributeValues={":z": 0, ":one": 1},
        )
    except Exception:
        pass  # ConditionalCheckFailed → already at 0 or META row absent

    try:
        audit_event(
            "ats.skill.unassigned",
            actor_sub,
            entity_type=entity_type,
            entity_id=entity_id,
            skill_id=skill_id,
        )
    except Exception:
        pass


def list_entity_skills(entity_type: str, entity_id: str) -> list[dict]:
    """List all skills assigned to an entity, from reverse rows.

    No pagination (typical entities have ≤200 skills; single-page response).
    """
    resp = T.ats_skills.query(
        KeyConditionExpression=(
            "pk = :pk AND begins_with(sk, :prefix)"
        ),
        ExpressionAttributeValues={
            ":pk": f"ENTITY#{entity_type}#{entity_id}",
            ":prefix": "SKILL#",
        },
    )
    items = resp.get("Items", [])
    return [
        {
            "skill_id": item.get("skill_id", ""),
            "name": item.get("name", ""),
            "weight": item.get("weight"),
            "required": item.get("required"),
            "created_at": int(item.get("created_at", 0)),
        }
        for item in items
    ]


def list_skill_entities(
    skill_id: str,
    entity_type: Optional[str] = None,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """List entities assigned a given skill (from forward rows).

    Paginated with encode_cursor/decode_cursor.
    Returns {"items": [...], "cursor": str|None}.
    """
    prefix = f"ENTITY#{entity_type}#" if entity_type else "ENTITY#"
    last_key = decode_cursor(cursor) if cursor else None

    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            "pk = :pk AND begins_with(sk, :prefix)"
        ),
        "ExpressionAttributeValues": {
            ":pk": f"SKILL#{skill_id}",
            ":prefix": prefix,
        },
        "Limit": limit,
    }
    if last_key:
        query_kwargs["ExclusiveStartKey"] = last_key

    resp = T.ats_skills.query(**query_kwargs)
    items = resp.get("Items", [])
    lek = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(lek) if lek else None

    return {
        "items": [
            {
                "entity_type": item.get("entity_type", ""),
                "entity_id": item.get("entity_id", ""),
                "skill_id": item.get("skill_id", ""),
                "weight": item.get("weight"),
                "required": item.get("required"),
                "created_at": int(item.get("created_at", 0)),
            }
            for item in items
        ],
        "cursor": next_cursor,
    }


def set_entity_skills(
    entity_type: str,
    entity_id: str,
    names: list[str],
    actor_sub: str,
) -> dict:
    """Bulk replace: diff current vs desired, assign/unassign deltas."""
    current_skills = list_entity_skills(entity_type, entity_id)
    current_ids = {s["skill_id"] for s in current_skills}

    desired_ids: set[str] = set()
    for n in names:
        try:
            sid, _ = normalize_skill(n)
            desired_ids.add(sid)
        except HTTPException:
            pass

    to_add = desired_ids - current_ids
    to_remove = current_ids - desired_ids

    for sid in to_remove:
        try:
            unassign_skill(entity_type, entity_id, sid, actor_sub)
        except Exception:
            pass

    for n in names:
        try:
            sid, _ = normalize_skill(n)
            if sid in to_add:
                assign_skill(entity_type, entity_id, n, actor_sub=actor_sub)
        except Exception:
            pass

    return {"assigned": len(to_add), "unassigned": len(to_remove)}


def set_candidate_skills(candidate_id: str, names: list[str], actor_sub: str) -> dict:
    return set_entity_skills("candidate", candidate_id, names, actor_sub)


def set_job_order_skills(job_order_id: str, names: list[str], actor_sub: str) -> dict:
    return set_entity_skills("job_order", job_order_id, names, actor_sub)


# ─────────────────────────────────────────────────────────────────────────────
# RSK-004: Skill-based search functions
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_entities_for_skill(
    skill_id: str,
    entity_type: str,
    *,
    required_only: bool = False,
) -> set[str]:
    """Fetch all entity IDs assigned a given skill from forward rows.

    Loops via LastEvaluatedKey until exhausted.
    When required_only=True, projects sk+required and filters client-side.
    """
    prefix = f"ENTITY#{entity_type}#"
    proj = "sk, required" if required_only else "sk"
    result: set[str] = set()
    last_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                "pk = :pk AND begins_with(sk, :prefix)"
            ),
            "ExpressionAttributeValues": {
                ":pk": f"SKILL#{skill_id}",
                ":prefix": prefix,
            },
            "ProjectionExpression": proj,
            "Limit": _SKILL_SEARCH_PAGE_LIMIT,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key

        resp = T.ats_skills.query(**kwargs)
        for item in resp.get("Items", []):
            if required_only and not item.get("required"):
                continue
            sk = item.get("sk", "")
            # sk format: ENTITY#{entity_type}#{entity_id}
            parts = sk.split("#", 2)
            if len(parts) == 3:
                result.add(parts[2])

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    return result


def find_candidates_by_skills(
    skill_ids: list[str],
    *,
    match: str = "all",
    owner_sub: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    """Find candidates that have the given skills (AND or OR semantics).

    Returns list of dicts with candidate_id, matched_skill_ids, match_score, etc.
    """
    if match not in ("all", "any"):
        raise ValueError(f"match must be 'all' or 'any', got {match!r}")

    # Normalize and deduplicate skill IDs, cap at _MAX_SKILL_QUERY_COUNT
    normalized: list[str] = []
    seen: set[str] = set()
    for sid in skill_ids:
        try:
            nid, _ = normalize_skill(sid)
            if nid not in seen:
                seen.add(nid)
                normalized.append(nid)
        except HTTPException:
            pass

    if not normalized:
        return []

    if len(normalized) > _MAX_SKILL_QUERY_COUNT:
        raise HTTPException(
            status_code=400,
            detail={"code": "too_many_skills", "msg": f"Max {_MAX_SKILL_QUERY_COUNT} skills per query"},
        )

    # Fetch per-skill entity sets
    per_skill: list[set[str]] = []
    for sid in normalized:
        per_skill.append(_fetch_entities_for_skill(sid, "candidate"))

    # Compute intersection or union
    if match == "all":
        if not per_skill:
            result_ids: set[str] = set()
        else:
            result_ids = per_skill[0]
            for s in per_skill[1:]:
                result_ids = result_ids & s
    else:
        result_ids = set()
        for s in per_skill:
            result_ids = result_ids | s

    if not result_ids:
        return []

    # Compute matched_skill_ids per candidate
    candidate_matched: Dict[str, list[str]] = {}
    for sid, s in zip(normalized, per_skill):
        for cid in s:
            if cid in result_ids:
                candidate_matched.setdefault(cid, []).append(sid)

    # Batch-fetch candidate META rows (lazy import — candidates.py may not exist)
    candidates_list: list[dict] = []
    try:
        from app.core.tables import T as _T
        # Build batch keys (up to limit * oversample to allow owner filtering)
        fetch_ids = list(result_ids)[: limit * _MATCH_CANDIDATES_OVERSAMPLE]
        batch_keys = [
            {"pk": f"CANDIDATE#{cid}", "sk": "META"} for cid in fetch_ids
        ]

        # DynamoDB batch_get_item processes 100 items max per call
        meta_by_id: Dict[str, dict] = {}
        for i in range(0, len(batch_keys), 100):
            chunk = batch_keys[i : i + 100]
            # We need the actual table name
            try:
                tbl_name = _T.candidates.name  # type: ignore[attr-defined]
                resp = _T.candidates.meta.client.batch_get_item(  # type: ignore[attr-defined]
                    RequestItems={tbl_name: {"Keys": chunk}}
                )
                for row in resp.get("Responses", {}).get(tbl_name, []):
                    cid = row.get("pk", "").removeprefix("CANDIDATE#")
                    meta_by_id[cid] = row
            except Exception:
                pass

        for cid in fetch_ids:
            meta = meta_by_id.get(cid, {})
            if owner_sub and meta.get("owner_sub") != owner_sub:
                continue
            candidates_list.append({
                "candidate_id": cid,
                "name": f"{meta.get('first_name', '')} {meta.get('last_name', '')}".strip()
                        or meta.get("name", "Unknown"),
                "email": meta.get("email"),
                "owner_sub": meta.get("owner_sub"),
                "matched_skill_ids": candidate_matched.get(cid, []),
                "match_score": len(candidate_matched.get(cid, [])) / max(len(normalized), 1),
                "created_at": int(meta.get("created_at", 0)),
            })
            if len(candidates_list) >= limit:
                break
    except Exception:
        # If candidates table doesn't exist yet, return stubs
        for cid in list(result_ids)[:limit]:
            candidates_list.append({
                "candidate_id": cid,
                "name": "",
                "email": None,
                "owner_sub": None,
                "matched_skill_ids": candidate_matched.get(cid, []),
                "match_score": len(candidate_matched.get(cid, [])) / max(len(normalized), 1),
                "created_at": 0,
            })

    candidates_list.sort(key=lambda c: c.get("created_at", 0), reverse=True)
    return candidates_list[:limit]


def find_job_orders_by_skills(
    skill_ids: list[str],
    *,
    match: str = "all",
    required_only: bool = False,
    limit: int = 50,
) -> list[dict]:
    """Find job orders that have the given skills."""
    if match not in ("all", "any"):
        raise ValueError(f"match must be 'all' or 'any', got {match!r}")

    normalized: list[str] = []
    seen: set[str] = set()
    for sid in skill_ids:
        try:
            nid, _ = normalize_skill(sid)
            if nid not in seen:
                seen.add(nid)
                normalized.append(nid)
        except HTTPException:
            pass

    if not normalized:
        return []

    if len(normalized) > _MAX_SKILL_QUERY_COUNT:
        raise HTTPException(
            status_code=400,
            detail={"code": "too_many_skills", "msg": f"Max {_MAX_SKILL_QUERY_COUNT} skills per query"},
        )

    per_skill = [
        _fetch_entities_for_skill(sid, "job_order", required_only=required_only)
        for sid in normalized
    ]

    if match == "all":
        if not per_skill:
            result_ids: set[str] = set()
        else:
            result_ids = per_skill[0]
            for s in per_skill[1:]:
                result_ids = result_ids & s
    else:
        result_ids = set()
        for s in per_skill:
            result_ids = result_ids | s

    if not result_ids:
        return []

    job_matched: Dict[str, list[str]] = {}
    for sid, s in zip(normalized, per_skill):
        for jid in s:
            if jid in result_ids:
                job_matched.setdefault(jid, []).append(sid)

    # Fetch job order META rows (lazy import)
    jobs_list: list[dict] = []
    for jid in list(result_ids)[:limit]:
        jobs_list.append({
            "job_order_id": jid,
            "title": "",
            "status": "unknown",
            "matched_skill_ids": job_matched.get(jid, []),
            "match_score": len(job_matched.get(jid, [])) / max(len(normalized), 1),
        })

    # Try to hydrate from job_orders table
    try:
        from app.core.tables import T as _T
        tbl_name = _T.job_orders.name  # type: ignore[attr-defined]
        for item in jobs_list:
            jid = item["job_order_id"]
            resp = _T.job_orders.query(  # type: ignore[attr-defined]
                IndexName="GSI_DIRECT",
                KeyConditionExpression="job_id = :jid",
                ExpressionAttributeValues={":jid": jid},
                Limit=1,
            )
            rows = resp.get("Items", [])
            if rows:
                item["title"] = rows[0].get("title", "")
                item["status"] = rows[0].get("status", "unknown")
    except Exception:
        pass

    jobs_list.sort(key=lambda j: j["match_score"], reverse=True)
    return jobs_list[:limit]


def match_candidates_to_job_order(
    job_order_id: str,
    *,
    actor_sub: str,
    limit: int = 50,
) -> list[dict]:
    """Score and rank candidates by how well they match a job order's required skills."""
    from app.services.alerts import audit_event

    # Fetch job order's required skills
    all_skills = list_entity_skills("job_order", job_order_id)
    required_skill_ids = [s["skill_id"] for s in all_skills if s.get("required")]

    if not required_skill_ids:
        return []

    # Broad over-fetch with "any" semantics
    pool = find_candidates_by_skills(
        required_skill_ids,
        match="any",
        limit=limit * _MATCH_CANDIDATES_OVERSAMPLE,
    )

    # Score each candidate
    required_set = set(required_skill_ids)
    for candidate in pool:
        matched = set(candidate.get("matched_skill_ids", [])) & required_set
        candidate["matched_skill_ids"] = list(matched)
        candidate["match_score"] = len(matched) / len(required_set)

    # Sort by match_score desc, then created_at desc
    pool.sort(key=lambda c: (c["match_score"], c.get("created_at", 0)), reverse=True)
    result = pool[:limit]

    try:
        audit_event(
            "ats.skill.match_candidates",
            actor_sub,
            job_order_id=job_order_id,
            candidate_count=len(result),
            top_score=result[0]["match_score"] if result else 0,
        )
    except Exception:
        pass

    return result

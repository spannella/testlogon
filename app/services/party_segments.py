"""Party segment management for marketing campaigns (MKT-008)."""
from __future__ import annotations

import hashlib
from typing import Any, Optional

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import PartySegmentCreateIn, PartySegmentUpdateIn, SegmentPredicate

# Valid attributes and operators
VALID_ATTRIBUTES: frozenset = frozenset({
    "subscription_tier", "total_spend_cents", "profile_country", "profile_city",
    "display_name", "first_name", "last_name", "gender", "location", "locale",
    "birthday", "has_active_subscription", "subscription_status",
    "order_count", "total_paid_cents", "last_order_at",
})

VALID_OPERATORS: frozenset = frozenset({
    "eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in",
})

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


def _make_segment_id(owner_id: str, name: str, ts: int) -> str:
    created_bucket = (ts // 3600) * 3600
    raw = f"{owner_id}\x00{name}\x00{created_bucket}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def _make_snap_id(segment_id: str, snap_ts: int) -> str:
    raw = f"{segment_id}\x00{snap_ts}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def _validate_predicates(predicates: list[SegmentPredicate]) -> None:
    for pred in predicates:
        if pred.attribute not in VALID_ATTRIBUTES:
            raise ValueError(f"Unknown attribute: {pred.attribute!r}")
        if pred.operator not in VALID_OPERATORS:
            raise ValueError(f"Unknown operator: {pred.operator!r}")


def _is_opted_out(party_id: str) -> bool:
    try:
        from app.services.cart_reminders import is_user_opted_out
        return is_user_opted_out(party_id)
    except (ImportError, Exception):
        return False


def _match_predicate(value: Any, operator: str, target: Any) -> bool:
    """Apply a single predicate operator."""
    try:
        if operator == "eq":
            return value == target
        elif operator == "neq":
            return value != target
        elif operator == "gt":
            return float(value) > float(target)
        elif operator == "gte":
            return float(value) >= float(target)
        elif operator == "lt":
            return float(value) < float(target)
        elif operator == "lte":
            return float(value) <= float(target)
        elif operator == "in":
            return value in (target if isinstance(target, (list, set)) else [target])
        elif operator == "not_in":
            return value not in (target if isinstance(target, (list, set)) else [target])
    except (TypeError, ValueError):
        pass
    return False


def _get_party_attribute(party_id: str, attribute: str) -> Any:
    """Retrieve a single attribute value for a party from the appropriate source."""
    # Profile attributes
    profile_attrs = {"display_name", "first_name", "last_name", "gender", "location",
                     "locale", "birthday", "profile_country", "profile_city"}
    if attribute in profile_attrs:
        try:
            from app.services.profile import get_profile
            profile = get_profile(party_id)
            if attribute == "profile_country":
                return profile.get("country") or profile.get("location")
            if attribute == "profile_city":
                return profile.get("city")
            return profile.get(attribute)
        except (ImportError, Exception):
            return None

    # Subscription attributes
    if attribute in ("has_active_subscription", "subscription_status"):
        try:
            resp = T.subscriptions.query(
                KeyConditionExpression=Key("pk").eq(f"SUBSCRIBER#{party_id}"),
                Limit=10,
            )
            subs = [s for s in resp.get("Items", []) if s.get("sk", "").startswith("SUB#")]
            active = [s for s in subs if s.get("status") in ("active", "past_due", "trialing")]
            if attribute == "has_active_subscription":
                return bool(active)
            if attribute == "subscription_status":
                return active[0].get("status") if active else None
        except Exception:
            return None

    # Order attributes
    if attribute in ("order_count", "total_spend_cents", "last_order_at"):
        try:
            resp = T.orders.query(
                IndexName="GSI_USER",
                KeyConditionExpression=Key("user_id").eq(party_id),
                Limit=500,
            )
            orders = resp.get("Items", [])
            if attribute == "order_count":
                return len(orders)
            if attribute == "total_spend_cents":
                return sum(int(o.get("amount_cents") or 0) for o in orders)
            if attribute == "last_order_at":
                dates = [o.get("created_at") for o in orders if o.get("created_at")]
                return max(dates) if dates else None
        except Exception:
            return None

    # Billing attributes
    if attribute == "total_paid_cents":
        try:
            from app.services.billing_shared import user_pk, ddb_query_pk
            items = ddb_query_pk(T.billing, user_pk(party_id))
            total = 0
            for row in items:
                sk = row.get("sk", "")
                if sk.startswith("LEDGER#"):
                    entry_type = row.get("entry_type", row.get("type", ""))
                    if row.get("state") == "settled" and entry_type in (
                        "charge", "debit", "purchase"
                    ):
                        total += int(row.get("amount_cents") or 0)
            return total
        except (ImportError, Exception):
            return None

    return None


def _evaluate_predicates_for_party(party_id: str, predicates: list[dict]) -> bool:
    """Check all predicates for a single party (AND logic)."""
    for pred in predicates:
        attr = pred.get("attribute") or (pred["attribute"] if isinstance(pred, dict) else pred.attribute)
        op = pred.get("operator") or (pred["operator"] if isinstance(pred, dict) else pred.operator)
        val_target = pred.get("value") if isinstance(pred, dict) else pred.value
        current_val = _get_party_attribute(party_id, attr)
        if not _match_predicate(current_val, op, val_target):
            return False
    return True


def _get_candidate_party_ids(
    predicates: list[dict],
    candidate_source: Optional[str],
) -> list[str]:
    """
    Return a list of candidate party_ids to evaluate.
    Controlled by candidate_source to avoid unbounded full-table scans.
    """
    if candidate_source and candidate_source.startswith("subscribers_of:"):
        creator_id = candidate_source[len("subscribers_of:"):]
        try:
            resp = T.subscriptions.query(
                KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}"),
                Limit=500,
            )
            subs = resp.get("Items", [])
            return [s.get("subscriber_id") or s.get("sk", "").lstrip("SUB#") for s in subs
                    if s.get("subscriber_id") or s.get("sk", "").startswith("SUB#")]
        except Exception:
            return []
    elif candidate_source and candidate_source.startswith("list:"):
        list_id = candidate_source[5:]
        try:
            from app.services.marketing_lists import list_members
            members = list_members(list_id)
            return [m["party_id"] for m in members if m.get("party_id")]
        except (ImportError, Exception):
            return []
    else:
        # No valid source — return empty list (avoid full scans)
        return []


# ---------------------------------------------------------------------------
# Segment CRUD
# ---------------------------------------------------------------------------


def create_segment(owner_id: str, data: PartySegmentCreateIn) -> dict:
    """Create a party segment (idempotent within the hour bucket)."""
    _require_enabled()
    _validate_predicates(data.predicates)

    ts = now_ts()
    segment_id = _make_segment_id(owner_id, data.name, ts)

    predicates_raw = [p.model_dump() for p in data.predicates]

    meta: dict = {
        "pk": f"OWNER#{owner_id}",
        "sk": f"SEGMENT#{segment_id}",
        "segment_id": segment_id,
        "owner_id": owner_id,
        "name": data.name,
        "predicates": predicates_raw,
        "created_at": ts,
        "updated_at": ts,
    }
    if data.description is not None:
        meta["description"] = data.description
    if data.candidate_source is not None:
        meta["candidate_source"] = data.candidate_source

    try:
        T.party_segments.put_item(
            Item=meta,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            existing = get_segment(owner_id, segment_id)
            return existing if existing is not None else meta
        raise

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.segment.created", owner_id,
                    segment_id=segment_id, name=data.name)
    except Exception:
        pass

    return meta


def get_segment(owner_id: str, segment_id: str) -> Optional[dict]:
    """Return a segment META item or None."""
    resp = T.party_segments.get_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"SEGMENT#{segment_id}"}
    )
    return resp.get("Item")


def list_segments(owner_id: str) -> list[dict]:
    """Return all segments for an owner."""
    resp = T.party_segments.query(
        IndexName="ByOwnerCreatedAt",
        KeyConditionExpression=Key("owner_id").eq(owner_id),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def update_segment(
    owner_id: str, segment_id: str, data: PartySegmentUpdateIn
) -> dict:
    """Update segment predicates / name."""
    seg = get_segment(owner_id, segment_id)
    if seg is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Segment not found")

    _require_enabled()

    if data.predicates is not None:
        _validate_predicates(data.predicates)

    updates: dict = {}
    if data.name is not None:
        updates["name"] = data.name
    if data.description is not None:
        updates["description"] = data.description
    if data.predicates is not None:
        updates["predicates"] = [p.model_dump() for p in data.predicates]
    if data.candidate_source is not None:
        updates["candidate_source"] = data.candidate_source

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

        T.party_segments.update_item(
            Key={"pk": f"OWNER#{owner_id}", "sk": f"SEGMENT#{segment_id}"},
            UpdateExpression="SET " + ", ".join(set_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )

    return get_segment(owner_id, segment_id) or seg


def delete_segment(owner_id: str, segment_id: str) -> None:
    """Delete a segment META row."""
    _require_enabled()
    T.party_segments.delete_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"SEGMENT#{segment_id}"}
    )


# ---------------------------------------------------------------------------
# Evaluation + snapshotting
# ---------------------------------------------------------------------------


def evaluate_segment(segment_id: str, owner_id: str) -> list[dict]:
    """
    Live evaluation — returns matching parties. Opted-out parties are included
    with opted_out=True so the caller can see the full count.

    Returns list of {party_id, opted_out} dicts.
    """
    seg = get_segment(owner_id, segment_id)
    if seg is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Segment not found")

    predicates_raw: list[dict] = seg.get("predicates") or []
    candidate_source: Optional[str] = seg.get("candidate_source")

    # Validate predicates list
    for pred in predicates_raw:
        attr = pred.get("attribute", "")
        op = pred.get("operator", "")
        if attr not in VALID_ATTRIBUTES:
            raise ValueError(f"Unknown segment attribute: {attr!r}")
        if op not in VALID_OPERATORS:
            raise ValueError(f"Unknown segment operator: {op!r}")

    candidates = _get_candidate_party_ids(predicates_raw, candidate_source)

    results = []
    for party_id in candidates:
        if _evaluate_predicates_for_party(party_id, predicates_raw):
            opted_out = _is_opted_out(party_id)
            results.append({"party_id": party_id, "opted_out": opted_out})

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.segment.evaluated", owner_id,
                    segment_id=segment_id, match_count=len(results))
    except Exception:
        pass

    return results


def snapshot_segment(owner_id: str, segment_id: str) -> dict:
    """
    Materialize a point-in-time membership snapshot.
    Returns the snap_id and snap_ts. Prior snapshots are immutable.
    """
    seg = get_segment(owner_id, segment_id)
    if seg is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Segment not found")

    _require_enabled()

    # Evaluate live membership
    members = evaluate_segment(segment_id, owner_id)
    snap_ts = now_ts()
    snap_id = _make_snap_id(segment_id, snap_ts)

    opted_out_count = 0

    # Write snapshot META
    snap_meta = {
        "pk": f"SEGMENT#{segment_id}",
        "sk": f"SNAP#{snap_ts}",
        "segment_id": segment_id,
        "snap_ts": snap_ts,
        "snap_id": snap_id,
        "party_count": len(members),
        "opted_out_count": sum(1 for m in members if m.get("opted_out")),
        "created_at": snap_ts,
    }
    T.party_segments.put_item(Item=snap_meta)

    # Write snapshot member rows
    for m in members:
        party_id = m["party_id"]
        opted_out = m.get("opted_out", False)
        member_row = {
            "pk": f"SEGMENT#{segment_id}#SNAP#{snap_id}",
            "sk": f"PARTY#{party_id}",
            "party_id": party_id,
            "snap_id": snap_id,
            "opted_out": opted_out,
            "snapped_at": snap_ts,
        }
        T.party_segments.put_item(Item=member_row)

    try:
        from app.services.alerts import audit_event
        audit_event("marketing.segment.snapshotted", owner_id,
                    segment_id=segment_id, snap_id=snap_id, party_count=len(members))
    except Exception:
        pass

    return {
        "segment_id": segment_id,
        "snap_id": snap_id,
        "snap_ts": snap_ts,
        "party_count": len(members),
    }


def list_snapshots(
    segment_id: str,
    owner_id: str,
    limit: int = 10,
) -> list[dict]:
    """Return snapshots for a segment, newest first."""
    resp = T.party_segments.query(
        IndexName="BySegmentSnapTs",
        KeyConditionExpression=Key("segment_id").eq(segment_id),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


def list_snapshot_members(
    segment_id: str,
    snap_id: str,
    owner_id: str,
    include_opted_out: bool = True,
    limit: int = 200,
) -> dict:
    """Return members of a specific snapshot."""
    pk = f"SEGMENT#{segment_id}#SNAP#{snap_id}"

    kwargs: dict = {
        "KeyConditionExpression": Key("pk").eq(pk),
        "Limit": limit,
    }
    if not include_opted_out:
        kwargs["FilterExpression"] = Attr("opted_out").eq(False)

    resp = T.party_segments.query(**kwargs)
    items = resp.get("Items", [])
    return {"members": items, "cursor": None}

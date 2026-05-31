"""Product Manager Agent service (AGENT-013).

The PM Agent is a *schedule-driven* agent type that reviews the live application,
analyzes UX flows / feature gaps / support tickets, and generates feature ideas
for the platform owner to approve or reject. Approved ideas become
``type:product_request`` tickets; rejected ideas store a reason and feed a
per-category preference-learning model.

This module owns:

* ``pm_config`` storage/validation on the ``agent_types`` table (reused).
* Feature idea CRUD + the idea lifecycle state machine
  (pending -> approved | rejected -> archived) on the ``agent_feature_ideas`` table.
* Per-category preference learning on the ``agent_preference_learning`` table.
* Review context assembly + a deterministic, mockable review lifecycle.

Real browsing/execution is gated behind ``S.pm_agent_execute_commands``. When
disabled (the default, and always in E2E) the review is generated in-memory so
tests are deterministic.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services import tickets as tickets_svc

logger = logging.getLogger("app.agent_pm")

PM_AGENT_TYPE = "product_manager"

IDEA_CATEGORIES = ("ux", "feature", "performance", "integration", "monetization", "accessibility")
IDEA_PRIORITIES = ("critical", "high", "medium", "low")
IDEA_STATUSES = ("pending", "approved", "rejected", "archived")

_REVIEW_FREQUENCIES = ("daily", "weekly", "biweekly")
_REVIEW_DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")

_TITLE_MAX = 200
_DESCRIPTION_MAX = 5000
_USER_IMPACT_MAX = 1000
_MOCKUP_MAX = 2000
_REASON_MAX = 1000
_MAX_COMPETITOR_URLS = 10

_PM_CONFIG_FIELDS = (
    "review_frequency",
    "review_day",
    "review_hour_utc",
    "focus_areas",
    "competitor_urls",
    "max_ideas_per_review",
    "analyze_support_tickets",
    "support_ticket_lookback_days",
    "app_url",
)


# ---------------------------------------------------------------------------
# Table bootstrap (idempotent; tables are additive)
# ---------------------------------------------------------------------------

_BOOTSTRAPPED = False


def ensure_tables() -> None:
    """Create the PM tables (and the reused agent_types table) on first use if absent."""
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    client = ddb.meta.client
    specs: List[Dict[str, Any]] = [
        {
            "TableName": S.agent_types_table_name,
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            "BillingMode": "PAY_PER_REQUEST",
        },
        {
            "TableName": S.agent_feature_ideas_table_name,
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "N"},
            ],
            "GlobalSecondaryIndexes": [
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI2",
                    "KeySchema": [
                        {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            "BillingMode": "PAY_PER_REQUEST",
        },
        {
            "TableName": S.agent_preference_learning_table_name,
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            "BillingMode": "PAY_PER_REQUEST",
        },
    ]
    for spec in specs:
        try:
            client.create_table(**spec)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ResourceInUseException",):
                logger.warning("ensure_tables: could not create %s: %s", spec["TableName"], exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ensure_tables: %s create error: %s", spec["TableName"], exc)
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Keys / helpers
# ---------------------------------------------------------------------------


def _user_pk(user_id: str) -> str:
    return f"USER#{user_id}"


def _idea_sk(idea_id: str) -> str:
    return f"IDEA#{idea_id}"


def _pref_sk(category: str) -> str:
    return f"PREF#{category}"


def _gsi1pk(user_id: str, status: str) -> str:
    return f"USER#{user_id}#STATUS#{status}"


def _gsi2pk(agent_id: str) -> str:
    return f"AGENT#{agent_id}"


def _type_pk(type_id: str) -> str:
    return f"TYPE#{type_id}"


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _loads(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class PmValidationError(Exception):
    """Raised when idea / config input fails validation."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def validate_idea_fields(
    *,
    title: str,
    description: str,
    category: str,
    priority_suggestion: str,
    user_impact: str,
) -> None:
    if category not in IDEA_CATEGORIES:
        raise PmValidationError("INVALID_CATEGORY", f"Invalid category: {category}")
    if priority_suggestion not in IDEA_PRIORITIES:
        raise PmValidationError("INVALID_PRIORITY", f"Invalid priority: {priority_suggestion}")
    if not (title or "").strip():
        raise PmValidationError("INVALID_TITLE", "Title is required")
    if len(title) > _TITLE_MAX:
        raise PmValidationError("INVALID_TITLE", f"Title exceeds {_TITLE_MAX} chars")
    if len(description or "") > _DESCRIPTION_MAX:
        raise PmValidationError("INVALID_DESCRIPTION", f"Description exceeds {_DESCRIPTION_MAX} chars")
    if len(user_impact or "") > _USER_IMPACT_MAX:
        raise PmValidationError("INVALID_USER_IMPACT", f"User impact exceeds {_USER_IMPACT_MAX} chars")


def validate_pm_config(config: Dict[str, Any]) -> List[str]:
    """Return list of validation errors (empty = valid)."""
    errors: List[str] = []
    freq = config.get("review_frequency")
    if freq is not None and freq not in _REVIEW_FREQUENCIES:
        errors.append("review_frequency must be daily, weekly, or biweekly")
    day = config.get("review_day")
    if day is not None and day not in _REVIEW_DAYS:
        errors.append("review_day must be a weekday (monday-friday)")
    hour = config.get("review_hour_utc")
    if hour is not None and not (0 <= _to_int(hour, -1) <= 23):
        errors.append("review_hour_utc must be between 0 and 23")
    max_ideas = config.get("max_ideas_per_review")
    if max_ideas is not None and not (1 <= _to_int(max_ideas, 0) <= 20):
        errors.append("max_ideas_per_review must be between 1 and 20")
    lookback = config.get("support_ticket_lookback_days")
    if lookback is not None and not (1 <= _to_int(lookback, 0) <= 90):
        errors.append("support_ticket_lookback_days must be between 1 and 90")
    urls = config.get("competitor_urls")
    if urls is not None:
        if len(urls) > _MAX_COMPETITOR_URLS:
            errors.append(f"At most {_MAX_COMPETITOR_URLS} competitor URLs allowed")
        for entry in urls:
            url = (entry or {}).get("url", "") if isinstance(entry, dict) else ""
            if not url.startswith("https://"):
                errors.append("Competitor URLs must be HTTPS")
                break
            if "localhost" in url or "127.0.0.1" in url or "://10." in url:
                errors.append("Competitor URLs must not target internal hosts (SSRF)")
                break
    return errors


# ---------------------------------------------------------------------------
# PM Agent configuration (on agent_types table)
# ---------------------------------------------------------------------------


_DEFAULT_PM_CONFIG: Dict[str, Any] = {
    "review_frequency": "weekly",
    "review_day": "monday",
    "review_hour_utc": 9,
    "focus_areas": ["messaging", "billing", "ux", "feed"],
    "competitor_urls": [],
    "max_ideas_per_review": 5,
    "analyze_support_tickets": True,
    "support_ticket_lookback_days": 30,
    "app_url": "http://localhost:3000",
}


def _normalize_pm_config(config: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = dict(_DEFAULT_PM_CONFIG)
    for key in _PM_CONFIG_FIELDS:
        if key in config and config[key] is not None:
            out[key] = config[key]
    out["review_hour_utc"] = _to_int(out.get("review_hour_utc"), 9)
    out["max_ideas_per_review"] = _to_int(out.get("max_ideas_per_review"), 5)
    out["support_ticket_lookback_days"] = _to_int(out.get("support_ticket_lookback_days"), 30)
    out["analyze_support_tickets"] = bool(out.get("analyze_support_tickets", True))
    return out


def get_pm_config(*, user_id: str) -> Dict[str, Any]:
    """Fetch PM config for a user. Returns defaults if none configured."""
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _type_pk(f"pm_{user_id}"), "sk": "PM_CONFIG"})
    item = resp.get("Item")
    if not item or not item.get("pm_config"):
        return dict(_DEFAULT_PM_CONFIG)
    return _normalize_pm_config(item["pm_config"])


def update_pm_config(*, user_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and persist PM config for a user (merging with existing)."""
    ensure_tables()
    errors = validate_pm_config(config)
    if errors:
        raise PmValidationError("CONFIG_INVALID", errors[0])
    current = get_pm_config(user_id=user_id)
    merged = dict(current)
    for key in _PM_CONFIG_FIELDS:
        if key in config and config[key] is not None:
            merged[key] = config[key]
    normalized = _normalize_pm_config(merged)
    ts = now_ts()
    T.agent_types.put_item(
        Item={
            "pk": _type_pk(f"pm_{user_id}"),
            "sk": "PM_CONFIG",
            "agent_type": PM_AGENT_TYPE,
            "owner_sub": user_id,
            "pm_config": normalized,
            "updated_at": ts,
        }
    )
    return normalized


# ---------------------------------------------------------------------------
# Feature idea serialization
# ---------------------------------------------------------------------------


def _idea_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "idea_id": item.get("idea_id", ""),
        "user_id": item.get("user_id", ""),
        "agent_id": item.get("agent_id", ""),
        "title": item.get("title", ""),
        "description": item.get("description", ""),
        "category": item.get("category", "feature"),
        "priority_suggestion": item.get("priority_suggestion", "medium"),
        "user_impact": item.get("user_impact", ""),
        "mockup_description": item.get("mockup_description"),
        "evidence": _loads(item.get("evidence")),
        "competitor_refs": _loads(item.get("competitor_refs")),
        "support_ticket_refs": _loads(item.get("support_ticket_refs")),
        "status": item.get("status", "pending"),
        "rejection_reason": item.get("rejection_reason"),
        "created_ticket_id": item.get("created_ticket_id"),
        "created_at": _to_int(item.get("created_at")),
        "reviewed_at": _to_int(item.get("reviewed_at")) or None,
    }


# ---------------------------------------------------------------------------
# Feature idea CRUD
# ---------------------------------------------------------------------------


def create_feature_idea(
    *,
    user_id: str,
    agent_id: str,
    worker_id: str = "",
    title: str,
    description: str,
    category: str,
    priority_suggestion: str,
    user_impact: str,
    mockup_description: Optional[str] = None,
    evidence: Optional[List[dict]] = None,
    competitor_refs: Optional[List[dict]] = None,
    support_ticket_refs: Optional[List[str]] = None,
    enforce_max: bool = False,
) -> Dict[str, Any]:
    """Create a new feature idea from a PM Agent review session."""
    ensure_tables()
    validate_idea_fields(
        title=title,
        description=description,
        category=category,
        priority_suggestion=priority_suggestion,
        user_impact=user_impact,
    )
    if enforce_max:
        cfg = get_pm_config(user_id=user_id)
        max_ideas = _to_int(cfg.get("max_ideas_per_review"), 5)
        pending = list_feature_ideas(user_id=user_id, status="pending", limit=100).get("ideas", [])
        agent_pending = [i for i in pending if i.get("agent_id") == agent_id]
        if len(agent_pending) >= max_ideas:
            raise PmValidationError(
                "MAX_IDEAS_EXCEEDED",
                f"Cannot create more than {max_ideas} ideas per review",
            )
    idea_id = f"idea_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _user_pk(user_id),
        "sk": _idea_sk(idea_id),
        "idea_id": idea_id,
        "user_id": user_id,
        "agent_id": agent_id,
        "worker_id": worker_id,
        "title": title,
        "description": description,
        "category": category,
        "priority_suggestion": priority_suggestion,
        "user_impact": user_impact,
        "status": "pending",
        "created_at": ts,
        "GSI1PK": _gsi1pk(user_id, "pending"),
        "GSI1SK": ts,
        "GSI2PK": _gsi2pk(agent_id),
        "GSI2SK": ts,
    }
    if mockup_description is not None:
        item["mockup_description"] = mockup_description
    if evidence is not None:
        item["evidence"] = json.dumps(evidence)
    if competitor_refs is not None:
        item["competitor_refs"] = json.dumps(competitor_refs)
    if support_ticket_refs is not None:
        item["support_ticket_refs"] = json.dumps(support_ticket_refs)
    T.agent_feature_ideas.put_item(Item=item)
    _bump_preference(user_id=user_id, category=category, field="total_suggested")
    return _idea_to_out(item)


def get_feature_idea(*, user_id: str, idea_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_feature_ideas.get_item(Key={"pk": _user_pk(user_id), "sk": _idea_sk(idea_id)})
    item = resp.get("Item")
    if not item:
        return None
    return _idea_to_out(item)


def _get_idea_raw(*, user_id: str, idea_id: str) -> Optional[Dict[str, Any]]:
    resp = T.agent_feature_ideas.get_item(Key={"pk": _user_pk(user_id), "sk": _idea_sk(idea_id)})
    return resp.get("Item")


def list_feature_ideas(
    *, user_id: str, status: Optional[str] = None, limit: int = 25, cursor: Optional[str] = None
) -> Dict[str, Any]:
    """List feature ideas for a user, optionally filtered by status. Newest first."""
    ensure_tables()
    limit = max(1, min(int(limit or 25), 100))
    start_key = decode_cursor(cursor) if cursor else None
    query_kwargs: Dict[str, Any] = {
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key
    if status:
        if status not in IDEA_STATUSES:
            raise PmValidationError("INVALID_STATUS", f"Invalid status: {status}")
        query_kwargs["IndexName"] = "GSI1"
        query_kwargs["KeyConditionExpression"] = "GSI1PK = :pk"
        query_kwargs["ExpressionAttributeValues"] = {":pk": _gsi1pk(user_id, status)}
    else:
        query_kwargs["KeyConditionExpression"] = "pk = :pk AND begins_with(sk, :sk)"
        query_kwargs["ExpressionAttributeValues"] = {":pk": _user_pk(user_id), ":sk": "IDEA#"}
    resp = T.agent_feature_ideas.query(**query_kwargs)
    ideas = [_idea_to_out(it) for it in resp.get("Items", [])]
    if not status:
        ideas.sort(key=lambda i: i["created_at"], reverse=True)
    return {
        "ideas": ideas,
        "next_cursor": encode_cursor(resp.get("LastEvaluatedKey")),
    }


# ---------------------------------------------------------------------------
# Idea lifecycle state machine
# ---------------------------------------------------------------------------


def approve_idea(*, user_id: str, idea_id: str) -> Dict[str, Any]:
    """Approve a pending feature idea, creating a product_request ticket."""
    ensure_tables()
    raw = _get_idea_raw(user_id=user_id, idea_id=idea_id)
    if not raw:
        raise PmValidationError("IDEA_NOT_FOUND", "Feature idea not found")
    if raw.get("status") != "pending":
        raise PmValidationError(
            "INVALID_STATUS_TRANSITION",
            f"Cannot approve an idea with status: {raw.get('status')}",
        )
    ts = now_ts()
    created_ticket_id = ""
    if S.pm_auto_ticket_creation:
        category = raw.get("category", "feature")
        priority = raw.get("priority_suggestion", "medium")
        ticket = tickets_svc.STORE.create_ticket(
            owner_sub=user_id,
            subject=str(raw.get("title", ""))[:_TITLE_MAX],
            description=str(raw.get("description", "")),
            category="product_request",
            labels=[
                "type:product_request",
                f"category:{category}",
                f"priority:{priority}",
            ],
            metadata={
                "source": "pm_agent",
                "idea_id": idea_id,
                "agent_id": raw.get("agent_id", ""),
                "user_impact": raw.get("user_impact", ""),
            },
        )
        created_ticket_id = ticket.get("ticket_id", "")
    update_expr = (
        "SET #st = :s, reviewed_at = :ts, GSI1PK = :g1, created_ticket_id = :tid"
    )
    T.agent_feature_ideas.update_item(
        Key={"pk": _user_pk(user_id), "sk": _idea_sk(idea_id)},
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":s": "approved",
            ":ts": ts,
            ":g1": _gsi1pk(user_id, "approved"),
            ":tid": created_ticket_id,
        },
    )
    _bump_preference(user_id=user_id, category=raw.get("category", "feature"), field="total_approved")
    out = _get_idea_raw(user_id=user_id, idea_id=idea_id)
    return _idea_to_out(out or raw)


def reject_idea(*, user_id: str, idea_id: str, reason: str) -> Dict[str, Any]:
    """Reject a pending feature idea with a reason."""
    ensure_tables()
    if not (reason or "").strip():
        raise PmValidationError("REASON_REQUIRED", "Rejection reason is required")
    raw = _get_idea_raw(user_id=user_id, idea_id=idea_id)
    if not raw:
        raise PmValidationError("IDEA_NOT_FOUND", "Feature idea not found")
    if raw.get("status") != "pending":
        raise PmValidationError(
            "INVALID_STATUS_TRANSITION",
            f"Cannot reject an idea with status: {raw.get('status')}",
        )
    ts = now_ts()
    T.agent_feature_ideas.update_item(
        Key={"pk": _user_pk(user_id), "sk": _idea_sk(idea_id)},
        UpdateExpression="SET #st = :s, reviewed_at = :ts, GSI1PK = :g1, rejection_reason = :r",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":s": "rejected",
            ":ts": ts,
            ":g1": _gsi1pk(user_id, "rejected"),
            ":r": reason[:_REASON_MAX],
        },
    )
    _bump_preference(
        user_id=user_id,
        category=raw.get("category", "feature"),
        field="total_rejected",
        rejection_reason=reason[:_REASON_MAX],
    )
    out = _get_idea_raw(user_id=user_id, idea_id=idea_id)
    return _idea_to_out(out or raw)


def archive_idea(*, user_id: str, idea_id: str) -> Dict[str, Any]:
    """Archive an idea (approved or rejected) to remove it from active lists."""
    ensure_tables()
    raw = _get_idea_raw(user_id=user_id, idea_id=idea_id)
    if not raw:
        raise PmValidationError("IDEA_NOT_FOUND", "Feature idea not found")
    if raw.get("status") not in ("approved", "rejected", "pending"):
        raise PmValidationError(
            "INVALID_STATUS_TRANSITION",
            f"Cannot archive an idea with status: {raw.get('status')}",
        )
    ts = now_ts()
    T.agent_feature_ideas.update_item(
        Key={"pk": _user_pk(user_id), "sk": _idea_sk(idea_id)},
        UpdateExpression="SET #st = :s, GSI1PK = :g1, archived_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":s": "archived",
            ":g1": _gsi1pk(user_id, "archived"),
            ":ts": ts,
        },
    )
    out = _get_idea_raw(user_id=user_id, idea_id=idea_id)
    return _idea_to_out(out or raw)


# ---------------------------------------------------------------------------
# Preference learning
# ---------------------------------------------------------------------------


def _bump_preference(
    *, user_id: str, category: str, field: str, rejection_reason: Optional[str] = None
) -> None:
    """Atomically increment a preference counter and recompute the approval rate."""
    ensure_tables()
    ts = now_ts()
    try:
        T.agent_preference_learning.update_item(
            Key={"pk": _user_pk(user_id), "sk": _pref_sk(category)},
            UpdateExpression=(
                "ADD #f :one "
                "SET category = if_not_exists(category, :cat), last_updated = :ts"
            ),
            ExpressionAttributeNames={"#f": field},
            ExpressionAttributeValues={":one": 1, ":cat": category, ":ts": ts},
        )
    except ClientError as exc:  # pragma: no cover - defensive
        logger.warning("preference bump failed: %s", exc)
        return
    # Recompute approval rate + append rejection reason (read-modify-write).
    resp = T.agent_preference_learning.get_item(
        Key={"pk": _user_pk(user_id), "sk": _pref_sk(category)}
    )
    item = resp.get("Item") or {}
    approved = _to_int(item.get("total_approved"))
    rejected = _to_int(item.get("total_rejected"))
    reviewed = approved + rejected
    rate = (approved / reviewed) if reviewed else 0.0
    update_expr = "SET approval_rate = :r"
    values: Dict[str, Any] = {":r": _to_decimal(rate)}
    names: Dict[str, str] = {}
    if rejection_reason:
        reasons = _loads(item.get("common_rejection_reasons")) or []
        reasons.append(rejection_reason)
        update_expr += ", common_rejection_reasons = :reasons"
        values[":reasons"] = json.dumps(reasons[-20:])
    T.agent_preference_learning.update_item(
        Key={"pk": _user_pk(user_id), "sk": _pref_sk(category)},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=values,
        **({"ExpressionAttributeNames": names} if names else {}),
    )


def _to_decimal(value: float):
    from decimal import Decimal

    return Decimal(str(round(value, 6)))


def get_preference_summary(*, user_id: str) -> List[Dict[str, Any]]:
    """Return preference learning summary per category, sorted by approval rate desc."""
    ensure_tables()
    resp = T.agent_preference_learning.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": _user_pk(user_id), ":sk": "PREF#"},
    )
    out: List[Dict[str, Any]] = []
    for item in resp.get("Items", []):
        approved = _to_int(item.get("total_approved"))
        rejected = _to_int(item.get("total_rejected"))
        out.append(
            {
                "category": item.get("category", item.get("sk", "").replace("PREF#", "")),
                "total_suggested": _to_int(item.get("total_suggested")),
                "total_approved": approved,
                "total_rejected": rejected,
                "approval_rate": round(float(item.get("approval_rate") or 0.0), 6),
            }
        )
    out.sort(key=lambda p: p["approval_rate"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Review context + lifecycle (deterministic / mockable)
# ---------------------------------------------------------------------------


def get_review_context(*, user_id: str, agent_id: str) -> Dict[str, Any]:
    """Build context for a PM Agent review session."""
    ensure_tables()
    config = get_pm_config(user_id=user_id)
    preferences = get_preference_summary(user_id=user_id)
    recent_rejected = list_feature_ideas(user_id=user_id, status="rejected", limit=10).get("ideas", [])
    support_ticket_subjects: List[str] = []
    if config.get("analyze_support_tickets") and S.pm_support_analysis_enabled:
        try:
            owned = tickets_svc.STORE.list_tickets(owner_sub=user_id, limit=100)
            for t in owned.get("tickets", []) if isinstance(owned, dict) else owned or []:
                subj = t.get("subject") if isinstance(t, dict) else None
                if subj:
                    support_ticket_subjects.append(subj)
        except Exception:  # pragma: no cover - tickets list shape varies
            support_ticket_subjects = []
    return {
        "user_id": user_id,
        "agent_id": agent_id,
        "config": config,
        "preferences": preferences,
        "recent_rejected_titles": [i.get("title") for i in recent_rejected],
        "support_ticket_subjects": support_ticket_subjects[:100],
        "competitor_analysis_enabled": S.pm_competitor_analysis_enabled,
    }


# Module-level guard so a manual trigger can't double-run for a user (E2E 675.4).
_RUNNING_REVIEWS: set[str] = set()


def is_review_running(*, user_id: str, agent_id: str) -> bool:
    return f"{user_id}:{agent_id}" in _RUNNING_REVIEWS


def trigger_review(*, user_id: str, agent_id: str, count: int = 3) -> Dict[str, Any]:
    """Run a deterministic mock review cycle, producing pending feature ideas.

    Gated: when ``S.pm_agent_execute_commands`` is true this would dispatch to the
    Worker Agent Framework (real Playwright browsing). For now the mock path is the
    only path so the lifecycle is fully driveable/testable.
    """
    ensure_tables()
    key = f"{user_id}:{agent_id}"
    if key in _RUNNING_REVIEWS:
        raise PmValidationError("REVIEW_IN_PROGRESS", "A review session is already running")
    _RUNNING_REVIEWS.add(key)
    try:
        config = get_pm_config(user_id=user_id)
        max_ideas = _to_int(config.get("max_ideas_per_review"), 5)
        n = min(max(1, int(count)), max_ideas)
        focus = config.get("focus_areas") or ["ux"]
        created: List[Dict[str, Any]] = []
        for i in range(n):
            category = IDEA_CATEGORIES[i % len(IDEA_CATEGORIES)]
            area = focus[i % len(focus)]
            idea = create_feature_idea(
                user_id=user_id,
                agent_id=agent_id,
                worker_id=f"worker_{agent_id}",
                title=f"Improve {area} ({category}) #{i + 1}",
                description=f"Mock review suggestion for the {area} area focusing on {category}.",
                category=category,
                priority_suggestion=IDEA_PRIORITIES[i % len(IDEA_PRIORITIES)],
                user_impact=f"Expected to improve {area} engagement.",
                evidence=[{"type": "screenshot", "description": f"{area} flow review"}],
            )
            created.append(idea)
        return {
            "ok": True,
            "agent_id": agent_id,
            "ideas_created": len(created),
            "ideas": created,
            "completed_at": now_ts(),
        }
    finally:
        _RUNNING_REVIEWS.discard(key)


# ---------------------------------------------------------------------------
# Review artifacts (screenshots / traces)
# ---------------------------------------------------------------------------


def list_review_sessions(*, user_id: str, limit: int = 25) -> List[Dict[str, Any]]:
    """Aggregate review sessions (grouped by agent_id) from stored ideas."""
    ensure_tables()
    all_ideas = list_feature_ideas(user_id=user_id, status=None, limit=100).get("ideas", [])
    sessions: Dict[str, Dict[str, Any]] = {}
    for idea in all_ideas:
        agent_id = idea.get("agent_id", "")
        sess = sessions.setdefault(
            agent_id,
            {
                "review_id": agent_id,
                "agent_id": agent_id,
                "worker_id": "",
                "ideas_count": 0,
                "screenshots_count": 0,
                "session_at": 0,
            },
        )
        sess["ideas_count"] += 1
        ev = idea.get("evidence") or []
        sess["screenshots_count"] += sum(1 for e in ev if (e or {}).get("type") == "screenshot")
        sess["session_at"] = max(sess["session_at"], idea.get("created_at", 0))
    out = sorted(sessions.values(), key=lambda s: s["session_at"], reverse=True)
    return out[:limit]


def get_review_screenshots(*, user_id: str, review_id: str) -> List[Dict[str, Any]]:
    """Return screenshot evidence items for ideas from a given review (agent_id)."""
    ensure_tables()
    resp = T.agent_feature_ideas.query(
        IndexName="GSI2",
        KeyConditionExpression="GSI2PK = :pk",
        ExpressionAttributeValues={":pk": _gsi2pk(review_id)},
    )
    shots: List[Dict[str, Any]] = []
    for item in resp.get("Items", []):
        if item.get("user_id") != user_id:
            continue
        for ev in _loads(item.get("evidence")) or []:
            if (ev or {}).get("type") == "screenshot":
                shots.append(
                    {
                        "idea_id": item.get("idea_id"),
                        "description": ev.get("description", ""),
                        "url": ev.get("url"),
                    }
                )
    return shots

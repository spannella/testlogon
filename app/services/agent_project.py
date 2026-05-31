"""Project Manager Agent service (AGENT-012).

The PM Agent is an *agent type config* (``agent_type = "pm"``) that plugs into the
Worker Agent Framework (AGENT-003) and sits at the TOP of the agent pipeline. It
ORCHESTRATES the downstream agents (architect -> coder -> qa -> devops): it
converts raw user ideas into prioritized feature requests, prioritizes the
development backlog, tracks velocity across all agent types, detects blockers,
runs sprint planning, and produces progress reports.

It owns:

* ``pm_config`` storage/validation on the ``agent_types`` table (REUSED from
  AGENT-008 — same table, distinct ``PM_CONFIG`` payload + ``agent_type`` discriminator)
* the ``product_ideas`` table (idea intake funnel)
* the ``project_sprints`` table (sprint/cycle boundaries + velocity)
* the ``project_reports`` table (generated progress reports)
* structured PM output on the ``agent_runs`` table
* deterministic, mockable orchestration workflows (idea_triage, backlog_prioritize,
  report_generate, blocker_detect, sprint_plan)

Real coding-tool / LLM execution for idea triage is gated behind
``S.pm_execute_commands``. When disabled (the default, and always in E2E), triage
uses a deterministic, formula-based scorer so tests are fully reproducible.

Reuses the ticket system (``app.services.tickets``) for the backlog and the
downstream agent services (``agent_coder``, ``agent_qa``, ``agent_devops``,
``agent_architect``) for cross-agent assignment + utilization data.
"""

from __future__ import annotations

import json
import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services import agent_coder as coder_svc
from app.services import tickets as tickets_svc

logger = logging.getLogger("app.agent_project")

PM_AGENT_TYPE = "pm"
FEATURE_REQUEST_LABEL = "type:feature_request"
PRODUCT_REQUEST_LABEL = "type:product_request"

IDEA_STATUSES = ("submitted", "triaging", "accepted", "rejected", "converted")
PRIORITIES = ("P0", "P1", "P2", "P3")
OPERATION_TYPES = (
    "idea_triage",
    "backlog_prioritize",
    "report_generate",
    "blocker_detect",
    "sprint_plan",
)
_BACKLOG_STATUSES = ("open", "in_progress", "code_complete", "qa_in_progress", "blocked")
_DONE_STATUSES = ("done", "deployed", "qa_approved")
_AGENT_TYPES = ("coder", "qa", "devops", "architect")

_DEFAULT_PRIORITY_FRAMEWORK = {
    "P0": "Critical/blocking",
    "P1": "High/next sprint",
    "P2": "Medium/backlog",
    "P3": "Low/nice-to-have",
}
_DEFAULT_PRIORITY_WEIGHTS = {
    "user_impact": 0.4,
    "revenue_impact": 0.3,
    "technical_debt": 0.15,
    "effort_inverse": 0.15,
}
_DEFAULT_CAPACITY = {"coder": 80, "qa": 40, "devops": 20, "architect": 20}

_CONFIG_FIELDS = (
    "priority_framework",
    "priority_weights",
    "sprint_duration_days",
    "capacity_per_agent_type",
    "reporting_cadence",
    "report_time_utc",
    "idea_intake_enabled",
    "auto_prioritize",
    "auto_create_feature_requests",
    "blocker_stale_hours",
    "escalation_on_conflict",
    "coding_tool",
    "coding_tool_model",
    "project_space_id",
    "stakeholder_subs",
)


# ---------------------------------------------------------------------------
# Table bootstrap (idempotent; tables are additive)
# ---------------------------------------------------------------------------

_BOOTSTRAPPED = False


def ensure_tables() -> None:
    """Create the product_ideas / project_sprints / project_reports tables on
    first use if absent.

    The agent_types / agent_runs tables are bootstrapped by AGENT-008's coder
    service (REUSED here). This adds only the new PM-owned tables so the feature
    is self-contained in any environment (E2E live DDB, fresh stacks).
    """
    global _BOOTSTRAPPED
    coder_svc.ensure_tables()
    if _BOOTSTRAPPED:
        return
    client = ddb.meta.client
    specs = [
        (
            S.product_ideas_table_name,
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "N"},
            ],
            [
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
        ),
        (S.project_sprints_table_name, [
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ], []),
        (S.project_reports_table_name, [
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ], []),
    ]
    for name, attr_defs, gsi in specs:
        kwargs: Dict[str, Any] = {
            "TableName": name,
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": attr_defs,
            "BillingMode": "PAY_PER_REQUEST",
        }
        if gsi:
            kwargs["GlobalSecondaryIndexes"] = gsi
        try:
            client.create_table(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ResourceInUseException",):
                logger.warning("ensure_tables: could not create %s: %s", name, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ensure_tables: %s create error: %s", name, exc)
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ddb_safe(value: Any) -> Any:
    """Recursively convert Python floats to Decimal (DynamoDB rejects floats)."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _ddb_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_ddb_safe(v) for v in value]
    return value


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _type_pk(type_id: str) -> str:
    return coder_svc._type_pk(type_id)  # noqa: SLF001 - shared key scheme


def _idea_pk(idea_id: str) -> str:
    return f"IDEA#{idea_id}"


def _project_pk(space_id: Optional[str]) -> str:
    return f"PROJECT#{space_id or 'default'}"


def _sprint_sk(sprint_id: str) -> str:
    return f"SPRINT#{sprint_id}"


def _ticket_table():
    return tickets_svc.STORE._table  # noqa: SLF001 - internal reuse


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def validate_pm_config(config: Dict[str, Any]) -> List[str]:
    """Return list of validation errors (empty = valid).

    Validates: priority_framework has P0-P3, weights sum to ~1.0,
    sprint_duration > 0, capacity values > 0, capacity includes 'coder'.
    """
    errors: List[str] = []

    framework = config.get("priority_framework") or {}
    for level in PRIORITIES:
        if level not in framework:
            errors.append(f"Priority framework must define {level}")

    weights = config.get("priority_weights") or {}
    if weights:
        total = sum(_num(v) for v in weights.values())
        if abs(total - 1.0) > 0.01:
            errors.append("Priority weights must sum to 1.0")

    sprint_days = config.get("sprint_duration_days")
    if sprint_days is not None and int(sprint_days) <= 0:
        errors.append("sprint_duration_days must be greater than 0")

    capacity = config.get("capacity_per_agent_type") or {}
    if capacity:
        if "coder" not in capacity:
            errors.append("Capacity must include at least 'coder' agent type")
        for agent_type, hours in capacity.items():
            if _num(hours) <= 0:
                errors.append(f"Capacity for {agent_type} must be greater than 0")

    cadence = config.get("reporting_cadence", "both")
    if cadence not in ("daily", "weekly", "both"):
        errors.append("reporting_cadence must be daily, weekly, or both")

    coding_tool = config.get("coding_tool", "claude_code")
    if coding_tool not in ("claude_code", "codex"):
        errors.append("Coding tool must be claude_code or codex")

    stale = config.get("blocker_stale_hours")
    if stale is not None and not (1 <= int(stale) <= 720):
        errors.append("blocker_stale_hours must be between 1 and 720")

    return errors


def _normalize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in _CONFIG_FIELDS:
        if key in config and config[key] is not None:
            out[key] = config[key]
    out.setdefault("priority_framework", dict(_DEFAULT_PRIORITY_FRAMEWORK))
    out.setdefault("priority_weights", dict(_DEFAULT_PRIORITY_WEIGHTS))
    out.setdefault("sprint_duration_days", 14)
    out.setdefault("capacity_per_agent_type", dict(_DEFAULT_CAPACITY))
    out.setdefault("reporting_cadence", "both")
    out.setdefault("report_time_utc", "09:00")
    out.setdefault("idea_intake_enabled", True)
    out.setdefault("auto_prioritize", True)
    out.setdefault("auto_create_feature_requests", False)
    out.setdefault("blocker_stale_hours", 48)
    out.setdefault("escalation_on_conflict", True)
    out.setdefault("coding_tool", "claude_code")
    return out


def _coerce_numbers(config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(config)
    for field in ("sprint_duration_days", "blocker_stale_hours"):
        if field in out and out[field] is not None:
            try:
                out[field] = int(out[field])
            except (TypeError, ValueError):
                pass
    weights = out.get("priority_weights")
    if isinstance(weights, dict):
        out["priority_weights"] = {k: _num(v) for k, v in weights.items()}
    cap = out.get("capacity_per_agent_type")
    if isinstance(cap, dict):
        out["capacity_per_agent_type"] = {k: int(_num(v)) for k, v in cap.items()}
    return out


def get_pm_config(*, agent_type_id: str) -> Optional[Dict[str, Any]]:
    """Fetch pm_config from agent_types table (PM_CONFIG item)."""
    ensure_tables()
    resp = T.agent_types.get_item(
        Key={"pk": _type_pk(agent_type_id), "sk": "PM_CONFIG"}
    )
    item = resp.get("Item")
    if not item:
        return None
    config = item.get("pm_config")
    if not config:
        return None
    result = _coerce_numbers(config)
    result["updated_at"] = int(item.get("updated_at", 0) or 0)
    return result


def update_pm_config(
    *, agent_type_id: str, owner_sub: str, config: Dict[str, Any]
) -> Dict[str, Any]:
    """Validate and persist pm_config. Auto-creates the type META if absent."""
    ensure_tables()
    if coder_svc.get_agent_type(agent_type_id=agent_type_id) is None:
        coder_svc.create_agent_type(
            agent_type_id=agent_type_id, owner_sub=owner_sub, agent_type=PM_AGENT_TYPE
        )
    normalized = _normalize_config(config)
    ts = now_ts()
    T.agent_types.put_item(
        Item=_ddb_safe({
            "pk": _type_pk(agent_type_id),
            "sk": "PM_CONFIG",
            "agent_type_id": agent_type_id,
            "agent_type": PM_AGENT_TYPE,
            "owner_sub": owner_sub,
            "pm_config": normalized,
            "updated_at": ts,
        })
    )
    T.agent_types.update_item(
        Key={"pk": _type_pk(agent_type_id), "sk": "META"},
        UpdateExpression="SET agent_type = :t, updated_at = :u",
        ExpressionAttributeValues={":t": PM_AGENT_TYPE, ":u": ts},
    )
    result = dict(normalized)
    result["updated_at"] = ts
    return result


# ---------------------------------------------------------------------------
# Idea intake
# ---------------------------------------------------------------------------


def _idea_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "idea_id": item.get("idea_id", ""),
        "submitted_by": item.get("submitted_by", ""),
        "title": item.get("title", ""),
        "description": item.get("description", ""),
        "status": item.get("status", "submitted"),
        "priority_suggestion": item.get("priority_suggestion"),
        "impact_score": (
            float(item["impact_score"]) if item.get("impact_score") is not None else None
        ),
        "effort_score": (
            float(item["effort_score"]) if item.get("effort_score") is not None else None
        ),
        "priority_rationale": item.get("priority_rationale"),
        "feature_ticket_id": item.get("feature_ticket_id"),
        "agent_run_id": item.get("agent_run_id"),
        "rejection_reason": item.get("rejection_reason"),
        "created_at": int(item.get("created_at", 0) or 0),
        "updated_at": int(item.get("updated_at", 0) or 0),
    }


def submit_idea(*, user_sub: str, title: str, description: str) -> Dict[str, Any]:
    """Create a product idea record. Status = submitted."""
    ensure_tables()
    idea_id = uuid.uuid4().hex
    ts = now_ts()
    item = {
        "pk": _idea_pk(idea_id),
        "sk": "META",
        "idea_id": idea_id,
        "submitted_by": user_sub,
        "title": title.strip()[:200],
        "description": description.strip()[:5000],
        "status": "submitted",
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": "STATUS#submitted",
        "GSI1SK": ts,
        "GSI2PK": f"USER#{user_sub}",
        "GSI2SK": ts,
    }
    T.product_ideas.put_item(Item=item)
    return _idea_out(item)


def get_idea(*, idea_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.product_ideas.get_item(Key={"pk": _idea_pk(idea_id), "sk": "META"})
    item = resp.get("Item")
    return _idea_out(item) if item else None


def list_ideas(
    *,
    status: Optional[str] = None,
    user_sub: Optional[str] = None,
    limit: int = 25,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List ideas filtered by status or submitter. Paginated via GSI1/GSI2."""
    ensure_tables()
    page_limit = max(1, min(int(limit or 25), 100))
    start_key = decode_cursor(cursor) if cursor else None
    query_kwargs: Dict[str, Any] = {"Limit": page_limit, "ScanIndexForward": False}
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key
    if user_sub:
        query_kwargs["IndexName"] = "GSI2"
        query_kwargs["KeyConditionExpression"] = "GSI2PK = :pk"
        query_kwargs["ExpressionAttributeValues"] = {":pk": f"USER#{user_sub}"}
    elif status:
        query_kwargs["IndexName"] = "GSI1"
        query_kwargs["KeyConditionExpression"] = "GSI1PK = :pk"
        query_kwargs["ExpressionAttributeValues"] = {":pk": f"STATUS#{status}"}
    else:
        # No filter: scan (small dataset). Sort newest-first in memory.
        resp = T.product_ideas.scan(
            FilterExpression="sk = :meta",
            ExpressionAttributeValues={":meta": "META"},
        )
        items = sorted(
            resp.get("Items", []),
            key=lambda i: int(i.get("created_at", 0) or 0),
            reverse=True,
        )[:page_limit]
        return {"ideas": [_idea_out(i) for i in items], "next_cursor": None}

    resp = T.product_ideas.query(**query_kwargs)
    items = resp.get("Items", [])
    next_cursor = (
        encode_cursor(resp["LastEvaluatedKey"]) if resp.get("LastEvaluatedKey") else None
    )
    return {"ideas": [_idea_out(i) for i in items], "next_cursor": next_cursor}


def update_idea_status(
    *,
    idea_id: str,
    status: str,
    agent_sub: Optional[str] = None,
    rejection_reason: Optional[str] = None,
    feature_ticket_id: Optional[str] = None,
    priority_suggestion: Optional[str] = None,
    impact_score: Optional[float] = None,
    effort_score: Optional[float] = None,
    priority_rationale: Optional[str] = None,
) -> Dict[str, Any]:
    """Update an idea's status + triage outputs. Keeps GSI1PK in sync."""
    ensure_tables()
    existing = T.product_ideas.get_item(
        Key={"pk": _idea_pk(idea_id), "sk": "META"}
    ).get("Item")
    if not existing:
        raise LookupError("Product idea not found")
    ts = now_ts()
    updates: Dict[str, Any] = {
        "status": status,
        "updated_at": ts,
        "GSI1PK": f"STATUS#{status}",
        "GSI1SK": int(existing.get("created_at", ts) or ts),
    }
    if agent_sub is not None:
        updates["agent_run_id"] = agent_sub
    if rejection_reason is not None:
        updates["rejection_reason"] = rejection_reason
    if feature_ticket_id is not None:
        updates["feature_ticket_id"] = feature_ticket_id
    if priority_suggestion is not None:
        updates["priority_suggestion"] = priority_suggestion
    if impact_score is not None:
        updates["impact_score"] = impact_score
    if effort_score is not None:
        updates["effort_score"] = effort_score
    if priority_rationale is not None:
        updates["priority_rationale"] = priority_rationale

    expr_names = {f"#k{i}": k for i, k in enumerate(updates)}
    expr_vals = {f":v{i}": v for i, (k, v) in enumerate(updates.items())}
    set_expr = "SET " + ", ".join(
        f"#k{i} = :v{i}" for i in range(len(updates))
    )
    T.product_ideas.update_item(
        Key={"pk": _idea_pk(idea_id), "sk": "META"},
        UpdateExpression=set_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=_ddb_safe(expr_vals),
    )
    return get_idea(idea_id=idea_id) or {}


# ---------------------------------------------------------------------------
# Idea triage (deterministic, formula-based; real LLM gated)
# ---------------------------------------------------------------------------


def _deterministic_scores(*, idea: Dict[str, Any]) -> Dict[str, float]:
    """Derive stable 0-100 impact dimension scores from the idea text.

    Used in mock mode (the default and always in E2E) so triage is reproducible.
    """
    text = f"{idea.get('title', '')} {idea.get('description', '')}".lower()
    seed = sum(ord(c) for c in text) or 1
    user_impact = 40 + (seed % 60)
    revenue_impact = 30 + ((seed * 7) % 60)
    tech_debt = 20 + ((seed * 13) % 60)
    effort = 20 + ((seed * 17) % 70)
    # Heuristic keyword nudges.
    if any(k in text for k in ("revenue", "subscription", "churn", "payment", "billing")):
        revenue_impact = min(100, revenue_impact + 25)
    if any(k in text for k in ("crash", "bug", "broken", "critical", "security")):
        user_impact = min(100, user_impact + 25)
    if any(k in text for k in ("refactor", "tech debt", "cleanup", "migrate")):
        tech_debt = min(100, tech_debt + 25)
    return {
        "user_impact": float(min(100, user_impact)),
        "revenue_impact": float(min(100, revenue_impact)),
        "tech_debt": float(min(100, tech_debt)),
        "effort_score": float(min(100, effort)),
    }


def _weighted_score(*, dims: Dict[str, float], weights: Dict[str, Any]) -> float:
    w = {**_DEFAULT_PRIORITY_WEIGHTS, **{k: _num(v) for k, v in (weights or {}).items()}}
    score = (
        w.get("user_impact", 0.4) * dims.get("user_impact", 0)
        + w.get("revenue_impact", 0.3) * dims.get("revenue_impact", 0)
        + w.get("technical_debt", 0.15) * dims.get("tech_debt", 0)
        + w.get("effort_inverse", 0.15) * (100 - dims.get("effort_score", 0))
    )
    return round(score, 2)


def priority_from_score(score: float) -> str:
    if score >= 80:
        return "P0"
    if score >= 60:
        return "P1"
    if score >= 40:
        return "P2"
    return "P3"


def triage_idea(
    *,
    idea: Dict[str, Any],
    coding_tool: str,
    model: Optional[str],
    priority_framework: Dict[str, str],
    priority_weights: Dict[str, Any],
) -> Dict[str, Any]:
    """Analyze an idea and produce a priority suggestion + user stories.

    Deterministic / formula-based in mock mode. Returns
    {priority, impact_score, effort_score, rationale, user_stories, success_criteria}.
    """
    dims = _deterministic_scores(idea=idea)
    score = _weighted_score(dims=dims, weights=priority_weights)
    priority = priority_from_score(score)
    title = idea.get("title", "this idea")
    rationale = (
        f"Weighted impact/effort score {score} (user_impact={dims['user_impact']:.0f}, "
        f"revenue_impact={dims['revenue_impact']:.0f}, tech_debt={dims['tech_debt']:.0f}, "
        f"effort={dims['effort_score']:.0f}) maps to {priority}: "
        f"{priority_framework.get(priority, '')}."
    )
    user_stories = [
        f"As a user, I want {title.lower()} so that my workflow is improved.",
        f"As an admin, I want to monitor adoption of {title.lower()}.",
    ]
    success_criteria = [
        "Feature is reachable from the UI and documented.",
        "E2E coverage added; no regressions in existing suites.",
    ]
    return {
        "priority": priority,
        "impact_score": round(dims["user_impact"], 2),
        "effort_score": round(dims["effort_score"], 2),
        "weighted_score": score,
        "rationale": rationale,
        "user_stories": user_stories,
        "success_criteria": success_criteria,
    }


def build_feature_request_from_idea(
    *, idea: Dict[str, Any], triage_result: Dict[str, Any], priority: str
) -> Dict[str, Any]:
    """Construct feature request ticket data (subject/description/labels/metadata)."""
    stories = triage_result.get("user_stories", [])
    criteria = triage_result.get("success_criteria", [])
    description = (
        f"## Feature Request (from idea {idea.get('idea_id', '')})\n\n"
        f"{idea.get('description', '')}\n\n"
        f"## User Stories\n" + "\n".join(f"- {s}" for s in stories) + "\n\n"
        f"## Success Criteria\n" + "\n".join(f"- {c}" for c in criteria) + "\n\n"
        f"## Prioritization\n{triage_result.get('rationale', '')}"
    )
    return {
        "subject": idea.get("title", "Feature request"),
        "description": description,
        "labels": [FEATURE_REQUEST_LABEL, f"priority:{priority}"],
        "metadata": {
            "idea_id": idea.get("idea_id", ""),
            "impact_score": triage_result.get("impact_score", 0),
            "effort_score": triage_result.get("effort_score", 0),
            "user_impact": triage_result.get("impact_score", 0),
            "revenue_impact": _num(triage_result.get("weighted_score", 0)),
            "tech_debt": 0,
            "user_stories": stories,
            "priority": priority,
        },
    }


def convert_idea_to_feature_request(
    *,
    idea_id: str,
    agent_sub: str,
    triage_result: Dict[str, Any],
    space_id: Optional[str],
) -> Dict[str, Any]:
    """Create a feature request ticket from a triaged idea and link it."""
    ensure_tables()
    idea = get_idea(idea_id=idea_id)
    if not idea:
        raise LookupError("Product idea not found")
    if idea.get("status") == "converted" and idea.get("feature_ticket_id"):
        raise ValueError("already_converted")
    priority = triage_result.get("priority", "P2")
    fr = build_feature_request_from_idea(idea=idea, triage_result=triage_result, priority=priority)
    ticket = tickets_svc.STORE.create_ticket(
        owner_sub=agent_sub,
        subject=fr["subject"],
        description=fr["description"],
        space_id=space_id,
        labels=fr["labels"],
        metadata=_ddb_safe(fr["metadata"]),
    )
    feature_ticket_id = ticket.get("ticket_id")
    updated = update_idea_status(
        idea_id=idea_id,
        status="converted",
        feature_ticket_id=feature_ticket_id,
        priority_suggestion=priority,
        impact_score=triage_result.get("impact_score"),
        effort_score=triage_result.get("effort_score"),
        priority_rationale=triage_result.get("rationale"),
    )
    return {"idea": updated, "feature_ticket": ticket}


# ---------------------------------------------------------------------------
# Backlog prioritization
# ---------------------------------------------------------------------------


def _scan_backlog_tickets(
    *, space_id: Optional[str], statuses: List[str], limit: int
) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for status in statuses:
        try:
            if space_id:
                page = tickets_svc.STORE.list_space_tickets(
                    space_id=space_id, status=status, limit=min(limit, 100)
                )
            else:
                page = tickets_svc.STORE.list_tickets(status=status, limit=min(limit, 100))
        except Exception:  # pragma: no cover - defensive
            continue
        for t in page.get("tickets", []):
            tid = t.get("ticket_id")
            if tid and tid not in seen:
                seen[tid] = t
        if len(seen) >= limit:
            break
    return list(seen.values())[:limit]


def get_backlog(
    *,
    space_id: Optional[str],
    statuses: Optional[List[str]] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Fetch open/in_progress/code_complete tickets (+ labels, metadata, estimates)."""
    ensure_tables()
    statuses = statuses or list(_BACKLOG_STATUSES)
    return _scan_backlog_tickets(space_id=space_id, statuses=statuses, limit=limit)


def _priority_from_labels(labels: List[str]) -> Optional[str]:
    for level in PRIORITIES:
        if f"priority:{level}" in labels:
            return level
    return None


def calculate_priority_score(*, ticket: Dict[str, Any], weights: Dict[str, Any]) -> float:
    """Score 0-100 from ticket metadata impact dimensions + effort estimate."""
    meta = ticket.get("metadata") or {}
    effort_hours = _num(ticket.get("estimated_effort_hours") or meta.get("estimated_effort_hours") or 0)
    # Normalize effort hours to 0-100 (assume 80h ~ a full sprint of one agent).
    effort_score = min(100.0, (effort_hours / 80.0) * 100.0) if effort_hours else 50.0
    dims = {
        "user_impact": _num(meta.get("user_impact"), 50.0),
        "revenue_impact": _num(meta.get("revenue_impact"), 40.0),
        "tech_debt": _num(meta.get("tech_debt"), 30.0),
        "effort_score": effort_score,
    }
    return _weighted_score(dims=dims, weights=weights)


def prioritize_backlog(
    *, backlog: List[Dict[str, Any]], weights: Dict[str, Any], capacity: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Sort tickets by score descending and assign P0-P3.

    Caps P0 count to 30% of coder sprint capacity (in tickets, min 1).
    """
    scored: List[Dict[str, Any]] = []
    for t in backlog:
        score = calculate_priority_score(ticket=t, weights=weights)
        scored.append({**t, "priority_score": score, "priority": priority_from_score(score)})
    scored.sort(key=lambda t: (-t["priority_score"], t.get("ticket_id", "")))

    coder_capacity = _num((capacity or {}).get("coder"), 80.0)
    p0_cap = max(1, int((coder_capacity * 0.3) / 8))  # ~8h average per P0 ticket
    p0_used = 0
    for t in scored:
        if t["priority"] == "P0":
            if p0_used >= p0_cap:
                t["priority"] = "P1"  # demote overflow P0s to P1
            else:
                p0_used += 1
    return scored


def apply_priorities(
    *, prioritized: List[Dict[str, Any]], agent_sub: str, auto_prioritize: bool
) -> int:
    """Update ticket labels with the computed priority. When auto_prioritize is
    False, only count the tickets that *would* change (suggestion mode).
    Returns count of tickets whose priority changed.
    """
    table = _ticket_table()
    changed = 0
    for t in prioritized:
        tid = t.get("ticket_id")
        if not tid:
            continue
        new_priority = t.get("priority")
        labels = [l for l in (t.get("labels") or []) if not str(l).startswith("priority:")]
        existing_priority = _priority_from_labels(t.get("labels") or [])
        if existing_priority == new_priority:
            continue
        changed += 1
        if not auto_prioritize:
            continue
        labels = sorted(set(labels + [f"priority:{new_priority}"]))
        meta = dict(t.get("metadata") or {})
        meta["priority"] = new_priority
        meta["priority_score"] = t.get("priority_score", 0)
        table.update_item(
            Key={"pk": f"TICKET#{tid}", "sk": "META"},
            UpdateExpression="SET labels = :l, metadata = :m, updated_at = :ts",
            ExpressionAttributeValues=_ddb_safe({
                ":l": labels,
                ":m": meta,
                ":ts": now_ts(),
            }),
        )
    return changed


def backlog_view(*, prioritized: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    now = now_ts()
    out = []
    for t in prioritized:
        meta = t.get("metadata") or {}
        out.append({
            "ticket_id": t.get("ticket_id", ""),
            "subject": t.get("subject", ""),
            "labels": list(t.get("labels", []) or []),
            "priority": t.get("priority") or _priority_from_labels(t.get("labels") or []) or "P3",
            "priority_score": round(_num(t.get("priority_score")), 2),
            "complexity": t.get("complexity"),
            "estimated_hours": _num(t.get("estimated_effort_hours") or meta.get("estimated_effort_hours") or 0),
            "status": t.get("status", "open"),
            "assigned_to": t.get("assigned_to_sub"),
            "age_hours": round(max(0, now - int(t.get("created_at", now) or now)) / 3600.0, 1),
        })
    return out


# ---------------------------------------------------------------------------
# Cross-agent assignment
# ---------------------------------------------------------------------------

_STATUS_TO_AGENT = {
    "open": "coder",
    "in_progress": "coder",
    "code_complete": "qa",
    "qa_in_progress": "qa",
    "qa_approved": "devops",
    "deploying": "devops",
}


def assign_work(*, backlog: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Map each backlog ticket to the agent type that should pick it up next,
    based on its current pipeline stage. Returns assignment recommendations
    (ordered by priority score so the highest-value work is taken first).
    """
    assignments = []
    for t in backlog:
        labels = t.get("labels") or []
        status = t.get("status", "open")
        agent_type = "architect" if FEATURE_REQUEST_LABEL in labels and status == "open" else _STATUS_TO_AGENT.get(status, "coder")
        assignments.append({
            "ticket_id": t.get("ticket_id", ""),
            "subject": t.get("subject", ""),
            "status": status,
            "assign_to_agent_type": agent_type,
            "priority": t.get("priority") or _priority_from_labels(labels) or "P3",
            "priority_score": round(_num(t.get("priority_score")), 2),
        })
    assignments.sort(key=lambda a: -a["priority_score"])
    return assignments


# ---------------------------------------------------------------------------
# Blocker detection
# ---------------------------------------------------------------------------


def detect_blockers(*, space_id: Optional[str], stale_hours: int) -> List[Dict[str, Any]]:
    """Scan tickets for blockers: stale in_progress, explicit blocked status,
    and unresolved dependencies (depends_on tickets not done).
    """
    ensure_tables()
    now = now_ts()
    cutoff = now - max(1, int(stale_hours)) * 3600
    blockers: List[Dict[str, Any]] = []

    candidates = _scan_backlog_tickets(
        space_id=space_id, statuses=["in_progress", "blocked", "code_complete"], limit=200
    )
    for t in candidates:
        tid = t.get("ticket_id")
        status = t.get("status")
        priority = _priority_from_labels(t.get("labels") or []) or "P3"
        updated_at = int(t.get("updated_at", now) or now)
        if status == "blocked":
            blockers.append({
                "ticket_id": tid,
                "ticket_subject": t.get("subject", ""),
                "blocker_type": "blocked",
                "stale_since": updated_at,
                "assigned_agent": t.get("assigned_to_sub"),
                "details": "Ticket is explicitly in 'blocked' status.",
                "priority": priority,
            })
            continue
        if status in ("in_progress", "code_complete", "qa_in_progress") and updated_at < cutoff:
            stale_h = round((now - updated_at) / 3600.0, 1)
            blockers.append({
                "ticket_id": tid,
                "ticket_subject": t.get("subject", ""),
                "blocker_type": "stale",
                "stale_since": updated_at,
                "assigned_agent": t.get("assigned_to_sub"),
                "details": f"No status change in {stale_h}h (stale > {stale_hours}h).",
                "priority": priority,
            })
            continue
        # Unresolved dependencies.
        deps = (t.get("metadata") or {}).get("depends_on") or []
        unresolved = []
        for dep in deps:
            dep_ticket = tickets_svc.STORE.get_ticket(str(dep))
            if dep_ticket and dep_ticket.get("status") not in _DONE_STATUSES:
                unresolved.append(dep)
        if unresolved:
            blockers.append({
                "ticket_id": tid,
                "ticket_subject": t.get("subject", ""),
                "blocker_type": "dependency",
                "stale_since": updated_at,
                "assigned_agent": t.get("assigned_to_sub"),
                "details": f"Blocked by unresolved dependencies: {', '.join(map(str, unresolved))}.",
                "priority": priority,
            })
    return blockers


def escalate_blockers(*, blockers: List[Dict[str, Any]], agent_sub: str) -> int:
    """Create feedback notes for critical blockers (P0/P1). Returns count escalated."""
    count = 0
    for b in blockers:
        if b.get("priority") not in ("P0", "P1"):
            continue
        tid = b.get("ticket_id")
        if not tid:
            continue
        try:
            tickets_svc.STORE.add_message(
                ticket_id=tid,
                sender_sub=agent_sub,
                sender_role="agent",
                body=(
                    f"PM Agent escalation: {b.get('blocker_type')} blocker detected — "
                    f"{b.get('details')}"
                ),
                email_targets=[],
            )
        except Exception:  # pragma: no cover - defensive
            pass
        count += 1
        logger.info("pm_blocker_escalated ticket=%s type=%s", tid, b.get("blocker_type"))
    return count


# ---------------------------------------------------------------------------
# Sprint management
# ---------------------------------------------------------------------------


def _sprint_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "sprint_id": item.get("sprint_id", ""),
        "sprint_number": int(item.get("sprint_number", 0) or 0),
        "start_date": item.get("start_date", ""),
        "end_date": item.get("end_date", ""),
        "status": item.get("status", "planned"),
        "planned_hours": _num(item.get("planned_hours")),
        "completed_hours": _num(item.get("completed_hours")),
        "tickets_planned": int(item.get("tickets_planned", 0) or 0),
        "tickets_completed": int(item.get("tickets_completed", 0) or 0),
        "tickets_carried_over": int(item.get("tickets_carried_over", 0) or 0),
        "velocity": _num(item.get("velocity")),
        "blockers_count": int(item.get("blockers_count", 0) or 0),
        "created_at": int(item.get("created_at", 0) or 0),
        "updated_at": int(item.get("updated_at", 0) or 0),
        "planned_ticket_ids": list(item.get("planned_ticket_ids", []) or []),
    }


def list_sprints(*, space_id: Optional[str]) -> List[Dict[str, Any]]:
    ensure_tables()
    resp = T.project_sprints.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": _project_pk(space_id), ":sk": "SPRINT#"},
    )
    sprints = [_sprint_out(i) for i in resp.get("Items", [])]
    sprints.sort(key=lambda s: s["sprint_number"])
    return sprints


def get_sprint(*, space_id: Optional[str], sprint_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.project_sprints.get_item(
        Key={"pk": _project_pk(space_id), "sk": _sprint_sk(sprint_id)}
    )
    item = resp.get("Item")
    return _sprint_out(item) if item else None


def get_current_sprint(*, space_id: Optional[str]) -> Optional[Dict[str, Any]]:
    for s in list_sprints(space_id=space_id):
        if s["status"] == "active":
            return s
    return None


def _planned_hours_for(ticket_ids: List[str]) -> float:
    total = 0.0
    for tid in ticket_ids:
        ticket = tickets_svc.STORE.get_ticket(tid)
        if ticket:
            total += _num(ticket.get("estimated_effort_hours") or 0)
    return total


def create_sprint(
    *,
    space_id: Optional[str],
    start_date: str,
    end_date: str,
    planned_tickets: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create a sprint record. Calculates planned_hours from ticket estimates.

    Raises ValueError("invalid_dates") / ("overlap") on validation failure.
    """
    ensure_tables()
    if end_date <= start_date:
        raise ValueError("invalid_dates")
    existing = list_sprints(space_id=space_id)
    for s in existing:
        if not (end_date <= s["start_date"] or start_date >= s["end_date"]):
            raise ValueError("overlap")
    planned_tickets = planned_tickets or []
    sprint_id = uuid.uuid4().hex
    sprint_number = (max((s["sprint_number"] for s in existing), default=0) + 1)
    ts = now_ts()
    planned_hours = _planned_hours_for(planned_tickets)
    item = {
        "pk": _project_pk(space_id),
        "sk": _sprint_sk(sprint_id),
        "sprint_id": sprint_id,
        "sprint_number": sprint_number,
        "start_date": start_date,
        "end_date": end_date,
        "status": "planned",
        "planned_hours": planned_hours,
        "completed_hours": 0,
        "tickets_planned": len(planned_tickets),
        "tickets_completed": 0,
        "tickets_carried_over": 0,
        "velocity": 0,
        "blockers_count": 0,
        "planned_ticket_ids": planned_tickets,
        "created_at": ts,
        "updated_at": ts,
    }
    T.project_sprints.put_item(Item=_ddb_safe(item))
    return _sprint_out(item)


def activate_sprint(*, space_id: Optional[str], sprint_id: str) -> Dict[str, Any]:
    ensure_tables()
    T.project_sprints.update_item(
        Key={"pk": _project_pk(space_id), "sk": _sprint_sk(sprint_id)},
        UpdateExpression="SET #st = :s, updated_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": "active", ":ts": now_ts()},
    )
    return get_sprint(space_id=space_id, sprint_id=sprint_id) or {}


def close_sprint(*, space_id: Optional[str], sprint_id: str) -> Dict[str, Any]:
    """Calculate completed vs planned, carry over incomplete tickets, set velocity."""
    ensure_tables()
    sprint = get_sprint(space_id=space_id, sprint_id=sprint_id)
    if not sprint:
        raise LookupError("Sprint not found")
    planned_ids = sprint.get("planned_ticket_ids", [])
    completed = 0
    completed_hours = 0.0
    carried = 0
    for tid in planned_ids:
        ticket = tickets_svc.STORE.get_ticket(tid)
        if not ticket:
            carried += 1
            continue
        if ticket.get("status") in _DONE_STATUSES:
            completed += 1
            completed_hours += _num(ticket.get("estimated_effort_hours") or 0)
        else:
            carried += 1
    ts = now_ts()
    T.project_sprints.update_item(
        Key={"pk": _project_pk(space_id), "sk": _sprint_sk(sprint_id)},
        UpdateExpression=(
            "SET #st = :s, tickets_completed = :tc, completed_hours = :ch, "
            "tickets_carried_over = :co, velocity = :v, updated_at = :ts"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues=_ddb_safe({
            ":s": "completed",
            ":tc": completed,
            ":ch": completed_hours,
            ":co": carried,
            ":v": completed_hours,
            ":ts": ts,
        }),
    )
    return get_sprint(space_id=space_id, sprint_id=sprint_id) or {}


def get_sprint_burndown(*, space_id: Optional[str], sprint_id: str) -> List[Dict[str, Any]]:
    """Daily snapshot of remaining vs ideal hours over the sprint window."""
    sprint = get_sprint(space_id=space_id, sprint_id=sprint_id)
    if not sprint:
        return []
    planned = _num(sprint.get("planned_hours"))
    completed = _num(sprint.get("completed_hours"))
    # Derive number of days from sprint dates (fallback to 14).
    try:
        from datetime import date

        sd = date.fromisoformat(sprint["start_date"])
        ed = date.fromisoformat(sprint["end_date"])
        days = max(1, (ed - sd).days)
    except Exception:
        days = 14
    out = []
    for d in range(days + 1):
        ideal = round(planned - (planned * d / days), 2) if days else 0.0
        # Linear actual interpolation between planned and remaining.
        remaining = round(planned - (completed * d / days), 2) if days else planned
        out.append({"date": f"day {d}", "remaining_hours": max(0.0, remaining), "ideal_hours": max(0.0, ideal)})
    return out


# ---------------------------------------------------------------------------
# Velocity tracking
# ---------------------------------------------------------------------------


def calculate_velocity(*, sprint: Dict[str, Any], completed_tickets: List[Dict[str, Any]]) -> Dict[str, Any]:
    velocity_hours = sum(_num(t.get("estimated_effort_hours") or 0) for t in completed_tickets)
    n = len(completed_tickets)
    return {
        "velocity_hours": round(velocity_hours, 2),
        "tickets_completed": n,
        "avg_hours_per_ticket": round(velocity_hours / n, 2) if n else 0.0,
    }


def get_velocity_trend(*, sprints: List[Dict[str, Any]], periods: int = 5) -> Dict[str, Any]:
    completed = [s for s in sprints if s.get("status") == "completed"]
    completed.sort(key=lambda s: s.get("sprint_number", 0))
    recent = completed[-periods:]
    velocities = [round(_num(s.get("velocity")), 2) for s in recent]
    if len(velocities) < 2:
        trend = "stable"
    else:
        first_half = velocities[: len(velocities) // 2] or [0]
        second_half = velocities[len(velocities) // 2 :] or [0]
        avg1 = sum(first_half) / len(first_half)
        avg2 = sum(second_half) / len(second_half)
        if avg2 > avg1 * 1.1:
            trend = "increasing"
        elif avg2 < avg1 * 0.9:
            trend = "decreasing"
        else:
            trend = "stable"
    avg_velocity = round(sum(velocities) / len(velocities), 2) if velocities else 0.0
    return {
        "trend": trend,
        "velocities": velocities,
        "avg_velocity": avg_velocity,
        "prediction_next": avg_velocity,
    }


# ---------------------------------------------------------------------------
# Capacity planning
# ---------------------------------------------------------------------------


def get_agent_utilization(*, capacity: Dict[str, Any], backlog: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Per-agent-type utilization. Used hours derived from in-flight backlog work
    mapped to the agent type that owns each stage.
    """
    capacity = capacity or dict(_DEFAULT_CAPACITY)
    used: Dict[str, float] = {a: 0.0 for a in capacity}
    for t in backlog or []:
        status = t.get("status", "open")
        labels = t.get("labels") or []
        agent_type = "architect" if (FEATURE_REQUEST_LABEL in labels and status == "open") else _STATUS_TO_AGENT.get(status)
        if agent_type and agent_type in used:
            meta = t.get("metadata") or {}
            used[agent_type] += _num(t.get("estimated_effort_hours") or meta.get("estimated_effort_hours") or 0)
    out = []
    for agent_type in capacity:
        total = _num(capacity.get(agent_type))
        used_h = round(used.get(agent_type, 0.0), 2)
        available = round(max(0.0, total - used_h), 2)
        pct = round((used_h / total) * 100, 1) if total else 0.0
        out.append({
            "agent_type": agent_type,
            "total_capacity_hours": total,
            "used_hours": used_h,
            "available_hours": available,
            "utilization_pct": pct,
        })
    return out


def check_capacity_fit(*, backlog: List[Dict[str, Any]], capacity: Dict[str, Any]) -> Dict[str, Any]:
    """Compare total estimated effort in P0+P1 tickets against coder capacity."""
    coder_capacity = _num((capacity or {}).get("coder"), 80.0)
    high_priority_hours = 0.0
    overflow_tickets = []
    for t in backlog:
        priority = t.get("priority") or _priority_from_labels(t.get("labels") or [])
        if priority in ("P0", "P1"):
            hours = _num(t.get("estimated_effort_hours") or (t.get("metadata") or {}).get("estimated_effort_hours") or 0)
            high_priority_hours += hours
            if high_priority_hours > coder_capacity:
                overflow_tickets.append(t.get("ticket_id"))
    fits = high_priority_hours <= coder_capacity
    overflow_hours = round(max(0.0, high_priority_hours - coder_capacity), 2)
    recommendation = (
        "P0/P1 work fits within sprint capacity."
        if fits
        else f"P0/P1 work exceeds coder capacity by {overflow_hours}h — consider scaling or deferring."
    )
    return {
        "fits": fits,
        "overflow_hours": overflow_hours,
        "overflow_tickets": overflow_tickets,
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Priority conflict resolution
# ---------------------------------------------------------------------------


def detect_priority_conflicts(*, backlog: List[Dict[str, Any]], capacity: Dict[str, Any]) -> List[Dict[str, Any]]:
    conflicts = []
    fit = check_capacity_fit(backlog=backlog, capacity=capacity)
    if not fit["fits"]:
        conflicts.append({
            "conflict_type": "capacity_overflow",
            "tickets": fit["overflow_tickets"],
            "description": f"P0/P1 work exceeds capacity by {fit['overflow_hours']}h.",
            "recommended_resolution": "Defer lowest-value P1 tickets to the next sprint.",
        })
    return conflicts


def escalate_conflict(*, conflict: Dict[str, Any], agent_sub: str) -> str:
    feedback_request_id = f"conflict_{uuid.uuid4().hex[:12]}"
    logger.info(
        "pm_conflict_escalated type=%s tickets=%d", conflict.get("conflict_type"), len(conflict.get("tickets", []))
    )
    return feedback_request_id


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def generate_daily_report(
    *,
    space_id: Optional[str],
    backlog: List[Dict[str, Any]],
    blockers: List[Dict[str, Any]],
    agent_utilization: List[Dict[str, Any]],
    recent_completions: List[Dict[str, Any]],
) -> str:
    lines = ["# Daily Project Report", ""]
    lines.append(f"_Generated at {now_ts()} (Unix)_\n")
    lines.append("## Completed Recently")
    if recent_completions:
        for c in recent_completions[:10]:
            lines.append(f"- {c.get('ticket_id')}: {c.get('subject')}")
    else:
        lines.append("- (none)")
    lines.append("\n## In Progress")
    in_progress = [t for t in backlog if t.get("status") == "in_progress"]
    if in_progress:
        for t in in_progress[:10]:
            lines.append(f"- {t.get('ticket_id')}: {t.get('subject')} (agent: {t.get('assigned_to_sub') or 'unassigned'})")
    else:
        lines.append("- (none)")
    lines.append("\n## Blockers")
    if blockers:
        for b in blockers[:10]:
            lines.append(f"- {b.get('ticket_id')} [{b.get('blocker_type')}]: {b.get('details')}")
    else:
        lines.append("- (none)")
    lines.append("\n## Agent Utilization")
    for u in agent_utilization:
        lines.append(f"- {u['agent_type']}: {u['used_hours']}/{u['total_capacity_hours']}h ({u['utilization_pct']}%)")
    p0 = sum(1 for t in backlog if (t.get("priority") or _priority_from_labels(t.get("labels") or [])) == "P0")
    lines.append(f"\n## Key Metrics\n- Open P0: {p0}\n- Backlog size: {len(backlog)}")
    return "\n".join(lines)


def generate_weekly_report(
    *,
    space_id: Optional[str],
    sprint: Optional[Dict[str, Any]],
    velocity_trend: Dict[str, Any],
    backlog: List[Dict[str, Any]],
    agent_utilization: List[Dict[str, Any]],
    blockers: List[Dict[str, Any]],
) -> str:
    lines = ["# Weekly Project Report", ""]
    lines.append("## Sprint Progress")
    if sprint:
        lines.append(
            f"- Sprint #{sprint['sprint_number']} ({sprint['start_date']} → {sprint['end_date']}): "
            f"{sprint['completed_hours']}/{sprint['planned_hours']}h, "
            f"{sprint['tickets_completed']}/{sprint['tickets_planned']} tickets"
        )
    else:
        lines.append("- No active sprint.")
    lines.append("\n## Velocity Trend")
    lines.append(f"- Direction: {velocity_trend.get('trend')}; recent: {velocity_trend.get('velocities')}")
    lines.append(f"- Avg velocity: {velocity_trend.get('avg_velocity')}h; forecast next: {velocity_trend.get('prediction_next')}h")
    lines.append("\n## Backlog Health")
    by_priority: Dict[str, int] = {p: 0 for p in PRIORITIES}
    for t in backlog:
        p = t.get("priority") or _priority_from_labels(t.get("labels") or []) or "P3"
        by_priority[p] = by_priority.get(p, 0) + 1
    for p in PRIORITIES:
        lines.append(f"- {p}: {by_priority.get(p, 0)}")
    lines.append("\n## Capacity")
    for u in agent_utilization:
        lines.append(f"- {u['agent_type']}: {u['utilization_pct']}% utilized")
    lines.append(f"\n## Blockers\n- {len(blockers)} active blocker(s)")
    lines.append("\n## Recommendations")
    fit = check_capacity_fit(backlog=backlog, capacity={u["agent_type"]: u["total_capacity_hours"] for u in agent_utilization})
    lines.append(f"- {fit['recommendation']}")
    return "\n".join(lines)


def save_report(
    *,
    space_id: Optional[str],
    report_type: str,
    content: str,
    metrics_snapshot: Dict[str, Any],
    agent_run_id: str,
) -> str:
    """Write a report to project_reports table. Returns report_id."""
    ensure_tables()
    report_id = uuid.uuid4().hex
    ts = now_ts()
    T.project_reports.put_item(
        Item=_ddb_safe({
            "pk": _project_pk(space_id),
            "sk": f"REPORT#{ts}#{report_id}",
            "report_id": report_id,
            "report_type": report_type,
            "agent_run_id": agent_run_id,
            "content": content[:50000],
            "metrics_snapshot": metrics_snapshot,
            "created_at": ts,
        })
    )
    return report_id


def list_reports(*, space_id: Optional[str], limit: int = 50) -> List[Dict[str, Any]]:
    ensure_tables()
    resp = T.project_reports.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": _project_pk(space_id), ":sk": "REPORT#"},
        ScanIndexForward=False,
        Limit=max(1, min(int(limit or 50), 100)),
    )
    return [_report_out(i) for i in resp.get("Items", [])]


def get_report(*, space_id: Optional[str], report_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.project_reports.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": _project_pk(space_id), ":sk": "REPORT#"},
    )
    for i in resp.get("Items", []):
        if i.get("report_id") == report_id:
            return _report_out(i)
    return None


def _report_out(item: Dict[str, Any]) -> Dict[str, Any]:
    snap = item.get("metrics_snapshot") or {}
    return {
        "report_id": item.get("report_id", ""),
        "report_type": item.get("report_type", "daily"),
        "content": item.get("content", ""),
        "metrics_snapshot": json.loads(json.dumps(snap, default=str)),
        "created_at": int(item.get("created_at", 0) or 0),
    }


def send_report_notifications(
    *, report_id: str, stakeholder_subs: Optional[List[str]], report_type: str
) -> None:
    for sub in stakeholder_subs or []:
        logger.info("pm_report_notification report=%s type=%s -> %s", report_id, report_type, sub)


# ---------------------------------------------------------------------------
# Workflow orchestration
# ---------------------------------------------------------------------------

WORKFLOW_STEP_TYPES = {
    "idea_triage": ["fetch_ideas", "triage_each", "assign_priority", "create_feature_requests", "update_idea_status"],
    "backlog_prioritize": ["fetch_backlog", "score_tickets", "reorder_backlog", "apply_labels", "detect_conflicts", "escalate_conflicts"],
    "report_generate": ["fetch_sprint", "calculate_velocity", "detect_blockers", "get_utilization", "generate_report", "save_report", "send_notifications"],
    "blocker_detect": ["scan_tickets", "classify_blockers", "escalate", "update_tickets"],
    "sprint_plan": ["close_current", "carry_over", "plan_next", "calculate_forecast"],
}


def build_pm_workflow(*, agent_run_id: str, agent_type_id: str, operation_type: str) -> Dict[str, Any]:
    """Return ordered workflow steps based on operation type. Pure / no I/O."""
    if operation_type not in OPERATION_TYPES:
        raise ValueError("invalid_operation_type")
    step_names = WORKFLOW_STEP_TYPES[operation_type]
    steps = [
        {"step_id": i + 1, "type": name, "on_failure": "escalate" if name in ("fetch_ideas", "fetch_backlog", "save_report") else "next"}
        for i, name in enumerate(step_names)
    ]
    return {
        "agent_run_id": agent_run_id,
        "agent_type_id": agent_type_id,
        "operation_type": operation_type,
        "steps": steps,
    }


# ---------------------------------------------------------------------------
# PM output storage
# ---------------------------------------------------------------------------


def build_pm_output(
    *,
    operation_type: str,
    ideas_processed: int = 0,
    ideas_accepted: int = 0,
    ideas_rejected: int = 0,
    feature_tickets_created: Optional[List[str]] = None,
    tickets_reprioritized: int = 0,
    blockers_found: int = 0,
    escalations_created: int = 0,
    report_id: Optional[str] = None,
    sprint_id: Optional[str] = None,
    velocity_current: Optional[float] = None,
    velocity_trend: Optional[str] = None,
    duration_seconds: int = 0,
) -> Dict[str, Any]:
    return {
        "operation_type": operation_type,
        "ideas_processed": int(ideas_processed),
        "ideas_accepted": int(ideas_accepted),
        "ideas_rejected": int(ideas_rejected),
        "feature_tickets_created": list(feature_tickets_created or []),
        "tickets_reprioritized": int(tickets_reprioritized),
        "blockers_found": int(blockers_found),
        "escalations_created": int(escalations_created),
        "report_id": report_id,
        "sprint_id": sprint_id,
        "velocity_current": velocity_current,
        "velocity_trend": velocity_trend,
        "total_duration_seconds": int(duration_seconds or 0),
    }


def store_pm_output(*, run_id: str, agent_type_id: str, output: Dict[str, Any]) -> Dict[str, Any]:
    coder_svc.ensure_tables()
    ts = now_ts()
    item = {
        "pk": coder_svc._run_pk(run_id),  # noqa: SLF001 - shared key scheme
        "sk": "PM_OUTPUT",
        "run_id": run_id,
        "agent_type_id": agent_type_id,
        "pm_output": output,
        "created_at": ts,
        "gsi_type_date_pk": f"PM#{agent_type_id}",
        "gsi_type_date_sk": f"DATE#{ts}",
    }
    T.agent_runs.put_item(Item=_ddb_safe(item))
    return output


def get_pm_output(*, run_id: str) -> Optional[Dict[str, Any]]:
    coder_svc.ensure_tables()
    resp = T.agent_runs.get_item(
        Key={"pk": coder_svc._run_pk(run_id), "sk": "PM_OUTPUT"}  # noqa: SLF001
    )
    item = resp.get("Item")
    return item.get("pm_output") if item else None


# ---------------------------------------------------------------------------
# Mock orchestration drivers (deterministic E2E transitions)
# ---------------------------------------------------------------------------


def run_idea_triage(*, run_id: str, agent_type_id: str, config: Dict[str, Any], agent_sub: str, limit: int = 25) -> Dict[str, Any]:
    """Triage all submitted ideas; create feature requests if auto enabled.

    Deterministic in mock mode (gated by S.pm_execute_commands).
    """
    cfg = _normalize_config(config)
    pending = list_ideas(status="submitted", limit=limit).get("ideas", [])
    processed = accepted = rejected = 0
    feature_ticket_ids: List[str] = []
    for idea in pending:
        processed += 1
        triage = triage_idea(
            idea=idea,
            coding_tool=cfg.get("coding_tool", "claude_code"),
            model=cfg.get("coding_tool_model"),
            priority_framework=cfg.get("priority_framework", _DEFAULT_PRIORITY_FRAMEWORK),
            priority_weights=cfg.get("priority_weights", _DEFAULT_PRIORITY_WEIGHTS),
        )
        if cfg.get("auto_create_feature_requests"):
            result = convert_idea_to_feature_request(
                idea_id=idea["idea_id"],
                agent_sub=agent_sub,
                triage_result=triage,
                space_id=cfg.get("project_space_id"),
            )
            feature_ticket_ids.append(result["feature_ticket"].get("ticket_id"))
            accepted += 1
        else:
            update_idea_status(
                idea_id=idea["idea_id"],
                status="accepted",
                priority_suggestion=triage["priority"],
                impact_score=triage["impact_score"],
                effort_score=triage["effort_score"],
                priority_rationale=triage["rationale"],
            )
            accepted += 1
    output = build_pm_output(
        operation_type="idea_triage",
        ideas_processed=processed,
        ideas_accepted=accepted,
        ideas_rejected=rejected,
        feature_tickets_created=feature_ticket_ids,
        duration_seconds=5,
    )
    store_pm_output(run_id=run_id, agent_type_id=agent_type_id, output=output)
    return output


def run_backlog_prioritize(*, run_id: str, agent_type_id: str, config: Dict[str, Any], agent_sub: str) -> Dict[str, Any]:
    cfg = _normalize_config(config)
    space_id = cfg.get("project_space_id")
    backlog = get_backlog(space_id=space_id)
    prioritized = prioritize_backlog(
        backlog=backlog,
        weights=cfg.get("priority_weights", _DEFAULT_PRIORITY_WEIGHTS),
        capacity=cfg.get("capacity_per_agent_type", _DEFAULT_CAPACITY),
    )
    reprioritized = apply_priorities(
        prioritized=prioritized, agent_sub=agent_sub, auto_prioritize=bool(cfg.get("auto_prioritize", True))
    )
    conflicts = detect_priority_conflicts(
        backlog=prioritized, capacity=cfg.get("capacity_per_agent_type", _DEFAULT_CAPACITY)
    )
    escalations = 0
    if cfg.get("escalation_on_conflict", True):
        for c in conflicts:
            escalate_conflict(conflict=c, agent_sub=agent_sub)
            escalations += 1
    output = build_pm_output(
        operation_type="backlog_prioritize",
        tickets_reprioritized=reprioritized,
        escalations_created=escalations,
        duration_seconds=2,
    )
    store_pm_output(run_id=run_id, agent_type_id=agent_type_id, output=output)
    return output


def run_report_generate(*, run_id: str, agent_type_id: str, config: Dict[str, Any], agent_sub: str, report_type: str = "daily") -> Dict[str, Any]:
    cfg = _normalize_config(config)
    space_id = cfg.get("project_space_id")
    capacity = cfg.get("capacity_per_agent_type", _DEFAULT_CAPACITY)
    backlog = get_backlog(space_id=space_id)
    blockers = detect_blockers(space_id=space_id, stale_hours=int(cfg.get("blocker_stale_hours", 48)))
    utilization = get_agent_utilization(capacity=capacity, backlog=backlog)
    sprint = get_current_sprint(space_id=space_id)
    sprints = list_sprints(space_id=space_id)
    trend = get_velocity_trend(sprints=sprints)
    recent = [
        {"ticket_id": t.get("ticket_id"), "subject": t.get("subject"), "completed_at": int(t.get("updated_at", 0) or 0)}
        for t in _scan_backlog_tickets(space_id=space_id, statuses=list(_DONE_STATUSES), limit=20)
    ]
    if report_type == "weekly":
        content = generate_weekly_report(
            space_id=space_id, sprint=sprint, velocity_trend=trend,
            backlog=backlog, agent_utilization=utilization, blockers=blockers,
        )
    else:
        content = generate_daily_report(
            space_id=space_id, backlog=backlog, blockers=blockers,
            agent_utilization=utilization, recent_completions=recent,
        )
    metrics_snapshot = {
        "backlog_size": len(backlog),
        "blockers": len(blockers),
        "velocity_trend": trend.get("trend"),
    }
    report_id = save_report(
        space_id=space_id, report_type=report_type, content=content,
        metrics_snapshot=metrics_snapshot, agent_run_id=run_id,
    )
    send_report_notifications(
        report_id=report_id, stakeholder_subs=cfg.get("stakeholder_subs"), report_type=report_type
    )
    output = build_pm_output(
        operation_type="report_generate",
        blockers_found=len(blockers),
        report_id=report_id,
        velocity_current=trend.get("avg_velocity"),
        velocity_trend=trend.get("trend"),
        duration_seconds=3,
    )
    store_pm_output(run_id=run_id, agent_type_id=agent_type_id, output=output)
    return output


def run_blocker_detect(*, run_id: str, agent_type_id: str, config: Dict[str, Any], agent_sub: str) -> Dict[str, Any]:
    cfg = _normalize_config(config)
    space_id = cfg.get("project_space_id")
    blockers = detect_blockers(space_id=space_id, stale_hours=int(cfg.get("blocker_stale_hours", 48)))
    escalations = escalate_blockers(blockers=blockers, agent_sub=agent_sub)
    output = build_pm_output(
        operation_type="blocker_detect",
        blockers_found=len(blockers),
        escalations_created=escalations,
        duration_seconds=1,
    )
    store_pm_output(run_id=run_id, agent_type_id=agent_type_id, output=output)
    return output


# ---------------------------------------------------------------------------
# Dashboard + metrics
# ---------------------------------------------------------------------------


def get_pm_metrics(*, space_id: Optional[str], period_days: int = 30) -> Dict[str, Any]:
    ensure_tables()
    now = now_ts()
    period_start = now - period_days * 86400
    all_ideas = list_ideas(limit=100).get("ideas", [])
    ideas_submitted = len(all_ideas)
    ideas_converted = sum(1 for i in all_ideas if i.get("status") == "converted")
    backlog = get_backlog(space_id=space_id)
    sprints = list_sprints(space_id=space_id)
    trend = get_velocity_trend(sprints=sprints)
    current = get_current_sprint(space_id=space_id)
    p0_count = sum(
        1 for t in backlog if (_priority_from_labels(t.get("labels") or []) or (t.get("metadata") or {}).get("priority")) == "P0"
    )
    blockers = detect_blockers(space_id=space_id, stale_hours=48)
    features_in_pipeline = sum(
        1 for t in backlog if FEATURE_REQUEST_LABEL in (t.get("labels") or []) or t.get("status") in ("in_progress", "code_complete")
    )
    return {
        "ideas_submitted": ideas_submitted,
        "ideas_converted": ideas_converted,
        "features_in_pipeline": features_in_pipeline,
        "velocity_current": _num(current.get("velocity")) if current else trend.get("avg_velocity", 0.0),
        "velocity_trend": trend.get("trend", "stable"),
        "backlog_size": len(backlog),
        "p0_count": p0_count,
        "blockers_count": len(blockers),
        "avg_cycle_time_hours": 0.0,
        "period_start": period_start,
        "period_end": now,
    }


def get_project_dashboard(*, space_id: Optional[str], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ensure_tables()
    cfg = _normalize_config(config or {})
    capacity = cfg.get("capacity_per_agent_type", _DEFAULT_CAPACITY)
    backlog_raw = get_backlog(space_id=space_id)
    prioritized = prioritize_backlog(
        backlog=backlog_raw, weights=cfg.get("priority_weights", _DEFAULT_PRIORITY_WEIGHTS), capacity=capacity
    )
    sprints = list_sprints(space_id=space_id)
    current = get_current_sprint(space_id=space_id)
    trend = get_velocity_trend(sprints=sprints)
    velocity_trend = [
        {"sprint_number": s["sprint_number"], "velocity": _num(s.get("velocity"))}
        for s in sprints
        if s.get("status") == "completed"
    ]
    backlog_by_priority: Dict[str, int] = {p: 0 for p in PRIORITIES}
    for t in prioritized:
        backlog_by_priority[t.get("priority", "P3")] = backlog_by_priority.get(t.get("priority", "P3"), 0) + 1

    ideas = list_ideas(limit=100).get("ideas", [])
    pipeline_funnel = [
        {"stage": "Ideas", "count": len(ideas)},
        {"stage": "Feature Requests", "count": sum(1 for t in backlog_raw if FEATURE_REQUEST_LABEL in (t.get("labels") or []))},
        {"stage": "In Progress", "count": sum(1 for t in backlog_raw if t.get("status") == "in_progress")},
        {"stage": "Code Complete", "count": sum(1 for t in backlog_raw if t.get("status") == "code_complete")},
        {"stage": "QA", "count": sum(1 for t in backlog_raw if t.get("status") in ("qa_in_progress", "qa_approved"))},
    ]
    blockers = detect_blockers(space_id=space_id, stale_hours=int(cfg.get("blocker_stale_hours", 48)))
    utilization = get_agent_utilization(capacity=capacity, backlog=backlog_raw)
    recent = [
        {"ticket_id": t.get("ticket_id"), "subject": t.get("subject"), "completed_at": int(t.get("updated_at", 0) or 0)}
        for t in _scan_backlog_tickets(space_id=space_id, statuses=list(_DONE_STATUSES), limit=10)
    ]
    return {
        "sprint": current,
        "velocity_trend": velocity_trend or [{"sprint_number": 0, "velocity": v} for v in [trend.get("avg_velocity", 0.0)]],
        "backlog_by_priority": backlog_by_priority,
        "pipeline_funnel": pipeline_funnel,
        "agent_utilization": utilization,
        "blockers": blockers,
        "recent_completions": recent,
    }

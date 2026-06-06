"""Stylist / UI Agent service (AGENT-016).

The Stylist Agent is a visual-design-review agent *type*. It picks up UI/design
tickets (``type:ui`` / ``type:ui_review`` / ``type:design``), audits pages and
components for design-system / accessibility / responsive issues, proposes style
fixes (Tailwind / shadcn), and produces visual-diff / style reports.

This module owns:

* UI review CRUD on the ``stylist_ui_reviews`` table (per-page design scores,
  screenshots, annotations, issues)
* design-rule CRUD on the ``stylist_design_rules`` table
* per-page + overall design-consistency / accessibility scoring
* issue -> ticket promotion (``type:ui_review`` tickets) via the tickets service
* Stylist Agent config storage on the shared ``agent_types`` table
* a deterministic, mockable review lifecycle for E2E

Real browser/Playwright/screenshot execution is gated behind
``S.stylist_agent_execute_commands`` (default off, and always off in E2E). When
disabled the review payloads are accepted/generated and stored verbatim so the
lifecycle is fully deterministic and testable.
"""

from __future__ import annotations

import hashlib
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

logger = logging.getLogger("app.agent_stylist")

STYLIST_AGENT_TYPE = "stylist"

_REVIEW_TYPES = ("full_page", "component", "responsive", "accessibility", "pr_review")
_RULE_CATEGORIES = (
    "spacing",
    "color",
    "typography",
    "layout",
    "component",
    "responsive",
    "accessibility",
)
_SEVERITIES = ("error", "warning", "info")
_SEVERITY_RANK = {"info": 0, "warning": 1, "error": 2}

_MAX_ISSUES_PER_REVIEW = 100
_MAX_SCREENSHOTS_PER_REVIEW = 60
_UI_TICKET_LABEL = "type:ui_review"

_CONFIG_FIELDS = (
    "review_on_pr_merge",
    "review_on_ui_ticket",
    "periodic_review_frequency",
    "periodic_review_day",
    "periodic_review_hour_utc",
    "viewports",
    "pages_to_review",
    "design_system_ref",
    "tailwind_config_path",
    "contrast_ratio_min",
    "auto_create_tickets",
    "ticket_min_severity",
    "brand_colors",
    "font_families",
    # GAP-0103: name of the Secrets Manager secret holding live-app auth
    # credentials for authenticated Playwright review sessions. This is a
    # *pointer* (ARN / secret name), never the raw credential. Stored in DDB;
    # the raw credential is resolved at trigger time and never persisted.
    "app_auth_credentials_secret_name",
)

# Static mock credentials used in dev mode so the dev and prod credential
# resolution code paths are identical (SECOPS-007). The same _resolve_app_credentials
# entrypoint and the same trigger_review gate run in both modes.
_DEV_MOCK_APP_CREDENTIALS: Dict[str, str] = {
    "username": "e2e_alice@test.local",
    "password": "devpassword",
}


# ---------------------------------------------------------------------------
# Table bootstrap (idempotent; tables are additive per AGENT-001/016)
# ---------------------------------------------------------------------------

_BOOTSTRAPPED = False


def ensure_tables() -> None:
    """Create the stylist_ui_reviews / stylist_design_rules / agent_types tables
    on first use if absent so the feature works in any environment (E2E live DDB,
    fresh stacks) without requiring a stack re-init."""
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
            "TableName": S.stylist_ui_reviews_table_name,
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
            "TableName": S.stylist_design_rules_table_name,
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
    for kwargs in specs:
        try:
            client.create_table(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ResourceInUseException",):
                logger.warning("ensure_tables: could not create %s: %s", kwargs["TableName"], exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ensure_tables: %s create error: %s", kwargs["TableName"], exc)
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def _user_pk(user_id: str) -> str:
    return f"USER#{user_id}"


def _review_sk(review_id: str) -> str:
    return f"REVIEW#{review_id}"


def _rule_sk(rule_id: str) -> str:
    return f"RULE#{rule_id}"


def _page_hash(page_url: str) -> str:
    return hashlib.sha256((page_url or "").encode("utf-8")).hexdigest()[:16]


def _type_pk(type_id: str) -> str:
    return f"TYPE#{type_id}"


# ---------------------------------------------------------------------------
# Number coercion (DynamoDB returns Decimal)
# ---------------------------------------------------------------------------


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_viewports(viewports: Optional[List[Dict[str, Any]]]) -> List[str]:
    errors: List[str] = []
    for vp in viewports or []:
        for dim in ("width", "height"):
            val = vp.get(dim)
            if val is None:
                continue
            try:
                n = int(val)
            except (TypeError, ValueError):
                errors.append(f"Viewport {dim} must be an integer")
                continue
            if not (320 <= n <= 3840):
                errors.append("Viewport width must be between 320 and 3840")
    return errors


# ---------------------------------------------------------------------------
# Issue normalization
# ---------------------------------------------------------------------------


def _normalize_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(issue or {})
    out.setdefault("issue_id", uuid.uuid4().hex)
    out.setdefault("category", "design")
    out.setdefault("severity", "warning")
    out.setdefault("title", "")
    out.setdefault("description", "")
    out.setdefault("suggestion", "")
    out.setdefault("created_ticket_id", None)
    return out


# ---------------------------------------------------------------------------
# Review CRUD
# ---------------------------------------------------------------------------


def create_review(
    *,
    user_id: str,
    agent_id: str = "",
    worker_id: str = "",
    page_url: str,
    page_name: str = "",
    review_type: str = "full_page",
    screenshots: Optional[List[Dict[str, Any]]] = None,
    design_score: float = 0.0,
    accessibility_score: Optional[float] = None,
    issues: Optional[List[Dict[str, Any]]] = None,
    annotations: Optional[List[Dict[str, Any]]] = None,
    source_ref: Optional[str] = None,
    status: str = "completed",
) -> Dict[str, Any]:
    """Create a UI review result and (optionally) auto-create issue tickets."""
    ensure_tables()
    review_id = uuid.uuid4().hex
    ts = now_ts()

    norm_screens = list((screenshots or [])[:_MAX_SCREENSHOTS_PER_REVIEW])
    norm_issues = [_normalize_issue(i) for i in (issues or [])[:_MAX_ISSUES_PER_REVIEW]]
    norm_annotations = list(annotations or [])
    issues_found = len(norm_issues)

    item: Dict[str, Any] = {
        "pk": _user_pk(user_id),
        "sk": _review_sk(review_id),
        "review_id": review_id,
        "user_id": user_id,
        "agent_id": agent_id,
        "worker_id": worker_id,
        "page_url": page_url,
        "page_name": page_name or page_url,
        "review_type": review_type,
        "source_ref": source_ref,
        "screenshots": norm_screens,
        "annotations": norm_annotations,
        "design_score": _to_float(design_score),
        "accessibility_score": (None if accessibility_score is None else _to_float(accessibility_score)),
        "issues_found": issues_found,
        "issues": norm_issues,
        "status": status,
        "created_at": ts,
        "GSI1PK": f"{_user_pk(user_id)}#PAGE#{_page_hash(page_url)}",
        "GSI1SK": ts,
        "GSI2PK": f"{_user_pk(user_id)}#TYPE#{review_type}",
        "GSI2SK": ts,
    }
    T.stylist_ui_reviews.put_item(Item={k: v for k, v in item.items() if v is not None})

    # Auto-create tickets for issues at/above min severity if enabled.
    config = get_stylist_config(user_id=user_id) or {}
    if config.get("auto_create_tickets"):
        min_sev = config.get("ticket_min_severity", "warning")
        threshold = _SEVERITY_RANK.get(min_sev, 1)
        for issue in norm_issues:
            if _SEVERITY_RANK.get(issue.get("severity", "info"), 0) >= threshold:
                try:
                    _create_issue_ticket_inner(
                        user_id=user_id, review_id=review_id, issue=issue, page_url=page_url
                    )
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("auto ticket create failed: %s", exc)
        # persist mutated created_ticket_id values
        T.stylist_ui_reviews.update_item(
            Key={"pk": _user_pk(user_id), "sk": _review_sk(review_id)},
            UpdateExpression="SET issues = :i",
            ExpressionAttributeValues={":i": norm_issues},
        )

    return _review_out(item)


def _review_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "review_id": item.get("review_id", ""),
        "agent_id": item.get("agent_id", ""),
        "worker_id": item.get("worker_id", ""),
        "page_url": item.get("page_url", ""),
        "page_name": item.get("page_name", ""),
        "review_type": item.get("review_type", "full_page"),
        "source_ref": item.get("source_ref"),
        "screenshots": item.get("screenshots", []) or [],
        "annotations": item.get("annotations", []) or [],
        "design_score": _to_float(item.get("design_score")),
        "accessibility_score": (
            None if item.get("accessibility_score") is None else _to_float(item.get("accessibility_score"))
        ),
        "issues_found": _to_int(item.get("issues_found")),
        "issues": [_coerce_issue_numbers(i) for i in (item.get("issues") or [])],
        "status": item.get("status", "completed"),
        "created_at": _to_int(item.get("created_at")),
    }


def _coerce_issue_numbers(issue: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(issue or {})
    rect = out.get("annotation_rect")
    if isinstance(rect, dict):
        out["annotation_rect"] = {k: _to_int(v) for k, v in rect.items()}
    if "screenshot_index" in out and out["screenshot_index"] is not None:
        out["screenshot_index"] = _to_int(out["screenshot_index"])
    return out


def _get_review_item(*, user_id: str, review_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.stylist_ui_reviews.get_item(Key={"pk": _user_pk(user_id), "sk": _review_sk(review_id)})
    return resp.get("Item")


def get_review(*, user_id: str, review_id: str) -> Optional[Dict[str, Any]]:
    item = _get_review_item(user_id=user_id, review_id=review_id)
    if not item:
        return None
    return _review_out(item)


def list_reviews(
    *,
    user_id: str,
    page_url: Optional[str] = None,
    review_type: Optional[str] = None,
    limit: int = 25,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List UI reviews, optionally filtered by page or type (newest first)."""
    ensure_tables()
    limit = max(1, min(limit, 100))
    start_key = decode_cursor(cursor) if cursor else None

    query_kwargs: Dict[str, Any] = {"Limit": limit, "ScanIndexForward": False}
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key

    if page_url:
        query_kwargs["IndexName"] = "GSI1"
        query_kwargs["KeyConditionExpression"] = "GSI1PK = :pk"
        query_kwargs["ExpressionAttributeValues"] = {
            ":pk": f"{_user_pk(user_id)}#PAGE#{_page_hash(page_url)}"
        }
    elif review_type:
        query_kwargs["IndexName"] = "GSI2"
        query_kwargs["KeyConditionExpression"] = "GSI2PK = :pk"
        query_kwargs["ExpressionAttributeValues"] = {
            ":pk": f"{_user_pk(user_id)}#TYPE#{review_type}"
        }
    else:
        query_kwargs["KeyConditionExpression"] = "pk = :pk AND begins_with(sk, :sk)"
        query_kwargs["ExpressionAttributeValues"] = {":pk": _user_pk(user_id), ":sk": "REVIEW#"}

    resp = T.stylist_ui_reviews.query(**query_kwargs)
    items = [_review_out(it) for it in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"reviews": items, "count": len(items), "next_cursor": next_cursor}


def _iter_all_reviews(*, user_id: str) -> List[Dict[str, Any]]:
    ensure_tables()
    items: List[Dict[str, Any]] = []
    start_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": "pk = :pk AND begins_with(sk, :sk)",
            "ExpressionAttributeValues": {":pk": _user_pk(user_id), ":sk": "REVIEW#"},
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = T.stylist_ui_reviews.query(**kwargs)
        items.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return items


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def get_page_scores(*, user_id: str) -> List[Dict[str, Any]]:
    """Latest design score per page (most recent review per page_url), worst first."""
    items = _iter_all_reviews(user_id=user_id)
    latest: Dict[str, Dict[str, Any]] = {}
    for it in items:
        page = it.get("page_url", "")
        ts = _to_int(it.get("created_at"))
        if page not in latest or ts > _to_int(latest[page].get("created_at")):
            latest[page] = it
    out: List[Dict[str, Any]] = []
    for page, it in latest.items():
        out.append(
            {
                "page_url": page,
                "page_name": it.get("page_name", page),
                "design_score": _to_float(it.get("design_score")),
                "accessibility_score": (
                    None
                    if it.get("accessibility_score") is None
                    else _to_float(it.get("accessibility_score"))
                ),
                "issues_found": _to_int(it.get("issues_found")),
                "last_reviewed": _to_int(it.get("created_at")),
            }
        )
    out.sort(key=lambda r: r["design_score"])
    return out


def get_overall_score(*, user_id: str) -> Dict[str, Any]:
    """Average of latest per-page design + accessibility scores."""
    pages = get_page_scores(user_id=user_id)
    if not pages:
        return {
            "overall_design_score": 0.0,
            "overall_accessibility_score": 0.0,
            "pages_reviewed": 0,
            "total_issues": 0,
        }
    design_vals = [p["design_score"] for p in pages]
    acc_vals = [p["accessibility_score"] for p in pages if p["accessibility_score"] is not None]
    total_issues = sum(p["issues_found"] for p in pages)
    overall_design = round(sum(design_vals) / len(design_vals), 2)
    overall_acc = round(sum(acc_vals) / len(acc_vals), 2) if acc_vals else 0.0
    return {
        "overall_design_score": overall_design,
        "overall_accessibility_score": overall_acc,
        "pages_reviewed": len(pages),
        "total_issues": total_issues,
    }


# ---------------------------------------------------------------------------
# Issue -> Ticket promotion
# ---------------------------------------------------------------------------


def _create_issue_ticket_inner(
    *, user_id: str, review_id: str, issue: Dict[str, Any], page_url: str
) -> Dict[str, Any]:
    """Create a type:ui_review ticket for an issue and stamp created_ticket_id on
    the (mutable) issue dict. Does NOT persist the review — caller persists."""
    title = issue.get("title") or "UI design issue"
    severity = issue.get("severity", "warning")
    category = issue.get("category", "design")
    desc_parts = [
        issue.get("description", ""),
        "",
        f"Page: {page_url}",
        f"Category: {category}",
        f"Severity: {severity}",
    ]
    if issue.get("page_element"):
        desc_parts.append(f"Element: {issue['page_element']}")
    if issue.get("suggestion"):
        desc_parts += ["", f"Suggestion: {issue['suggestion']}"]
    labels = [_UI_TICKET_LABEL]
    if severity == "error":
        labels.append("complexity:medium")
    else:
        labels.append("complexity:low")
    ticket = tickets_svc.STORE.create_ticket(
        owner_sub=user_id,
        subject=f"[UI] {title}",
        description="\n".join(desc_parts),
        labels=labels,
        metadata={
            "stylist_review_id": review_id,
            "stylist_issue_id": issue.get("issue_id"),
            "page_url": page_url,
        },
    )
    issue["created_ticket_id"] = ticket.get("ticket_id")
    return ticket


def create_issue_ticket(*, user_id: str, review_id: str, issue_id: str) -> Dict[str, Any]:
    """Create a ticket for a specific UI issue from a review.

    Raises LookupError("review") / LookupError("issue") and
    ValueError("duplicate") when a ticket already exists for the issue.
    """
    item = _get_review_item(user_id=user_id, review_id=review_id)
    if not item:
        raise LookupError("review")
    issues = list(item.get("issues") or [])
    target = next((i for i in issues if i.get("issue_id") == issue_id), None)
    if target is None:
        raise LookupError("issue")
    if target.get("created_ticket_id"):
        raise ValueError("duplicate")
    ticket = _create_issue_ticket_inner(
        user_id=user_id, review_id=review_id, issue=target, page_url=item.get("page_url", "")
    )
    T.stylist_ui_reviews.update_item(
        Key={"pk": _user_pk(user_id), "sk": _review_sk(review_id)},
        UpdateExpression="SET issues = :i",
        ExpressionAttributeValues={":i": issues},
    )
    return {
        "ok": True,
        "ticket_id": ticket.get("ticket_id"),
        "review_id": review_id,
        "issue_id": issue_id,
    }


# ---------------------------------------------------------------------------
# Design rules
# ---------------------------------------------------------------------------


def _rule_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rule_id": item.get("rule_id", ""),
        "name": item.get("name", ""),
        "category": item.get("category", ""),
        "description": item.get("description", ""),
        "severity": item.get("severity", "warning"),
        "enabled": bool(item.get("enabled", True)),
        "config": item.get("config"),
        "created_at": _to_int(item.get("created_at")),
    }


def create_design_rule(
    *,
    user_id: str,
    name: str,
    category: str,
    description: str,
    severity: str,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ensure_tables()
    rule_id = uuid.uuid4().hex
    ts = now_ts()
    item = {
        "pk": _user_pk(user_id),
        "sk": _rule_sk(rule_id),
        "rule_id": rule_id,
        "user_id": user_id,
        "name": name,
        "category": category,
        "description": description,
        "severity": severity,
        "enabled": True,
        "config": config,
        "created_at": ts,
    }
    T.stylist_design_rules.put_item(Item={k: v for k, v in item.items() if v is not None})
    return _rule_out(item)


def list_design_rules(
    *, user_id: str, category: Optional[str] = None, enabled_only: bool = False
) -> List[Dict[str, Any]]:
    ensure_tables()
    resp = T.stylist_design_rules.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": _user_pk(user_id), ":sk": "RULE#"},
    )
    out: List[Dict[str, Any]] = []
    for it in resp.get("Items", []):
        rule = _rule_out(it)
        if category and rule["category"] != category:
            continue
        if enabled_only and not rule["enabled"]:
            continue
        out.append(rule)
    out.sort(key=lambda r: r["created_at"], reverse=True)
    return out


def get_design_rule(*, user_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.stylist_design_rules.get_item(Key={"pk": _user_pk(user_id), "sk": _rule_sk(rule_id)})
    item = resp.get("Item")
    return _rule_out(item) if item else None


def update_design_rule(*, user_id: str, rule_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
    ensure_tables()
    existing = T.stylist_design_rules.get_item(
        Key={"pk": _user_pk(user_id), "sk": _rule_sk(rule_id)}
    ).get("Item")
    if not existing:
        return None
    allowed = ("name", "category", "description", "severity", "enabled", "config")
    set_parts: List[str] = []
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {}
    for key in allowed:
        if key in fields and fields[key] is not None:
            names[f"#{key}"] = key
            values[f":{key}"] = fields[key]
            set_parts.append(f"#{key} = :{key}")
    if not set_parts:
        return _rule_out(existing)
    T.stylist_design_rules.update_item(
        Key={"pk": _user_pk(user_id), "sk": _rule_sk(rule_id)},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    updated = T.stylist_design_rules.get_item(
        Key={"pk": _user_pk(user_id), "sk": _rule_sk(rule_id)}
    ).get("Item")
    return _rule_out(updated) if updated else None


def delete_design_rule(*, user_id: str, rule_id: str) -> bool:
    ensure_tables()
    existing = T.stylist_design_rules.get_item(
        Key={"pk": _user_pk(user_id), "sk": _rule_sk(rule_id)}
    ).get("Item")
    if not existing:
        return False
    T.stylist_design_rules.delete_item(Key={"pk": _user_pk(user_id), "sk": _rule_sk(rule_id)})
    return True


# ---------------------------------------------------------------------------
# Stylist agent config (on agent_types table, scoped per user)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG: Dict[str, Any] = {
    "review_on_pr_merge": True,
    "review_on_ui_ticket": True,
    "periodic_review_frequency": "weekly",
    "periodic_review_day": "wednesday",
    "periodic_review_hour_utc": 10,
    "viewports": [
        {"name": "mobile", "width": 375, "height": 812},
        {"name": "tablet", "width": 768, "height": 1024},
        {"name": "desktop", "width": 1280, "height": 720},
    ],
    "pages_to_review": ["/messages", "/feed", "/billing", "/files", "/settings"],
    "design_system_ref": "shadcn-ui",
    "tailwind_config_path": "frontend/src/globals.css",
    "contrast_ratio_min": 4.5,
    "auto_create_tickets": False,
    "ticket_min_severity": "warning",
    "brand_colors": ["#000000", "#ffffff", "#3b82f6", "#ef4444"],
    "font_families": ["Inter", "system-ui"],
    # Empty = no live-app credentials configured (has_app_credentials -> False).
    "app_auth_credentials_secret_name": "",
}


def _config_pk(user_id: str) -> str:
    return _type_pk(f"stylist_{user_id}")


def get_stylist_config(*, user_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _config_pk(user_id), "sk": "STYLIST_CONFIG"})
    item = resp.get("Item")
    if not item:
        return None
    config = item.get("stylist_config")
    if not config:
        return None
    return _coerce_config_numbers(config)


def update_stylist_config(*, user_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Merge provided fields onto the stored (or default) config and persist."""
    ensure_tables()
    current = get_stylist_config(user_id=user_id) or dict(_DEFAULT_CONFIG)
    merged = dict(current)
    for key in _CONFIG_FIELDS:
        if key in fields and fields[key] is not None:
            merged[key] = fields[key]
    ts = now_ts()
    T.agent_types.put_item(
        Item={
            "pk": _config_pk(user_id),
            "sk": "STYLIST_CONFIG",
            "agent_type": STYLIST_AGENT_TYPE,
            "owner_sub": user_id,
            "stylist_config": merged,
            "updated_at": ts,
        }
    )
    out = dict(merged)
    out["updated_at"] = ts
    return _coerce_config_numbers(out)


def _coerce_config_numbers(config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(config)
    if "contrast_ratio_min" in out and out["contrast_ratio_min"] is not None:
        out["contrast_ratio_min"] = _to_float(out["contrast_ratio_min"])
    if "periodic_review_hour_utc" in out and out["periodic_review_hour_utc"] is not None:
        out["periodic_review_hour_utc"] = _to_int(out["periodic_review_hour_utc"])
    vps = out.get("viewports")
    if isinstance(vps, list):
        out["viewports"] = [
            {k: (_to_int(v) if k in ("width", "height") else v) for k, v in vp.items()}
            for vp in vps
        ]
    # GAP-0103: expose only a derived boolean indicator. The raw secret pointer
    # is intentionally NOT surfaced via StylistConfigOut (which has no
    # app_auth_credentials_secret_name field), and the credential itself is
    # never stored in DDB nor returned by any endpoint.
    out["has_app_credentials"] = bool(out.get("app_auth_credentials_secret_name"))
    return out


def _resolve_app_credentials(*, user_id: str) -> Optional[Dict[str, str]]:
    """Resolve live-app auth credentials for an authenticated Playwright session.

    Returns a dict (e.g. ``{"username": ..., "password": ...}`` or a session-cookie
    bundle) or ``None`` when no credentials are configured. The raw credential is
    NEVER persisted to DDB and never returned by any API endpoint.

    Dev/prod parity (SECOPS-007): both modes go through this single entrypoint.
    In dev mode a static mock is returned (no network / AWS call). In prod the
    credential is fetched from AWS Secrets Manager using the configured secret
    name pointer stored on the stylist config.
    """
    if S.dev_mode:
        return dict(_DEV_MOCK_APP_CREDENTIALS)
    config = get_stylist_config(user_id=user_id) or {}
    secret_name = (config.get("app_auth_credentials_secret_name") or "").strip()
    if not secret_name:
        return None
    try:
        # Imported lazily so dev/test paths never touch boto3/AWS.
        from app.core.aws import secretsmanager

        resp = secretsmanager.get_secret_value(SecretId=secret_name)
        import json as _json

        creds = _json.loads(resp["SecretString"])
        if not isinstance(creds, dict):
            return None
        return creds
    except Exception as exc:  # pragma: no cover - prod-only Secrets Manager path
        logger.error("Failed to resolve stylist app credentials: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Deterministic mock review lifecycle (gated)
# ---------------------------------------------------------------------------


def _mock_screenshot(viewport: Dict[str, Any], page_url: str) -> Dict[str, Any]:
    name = viewport.get("name", "desktop")
    w = _to_int(viewport.get("width"), 1280)
    h = _to_int(viewport.get("height"), 720)
    prefix = f"agent-artifacts/stylist/{_page_hash(page_url)}"
    return {
        "url": f"/mock/s3/{prefix}/{name}.png",
        "viewport": f"{w}x{h}",
        "label": name,
    }


def trigger_review(
    *,
    user_id: str,
    pages: List[str],
    review_type: str = "full_page",
    viewports: Optional[List[Dict[str, Any]]] = None,
    agent_id: str = "stylist",
) -> Dict[str, Any]:
    """Run a (mock) UI review for the given pages and persist one review per page.

    Gated: when ``S.stylist_agent_execute_commands`` is true this would dispatch
    to the real Worker Agent Framework (Playwright capture). For now the mock is
    the only path so the lifecycle is deterministic / testable.
    """
    config = get_stylist_config(user_id=user_id) or dict(_DEFAULT_CONFIG)
    # GAP-0103: real Playwright execution requires authenticated app sessions.
    # When the execute gate is on, refuse to run unless credentials resolve
    # (dev mock or Secrets Manager). The mock review path below is unaffected.
    if S.stylist_agent_execute_commands:
        creds = _resolve_app_credentials(user_id=user_id)
        if creds is None:
            raise ValueError("app_auth_credentials_not_configured")
    vps = viewports or config.get("viewports") or _DEFAULT_CONFIG["viewports"]
    if review_type != "responsive":
        # full_page / accessibility default to the desktop viewport only
        vps = [vps[-1]] if vps else [{"name": "desktop", "width": 1280, "height": 720}]

    created: List[Dict[str, Any]] = []
    for page in pages:
        screenshots = [_mock_screenshot(vp, page) for vp in vps]
        # Deterministic mock scoring: pages with "/missing" treated as not-found.
        if "/missing" in page or "/404" in page:
            review = create_review(
                user_id=user_id,
                agent_id=agent_id,
                page_url=page,
                page_name=page,
                review_type=review_type,
                screenshots=[],
                design_score=0.0,
                accessibility_score=0.0,
                issues=[],
                status="failed",
            )
            review["page_not_found"] = True
            created.append(review)
            continue
        review = create_review(
            user_id=user_id,
            agent_id=agent_id,
            page_url=page,
            page_name=page,
            review_type=review_type,
            screenshots=screenshots,
            design_score=88.0,
            accessibility_score=92.0,
            issues=[
                {
                    "category": "spacing",
                    "severity": "warning",
                    "title": "Inconsistent card padding",
                    "description": f"Card padding on {page} differs from the design system default.",
                    "suggestion": "Standardize to p-4 across card components.",
                    "screenshot_index": 0,
                }
            ],
            status="completed",
        )
        created.append(review)
    return {"ok": True, "reviews": created, "count": len(created)}

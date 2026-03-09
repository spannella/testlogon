from __future__ import annotations

import base64
import json
import os
import time
import uuid
from typing import Any, Dict, Literal

from boto3.dynamodb.conditions import Attr, Key
from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_scope
from app.auth.roles import AdminScope, admin_profile_has_scope, normalize_admin_profile
from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T
from app.services.moderation_content_removal import apply_content_removal
from app.services.moderation_audit_log import write_moderation_audit_event
from app.services.moderation_policy_engine import apply_ban, issue_warning_notification, notify_content_removal
from app.services.moderation_kpis import compute_moderation_kpis, evaluate_and_dispatch_moderation_alerts
from app.services.moderation_flags import (
    ensure_admin_actions_enabled,
    ensure_admin_board_enabled,
    ensure_permanent_ban_scope_rollout,
    get_moderation_feature_flags,
    set_moderation_feature_flags,
)

router = APIRouter(prefix="/v1/admin/moderation", tags=["admin-moderation"])

require_content_moderation_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)
APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
MESSAGES_TABLE = os.environ.get("DDB_MESSAGES", "Messages")
SERIALIZER = TypeSerializer()
POLICY_CATEGORY_RANK = {"spam": 1, "sexual": 2, "racist": 2, "criminal": 3, "extortion": 4}


def _require_senior_moderation_for_permanent_ban(*, admin: AuthenticatedUser) -> None:
    if admin.role.name == "ROOT":
        return
    profile = normalize_admin_profile(getattr(admin, "admin_profile", None))
    if admin_profile_has_scope(profile, AdminScope.CONTENT_MODERATION_SENIOR):
        return
    raise HTTPException(
        status_code=403,
        detail={
            "code": "role_required_scope",
            "required_scope": AdminScope.CONTENT_MODERATION_SENIOR.value,
            "actual_role": str(getattr(admin.role, "value", admin.role)),
            "actual_admin_profile": profile.to_dict(),
        },
    )




def _require_dual_approval_for_permanent_ban(*, admin: AuthenticatedUser, second_approver_admin_user_id: str | None) -> None:
    if not bool(getattr(S, "moderation_dual_approval_permanent_ban_enabled", False)):
        return
    approver = str(second_approver_admin_user_id or "").strip()
    if not approver:
        raise HTTPException(status_code=403, detail="second approver is required for permanent ban")
    if approver == admin.sub:
        raise HTTPException(status_code=403, detail="second approver must be different from acting admin")

def _encode_cursor(cursor: Dict[str, Any] | None) -> str | None:
    if not cursor:
        return None
    payload = json.dumps(cursor).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("utf-8")


def _decode_cursor(cursor: str | None) -> Dict[str, Any] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("utf-8"))
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid cursor") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid cursor")
    return data


class ModerationTicketOut(BaseModel):
    ticket_id: str
    content_type: str
    content_id: str
    status: str
    priority: str
    queue: str
    assigned_admin_user_id: str | None = None
    report_count: int = 0
    aggregated_topics: list[str] = Field(default_factory=list)
    latest_report_at: int
    updated_at: int
    created_at: int


class ModerationTicketsListOut(BaseModel):
    items: list[ModerationTicketOut]
    next_cursor: str | None = None


class LinkedReportOut(BaseModel):
    report_id: str
    reporter_user_id: str
    topics: list[str] = Field(default_factory=list)
    reason_text: str
    created_at: int
    metadata: dict[str, Any] = Field(default_factory=dict)




class UserEnforcementHistoryOut(BaseModel):
    user_id: str
    enforcement_id: str
    enforcement_type: str
    status: str
    source_ticket_id: str
    created_at: int
    created_by_admin_user_id: str | None = None
    duration_days: int = 0
    note: str = ""


class UserEnforcementHistoryListOut(BaseModel):
    items: list[UserEnforcementHistoryOut]

class OffenderHistorySummaryOut(BaseModel):
    offender_user_id: str | None = None
    total_tickets: int = 0
    open_tickets: int = 0
    total_reports: int = 0


class ModerationTicketDetailOut(BaseModel):
    ticket: ModerationTicketOut
    content_snapshot: dict[str, Any] = Field(default_factory=dict)
    linked_reports: list[LinkedReportOut] = Field(default_factory=list)
    offender_history_summary: OffenderHistorySummaryOut
    prior_enforcement_history: list[dict[str, Any]] = Field(default_factory=list)


class ModerationDecisionIn(BaseModel):
    decision: Literal["no_violation", "remove", "warn", "ban"]
    second_approver_admin_user_id: str | None = Field(default=None, max_length=256)
    note: str | None = Field(default=None, max_length=2000)


class ResolveModerationTicketIn(BaseModel):
    resolution: Literal["no_violation", "content_removed"]
    enforcement_action: Literal["none", "warn", "ban"] = "none"
    enforcement_duration_days: int | None = Field(default=None, ge=1, le=3650)
    second_approver_admin_user_id: str | None = Field(default=None, max_length=256)
    note: str | None = Field(default=None, max_length=2000)



class ModerationKpisOut(BaseModel):
    generated_at: int
    lookback_hours: int
    surge_window_minutes: int
    ticket_volume: int
    resolution_count: int
    resolution_latency_avg_seconds: int
    resolution_latency_p95_seconds: int
    warning_count: int
    ban_count: int
    warning_rate: float
    ban_rate: float
    open_ticket_count: int
    critical_backlog: int
    oldest_open_age_minutes: int
    extortion_criminal_reports_window_count: int


class ModerationKpiAlertsOut(BaseModel):
    ok: bool
    kpis: ModerationKpisOut
    alerts_fired: list[dict[str, Any]] = Field(default_factory=list)
    notified_user_subs: list[str] = Field(default_factory=list)



class ModerationFeatureFlagsOut(BaseModel):
    enabled: bool
    report_feed_enabled: bool
    report_messages_enabled: bool
    report_profile_enabled: bool
    admin_board_enabled: bool
    admin_actions_enabled: bool
    enforcement_enabled: bool
    min_scope_for_board: str
    min_scope_for_actions: str
    min_scope_for_permanent_ban: str


class ModerationFeatureFlagsUpdateIn(BaseModel):
    enabled: bool | None = None
    report_feed_enabled: bool | None = None
    report_messages_enabled: bool | None = None
    report_profile_enabled: bool | None = None
    admin_board_enabled: bool | None = None
    admin_actions_enabled: bool | None = None
    enforcement_enabled: bool | None = None
    min_scope_for_board: Literal["content_moderation", "content_moderation_senior"] | None = None
    min_scope_for_actions: Literal["content_moderation", "content_moderation_senior"] | None = None
    min_scope_for_permanent_ban: Literal["content_moderation", "content_moderation_senior"] | None = None
def _parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _policy_category_for_notification(ticket_item: dict[str, Any], reports: list[dict[str, Any]]) -> str:
    topics: list[str] = []
    raw_ticket_topics = ticket_item.get("aggregated_topics")
    if isinstance(raw_ticket_topics, (list, set, tuple)):
        topics.extend(str(v).strip().lower() for v in raw_ticket_topics if str(v).strip())
    for report in reports:
        raw_report_topics = report.get("topics")
        if isinstance(raw_report_topics, (list, set, tuple)):
            topics.extend(str(v).strip().lower() for v in raw_report_topics if str(v).strip())

    normalized = sorted(set(topics))
    if not normalized:
        return "unspecified"
    return max(normalized, key=lambda topic: (POLICY_CATEGORY_RANK.get(topic, 0), topic))


def _to_topic_list(raw: Any) -> list[str]:
    if isinstance(raw, set):
        return sorted(str(v) for v in raw)
    if isinstance(raw, list):
        return sorted(str(v) for v in raw)
    return []


def _to_ticket_out(item: Dict[str, Any]) -> ModerationTicketOut:
    return ModerationTicketOut(
        ticket_id=str(item.get("ticket_id") or ""),
        content_type=str(item.get("content_type") or ""),
        content_id=str(item.get("content_id") or ""),
        status=str(item.get("status") or ""),
        priority=str(item.get("priority") or "medium"),
        queue=str(item.get("queue") or "general"),
        assigned_admin_user_id=str(item.get("assigned_admin_user_id") or "") or None,
        report_count=_parse_int(item.get("report_count"), default=0),
        aggregated_topics=_to_topic_list(item.get("aggregated_topics")),
        latest_report_at=_parse_int(item.get("latest_report_at"), default=0),
        updated_at=_parse_int(item.get("updated_at"), default=0),
        created_at=_parse_int(item.get("created_at"), default=0),
    )


def _query_config(*, status: str | None, queue: str | None, assignee: str | None) -> tuple[str, str, str]:
    if assignee:
        return ("ByAssignedAdminLatestReportAt", "assigned_admin_user_id", assignee)
    if queue:
        return ("ByQueueLatestReportAt", "queue", queue)
    if status:
        return ("ByStatusLatestReportAt", "status", status)
    return ("ByLatestReportAt", "latest_report_scope", "ALL")


def _get_ticket_or_404(ticket_id: str) -> dict[str, Any]:
    item = T.moderation_tickets.get_item(Key={"ticket_id": ticket_id}).get("Item")
    if not item or item.get("entity_type") != "moderation_ticket":
        raise HTTPException(status_code=404, detail="ticket not found")
    return item


def _linked_reports(ticket_id: str) -> list[dict[str, Any]]:
    # No direct ticket-id index yet; query timeline index and filter.
    cursor = None
    reports: list[dict[str, Any]] = []
    for _ in range(8):
        kwargs: dict[str, Any] = {
            "IndexName": "ByCreatedAt",
            "KeyConditionExpression": Key("created_scope").eq("ALL"),
            "ScanIndexForward": False,
            "Limit": 200,
            "FilterExpression": Attr("linked_ticket_id").eq(ticket_id),
        }
        if cursor:
            kwargs["ExclusiveStartKey"] = cursor
        resp = T.content_reports.query(**kwargs)
        items = [i for i in resp.get("Items", []) if i.get("entity_type") == "content_report"]
        reports.extend(items)
        cursor = resp.get("LastEvaluatedKey")
        if not cursor:
            break
    reports.sort(key=lambda i: _parse_int(i.get("created_at"), 0), reverse=True)
    return reports


def _content_snapshot(ticket: dict[str, Any], reports: list[dict[str, Any]]) -> dict[str, Any]:
    content_type = str(ticket.get("content_type") or "")
    content_id = str(ticket.get("content_id") or "")
    meta = (reports[0].get("metadata") if reports else {}) or {}

    if content_type in {"feed_post", "feed_media"}:
        post_id = str(meta.get("post_id") or content_id)
        post = ddb.Table(APP_TABLE).get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item") or {}
        out = {
            "kind": content_type,
            "exists": bool(post),
            "post_id": post_id,
            "author_user_id": str(post.get("user_sub") or "") or None,
            "text": str(post.get("text") or ""),
            "image_urls": post.get("image_urls") or [],
            "created_at": _parse_int(post.get("created_at"), 0),
        }
        if content_type == "feed_media":
            out["media_index"] = _parse_int(meta.get("media_index"), -1)
        return out

    if content_type == "feed_comment":
        post_id = str(meta.get("post_id") or "")
        if not post_id:
            return {"kind": content_type, "exists": False}
        resp = ddb.Table(APP_TABLE).query(
            KeyConditionExpression=Key("pk").eq(f"POST#{post_id}#COMMENTS"),
            FilterExpression=Attr("comment_id").eq(content_id),
            Limit=1,
        )
        row = (resp.get("Items") or [None])[0] or {}
        return {
            "kind": content_type,
            "exists": bool(row),
            "post_id": post_id,
            "comment_id": content_id,
            "author_user_id": str(row.get("user_sub") or "") or None,
            "text": str(row.get("body") or row.get("text") or ""),
            "created_at": _parse_int(row.get("created_at"), 0),
        }

    if content_type in {"message", "message_media"}:
        conversation_id = str(meta.get("conversation_id") or "")
        if not conversation_id:
            return {"kind": content_type, "exists": False}
        msg = ddb.Table(MESSAGES_TABLE).get_item(Key={"conversation_id": conversation_id, "message_id": content_id}).get("Item") or {}
        return {
            "kind": content_type,
            "exists": bool(msg),
            "conversation_id": conversation_id,
            "message_id": content_id,
            "author_user_id": str(msg.get("sender_user_id") or msg.get("user_id") or "") or None,
            "text": str(msg.get("text") or msg.get("body") or ""),
            "attachments": msg.get("attachments") or [],
            "created_at": _parse_int(msg.get("created_at"), 0),
        }

    if content_type == "profile_photo":
        profile = T.profile.get_item(Key={"user_sub": content_id}).get("Item") or {}
        return {
            "kind": content_type,
            "exists": bool((profile.get("profile") or {}).get("profile_photo_url")),
            "user_id": content_id,
            "author_user_id": content_id,
            "profile_photo_url": str((profile.get("profile") or {}).get("profile_photo_url") or "") or None,
        }

    return {"kind": content_type, "exists": False}


def _infer_offender_user_id(ticket: dict[str, Any], content_snapshot: dict[str, Any]) -> str | None:
    offender = str(content_snapshot.get("author_user_id") or "").strip()
    if offender:
        return offender
    if str(ticket.get("content_type") or "") == "profile_photo":
        content_id = str(ticket.get("content_id") or "").strip()
        return content_id or None
    return None




def _query_enforcement_history(user_id: str, *, limit: int = 25) -> list[dict[str, Any]]:
    resp = T.user_enforcement_history.query(
        KeyConditionExpression=Key("user_id").eq(user_id),
        ScanIndexForward=False,
        Limit=max(1, min(limit, 100)),
    )
    rows = resp.get("Items", [])
    out: list[dict[str, Any]] = []
    for row in rows:
        if row.get("entity_type") != "user_enforcement":
            continue
        out.append(
            {
                "user_id": str(row.get("user_id") or user_id),
                "enforcement_id": str(row.get("enforcement_id") or ""),
                "enforcement_type": str(row.get("enforcement_type") or ""),
                "status": str(row.get("status") or ""),
                "source_ticket_id": str(row.get("source_ticket_id") or ""),
                "created_at": _parse_int(row.get("created_at"), 0),
                "created_by_admin_user_id": str(row.get("created_by_admin_user_id") or "") or None,
                "duration_days": _parse_int(row.get("duration_days"), 0),
                "note": str(row.get("note") or ""),
            }
        )
    out.sort(key=lambda i: (int(i.get("created_at") or 0), str(i.get("enforcement_id") or "")), reverse=True)
    return out[:limit]


def _prior_enforcement_history(offender_user_id: str | None) -> list[dict[str, Any]]:
    if not offender_user_id:
        return []
    return _query_enforcement_history(offender_user_id, limit=25)

def _offender_history_summary(offender_user_id: str | None, reports: list[dict[str, Any]]) -> OffenderHistorySummaryOut:
    if not offender_user_id:
        return OffenderHistorySummaryOut(offender_user_id=None, total_tickets=0, open_tickets=0, total_reports=len(reports))

    # Best-effort summary from moderation tickets table (future: dedicated offender index).
    scanned = T.moderation_tickets.scan(FilterExpression=Attr("offender_user_id").eq(offender_user_id)).get("Items", [])
    ticket_rows = [r for r in scanned if r.get("entity_type") == "moderation_ticket"]
    open_tickets = sum(1 for r in ticket_rows if str(r.get("status") or "") == "open")

    return OffenderHistorySummaryOut(
        offender_user_id=offender_user_id,
        total_tickets=len(ticket_rows),
        open_tickets=open_tickets,
        total_reports=len(reports),
    )






def _ddb_av_map(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: SERIALIZER.serialize(v) for k, v in payload.items()}


def _validate_resolve_combination(inp: ResolveModerationTicketIn) -> None:
    if inp.resolution == "no_violation" and inp.enforcement_action != "none":
        raise HTTPException(status_code=400, detail="invalid resolution/enforcement combination")
    if inp.enforcement_action != "ban" and inp.enforcement_duration_days is not None:
        raise HTTPException(status_code=400, detail="enforcement_duration_days is only valid for ban action")


def _resolve_action_type(resolution: str) -> str:
    if resolution == "content_removed":
        return "content_removed"
    return "no_violation"

def _persist_moderation_action(*, ticket_id: str, decision: str, note: str, admin_user_id: str, offender_user_id: str | None, now_ts: str) -> None:
    action_id = f"modact_{uuid.uuid4().hex[:20]}"
    T.moderation_actions.put_item(
        Item={
            "action_id": action_id,
            "entity_type": "moderation_action",
            "ticket_id": ticket_id,
            "action_type": decision,
            "created_at": now_ts,
            "admin_user_id": admin_user_id,
            "target_user_id": str(offender_user_id or ""),
            "note": note,
            "source_ticket_id": ticket_id,
        }
    )


def _persist_enforcement_if_needed(*, decision: str, ticket_id: str, offender_user_id: str | None, admin_user_id: str, note: str, now_ts: str) -> None:
    if decision not in {"warn", "ban"}:
        return
    user_id = str(offender_user_id or "").strip()
    if not user_id:
        return

    enforcement_id = f"enf_{uuid.uuid4().hex[:20]}"
    T.user_enforcement_history.put_item(
        Item={
            "user_id": user_id,
            "enforcement_id": enforcement_id,
            "entity_type": "user_enforcement",
            "status": "active" if decision == "ban" else "recorded",
            "enforcement_type": decision,
            "source_ticket_id": ticket_id,
            "created_at": now_ts,
            "created_by_admin_user_id": admin_user_id,
            "note": note,
        }
    )



@router.get("/kpis", response_model=ModerationKpisOut)
def get_moderation_kpis(_admin: AuthenticatedUser = Depends(require_content_moderation_admin)) -> ModerationKpisOut:
    ensure_admin_board_enabled(_admin)
    return ModerationKpisOut(**compute_moderation_kpis())


@router.post("/kpis/evaluate-alerts", response_model=ModerationKpiAlertsOut)
def evaluate_moderation_kpi_alerts(admin: AuthenticatedUser = Depends(require_content_moderation_admin)) -> ModerationKpiAlertsOut:
    ensure_admin_actions_enabled(admin)
    result = evaluate_and_dispatch_moderation_alerts(actor_user_id=admin.sub)
    return ModerationKpiAlertsOut(ok=True, **result)



@router.get("/feature-flags", response_model=ModerationFeatureFlagsOut)
def get_moderation_feature_flags_endpoint(_admin: AuthenticatedUser = Depends(require_content_moderation_admin)) -> ModerationFeatureFlagsOut:
    ensure_admin_board_enabled(_admin)
    return ModerationFeatureFlagsOut(**get_moderation_feature_flags())


@router.put("/feature-flags", response_model=ModerationFeatureFlagsOut)
def update_moderation_feature_flags(
    body: ModerationFeatureFlagsUpdateIn,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> ModerationFeatureFlagsOut:
    if admin.role.name != "ROOT":
        raise HTTPException(status_code=403, detail="only root can update moderation feature flags")
    updated = set_moderation_feature_flags(body.model_dump(exclude_none=True))
    return ModerationFeatureFlagsOut(**updated)

@router.get("/users/{user_id}/history", response_model=UserEnforcementHistoryListOut)
def get_user_enforcement_history(
    user_id: str,
    limit: int = Query(default=25, ge=1, le=100),
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> UserEnforcementHistoryListOut:
    ensure_admin_board_enabled(_admin)
    items = _query_enforcement_history(user_id, limit=limit)
    return UserEnforcementHistoryListOut(items=[UserEnforcementHistoryOut(**row) for row in items])


@router.get("/tickets", response_model=ModerationTicketsListOut)
def list_moderation_tickets(
    status: str | None = Query(default=None),
    queue: str | None = Query(default=None),
    topic: Literal["sexual", "extortion", "criminal", "spam", "racist"] | None = Query(default=None),
    assignee: str | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    cursor: str | None = Query(default=None),
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> ModerationTicketsListOut:
    ensure_admin_board_enabled(_admin)
    index_name, partition_key, partition_value = _query_config(status=status, queue=queue, assignee=assignee)
    exclusive_start_key = _decode_cursor(cursor)

    collected: list[Dict[str, Any]] = []
    last_evaluated_key: Dict[str, Any] | None = None
    fetch_limit = min(100, max(limit, 25))
    scans = 0

    while len(collected) < limit and scans < 8:
        scans += 1
        query_kwargs: Dict[str, Any] = {
            "IndexName": index_name,
            "KeyConditionExpression": Key(partition_key).eq(partition_value),
            "ScanIndexForward": False,
            "Limit": fetch_limit,
        }
        if exclusive_start_key:
            query_kwargs["ExclusiveStartKey"] = exclusive_start_key

        if topic and index_name != "ByLatestReportAt":
            query_kwargs["FilterExpression"] = Attr("aggregated_topics").contains(topic)

        resp = T.moderation_tickets.query(**query_kwargs)
        items = [i for i in resp.get("Items", []) if i.get("entity_type") == "moderation_ticket"]

        if topic and index_name == "ByLatestReportAt":
            items = [i for i in items if topic in set(i.get("aggregated_topics") or [])]

        if status and index_name != "ByStatusLatestReportAt":
            items = [i for i in items if str(i.get("status") or "") == status]
        if queue and index_name != "ByQueueLatestReportAt":
            items = [i for i in items if str(i.get("queue") or "") == queue]
        if assignee and index_name != "ByAssignedAdminLatestReportAt":
            items = [i for i in items if str(i.get("assigned_admin_user_id") or "") == assignee]

        collected.extend(items)

        last_evaluated_key = resp.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break
        exclusive_start_key = last_evaluated_key

    collected.sort(
        key=lambda item: (
            _parse_int(item.get("latest_report_at"), default=0),
            str(item.get("ticket_id") or ""),
        ),
        reverse=True,
    )
    page = collected[:limit]
    next_cursor = _encode_cursor(last_evaluated_key) if last_evaluated_key else None

    return ModerationTicketsListOut(items=[_to_ticket_out(i) for i in page], next_cursor=next_cursor)


@router.get("/tickets/{ticket_id}", response_model=ModerationTicketDetailOut)
def get_moderation_ticket_detail(
    ticket_id: str,
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> ModerationTicketDetailOut:
    ensure_admin_board_enabled(_admin)
    ticket_item = _get_ticket_or_404(ticket_id)
    reports = _linked_reports(ticket_id)
    snapshot = _content_snapshot(ticket_item, reports)
    offender_user_id = _infer_offender_user_id(ticket_item, snapshot)

    return ModerationTicketDetailOut(
        ticket=_to_ticket_out(ticket_item),
        content_snapshot=snapshot,
        linked_reports=[
            LinkedReportOut(
                report_id=str(r.get("report_id") or ""),
                reporter_user_id=str(r.get("reporter_user_id") or ""),
                topics=_to_topic_list(r.get("topics")),
                reason_text=str(r.get("reason_text") or ""),
                created_at=_parse_int(r.get("created_at"), 0),
                metadata=(r.get("metadata") if isinstance(r.get("metadata"), dict) else {}),
            )
            for r in reports
        ],
        offender_history_summary=_offender_history_summary(offender_user_id, reports),
        prior_enforcement_history=_prior_enforcement_history(offender_user_id),
    )


@router.post("/tickets/{ticket_id}/claim", response_model=ModerationTicketOut)
def claim_moderation_ticket(
    ticket_id: str,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> ModerationTicketOut:
    ensure_admin_actions_enabled(admin)
    ticket_item = _get_ticket_or_404(ticket_id)
    if str(ticket_item.get("status") or "") != "open":
        raise HTTPException(status_code=409, detail="ticket is not open")

    T.moderation_tickets.update_item(
        Key={"ticket_id": ticket_id},
        ConditionExpression="#status = :open",
        UpdateExpression="SET #assigned_admin_user_id = :admin_sub, #updated_at = :updated_at",
        ExpressionAttributeNames={
            "#status": "status",
            "#assigned_admin_user_id": "assigned_admin_user_id",
            "#updated_at": "updated_at",
        },
        ExpressionAttributeValues={
            ":open": "open",
            ":admin_sub": admin.sub,
            ":updated_at": str(int(time.time())),
        },
    )

    write_moderation_audit_event(
        action="ticket_assigned",
        actor_user_id=admin.sub,
        ticket_id=ticket_id,
        content_type=str(ticket_item.get("content_type") or ""),
        content_id=str(ticket_item.get("content_id") or ""),
        metadata={"assigned_admin_user_id": admin.sub},
    )

    updated = _get_ticket_or_404(ticket_id)
    return _to_ticket_out(updated)


@router.post("/tickets/{ticket_id}/decision", response_model=ModerationTicketOut)
def decide_moderation_ticket(
    ticket_id: str,
    inp: ModerationDecisionIn,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> ModerationTicketOut:
    ensure_admin_actions_enabled(admin)
    ticket_item = _get_ticket_or_404(ticket_id)
    reports = _linked_reports(ticket_id)
    snapshot = _content_snapshot(ticket_item, reports)
    offender_user_id = _infer_offender_user_id(ticket_item, snapshot)

    now = str(int(time.time()))
    note = str(inp.note or "").strip()
    policy_category = _policy_category_for_notification(ticket_item, reports)

    if inp.decision == "ban":
        _require_senior_moderation_for_permanent_ban(admin=admin)
        ensure_permanent_ban_scope_rollout(admin)
        _require_dual_approval_for_permanent_ban(
            admin=admin,
            second_approver_admin_user_id=inp.second_approver_admin_user_id,
        )

    _persist_moderation_action(
        ticket_id=ticket_id,
        decision=inp.decision,
        note=note,
        admin_user_id=admin.sub,
        offender_user_id=offender_user_id,
        now_ts=now,
    )
    _persist_enforcement_if_needed(
        decision=inp.decision,
        ticket_id=ticket_id,
        offender_user_id=offender_user_id,
        admin_user_id=admin.sub,
        note=note,
        now_ts=now,
    )

    T.moderation_tickets.update_item(
        Key={"ticket_id": ticket_id},
        UpdateExpression=(
            "SET #status = :status, #updated_at = :updated_at, #moderation_decision = :decision, "
            "#moderation_note = :note, #decision_at = :decision_at, #decision_by_admin_user_id = :decision_by, "
            "#offender_user_id = :offender_user_id"
        ),
        ExpressionAttributeNames={
            "#status": "status",
            "#updated_at": "updated_at",
            "#moderation_decision": "moderation_decision",
            "#moderation_note": "moderation_note",
            "#decision_at": "decision_at",
            "#decision_by_admin_user_id": "decision_by_admin_user_id",
            "#offender_user_id": "offender_user_id",
        },
        ExpressionAttributeValues={
            ":status": "closed",
            ":updated_at": now,
            ":decision": inp.decision,
            ":note": note,
            ":decision_at": now,
            ":decision_by": admin.sub,
            ":offender_user_id": str(offender_user_id or ""),
        },
    )

    write_moderation_audit_event(
        action="ticket_decision_recorded",
        actor_user_id=admin.sub,
        ticket_id=ticket_id,
        content_type=str(ticket_item.get("content_type") or ""),
        content_id=str(ticket_item.get("content_id") or ""),
        target_user_id=str(offender_user_id or ""),
        metadata={"decision": inp.decision, "note": note, "second_approver_admin_user_id": inp.second_approver_admin_user_id},
    )

    updated = _get_ticket_or_404(ticket_id)
    return _to_ticket_out(updated)


@router.post("/tickets/{ticket_id}/resolve", response_model=ModerationTicketOut)
def resolve_moderation_ticket(
    ticket_id: str,
    inp: ResolveModerationTicketIn,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> ModerationTicketOut:
    ensure_admin_actions_enabled(admin)
    _validate_resolve_combination(inp)

    ticket_item = _get_ticket_or_404(ticket_id)
    reports = _linked_reports(ticket_id)
    snapshot = _content_snapshot(ticket_item, reports)
    offender_user_id = _infer_offender_user_id(ticket_item, snapshot)

    now = str(int(time.time()))
    note = str(inp.note or "").strip()
    policy_category = _policy_category_for_notification(ticket_item, reports)

    if inp.enforcement_action in {"warn", "ban"} and not str(offender_user_id or "").strip():
        raise HTTPException(status_code=422, detail="offender_user_id required for enforcement action")

    if inp.enforcement_action == "ban" and int(inp.enforcement_duration_days or 0) <= 0:
        _require_senior_moderation_for_permanent_ban(admin=admin)
        ensure_permanent_ban_scope_rollout(admin)
        _require_dual_approval_for_permanent_ban(
            admin=admin,
            second_approver_admin_user_id=inp.second_approver_admin_user_id,
        )

    action_id = f"modact_{uuid.uuid4().hex[:20]}"
    transact_items: list[dict[str, Any]] = [
        {
            "Update": {
                "TableName": T.moderation_tickets.name,
                "Key": _ddb_av_map({"ticket_id": ticket_id}),
                "ConditionExpression": "#status = :open",
                "UpdateExpression": (
                    "SET #status = :closed, #updated_at = :updated_at, #resolved_at = :resolved_at, "
                    "#resolved_by_admin_user_id = :resolved_by, #resolution = :resolution, "
                    "#enforcement_action = :enforcement_action, #moderation_note = :note, "
                    "#offender_user_id = :offender_user_id"
                ),
                "ExpressionAttributeNames": {
                    "#status": "status",
                    "#updated_at": "updated_at",
                    "#resolved_at": "resolved_at",
                    "#resolved_by_admin_user_id": "resolved_by_admin_user_id",
                    "#resolution": "resolution",
                    "#enforcement_action": "enforcement_action",
                    "#moderation_note": "moderation_note",
                    "#offender_user_id": "offender_user_id",
                },
                "ExpressionAttributeValues": _ddb_av_map({
                    ":open": "open",
                    ":closed": "closed",
                    ":updated_at": now,
                    ":resolved_at": now,
                    ":resolved_by": admin.sub,
                    ":resolution": inp.resolution,
                    ":enforcement_action": inp.enforcement_action,
                    ":note": note,
                    ":offender_user_id": str(offender_user_id or ""),
                }),
            }
        },
        {
            "Put": {
                "TableName": T.moderation_actions.name,
                "Item": _ddb_av_map({
                    "action_id": action_id,
                    "entity_type": "moderation_action",
                    "ticket_id": ticket_id,
                    "action_type": _resolve_action_type(inp.resolution),
                    "created_at": now,
                    "admin_user_id": admin.sub,
                    "target_user_id": str(offender_user_id or ""),
                    "note": note,
                    "source_ticket_id": ticket_id,
                }),
            }
        },
    ]

    if inp.enforcement_action in {"warn", "ban"}:
        enforce_action_id = f"modact_{uuid.uuid4().hex[:20]}"
        transact_items.append(
            {
                "Put": {
                    "TableName": T.moderation_actions.name,
                    "Item": _ddb_av_map({
                        "action_id": enforce_action_id,
                        "entity_type": "moderation_action",
                        "ticket_id": ticket_id,
                        "action_type": inp.enforcement_action,
                        "created_at": now,
                        "admin_user_id": admin.sub,
                        "target_user_id": str(offender_user_id or ""),
                        "note": note,
                        "source_ticket_id": ticket_id,
                    }),
                }
            }
        )

        enforcement_id = f"enf_{uuid.uuid4().hex[:20]}"
        transact_items.append(
            {
                "Put": {
                    "TableName": T.user_enforcement_history.name,
                    "Item": _ddb_av_map({
                        "user_id": str(offender_user_id or ""),
                        "enforcement_id": enforcement_id,
                        "entity_type": "user_enforcement",
                        "status": "active" if inp.enforcement_action == "ban" else "recorded",
                        "enforcement_type": inp.enforcement_action,
                        "source_ticket_id": ticket_id,
                        "created_at": now,
                        "created_by_admin_user_id": admin.sub,
                        "note": note,
                        "duration_days": int(inp.enforcement_duration_days or 0),
                    }),
                }
            }
        )

    try:
        ddb.meta.client.transact_write_items(TransactItems=transact_items)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in {"TransactionCanceledException", "ConditionalCheckFailedException"}:
            raise HTTPException(status_code=409, detail="invalid ticket state transition") from exc
        raise

    if inp.resolution == "content_removed":
        try:
            apply_content_removal(ticket=ticket_item, reports=reports, ticket_id=ticket_id, admin_user_id=admin.sub)
            T.moderation_tickets.update_item(
                Key={"ticket_id": ticket_id},
                UpdateExpression="SET content_removal_state = :done, content_removed_at = :ts",
                ExpressionAttributeValues={":done": "completed", ":ts": now},
            )
        except Exception as exc:
            T.moderation_tickets.update_item(
                Key={"ticket_id": ticket_id},
                UpdateExpression="SET content_removal_state = :retry, content_removal_error = :err, updated_at = :updated_at",
                ExpressionAttributeValues={
                    ":retry": "retry_required",
                    ":err": str(exc)[:500],
                    ":updated_at": str(int(time.time())),
                },
            )
            raise HTTPException(status_code=503, detail="content removal adapter failed; retry required") from exc

        try:
            notify_content_removal(
                offender_user_id=str(offender_user_id or ""),
                ticket_id=ticket_id,
                content_type=str(ticket_item.get("content_type") or ""),
                policy_category=policy_category,
                note=note,
            )
        except Exception:
            # Best effort: notification failures must not rollback moderation resolution.
            pass

    write_moderation_audit_event(
        action="ticket_resolved",
        actor_user_id=admin.sub,
        ticket_id=ticket_id,
        content_type=str(ticket_item.get("content_type") or ""),
        content_id=str(ticket_item.get("content_id") or ""),
        target_user_id=str(offender_user_id or ""),
        metadata={
            "resolution": inp.resolution,
            "enforcement_action": inp.enforcement_action,
            "enforcement_duration_days": int(inp.enforcement_duration_days or 0),
            "second_approver_admin_user_id": inp.second_approver_admin_user_id,
            "note": note,
        },
    )

    if inp.enforcement_action == "warn":
        issue_warning_notification(
            offender_user_id=str(offender_user_id or ""),
            ticket_id=ticket_id,
            note=note,
            policy_category=policy_category,
        )
        write_moderation_audit_event(
            action="enforcement_warned",
            actor_user_id=admin.sub,
            ticket_id=ticket_id,
            target_user_id=str(offender_user_id or ""),
            metadata={"note": note},
        )
    elif inp.enforcement_action == "ban":
        apply_ban(
            offender_user_id=str(offender_user_id or ""),
            ticket_id=ticket_id,
            admin_user_id=admin.sub,
            note=note,
            duration_days=inp.enforcement_duration_days,
            policy_category=policy_category,
        )
        write_moderation_audit_event(
            action="enforcement_banned",
            actor_user_id=admin.sub,
            ticket_id=ticket_id,
            target_user_id=str(offender_user_id or ""),
            metadata={"duration_days": int(inp.enforcement_duration_days or 0), "second_approver_admin_user_id": inp.second_approver_admin_user_id, "note": note},
        )

    updated = _get_ticket_or_404(ticket_id)
    return _to_ticket_out(updated)

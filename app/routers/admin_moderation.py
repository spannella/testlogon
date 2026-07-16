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
from app.auth.roles import AdminScope, Role, admin_profile_has_scope, normalize_admin_profile, normalize_role
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

# MODX-18 (D5): live 6-category taxonomy (+ illegal lane) with the legacy report
# topics accepted as server-side synonyms, so filtering by either the new
# canonical category or the historical topic returns the same tickets.
_CATEGORY_SYNONYMS: dict[str, set[str]] = {
    "sexual": {"sexual"},
    "violence_threats": {"violence_threats", "criminal"},
    "hate": {"hate", "racist"},
    "harassment": {"harassment", "extortion"},
    "spam": {"spam"},
    "other": {"other"},
    "illegal": {"illegal", "csam"},
    "criminal": {"violence_threats", "criminal"},
    "racist": {"hate", "racist"},
    "extortion": {"harassment", "extortion"},
    "csam": {"illegal", "csam"},
}


def _topic_match_set(topic: str | None) -> set[str]:
    if not topic:
        return set()
    return _CATEGORY_SYNONYMS.get(topic, {topic})


CLAIM_TTL_SECONDS = 30 * 60  # MODX-20 (D8): stale claims auto-release after 30 min.


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




def _admin_user_has_senior_scope(user_sub: str) -> bool:
    """MODX-7: is ``user_sub`` a real admin that actually holds the SENIOR
    moderation scope (or ROOT)? Looks the user up in the users table — a
    caller-supplied string that is not a real senior admin is rejected."""
    if not user_sub:
        return False
    try:
        item = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
    except ClientError:
        item = None
    if not item:
        return False
    try:
        role = normalize_role(item.get("role"))
    except Exception:
        role = None
    if role == Role.ROOT:
        return True
    if role != Role.ADMIN:
        return False
    profile = normalize_admin_profile(item.get("admin_profile"))
    return admin_profile_has_scope(profile, AdminScope.CONTENT_MODERATION_SENIOR)


def _require_dual_approval_for_permanent_ban(*, admin: AuthenticatedUser, second_approver_admin_user_id: str | None) -> None:
    """MODX-7: real, non-self-attested dual approval. The second approver must be
    supplied, be DISTINCT from the acting admin, EXIST, and actually hold the
    CONTENT_MODERATION_SENIOR scope (or be ROOT). A fabricated/non-senior/absent
    approver id is rejected. The approval is recorded as an auditable action."""
    if not bool(getattr(S, "moderation_dual_approval_permanent_ban_enabled", True)):
        return
    approver = str(second_approver_admin_user_id or "").strip()
    if not approver:
        raise HTTPException(status_code=403, detail={"code": "dual_approval_required", "message": "second approver is required for permanent ban"})
    if approver == admin.sub:
        raise HTTPException(status_code=403, detail={"code": "dual_approval_self", "message": "second approver must be different from acting admin"})
    if not _admin_user_has_senior_scope(approver):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "dual_approval_invalid_approver",
                "message": "second approver must be an existing admin holding the senior moderation scope",
                "required_scope": AdminScope.CONTENT_MODERATION_SENIOR.value,
            },
        )
    # Record the second signature as an auditable, attributable action.
    try:
        write_moderation_audit_event(
            action="permanent_ban_dual_approval_recorded",
            actor_user_id=admin.sub,
            ticket_id="",
            target_user_id="",
            metadata={"second_approver_admin_user_id": approver},
        )
    except Exception:
        pass

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
    total_enforcements: int = 0  # MOD-1: precise count of ALL enforcement records


class ModerationTicketDetailOut(BaseModel):
    ticket: ModerationTicketOut
    content_snapshot: dict[str, Any] = Field(default_factory=dict)
    linked_reports: list[LinkedReportOut] = Field(default_factory=list)
    offender_history_summary: OffenderHistorySummaryOut
    prior_enforcement_history: list[dict[str, Any]] = Field(default_factory=list)
    case_state: str = ""
    hold_until: int | None = None
    owner_user_id: str | None = None
    distinct_reporter_count: int = 0
    needs_human_review: bool = False
    human_review_reason: str | None = None
    illegal_lane: bool = False
    sla_deadline: int | None = None
    # MODX-14 (C3): surface the poster hold-response so the admin final call is not made blind.
    poster_response: str | None = None
    responded_at: int | None = None


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
    on_hold_count: int = 0
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


def _claim_is_active(ticket_item: Dict[str, Any], *, now: int | None = None) -> bool:
    """A ticket is EXCLUSIVELY claimed only when a moderator claimed it through
    the claim endpoint (which stamps assigned_at). A bare assigned_admin_user_id
    with no claim timestamp (auto/legacy triage assignment) is NOT an exclusive
    claim, and a claim older than the TTL auto-releases."""
    assignee = str(ticket_item.get("assigned_admin_user_id") or "")
    if not assignee:
        return False
    assigned_at = _parse_int(ticket_item.get("assigned_at"), 0)
    if assigned_at <= 0:
        return False  # MODX-20 (D8): assignment without a claim stamp is not a lock.
    now = int(now or time.time())
    if (now - assigned_at) > CLAIM_TTL_SECONDS:
        return False  # MODX-20 (D8): stale claim -> treated as released.
    return True


def _enforce_claim(ticket_item: Dict[str, Any], admin: AuthenticatedUser, *, steal: bool = False) -> None:
    """MODX-20 (D8): a fresh claim reserves the ticket for its assignee. Another
    moderator must pass steal=true to act on it (recorded as an audit steal). An
    unassigned or TTL-expired (stale) claim is free to act on."""
    assignee = str(ticket_item.get("assigned_admin_user_id") or "")
    if not _claim_is_active(ticket_item):
        return
    if assignee == admin.sub:
        return
    if steal:
        write_moderation_audit_event(
            action="ticket_claim_stolen",
            actor_user_id=admin.sub,
            ticket_id=str(ticket_item.get("ticket_id") or ""),
            metadata={"previous_assignee": assignee},
        )
        return
    raise HTTPException(
        status_code=409,
        detail={
            "code": "ticket_claimed_by_other",
            "assigned_admin_user_id": assignee,
            "message": "ticket is claimed by another moderator; retry with steal=true to take it over",
        },
    )


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

    if content_type == "syndicate_post":
        from app.services import syndicate_feed as _sf
        from app.services import moderation_case as _mc2
        syndicate_id = str(meta.get("syndicate_id") or "")
        if not syndicate_id:
            _c = _mc2.get_case_for_content(content_type, content_id) or {}
            syndicate_id = str((_c.get("content_metadata") or {}).get("syndicate_id") or "")
        post = (_sf._get_post(syndicate_id, content_id) if syndicate_id else None) or {}
        return {
            "kind": content_type,
            "exists": bool(post),
            "post_id": content_id,
            "syndicate_id": syndicate_id,
            "author_user_id": str(post.get("author_id") or "") or None,
            "text": str(post.get("text") or ""),
            "created_at": _parse_int(post.get("created_at"), 0),
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


def _project_enforcement_row(row: dict[str, Any], fallback_user_id: str) -> dict[str, Any]:
    return {
        "user_id": str(row.get("user_id") or fallback_user_id),
        "enforcement_id": str(row.get("enforcement_id") or ""),
        "enforcement_type": str(row.get("enforcement_type") or ""),
        "status": str(row.get("status") or ""),
        "source_ticket_id": str(row.get("source_ticket_id") or ""),
        "created_at": _parse_int(row.get("created_at"), 0),
        "created_by_admin_user_id": str(row.get("created_by_admin_user_id") or "") or None,
        "duration_days": _parse_int(row.get("duration_days"), 0),
        "note": str(row.get("note") or ""),
    }


def _query_enforcement_history_by_offender(offender_user_id: str, *, cap: int | None = None) -> list[dict[str, Any]]:
    """MOD-1: COMPLETE query of ALL enforcement records for an offender. Prefers the
    ByOffenderCreatedAt GSI (user_id HASH -- the offender -- + created_at RANGE, so the
    DB returns them newest-first); falls back to a COMPLETE paginated base-table Query
    (also keyed on user_id) whenever the index is not queryable, so the admin offender
    summary counts are ALWAYS precise -- never Limit-truncated like the old bounded
    query, and never dependent on index availability."""
    if not offender_user_id:
        return []
    raw_rows: list[dict[str, Any]] = []
    try:
        exclusive_start_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": "ByOffenderCreatedAt",
                "KeyConditionExpression": Key("user_id").eq(offender_user_id),
                "ScanIndexForward": False,
            }
            if exclusive_start_key:
                kwargs["ExclusiveStartKey"] = exclusive_start_key
            resp = T.user_enforcement_history.query(**kwargs)
            raw_rows.extend(resp.get("Items", []))
            exclusive_start_key = resp.get("LastEvaluatedKey")
            if not exclusive_start_key:
                break
    except ClientError:
        # Index missing / not ACTIVE -> COMPLETE base-table query (user_id is the HASH
        # key, so this returns every enforcement record for the offender).
        raw_rows = []
        exclusive_start_key = None
        while True:
            kwargs = {"KeyConditionExpression": Key("user_id").eq(offender_user_id)}
            if exclusive_start_key:
                kwargs["ExclusiveStartKey"] = exclusive_start_key
            resp = T.user_enforcement_history.query(**kwargs)
            raw_rows.extend(resp.get("Items", []))
            exclusive_start_key = resp.get("LastEvaluatedKey")
            if not exclusive_start_key:
                break
    out: list[dict[str, Any]] = [
        _project_enforcement_row(row, offender_user_id)
        for row in raw_rows
        if row.get("entity_type") == "user_enforcement"
    ]
    out.sort(key=lambda i: (int(i.get("created_at") or 0), str(i.get("enforcement_id") or "")), reverse=True)
    return out[:cap] if cap else out


def _prior_enforcement_history(offender_user_id: str | None) -> list[dict[str, Any]]:
    if not offender_user_id:
        return []
    return _query_enforcement_history_by_offender(offender_user_id, cap=25)

def _offender_history_summary(offender_user_id: str | None, reports: list[dict[str, Any]]) -> OffenderHistorySummaryOut:
    if not offender_user_id:
        return OffenderHistorySummaryOut(offender_user_id=None, total_tickets=0, open_tickets=0, total_reports=len(reports))

    # MOD-1: COMPLETE indexed query over the ByOffenderCreatedAt GSI -- EVERY
    # enforcement record for the offender, not a Limit-bounded base-table page --
    # so total_tickets (distinct source tickets), open_tickets (active
    # enforcements) and total_enforcements are PRECISE counts.
    history = _query_enforcement_history_by_offender(offender_user_id)
    distinct_tickets = {str(h.get("source_ticket_id") or "") for h in history if h.get("source_ticket_id")}
    active_enforcements = sum(
        1 for h in history if str(h.get("status") or "").lower() in ("active", "banned", "open")
    )

    return OffenderHistorySummaryOut(
        offender_user_id=offender_user_id,
        total_tickets=len(distinct_tickets),
        open_tickets=active_enforcements,
        total_reports=len(reports),
        total_enforcements=len(history),
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
    items = _query_enforcement_history_by_offender(user_id, cap=limit)
    return UserEnforcementHistoryListOut(items=[UserEnforcementHistoryOut(**row) for row in items])


@router.get("/tickets", response_model=ModerationTicketsListOut)
def list_moderation_tickets(
    status: str | None = Query(default=None),
    queue: str | None = Query(default=None),
    topic: Literal[
        "sexual", "violence_threats", "hate", "spam", "harassment", "other", "illegal",
        "extortion", "criminal", "racist", "csam",
    ] | None = Query(default=None),
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

        resp = T.moderation_tickets.query(**query_kwargs)
        items = [i for i in resp.get("Items", []) if i.get("entity_type") == "moderation_ticket"]

        # MODX-18 (D5): match against the live category AND its legacy synonyms.
        if topic:
            _match = _topic_match_set(topic)
            items = [
                i for i in items
                if _match & {str(v) for v in (i.get("aggregated_topics") or [])}
            ]

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

    from app.services import moderation_case as _mc
    _case = _mc.get_case_for_content(str(ticket_item.get("content_type") or ""), str(ticket_item.get("content_id") or "")) or {}
    _case_state = str(_case.get("state") or ticket_item.get("moderation_case_state") or "")
    _hold_until_raw = _case.get("hold_until") if _case.get("hold_until") is not None else ticket_item.get("hold_until")
    _hold_until = _parse_int(_hold_until_raw, 0) or None
    _owner = str(_case.get("owner_user_id") or offender_user_id or "") or None
    # MODX-3: distinct reporters (not raw events) + the human-review / illegal flags.
    _rids = _case.get("reporter_ids")
    if isinstance(_rids, (set, frozenset, list, tuple)):
        _distinct = len({str(r) for r in _rids if r})
    else:
        _distinct = _parse_int(_case.get("distinct_reporter_count"), 0)

    return ModerationTicketDetailOut(
        ticket=_to_ticket_out(ticket_item),
        content_snapshot=snapshot,
        case_state=_case_state,
        hold_until=_hold_until,
        owner_user_id=_owner,
        distinct_reporter_count=_distinct,
        needs_human_review=bool(_case.get("needs_human_review")),
        human_review_reason=(str(_case.get("human_review_reason")) if _case.get("human_review_reason") else None),
        illegal_lane=bool(_case.get("illegal_lane")),
        sla_deadline=(_parse_int(_case.get("sla_deadline"), 0) or None),
        poster_response=(str(_case.get("poster_response")) if _case.get("poster_response") else None),
        responded_at=(_parse_int(_case.get("responded_at"), 0) or None),
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
        UpdateExpression="SET #assigned_admin_user_id = :admin_sub, #assigned_at = :now, #updated_at = :now",
        ExpressionAttributeNames={
            "#status": "status",
            "#assigned_admin_user_id": "assigned_admin_user_id",
            "#assigned_at": "assigned_at",
            "#updated_at": "updated_at",
        },
        ExpressionAttributeValues={
            ":open": "open",
            ":admin_sub": admin.sub,
            ":now": int(time.time()),
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
            enforcement_id=enforcement_id,
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
            enforcement_id=enforcement_id,
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


# ── MODAB (MOD-A4): moderation_case triage — dismiss / confirm-30d-hold / final-call ──
class _CaseActionOut(BaseModel):
    ok: bool
    ticket_id: str
    case_id: str
    state: str
    hidden: bool = False
    hold_until: int | None = None
    owner_user_id: str | None = None
    enforcement_id: str | None = None


class _FinalCallIn(BaseModel):
    action: Literal["reinstate", "delete"]
    note: str | None = Field(default=None, max_length=2000)
    ban: bool = False
    ban_duration_days: int | None = Field(default=None, ge=0, le=3650)
    second_approver_admin_user_id: str | None = Field(default=None, max_length=256)


def _modab_case_and_meta(ticket_id: str):
    from app.services import moderation_case as _mc
    ticket = _get_ticket_or_404(ticket_id)
    reports = _linked_reports(ticket_id)
    snapshot = _content_snapshot(ticket, reports)
    ct = str(ticket.get("content_type") or "")
    cid = str(ticket.get("content_id") or "")
    meta = (reports[0].get("metadata") if reports else {}) or {}
    case = _mc.get_case_for_content(ct, cid)
    if not case:
        owner = _infer_offender_user_id(ticket, snapshot)
        case = _mc.aggregate_report(
            content_type=ct,
            content_id=cid,
            categories=_to_topic_list(ticket.get("aggregated_topics")),
            owner_user_id=owner,
            ticket_id=ticket_id,
            metadata=meta,
        )
    return ticket, case, meta


def _modab_guard(fn, **kwargs):
    """MODX-1/MODX-2: translate a guarded moderation_case state error into a clean
    HTTP 409 instead of an unhandled 500. An admin action on a re-report ticket
    whose case is in an incompatible state (e.g. an illegal transition, or a
    terminal case that was not reopened) must surface as a conflict, never a 500."""
    try:
        return fn(**kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=f"moderation_case_state_conflict: {exc}") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _modab_tag_ticket(ticket_id: str, *, status: str, admin_sub: str, case_state: str, resolution: str | None = None, hold_until: int | None = None) -> None:
    now = str(int(time.time()))
    names = {"#s": "status", "#ua": "updated_at", "#cs": "moderation_case_state"}
    vals: dict[str, Any] = {":s": status, ":ua": now, ":cs": case_state}
    sets = ["#s = :s", "#ua = :ua", "#cs = :cs"]
    if resolution is not None:
        names["#r"] = "resolution"; vals[":r"] = resolution; sets.append("#r = :r")
        names["#ra"] = "resolved_at"; vals[":ra"] = now; sets.append("#ra = :ra")
        names["#rb"] = "resolved_by_admin_user_id"; vals[":rb"] = admin_sub; sets.append("#rb = :rb")
    if hold_until is not None:
        names["#hu"] = "hold_until"; vals[":hu"] = hold_until; sets.append("#hu = :hu")
    T.moderation_tickets.update_item(
        Key={"ticket_id": ticket_id},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=vals,
    )


@router.post("/tickets/{ticket_id}/dismiss", response_model=_CaseActionOut)
def dismiss_moderation_case(
    ticket_id: str,
    steal: bool = Query(default=False),
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> _CaseActionOut:
    ensure_admin_actions_enabled(admin)
    from app.services import moderation_lifecycle as _life
    ticket, case, meta = _modab_case_and_meta(ticket_id)
    _enforce_claim(ticket, admin, steal=steal)
    res = _modab_guard(_life.admin_dismiss, case=case, metadata=meta, admin_user_id=admin.sub)
    _modab_tag_ticket(ticket_id, status="closed", admin_sub=admin.sub, case_state=res["state"], resolution="no_violation")
    write_moderation_audit_event(
        action="content_case_dismissed",
        actor_user_id=admin.sub,
        ticket_id=ticket_id,
        content_type=str(ticket.get("content_type") or ""),
        content_id=str(ticket.get("content_id") or ""),
        target_user_id=str(res.get("owner_user_id") or ""),
        metadata={"case_id": case["case_id"], "state": res["state"]},
    )
    return _CaseActionOut(ok=True, ticket_id=ticket_id, case_id=case["case_id"], state=res["state"], hidden=False, owner_user_id=res.get("owner_user_id"))


@router.post("/tickets/{ticket_id}/confirm", response_model=_CaseActionOut)
def confirm_moderation_case(
    ticket_id: str,
    steal: bool = Query(default=False),
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> _CaseActionOut:
    ensure_admin_actions_enabled(admin)
    from app.services import moderation_lifecycle as _life
    ticket, case, meta = _modab_case_and_meta(ticket_id)
    _enforce_claim(ticket, admin, steal=steal)
    res = _modab_guard(_life.admin_confirm_hold, case=case, metadata=meta, admin_user_id=admin.sub)
    _modab_tag_ticket(ticket_id, status="open", admin_sub=admin.sub, case_state=res["state"], hold_until=res.get("hold_until"))
    write_moderation_audit_event(
        action="content_violation_confirmed",
        actor_user_id=admin.sub,
        ticket_id=ticket_id,
        content_type=str(ticket.get("content_type") or ""),
        content_id=str(ticket.get("content_id") or ""),
        target_user_id=str(res.get("owner_user_id") or ""),
        metadata={"case_id": case["case_id"], "hold_until": res.get("hold_until")},
    )
    return _CaseActionOut(ok=True, ticket_id=ticket_id, case_id=case["case_id"], state=res["state"], hidden=True, hold_until=res.get("hold_until"), owner_user_id=res.get("owner_user_id"))


@router.post("/tickets/{ticket_id}/final-call", response_model=_CaseActionOut)
def final_call_moderation_case(
    ticket_id: str,
    inp: _FinalCallIn,
    steal: bool = Query(default=False),
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> _CaseActionOut:
    ensure_admin_actions_enabled(admin)
    from app.services import moderation_lifecycle as _life
    from app.services import moderation_reporter_reputation as _rep
    from app.services import moderation_case as _mc
    ticket, case, meta = _modab_case_and_meta(ticket_id)
    _enforce_claim(ticket, admin, steal=steal)
    note = str(inp.note or "").strip()

    # MODX-5 (A13): an admin may not adjudicate a case where they are the owner or
    # the sole reporter (conflict of interest).
    if _rep.is_conflicted_admin(case, admin.sub):
        raise HTTPException(status_code=403, detail={"code": "moderation_conflict_of_interest", "message": "cannot make the final call on your own content or a case where you are the sole reporter"})

    # MODX-8: any final-call action on a locked illegal/CSAM case is SENIOR-only.
    if _mc.is_illegal_category(case.get("categories") or []) or bool(case.get("illegal_lane")):
        _require_senior_moderation_for_permanent_ban(admin=admin)

    if inp.action == "reinstate":
        res = _modab_guard(_life.admin_final_reinstate, case=case, metadata=meta, admin_user_id=admin.sub)
        _modab_tag_ticket(ticket_id, status="closed", admin_sub=admin.sub, case_state=res["state"], resolution="no_violation")
        write_moderation_audit_event(
            action="content_case_reinstated",
            actor_user_id=admin.sub,
            ticket_id=ticket_id,
            content_type=str(ticket.get("content_type") or ""),
            content_id=str(ticket.get("content_id") or ""),
            target_user_id=str(res.get("owner_user_id") or ""),
            metadata={"case_id": case["case_id"]},
        )
        return _CaseActionOut(ok=True, ticket_id=ticket_id, case_id=case["case_id"], state=res["state"], hidden=False, owner_user_id=res.get("owner_user_id"))

    # action == "delete"
    permanent = bool(inp.ban) and int(inp.ban_duration_days or 0) <= 0
    if permanent:
        _require_senior_moderation_for_permanent_ban(admin=admin)
        ensure_permanent_ban_scope_rollout(admin)
        _require_dual_approval_for_permanent_ban(admin=admin, second_approver_admin_user_id=inp.second_approver_admin_user_id)

    res = _modab_guard(_life.admin_final_delete, case=case, metadata=meta, admin_user_id=admin.sub, source_ticket_id=ticket_id, note=note or "admin_final_delete")
    owner = str(res.get("owner_user_id") or "")

    # MODX-2: a lost race / already-terminal case is a clean no-op (changed=False):
    # nothing was deleted by THIS call, so do not apply a ban or re-close as a new
    # deletion — surface the current state as a conflict.
    if res.get("changed") is False:
        raise HTTPException(status_code=409, detail=f"moderation_case_state_conflict: not in a deletable state (state={res.get('state')})")

    if inp.ban and owner:
        ban_enf_id = f"enf_{uuid.uuid4().hex[:20]}"
        now = str(int(time.time()))
        T.user_enforcement_history.put_item(
            Item={
                "user_id": owner,
                "enforcement_id": ban_enf_id,
                "entity_type": "user_enforcement",
                "status": "active",
                "enforcement_type": "ban",
                "source_ticket_id": ticket_id,
                "created_at": now,
                "created_by_admin_user_id": admin.sub,
                "note": note,
                "duration_days": int(inp.ban_duration_days or 0),
            }
        )
        apply_ban(
            offender_user_id=owner,
            ticket_id=ticket_id,
            admin_user_id=admin.sub,
            note=note,
            duration_days=inp.ban_duration_days,
            policy_category="content_violation",
            enforcement_id=ban_enf_id,
        )
        write_moderation_audit_event(
            action="enforcement_banned",
            actor_user_id=admin.sub,
            ticket_id=ticket_id,
            target_user_id=owner,
            metadata={"duration_days": int(inp.ban_duration_days or 0), "permanent": permanent},
        )

    _modab_tag_ticket(ticket_id, status="closed", admin_sub=admin.sub, case_state=res["state"], resolution="content_removed")
    write_moderation_audit_event(
        action="content_case_deleted",
        actor_user_id=admin.sub,
        ticket_id=ticket_id,
        content_type=str(ticket.get("content_type") or ""),
        content_id=str(ticket.get("content_id") or ""),
        target_user_id=owner,
        metadata={"case_id": case["case_id"], "enforcement_id": res.get("enforcement_id"), "banned": bool(inp.ban)},
    )
    return _CaseActionOut(ok=True, ticket_id=ticket_id, case_id=case["case_id"], state=res["state"], hidden=True, owner_user_id=owner, enforcement_id=res.get("enforcement_id"))


# ── MODX-19: ban management (active-enforcement roster + lift) ────────────────
class BanRosterEntryOut(BaseModel):
    user_id: str
    enforcement_id: str
    source_ticket_id: str = ""
    created_at: int = 0
    created_by_admin_user_id: str | None = None
    duration_days: int = 0
    ban_until: int = 0
    permanent: bool = False
    note: str = ""
    account_status: str = ""
    active: bool = True


class BanRosterOut(BaseModel):
    items: list[BanRosterEntryOut]
    next_cursor: str | None = None


def _active_ban_enforcements() -> list[dict[str, Any]]:
    """All active ban enforcement rows. Prefers the ByStatusCreatedAt GSI
    (status HASH) and falls back to a bounded scan if the index is unavailable."""
    rows: list[dict[str, Any]] = []
    esk = None
    try:
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": "ByStatusCreatedAt",
                "KeyConditionExpression": Key("status").eq("active"),
                "ScanIndexForward": False,
            }
            if esk:
                kwargs["ExclusiveStartKey"] = esk
            resp = T.user_enforcement_history.query(**kwargs)
            rows.extend(resp.get("Items", []))
            esk = resp.get("LastEvaluatedKey")
            if not esk:
                break
    except ClientError:
        rows = []
        esk = None
        for _ in range(20):
            kwargs = {"FilterExpression": Attr("status").eq("active")}
            if esk:
                kwargs["ExclusiveStartKey"] = esk
            resp = T.user_enforcement_history.scan(**kwargs)
            rows.extend(resp.get("Items", []))
            esk = resp.get("LastEvaluatedKey")
            if not esk:
                break
    return [
        r for r in rows
        if r.get("entity_type") == "user_enforcement" and str(r.get("enforcement_type")) == "ban"
    ]


def _ban_roster_entry(r: dict[str, Any], *, now: int) -> BanRosterEntryOut:
    uid = str(r.get("user_id") or "")
    acct: dict[str, Any] = {}
    try:
        acct = T.account_state.get_item(Key={"user_sub": uid}).get("Item") or {}
    except Exception:
        acct = {}
    acct_status = str(acct.get("status") or "")
    ban_until = _parse_int(acct.get("ban_until"), 0)
    currently_banned = acct_status in ("banned", "suspended") and (ban_until == 0 or now < ban_until)
    active = str(r.get("status") or "") == "active" and currently_banned
    return BanRosterEntryOut(
        user_id=uid,
        enforcement_id=str(r.get("enforcement_id") or ""),
        source_ticket_id=str(r.get("source_ticket_id") or ""),
        created_at=_parse_int(r.get("created_at"), 0),
        created_by_admin_user_id=str(r.get("created_by_admin_user_id") or "") or None,
        duration_days=_parse_int(r.get("duration_days"), 0),
        ban_until=ban_until,
        permanent=bool(acct_status in ("banned", "suspended") and ban_until == 0),
        note=str(r.get("note") or acct.get("ban_note") or ""),
        account_status=acct_status,
        active=active,
    )


@router.get("/bans", response_model=BanRosterOut)
def list_moderation_bans(
    user: str | None = Query(default=None),
    include_inactive: bool = Query(default=False),
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> BanRosterOut:
    """MODX-19 (D4): active-ban roster. ``?user=`` returns that user's full ban
    history (active + lifted/expired); the default roster returns only currently
    active bans."""
    ensure_admin_board_enabled(_admin)
    now = int(time.time())
    if user:
        rows = [
            r for r in _query_enforcement_history_by_offender(str(user))
            if str(r.get("enforcement_type")) == "ban"
        ]
    else:
        rows = _active_ban_enforcements()
    entries = [_ban_roster_entry(r, now=now) for r in rows]
    if not user and not include_inactive:
        entries = [e for e in entries if e.active]
    entries.sort(key=lambda e: e.created_at, reverse=True)
    return BanRosterOut(items=entries, next_cursor=None)


class BanLiftIn(BaseModel):
    note: str | None = Field(default=None, max_length=2000)
    enforcement_id: str | None = Field(default=None, max_length=128)


class BanLiftOut(BaseModel):
    ok: bool
    user_id: str
    account_status: str
    lifted_enforcement_ids: list[str] = Field(default_factory=list)


@router.post("/bans/{user_id}/lift", response_model=BanLiftOut)
def lift_moderation_ban(
    user_id: str,
    inp: BanLiftIn,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> BanLiftOut:
    """MODX-19 (D4): reverse a wrongful/permanent ban. Sets account_state back to
    ``active`` (fail-closed ban gate re-admits the user), closes the matching active
    ban enforcement row(s) as ``lifted``, writes an audit event, notifies the user.
    Idempotent."""
    ensure_admin_actions_enabled(admin)
    uid = str(user_id or "").strip()
    if not uid:
        raise HTTPException(status_code=400, detail="user_id required")
    now = str(int(time.time()))
    acct: dict[str, Any] = {}
    try:
        acct = T.account_state.get_item(Key={"user_sub": uid}).get("Item") or {}
    except Exception:
        acct = {}
    T.account_state.put_item(
        Item={
            "user_sub": uid,
            "status": "active",
            "updated_at": int(time.time()),
            "reason": "moderation_ban_lifted",
            "requested_by": admin.sub,
            "ban_until": 0,
            "lifted_at": int(time.time()),
            "lifted_by_admin_user_id": admin.sub,
            "ban_note": str(inp.note or acct.get("ban_note") or "")[:500],
        }
    )
    rows = [
        r for r in _query_enforcement_history_by_offender(uid)
        if str(r.get("enforcement_type")) == "ban" and str(r.get("status")) == "active"
    ]
    if inp.enforcement_id:
        rows = [r for r in rows if str(r.get("enforcement_id")) == str(inp.enforcement_id)]
    lifted: list[str] = []
    for r in rows:
        enf_id = str(r.get("enforcement_id") or "")
        if not enf_id:
            continue
        try:
            T.user_enforcement_history.update_item(
                Key={"user_id": uid, "enforcement_id": enf_id},
                UpdateExpression="SET #s = :lifted, #la = :now, #lb = :admin",
                ExpressionAttributeNames={"#s": "status", "#la": "lifted_at", "#lb": "lifted_by_admin_user_id"},
                ExpressionAttributeValues={":lifted": "lifted", ":now": now, ":admin": admin.sub},
            )
            lifted.append(enf_id)
        except Exception:
            pass
    write_moderation_audit_event(
        action="ban_lifted",
        actor_user_id=admin.sub,
        target_user_id=uid,
        metadata={"lifted_enforcement_ids": lifted, "note": str(inp.note or "")[:500]},
    )
    try:
        from app.services.alerts import write_alert
        write_alert(
            uid,
            event="moderation_ban_lifted",
            outcome="resolved",
            title="Account restriction lifted",
            details={"action": "ban_lifted", "note": str(inp.note or "")[:500]},
        )
    except Exception:
        pass
    return BanLiftOut(ok=True, user_id=uid, account_status="active", lifted_enforcement_ids=lifted)


# ── MODX-20: decision audit-trail read ───────────────────────────────────────
class AuditEventOut(BaseModel):
    audit_id: str
    action: str
    actor_user_id: str
    ticket_id: str = ""
    content_type: str = ""
    content_id: str = ""
    target_user_id: str = ""
    created_at: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditTrailOut(BaseModel):
    items: list[AuditEventOut]


def _project_audit(row: dict[str, Any]) -> AuditEventOut:
    return AuditEventOut(
        audit_id=str(row.get("audit_id") or ""),
        action=str(row.get("action") or ""),
        actor_user_id=str(row.get("actor_user_id") or ""),
        ticket_id=str(row.get("ticket_id") or ""),
        content_type=str(row.get("content_type") or ""),
        content_id=str(row.get("content_id") or ""),
        target_user_id=str(row.get("target_user_id") or ""),
        created_at=_parse_int(row.get("created_at"), 0),
        metadata=(row.get("metadata") if isinstance(row.get("metadata"), dict) else {}),
    )


def _query_audit(index_name: str, key_attr: str, key_val: str, limit: int) -> list[dict[str, Any]]:
    try:
        resp = T.moderation_audit_log.query(
            IndexName=index_name,
            KeyConditionExpression=Key(key_attr).eq(key_val),
            ScanIndexForward=False,
            Limit=limit,
        )
        rows = resp.get("Items", [])
    except ClientError:
        rows = []
    rows.sort(key=lambda r: _parse_int(r.get("created_at"), 0), reverse=True)
    return rows[:limit]


@router.get("/tickets/{ticket_id}/audit", response_model=AuditTrailOut)
def get_ticket_audit_trail(
    ticket_id: str,
    limit: int = Query(default=100, ge=1, le=200),
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> AuditTrailOut:
    """MODX-20 (D6): who/when/why decision timeline for one ticket."""
    ensure_admin_board_enabled(_admin)
    rows = _query_audit("ByTicketCreatedAt", "ticket_id", ticket_id, limit)
    return AuditTrailOut(items=[_project_audit(r) for r in rows])


@router.get("/audit", response_model=AuditTrailOut)
def get_audit_by_actor(
    actor: str = Query(...),
    limit: int = Query(default=100, ge=1, le=200),
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> AuditTrailOut:
    """MODX-20 (D6): every moderation action taken by one moderator."""
    ensure_admin_board_enabled(_admin)
    rows = _query_audit("ByActorCreatedAt", "actor_user_id", actor, limit)
    return AuditTrailOut(items=[_project_audit(r) for r in rows])


# ── MODX-20: unclaim / reassign ──────────────────────────────────────────────
@router.post("/tickets/{ticket_id}/unclaim", response_model=ModerationTicketOut)
def unclaim_moderation_ticket(
    ticket_id: str,
    reassign_to: str | None = Query(default=None),
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> ModerationTicketOut:
    """MODX-20 (D8): release a claim (or hand it to another moderator) so an
    abandoned claim never wedges the assignee filter."""
    ensure_admin_actions_enabled(admin)
    ticket_item = _get_ticket_or_404(ticket_id)
    assignee = str(ticket_item.get("assigned_admin_user_id") or "")
    new_assignee = str(reassign_to or "").strip()
    now = int(time.time())
    if new_assignee:
        T.moderation_tickets.update_item(
            Key={"ticket_id": ticket_id},
            UpdateExpression="SET assigned_admin_user_id = :a, assigned_at = :now, updated_at = :nows",
            ExpressionAttributeValues={":a": new_assignee, ":now": now, ":nows": str(now)},
        )
        action, meta = "ticket_reassigned", {"from": assignee, "to": new_assignee}
    else:
        T.moderation_tickets.update_item(
            Key={"ticket_id": ticket_id},
            UpdateExpression="REMOVE assigned_admin_user_id, assigned_at SET updated_at = :nows",
            ExpressionAttributeValues={":nows": str(now)},
        )
        action, meta = "ticket_unassigned", {"from": assignee}
    write_moderation_audit_event(action=action, actor_user_id=admin.sub, ticket_id=ticket_id, metadata=meta)
    return _to_ticket_out(_get_ticket_or_404(ticket_id))


# ── MODX-22: bulk triage actions ─────────────────────────────────────────────
class BulkModerationIn(BaseModel):
    ticket_ids: list[str] = Field(default_factory=list, max_length=100)
    action: Literal["dismiss", "confirm", "reinstate", "delete"]
    note: str | None = Field(default=None, max_length=2000)
    steal: bool = False


class BulkItemResultOut(BaseModel):
    ticket_id: str
    ok: bool
    state: str | None = None
    error_code: str | None = None
    error: str | None = None


class BulkModerationOut(BaseModel):
    action: str
    total: int
    succeeded: int
    failed: int
    results: list[BulkItemResultOut]


@router.post("/tickets/bulk", response_model=BulkModerationOut)
def bulk_moderation_action(
    inp: BulkModerationIn,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> BulkModerationOut:
    """MODX-22 (D11): apply one triage action to many tickets, returning a per-item
    outcome. Each item runs the SAME guarded state-machine path as the single-ticket
    endpoints, so a brigade wave can be cleared in one call without losing per-item
    correctness (illegal-state / claimed / conflict errors are reported, not fatal)."""
    ensure_admin_actions_enabled(admin)
    seen: set[str] = set()
    uniq: list[str] = []
    for t in (inp.ticket_ids or []):
        tid = str(t).strip()
        if tid and tid not in seen:
            seen.add(tid)
            uniq.append(tid)
    results: list[BulkItemResultOut] = []
    for tid in uniq:
        try:
            if inp.action == "dismiss":
                r = dismiss_moderation_case(tid, steal=inp.steal, admin=admin)
            elif inp.action == "confirm":
                r = confirm_moderation_case(tid, steal=inp.steal, admin=admin)
            elif inp.action == "reinstate":
                r = final_call_moderation_case(tid, _FinalCallIn(action="reinstate", note=inp.note), steal=inp.steal, admin=admin)
            else:  # delete
                r = final_call_moderation_case(tid, _FinalCallIn(action="delete", note=inp.note), steal=inp.steal, admin=admin)
            results.append(BulkItemResultOut(ticket_id=tid, ok=True, state=getattr(r, "state", None)))
        except HTTPException as exc:
            code = None
            detail = exc.detail
            if isinstance(detail, dict):
                code = str(detail.get("code") or "") or None
                msg = str(detail.get("message") or detail)
            else:
                msg = str(detail)
            results.append(BulkItemResultOut(ticket_id=tid, ok=False, error_code=code, error=msg))
        except Exception as exc:  # noqa: BLE001
            results.append(BulkItemResultOut(ticket_id=tid, ok=False, error=str(exc)))
    succeeded = sum(1 for r in results if r.ok)
    return BulkModerationOut(
        action=inp.action,
        total=len(uniq),
        succeeded=succeeded,
        failed=len(uniq) - succeeded,
        results=results,
    )


# ── MODX-18 (D16): read-only auto-hide rules panel ───────────────────────────
class AutoHideRulesOut(BaseModel):
    severe_categories: list[str]
    lower_categories: list[str]
    illegal_categories: list[str]
    lower_hide_distinct_reporter_threshold: int
    severe_distinct_reporter_floor: int
    velocity_burst_min: int
    new_account_age_seconds: int
    protected_account_age_seconds: int
    hold_window_seconds: int


@router.get("/auto-hide-rules", response_model=AutoHideRulesOut)
def get_auto_hide_rules(
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> AutoHideRulesOut:
    """MODX-18 (D16): surface the (currently hardcoded) auto-hide thresholds so an
    operator can see WHY content auto-hid instead of guessing."""
    ensure_admin_board_enabled(_admin)
    from app.services import moderation_case as _mc
    return AutoHideRulesOut(
        severe_categories=sorted(_mc.SEVERE_CATEGORIES),
        lower_categories=sorted(_mc.LOWER_CATEGORIES),
        illegal_categories=sorted(_mc.ILLEGAL_CATEGORIES),
        lower_hide_distinct_reporter_threshold=int(_mc.LOWER_HIDE_THRESHOLD),
        severe_distinct_reporter_floor=int(_mc.SEVERE_DISTINCT_FLOOR),
        velocity_burst_min=int(_mc.VELOCITY_BURST_MIN),
        new_account_age_seconds=int(_mc.NEW_ACCOUNT_AGE_SECONDS),
        protected_account_age_seconds=int(_mc.PROTECTED_ACCOUNT_AGE_SECONDS),
        hold_window_seconds=int(_mc.HOLD_WINDOW_SECONDS),
    )

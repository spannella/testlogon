from __future__ import annotations

import base64
import time

from uuid import uuid4
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.contracts.questionnaire_validation_contract import QuestionnaireValidationRequest, QuestionnaireValidationResponse
from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.services.questionnaire_validation import validate_form_submission
from app.services.questionnaire_response_pdf import html_to_pdf_bytes, render_response_html
from app.services.text_sanitizer import sanitize_user_text
from app.services.questionnaires_repository import DynamoQuestionnaireRepository
from app.services.rate_limit import rate_limit_password_recovery
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/questionnaires", tags=["questionnaires"])
REPO = DynamoQuestionnaireRepository()

_ALLOWED_TYPES = {"text", "select", "multiselect", "radio", "slider", "date", "time", "timezone", "address"}


class QuestionnaireDraftCreateReq(BaseModel):
    questionnaire_id: str = Field(..., min_length=1, max_length=120)
    title: str = Field(..., min_length=1, max_length=240)
    description: str = Field(default="", max_length=4000)
    visibility: str = Field(default="private", pattern="^(private|public|unlisted)$")


class QuestionnaireDraftUpdateReq(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=4000)
    visibility: str | None = Field(default=None, pattern="^(private|public|unlisted)$")


class SectionCreateReq(BaseModel):
    section_id: str = Field(..., min_length=1, max_length=120)
    title: str = Field(..., min_length=1, max_length=240)
    description: str = Field(default="", max_length=4000)


class SectionUpdateReq(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=4000)


class SectionReorderReq(BaseModel):
    section_ids: list[str] = Field(default_factory=list)


class QuestionCreateReq(BaseModel):
    section_id: str = Field(..., min_length=1, max_length=120)
    question_id: str = Field(..., min_length=1, max_length=120)
    type: str = Field(..., min_length=1, max_length=32)
    label: str = Field(..., min_length=1, max_length=400)
    required: bool = False
    hint: str = Field(default="", max_length=4000)
    config_json: dict[str, Any] = Field(default_factory=dict)


class QuestionUpdateReq(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=400)
    required: bool | None = None
    hint: str | None = Field(default=None, max_length=4000)
    config_json: dict[str, Any] | None = None


class QuestionReorderReq(BaseModel):
    section_id: str = Field(..., min_length=1, max_length=120)
    question_ids: list[str] = Field(default_factory=list)


class PublishDraftReq(BaseModel):
    published_slug: str | None = Field(default=None, min_length=1, max_length=240)
    # LED-005: web-to-lead capture flags (default-off)
    capture_as_lead: bool = False
    lead_source_override: str | None = Field(
        default=None,
        pattern=r"^(web_site|cold_call|email|campaign|trade_show|word_of_mouth|other|internal)$",
    )


class QuestionnaireVersionEnvelope(BaseModel):
    version: dict[str, Any]


class QuestionnaireDraftEnvelope(BaseModel):
    draft: dict[str, Any]


class QuestionnaireDraftListEnvelope(BaseModel):
    items: list[dict[str, Any]]


class SectionEnvelope(BaseModel):
    section: dict[str, Any]


class SectionListEnvelope(BaseModel):
    items: list[dict[str, Any]]


class QuestionEnvelope(BaseModel):
    question: dict[str, Any]


class QuestionListEnvelope(BaseModel):
    items: list[dict[str, Any]]




class ResponseSessionStartReq(BaseModel):
    questionnaire_id: str | None = Field(default=None, min_length=1, max_length=120)


class ResponseSessionEnvelope(BaseModel):
    session: dict[str, Any]


class PublishedQuestionnaireEnvelope(BaseModel):
    version: dict[str, Any]



class SessionSaveReq(BaseModel):
    answers_by_question_id: dict[str, Any] = Field(default_factory=dict)
    current_section_index: int | None = Field(default=None, ge=0)
    current_question_id: str | None = Field(default=None, min_length=1, max_length=120)


class SessionStateEnvelope(BaseModel):
    session: dict[str, Any]
    answers_by_question_id: dict[str, Any]


class SessionPdfEnvelope(BaseModel):
    artifact: dict[str, Any]


class QuestionnaireAnalyticsEnvelope(BaseModel):
    analytics: dict[str, Any]


class SessionSubmitEnvelope(BaseModel):
    session: dict[str, Any]
    result: QuestionnaireValidationResponse


def _compute_questionnaire_analytics(*, questionnaire_id: str, versions: list[dict[str, Any]]) -> dict[str, Any]:
    sessions = REPO.list_response_sessions(questionnaire_id=questionnaire_id)
    events = REPO.list_response_events(questionnaire_id=questionnaire_id)

    version_rows: list[dict[str, Any]] = []
    all_dropoffs: dict[str, int] = {}
    all_hotspots: dict[str, int] = {}

    for version in versions:
        vid = str(version.get("version_id") or "")
        schema = version.get("schema_json") or {}
        sections = schema.get("sections") or []
        section_title_by_index = {idx: str(section.get("title") or f"Section {idx + 1}") for idx, section in enumerate(sections)}

        version_sessions = [s for s in sessions if str(s.get("version_id") or "") == vid]
        starts = len(version_sessions)
        completed_sessions = [s for s in version_sessions if s.get("status") == "submitted" and s.get("submitted_at") is not None]
        completions = len(completed_sessions)

        duration_secs: list[int] = []
        for session in completed_sessions:
            try:
                started = int(session.get("started_at") or 0)
                submitted = int(session.get("submitted_at") or 0)
                if submitted >= started > 0:
                    duration_secs.append(submitted - started)
            except Exception:
                continue

        dropoffs: dict[str, int] = {}
        for session in version_sessions:
            if session.get("status") == "submitted":
                continue
            sec_idx = int(session.get("current_section_index") or 0)
            sec_name = section_title_by_index.get(sec_idx, f"Section {sec_idx + 1}")
            question_id = str(session.get("current_question_id") or "").strip()
            key = f"{sec_name}{' / ' + question_id if question_id else ''}"
            dropoffs[key] = dropoffs.get(key, 0) + 1
            all_dropoffs[key] = all_dropoffs.get(key, 0) + 1

        failure_events = [
            event for event in events
            if event.get("event_type") == "response_validation_failed" and event.get("payload", {}).get("version_id") == vid
        ]
        hotspots: dict[str, int] = {}
        for event in failure_events:
            keys = event.get("payload", {}).get("error_keys") or []
            if not isinstance(keys, list):
                continue
            for key in keys:
                k = str(key)
                hotspots[k] = hotspots.get(k, 0) + 1
                all_hotspots[k] = all_hotspots.get(k, 0) + 1

        top_dropoffs = sorted(dropoffs.items(), key=lambda x: x[1], reverse=True)[:5]
        top_hotspots = sorted(hotspots.items(), key=lambda x: x[1], reverse=True)[:5]
        completion_rate = (completions / starts) if starts else 0.0

        version_rows.append({
            "version_id": vid,
            "version_number": version.get("version_number"),
            "published_at": version.get("published_at"),
            "funnel": {"starts": starts, "completions": completions, "completion_rate": completion_rate},
            "average_completion_seconds": (sum(duration_secs) / len(duration_secs)) if duration_secs else None,
            "dropoff_points": [{"label": label, "count": count} for label, count in top_dropoffs],
            "validation_hotspots": [{"key": key, "count": count} for key, count in top_hotspots],
        })

    return {
        "generated_at": str(int(time.time())),
        "freshness_sla_seconds": 60,
        "versions": version_rows,
        "totals": {
            "starts": sum(v["funnel"]["starts"] for v in version_rows),
            "completions": sum(v["funnel"]["completions"] for v in version_rows),
            "top_dropoffs": [{"label": label, "count": count} for label, count in sorted(all_dropoffs.items(), key=lambda x: x[1], reverse=True)[:5]],
            "top_validation_hotspots": [{"key": key, "count": count} for key, count in sorted(all_hotspots.items(), key=lambda x: x[1], reverse=True)[:5]],
        },
    }


def _owned_questionnaire_or_404(questionnaire_id: str, user_sub: str) -> dict[str, Any]:
    row = REPO.get_questionnaire(questionnaire_id)
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "questionnaire_not_found", "message": "questionnaire not found"}})
    if row.get("owner_id") != user_sub:
        raise HTTPException(status_code=403, detail={"error": {"code": "questionnaire_forbidden", "message": "not owner of questionnaire"}})
    return row


def _ensure_draft(questionnaire_id: str, user_sub: str) -> dict[str, Any]:
    row = _owned_questionnaire_or_404(questionnaire_id, user_sub)
    if row.get("status") != "draft":
        raise HTTPException(status_code=409, detail={"error": {"code": "questionnaire_not_draft", "message": "only draft questionnaires are editable"}})
    return row


def _sanitize_question_text_fields(*, hint: str | None, config_json: dict[str, Any] | None) -> tuple[str | None, dict[str, Any] | None]:
    out_hint = sanitize_user_text(hint) if hint is not None else None
    if config_json is None:
        return out_hint, None
    out_cfg = dict(config_json)
    if "placeholder" in out_cfg:
        out_cfg["placeholder"] = sanitize_user_text(str(out_cfg.get("placeholder", "")), max_length=400)
    if "help_text" in out_cfg:
        out_cfg["help_text"] = sanitize_user_text(str(out_cfg.get("help_text", "")))
    return out_hint, out_cfg




async def _maybe_authenticated_user(request: Request) -> AuthenticatedUser | None:
    try:
        return await get_authenticated_user(request)
    except HTTPException:
        return None


def _enforce_published_access(version: dict[str, Any], user: AuthenticatedUser | None) -> None:
    visibility = version.get("visibility", "private")
    if visibility == "private" and user is None:
        raise HTTPException(status_code=401, detail={"error": {"code": "auth_required", "message": "authentication required for private questionnaire"}})


def _enforce_session_access(version: dict[str, Any], session: dict[str, Any], user: AuthenticatedUser | None) -> None:
    if session.get("respondent_id"):
        if user is None:
            raise HTTPException(status_code=401, detail={"error": {"code": "auth_required", "message": "authentication required for this response session"}})
        if session.get("respondent_id") != user.sub:
            raise HTTPException(status_code=403, detail={"error": {"code": "session_forbidden", "message": "not allowed"}})


def _enforce_anonymous_submission_controls(*, request: Request, version: dict[str, Any], user: AuthenticatedUser | None, action: str) -> None:
    if user is not None:
        return
    if not version.get("allow_anonymous", False):
        return

    if bool(getattr(S, "questionnaire_captcha_required_anonymous", False)):
        token = request.headers.get("x-captcha-token", "")
        expected = str(getattr(S, "questionnaire_captcha_static_token", "") or "")
        if not expected or token != expected:
            raise HTTPException(status_code=403, detail={"error": {"code": "captcha_required", "message": "captcha verification required"}})

    ip = client_ip_from_request(request)
    rate_limit_password_recovery(f"qnr:{version.get('questionnaire_id', 'unknown')}", ip, f"questionnaire_{action}")


def _validate_question_config(question_type: str, config_json: dict[str, Any]) -> None:
    if question_type not in _ALLOWED_TYPES:
        raise HTTPException(status_code=422, detail={"error": {"code": "invalid_question_type", "message": "unsupported question type"}})
    if question_type in {"select", "multiselect", "radio"}:
        options = config_json.get("options")
        if not isinstance(options, list) or not options:
            raise HTTPException(status_code=422, detail={"error": {"code": "invalid_question_config", "message": "options[] is required for select/radio types"}})
    if question_type == "slider":
        if not all(k in config_json for k in ("min", "max", "step")):
            raise HTTPException(status_code=422, detail={"error": {"code": "invalid_question_config", "message": "slider config requires min/max/step"}})
    if question_type == "text":
        for k in ("minLength", "maxLength"):
            if k in config_json and not isinstance(config_json[k], int):
                raise HTTPException(status_code=422, detail={"error": {"code": "invalid_question_config", "message": f"{k} must be an integer"}})


@router.post("/drafts", response_model=QuestionnaireDraftEnvelope)
def create_draft(
    body: QuestionnaireDraftCreateReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    existing = REPO.get_questionnaire(body.questionnaire_id)
    if existing:
        raise HTTPException(status_code=409, detail={"error": {"code": "questionnaire_exists", "message": "questionnaire already exists"}})
    created = REPO.create_draft(
        questionnaire_id=body.questionnaire_id.strip(),
        owner_id=user.sub,
        title=body.title.strip(),
        description=body.description.strip(),
        visibility=body.visibility,
        actor_sub=user.sub,
    )
    return {"draft": created}


@router.get("/drafts", response_model=QuestionnaireDraftListEnvelope)
def list_drafts(
    include_archived: bool = Query(default=False),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    rows = REPO.list_questionnaires_by_owner(user.sub, limit=100)
    if not include_archived:
        rows = [r for r in rows if r.get("status") != "archived"]
    return {"items": rows}


@router.get("/drafts/{questionnaire_id}", response_model=QuestionnaireDraftEnvelope)
def get_draft(
    questionnaire_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    row = _owned_questionnaire_or_404(questionnaire_id, user.sub)
    return {"draft": row}


@router.patch("/drafts/{questionnaire_id}", response_model=QuestionnaireDraftEnvelope)
def update_draft(
    questionnaire_id: str,
    body: QuestionnaireDraftUpdateReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_draft(questionnaire_id, user.sub)
    updated = REPO.update_draft_metadata(
        questionnaire_id=questionnaire_id,
        owner_id=user.sub,
        title=body.title.strip() if body.title is not None else None,
        description=body.description.strip() if body.description is not None else None,
        visibility=body.visibility,
        actor_sub=user.sub,
    )
    return {"draft": updated}


@router.delete("/drafts/{questionnaire_id}", response_model=QuestionnaireDraftEnvelope)
def archive_draft(
    questionnaire_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _owned_questionnaire_or_404(questionnaire_id, user.sub)
    archived = REPO.archive_draft(questionnaire_id=questionnaire_id, owner_id=user.sub, actor_sub=user.sub)
    return {"draft": archived}


@router.post("/drafts/{questionnaire_id}/sections", response_model=SectionEnvelope)
def create_section(
    questionnaire_id: str,
    body: SectionCreateReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_draft(questionnaire_id, user.sub)
    section = REPO.create_section(
        questionnaire_id=questionnaire_id,
        section_id=body.section_id.strip(),
        title=body.title.strip(),
        description=body.description.strip(),
        actor_sub=user.sub,
    )
    return {"section": section}


@router.get("/drafts/{questionnaire_id}/sections", response_model=SectionListEnvelope)
def list_sections(
    questionnaire_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _owned_questionnaire_or_404(questionnaire_id, user.sub)
    return {"items": REPO.list_sections(questionnaire_id)}


@router.patch("/drafts/{questionnaire_id}/sections/{section_id}", response_model=SectionEnvelope)
def update_section(
    questionnaire_id: str,
    section_id: str,
    body: SectionUpdateReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_draft(questionnaire_id, user.sub)
    section = REPO.update_section(
        questionnaire_id=questionnaire_id,
        section_id=section_id,
        title=body.title.strip() if body.title is not None else None,
        description=body.description.strip() if body.description is not None else None,
        visibility=body.visibility,
        actor_sub=user.sub,
    )
    if not section:
        raise HTTPException(status_code=404, detail={"error": {"code": "section_not_found", "message": "section not found"}})
    return {"section": section}


@router.delete("/drafts/{questionnaire_id}/sections/{section_id}", response_model=SectionEnvelope)
def delete_section(
    questionnaire_id: str,
    section_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_draft(questionnaire_id, user.sub)
    section = REPO.delete_section(questionnaire_id=questionnaire_id, section_id=section_id, actor_sub=user.sub)
    if not section:
        raise HTTPException(status_code=404, detail={"error": {"code": "section_not_found", "message": "section not found"}})
    return {"section": section}


@router.post("/drafts/{questionnaire_id}/sections/reorder", response_model=SectionListEnvelope)
def reorder_sections(
    questionnaire_id: str,
    body: SectionReorderReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_draft(questionnaire_id, user.sub)
    current_ids = [s["section_id"] for s in REPO.list_sections(questionnaire_id)]
    if set(current_ids) != set(body.section_ids):
        raise HTTPException(status_code=422, detail={"error": {"code": "invalid_section_order", "message": "section_ids must match current section set"}})
    return {"items": REPO.reorder_sections(questionnaire_id=questionnaire_id, ordered_section_ids=body.section_ids, actor_sub=user.sub)}


@router.post("/drafts/{questionnaire_id}/questions", response_model=QuestionEnvelope)
def create_question(
    questionnaire_id: str,
    body: QuestionCreateReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_draft(questionnaire_id, user.sub)
    section_ids = {s["section_id"] for s in REPO.list_sections(questionnaire_id)}
    if body.section_id not in section_ids:
        raise HTTPException(status_code=404, detail={"error": {"code": "section_not_found", "message": "section not found"}})
    sanitized_hint, sanitized_config = _sanitize_question_text_fields(hint=body.hint.strip(), config_json=body.config_json)
    _validate_question_config(body.type, sanitized_config or {})
    question = REPO.create_question(
        questionnaire_id=questionnaire_id,
        section_id=body.section_id,
        question_id=body.question_id,
        question_type=body.type,
        label=body.label.strip(),
        required=body.required,
        hint=sanitized_hint or "",
        config_json=sanitized_config or {},
        actor_sub=user.sub,
    )
    return {"question": question}


@router.get("/drafts/{questionnaire_id}/sections/{section_id}/questions", response_model=QuestionListEnvelope)
def list_questions(
    questionnaire_id: str,
    section_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _owned_questionnaire_or_404(questionnaire_id, user.sub)
    return {"items": REPO.list_questions(questionnaire_id, section_id)}


@router.patch("/drafts/{questionnaire_id}/questions/{question_id}", response_model=QuestionEnvelope)
def update_question(
    questionnaire_id: str,
    question_id: str,
    section_id: str = Query(...),
    body: QuestionUpdateReq = ...,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_draft(questionnaire_id, user.sub)
    existing = REPO.list_questions(questionnaire_id, section_id, include_deleted=True)
    target = next((q for q in existing if q.get("question_id") == question_id), None)
    if not target:
        raise HTTPException(status_code=404, detail={"error": {"code": "question_not_found", "message": "question not found"}})
    raw_hint = body.hint.strip() if body.hint is not None else None
    incoming_config = body.config_json if body.config_json is not None else None
    sanitized_hint, sanitized_config = _sanitize_question_text_fields(hint=raw_hint, config_json=incoming_config)
    new_config = sanitized_config if sanitized_config is not None else target.get("config_json", {})
    _validate_question_config(target.get("type", "text"), new_config)
    question = REPO.update_question(
        questionnaire_id=questionnaire_id,
        section_id=section_id,
        question_id=question_id,
        label=body.label.strip() if body.label is not None else None,
        required=body.required,
        hint=sanitized_hint,
        config_json=sanitized_config,
        actor_sub=user.sub,
    )
    return {"question": question}


@router.delete("/drafts/{questionnaire_id}/questions/{question_id}", response_model=QuestionEnvelope)
def delete_question(
    questionnaire_id: str,
    question_id: str,
    section_id: str = Query(...),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_draft(questionnaire_id, user.sub)
    question = REPO.delete_question(questionnaire_id=questionnaire_id, section_id=section_id, question_id=question_id, actor_sub=user.sub)
    if not question:
        raise HTTPException(status_code=404, detail={"error": {"code": "question_not_found", "message": "question not found"}})
    return {"question": question}


@router.post("/drafts/{questionnaire_id}/questions/reorder", response_model=QuestionListEnvelope)
def reorder_questions(
    questionnaire_id: str,
    body: QuestionReorderReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_draft(questionnaire_id, user.sub)
    current_ids = [q["question_id"] for q in REPO.list_questions(questionnaire_id, body.section_id)]
    if set(current_ids) != set(body.question_ids):
        raise HTTPException(status_code=422, detail={"error": {"code": "invalid_question_order", "message": "question_ids must match current question set"}})
    return {
        "items": REPO.reorder_questions(
            questionnaire_id=questionnaire_id,
            section_id=body.section_id,
            ordered_question_ids=body.question_ids,
            actor_sub=user.sub,
        )
    }


@router.get("/drafts/{questionnaire_id}/schema")
def get_draft_schema(
    questionnaire_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _owned_questionnaire_or_404(questionnaire_id, user.sub)
    return REPO.build_schema_snapshot(questionnaire_id)


@router.post("/drafts/{questionnaire_id}/publish", response_model=QuestionnaireVersionEnvelope)
def publish_draft(
    questionnaire_id: str,
    body: PublishDraftReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_draft(questionnaire_id, user.sub)
    try:
        version = REPO.publish_draft(
            questionnaire_id=questionnaire_id,
            owner_id=user.sub,
            actor_sub=user.sub,
            published_slug=body.published_slug.strip() if body.published_slug else None,
            capture_as_lead=body.capture_as_lead,           # LED-005
            lead_source_override=body.lead_source_override, # LED-005
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail={"error": {"code": "questionnaire_forbidden", "message": str(exc)}}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={"error": {"code": "publish_failed", "message": str(exc)}}) from exc
    return {"version": version}




@router.get("/drafts/{questionnaire_id}/analytics", response_model=QuestionnaireAnalyticsEnvelope)
def get_questionnaire_analytics(
    questionnaire_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _owned_questionnaire_or_404(questionnaire_id, user.sub)
    versions = REPO.list_versions(questionnaire_id)
    analytics = _compute_questionnaire_analytics(questionnaire_id=questionnaire_id, versions=versions)
    return {"analytics": analytics}

@router.get("/published/{published_slug}", response_model=PublishedQuestionnaireEnvelope)
async def get_published_by_slug(
    published_slug: str,
    request: Request,
):
    version = REPO.get_published_by_slug(published_slug)
    if not version:
        raise HTTPException(status_code=404, detail={"error": {"code": "published_not_found", "message": "published questionnaire not found"}})
    user = await _maybe_authenticated_user(request)
    _enforce_published_access(version, user)
    return {"version": version}


@router.get("/published/by-id/{questionnaire_id}", response_model=PublishedQuestionnaireEnvelope)
async def get_published_by_questionnaire_id(
    questionnaire_id: str,
    request: Request,
):
    draft = REPO.get_questionnaire(questionnaire_id)
    if not draft or not draft.get("published_version_id"):
        raise HTTPException(status_code=404, detail={"error": {"code": "published_not_found", "message": "published questionnaire not found"}})
    version = REPO.get_version_by_id(questionnaire_id, draft["published_version_id"])
    if not version:
        raise HTTPException(status_code=404, detail={"error": {"code": "published_not_found", "message": "published questionnaire not found"}})
    user = await _maybe_authenticated_user(request)
    _enforce_published_access(version, user)
    return {"version": version}


@router.post("/published/{published_slug}/sessions", response_model=ResponseSessionEnvelope)
async def start_response_session(
    published_slug: str,
    body: ResponseSessionStartReq,
    request: Request,
):
    version = REPO.get_published_by_slug(published_slug)
    if not version:
        raise HTTPException(status_code=404, detail={"error": {"code": "published_not_found", "message": "published questionnaire not found"}})
    user = await _maybe_authenticated_user(request)
    _enforce_published_access(version, user)
    if not version.get("allow_anonymous", False) and user is None:
        raise HTTPException(status_code=401, detail={"error": {"code": "auth_required", "message": "authentication required to start session"}})
    _enforce_anonymous_submission_controls(request=request, version=version, user=user, action="start")
    session = REPO.put_response_session(
        response_session_id=f"resp_{uuid4().hex}",
        questionnaire_id=version["questionnaire_id"],
        version_id=version["version_id"],
        respondent_id=(user.sub if user else None),
    )
    return {"session": session}


@router.get("/published/{published_slug}/sessions/{response_session_id}", response_model=SessionStateEnvelope)
async def get_response_session_state(
    published_slug: str,
    response_session_id: str,
    request: Request,
):
    version = REPO.get_published_by_slug(published_slug)
    if not version:
        raise HTTPException(status_code=404, detail={"error": {"code": "published_not_found", "message": "published questionnaire not found"}})
    user = await _maybe_authenticated_user(request)
    _enforce_published_access(version, user)

    session = REPO.get_response_session(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    if not session:
        raise HTTPException(status_code=404, detail={"error": {"code": "session_not_found", "message": "response session not found"}})
    _enforce_session_access(version, session, user)

    answers = REPO.list_session_answers(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    return {"session": session, "answers_by_question_id": answers}


@router.put("/published/{published_slug}/sessions/{response_session_id}", response_model=SessionStateEnvelope)
async def save_response_session_state(
    published_slug: str,
    response_session_id: str,
    body: SessionSaveReq,
    request: Request,
):
    version = REPO.get_published_by_slug(published_slug)
    if not version:
        raise HTTPException(status_code=404, detail={"error": {"code": "published_not_found", "message": "published questionnaire not found"}})
    user = await _maybe_authenticated_user(request)
    _enforce_published_access(version, user)

    session = REPO.get_response_session(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    if not session:
        raise HTTPException(status_code=404, detail={"error": {"code": "session_not_found", "message": "response session not found"}})
    if session.get("status") != "in_progress":
        raise HTTPException(status_code=409, detail={"error": {"code": "session_not_in_progress", "message": "cannot save submitted session"}})
    _enforce_session_access(version, session, user)
    _enforce_anonymous_submission_controls(request=request, version=version, user=user, action="save")

    updated = REPO.save_session_answers(
        questionnaire_id=version["questionnaire_id"],
        response_session_id=response_session_id,
        answers_by_question_id=body.answers_by_question_id,
        current_section_index=body.current_section_index,
        current_question_id=body.current_question_id,
    )
    if not updated:
        raise HTTPException(status_code=404, detail={"error": {"code": "session_not_found", "message": "response session not found"}})

    answers = REPO.list_session_answers(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    return {"session": updated, "answers_by_question_id": answers}


@router.post("/published/{published_slug}/sessions/{response_session_id}/validate", response_model=QuestionnaireValidationResponse)
async def validate_response_session_state(
    published_slug: str,
    response_session_id: str,
    body: QuestionnaireValidationRequest,
    request: Request,
):
    version = REPO.get_published_by_slug(published_slug)
    if not version:
        raise HTTPException(status_code=404, detail={"error": {"code": "published_not_found", "message": "published questionnaire not found"}})
    user = await _maybe_authenticated_user(request)
    _enforce_published_access(version, user)

    session = REPO.get_response_session(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    if not session:
        raise HTTPException(status_code=404, detail={"error": {"code": "session_not_found", "message": "response session not found"}})
    _enforce_session_access(version, session, user)
    _enforce_anonymous_submission_controls(request=request, version=version, user=user, action="validate")

    session_version = REPO.get_version_by_id(version["questionnaire_id"], str(session.get("version_id") or ""))
    if not session_version:
        raise HTTPException(status_code=404, detail={"error": {"code": "session_version_not_found", "message": "response session version not found"}})

    try:
        result = validate_form_submission(
            schema_json=session_version.get("schema_json", {}),
            answers_by_question_id=body.answers_by_question_id,
            group_rules=body.group_rules,
            form_rules=body.form_rules,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": {"code": "invalid_rule_reference", "message": str(exc)}}) from exc

    if body.final_submit and not result.get("can_submit", False):
        REPO.put_response_event(
            questionnaire_id=version["questionnaire_id"],
            response_session_id=response_session_id,
            event_type="response_validation_failed",
            payload={
                "version_id": session_version.get("version_id"),
                "error_keys": list((result.get("errors") or {}).keys()),
                "can_submit": result.get("can_submit", False),
            },
            actor_sub=(user.sub if user else None),
        )
        raise HTTPException(status_code=422, detail={"error": {"code": "form_validation_failed", "result": result}})
    return result


@router.post("/published/{published_slug}/sessions/{response_session_id}/submit", response_model=SessionSubmitEnvelope)
async def submit_response_session(
    published_slug: str,
    response_session_id: str,
    body: QuestionnaireValidationRequest,
    request: Request,
):
    version = REPO.get_published_by_slug(published_slug)
    if not version:
        raise HTTPException(status_code=404, detail={"error": {"code": "published_not_found", "message": "published questionnaire not found"}})

    user = await _maybe_authenticated_user(request)
    _enforce_published_access(version, user)

    session = REPO.get_response_session(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    if not session:
        raise HTTPException(status_code=404, detail={"error": {"code": "session_not_found", "message": "response session not found"}})
    _enforce_session_access(version, session, user)
    _enforce_anonymous_submission_controls(request=request, version=version, user=user, action="submit")
    if session.get("status") != "in_progress":
        raise HTTPException(status_code=409, detail={"error": {"code": "session_not_in_progress", "message": "session already submitted"}})

    if body.answers_by_question_id:
        REPO.save_session_answers(
            questionnaire_id=version["questionnaire_id"],
            response_session_id=response_session_id,
            answers_by_question_id=body.answers_by_question_id,
            current_section_index=session.get("current_section_index"),
            current_question_id=session.get("current_question_id"),
        )

    authoritative_answers = REPO.list_session_answers(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    final_request = QuestionnaireValidationRequest(
        answers_by_question_id=authoritative_answers,
        group_rules=body.group_rules,
        form_rules=body.form_rules,
        final_submit=True,
    )
    result = await validate_response_session_state(published_slug, response_session_id, final_request, request)

    submitted = REPO.mark_response_submitted(
        questionnaire_id=version["questionnaire_id"],
        response_session_id=response_session_id,
        actor_sub=(user.sub if user else None),
    )
    if not submitted:
        raise HTTPException(status_code=404, detail={"error": {"code": "session_not_found", "message": "response session not found"}})

    # LED-005: best-effort web-to-lead capture (default-off)
    from app.core.settings import S as _S
    if getattr(_S, "leads_enabled", False) and version.get("capture_as_lead", False):
        try:
            import app.services.leads as _leads_svc
            _leads_svc.create_lead_from_submission(
                version,
                authoritative_answers,
                response_session_id=response_session_id,
                user_sub=(user.sub if user else None),
            )
        except Exception:
            pass  # never block a successful submission

    return {"session": submitted, "result": result}




@router.post("/published/{published_slug}/sessions/{response_session_id}/pdf", response_model=SessionPdfEnvelope)
async def generate_response_session_pdf(
    published_slug: str,
    response_session_id: str,
    request: Request,
):
    version = REPO.get_published_by_slug(published_slug)
    if not version:
        raise HTTPException(status_code=404, detail={"error": {"code": "published_not_found", "message": "published questionnaire not found"}})

    user = await _maybe_authenticated_user(request)
    _enforce_published_access(version, user)

    session = REPO.get_response_session(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    if not session:
        raise HTTPException(status_code=404, detail={"error": {"code": "session_not_found", "message": "response session not found"}})
    _enforce_session_access(version, session, user)
    if session.get("status") != "submitted":
        raise HTTPException(status_code=409, detail={"error": {"code": "session_not_submitted", "message": "session must be submitted"}})

    session_version = REPO.get_version_by_id(version["questionnaire_id"], str(session.get("version_id") or ""))
    if not session_version:
        raise HTTPException(status_code=404, detail={"error": {"code": "session_version_not_found", "message": "response session version not found"}})

    questionnaire = REPO.get_questionnaire(version["questionnaire_id"]) or {}
    answers = REPO.list_session_answers(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    rendered_html = render_response_html(questionnaire=questionnaire, version=session_version, session=session, answers_by_question_id=answers)
    pdf_bytes = html_to_pdf_bytes(rendered_html)
    artifact = REPO.put_response_pdf_artifact(
        questionnaire_id=version["questionnaire_id"],
        response_session_id=response_session_id,
        pdf_bytes=pdf_bytes,
        generated_by=(user.sub if user else None),
    )
    return {"artifact": {
        "response_session_id": response_session_id,
        "content_type": artifact.get("content_type"),
        "generated_at": artifact.get("generated_at"),
        "size_bytes": artifact.get("size_bytes"),
        "download_url": f"/questionnaires/published/{published_slug}/sessions/{response_session_id}/pdf",
    }}


@router.get("/published/{published_slug}/sessions/{response_session_id}/pdf")
async def download_response_session_pdf(
    published_slug: str,
    response_session_id: str,
    request: Request,
):
    version = REPO.get_published_by_slug(published_slug)
    if not version:
        raise HTTPException(status_code=404, detail={"error": {"code": "published_not_found", "message": "published questionnaire not found"}})

    user = await _maybe_authenticated_user(request)
    _enforce_published_access(version, user)

    session = REPO.get_response_session(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    if not session:
        raise HTTPException(status_code=404, detail={"error": {"code": "session_not_found", "message": "response session not found"}})
    _enforce_session_access(version, session, user)

    artifact = REPO.get_response_pdf_artifact(questionnaire_id=version["questionnaire_id"], response_session_id=response_session_id)
    if not artifact or not artifact.get("pdf_base64"):
        raise HTTPException(status_code=404, detail={"error": {"code": "pdf_not_found", "message": "response pdf not generated"}})

    try:
        pdf_bytes = base64.b64decode(str(artifact.get("pdf_base64") or ""), validate=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": {"code": "pdf_corrupt", "message": "stored response pdf is corrupt"}}) from exc

    filename = f"questionnaire-response-{response_session_id}.pdf"
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{filename}"'})

@router.post("/drafts/{questionnaire_id}/validate", response_model=QuestionnaireValidationResponse)
def validate_draft_form(
    questionnaire_id: str,
    body: QuestionnaireValidationRequest,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _owned_questionnaire_or_404(questionnaire_id, user.sub)
    schema = REPO.build_schema_snapshot(questionnaire_id)
    try:
        result = validate_form_submission(
            schema_json=schema,
            answers_by_question_id=body.answers_by_question_id,
            group_rules=body.group_rules,
            form_rules=body.form_rules,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": {"code": "invalid_rule_reference", "message": str(exc)}}) from exc

    if body.final_submit and not result.get("can_submit", False):
        raise HTTPException(status_code=422, detail={"error": {"code": "form_validation_failed", "result": result}})
    return result

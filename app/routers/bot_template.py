"""Bot template & scheduled send endpoints (BOT-002)."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator

from app.services.sessions import require_ui_session
from app.core.settings import S
from app.services.bot_template import (
    TemplateLimitExceeded,
    create_template,
    delete_template,
    get_template,
    list_templates,
    render_template,
    update_template,
)
from app.services.bot_scheduler import (
    InvalidCronExpression,
    InvalidTimezone,
    ScheduleLimitExceeded,
    TemplateNotFoundError,
    create_scheduled_send,
    delete_scheduled_send,
    list_scheduled_sends,
    update_scheduled_send,
)
from app.services.chat_bot import BotNotFound, get_bot_for_owner, send_bot_message

logger = logging.getLogger(__name__)

router = APIRouter(tags=["bot-templates"])

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class QuickReplyIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=40)
    value: str = Field(..., min_length=1, max_length=200)


class CreateTemplateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    text: str = Field(..., min_length=1, max_length=4000)
    category: Literal["greeting", "support", "promotion", "farewell", "away", "custom"] = "custom"
    body_format: Literal["plain", "markdown"] = "plain"
    quick_replies: Optional[List[QuickReplyIn]] = Field(default=None)
    ab_group: Optional[str] = Field(default=None, max_length=50)
    ab_weight: int = Field(default=1, ge=1, le=100)


class UpdateTemplateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    text: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    category: Optional[Literal["greeting", "support", "promotion", "farewell", "away", "custom"]] = None
    body_format: Optional[Literal["plain", "markdown"]] = None
    quick_replies: Optional[List[QuickReplyIn]] = None
    ab_group: Optional[str] = Field(default=None, max_length=50)
    ab_weight: Optional[int] = Field(default=None, ge=1, le=100)


class PreviewTemplateIn(BaseModel):
    sample_user_name: Optional[str] = Field(default=None, max_length=100)
    sample_subscriber_status: Optional[str] = Field(default=None, max_length=50)
    conversation_id: Optional[str] = Field(default=None, max_length=100)


class SendTestTemplateIn(BaseModel):
    conversation_id: str = Field(..., min_length=1, max_length=100)


class CreateScheduledSendIn(BaseModel):
    template_id: str = Field(..., min_length=1, max_length=100)
    target_type: Literal["conversation", "all_dms", "all_groups", "all_broadcasts"]
    target_id: Optional[str] = Field(default=None, max_length=100)
    cron_expression: str = Field(..., min_length=5, max_length=100)
    timezone: str = Field(default="UTC", max_length=50)

    @model_validator(mode="after")
    def validate_target_id(self):
        if self.target_type == "conversation" and not self.target_id:
            raise ValueError("target_id is required when target_type is 'conversation'")
        return self


class UpdateScheduledSendIn(BaseModel):
    template_id: Optional[str] = Field(default=None, max_length=100)
    cron_expression: Optional[str] = Field(default=None, min_length=5, max_length=100)
    timezone: Optional[str] = Field(default=None, max_length=50)
    enabled: Optional[bool] = None


# ---------------------------------------------------------------------------
# Template endpoints
# ---------------------------------------------------------------------------


@router.post("/bots/{bot_id}/templates", status_code=201)
async def create_template_endpoint(
    bot_id: str,
    body: CreateTemplateIn,
    session=Depends(require_ui_session),
):
    if not S.bot_templates_enabled:
        raise HTTPException(503, "Bot templates are disabled")
    try:
        qr = [q.model_dump() for q in body.quick_replies] if body.quick_replies else None
        template = create_template(
            bot_id=bot_id,
            creator_id=session["user_sub"],
            name=body.name,
            text=body.text,
            category=body.category,
            body_format=body.body_format,
            quick_replies=qr,
            ab_group=body.ab_group,
            ab_weight=body.ab_weight,
        )
        return template
    except BotNotFound:
        raise HTTPException(404, "Bot not found")
    except TemplateLimitExceeded as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/bots/{bot_id}/templates")
async def list_templates_endpoint(
    bot_id: str,
    category: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    if not S.bot_templates_enabled:
        raise HTTPException(503, "Bot templates are disabled")
    # Verify ownership
    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")
    templates = list_templates(bot_id=bot_id, category=category)
    return templates


@router.get("/bots/{bot_id}/templates/{template_id}")
async def get_template_endpoint(
    bot_id: str,
    template_id: str,
    session=Depends(require_ui_session),
):
    if not S.bot_templates_enabled:
        raise HTTPException(503, "Bot templates are disabled")
    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")
    template = get_template(bot_id=bot_id, template_id=template_id)
    if not template:
        raise HTTPException(404, "Template not found")
    return template


@router.put("/bots/{bot_id}/templates/{template_id}")
async def update_template_endpoint(
    bot_id: str,
    template_id: str,
    body: UpdateTemplateIn,
    session=Depends(require_ui_session),
):
    if not S.bot_templates_enabled:
        raise HTTPException(503, "Bot templates are disabled")
    try:
        updates = body.model_dump(exclude_none=True)
        if "quick_replies" in updates and updates["quick_replies"]:
            updates["quick_replies"] = [q if isinstance(q, dict) else q.model_dump() for q in updates["quick_replies"]]
        template = update_template(
            bot_id=bot_id,
            template_id=template_id,
            creator_id=session["user_sub"],
            **updates,
        )
        if not template:
            raise HTTPException(404, "Template not found")
        return template
    except BotNotFound:
        raise HTTPException(404, "Bot not found")
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.delete("/bots/{bot_id}/templates/{template_id}")
async def delete_template_endpoint(
    bot_id: str,
    template_id: str,
    session=Depends(require_ui_session),
):
    if not S.bot_templates_enabled:
        raise HTTPException(503, "Bot templates are disabled")
    try:
        ok = delete_template(
            bot_id=bot_id,
            template_id=template_id,
            creator_id=session["user_sub"],
        )
        if not ok:
            raise HTTPException(404, "Template not found")
        return {"ok": True}
    except BotNotFound:
        raise HTTPException(404, "Bot not found")


@router.post("/bots/{bot_id}/templates/{template_id}/preview")
async def preview_template_endpoint(
    bot_id: str,
    template_id: str,
    body: PreviewTemplateIn,
    session=Depends(require_ui_session),
):
    if not S.bot_templates_enabled:
        raise HTTPException(503, "Bot templates are disabled")
    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")
    template = get_template(bot_id=bot_id, template_id=template_id)
    if not template:
        raise HTTPException(404, "Template not found")

    overrides: dict[str, str] = {}
    if body.sample_user_name:
        overrides["user_name"] = body.sample_user_name
    if body.sample_subscriber_status:
        overrides["subscriber_status"] = body.sample_subscriber_status

    result = render_template(
        template=template,
        sender_id=session["user_sub"],
        creator_id=session["user_sub"],
        bot=bot,
        conversation_id=body.conversation_id,
        sample_overrides=overrides,
    )
    return result


@router.post("/bots/{bot_id}/templates/{template_id}/send-test")
async def send_test_template_endpoint(
    bot_id: str,
    template_id: str,
    body: SendTestTemplateIn,
    session=Depends(require_ui_session),
):
    if not S.bot_templates_enabled:
        raise HTTPException(503, "Bot templates are disabled")
    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")
    template = get_template(bot_id=bot_id, template_id=template_id)
    if not template:
        raise HTTPException(404, "Template not found")

    result = render_template(
        template=template,
        sender_id=session["user_sub"],
        creator_id=session["user_sub"],
        bot=bot,
        conversation_id=body.conversation_id,
    )
    msg = send_bot_message(
        bot_id=bot_id,
        conversation_id=body.conversation_id,
        text=result["rendered_text"],
    )
    if not msg:
        raise HTTPException(409, "Bot is not active")
    return {"ok": True, "rendered_text": result["rendered_text"]}


# ---------------------------------------------------------------------------
# Schedule endpoints
# ---------------------------------------------------------------------------


@router.post("/bots/{bot_id}/schedules", status_code=201)
async def create_schedule_endpoint(
    bot_id: str,
    body: CreateScheduledSendIn,
    session=Depends(require_ui_session),
):
    if not S.bot_scheduled_messages_enabled:
        raise HTTPException(503, "Bot scheduled messages are disabled")
    try:
        schedule = create_scheduled_send(
            bot_id=bot_id,
            creator_id=session["user_sub"],
            template_id=body.template_id,
            target_type=body.target_type,
            target_id=body.target_id,
            cron_expression=body.cron_expression,
            timezone=body.timezone,
        )
        return schedule
    except BotNotFound:
        raise HTTPException(404, "Bot not found")
    except TemplateNotFoundError:
        raise HTTPException(404, "Template not found")
    except InvalidCronExpression as exc:
        raise HTTPException(422, str(exc))
    except InvalidTimezone as exc:
        raise HTTPException(422, str(exc))
    except ScheduleLimitExceeded as exc:
        raise HTTPException(409, str(exc))


@router.get("/bots/{bot_id}/schedules")
async def list_schedules_endpoint(
    bot_id: str,
    session=Depends(require_ui_session),
):
    if not S.bot_scheduled_messages_enabled:
        raise HTTPException(503, "Bot scheduled messages are disabled")
    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")
    schedules = list_scheduled_sends(bot_id=bot_id)
    return schedules


@router.put("/bots/{bot_id}/schedules/{schedule_id}")
async def update_schedule_endpoint(
    bot_id: str,
    schedule_id: str,
    body: UpdateScheduledSendIn,
    session=Depends(require_ui_session),
):
    if not S.bot_scheduled_messages_enabled:
        raise HTTPException(503, "Bot scheduled messages are disabled")
    try:
        updates = body.model_dump(exclude_none=True)
        schedule = update_scheduled_send(
            bot_id=bot_id,
            schedule_id=schedule_id,
            creator_id=session["user_sub"],
            **updates,
        )
        if not schedule:
            raise HTTPException(404, "Schedule not found")
        return schedule
    except BotNotFound:
        raise HTTPException(404, "Bot not found")
    except InvalidCronExpression as exc:
        raise HTTPException(422, str(exc))
    except InvalidTimezone as exc:
        raise HTTPException(422, str(exc))


@router.delete("/bots/{bot_id}/schedules/{schedule_id}")
async def delete_schedule_endpoint(
    bot_id: str,
    schedule_id: str,
    session=Depends(require_ui_session),
):
    if not S.bot_scheduled_messages_enabled:
        raise HTTPException(503, "Bot scheduled messages are disabled")
    try:
        ok = delete_scheduled_send(
            bot_id=bot_id,
            schedule_id=schedule_id,
            creator_id=session["user_sub"],
        )
        if not ok:
            raise HTTPException(404, "Schedule not found")
        return {"ok": True}
    except BotNotFound:
        raise HTTPException(404, "Bot not found")

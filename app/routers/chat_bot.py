"""Bot management endpoints (BOT-001)."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator

from app.services.sessions import require_ui_session
from app.auth.deps import require_ui_session
from app.core.settings import S
from app.services.chat_bot import (
    BotLimitExceeded,
    BotNotFound,
    DuplicateAssignment,
    InvalidStatusTransition,
    assign_bot,
    create_bot,
    delete_bot,
    get_bot,
    get_bot_for_owner,
    get_bot_stats,
    list_assignments,
    list_bots,
    send_bot_message,
    unassign_bot,
    update_bot,
    update_bot_status,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["bots"])

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CreateBotIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    avatar_url: Optional[str] = Field(default=None, max_length=2048)
    description: Optional[str] = Field(default=None, max_length=500)
    personality: str = Field(default="friendly")
    custom_personality: Optional[str] = Field(default=None, max_length=2000)


class UpdateBotIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    avatar_url: Optional[str] = Field(default=None, max_length=2048)
    description: Optional[str] = Field(default=None, max_length=500)
    personality: Optional[str] = None
    custom_personality: Optional[str] = Field(default=None, max_length=2000)
    trigger_config: Optional[Dict[str, Any]] = None


class UpdateBotStatusIn(BaseModel):
    status: str = Field(...)


class AssignBotIn(BaseModel):
    target_type: str = Field(...)
    target_id: Optional[str] = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def validate_target_id(self):
        if self.target_type in ("conversation", "broadcast") and not self.target_id:
            raise ValueError("target_id is required for conversation and broadcast assignments")
        return self


class SendBotMessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    conversation_id: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/bots", status_code=201)
async def create_bot_endpoint(body: CreateBotIn, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    try:
        bot = create_bot(
            creator_id=session["user_sub"],
            name=body.name,
            avatar_url=body.avatar_url,
            description=body.description,
            personality=body.personality,
            custom_personality=body.custom_personality,
        )
        return bot
    except BotLimitExceeded as exc:
        raise HTTPException(409, str(exc))


@router.get("/bots")
async def list_bots_endpoint(session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    bots = list_bots(creator_id=session["user_sub"])
    return {"bots": bots}


@router.get("/bots/{bot_id}")
async def get_bot_endpoint(bot_id: str, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")
    return bot


@router.put("/bots/{bot_id}")
async def update_bot_endpoint(bot_id: str, body: UpdateBotIn, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    updates = body.model_dump(exclude_none=True)
    bot = update_bot(creator_id=session["user_sub"], bot_id=bot_id, **updates)
    if not bot:
        raise HTTPException(404, "Bot not found")
    return bot


@router.patch("/bots/{bot_id}/status")
async def update_bot_status_endpoint(bot_id: str, body: UpdateBotStatusIn, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    try:
        bot = update_bot_status(creator_id=session["user_sub"], bot_id=bot_id, status=body.status)
        if not bot:
            raise HTTPException(404, "Bot not found")
        return bot
    except InvalidStatusTransition as exc:
        raise HTTPException(400, str(exc))


@router.delete("/bots/{bot_id}")
async def delete_bot_endpoint(bot_id: str, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    ok = delete_bot(creator_id=session["user_sub"], bot_id=bot_id)
    if not ok:
        raise HTTPException(404, "Bot not found")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Assignment endpoints
# ---------------------------------------------------------------------------

@router.post("/bots/{bot_id}/assignments", status_code=201)
async def assign_bot_endpoint(bot_id: str, body: AssignBotIn, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    try:
        assignment = assign_bot(
            bot_id=bot_id,
            creator_id=session["user_sub"],
            target_type=body.target_type,
            target_id=body.target_id,
        )
        return assignment
    except BotNotFound:
        raise HTTPException(404, "Bot not found")
    except DuplicateAssignment as exc:
        raise HTTPException(409, str(exc))


@router.delete("/bots/{bot_id}/assignments/{assignment_sk:path}")
async def unassign_bot_endpoint(bot_id: str, assignment_sk: str, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    try:
        ok = unassign_bot(bot_id=bot_id, creator_id=session["user_sub"], assignment_sk=assignment_sk)
        if not ok:
            raise HTTPException(404, "Assignment not found")
        return {"ok": True}
    except BotNotFound:
        raise HTTPException(404, "Bot not found")


@router.get("/bots/{bot_id}/assignments")
async def list_assignments_endpoint(bot_id: str, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    try:
        assignments = list_assignments(bot_id=bot_id, creator_id=session["user_sub"])
        return {"assignments": assignments}
    except BotNotFound:
        raise HTTPException(404, "Bot not found")


@router.get("/bots/{bot_id}/stats")
async def get_bot_stats_endpoint(bot_id: str, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    stats = get_bot_stats(bot_id=bot_id, creator_id=session["user_sub"])
    if not stats:
        raise HTTPException(404, "Bot not found")
    return stats


# ---------------------------------------------------------------------------
# Bot message send (for testing / manual send)
# ---------------------------------------------------------------------------

@router.post("/bots/{bot_id}/send")
async def send_bot_message_endpoint(bot_id: str, body: SendBotMessageIn, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")
    if bot["status"] != "active":
        raise HTTPException(409, "Bot is not active")
    result = send_bot_message(bot_id=bot_id, conversation_id=body.conversation_id, text=body.text)
    if not result:
        raise HTTPException(409, "Bot is not active")
    return result

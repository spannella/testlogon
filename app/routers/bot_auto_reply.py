"""Bot auto-reply rule endpoints (BOT-003)."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.services.sessions import require_ui_session
from app.core.settings import S
from app.services.chat_bot import get_bot_for_owner
from app.services.bot_auto_reply import (
    create_auto_reply_rule,
    list_auto_reply_rules,
    get_auto_reply_rule,
    update_auto_reply_rule,
    delete_auto_reply_rule,
    process_incoming_message,
    test_message_against_rules,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["bot-auto-reply"])

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateAutoReplyRuleIn(BaseModel):
    trigger_pattern: str = Field(..., min_length=1, max_length=500)
    response_template: str = Field(..., min_length=1, max_length=2000)
    match_type: Literal["keyword", "regex", "contains", "exact"] = "contains"
    priority: int = Field(default=100, ge=1, le=10000)
    enabled: bool = True


class UpdateAutoReplyRuleIn(BaseModel):
    trigger_pattern: Optional[str] = Field(default=None, min_length=1, max_length=500)
    response_template: Optional[str] = Field(default=None, min_length=1, max_length=2000)
    match_type: Optional[Literal["keyword", "regex", "contains", "exact"]] = None
    priority: Optional[int] = Field(default=None, ge=1, le=10000)
    enabled: Optional[bool] = None


class TestAutoReplyIn(BaseModel):
    message_text: str = Field(..., min_length=1, max_length=5000)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/bots/{bot_id}/auto-replies", status_code=201)
async def create_auto_reply_rule_endpoint(
    bot_id: str, body: CreateAutoReplyRuleIn, session=Depends(require_ui_session)
):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    if not S.bot_auto_reply_enabled:
        raise HTTPException(503, "Bot auto-reply is disabled")

    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")

    rule = create_auto_reply_rule(
        bot_id=bot_id,
        creator_id=session["user_sub"],
        trigger_pattern=body.trigger_pattern,
        response_template=body.response_template,
        match_type=body.match_type,
        priority=body.priority,
        enabled=body.enabled,
    )
    return rule


@router.get("/bots/{bot_id}/auto-replies")
async def list_auto_reply_rules_endpoint(bot_id: str, session=Depends(require_ui_session)):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")

    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")

    rules = list_auto_reply_rules(bot_id=bot_id)
    return {"rules": rules}


@router.get("/bots/{bot_id}/auto-replies/{rule_id}")
async def get_auto_reply_rule_endpoint(
    bot_id: str, rule_id: str, session=Depends(require_ui_session)
):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")

    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")

    rule = get_auto_reply_rule(bot_id=bot_id, rule_id=rule_id)
    if not rule:
        raise HTTPException(404, "Auto-reply rule not found")
    return rule


@router.put("/bots/{bot_id}/auto-replies/{rule_id}")
async def update_auto_reply_rule_endpoint(
    bot_id: str, rule_id: str, body: UpdateAutoReplyRuleIn, session=Depends(require_ui_session)
):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")

    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")

    updates = body.model_dump(exclude_none=True)
    rule = update_auto_reply_rule(bot_id=bot_id, rule_id=rule_id, **updates)
    if not rule:
        raise HTTPException(404, "Auto-reply rule not found")
    return rule


@router.delete("/bots/{bot_id}/auto-replies/{rule_id}")
async def delete_auto_reply_rule_endpoint(
    bot_id: str, rule_id: str, session=Depends(require_ui_session)
):
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")

    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")

    ok = delete_auto_reply_rule(bot_id=bot_id, rule_id=rule_id)
    if not ok:
        raise HTTPException(404, "Auto-reply rule not found")
    return {"ok": True}


@router.post("/bots/{bot_id}/auto-replies/test")
async def test_auto_reply_endpoint(
    bot_id: str, body: TestAutoReplyIn, session=Depends(require_ui_session)
):
    """Test a message against rules without sending a response."""
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")

    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")

    result = test_message_against_rules(bot_id=bot_id, message_text=body.message_text)
    return result


@router.post("/bots/{bot_id}/auto-replies/process")
async def process_message_endpoint(
    bot_id: str,
    body: TestAutoReplyIn,
    session=Depends(require_ui_session),
):
    """Process an incoming message against auto-reply rules (rate-limited).

    This is the production entry point for triggering auto-replies.
    """
    if not S.bot_framework_enabled:
        raise HTTPException(503, "Bot framework is disabled")
    if not S.bot_auto_reply_enabled:
        raise HTTPException(503, "Bot auto-reply is disabled")

    bot = get_bot_for_owner(creator_id=session["user_sub"], bot_id=bot_id)
    if not bot:
        raise HTTPException(404, "Bot not found")

    # Use a placeholder conversation_id for the process endpoint
    result = process_incoming_message(
        bot_id=bot_id,
        conversation_id="test",
        message_text=body.message_text,
    )
    if not result:
        return {"matched": False, "response_text": None}
    return result

"""Bot framework service — CRUD, assignments, trigger evaluation (BOT-001)."""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Messages / Conversations table handles. These live in app/routers/messaging.py
# (as tbl_msgs / tbl_convos) which would create a circular import if imported
# here, so we resolve them directly from the boto3 resource using the same env
# var names the messaging router uses (GAP-0015).
_tbl_messages = ddb.Table(os.getenv("DDB_MESSAGES", "Messages"))
_tbl_conversations = ddb.Table(os.getenv("DDB_CONVERSATIONS", "Conversations"))

# ---------------------------------------------------------------------------
# Bot CRUD
# ---------------------------------------------------------------------------

def create_bot(
    *,
    creator_id: str,
    name: str,
    avatar_url: str | None = None,
    description: str | None = None,
    personality: str = "friendly",
    custom_personality: str | None = None,
) -> dict:
    """Create a new bot for a creator. Enforces max bots per creator."""
    # Count existing bots
    resp = T.chat_bots.query(
        KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}") & Key("sk").begins_with("BOT#"),
        Select="COUNT",
    )
    count = resp.get("Count", 0)
    if count >= S.bot_max_per_creator:
        raise BotLimitExceeded(f"Maximum of {S.bot_max_per_creator} bots per creator")

    bot_id = uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"CREATOR#{creator_id}",
        "sk": f"BOT#{bot_id}",
        "bot_id": bot_id,
        "creator_id": creator_id,
        "name": name,
        "status": "active",
        "personality": personality,
        "created_at": ts,
        "updated_at": ts,
        "message_count": 0,
        "GSI1PK": f"BOT#{bot_id}",
        "GSI1SK": "META",
    }
    if avatar_url:
        item["avatar_url"] = avatar_url
    if description:
        item["description"] = description
    if custom_personality:
        item["custom_personality"] = custom_personality

    T.chat_bots.put_item(Item=item)
    logger.info("Bot created: bot_id=%s creator_id=%s name=%s", bot_id, creator_id, name)
    return _bot_dict(item)


def get_bot(*, bot_id: str) -> dict | None:
    """Fetch bot by bot_id via GSI1."""
    resp = T.chat_bots.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"BOT#{bot_id}") & Key("GSI1SK").eq("META"),
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _bot_dict(items[0])


def get_bot_for_owner(*, creator_id: str, bot_id: str) -> dict | None:
    """Fetch bot ensuring ownership."""
    resp = T.chat_bots.get_item(Key={"pk": f"CREATOR#{creator_id}", "sk": f"BOT#{bot_id}"})
    item = resp.get("Item")
    if not item:
        return None
    return _bot_dict(item)


def list_bots(*, creator_id: str) -> list[dict]:
    """List all bots for a creator."""
    resp = T.chat_bots.query(
        KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}") & Key("sk").begins_with("BOT#"),
    )
    return [_bot_dict(item) for item in resp.get("Items", [])]


def update_bot(*, creator_id: str, bot_id: str, **fields) -> dict | None:
    """Update bot fields. Returns updated bot dict or None if not found."""
    allowed = {"name", "avatar_url", "description", "personality", "custom_personality", "trigger_config"}
    updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if not updates:
        return get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)

    ts = now_ts()
    expr_parts = []
    attr_names: Dict[str, str] = {}
    attr_values: Dict[str, Any] = {}
    for i, (k, v) in enumerate(updates.items()):
        placeholder = f"#f{i}"
        value_ph = f":v{i}"
        expr_parts.append(f"{placeholder} = {value_ph}")
        attr_names[placeholder] = k
        attr_values[value_ph] = v

    expr_parts.append("#ua = :ua_val")
    attr_names["#ua"] = "updated_at"
    attr_values[":ua_val"] = ts

    try:
        resp = T.chat_bots.update_item(
            Key={"pk": f"CREATOR#{creator_id}", "sk": f"BOT#{bot_id}"},
            UpdateExpression="SET " + ", ".join(expr_parts),
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
            ConditionExpression="attribute_exists(pk)",
            ReturnValues="ALL_NEW",
        )
        return _bot_dict(resp["Attributes"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return None
        raise


def update_bot_status(*, creator_id: str, bot_id: str, status: str) -> dict | None:
    """Transition bot status."""
    valid_transitions = {
        "active": {"paused", "disabled"},
        "paused": {"active", "disabled"},
        "disabled": {"active", "paused"},
    }
    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        return None
    current = bot["status"]
    if status not in valid_transitions.get(current, set()):
        raise InvalidStatusTransition(f"Cannot transition from {current} to {status}")

    ts = now_ts()
    try:
        resp = T.chat_bots.update_item(
            Key={"pk": f"CREATOR#{creator_id}", "sk": f"BOT#{bot_id}"},
            UpdateExpression="SET #st = :st, #ua = :ua",
            ExpressionAttributeNames={"#st": "status", "#ua": "updated_at"},
            ExpressionAttributeValues={":st": status, ":ua": ts},
            ConditionExpression="attribute_exists(pk)",
            ReturnValues="ALL_NEW",
        )
        logger.info("Bot status changed: bot_id=%s from=%s to=%s", bot_id, current, status)
        return _bot_dict(resp["Attributes"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return None
        raise


def delete_bot(*, creator_id: str, bot_id: str) -> bool:
    """Delete a bot and all its assignments, auto-reply rules and scheduled sends."""
    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        return False

    # Delete all assignments first
    assignments = _query_all_assignments(bot_id=bot_id)
    for a in assignments:
        T.bot_assignments.delete_item(Key={"pk": a["pk"], "sk": a["sk"]})

    # GAP-0138: cascade-delete auto-reply rules. These live in T.chat_bots under
    # pk=BOT#{bot_id} / sk=RULE#{rule_id} (a different partition than the main bot
    # record at CREATOR#{creator_id}/BOT#{bot_id}). Without this they were orphaned.
    rules = _query_all_auto_reply_rules_raw(bot_id=bot_id)
    for r in rules:
        T.chat_bots.delete_item(Key={"pk": r["pk"], "sk": r["sk"]})
    if rules:
        logger.info(
            "Bot deleted: cascade-deleted %d auto-reply rule(s) for bot_id=%s",
            len(rules), bot_id,
        )

    # GAP-0138: cascade-delete scheduled sends (T.bot_scheduled_sends under
    # pk=BOT#{bot_id} / sk=SCHED#{schedule_id}) so they are not left orphaned.
    scheds = _query_all_scheduled_sends_raw(bot_id=bot_id)
    for s in scheds:
        T.bot_scheduled_sends.delete_item(Key={"pk": s["pk"], "sk": s["sk"]})
    if scheds:
        logger.info(
            "Bot deleted: cascade-deleted %d scheduled send(s) for bot_id=%s",
            len(scheds), bot_id,
        )

    T.chat_bots.delete_item(Key={"pk": f"CREATOR#{creator_id}", "sk": f"BOT#{bot_id}"})
    logger.info("Bot deleted: bot_id=%s creator_id=%s", bot_id, creator_id)
    return True


# ---------------------------------------------------------------------------
# Assignments
# ---------------------------------------------------------------------------

def assign_bot(
    *,
    bot_id: str,
    creator_id: str,
    target_type: str,
    target_id: str | None = None,
) -> dict:
    """Assign bot to a conversation, broadcast, or wildcard scope."""
    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        raise BotNotFound("Bot not found")

    sk = _build_assignment_sk(target_type, target_id)
    gsi1pk = _build_assignment_gsi1pk(target_type, target_id)

    # Check for duplicate
    existing = T.bot_assignments.get_item(Key={"pk": f"BOT#{bot_id}", "sk": sk}).get("Item")
    if existing:
        raise DuplicateAssignment("Bot is already assigned to this target")

    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"BOT#{bot_id}",
        "sk": sk,
        "bot_id": bot_id,
        "creator_id": creator_id,
        "target_type": target_type,
        "created_at": ts,
    }
    if target_id:
        item["target_id"] = target_id
    if gsi1pk:
        item["GSI1PK"] = gsi1pk
        item["GSI1SK"] = f"BOT#{bot_id}"

    T.bot_assignments.put_item(Item=item)
    logger.info("Bot assigned: bot_id=%s target_type=%s target_id=%s", bot_id, target_type, target_id)
    return _assignment_dict(item)


def unassign_bot(*, bot_id: str, creator_id: str, assignment_sk: str) -> bool:
    """Remove an assignment by sk."""
    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        raise BotNotFound("Bot not found")

    existing = T.bot_assignments.get_item(Key={"pk": f"BOT#{bot_id}", "sk": assignment_sk}).get("Item")
    if not existing:
        return False

    T.bot_assignments.delete_item(Key={"pk": f"BOT#{bot_id}", "sk": assignment_sk})
    return True


def list_assignments(*, bot_id: str, creator_id: str) -> list[dict]:
    """List all assignments for a bot."""
    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        raise BotNotFound("Bot not found")

    items = _query_all_assignments(bot_id=bot_id)
    return [_assignment_dict(i) for i in items]


def get_bots_for_conversation(
    *,
    conversation_id: str,
    conversation_type: str = "dm",
) -> list[dict]:
    """Find all bots that apply to a conversation.

    Resolves both direct ``CONV#{conversation_id}`` assignments and wildcard
    scope assignments (``all_dms`` / ``all_groups`` / ``all_broadcasts``) that
    match the conversation kind. All assignments live on GSI1: direct ones under
    the ``CONV#`` bucket and wildcard ones under their ``SCOPE#`` bucket, so each
    is reachable with a single keyed query (GAP-0134).
    """
    bot_ids: set[str] = set()

    # 1. Direct assignments.
    resp = T.bot_assignments.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"CONV#{conversation_id}"),
    )
    for item in resp.get("Items", []):
        bot_ids.add(item["bot_id"])

    # 2. Wildcard scope assignments matching this conversation kind.
    scope_pk = _CONVO_KIND_TO_SCOPE_GSI1PK.get(conversation_type)
    if scope_pk:
        scope_resp = T.bot_assignments.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(scope_pk),
        )
        for item in scope_resp.get("Items", []):
            bot_ids.add(item["bot_id"])

    bots = []
    for bid in bot_ids:
        b = get_bot(bot_id=bid)
        if b and b["status"] == "active":
            bots.append(b)
    return bots


def get_bot_stats(*, bot_id: str, creator_id: str) -> dict | None:
    """Get bot stats."""
    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        return None
    assignments = _query_all_assignments(bot_id=bot_id)
    return {
        "message_count": int(bot.get("message_count", 0)),
        "last_active_at": bot.get("updated_at"),
        "assignment_count": len(assignments),
    }


# ---------------------------------------------------------------------------
# Send bot message
# ---------------------------------------------------------------------------

def send_bot_message(
    *,
    bot_id: str,
    conversation_id: str,
    text: str,
    kind: str = "text",
) -> dict | None:
    """Send a message as a bot.

    Writes the message to the Messages table so it actually appears in the
    conversation, updates the conversation's last-message metadata (as ordinary
    sends do), increments the bot's cosmetic message_count, and returns the full
    stored item dict (including ``message_id``). Returns None if the bot is not
    active. (GAP-0015)
    """
    bot = get_bot(bot_id=bot_id)
    if not bot or bot["status"] != "active":
        return None

    ts = now_ts()
    message_id = "m_" + uuid4().hex

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": message_id,
        "sender_id": f"bot:{bot_id}",
        "sender_type": "bot",
        "bot_id": bot_id,
        "bot_name": bot["name"],
        "bot_avatar_url": bot.get("avatar_url"),
        "text": text,
        "kind": kind,
        "created_at": ts,
        "is_encrypted": False,
        "reactions": {},
    }
    quick_replies = _bot_quick_replies(creator_id=bot["creator_id"], bot_id=bot_id)
    if quick_replies:
        item["quick_replies"] = quick_replies

    # Write the message to the Messages table so it surfaces in the conversation.
    _tbl_messages.put_item(Item=item)

    # Update the conversation's last-message metadata (best-effort).
    try:
        _tbl_conversations.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression=(
                "SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid"
            ),
            ExpressionAttributeValues={":ts": ts, ":p": text[:140], ":mid": message_id},
        )
    except ClientError:
        pass  # Non-critical; conversation metadata is best-effort.

    # Increment message count on the bot record (existing behaviour, preserved).
    try:
        T.chat_bots.update_item(
            Key={"pk": f"CREATOR#{bot['creator_id']}", "sk": f"BOT#{bot_id}"},
            UpdateExpression="SET message_count = if_not_exists(message_count, :zero) + :one, updated_at = :ua",
            ExpressionAttributeValues={":zero": 0, ":one": 1, ":ua": ts},
        )
    except ClientError:
        pass  # Non-critical

    return item


def _bot_quick_replies(*, creator_id: str, bot_id: str) -> list | None:
    """Read the bot's configured quick_replies from its raw record (best-effort).

    ``_bot_dict`` drops quick_replies, so fetch the raw item directly.
    """
    try:
        resp = T.chat_bots.get_item(Key={"pk": f"CREATOR#{creator_id}", "sk": f"BOT#{bot_id}"})
    except ClientError:
        return None
    item = resp.get("Item") or {}
    qr = item.get("quick_replies")
    return qr if qr else None


# ---------------------------------------------------------------------------
# Trigger evaluation
# ---------------------------------------------------------------------------

def evaluate_triggers(
    *,
    bot: dict,
    conversation_id: str,
    incoming_message: dict | None = None,
    event_type: str = "message",
) -> str | None:
    """Evaluate trigger rules against incoming message. Returns template_id or None."""
    config = bot.get("trigger_config")
    if not config or not isinstance(config, dict):
        return None

    triggers = config.get("triggers", [])
    priority_order = config.get("priority_order", [])

    # Build lookup map
    trigger_map: Dict[str, list] = {}
    for t in triggers:
        ttype = t.get("type", "")
        trigger_map.setdefault(ttype, []).append(t)

    # Evaluate in priority order
    for ttype in priority_order:
        for t in trigger_map.get(ttype, []):
            if _trigger_matches(t, incoming_message, event_type):
                return t.get("response_template_id")

    # Evaluate remaining triggers not in priority_order
    for t in triggers:
        if t.get("type") not in priority_order:
            if _trigger_matches(t, incoming_message, event_type):
                return t.get("response_template_id")

    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _trigger_matches(trigger: dict, message: dict | None, event_type: str) -> bool:
    ttype = trigger.get("type", "")
    if ttype == "all_messages" and event_type == "message" and message:
        return True
    if ttype == "keyword" and message:
        text = (message.get("text") or "").lower()
        keywords = trigger.get("keywords", [])
        return any(kw.lower() in text for kw in keywords)
    if ttype == "mention" and message:
        text = (message.get("text") or "").lower()
        # check for @botname in text
        return "@" in text
    if ttype == "first_message" and event_type == "first_message":
        return True
    return False


def _query_all_assignments(*, bot_id: str) -> list[dict]:
    resp = T.bot_assignments.query(
        KeyConditionExpression=Key("pk").eq(f"BOT#{bot_id}"),
    )
    return resp.get("Items", [])


def _query_all_auto_reply_rules_raw(*, bot_id: str) -> list[dict]:
    """Query T.chat_bots for all RULE# items for a bot (raw items with pk/sk).

    Used by delete_bot() to cascade-delete auto-reply rules (GAP-0138).
    Pages through LastEvaluatedKey so no rules are missed on busy tables.
    """
    items: list[dict] = []
    kwargs: dict = {
        "KeyConditionExpression": Key("pk").eq(f"BOT#{bot_id}") & Key("sk").begins_with("RULE#"),
    }
    while True:
        resp = T.chat_bots.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def _query_all_scheduled_sends_raw(*, bot_id: str) -> list[dict]:
    """Query T.bot_scheduled_sends for all SCHED# items for a bot (raw pk/sk).

    Used by delete_bot() to cascade-delete scheduled sends (GAP-0138).
    Pages through LastEvaluatedKey so none are missed on busy tables.
    """
    items: list[dict] = []
    kwargs: dict = {
        "KeyConditionExpression": Key("pk").eq(f"BOT#{bot_id}") & Key("sk").begins_with("SCHED#"),
    }
    while True:
        resp = T.bot_scheduled_sends.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def _build_assignment_sk(target_type: str, target_id: str | None) -> str:
    if target_type == "conversation":
        return f"CONV#{target_id}"
    if target_type == "broadcast":
        return f"BCAST#{target_id}"
    if target_type == "all_dms":
        return "SCOPE#ALL_DMS"
    if target_type == "all_groups":
        return "SCOPE#ALL_GROUPS"
    if target_type == "all_broadcasts":
        return "SCOPE#ALL_BROADCASTS"
    return f"SCOPE#{target_type.upper()}"


def _build_assignment_gsi1pk(target_type: str, target_id: str | None) -> str | None:
    if target_type == "conversation" and target_id:
        return f"CONV#{target_id}"
    if target_type == "broadcast" and target_id:
        return f"BCAST#{target_id}"
    # Wildcard scope assignments are stored on GSI1 under a scope bucket so that
    # get_bots_for_conversation() can find them by querying the matching bucket
    # for the conversation kind (GAP-0134). The scope sk is reused as GSI1PK.
    if target_type in ("all_dms", "all_groups", "all_broadcasts"):
        return _build_assignment_sk(target_type, target_id)
    return None


# Maps a conversation kind to the wildcard scope bucket whose assignments apply.
_CONVO_KIND_TO_SCOPE_GSI1PK = {
    "dm": "SCOPE#ALL_DMS",
    "group": "SCOPE#ALL_GROUPS",
    "broadcast": "SCOPE#ALL_BROADCASTS",
}


def _bot_dict(item: dict) -> dict:
    """Convert DDB item to a clean bot dict."""
    return {
        "bot_id": item.get("bot_id", ""),
        "creator_id": item.get("creator_id", ""),
        "name": item.get("name", ""),
        "avatar_url": item.get("avatar_url"),
        "description": item.get("description"),
        "personality": item.get("personality", "friendly"),
        "custom_personality": item.get("custom_personality"),
        "status": item.get("status", "active"),
        "trigger_config": item.get("trigger_config"),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "message_count": int(item.get("message_count", 0)),
    }


def _assignment_dict(item: dict) -> dict:
    """Convert DDB item to a clean assignment dict."""
    return {
        "bot_id": item.get("bot_id", ""),
        "target_type": item.get("target_type", ""),
        "target_id": item.get("target_id"),
        "created_at": int(item.get("created_at", 0)),
        "sk": item.get("sk", ""),
    }


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class BotLimitExceeded(Exception):
    pass

class BotNotFound(Exception):
    pass

class InvalidStatusTransition(Exception):
    pass

class DuplicateAssignment(Exception):
    pass

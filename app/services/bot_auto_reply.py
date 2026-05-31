"""Bot auto-reply rule management and message processing (BOT-003)."""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# In-memory rate-limit cache: {(bot_id, conversation_id): last_reply_ts}
_reply_rate_cache: Dict[tuple, int] = {}
RATE_LIMIT_SECONDS = 60  # max 1 auto-reply per conversation per minute


# ---------------------------------------------------------------------------
# Auto-Reply Rule CRUD
# ---------------------------------------------------------------------------

def create_auto_reply_rule(
    *,
    bot_id: str,
    creator_id: str,
    trigger_pattern: str,
    response_template: str,
    match_type: str = "contains",
    priority: int = 100,
    enabled: bool = True,
) -> dict:
    """Create an auto-reply rule for a bot."""
    rule_id = uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"BOT#{bot_id}",
        "sk": f"RULE#{rule_id}",
        "rule_id": rule_id,
        "bot_id": bot_id,
        "creator_id": creator_id,
        "trigger_pattern": trigger_pattern,
        "response_template": response_template,
        "match_type": match_type,
        "priority": priority,
        "enabled": enabled,
        "created_at": ts,
        "updated_at": ts,
        "match_count": 0,
        "GSI1PK": f"BOT#{bot_id}",
        "GSI1SK": f"RULE#{priority:08d}#{rule_id}",
    }
    T.chat_bots.put_item(Item=item)
    logger.info("Auto-reply rule created: rule_id=%s bot_id=%s match_type=%s", rule_id, bot_id, match_type)
    return _rule_dict(item)


def list_auto_reply_rules(*, bot_id: str) -> list[dict]:
    """List all auto-reply rules for a bot, ordered by priority."""
    resp = T.chat_bots.query(
        KeyConditionExpression=Key("pk").eq(f"BOT#{bot_id}") & Key("sk").begins_with("RULE#"),
    )
    rules = [_rule_dict(item) for item in resp.get("Items", [])]
    rules.sort(key=lambda r: r["priority"])
    return rules


def get_auto_reply_rule(*, bot_id: str, rule_id: str) -> dict | None:
    """Get a single auto-reply rule."""
    resp = T.chat_bots.get_item(Key={"pk": f"BOT#{bot_id}", "sk": f"RULE#{rule_id}"})
    item = resp.get("Item")
    if not item:
        return None
    return _rule_dict(item)


def update_auto_reply_rule(
    *,
    bot_id: str,
    rule_id: str,
    **fields,
) -> dict | None:
    """Update an auto-reply rule. Returns updated dict or None if not found."""
    allowed = {"trigger_pattern", "response_template", "match_type", "priority", "enabled"}
    updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if not updates:
        return get_auto_reply_rule(bot_id=bot_id, rule_id=rule_id)

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

    # Update GSI1SK if priority changed
    if "priority" in updates:
        expr_parts.append("#gsi1sk = :gsi1sk_val")
        attr_names["#gsi1sk"] = "GSI1SK"
        attr_values[":gsi1sk_val"] = f"RULE#{updates['priority']:08d}#{rule_id}"

    try:
        resp = T.chat_bots.update_item(
            Key={"pk": f"BOT#{bot_id}", "sk": f"RULE#{rule_id}"},
            UpdateExpression="SET " + ", ".join(expr_parts),
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
            ConditionExpression="attribute_exists(pk)",
            ReturnValues="ALL_NEW",
        )
        return _rule_dict(resp["Attributes"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return None
        raise


def delete_auto_reply_rule(*, bot_id: str, rule_id: str) -> bool:
    """Delete an auto-reply rule."""
    existing = get_auto_reply_rule(bot_id=bot_id, rule_id=rule_id)
    if not existing:
        return False
    T.chat_bots.delete_item(Key={"pk": f"BOT#{bot_id}", "sk": f"RULE#{rule_id}"})
    logger.info("Auto-reply rule deleted: rule_id=%s bot_id=%s", rule_id, bot_id)
    return True


# ---------------------------------------------------------------------------
# Message matching
# ---------------------------------------------------------------------------

def _matches_pattern(text: str, pattern: str, match_type: str) -> bool:
    """Check if text matches the pattern according to match_type."""
    text_lower = text.lower()
    pattern_lower = pattern.lower()

    if match_type == "exact":
        return text_lower == pattern_lower
    if match_type == "contains":
        return pattern_lower in text_lower
    if match_type == "keyword":
        # Split pattern by comma or whitespace, any keyword match
        keywords = [kw.strip() for kw in re.split(r"[,\s]+", pattern_lower) if kw.strip()]
        return any(kw in text_lower for kw in keywords)
    if match_type == "regex":
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except re.error:
            logger.warning("Invalid regex pattern: %s", pattern)
            return False
    return False


def process_incoming_message(
    *,
    bot_id: str,
    conversation_id: str,
    message_text: str,
) -> dict | None:
    """Match an incoming message against auto-reply rules and return the response if matched.

    Returns dict with matched rule info and response, or None if no match.
    Rate-limited to 1 reply per conversation per minute.
    """
    if not S.bot_auto_reply_enabled:
        return None

    # Rate limit check
    cache_key = (bot_id, conversation_id)
    now = int(time.time())
    last_reply = _reply_rate_cache.get(cache_key, 0)
    if now - last_reply < RATE_LIMIT_SECONDS:
        logger.debug("Rate limited: bot_id=%s conversation_id=%s", bot_id, conversation_id)
        return None

    rules = list_auto_reply_rules(bot_id=bot_id)

    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if _matches_pattern(message_text, rule["trigger_pattern"], rule["match_type"]):
            # Update rate limit cache
            _reply_rate_cache[cache_key] = now

            # Increment match count
            try:
                T.chat_bots.update_item(
                    Key={"pk": f"BOT#{bot_id}", "sk": f"RULE#{rule['rule_id']}"},
                    UpdateExpression="SET match_count = if_not_exists(match_count, :zero) + :one",
                    ExpressionAttributeValues={":zero": 0, ":one": 1},
                )
            except ClientError:
                pass  # Non-critical

            return {
                "matched": True,
                "rule_id": rule["rule_id"],
                "match_type": rule["match_type"],
                "trigger_pattern": rule["trigger_pattern"],
                "response_text": rule["response_template"],
                "priority": rule["priority"],
            }

    return None


def test_message_against_rules(
    *,
    bot_id: str,
    message_text: str,
) -> dict:
    """Test a message against auto-reply rules without sending or rate-limiting.

    Returns match result with all matching rules (not just first).
    """
    rules = list_auto_reply_rules(bot_id=bot_id)
    matches = []

    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if _matches_pattern(message_text, rule["trigger_pattern"], rule["match_type"]):
            matches.append({
                "rule_id": rule["rule_id"],
                "match_type": rule["match_type"],
                "trigger_pattern": rule["trigger_pattern"],
                "response_text": rule["response_template"],
                "priority": rule["priority"],
            })

    if matches:
        return {
            "matched": True,
            "first_match": matches[0],
            "all_matches": matches,
            "match_count": len(matches),
        }
    return {
        "matched": False,
        "first_match": None,
        "all_matches": [],
        "match_count": 0,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _rule_dict(item: dict) -> dict:
    """Convert DDB item to a clean rule dict."""
    return {
        "rule_id": item.get("rule_id", ""),
        "bot_id": item.get("bot_id", ""),
        "creator_id": item.get("creator_id", ""),
        "trigger_pattern": item.get("trigger_pattern", ""),
        "response_template": item.get("response_template", ""),
        "match_type": item.get("match_type", "contains"),
        "priority": int(item.get("priority", 100)),
        "enabled": bool(item.get("enabled", True)),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "match_count": int(item.get("match_count", 0)),
    }


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AutoReplyRuleNotFound(Exception):
    pass

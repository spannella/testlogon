"""Bot template service — CRUD, variable resolution, A/B selection (BOT-002)."""
from __future__ import annotations

import logging
import random
import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

VALID_CATEGORIES = {"greeting", "support", "promotion", "farewell", "away", "custom"}
VALID_BODY_FORMATS = {"plain", "markdown"}
MAX_TEMPLATES_PER_BOT = 50
MAX_QUICK_REPLIES = 5

_VAR_RE = re.compile(r"\{(\w+)\}")

# ---------------------------------------------------------------------------
# Template CRUD
# ---------------------------------------------------------------------------


def create_template(
    *,
    bot_id: str,
    creator_id: str,
    name: str,
    text: str,
    category: str = "custom",
    body_format: str = "plain",
    quick_replies: list[dict] | None = None,
    ab_group: str | None = None,
    ab_weight: int = 1,
) -> dict:
    """Create a message template for a bot."""
    from app.services.chat_bot import get_bot_for_owner, BotNotFound

    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        raise BotNotFound("Bot not found")

    # Count existing templates
    resp = T.bot_templates.query(
        KeyConditionExpression=Key("pk").eq(f"BOT#{bot_id}") & Key("sk").begins_with("TEMPLATE#"),
        Select="COUNT",
    )
    if resp.get("Count", 0) >= MAX_TEMPLATES_PER_BOT:
        raise TemplateLimitExceeded(f"Maximum of {MAX_TEMPLATES_PER_BOT} templates per bot")

    # Validate quick replies
    if quick_replies:
        _validate_quick_replies(quick_replies)

    # Auto-detect variables
    variables_used = sorted(set(_VAR_RE.findall(text)))

    template_id = uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"BOT#{bot_id}",
        "sk": f"TEMPLATE#{template_id}",
        "template_id": template_id,
        "bot_id": bot_id,
        "creator_id": creator_id,
        "name": name,
        "category": category,
        "text": text,
        "body_format": body_format,
        "impression_count": 0,
        "response_count": 0,
        "ab_weight": ab_weight,
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": f"BOT#{bot_id}#CAT#{category}",
        "GSI1SK": ts,
    }
    if quick_replies:
        item["quick_replies"] = quick_replies
    if variables_used:
        item["variables_used"] = set(variables_used)
    if ab_group:
        item["ab_group"] = ab_group

    T.bot_templates.put_item(Item=item)
    logger.info("Template created: template_id=%s bot_id=%s name=%s", template_id, bot_id, name)
    return _template_dict(item)


def get_template(*, bot_id: str, template_id: str) -> dict | None:
    """Fetch a single template."""
    resp = T.bot_templates.get_item(
        Key={"pk": f"BOT#{bot_id}", "sk": f"TEMPLATE#{template_id}"}
    )
    item = resp.get("Item")
    if not item:
        return None
    return _template_dict(item)


def list_templates(*, bot_id: str, category: str | None = None) -> list[dict]:
    """List templates for a bot, optionally filtered by category."""
    if category:
        resp = T.bot_templates.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(f"BOT#{bot_id}#CAT#{category}"),
            ScanIndexForward=False,
        )
    else:
        resp = T.bot_templates.query(
            KeyConditionExpression=(
                Key("pk").eq(f"BOT#{bot_id}") & Key("sk").begins_with("TEMPLATE#")
            ),
        )
    return [_template_dict(item) for item in resp.get("Items", [])]


def update_template(*, bot_id: str, template_id: str, creator_id: str, **fields) -> dict | None:
    """Update template text, name, category, quick_replies, etc."""
    from app.services.chat_bot import get_bot_for_owner

    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        return None

    allowed = {"name", "text", "category", "body_format", "quick_replies", "ab_group", "ab_weight"}
    updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if not updates:
        return get_template(bot_id=bot_id, template_id=template_id)

    if "quick_replies" in updates and updates["quick_replies"]:
        _validate_quick_replies(updates["quick_replies"])

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

    # Update variables_used if text changed
    if "text" in updates:
        variables_used = sorted(set(_VAR_RE.findall(updates["text"])))
        if variables_used:
            expr_parts.append("#vars = :vars_val")
            attr_names["#vars"] = "variables_used"
            attr_values[":vars_val"] = set(variables_used)
        else:
            # Remove variables_used if no variables
            expr_parts.append("#vars = :empty_list")
            attr_names["#vars"] = "variables_used"
            attr_values[":empty_list"] = None

    # Update GSI1 if category changed
    if "category" in updates:
        expr_parts.append("#gsi1pk = :gsi1pk_val")
        attr_names["#gsi1pk"] = "GSI1PK"
        attr_values[":gsi1pk_val"] = f"BOT#{bot_id}#CAT#{updates['category']}"

    expr_parts.append("#ua = :ua_val")
    attr_names["#ua"] = "updated_at"
    attr_values[":ua_val"] = ts

    try:
        resp = T.bot_templates.update_item(
            Key={"pk": f"BOT#{bot_id}", "sk": f"TEMPLATE#{template_id}"},
            UpdateExpression="SET " + ", ".join(expr_parts),
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
            ConditionExpression="attribute_exists(pk)",
            ReturnValues="ALL_NEW",
        )
        return _template_dict(resp["Attributes"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return None
        raise


def delete_template(*, bot_id: str, template_id: str, creator_id: str) -> bool:
    """Delete a template."""
    from app.services.chat_bot import get_bot_for_owner

    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        return False

    existing = get_template(bot_id=bot_id, template_id=template_id)
    if not existing:
        return False

    T.bot_templates.delete_item(
        Key={"pk": f"BOT#{bot_id}", "sk": f"TEMPLATE#{template_id}"}
    )
    logger.info("Template deleted: template_id=%s bot_id=%s", template_id, bot_id)
    return True


# ---------------------------------------------------------------------------
# Variable resolution
# ---------------------------------------------------------------------------

def resolve_variables(template_text: str, context: dict[str, str]) -> tuple[str, list[str]]:
    """Replace {var} placeholders in template_text with values from context.

    Returns (resolved_text, list_of_unresolved_variable_names).
    """
    unresolved: list[str] = []

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        if var_name in context:
            return str(context[var_name])
        unresolved.append(var_name)
        return match.group(0)  # leave as-is

    resolved = _VAR_RE.sub(_replace, template_text)
    return resolved, unresolved


def build_variable_context(
    *,
    template_text: str,
    sender_id: str | None = None,
    creator_id: str | None = None,
    bot: dict | None = None,
    conversation_id: str | None = None,
    sample_overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build the variable context dict, only fetching data for variables present."""
    variables_needed = set(_VAR_RE.findall(template_text))
    ctx: dict[str, str] = {}

    if sample_overrides:
        for k, v in sample_overrides.items():
            ctx[k] = v

    # Only fetch what's needed and not already overridden
    if "user_name" in variables_needed and "user_name" not in ctx and sender_id:
        try:
            profile = T.profile.get_item(Key={"user_sub": sender_id}).get("Item")
            if profile:
                ctx["user_name"] = profile.get("display_name") or profile.get("user_sub", "User")
            else:
                ctx["user_name"] = "User"
        except Exception:
            ctx["user_name"] = "User"

    if "creator_name" in variables_needed and "creator_name" not in ctx and creator_id:
        try:
            profile = T.profile.get_item(Key={"user_sub": creator_id}).get("Item")
            if profile:
                ctx["creator_name"] = profile.get("display_name") or profile.get("user_sub", "Creator")
            else:
                ctx["creator_name"] = "Creator"
        except Exception:
            ctx["creator_name"] = "Creator"

    if "bot_name" in variables_needed and "bot_name" not in ctx and bot:
        ctx["bot_name"] = bot.get("name", "Bot")

    if "current_time" in variables_needed and "current_time" not in ctx:
        from datetime import datetime, timezone
        ctx["current_time"] = datetime.now(timezone.utc).strftime("%H:%M UTC")

    if "current_date" in variables_needed and "current_date" not in ctx:
        from datetime import datetime, timezone
        ctx["current_date"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if "subscriber_status" in variables_needed and "subscriber_status" not in ctx:
        ctx["subscriber_status"] = "none"  # default

    if "conversation_name" in variables_needed and "conversation_name" not in ctx:
        ctx["conversation_name"] = "Conversation"

    return ctx


def render_template(
    *,
    template: dict,
    sender_id: str | None = None,
    creator_id: str | None = None,
    bot: dict | None = None,
    conversation_id: str | None = None,
    sample_overrides: dict[str, str] | None = None,
) -> dict:
    """Resolve variables and return rendered message content."""
    ctx = build_variable_context(
        template_text=template["text"],
        sender_id=sender_id,
        creator_id=creator_id,
        bot=bot,
        conversation_id=conversation_id,
        sample_overrides=sample_overrides,
    )
    rendered_text, unresolved = resolve_variables(template["text"], ctx)
    result: dict = {
        "rendered_text": rendered_text,
        "resolved_variables": ctx,
        "unresolved_variables": unresolved,
    }
    if template.get("quick_replies"):
        result["quick_replies"] = template["quick_replies"]
    return result


# ---------------------------------------------------------------------------
# A/B testing
# ---------------------------------------------------------------------------

def select_ab_template(templates: list[dict]) -> dict:
    """Weighted random selection among A/B group templates."""
    if len(templates) == 1:
        return templates[0]
    weights = [t.get("ab_weight", 1) for t in templates]
    return random.choices(templates, weights=weights, k=1)[0]


def get_templates_for_trigger(*, bot_id: str, trigger: dict) -> list[dict]:
    """Get all templates linked to a trigger, resolving A/B groups."""
    template_id = trigger.get("response_template_id")
    if not template_id:
        return []

    template = get_template(bot_id=bot_id, template_id=template_id)
    if not template:
        return []

    ab_group = template.get("ab_group")
    if not ab_group:
        return [template]

    # Fetch all templates in the same A/B group
    all_templates = list_templates(bot_id=bot_id)
    return [t for t in all_templates if t.get("ab_group") == ab_group]


# ---------------------------------------------------------------------------
# Impression / response tracking
# ---------------------------------------------------------------------------

def record_impression(*, bot_id: str, template_id: str) -> None:
    """Increment impression_count atomically."""
    try:
        T.bot_templates.update_item(
            Key={"pk": f"BOT#{bot_id}", "sk": f"TEMPLATE#{template_id}"},
            UpdateExpression="SET impression_count = if_not_exists(impression_count, :zero) + :one",
            ExpressionAttributeValues={":zero": 0, ":one": 1},
        )
    except ClientError:
        pass  # Non-critical


def record_response(*, bot_id: str, template_id: str) -> None:
    """Increment response_count atomically."""
    try:
        T.bot_templates.update_item(
            Key={"pk": f"BOT#{bot_id}", "sk": f"TEMPLATE#{template_id}"},
            UpdateExpression="SET response_count = if_not_exists(response_count, :zero) + :one",
            ExpressionAttributeValues={":zero": 0, ":one": 1},
        )
    except ClientError:
        pass  # Non-critical


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _validate_quick_replies(quick_replies: list[dict]) -> None:
    if len(quick_replies) > MAX_QUICK_REPLIES:
        raise ValueError(f"Maximum of {MAX_QUICK_REPLIES} quick replies")
    for qr in quick_replies:
        label = qr.get("label", "")
        value = qr.get("value", "")
        if not label or len(label) > 40:
            raise ValueError("Quick reply label must be 1-40 characters")
        if not value or len(value) > 200:
            raise ValueError("Quick reply value must be 1-200 characters")


def _template_dict(item: dict) -> dict:
    """Convert DDB item to a clean template dict."""
    variables_used = item.get("variables_used")
    if isinstance(variables_used, set):
        variables_used = sorted(variables_used)
    elif variables_used is None:
        variables_used = []
    else:
        variables_used = list(variables_used)

    return {
        "template_id": item.get("template_id", ""),
        "bot_id": item.get("bot_id", ""),
        "name": item.get("name", ""),
        "text": item.get("text", ""),
        "category": item.get("category", "custom"),
        "body_format": item.get("body_format", "plain"),
        "quick_replies": item.get("quick_replies"),
        "variables_used": variables_used,
        "ab_group": item.get("ab_group"),
        "ab_weight": int(item.get("ab_weight", 1)),
        "impression_count": int(item.get("impression_count", 0)),
        "response_count": int(item.get("response_count", 0)),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TemplateLimitExceeded(Exception):
    pass

class TemplateNotFound(Exception):
    pass

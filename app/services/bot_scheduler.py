"""Bot scheduler service — scheduled send management + background dispatch (BOT-002)."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

MAX_SCHEDULES_PER_BOT = 20

# ---------------------------------------------------------------------------
# Cron helpers (simple 5-field cron parser)
# ---------------------------------------------------------------------------


def _parse_cron(expression: str) -> dict | None:
    """Parse a 5-field cron expression. Returns parsed dict or None if invalid."""
    parts = expression.strip().split()
    if len(parts) != 5:
        return None
    fields = ["minute", "hour", "day_of_month", "month", "day_of_week"]
    result = {}
    for field, val in zip(fields, parts):
        result[field] = val
    # Reject frequency higher than once per hour
    if parts[0] == "*" and parts[1] == "*":
        return None  # runs every minute — too frequent
    return result


def _next_run_from_cron(cron_expression: str, timezone: str = "UTC") -> int:
    """Calculate next run timestamp from cron expression.

    For simplicity, we compute a rough next-run based on current time + interval.
    A full cron engine (like croniter) would be used in production.
    """
    parsed = _parse_cron(cron_expression)
    if not parsed:
        raise ValueError("Invalid cron expression")

    ts = now_ts()
    # Simple heuristic: next run = now + 3600 (1 hour) minimum
    # This is a simplified implementation; production would use croniter
    return ts + 3600


# ---------------------------------------------------------------------------
# Scheduled Send CRUD
# ---------------------------------------------------------------------------


def create_scheduled_send(
    *,
    bot_id: str,
    creator_id: str,
    template_id: str,
    target_type: str,
    target_id: str | None = None,
    cron_expression: str,
    timezone: str = "UTC",
) -> dict:
    """Create a scheduled send job."""
    from app.services.chat_bot import get_bot_for_owner, BotNotFound
    from app.services.bot_template import get_template

    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        raise BotNotFound("Bot not found")

    # Verify template exists
    template = get_template(bot_id=bot_id, template_id=template_id)
    if not template:
        raise TemplateNotFoundError("Template not found")

    # Validate cron
    parsed = _parse_cron(cron_expression)
    if not parsed:
        raise InvalidCronExpression("Invalid cron expression")

    # Validate timezone
    _validate_timezone(timezone)

    # Count existing schedules
    resp = T.bot_scheduled_sends.query(
        KeyConditionExpression=Key("pk").eq(f"BOT#{bot_id}") & Key("sk").begins_with("SCHED#"),
        Select="COUNT",
    )
    if resp.get("Count", 0) >= MAX_SCHEDULES_PER_BOT:
        raise ScheduleLimitExceeded(f"Maximum of {MAX_SCHEDULES_PER_BOT} scheduled sends per bot")

    schedule_id = uuid4().hex
    ts = now_ts()
    next_run = _next_run_from_cron(cron_expression, timezone)

    item: Dict[str, Any] = {
        "pk": f"BOT#{bot_id}",
        "sk": f"SCHED#{schedule_id}",
        "schedule_id": schedule_id,
        "bot_id": bot_id,
        "creator_id": creator_id,
        "template_id": template_id,
        "target_type": target_type,
        "cron_expression": cron_expression,
        "timezone": timezone,
        "next_run_at": next_run,
        "enabled": True,
        "created_at": ts,
        "GSI1PK": "BOTSCHED#PENDING",
        "GSI1SK": next_run,
    }
    if target_id:
        item["target_id"] = target_id

    T.bot_scheduled_sends.put_item(Item=item)
    logger.info(
        "Scheduled send created: schedule_id=%s bot_id=%s template_id=%s",
        schedule_id, bot_id, template_id,
    )
    return _schedule_dict(item)


def list_scheduled_sends(*, bot_id: str) -> list[dict]:
    """List all scheduled sends for a bot."""
    resp = T.bot_scheduled_sends.query(
        KeyConditionExpression=Key("pk").eq(f"BOT#{bot_id}") & Key("sk").begins_with("SCHED#"),
    )
    return [_schedule_dict(item) for item in resp.get("Items", [])]


def update_scheduled_send(
    *, bot_id: str, schedule_id: str, creator_id: str, **fields
) -> dict | None:
    """Update schedule (cron, timezone, template_id, enabled)."""
    from app.services.chat_bot import get_bot_for_owner

    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        return None

    allowed = {"template_id", "cron_expression", "timezone", "enabled"}
    updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if not updates:
        return _get_schedule(bot_id=bot_id, schedule_id=schedule_id)

    if "cron_expression" in updates:
        parsed = _parse_cron(updates["cron_expression"])
        if not parsed:
            raise InvalidCronExpression("Invalid cron expression")

    if "timezone" in updates:
        _validate_timezone(updates["timezone"])

    expr_parts = []
    attr_names: Dict[str, str] = {}
    attr_values: Dict[str, Any] = {}

    for i, (k, v) in enumerate(updates.items()):
        placeholder = f"#f{i}"
        value_ph = f":v{i}"
        expr_parts.append(f"{placeholder} = {value_ph}")
        attr_names[placeholder] = k
        attr_values[value_ph] = v

    # Recalculate next_run_at if cron changed
    if "cron_expression" in updates:
        tz = updates.get("timezone", "UTC")
        next_run = _next_run_from_cron(updates["cron_expression"], tz)
        expr_parts.append("#nra = :nra_val")
        attr_names["#nra"] = "next_run_at"
        attr_values[":nra_val"] = next_run
        # Update GSI1SK
        expr_parts.append("#gsi1sk = :gsi1sk_val")
        attr_names["#gsi1sk"] = "GSI1SK"
        attr_values[":gsi1sk_val"] = next_run

    # Update GSI1PK based on enabled state
    if "enabled" in updates:
        if updates["enabled"]:
            expr_parts.append("#gsi1pk = :gsi1pk_val")
            attr_names["#gsi1pk"] = "GSI1PK"
            attr_values[":gsi1pk_val"] = "BOTSCHED#PENDING"
        else:
            expr_parts.append("#gsi1pk = :gsi1pk_val")
            attr_names["#gsi1pk"] = "GSI1PK"
            attr_values[":gsi1pk_val"] = "BOTSCHED#DISABLED"

    try:
        resp = T.bot_scheduled_sends.update_item(
            Key={"pk": f"BOT#{bot_id}", "sk": f"SCHED#{schedule_id}"},
            UpdateExpression="SET " + ", ".join(expr_parts),
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
            ConditionExpression="attribute_exists(pk)",
            ReturnValues="ALL_NEW",
        )
        return _schedule_dict(resp["Attributes"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return None
        raise


def delete_scheduled_send(*, bot_id: str, schedule_id: str, creator_id: str) -> bool:
    """Delete a scheduled send."""
    from app.services.chat_bot import get_bot_for_owner

    bot = get_bot_for_owner(creator_id=creator_id, bot_id=bot_id)
    if not bot:
        return False

    existing = _get_schedule(bot_id=bot_id, schedule_id=schedule_id)
    if not existing:
        return False

    T.bot_scheduled_sends.delete_item(
        Key={"pk": f"BOT#{bot_id}", "sk": f"SCHED#{schedule_id}"}
    )
    logger.info("Scheduled send deleted: schedule_id=%s bot_id=%s", schedule_id, bot_id)
    return True


# ---------------------------------------------------------------------------
# Background dispatch
# ---------------------------------------------------------------------------


def dispatch_due_scheduled_sends(*, now_ts_value: int | None = None, limit: int = 50) -> dict[str, int]:
    """Background worker: query GSI1 for due sends, execute each."""
    from app.services.chat_bot import get_bot, send_bot_message
    from app.services.bot_template import get_template, render_template, record_impression

    current_ts = now_ts_value or now_ts()
    dispatched = 0
    failed = 0

    try:
        resp = T.bot_scheduled_sends.query(
            IndexName="GSI1",
            KeyConditionExpression=(
                Key("GSI1PK").eq("BOTSCHED#PENDING") & Key("GSI1SK").lte(current_ts)
            ),
            Limit=limit,
        )
    except ClientError as exc:
        logger.exception("bot_scheduler: GSI1 query failed")
        return {"dispatched": 0, "failed": 0}

    items = resp.get("Items", [])
    for item in items:
        try:
            sched = _schedule_dict(item)
            bot = get_bot(bot_id=sched["bot_id"])
            if not bot or bot["status"] != "active":
                continue

            template = get_template(bot_id=sched["bot_id"], template_id=sched["template_id"])
            if not template:
                continue

            rendered = render_template(
                template=template,
                creator_id=bot.get("creator_id"),
                bot=bot,
            )

            # Send bot message (for single conversation target)
            if sched["target_type"] == "conversation" and sched.get("target_id"):
                send_bot_message(
                    bot_id=sched["bot_id"],
                    conversation_id=sched["target_id"],
                    text=rendered["rendered_text"],
                )
                record_impression(bot_id=sched["bot_id"], template_id=sched["template_id"])

            # Update last_run_at and calculate next next_run_at
            next_run = _next_run_from_cron(sched["cron_expression"], sched.get("timezone", "UTC"))
            T.bot_scheduled_sends.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET last_run_at = :lra, next_run_at = :nra, GSI1SK = :nra",
                ExpressionAttributeValues={
                    ":lra": current_ts,
                    ":nra": next_run,
                },
            )
            dispatched += 1
        except Exception:
            logger.exception("bot_scheduler: failed to dispatch schedule_id=%s", item.get("schedule_id"))
            failed += 1

    return {"dispatched": dispatched, "failed": failed}


async def run_bot_scheduler_loop() -> None:
    """Background async loop, runs every 60 seconds."""
    while True:
        try:
            dispatch_due_scheduled_sends()
        except Exception:
            logger.exception("bot_scheduler: dispatch error")
        await asyncio.sleep(60)


def start_bot_scheduler_task() -> None:
    """Called from main.py startup to launch background scheduler."""
    if not S.bot_scheduled_messages_enabled:
        logger.info("bot_scheduler: disabled by BOT_SCHEDULED_MESSAGES_ENABLED")
        return
    asyncio.create_task(run_bot_scheduler_loop())
    logger.info("bot_scheduler: background loop started")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_schedule(*, bot_id: str, schedule_id: str) -> dict | None:
    resp = T.bot_scheduled_sends.get_item(
        Key={"pk": f"BOT#{bot_id}", "sk": f"SCHED#{schedule_id}"}
    )
    item = resp.get("Item")
    if not item:
        return None
    return _schedule_dict(item)


def _validate_timezone(timezone: str) -> None:
    """Validate IANA timezone string."""
    # Accept common timezones without requiring pytz
    valid_prefixes = (
        "UTC", "US/", "America/", "Europe/", "Asia/", "Africa/", "Australia/",
        "Pacific/", "Atlantic/", "Indian/", "Etc/",
    )
    if timezone == "UTC" or any(timezone.startswith(p) for p in valid_prefixes):
        return
    raise InvalidTimezone(f"Invalid timezone: {timezone}")


def _schedule_dict(item: dict) -> dict:
    """Convert DDB item to a clean schedule dict."""
    return {
        "schedule_id": item.get("schedule_id", ""),
        "bot_id": item.get("bot_id", ""),
        "creator_id": item.get("creator_id", ""),
        "template_id": item.get("template_id", ""),
        "target_type": item.get("target_type", ""),
        "target_id": item.get("target_id"),
        "cron_expression": item.get("cron_expression", ""),
        "timezone": item.get("timezone", "UTC"),
        "next_run_at": int(item.get("next_run_at", 0)),
        "last_run_at": int(item["last_run_at"]) if item.get("last_run_at") is not None else None,
        "enabled": bool(item.get("enabled", True)),
        "created_at": int(item.get("created_at", 0)),
    }


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TemplateNotFoundError(Exception):
    pass

class InvalidCronExpression(Exception):
    pass

class InvalidTimezone(Exception):
    pass

class ScheduleLimitExceeded(Exception):
    pass

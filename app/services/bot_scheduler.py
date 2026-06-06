"""Bot scheduler service — scheduled send management + background dispatch (BOT-002)."""
from __future__ import annotations

import asyncio
import datetime
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

# Maximum number of conversations a single wildcard scheduled send may fan out to.
WILDCARD_SCOPE_LIMIT = 500

# ---------------------------------------------------------------------------
# Cron helpers (simple 5-field cron parser)
# ---------------------------------------------------------------------------


# Inclusive (min, max) range for each of the 5 standard cron fields, in order:
# minute, hour, day_of_month, month, day_of_week.
_CRON_FIELD_BOUNDS = (
    (0, 59),   # minute
    (0, 23),   # hour
    (1, 31),   # day of month
    (1, 12),   # month
    (0, 6),    # day of week (0 = Sunday)
)
_CRON_FIELD_NAMES = ("minute", "hour", "day_of_month", "month", "day_of_week")


def _expand_cron_field(spec: str, lo: int, hi: int) -> set[int] | None:
    """Expand a single cron field into the set of integers it matches.

    Supports ``*``, ``*/step``, ``a-b``, ``a-b/step``, single values, and
    comma-separated lists of any of these. Returns ``None`` if invalid.
    """
    values: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            return None
        step = 1
        if "/" in part:
            base, _, step_str = part.partition("/")
            if not step_str.isdigit() or int(step_str) <= 0:
                return None
            step = int(step_str)
        else:
            base = part
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            start_str, _, end_str = base.partition("-")
            if not (start_str.isdigit() and end_str.isdigit()):
                return None
            start, end = int(start_str), int(end_str)
        else:
            if not base.isdigit():
                return None
            start = end = int(base)
        if start < lo or end > hi or start > end:
            return None
        values.update(range(start, end + 1, step))
    return values or None


def _parse_cron(expression: str) -> dict | None:
    """Parse a 5-field cron expression into matched value sets.

    Returns a dict mapping each field name to a ``set[int]`` of matching values,
    or ``None`` if the expression is invalid. Frequencies higher than once per
    hour (every-minute schedules) are rejected to bound dispatch volume.
    """
    parts = expression.strip().split()
    if len(parts) != 5:
        return None

    # Reject frequency higher than once per hour (e.g. "* * * * *").
    if parts[0] == "*" and parts[1] == "*":
        return None

    result: dict[str, set[int]] = {}
    for name, raw, (lo, hi) in zip(_CRON_FIELD_NAMES, parts, _CRON_FIELD_BOUNDS):
        expanded = _expand_cron_field(raw, lo, hi)
        if expanded is None:
            return None
        result[name] = expanded
    return result


def _next_run_from_cron(cron_expression: str, timezone: str = "UTC") -> int:
    """Return the next Unix timestamp (integer seconds) at which the cron fires.

    Computes the next occurrence of a standard 5-field cron expression
    (minute hour day-of-month month day-of-week) strictly after the current
    time, evaluated in the supplied IANA timezone. The result is returned as a
    UTC Unix timestamp. Self-contained — no external cron library required.

    Args:
        cron_expression: Standard 5-field cron, e.g. ``"0 14 * * *"``.
        timezone: IANA timezone name (default ``"UTC"``).

    Raises:
        ValueError: If the cron expression or timezone is invalid, or no match
            is found within a one-year search horizon.
    """
    parsed = _parse_cron(cron_expression)
    if not parsed:
        raise ValueError(f"Invalid cron expression: {cron_expression!r}")

    try:
        import zoneinfo

        tz: datetime.tzinfo = zoneinfo.ZoneInfo(timezone)
    except Exception as exc:  # noqa: BLE001 — fall back / re-raise as ValueError
        if timezone == "UTC":
            tz = datetime.timezone.utc
        else:
            raise ValueError(f"Unknown timezone: {timezone!r}") from exc

    # Base the search on the current wall-clock time, expressed in the target tz.
    base_utc = datetime.datetime.fromtimestamp(now_ts(), tz=datetime.timezone.utc)
    candidate = base_utc.astimezone(tz)

    # Start strictly after "now": advance to the next whole minute boundary.
    candidate = candidate.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)

    minutes = parsed["minute"]
    hours = parsed["hour"]
    doms = parsed["day_of_month"]
    months = parsed["month"]
    dows = parsed["day_of_week"]

    # Standard cron day matching: if BOTH day-of-month and day-of-week are
    # restricted (not "*"), a day matches if it satisfies EITHER field.
    dom_restricted = doms != set(range(1, 32))
    dow_restricted = dows != set(range(0, 7))

    # Search up to one year ahead, one minute at a time. A year of minutes is the
    # safe upper bound for any valid 5-field cron expression.
    limit = 366 * 24 * 60
    for _ in range(limit):
        if (
            candidate.month in months
            and candidate.hour in hours
            and candidate.minute in minutes
        ):
            # cron day-of-week: Sunday = 0; Python weekday(): Monday = 0.
            cron_dow = (candidate.weekday() + 1) % 7
            dom_ok = candidate.day in doms
            dow_ok = cron_dow in dows
            if dom_restricted and dow_restricted:
                day_ok = dom_ok or dow_ok
            elif dom_restricted:
                day_ok = dom_ok
            elif dow_restricted:
                day_ok = dow_ok
            else:
                day_ok = True
            if day_ok:
                return int(candidate.astimezone(datetime.timezone.utc).timestamp())
        candidate += datetime.timedelta(minutes=1)

    raise ValueError(
        f"No cron occurrence found within one year for: {cron_expression!r}"
    )


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

            # Resolve target conversation IDs (handles single + wildcard scopes).
            target_conv_ids = _resolve_target_conversations(sched, bot=bot)
            sent_count = 0
            if not target_conv_ids:
                logger.warning(
                    "bot_scheduler: no target conversations resolved for "
                    "schedule_id=%s target_type=%s — skipping send",
                    sched.get("schedule_id"), sched["target_type"],
                )
            else:
                for conv_id in target_conv_ids[:WILDCARD_SCOPE_LIMIT]:
                    send_bot_message(
                        bot_id=sched["bot_id"],
                        conversation_id=conv_id,
                        text=rendered["rendered_text"],
                    )
                    sent_count += 1
                record_impression(bot_id=sched["bot_id"], template_id=sched["template_id"])
                logger.info(
                    "bot_scheduler: dispatched schedule_id=%s target_type=%s conv_count=%d",
                    sched.get("schedule_id"), sched["target_type"], sent_count,
                )

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
            # Only count schedules that actually delivered at least one message.
            if sent_count > 0:
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


async def start_bot_scheduler_task() -> None:
    """Called from main.py startup to launch background scheduler.

    Must be ``async`` so that ``asyncio.create_task()`` is always invoked from
    within a running event loop. Starlette's startup machinery awaits async
    handlers (``is_async_callable()`` returns ``True`` for coroutine functions),
    guaranteeing a running loop. Keeping this synchronous would raise
    ``RuntimeError: no running event loop`` when the function is called from a
    sync/CLI/alternative-server context (GAP-0137). No change to the
    registration in ``app/main.py`` is required.
    """
    if not S.bot_scheduled_messages_enabled:
        logger.info("bot_scheduler: disabled by BOT_SCHEDULED_MESSAGES_ENABLED")
        return
    asyncio.create_task(run_bot_scheduler_loop())
    logger.info("bot_scheduler: background loop started")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


# Maps a wildcard target_type to the conversation `type` value it fans out to.
_WILDCARD_TARGET_TO_CONV_TYPE = {
    "all_dms": "dm",
    "all_groups": "group",
    "all_broadcasts": "broadcast",
}


def _resolve_target_conversations(sched: dict, *, bot: dict | None = None) -> list[str]:
    """Resolve a scheduled send's target into a list of conversation IDs.

    - ``target_type="conversation"`` with a ``target_id`` resolves to that single
      conversation.
    - Wildcard scopes (``all_dms``, ``all_groups``, ``all_broadcasts``) fan out to
      every matching conversation the bot's creator participates in, capped at
      ``WILDCARD_SCOPE_LIMIT``.

    Returns an empty list for unknown target types or when no conversations match.
    """
    target_type = sched.get("target_type", "")
    target_id = sched.get("target_id")

    if target_type == "conversation":
        return [target_id] if target_id else []

    conv_type = _WILDCARD_TARGET_TO_CONV_TYPE.get(target_type)
    if conv_type is None:
        logger.warning(
            "bot_scheduler: unknown target_type=%s schedule_id=%s",
            target_type, sched.get("schedule_id"),
        )
        return []

    if bot is None:
        from app.services.chat_bot import get_bot

        bot = get_bot(bot_id=sched["bot_id"])
    creator_id = (bot or {}).get("creator_id") or sched.get("creator_id")
    if not creator_id:
        return []

    # Conversations are stored in the messaging tables: a Participants table keyed
    # on user_id lists every conversation a user belongs to; the Conversations
    # table carries the `type` field. Resolve the creator's matching conversations.
    from app.core.aws import ddb
    import os as _os

    parts_table = ddb.Table(_os.getenv("DDB_PARTICIPANTS", "Participants"))
    convos_table = ddb.Table(_os.getenv("DDB_CONVERSATIONS", "Conversations"))

    conv_ids: list[str] = []
    last_key = None
    try:
        while len(conv_ids) < WILDCARD_SCOPE_LIMIT:
            kwargs: dict = {
                "KeyConditionExpression": Key("user_id").eq(creator_id),
                "Limit": 500,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = parts_table.query(**kwargs)
            for p in resp.get("Items", []):
                cid = p.get("conversation_id")
                if cid:
                    conv_ids.append(cid)
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    except Exception:
        logger.exception(
            "bot_scheduler: failed to list participant conversations for creator_id=%s",
            creator_id,
        )
        return []

    matched: list[str] = []
    for cid in conv_ids:
        if len(matched) >= WILDCARD_SCOPE_LIMIT:
            break
        try:
            convo = convos_table.get_item(Key={"conversation_id": cid}).get("Item")
        except Exception:
            continue
        if convo and convo.get("type") == conv_type:
            matched.append(cid)
    return matched


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

"""Ad scheduling and dayparting service (ADS-016).

Handles dayparting eligibility checks, flight resolution, dayparting-aware
budget pacing, and schedule persistence on the campaign record.

The schedule is stored directly on the existing campaign record in the
``ad_campaigns`` table (no separate table is required) under the fields
``dayparting``, ``flights`` and ``campaign_timezone``.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

VALID_DAYS = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
]
VALID_HOURS = list(range(24))  # 0-23

# Predefined schedule templates
SCHEDULE_TEMPLATES: Dict[str, Dict[str, List[int]]] = {
    "always": {day: list(range(24)) for day in VALID_DAYS},
    "weekdays_business": {
        **{day: list(range(9, 18)) for day in VALID_DAYS[:5]},
        "saturday": [],
        "sunday": [],
    },
    "evenings": {day: list(range(18, 24)) for day in VALID_DAYS},
    "weekends": {
        **{day: [] for day in VALID_DAYS[:5]},
        "saturday": list(range(24)),
        "sunday": list(range(24)),
    },
}


# ── Time helpers ─────────────────────────────────────────────────────


def _resolve_now(now: Optional[int], tz: timezone | ZoneInfo) -> datetime:
    """Build a tz-aware datetime from an optional Unix timestamp.

    Falls back to the real wall-clock when ``now`` is None. Accepting an
    injectable ``now`` keeps eligibility checks deterministic for tests.
    """
    if now is None:
        return datetime.now(tz)
    return datetime.fromtimestamp(int(now), tz=timezone.utc).astimezone(tz)


def _zone(tz_str: str) -> Optional[ZoneInfo]:
    try:
        return ZoneInfo(tz_str)
    except (ZoneInfoNotFoundError, KeyError, ValueError):
        return None


# ── Validation ───────────────────────────────────────────────────────


def validate_dayparting_config(
    config: Optional[Dict[str, Any]],
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Validate dayparting configuration.

    Returns ``(error_message, None)`` on failure or ``(None, sanitized_config)``
    on success. A ``None``/empty input clears dayparting (``(None, None)``).
    """
    if not config:
        return None, None

    tz_str = config.get("timezone", "UTC") or "UTC"
    if _zone(tz_str) is None:
        return f"Invalid timezone: {tz_str}", None

    schedule = config.get("schedule", {})
    if not isinstance(schedule, dict):
        return "schedule must be a dict", None

    sanitized_schedule: Dict[str, List[int]] = {}
    for day in VALID_DAYS:
        hours = schedule.get(day, [])
        if not isinstance(hours, list):
            return f"{day} must be a list of hours", None
        valid_hours = sorted(
            {h for h in hours if isinstance(h, int) and 0 <= h <= 23}
        )
        sanitized_schedule[day] = valid_hours

    total_active = sum(len(h) for h in sanitized_schedule.values())
    if total_active == 0:
        return "Schedule must have at least one active hour", None

    return None, {"timezone": tz_str, "schedule": sanitized_schedule}


def _to_date_str(value: Any) -> Optional[str]:
    """Normalize a campaign bound to a ``YYYY-MM-DD`` string for comparison.

    Campaign ``start_date`` / ``end_date`` are persisted as Unix timestamp
    integers (stored as ``Decimal`` in DynamoDB), whereas flight dates are
    ``YYYY-MM-DD`` strings. Comparing the two directly raises ``TypeError``,
    so coerce the campaign bound to a date string here.
    """
    if value is None or value == "":
        return None
    # Numeric (int / float / Decimal) → treat as a Unix timestamp.
    if isinstance(value, (int, float)) or (
        hasattr(value, "__int__") and not isinstance(value, str)
    ):
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime(
                "%Y-%m-%d"
            )
        except (ValueError, OSError, OverflowError):
            return None
    text = str(value).strip()
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), tz=timezone.utc).strftime(
                "%Y-%m-%d"
            )
        except (ValueError, OSError, OverflowError):
            return None
    # Already a date-ish string — keep the leading YYYY-MM-DD portion.
    return text[:10]


def validate_flights(
    flights: Optional[List[Dict[str, Any]]],
    campaign_start: Optional[str],
    campaign_end: Optional[str],
) -> Tuple[Optional[str], Optional[List[Dict[str, Any]]]]:
    """Validate flight schedule.

    Rules:
    - Flights must be within the campaign start/end dates (when provided).
    - Flights must not overlap.
    - Each flight must have a positive ``daily_budget_cents`` (>= 100).
    - Each flight must have at least one ``creative_id``.
    """
    if not flights:
        return None, None

    # Campaign bounds are stored as Unix timestamps; flight dates are
    # YYYY-MM-DD strings. Normalize the bounds so comparisons don't raise.
    campaign_start = _to_date_str(campaign_start)
    campaign_end = _to_date_str(campaign_end)

    sanitized: List[Dict[str, Any]] = []
    for i, flight in enumerate(flights):
        f_start = flight.get("start_date", "")
        f_end = flight.get("end_date", "")
        if not f_start or not f_end:
            return f"Flight {i}: start_date and end_date required", None
        if f_start > f_end:
            return f"Flight {i}: start_date must be before end_date", None
        if campaign_start and f_start < campaign_start:
            return f"Flight {i}: dates must be within campaign range", None
        if campaign_end and f_end > campaign_end:
            return f"Flight {i}: dates must be within campaign range", None

        budget = flight.get("daily_budget_cents", 0)
        if not isinstance(budget, int) or budget < 100:
            return f"Flight {i}: daily_budget_cents must be >= 100", None

        creative_ids = flight.get("creative_ids", [])
        if not creative_ids:
            return f"Flight {i}: at least one creative_id required", None

        sanitized.append(
            {
                "flight_id": flight.get("flight_id") or f"fl_{uuid.uuid4().hex[:8]}",
                "name": flight.get("name", f"Flight {i + 1}"),
                "start_date": f_start,
                "end_date": f_end,
                "daily_budget_cents": budget,
                "creative_ids": list(creative_ids),
                # A flight's status defaults to "scheduled". The request model
                # carries ``status: Optional[str] = None``, so ``.get`` returns
                # an explicit ``None`` (not the default) — coalesce it here.
                "status": flight.get("status") or "scheduled",
            }
        )

    # Check for overlaps (sorted by start date).
    sorted_flights = sorted(sanitized, key=lambda f: f["start_date"])
    for i in range(len(sorted_flights) - 1):
        if sorted_flights[i]["end_date"] >= sorted_flights[i + 1]["start_date"]:
            return (
                f"Flights overlap: {sorted_flights[i]['name']} and "
                f"{sorted_flights[i + 1]['name']}",
                None,
            )

    return None, sanitized


# ── Eligibility / flight resolution ──────────────────────────────────


def is_campaign_eligible_now(
    *,
    dayparting: Optional[Dict[str, Any]],
    campaign_timezone: str = "UTC",
    now: Optional[int] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Check whether the campaign may serve right now based on dayparting.

    ``now`` is an optional Unix timestamp for deterministic evaluation.
    Returns ``(eligible, debug_info)``.
    """
    if not dayparting:
        return True, {"reason": "no_dayparting", "eligible": True}

    tz_str = dayparting.get("timezone", campaign_timezone) or "UTC"
    tz = _zone(tz_str)
    if tz is None:
        # Invalid timezone — fail open (serve), but flag it.
        return True, {"reason": "invalid_timezone", "eligible": True}

    now_local = _resolve_now(now, tz)
    day_name = now_local.strftime("%A").lower()
    hour = now_local.hour

    schedule = dayparting.get("schedule", {})
    active_hours = schedule.get(day_name, [])

    eligible = hour in active_hours
    return eligible, {
        "timezone": tz_str,
        "local_time": now_local.isoformat(),
        "day": day_name,
        "hour": hour,
        "active_hours": list(active_hours),
        "eligible": eligible,
    }


def get_active_flight(
    *,
    flights: Optional[List[Dict[str, Any]]],
    now: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Determine which flight is active based on the current date.

    Returns the active flight dict or ``None`` (no flights / a gap between
    flights → use campaign defaults).
    """
    if not flights:
        return None

    today = _resolve_now(now, timezone.utc).strftime("%Y-%m-%d")
    for flight in flights:
        if flight.get("start_date", "") <= today <= flight.get("end_date", ""):
            return flight
    return None


def calculate_dayparted_budget(
    *,
    daily_budget_cents: int,
    dayparting: Optional[Dict[str, Any]],
    campaign_timezone: str = "UTC",
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Calculate budget pacing for dayparted campaigns.

    When ads only run a subset of hours, the hourly budget is the daily budget
    divided by the number of *active* hours (not 24).
    """
    daily_budget_cents = int(daily_budget_cents or 0)

    if not dayparting:
        current_hour = _resolve_now(now, timezone.utc).hour
        return {
            "active_hours_today": 24,
            "hours_remaining": 24 - current_hour,
            "hourly_budget_cents": daily_budget_cents // 24,
            "remaining_budget_cents": daily_budget_cents,
        }

    tz_str = dayparting.get("timezone", campaign_timezone) or "UTC"
    tz = _zone(tz_str) or timezone.utc

    now_local = _resolve_now(now, tz)
    day_name = now_local.strftime("%A").lower()
    current_hour = now_local.hour

    schedule = dayparting.get("schedule", {})
    active_hours = schedule.get(day_name, [])

    if not active_hours:
        return {
            "active_hours_today": 0,
            "hours_remaining": 0,
            "hourly_budget_cents": 0,
            "remaining_budget_cents": 0,
        }

    total_active = len(active_hours)
    hours_remaining = len([h for h in active_hours if h >= current_hour])

    hourly_budget = daily_budget_cents // total_active if total_active > 0 else 0
    remaining_budget = hourly_budget * hours_remaining

    return {
        "active_hours_today": total_active,
        "hours_remaining": hours_remaining,
        "hourly_budget_cents": hourly_budget,
        "remaining_budget_cents": remaining_budget,
    }


# ── Persistence (on the campaign record) ─────────────────────────────


def _campaign_by_id(campaign_id: str) -> Optional[dict]:
    resp = T.ad_campaigns.query(
        IndexName="ByCampaignId",
        KeyConditionExpression=Key("campaign_id").eq(campaign_id),
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def get_campaign_schedule(campaign: dict) -> Dict[str, Any]:
    """Extract the schedule view from a campaign record."""
    return {
        "campaign_id": campaign.get("campaign_id"),
        "campaign_timezone": campaign.get("campaign_timezone", "UTC"),
        "dayparting": campaign.get("dayparting"),
        "flights": campaign.get("flights"),
        "start_date": campaign.get("start_date"),
        "end_date": campaign.get("end_date"),
    }


def update_campaign_schedule(
    *,
    account_id: str,
    campaign_id: str,
    dayparting: Optional[Dict[str, Any]] = None,
    flights: Optional[List[Dict[str, Any]]] = None,
    campaign_timezone: Optional[str] = None,
    set_dayparting: bool = False,
    set_flights: bool = False,
    campaign: Optional[dict] = None,
) -> Dict[str, Any]:
    """Validate and persist dayparting / flight / timezone on the campaign.

    ``set_dayparting`` / ``set_flights`` indicate whether the caller included
    that field at all (so an explicit ``null`` can clear it without being
    confused with "unchanged").

    Raises ``ValueError`` on validation failure.
    """
    camp = campaign or get_campaign(account_id, campaign_id)
    if not camp:
        raise ValueError("Campaign not found")

    sets: Dict[str, Any] = {"updated_at": now_ts()}

    if campaign_timezone is not None:
        if _zone(campaign_timezone) is None:
            raise ValueError(f"Invalid timezone: {campaign_timezone}")
        sets["campaign_timezone"] = campaign_timezone

    if set_dayparting:
        err, sanitized = validate_dayparting_config(dayparting)
        if err:
            raise ValueError(err)
        sets["dayparting"] = sanitized

    if set_flights:
        err, sanitized_flights = validate_flights(
            flights, camp.get("start_date"), camp.get("end_date")
        )
        if err:
            raise ValueError(err)
        sets["flights"] = sanitized_flights

    expr_parts: List[str] = []
    attr_names: Dict[str, str] = {}
    attr_values: Dict[str, Any] = {}
    for i, (k, v) in enumerate(sets.items()):
        alias = f"#f{i}"
        val_alias = f":v{i}"
        attr_names[alias] = k
        attr_values[val_alias] = v
        expr_parts.append(f"{alias} = {val_alias}")

    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=attr_names,
        ExpressionAttributeValues=attr_values,
    )

    updated = get_campaign(account_id, campaign_id) or camp
    return get_campaign_schedule(updated)


# Local import to avoid a circular import at module load time.
def get_campaign(account_id: str, campaign_id: str) -> Optional[dict]:
    from app.services.ad_campaigns import get_campaign as _get

    return _get(account_id, campaign_id)

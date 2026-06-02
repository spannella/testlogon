"""Find-a-DateTime (MSG-009) business logic.

A group availability finder embedded as a messaging kind (``find_datetime``).
Unlike meeting polls (which present a fixed set of slot options to vote on),
Find-a-DateTime lets participants mark available time ranges on a continuous
grid; the best overlapping windows are then computed deterministically.

Storage reuses the single-table ``calendar`` DDB table (same pattern as meeting
polls), keyed by ``calendar_id = FADT#{poll_id}``:

    PK: FADT#{poll_id}  SK: META               -> poll metadata
                        SK: AVAIL#{user_sub}    -> a participant's submitted slots
                        SK: RESULT              -> computed best windows

The overlap computation (``compute_best_windows``) is pure and unit-testable: it
takes a list of availability submissions plus the slot duration and returns the
ranked best overlapping windows. FEED-003 may reuse this module's grid helpers.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Set

VALID_SLOT_DURATIONS = (15, 30, 60)
_SLOT_FMT = "%Y-%m-%dT%H:%M"


def parse_date(value: str) -> date:
    """Parse an ISO ``YYYY-MM-DD`` date string."""
    return datetime.strptime(value, "%Y-%m-%d").date()


def slot_key(d: date, hour: int, minute: int) -> str:
    """Build a canonical slot key (ISO datetime at grid granularity)."""
    return f"{d.isoformat()}T{hour:02d}:{minute:02d}"


def enumerate_slots(
    *,
    from_date: str,
    to_date: str,
    start_hour: int,
    end_hour: int,
    slot_duration_minutes: int,
) -> List[str]:
    """Return every valid slot key for the poll's date range + daily window.

    The daily window runs ``[start_hour, end_hour)`` so a slot's start time is
    always strictly before ``end_hour``. Date range is inclusive of both ends.
    """
    d0 = parse_date(from_date)
    d1 = parse_date(to_date)
    keys: List[str] = []
    day = d0
    while day <= d1:
        minute_of_day = start_hour * 60
        end_minute = end_hour * 60
        while minute_of_day < end_minute:
            keys.append(slot_key(day, minute_of_day // 60, minute_of_day % 60))
            minute_of_day += slot_duration_minutes
        day = day + timedelta(days=1)
    return keys


def _add_minutes(slot: str, minutes: int) -> str:
    dt = datetime.strptime(slot, _SLOT_FMT) + timedelta(minutes=minutes)
    return dt.strftime(_SLOT_FMT)


def _is_contiguous(prev_slot: str, next_slot: str, slot_duration_minutes: int) -> bool:
    """True when ``next_slot`` immediately follows ``prev_slot`` on the same day."""
    try:
        prev_dt = datetime.strptime(prev_slot, _SLOT_FMT)
        next_dt = datetime.strptime(next_slot, _SLOT_FMT)
    except ValueError:
        return False
    if prev_dt.date() != next_dt.date():
        return False
    return next_dt - prev_dt == timedelta(minutes=slot_duration_minutes)


def compute_best_windows(
    availabilities: List[Dict[str, Any]],
    slot_duration_minutes: int,
    *,
    min_count: int = 1,
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """Compute ranked overlapping availability windows.

    Args:
        availabilities: list of ``{"user_sub", "user_name", "slots": [str]}``.
        slot_duration_minutes: grid granularity (15/30/60).
        min_count: minimum overlap count for a window to be reported. When at
            least 2 participants exist this is raised to 2 so windows reflect a
            real overlap; with a single participant their own ranges are returned.
        top_n: maximum number of windows to return.

    Returns:
        Ranked list of ``{start, end, count, participants}`` where ``end`` is the
        exclusive end of the window (start of the next slot after the run).
        Ranking: count desc, then run length desc, then earliest start asc.

    The algorithm:
        1. Build ``slot -> set(user_sub)`` from all submissions.
        2. Group contiguous slots that share an *identical* overlap set into
           runs (so a window has a single, stable participant set + count).
        3. Emit one window per run with its participant display names.
    """
    # 1. slot -> set of participants available
    slot_users: Dict[str, Set[str]] = {}
    name_by_sub: Dict[str, str] = {}
    for av in availabilities:
        sub = av.get("user_sub")
        if not sub:
            continue
        name_by_sub[sub] = av.get("user_name") or sub
        for s in av.get("slots") or []:
            slot_users.setdefault(str(s), set()).add(sub)

    if not slot_users:
        return []

    effective_min = min_count
    if len(name_by_sub) >= 2:
        effective_min = max(min_count, 2)

    ordered_slots = sorted(slot_users.keys())

    windows: List[Dict[str, Any]] = []
    run_start: Optional[str] = None
    run_end: Optional[str] = None
    run_users: Optional[Set[str]] = None
    run_len = 0

    def _flush() -> None:
        nonlocal run_start, run_end, run_users, run_len
        if run_start is None or run_users is None:
            return
        count = len(run_users)
        if count >= effective_min and run_end is not None:
            participants = sorted(
                name_by_sub.get(u, u) for u in run_users
            )
            windows.append({
                "start": run_start,
                "end": _add_minutes(run_end, slot_duration_minutes),
                "count": count,
                "participants": participants,
                "_run_len": run_len,
            })
        run_start = run_end = run_users = None
        run_len = 0

    for slot in ordered_slots:
        users = slot_users[slot]
        if (
            run_users is not None
            and run_end is not None
            and users == run_users
            and _is_contiguous(run_end, slot, slot_duration_minutes)
        ):
            run_end = slot
            run_len += 1
        else:
            _flush()
            run_start = slot
            run_end = slot
            run_users = set(users)
            run_len = 1
    _flush()

    windows.sort(key=lambda w: (-w["count"], -w["_run_len"], w["start"]))
    for w in windows:
        w.pop("_run_len", None)
    return windows[:top_n]

# ADS-016: Ad Scheduling & Dayparting

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 6-8 days  
**Dependencies**: ADS-001 (campaign manager), ADS-004 (ad serving engine), ADS-007 (ad billing) — all sibling tickets, not yet implemented
<!-- NOTE: All ADS dependencies are sibling tickets not yet in the codebase. -->

---

## 1. Overview & Motivation

### The Gap

Ad campaigns (ADS-001) have `start_date` and `end_date` fields for broad scheduling, but offer no control over which hours of the day or days of the week ads run. This is a critical missing feature called "dayparting" — the ability to schedule ads for specific time slots when the target audience is most active.

Consider a restaurant chain advertising lunch specials: they want ads to run between 10 AM and 2 PM on weekdays, not at 3 AM on Sundays. A streaming service promoting weekend content wants Friday-Sunday evenings only. Without dayparting, these advertisers waste budget on low-value impressions during off-hours.

Additionally, campaigns lack "flight" scheduling — the ability to have multiple phases within a single campaign, each with different budgets, creatives, or targeting. A back-to-school campaign might have a "teaser" flight in July with $500/day budget, an "awareness" flight in August at $2000/day, and a "last chance" flight in September at $1000/day. Currently this requires creating three separate campaigns.

### Why This Is Needed

1. **Budget efficiency**: Dayparting lets advertisers focus spend on hours with highest conversion rates. Industry data shows conversion rates vary 3-5x between peak and off-peak hours. Without dayparting, 30-40% of budget may be wasted on low-value hours.

2. **Audience alignment**: Different audiences are active at different times. B2B advertisers need weekday business hours; entertainment advertisers need evenings and weekends; fitness brands need early mornings. Generic 24/7 scheduling ignores these patterns.

3. **Competitive parity**: Every major ad platform (Google Ads, Meta Ads, TikTok Ads) offers dayparting and flight scheduling. Missing this feature signals an immature platform to professional advertisers.

4. **Budget pacing**: When ads only run 12 hours/day, the daily budget must be paced over those 12 hours, not 24. Without dayparting-aware pacing, the system would either under-spend (saving budget for hours when ads are paused) or front-load spending.

5. **Flight scheduling**: Multi-phase campaigns avoid the operational overhead of manually pausing/resuming campaigns and adjusting budgets at phase boundaries.

### Architecture After This Change

```
Campaign Configuration
│
├── start_date: "2026-06-01"
├── end_date: "2026-06-30"
│
├── dayparting: {                         ← NEW
│     timezone: "America/New_York",
│     schedule: {
│       monday:    [10,11,12,13,14,15,16,17],
│       tuesday:   [10,11,12,13,14,15,16,17],
│       wednesday: [10,11,12,13,14,15,16,17],
│       thursday:  [10,11,12,13,14,15,16,17],
│       friday:    [10,11,12,13,14,15,16,17],
│       saturday:  [],        ← No ads on weekends
│       sunday:    [],
│     }
│   }
│
├── flights: [                            ← NEW
│     {
│       flight_id: "fl_001",
│       name: "Teaser Phase",
│       start_date: "2026-06-01",
│       end_date: "2026-06-14",
│       daily_budget_cents: 50000,
│       creative_ids: ["cr_1", "cr_2"],
│     },
│     {
│       flight_id: "fl_002",
│       name: "Full Launch",
│       start_date: "2026-06-15",
│       end_date: "2026-06-30",
│       daily_budget_cents: 200000,
│       creative_ids: ["cr_3", "cr_4", "cr_5"],
│     },
│   ]


Ad Serving Engine (request time)
│
│ 1. Get current time in campaign timezone
│ 2. Check if current day/hour is in dayparting schedule
│ 3. If not → skip this campaign (not eligible)
│ 4. Determine active flight by date
│ 5. Use flight's budget and creatives for serving
│ 6. Pace budget based on active hours remaining today
```

### Data Flow — Dayparting Check at Serving Time

```
Ad Request                      Backend                              DynamoDB
  │                                 │                                    │
  │── GET /ui/ads/serve?context=   │                                    │
  │   feed&viewer_tz=US/Eastern ──>│                                    │
  │                                 │                                    │
  │                                 │── get candidate campaigns ────────>│
  │                                 │   ad_campaigns table               │
  │                                 │<── campaigns[] ───────────────────│
  │                                 │                                    │
  │                                 │── for each campaign: ──────────────│
  │                                 │                                    │
  │                                 │   Step 1: Parse campaign timezone  │
  │                                 │   tz = "America/New_York"          │
  │                                 │   now_local = now_utc → local      │
  │                                 │   day = "tuesday"                  │
  │                                 │   hour = 14                        │
  │                                 │                                    │
  │                                 │   Step 2: Dayparting check         │
  │                                 │   schedule["tuesday"] = [10..17]   │
  │                                 │   14 in [10..17] → ELIGIBLE        │
  │                                 │                                    │
  │                                 │   Step 3: Active flight check      │
  │                                 │   now_date = "2026-06-18"          │
  │                                 │   flights[1].start = "2026-06-15"  │
  │                                 │   flights[1].end = "2026-06-30"    │
  │                                 │   → Use flight "Full Launch"       │
  │                                 │                                    │
  │                                 │   Step 4: Budget pacing            │
  │                                 │   active_hours_today = 8 (10-17)   │
  │                                 │   hours_remaining = 3 (14-17)      │
  │                                 │   hourly_budget = daily / 8        │
  │                                 │   remaining_budget = hourly * 3    │
  │                                 │                                    │
  │                                 │── select best ad from eligible ────│
  │                                 │                                    │
  │<── 200 { ad: { creative_id,    │                                    │
  │     campaign_id, ... } }        │                                    │
```

---

## 2. Current State Analysis

### 2.1 Campaign Schedule (ADS-001)

Campaigns have `start_date` and `end_date` fields (date strings, e.g., "2026-06-01"). The ad serving engine checks whether the current date falls within this range. There are no hour-level or day-of-week controls.

Campaign records also have `daily_budget_cents` for pacing. The pacing logic distributes the daily budget evenly across 24 hours. There is no concept of "active hours" for budget pacing.

### 2.2 Ad Serving Engine (ADS-004)

The serving engine (to be built in ADS-004) selects ad candidates by:
1. Querying active campaigns (status="active", date within range)
2. Filtering by targeting criteria
3. Selecting the best candidate by bid/priority

Missing: dayparting filter between steps 1 and 2, and flight-aware creative/budget selection.

### 2.3 Timezone Handling

The backend uses `now_ts()` which returns Unix timestamps in UTC (`app/core/time.py`). There is no timezone conversion utility. Python's `zoneinfo` module (stdlib since 3.9) handles timezone conversion.

### 2.4 Gaps

1. No dayparting configuration on campaigns
2. No timezone field on campaigns
3. No hour/day-of-week filtering in ad serving
4. No flight scheduling (multiple phases within a campaign)
5. No dayparting-aware budget pacing
6. No frontend UI for dayparting configuration
7. No timezone conversion utility in the backend

---

## 3. Technical Design

### 3.1 Campaign Schema Extension

Add to campaign record in `ad_campaigns` table:

```python
# New fields on campaign record
dayparting: Optional[Dict[str, Any]] = None  # Dayparting configuration
flights: Optional[List[Dict[str, Any]]] = None  # Flight schedule
campaign_timezone: str = "UTC"  # IANA timezone string
```

**Dayparting schema:**
```python
{
    "timezone": "America/New_York",  # IANA timezone
    "schedule": {
        "monday":    [10, 11, 12, 13, 14, 15, 16, 17],  # Active hours (0-23)
        "tuesday":   [10, 11, 12, 13, 14, 15, 16, 17],
        "wednesday": [10, 11, 12, 13, 14, 15, 16, 17],
        "thursday":  [10, 11, 12, 13, 14, 15, 16, 17],
        "friday":    [10, 11, 12, 13, 14, 15, 16, 17],
        "saturday":  [],
        "sunday":    [],
    }
}
```

**Flight schema:**
```python
{
    "flight_id": "fl_abc123",
    "name": "Teaser Phase",
    "start_date": "2026-06-01",
    "end_date": "2026-06-14",
    "daily_budget_cents": 50000,
    "creative_ids": ["cr_1", "cr_2"],
    "status": "scheduled",  # "scheduled" | "active" | "completed"
}
```

### 3.2 Dayparting Service: `app/services/ad_scheduling.py`

```python
"""Ad scheduling and dayparting service (ADS-016).

Handles dayparting eligibility checks, flight resolution,
and dayparting-aware budget pacing.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger(__name__)

VALID_DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
VALID_HOURS = list(range(24))  # 0-23

# Predefined schedule templates
SCHEDULE_TEMPLATES = {
    "always": {day: list(range(24)) for day in VALID_DAYS},
    "weekdays_business": {
        day: list(range(9, 18)) for day in VALID_DAYS[:5]
    } | {"saturday": [], "sunday": []},
    "evenings": {
        day: list(range(18, 24)) for day in VALID_DAYS
    },
    "weekends": {
        **{day: [] for day in VALID_DAYS[:5]},
        "saturday": list(range(24)),
        "sunday": list(range(24)),
    },
}


def validate_dayparting_config(config: Dict[str, Any]) -> tuple[Optional[str], Optional[Dict]]:
    """Validate dayparting configuration.

    Returns (error_message, None) or (None, sanitized_config).
    """
    if not config:
        return None, None

    tz_str = config.get("timezone", "UTC")
    try:
        ZoneInfo(tz_str)
    except (ZoneInfoNotFoundError, KeyError):
        return f"Invalid timezone: {tz_str}", None

    schedule = config.get("schedule", {})
    if not isinstance(schedule, dict):
        return "schedule must be a dict", None

    sanitized_schedule = {}
    for day in VALID_DAYS:
        hours = schedule.get(day, [])
        if not isinstance(hours, list):
            return f"{day} must be a list of hours", None
        valid_hours = sorted(set(h for h in hours if isinstance(h, int) and 0 <= h <= 23))
        sanitized_schedule[day] = valid_hours

    # Must have at least some active hours
    total_active = sum(len(h) for h in sanitized_schedule.values())
    if total_active == 0:
        return "Schedule must have at least one active hour", None

    return None, {"timezone": tz_str, "schedule": sanitized_schedule}


def validate_flights(
    flights: List[Dict[str, Any]], campaign_start: str, campaign_end: str
) -> tuple[Optional[str], Optional[List[Dict]]]:
    """Validate flight schedule.

    Rules:
    - Flights must be within campaign start/end dates
    - Flights must not overlap
    - Each flight must have positive daily_budget_cents
    - Each flight must have at least one creative_id
    """
    if not flights:
        return None, None

    sanitized = []
    for i, flight in enumerate(flights):
        f_start = flight.get("start_date", "")
        f_end = flight.get("end_date", "")
        if not f_start or not f_end:
            return f"Flight {i}: start_date and end_date required", None
        if f_start < campaign_start or f_end > campaign_end:
            return f"Flight {i}: dates must be within campaign range", None
        if f_start > f_end:
            return f"Flight {i}: start_date must be before end_date", None

        budget = flight.get("daily_budget_cents", 0)
        if budget < 100:
            return f"Flight {i}: daily_budget_cents must be >= 100", None

        creative_ids = flight.get("creative_ids", [])
        if not creative_ids:
            return f"Flight {i}: at least one creative_id required", None

        sanitized.append({
            "flight_id": flight.get("flight_id", f"fl_{i}"),
            "name": flight.get("name", f"Flight {i+1}"),
            "start_date": f_start,
            "end_date": f_end,
            "daily_budget_cents": budget,
            "creative_ids": creative_ids,
            "status": "scheduled",
        })

    # Check for overlaps
    sorted_flights = sorted(sanitized, key=lambda f: f["start_date"])
    for i in range(len(sorted_flights) - 1):
        if sorted_flights[i]["end_date"] > sorted_flights[i+1]["start_date"]:
            return f"Flights overlap: {sorted_flights[i]['name']} and {sorted_flights[i+1]['name']}", None

    return None, sanitized


def is_campaign_eligible_now(
    *, dayparting: Optional[Dict[str, Any]], campaign_timezone: str = "UTC"
) -> tuple[bool, Dict[str, Any]]:
    """Check if the campaign is eligible to serve right now based on dayparting.

    Returns (eligible, debug_info).
    """
    if not dayparting:
        return True, {"reason": "no_dayparting", "eligible": True}

    tz_str = dayparting.get("timezone", campaign_timezone)
    try:
        tz = ZoneInfo(tz_str)
    except (ZoneInfoNotFoundError, KeyError):
        # Invalid timezone, allow serving (fail open)
        return True, {"reason": "invalid_timezone", "eligible": True}

    now_local = datetime.now(tz)
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
        "active_hours": active_hours,
        "eligible": eligible,
    }


def get_active_flight(
    *, flights: Optional[List[Dict[str, Any]]]
) -> Optional[Dict[str, Any]]:
    """Determine which flight is active based on current date.

    Returns the active flight dict or None if no flight is active.
    If no flights are configured, returns None (use campaign defaults).
    """
    if not flights:
        return None

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for flight in flights:
        if flight["start_date"] <= today <= flight["end_date"]:
            return flight

    return None  # No flight active (gap between flights)


def calculate_dayparted_budget(
    *, daily_budget_cents: int, dayparting: Optional[Dict[str, Any]],
    campaign_timezone: str = "UTC"
) -> Dict[str, Any]:
    """Calculate budget pacing for dayparted campaigns.

    If ads run 12h/day, hourly budget = daily_budget / 12 (not /24).
    Returns remaining budget for today based on hours remaining.
    """
    if not dayparting:
        return {
            "active_hours_today": 24,
            "hours_remaining": 24 - datetime.now(timezone.utc).hour,
            "hourly_budget_cents": daily_budget_cents // 24,
            "remaining_budget_cents": daily_budget_cents,
        }

    tz_str = dayparting.get("timezone", campaign_timezone)
    try:
        tz = ZoneInfo(tz_str)
    except (ZoneInfoNotFoundError, KeyError):
        tz = timezone.utc

    now_local = datetime.now(tz)
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
    remaining_hours = [h for h in active_hours if h >= current_hour]
    hours_remaining = len(remaining_hours)

    hourly_budget = daily_budget_cents // total_active if total_active > 0 else 0
    remaining_budget = hourly_budget * hours_remaining

    return {
        "active_hours_today": total_active,
        "hours_remaining": hours_remaining,
        "hourly_budget_cents": hourly_budget,
        "remaining_budget_cents": remaining_budget,
    }
```

### 3.3 Pydantic Models

**File**: `app/models.py`

```python
class DaypartingSchedule(BaseModel):
    timezone: str = "UTC"
    schedule: Dict[str, List[int]]  # day_name → list of hours (0-23)

class CampaignFlight(BaseModel):
    flight_id: Optional[str] = None
    name: str = Field(max_length=100)
    start_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    daily_budget_cents: int = Field(ge=100)
    creative_ids: List[str] = Field(min_length=1)

class CampaignScheduleUpdate(BaseModel):
    dayparting: Optional[DaypartingSchedule] = None
    flights: Optional[List[CampaignFlight]] = None
    campaign_timezone: Optional[str] = None

class DaypartingEligibility(BaseModel):
    eligible: bool
    timezone: str
    local_time: str
    day: str
    hour: int
    active_hours: List[int]

class BudgetPacing(BaseModel):
    active_hours_today: int
    hours_remaining: int
    hourly_budget_cents: int
    remaining_budget_cents: int
```

### 3.4 Router Endpoints

**File**: `app/routers/ad_scheduling.py` (or extend existing campaign router)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PATCH | `/ui/ads/campaigns/{id}/schedule` | `require_ui_session` | Update dayparting and/or flights |
| GET | `/ui/ads/campaigns/{id}/schedule` | `require_ui_session` | Get current schedule config |
| GET | `/ui/ads/campaigns/{id}/schedule/eligibility` | `require_ui_session` | Check current eligibility |
| GET | `/ui/ads/campaigns/{id}/schedule/pacing` | `require_ui_session` | Get current budget pacing |
| GET | `/ui/ads/schedule/templates` | `require_ui_session` | List predefined schedule templates |

### 3.5 Frontend Components

#### DaypartingGrid (`frontend/src/components/ads/DaypartingGrid.tsx`)

Interactive 24h x 7-day matrix for selecting active hours:

```typescript
interface DaypartingGridProps {
  schedule: Record<string, number[]>;
  onChange: (schedule: Record<string, number[]>) => void;
  timezone: string;
  onTimezoneChange: (tz: string) => void;
}
```

Features:
- 7 rows (days) x 24 columns (hours), each cell is a toggle button
- Click to toggle individual cells
- Click-drag to select/deselect ranges
- Row header buttons: "All day" / "Clear day"
- Column header buttons: select/deselect entire hour across all days
- Preset buttons: "Weekdays 9-5", "Evenings", "Weekends", "Always"
- Timezone selector dropdown
- Visual summary: "Active 80 hours/week (48% of total)"

#### FlightScheduler (`frontend/src/components/ads/FlightScheduler.tsx`)

Timeline-based flight configuration:

```typescript
interface FlightSchedulerProps {
  flights: CampaignFlight[];
  onChange: (flights: CampaignFlight[]) => void;
  campaignStart: string;
  campaignEnd: string;
}
```

Features:
- Visual timeline bar showing campaign duration with flight segments
- Add/remove flight buttons
- Per-flight: name, start/end date pickers, daily budget input, creative multi-select
- Overlap validation with error highlighting
- Gap warning (days with no active flight)

#### Campaign Schedule Tab

Integrated into the campaign detail page as a new tab:
```tsx
<Tabs defaultValue="overview">
  <TabsList>
    <TabsTrigger value="overview">Overview</TabsTrigger>
    <TabsTrigger value="targeting">Targeting</TabsTrigger>
    <TabsTrigger value="schedule">Schedule</TabsTrigger>  {/* NEW */}
    <TabsTrigger value="analytics">Analytics</TabsTrigger>
  </TabsList>
  <TabsContent value="schedule">
    <DaypartingGrid ... />
    <FlightScheduler ... />
  </TabsContent>
</Tabs>
```

### 3.6 Frontend API

**File**: `frontend/src/api/endpoints/adScheduling.ts`

```typescript
export const updateCampaignSchedule = (campaignId: string, data: CampaignScheduleUpdate) =>
  client.patch(`/ui/ads/campaigns/${campaignId}/schedule`, data);
export const getCampaignSchedule = (campaignId: string) =>
  client.get(`/ui/ads/campaigns/${campaignId}/schedule`);
export const getScheduleEligibility = (campaignId: string) =>
  client.get(`/ui/ads/campaigns/${campaignId}/schedule/eligibility`);
export const getBudgetPacing = (campaignId: string) =>
  client.get(`/ui/ads/campaigns/${campaignId}/schedule/pacing`);
export const getScheduleTemplates = () =>
  client.get("/ui/ads/schedule/templates");
```

### 3.7 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface DaypartingSchedule {
  timezone: string;
  schedule: Record<string, number[]>;
}

export interface CampaignFlight {
  flight_id?: string;
  name: string;
  start_date: string;
  end_date: string;
  daily_budget_cents: number;
  creative_ids: string[];
  status?: string;
}

export interface CampaignScheduleUpdate {
  dayparting?: DaypartingSchedule | null;
  flights?: CampaignFlight[] | null;
  campaign_timezone?: string | null;
}

export interface ScheduleEligibility {
  eligible: boolean;
  timezone: string;
  local_time: string;
  day: string;
  hour: number;
  active_hours: number[];
}

export interface BudgetPacing {
  active_hours_today: number;
  hours_remaining: number;
  hourly_budget_cents: number;
  remaining_budget_cents: number;
}
```

---

## 4. Implementation Plan

### 4.1 Backend (Days 1-4)

1. **`app/services/ad_scheduling.py`**: New file. Dayparting validation, eligibility check, flight resolution, budget pacing calculation.
2. **`app/models.py`**: Add Pydantic models for dayparting, flights, and schedule operations.
3. **`app/routers/ad_scheduling.py`**: New router. Five endpoints. Register in `app/main.py`.
4. **`app/main.py`**: Register router.
5. **Ad serving integration**: Modify the ad serving candidate selection to call `is_campaign_eligible_now()` and `get_active_flight()` before selecting ads.

### 4.2 Frontend (Days 5-7)

6. **`frontend/src/api/types.ts`**: Add scheduling TypeScript types.
7. **`frontend/src/api/endpoints/adScheduling.ts`**: New file. API wrappers.
8. **`frontend/src/components/ads/DaypartingGrid.tsx`**: New component. Interactive hour/day matrix.
9. **`frontend/src/components/ads/FlightScheduler.tsx`**: New component. Timeline-based flight configuration.
10. **Campaign detail page**: Add "Schedule" tab with DaypartingGrid and FlightScheduler.

### 4.3 E2E Tests (Days 7-8)

11. **`frontend/e2e/ad-scheduling.spec.ts`**: New file. 12 tests across 3 sections.

---

## 5. Security Considerations

### 5.1 Timezone Validation

- Only valid IANA timezone strings are accepted (validated by `zoneinfo.ZoneInfo`).
- Invalid timezone strings return 400 rather than falling back to UTC (explicit failure).

### 5.2 Schedule Validation

- At least one active hour per week is required (prevents accidentally creating campaigns that never run).
- Hours validated to 0-23 range; invalid values are silently dropped.
- Flight dates validated against campaign date range.
- Flight overlaps are rejected (prevents double-spending).

### 5.3 Budget Pacing Security

- Budget pacing is calculated server-side based on dayparting config.
- Clients cannot override pacing calculations.
- Budget pacing cannot exceed the campaign's total daily budget.

---

## 6. Testing Strategy

### 6.1 Unit Tests (`tests/test_ad_scheduling.py`)

| # | Test | Description |
|---|------|-------------|
| 1 | Validate valid dayparting config | No error, sanitized config returned |
| 2 | Reject invalid timezone | Error message returned |
| 3 | Reject empty schedule | Error: must have at least one active hour |
| 4 | Dayparting eligibility: active hour | Returns eligible=True |
| 5 | Dayparting eligibility: inactive hour | Returns eligible=False |
| 6 | Flight resolution: active flight found | Returns correct flight |
| 7 | Flight resolution: gap between flights | Returns None |
| 8 | Flight overlap rejected | Error message returned |
| 9 | Budget pacing: 12h active | Hourly budget = daily / 12 |

### 6.2 E2E Tests (`frontend/e2e/ad-scheduling.spec.ts`)

**Test File**: `frontend/e2e/ad-scheduling.spec.ts`

**Test setup (beforeAll):**
- Seed sessions for Alice (advertiser)
- Create a campaign as Alice with start_date/end_date
- Create two creatives for flight assignment

**Section 408: Dayparting Configuration API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Set dayparting schedule on campaign` | PATCH /campaigns/{id}/schedule with dayparting → 200, schedule saved |
| 2 | `Invalid timezone rejected` | PATCH with timezone="Invalid/Zone" → 400 |
| 3 | `Empty schedule rejected` | PATCH with all days = [] → 400 |
| 4 | `Get schedule returns dayparting config` | GET /campaigns/{id}/schedule → 200, dayparting matches what was set |

**Section 409: Flight Scheduling API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Set flight schedule on campaign` | PATCH with flights array → 200, flights saved |
| 6 | `Overlapping flights rejected` | PATCH with overlapping date ranges → 400 |
| 7 | `Flight outside campaign range rejected` | PATCH with flight dates outside campaign dates → 400 |
| 8 | `Get active flight returns correct flight` | Configure two flights; query eligibility; active flight matches current date |

**Section 410: Eligibility & Budget Pacing API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Eligibility check returns current status` | GET /campaigns/{id}/schedule/eligibility → 200, has eligible, timezone, day, hour fields |
| 10 | `Budget pacing reflects dayparting hours` | GET /campaigns/{id}/schedule/pacing → 200, active_hours_today <= 24 |
| 11 | `Schedule templates endpoint returns presets` | GET /schedule/templates → 200, has weekdays_business, evenings, weekends |
| 12 | `Campaign without dayparting is always eligible` | No dayparting set; eligibility → eligible=True |

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_scheduling.py` | Dayparting validation, eligibility, flight resolution, budget pacing |
| `app/routers/ad_scheduling.py` | Schedule API endpoints |
| `frontend/src/api/endpoints/adScheduling.ts` | API wrappers |
| `frontend/src/components/ads/DaypartingGrid.tsx` | Interactive hour/day matrix |
| `frontend/src/components/ads/FlightScheduler.tsx` | Flight timeline configuration |
| `frontend/e2e/ad-scheduling.spec.ts` | E2E tests (12 tests, sections 408-410) |
| `tests/test_ad_scheduling.py` | Unit tests |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add scheduling Pydantic models |
| `app/main.py` | Register scheduling router |
| `frontend/src/api/types.ts` | Add scheduling TypeScript types |

## 9. Acceptance Criteria

1. Campaigns can be configured with dayparting schedules (specific hours per day of week)
2. Campaign timezone is configurable (IANA timezone string)
3. Invalid timezones, empty schedules, and overlapping flights are rejected with clear error messages
4. Ad serving checks dayparting eligibility before serving ads from a campaign
5. Flight scheduling supports multiple phases with different budgets and creatives
6. Budget pacing adjusts for active hours (12h/day campaign paces over 12h, not 24h)
7. Predefined schedule templates are available (weekdays business, evenings, weekends, always)
8. DaypartingGrid provides interactive hour/day matrix with drag-select and presets
9. FlightScheduler provides timeline-based flight configuration with overlap validation
10. All 12 E2E tests pass in `frontend/e2e/ad-scheduling.spec.ts`

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/ad_placement.py` | 178 | Existing `get_ad_config` — no scheduling awareness currently |
| `app/services/ad_scheduling.py` | — | Does not exist yet — new implementation required |

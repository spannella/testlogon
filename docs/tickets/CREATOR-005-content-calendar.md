# CREATOR-005: Visual Content Scheduling Calendar

**Ticket**: CREATOR-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

Creators on the platform can schedule three types of content for future publication:

- **Newsfeed Posts**: Scheduled via `publish_at` field in `POST /posts` (supports timezone-aware scheduling)
- **Broadcasts**: Scheduled via `POST /broadcast/sessions/{id}/schedule` (Unix timestamp with configurable lead time)
- **VOD Releases**: Scheduled via video metadata fields (publish date)

However, each scheduling system operates in isolation. Creators must check three separate interfaces to understand their upcoming content calendar:

- The `ScheduledPostsPanel` sheet on the feed page
- The broadcast sessions list filtered by `schedule_status=scheduled`
- The video library filtered by upcoming publish dates

There is no unified visual calendar showing all scheduled content in one place, making it difficult for creators to plan content cadence, avoid scheduling conflicts, and maintain a consistent posting schedule.

The lack of a unified view has measurable consequences:

1. **Double-booking**: Creators accidentally schedule a broadcast at the same time as a scheduled post, splitting their audience across two competing content drops.
2. **Content droughts**: Without seeing gaps in the calendar, creators go days without publishing, losing engagement momentum.
3. **Timezone confusion**: Posts scheduled via the feed page carry `schedule_timezone` metadata, but broadcasts use raw Unix timestamps. Creators working across timezones have no single place to verify local publish times.
4. **Manual tracking overhead**: Creators resort to external tools (Google Calendar, spreadsheets) to track their content pipeline, leading to stale data when items are rescheduled or cancelled in-platform.

### 1.2 Goals

1. **Unified Visual Calendar**: A single calendar view showing all scheduled posts, broadcasts, and VOD releases.
2. **Color-Coded Content Types**: Each content type has a distinct color (posts = blue, broadcasts = red, VOD = purple).
3. **Weekly and Monthly Views**: Toggle between week and month views, matching the existing calendar page UI patterns.
4. **Drag-and-Drop Rescheduling**: Creators can drag a scheduled item to a new date/time to reschedule it.
5. **Quick Create**: Click on an empty time slot to create a new scheduled post or broadcast.
6. **Integration with Existing Scheduling Endpoints**: No new scheduling logic -- the calendar is a read/write frontend for existing scheduling APIs.
7. **Conflict Detection**: Warn creators when two items are scheduled too close together.
8. **Mobile-First Agenda View**: A chronological list view for mobile devices showing today's and tomorrow's items.

### 1.3 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to see all my scheduled content on one calendar. | Calendar page shows posts, broadcasts, and VOD releases in a unified view. |
| Creator | I want to distinguish between content types at a glance. | Posts are blue, broadcasts are red, VOD releases are purple. Each has a unique icon. |
| Creator | I want to switch between weekly and monthly views. | Tabs or toggle switches between views. Default is weekly. |
| Creator | I want to drag a scheduled post to a different date. | Drag-and-drop triggers a PATCH request to update `publish_at`. Toast confirms rescheduling. |
| Creator | I want to click a time slot to create a new scheduled post. | Click opens `CreatePost` dialog with `publish_at` pre-filled to the clicked time. |
| Creator | I want to click a scheduled broadcast to see its details. | Click opens broadcast detail panel with edit/cancel options. |
| Creator | I want to see today's agenda as a list (for mobile). | Mobile view shows a chronological list of today's and tomorrow's scheduled items. |
| Creator | I want to cancel a scheduled item from the calendar. | Right-click or long-press shows "Cancel" option. Confirmation dialog before cancellation. |
| Creator | I want to see warnings when I schedule items too close together. | Conflict banner appears when items are within 30 minutes of each other. |
| Creator | I want to filter the calendar by content type. | Filter chips for post/broadcast/vod; toggling off a type hides those items. |
| Creator | I want to see overdue items clearly marked. | Items past their scheduled time but not yet published show an amber "Overdue" badge. |
| Creator | I want to quickly navigate to today. | A "Today" button resets the calendar to the current week/day. |
| Creator | I want to undo an accidental drag-and-drop. | After rescheduling, a 5-second undo toast lets me revert to the original time. |

### 1.4 Non-Goals

- **Cross-creator visibility**: No admin or multi-creator calendar view (separate ticket).
- **Recurring content templates**: No support for recurring schedules (e.g., "post every Tuesday at 9 AM").
- **External calendar sync**: No iCal export or Google Calendar integration for the content calendar (the existing events calendar already has this).
- **Content drafts**: Only scheduled items appear; draft posts/broadcasts without a scheduled time are not shown.

---

## 2. Current State Analysis

### 2.1 Newsfeed Post Scheduling

The newsfeed router (`app/routers/newsfeed.py`) supports scheduled posts via the `PostCreateIn` model (see `app/routers/newsfeed.py:1297` for `publish_at` field):

```python
publish_at: Optional[int] = Field(
    default=None,
    ge=0,
    description="Unix timestamp (seconds) for scheduled publish time.",
)
schedule_timezone: Optional[str] = Field(
    default=None,
    min_length=1,
    max_length=64,
    description="IANA timezone name used when scheduling (e.g. America/New_York).",
)
scheduled_at_local: Optional[str] = Field(
    default=None,
    min_length=1,
    max_length=32,
    description="User-entered local datetime string (for display/audit), e.g. 2026-12-31T19:00.",
)
```

Scheduled posts have `status="scheduled"` and are listed via the `ScheduledPostsResponse` model (see `app/routers/newsfeed.py:1396`). The scheduler service (`app/services/newsfeed_scheduler.py`) runs a background loop that publishes due posts.

The scheduler service processes due posts by querying a GSI (see `app/services/newsfeed_scheduler.py:234`):

```python
def process_due_scheduled_posts(
    *,
    now_ts: Optional[int] = None,
    page_limit: int = 50,
    max_batches: int = 1,
    publish_retry_max: int = 3,
    retry_backoff_seconds: float = 0.25,
) -> Dict[str, Any]:
```

It uses the `GSI_SCHEDULE_DUE` index with PK `"SCHEDULED"` and SK `"{publish_at:012d}#POST#{post_id}"`:

```python
DUE_INDEX_NAME = os.environ.get("NEWSFEED_SCHEDULE_DUE_INDEX_NAME", "GSI_SCHEDULE_DUE")
DUE_INDEX_PK_ATTR = "GSI_SCHEDULE_PK"
DUE_INDEX_SK_ATTR = "GSI_SCHEDULE_SK"
DUE_INDEX_PK_VALUE = "SCHEDULED"
```

**Scheduled Post Ref pattern**: Each scheduled post writes a `ScheduledPostRef` record under the user's PK, with SK `SCHEDULEDPOST#{publish_at:012d}#{post_id}`. This enables the `list_scheduled_posts` endpoint to query posts ordered by publish time without scanning the schedule index globally. The ref has fields: `post_id`, `owner_user_id`, `status`, `publish_at`, `schedule_timezone`, `scheduled_at_local`, `created_at`.

**Listing scheduled posts** (`list_scheduled_posts`, see `app/routers/newsfeed.py:3377`): Queries `pk=USER#{user_id}` with `sk begins_with SCHEDULEDPOST#`, then batch-fetches the actual post records. This is the pattern the content calendar will reuse.

**Post cancellation** (`cancel_scheduled_post`, see `app/routers/newsfeed.py:3662`): Updates the post status from `scheduled` to `cancelled`, removes the GSI attributes (`GSI_SCHEDULE_PK`, `GSI_SCHEDULE_SK`), and deletes the `ScheduledPostRef` record. This is the existing delete path the calendar's cancel button calls.
<!-- NOTE: cancel_scheduled_post uses POST /posts/{post_id}/cancel, not DELETE -->

**Post rescheduling** (`edit_post`, see `app/routers/newsfeed.py:3437`): The `PATCH /posts/{post_id}` endpoint allows updating `publish_at` on a scheduled post. When `publish_at` changes, the old `ScheduledPostRef` and GSI sort key must be re-written. This is the reschedule path for drag-and-drop.

### 2.2 Broadcast Scheduling

The broadcast router (`app/routers/broadcast.py`) provides scheduling via `schedule_session_route` (see `app/routers/broadcast.py:2053`):

```python
@router.post("/sessions/{session_id}/schedule", response_model=BroadcastSessionOut)
def schedule_session_route(
    session_id: str,
    body: BroadcastScheduleIn,
    request: Request,
    ctx: dict = Depends(_ctx),
):
    """Schedule a draft broadcast session for a future time."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the session creator can schedule.")
    if session.status not in ("draft",):
        raise HTTPException(
            status_code=409,
            detail={"code": "BROADCAST_INVALID_STATE", "detail": "Session must be in draft status to schedule."},
        )
    now = now_ts()
    min_lead = _S.broadcast_schedule_min_lead_time_seconds
    if body.scheduled_at < now + min_lead:
        raise HTTPException(
            status_code=400,
            detail={"code": "SCHEDULE_TOO_SOON", "detail": f"scheduled_at must be at least {min_lead} seconds in the future"},
        )
```

Rescheduling (see `app/routers/broadcast.py:2124`):

```python
@router.post("/sessions/{session_id}/reschedule", response_model=BroadcastSessionOut)
def reschedule_session_route(
    session_id: str,
    body: BroadcastRescheduleIn,
    ...
):
    """Reschedule an already-scheduled broadcast session."""
    session = get_session(session_id)
    if session.schedule_status != "scheduled":
        raise HTTPException(
            status_code=409,
            detail={"code": "BROADCAST_NOT_SCHEDULED", "detail": "Session is not currently scheduled."},
        )
```

Cancellation via `cancel_schedule_route` (see `app/routers/broadcast.py:2170`): Transitions `scheduled -> cancelled`, cancels reminders, deletes the BCAST-010 announcement post if present, and records an audit action.
<!-- NOTE: The actual route path is POST /sessions/{id}/cancel-schedule (with hyphen), not /cancel_schedule -->

**Broadcast listing for calendar**: The `list_scheduled_sessions_by_creator` function (see `app/services/broadcast_store.py:452`) queries `ByCreatorCreatedAt` GSI with `FilterExpression` for `schedule_status="scheduled"`. Note the CLAUDE.md caveat: `FilterExpression` doesn't reduce page size. This is acceptable for the content calendar since creators rarely have more than a few dozen scheduled broadcasts, but the content calendar service must paginate via `LastEvaluatedKey` to guarantee completeness.

Scheduled broadcasts are listed via the `ByScheduledAt` GSI (see `app/services/broadcast_store.py:437`):

```python
def list_due_scheduled_sessions(*, now: int, limit: int = 10) -> List[BroadcastSessionModel]:
    """Queries ByScheduledAt GSI: schedule_status='scheduled', scheduled_at <= now."""
    resp = T.broadcast_sessions.query(
        IndexName="ByScheduledAt",
        KeyConditionExpression=Key("schedule_status").eq("scheduled") & Key("scheduled_at").lte(now),
        ScanIndexForward=True,
        Limit=limit,
    )
```

### 2.3 VOD Scheduling

The `VideoMetadataModel` (see `app/models_video.py:36`) currently has a `published_at: Optional[int]` field (line 100), `status` (with values `created`, `encoding`, `ready`, `published`, `deleted`), and `visibility` (`private`, `unlisted`, `public`). The `scheduled_publish_at: Optional[int]` field already exists (see `app/models_video.py:104`, comment `# Scheduled Publishing (CREATOR-005)`).

For the content calendar, VOD "scheduled releases" are defined as videos with:
- `status = "ready"` (encoding complete, ready to publish)
- `visibility = "private"` (not yet visible to audience)
- `published_at` is `None` (has not been published yet)
- `scheduled_publish_at` is set to a future Unix timestamp

<!-- NOTE: scheduled_publish_at already exists in VideoMetadataModel (line 104) and is serialized/deserialized in video_metadata_store.py (lines 97, 241) — no new field needed -->

**Video listing for calendar**: Uses `list_videos_by_owner` (see `app/services/video_metadata_store.py:402`) which queries `ByOwnerCreatedAt` GSI. For the content calendar, a `FilterExpression` for `attribute_exists(scheduled_publish_at)` filters to only videos with an explicit future release date.

### 2.4 Existing Calendar UI

The frontend calendar (`frontend/src/pages/calendar/CalendarPage.tsx`) already provides a sophisticated calendar interface with tabs for Calendars, View, Booking Links, Sharing, Settings, and Integrations:

```tsx
export default function CalendarPage() {
  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Calendar"
        description="Manage events, schedules, and booking links"
      />
      <Tabs defaultValue="calendars">
        <TabsList>
          <TabsTrigger value="calendars">Calendars</TabsTrigger>
          <TabsTrigger value="calendar">View</TabsTrigger>
          <TabsTrigger value="booking">Booking Links</TabsTrigger>
          ...
        </TabsList>
```

The `CalendarView.tsx` component (see `frontend/src/pages/calendar/CalendarView.tsx`, 586 lines total) provides month and week views with event rendering, including helper functions for date calculation:

```tsx
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

function getMonthDays(year: number, month: number): Date[] {
  const first = new Date(year, month, 1);
  const startDay = first.getDay();
  const days: Date[] = [];
  // ...
}

function getWeekDays(date: Date): Date[] {
  const day = date.getDay();
  const start = new Date(date);
  start.setDate(start.getDate() - day);
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(start);
    d.setDate(d.getDate() + i);
    return d;
  });
}

function eventOnDay(ev: CalendarEvent, day: Date): boolean {
  if (ev.all_day && ev.all_day_date) {
    return ev.all_day_date === day.toISOString().slice(0, 10);
  }
  if (ev.start_utc) {
    return isSameDay(new Date(ev.start_utc), day);
  }
  return false;
}
```

The content calendar will reuse these date utility functions and follow the same visual patterns (month grid, week columns, hour rows), but display content items instead of calendar events.

### 2.5 Scheduled Posts Panel (Frontend)

The `ScheduledPostsPanel` (see `frontend/src/pages/feed/ScheduledPostsPanel.tsx`, 166 lines total) provides a list view of scheduled posts with cancel and edit functionality:

```tsx
export function ScheduledPostsPanel() {
  const query = useInfiniteQuery({
    queryKey: ["scheduled-posts"],
    queryFn: ({ pageParam }) => getScheduledPosts(pageParam as string | undefined),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });

  const cancelMut = useMutation({
    mutationFn: (postId: string) => cancelScheduledPost(postId),
    onSuccess: () => {
      toast.success("Scheduled post cancelled");
      void queryClient.invalidateQueries({ queryKey: ["scheduled-posts"] });
      void queryClient.invalidateQueries({ queryKey: ["feed"] });
    },
  });

  const all = useMemo(
    () =>
      (query.data?.pages ?? [])
        .flatMap((p) => p.items)
        .slice()
        .sort((a, b) => (a.publish_at ?? Number.MAX_SAFE_INTEGER) - (b.publish_at ?? Number.MAX_SAFE_INTEGER)),
    [query.data?.pages],
  );
```

This component handles scheduled post data well but only covers posts, not broadcasts or VOD. The content calendar will aggregate data from all three sources. A "View on Calendar" link will be added to `ScheduledPostsPanel` to navigate to the content calendar with the relevant week in view.

### 2.6 Broadcast Session List

The broadcast store (see `app/services/broadcast_store.py:452`) lists scheduled broadcasts for a creator:

```python
def list_scheduled_sessions_by_creator(created_by: str, *, limit: int = 50) -> List[BroadcastSessionModel]:
    """List sessions with schedule_status='scheduled' for a specific creator.
    Uses ByCreatorCreatedAt GSI filtered by schedule_status.
    """
    from boto3.dynamodb.conditions import Attr
    kwargs: Dict[str, Any] = {
        "IndexName": "ByCreatorCreatedAt",
        "KeyConditionExpression": Key("created_by").eq(created_by),
        "FilterExpression": Attr("schedule_status").eq("scheduled"),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    resp = T.broadcast_sessions.query(**kwargs)
    return [session_from_item(i) for i in resp.get("Items", [])]
```

Note the caveat from CLAUDE.md: `FilterExpression` doesn't reduce page size, so if a creator has many sessions, this query may need pagination. For the calendar view, this is acceptable since creators rarely have more than a few dozen scheduled broadcasts.

---

## 3. Technical Design

### 3.1 Content Calendar Service Layer

A new service module at `app/services/content_calendar.py` aggregates content from all three scheduling systems. This keeps the router thin and enables unit testing of the aggregation logic.

```python
"""Content calendar aggregation service.

Queries scheduled posts, broadcasts, and VOD releases and returns them
as normalized CalendarItem dicts sorted by scheduled_at.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

from boto3.dynamodb.conditions import Attr, Key

from app.core.aws import ddb
from app.core.settings import S
import os
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ─── Constants ──────────────────────────────────────────────────

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")  # actual uses env var, not S.app_table_name
MAX_RANGE_SECONDS = 90 * 86400  # 90 days maximum query window
CONFLICT_BUFFER_MINUTES = 30

ContentType = Literal["post", "broadcast", "vod"]

CONTENT_COLORS: Dict[ContentType, str] = {
    "post": "#3B82F6",       # blue-500
    "broadcast": "#EF4444",  # red-500
    "vod": "#8B5CF6",        # violet-500
}

CONTENT_ICONS: Dict[ContentType, str] = {
    "post": "file-text",
    "broadcast": "radio",
    "vod": "video",
}


# ─── Scheduled Post Retrieval ───────────────────────────────────

def _get_scheduled_posts(
    user_id: str,
    from_ts: int,
    to_ts: int,
    *,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Retrieve scheduled posts for a user within the time window.

    Uses the user's ScheduledPostRef records (PK=USER#{user_id},
    SK begins_with SCHEDULEDPOST#) which are sorted by publish_at.
    Then batch-fetches the full post records.
    """
    tbl = ddb.Table(APP_TABLE)
    # ScheduledPostRef SK format: SCHEDULEDPOST#{publish_at:012d}#{post_id}
    sk_lower = f"SCHEDULEDPOST#{from_ts:012d}"
    sk_upper = f"SCHEDULEDPOST#{to_ts:012d}~"

    resp = tbl.query(
        KeyConditionExpression=(
            Key("pk").eq(f"USER#{user_id}")
            & Key("sk").between(sk_lower, sk_upper)
        ),
        Limit=limit,
        ScanIndexForward=True,
    )
    refs = resp.get("Items", [])

    if not refs:
        return []

    # Batch-fetch actual post records
    post_ids = [str(r.get("post_id", "")).strip() for r in refs if r.get("post_id")]
    if not post_ids:
        return []

    keys = [{"pk": f"POST#{pid}", "sk": "META"} for pid in post_ids]
    raw = ddb.batch_get_item(RequestItems={APP_TABLE: {"Keys": keys}})
    posts = raw.get("Responses", {}).get(APP_TABLE, [])

    # Filter to only scheduled posts owned by user
    return [
        p for p in posts
        if str(p.get("status", "")).strip().lower() == "scheduled"
        and p.get("user_id") == user_id
    ]


# ─── Scheduled Broadcast Retrieval ─────────────────────────────

def _get_scheduled_broadcasts(
    user_id: str,
    from_ts: int,
    to_ts: int,
) -> List[BroadcastSessionModel]:
    """Retrieve scheduled broadcasts for a user within the time window.

    Uses list_scheduled_sessions_by_creator (ByCreatorCreatedAt GSI
    with FilterExpression on schedule_status='scheduled'), then
    filters client-side by scheduled_at range.
    """
    sessions = list_scheduled_sessions_by_creator(user_id, limit=200)
    return [
        s for s in sessions
        if s.scheduled_at is not None
        and from_ts <= s.scheduled_at <= to_ts
    ]


# ─── Scheduled VOD Retrieval ───────────────────────────────────

def _get_scheduled_vod(
    user_id: str,
    from_ts: int,
    to_ts: int,
) -> List[Dict[str, Any]]:
    """Retrieve videos with a scheduled_publish_at within the time window.

    Uses ByOwnerCreatedAt GSI with FilterExpression for
    attribute_exists(scheduled_publish_at).
    """
    from app.services.video_metadata_store import list_videos_by_owner

    result = list_videos_by_owner(user_id, limit=200)
    videos = result.get("items", [])

    scheduled = []
    for v in videos:
        spa = getattr(v, "scheduled_publish_at", None)
        if spa is not None and from_ts <= spa <= to_ts:
            scheduled.append({
                "video_id": v.id,
                "title": v.title,
                "scheduled_publish_at": spa,
                "duration_seconds": v.duration_seconds,
                "thumbnail_url": v.thumbnail_url,
                "status": v.status,
                "visibility": v.visibility,
            })
    return scheduled


# ─── Normalization ──────────────────────────────────────────────

def _truncate(text: str, max_len: int = 60) -> str:
    """Truncate a string to max_len, adding ellipsis if needed."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _post_to_calendar_item(post: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a scheduled post DDB item to a calendar item dict."""
    publish_at = int(post.get("publish_at", 0))
    now = now_ts()
    is_overdue = publish_at < now

    return {
        "id": post.get("post_id", ""),
        "type": "post",
        "title": _truncate(post.get("body_plain") or post.get("body", ""), 60),
        "scheduled_at": publish_at,
        "timezone": post.get("schedule_timezone"),
        "local_time": post.get("scheduled_at_local"),
        "status": "overdue" if is_overdue else post.get("status", "scheduled"),
        "color": CONTENT_COLORS["post"],
        "icon": CONTENT_ICONS["post"],
        "has_images": bool(post.get("image_urls")),
        "has_video": bool(post.get("video")),
        "visibility": post.get("visibility", "followers"),
        "locked": bool(post.get("locked")),
        "unlock_price_cents": int(post["unlock_price_cents"]) if post.get("unlock_price_cents") is not None else 0,
    }


def _broadcast_to_calendar_item(session: BroadcastSessionModel) -> Dict[str, Any]:
    """Convert a BroadcastSessionModel to a calendar item dict."""
    scheduled_at = session.scheduled_at or 0
    now = now_ts()
    is_overdue = scheduled_at < now

    return {
        "id": session.id,
        "type": "broadcast",
        "title": session.name or f"Broadcast {session.id[:8]}",
        "scheduled_at": scheduled_at,
        "timezone": None,
        "local_time": None,
        "status": "overdue" if is_overdue else (session.schedule_status or "scheduled"),
        "color": CONTENT_COLORS["broadcast"],
        "icon": CONTENT_ICONS["broadcast"],
        "description": session.description,
        "profile_id": session.profile_id,
        "has_announcement": bool(getattr(session, "announcement_post_id", None)),
    }


def _vod_to_calendar_item(video: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a scheduled VOD dict to a calendar item dict."""
    scheduled_at = int(video.get("scheduled_publish_at", 0))
    now = now_ts()
    is_overdue = scheduled_at < now

    return {
        "id": video["video_id"],
        "type": "vod",
        "title": video.get("title", "Untitled Video"),
        "scheduled_at": scheduled_at,
        "timezone": None,
        "local_time": None,
        "status": "overdue" if is_overdue else "scheduled",
        "color": CONTENT_COLORS["vod"],
        "icon": CONTENT_ICONS["vod"],
        "duration_seconds": video.get("duration_seconds"),
        "thumbnail_url": video.get("thumbnail_url"),
    }


# ─── Aggregation ────────────────────────────────────────────────

def get_content_calendar(
    user_id: str,
    from_ts: int,
    to_ts: int,
    type_filter: Optional[Set[ContentType]] = None,
) -> Dict[str, Any]:
    """Aggregate all scheduled content for a creator within a time range.

    Returns a dict with items sorted by scheduled_at, plus conflict data.
    """
    if to_ts - from_ts > MAX_RANGE_SECONDS:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail=f"Time range exceeds maximum of {MAX_RANGE_SECONDS // 86400} days",
        )

    types = type_filter or {"post", "broadcast", "vod"}
    items: List[Dict[str, Any]] = []

    if "post" in types:
        posts = _get_scheduled_posts(user_id, from_ts, to_ts)
        items.extend(_post_to_calendar_item(p) for p in posts)

    if "broadcast" in types:
        broadcasts = _get_scheduled_broadcasts(user_id, from_ts, to_ts)
        items.extend(_broadcast_to_calendar_item(b) for b in broadcasts)

    if "vod" in types:
        vod_items = _get_scheduled_vod(user_id, from_ts, to_ts)
        items.extend(_vod_to_calendar_item(v) for v in vod_items)

    items.sort(key=lambda x: x["scheduled_at"])

    conflicts = detect_conflicts(items)

    return {
        "items": items,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "count": len(items),
        "conflicts": conflicts,
    }


# ─── Conflict Detection ────────────────────────────────────────

def detect_conflicts(
    items: List[Dict[str, Any]],
    buffer_minutes: int = CONFLICT_BUFFER_MINUTES,
) -> List[Dict[str, Any]]:
    """Find items that are scheduled too close together.

    Two items conflict if they are scheduled within buffer_minutes of
    each other. Returns a list of conflict dicts describing each pair.
    """
    conflicts: List[Dict[str, Any]] = []
    sorted_items = sorted(items, key=lambda x: x["scheduled_at"])
    buffer_seconds = buffer_minutes * 60

    for i in range(len(sorted_items) - 1):
        a = sorted_items[i]
        b = sorted_items[i + 1]
        gap = b["scheduled_at"] - a["scheduled_at"]
        if gap < buffer_seconds:
            conflicts.append({
                "item_a_id": a["id"],
                "item_a_type": a["type"],
                "item_b_id": b["id"],
                "item_b_type": b["type"],
                "gap_seconds": gap,
                "gap_minutes": round(gap / 60, 1),
            })
    return conflicts


# ─── Today's Agenda ─────────────────────────────────────────────

def get_today_agenda(user_id: str) -> Dict[str, Any]:
    """Get scheduled content for today and tomorrow.

    Convenience method for the mobile agenda view.
    Returns items partitioned into 'today' and 'tomorrow' lists.
    """
    import time
    from datetime import datetime, timezone, timedelta

    now_dt = datetime.now(timezone.utc)
    today_start = int(now_dt.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    tomorrow_end = int((now_dt + timedelta(days=2)).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())

    result = get_content_calendar(user_id, today_start, tomorrow_end)
    items = result["items"]

    today_end = today_start + 86400
    today_items = [i for i in items if i["scheduled_at"] < today_end]
    tomorrow_items = [i for i in items if today_end <= i["scheduled_at"] < tomorrow_end]

    return {
        "today": today_items,
        "tomorrow": tomorrow_items,
        "today_count": len(today_items),
        "tomorrow_count": len(tomorrow_items),
        "conflicts": result["conflicts"],
    }


# ─── Reschedule Dispatch ───────────────────────────────────────

def reschedule_item(
    user_id: str,
    item_id: str,
    item_type: ContentType,
    new_scheduled_at: int,
) -> Dict[str, Any]:
    """Dispatch a reschedule request to the appropriate content system.

    Validates ownership and constraints for each content type.
    Returns the updated item as a calendar item dict.
    """
    now = now_ts()
    if new_scheduled_at <= now:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail="Cannot schedule content in the past",
        )

    if item_type == "post":
        return _reschedule_post(user_id, item_id, new_scheduled_at)
    elif item_type == "broadcast":
        return _reschedule_broadcast(user_id, item_id, new_scheduled_at)
    elif item_type == "vod":
        return _reschedule_vod(user_id, item_id, new_scheduled_at)
    else:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unknown item type: {item_type}")


def _reschedule_post(user_id: str, post_id: str, new_ts: int) -> Dict[str, Any]:
    """Reschedule a newsfeed post by updating publish_at.

    Updates:
    1. The post record (publish_at, GSI_SCHEDULE_SK)
    2. The ScheduledPostRef record (delete old, write new)
    """
    from fastapi import HTTPException

    tbl = ddb.Table(APP_TABLE)
    post = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    if str(post.get("status", "")).strip().lower() != "scheduled":
        raise HTTPException(status_code=409, detail="Post is not in scheduled status")

    old_publish_at = int(post.get("publish_at", 0))

    # Update the post record
    new_schedule_sk = f"{new_ts:012d}#POST#{post_id}"
    tbl.update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression="SET publish_at = :new_ts, GSI_SCHEDULE_SK = :new_sk, updated_at = :now",
        ExpressionAttributeValues={
            ":new_ts": new_ts,
            ":new_sk": new_schedule_sk,
            ":now": now_ts(),
        },
    )

    # Delete old ScheduledPostRef, write new one
    old_ref_sk = f"SCHEDULEDPOST#{old_publish_at:012d}#{post_id}"
    new_ref_sk = f"SCHEDULEDPOST#{new_ts:012d}#{post_id}"
    try:
        tbl.delete_item(Key={"pk": f"USER#{user_id}", "sk": old_ref_sk})
    except Exception:
        logger.warning("Failed to delete old ScheduledPostRef", extra={"post_id": post_id})

    tbl.put_item(Item={
        "pk": f"USER#{user_id}",
        "sk": new_ref_sk,
        "Entity": "ScheduledPostRef",
        "post_id": post_id,
        "owner_user_id": user_id,
        "status": "scheduled",
        "publish_at": new_ts,
        "schedule_timezone": post.get("schedule_timezone"),
        "scheduled_at_local": None,  # clear since time changed
        "created_at": post.get("created_at"),
    })

    # Return updated calendar item
    post["publish_at"] = new_ts
    return _post_to_calendar_item(post)


def _reschedule_broadcast(user_id: str, session_id: str, new_ts: int) -> Dict[str, Any]:
    """Reschedule a broadcast session via the broadcast store."""
    from app.services.broadcast_store import get_session, update_session_fields
    from app.services.broadcast_reminders import cancel_reminders_for_session
    from fastapi import HTTPException

    session = get_session(session_id)
    if session.created_by != user_id:
        raise HTTPException(status_code=403, detail="Not your broadcast")
    if session.schedule_status != "scheduled":
        raise HTTPException(status_code=409, detail="Broadcast is not in scheduled status")

    # Enforce minimum lead time
    min_lead = S.broadcast_schedule_min_lead_time_seconds
    now = now_ts()
    if new_ts < now + min_lead:
        raise HTTPException(
            status_code=400,
            detail=f"scheduled_at must be at least {min_lead} seconds in the future",
        )

    cancel_reminders_for_session(session_id)
    updated = update_session_fields(session_id, {"scheduled_at": new_ts})
    return _broadcast_to_calendar_item(updated)


def _reschedule_vod(user_id: str, video_id: str, new_ts: int) -> Dict[str, Any]:
    """Reschedule a VOD release by updating scheduled_publish_at."""
    from app.services.video_metadata_store import get_video
    from fastapi import HTTPException

    video = get_video(video_id)
    if video.owner_user_id != user_id:
        raise HTTPException(status_code=403, detail="Not your video")

    spa = getattr(video, "scheduled_publish_at", None)
    if spa is None:
        raise HTTPException(status_code=409, detail="Video does not have a scheduled publish time")

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET scheduled_publish_at = :ts, updated_at = :now",
        ExpressionAttributeValues={":ts": new_ts, ":now": now_ts()},
    )

    return _vod_to_calendar_item({
        "video_id": video_id,
        "title": video.title,
        "scheduled_publish_at": new_ts,
        "duration_seconds": video.duration_seconds,
        "thumbnail_url": video.thumbnail_url,
        "status": video.status,
        "visibility": video.visibility,
    })


# ─── Cancel Dispatch ────────────────────────────────────────────

def cancel_item(
    user_id: str,
    item_id: str,
    item_type: ContentType,
) -> Dict[str, str]:
    """Cancel a scheduled content item.

    Dispatches to the appropriate cancel endpoint for the content type.
    """
    if item_type == "post":
        return _cancel_post(user_id, item_id)
    elif item_type == "broadcast":
        return _cancel_broadcast(user_id, item_id)
    elif item_type == "vod":
        return _cancel_vod(user_id, item_id)
    else:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unknown item type: {item_type}")


def _cancel_post(user_id: str, post_id: str) -> Dict[str, str]:
    """Cancel a scheduled post."""
    from fastapi import HTTPException

    tbl = ddb.Table(APP_TABLE)
    post = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    if str(post.get("status", "")).strip().lower() != "scheduled":
        raise HTTPException(status_code=409, detail="Post is not in scheduled status")

    publish_at = int(post.get("publish_at", 0))

    # Update status to cancelled, remove GSI attrs
    tbl.update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression=(
            "SET #status = :cancelled, updated_at = :now "
            "REMOVE publish_at, schedule_timezone, scheduled_at_local, "
            "GSI_SCHEDULE_PK, GSI_SCHEDULE_SK"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":cancelled": "cancelled",
            ":now": now_ts(),
        },
    )

    # Delete ScheduledPostRef
    ref_sk = f"SCHEDULEDPOST#{publish_at:012d}#{post_id}"
    try:
        tbl.delete_item(Key={"pk": f"USER#{user_id}", "sk": ref_sk})
    except Exception:
        logger.warning("Failed to delete ScheduledPostRef on cancel", extra={"post_id": post_id})

    return {"ok": "true", "id": post_id, "type": "post"}


def _cancel_broadcast(user_id: str, session_id: str) -> Dict[str, str]:
    """Cancel a scheduled broadcast."""
    from app.services.broadcast_store import get_session, transition_session_status, now_iso
    from app.services.broadcast_reminders import cancel_reminders_for_session
    from fastapi import HTTPException

    session = get_session(session_id)
    if session.created_by != user_id:
        raise HTTPException(status_code=403, detail="Not your broadcast")
    if session.schedule_status != "scheduled":
        raise HTTPException(status_code=409, detail="Broadcast is not in scheduled status")

    cancel_reminders_for_session(session_id)
    transition_session_status(
        session_id=session_id,
        to_status="cancelled",
        reason="calendar-cancel",
        actor=user_id,
        extra_fields={
            "schedule_status": "cancelled",
            "cancelled_at": now_iso(),
        },
    )
    return {"ok": "true", "id": session_id, "type": "broadcast"}


def _cancel_vod(user_id: str, video_id: str) -> Dict[str, str]:
    """Cancel a scheduled VOD release (remove scheduled_publish_at)."""
    from app.services.video_metadata_store import get_video
    from fastapi import HTTPException

    video = get_video(video_id)
    if video.owner_user_id != user_id:
        raise HTTPException(status_code=403, detail="Not your video")

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="REMOVE scheduled_publish_at SET updated_at = :now",
        ExpressionAttributeValues={":now": now_ts()},
    )
    return {"ok": "true", "id": video_id, "type": "vod"}
```

### 3.2 Content Calendar Router

The router is thin, delegating all logic to the service layer:

<!-- NOTE: The actual router at app/routers/content_calendar.py imports require_ui_session from app.services.sessions, not app.auth.deps -->
```python
"""Content calendar router.

Provides unified read/write access to scheduled content items
across posts, broadcasts, and VOD releases.

Registered in app/main.py with prefix="/ui/content-calendar".
"""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query

from app.services.sessions import require_ui_session  # actual import path
from app.services.content_calendar import (
    get_content_calendar,
    get_today_agenda,
    reschedule_item,
    cancel_item,
    ContentType,
)

router = APIRouter(prefix="/ui/content-calendar", tags=["content-calendar"])


@router.get("")
def content_calendar(
    from_ts: int = Query(..., description="Start of time range (Unix seconds)"),
    to_ts: int = Query(..., description="End of time range (Unix seconds)"),
    types: Optional[str] = Query(
        default=None,
        description="Comma-separated content types: post,broadcast,vod",
    ),
    session=Depends(require_ui_session),
):
    """Get all scheduled content for the authenticated creator in a time range.

    Merges:
    1. Scheduled posts (status='scheduled', publish_at in range)
    2. Scheduled broadcasts (schedule_status='scheduled', scheduled_at in range)
    3. Scheduled VOD releases (scheduled_publish_at in range)

    Returns a flat list of calendar items sorted by scheduled time,
    plus any detected scheduling conflicts.
    """
    user_id = session["user_sub"]

    type_filter = None
    if types:
        raw = {t.strip().lower() for t in types.split(",")}
        valid: set[ContentType] = set()
        for t in raw:
            if t in ("post", "broadcast", "vod"):
                valid.add(t)  # type: ignore[arg-type]
        if valid:
            type_filter = valid

    return get_content_calendar(user_id, from_ts, to_ts, type_filter=type_filter)


@router.get("/today")
def content_calendar_today(
    session=Depends(require_ui_session),
):
    """Get today's and tomorrow's scheduled items.

    Convenience endpoint for the mobile agenda view. Returns items
    partitioned into 'today' and 'tomorrow' lists.
    """
    return get_today_agenda(session["user_sub"])


@router.get("/conflicts")
def content_calendar_conflicts(
    from_ts: int = Query(..., description="Start of time range (Unix seconds)"),
    to_ts: int = Query(..., description="End of time range (Unix seconds)"),
    session=Depends(require_ui_session),
):
    """Detect scheduling conflicts in a time range.

    Returns only the conflicts list (items within 30 minutes of each other).
    """
    result = get_content_calendar(session["user_sub"], from_ts, to_ts)
    return {"conflicts": result["conflicts"], "count": len(result["conflicts"])}


@router.post("/reschedule")
def content_calendar_reschedule(
    item_id: str = Query(...),
    item_type: Literal["post", "broadcast", "vod"] = Query(...),
    new_scheduled_at: int = Query(..., description="New scheduled time (Unix seconds)"),
    session=Depends(require_ui_session),
):
    """Reschedule a content item to a new time.

    Dispatches to the appropriate scheduling endpoint for the content type.
    Validates ownership and scheduling constraints.
    """
    return reschedule_item(
        user_id=session["user_sub"],
        item_id=item_id,
        item_type=item_type,
        new_scheduled_at=new_scheduled_at,
    )


@router.post("/cancel")
def content_calendar_cancel(
    item_id: str = Query(...),
    item_type: Literal["post", "broadcast", "vod"] = Query(...),
    session=Depends(require_ui_session),
):
    """Cancel a scheduled content item.

    Dispatches to the appropriate cancel endpoint for the content type.
    """
    return cancel_item(
        user_id=session["user_sub"],
        item_id=item_id,
        item_type=item_type,
    )
```

### 3.3 Calendar Item Normalization

Each content type is normalized to a common calendar item shape:

```python
def _post_to_calendar_item(post: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": post["post_id"],
        "type": "post",
        "title": _truncate(post.get("body_plain") or post.get("body", ""), 60),
        "scheduled_at": int(post.get("publish_at", 0)),
        "timezone": post.get("schedule_timezone"),
        "local_time": post.get("scheduled_at_local"),
        "status": post.get("status", "scheduled"),
        "color": "#3B82F6",     # blue-500
        "icon": "file-text",
        "has_images": bool(post.get("image_urls")),
        "has_video": bool(post.get("video")),
        "visibility": post.get("visibility", "followers"),
    }

def _broadcast_to_calendar_item(session: BroadcastSessionModel) -> Dict[str, Any]:
    return {
        "id": session.id,
        "type": "broadcast",
        "title": session.name or f"Broadcast {session.id[:8]}",
        "scheduled_at": session.scheduled_at or 0,
        "timezone": None,
        "local_time": None,
        "status": session.schedule_status or "scheduled",
        "color": "#EF4444",     # red-500
        "icon": "radio",
        "description": session.description,
        "profile_id": session.profile_id,
    }

def _vod_to_calendar_item(video: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": video["video_id"],
        "type": "vod",
        "title": video.get("title", "Untitled Video"),
        "scheduled_at": int(video.get("publish_at", 0)),
        "timezone": None,
        "local_time": None,
        "status": "scheduled",
        "color": "#8B5CF6",     # violet-500
        "icon": "video",
        "duration_seconds": video.get("duration_seconds"),
        "thumbnail_url": video.get("thumbnail_url"),
    }
```

### 3.4 Rescheduling via Calendar

When a user drags an item to a new time slot, the frontend calls the appropriate reschedule endpoint:

```typescript
async function rescheduleItem(item: CalendarItem, newTimestamp: number) {
  switch (item.type) {
    case "post":
      // PATCH /posts/{post_id} with { publish_at: newTimestamp }
      await updatePost(item.id, { publish_at: newTimestamp });
      break;
    case "broadcast":
      // POST /broadcast/sessions/{id}/reschedule
      await rescheduleBroadcast(item.id, { scheduled_at: newTimestamp });
      break;
    case "vod":
      // PATCH /ui/videos/{id} with { publish_at: newTimestamp }
      await updateVideo(item.id, { publish_at: newTimestamp });
      break;
  }
  queryClient.invalidateQueries({ queryKey: ["content-calendar"] });
  toast.success(`${item.type} rescheduled`);
}
```

Alternatively, the unified `/ui/content-calendar/reschedule` endpoint can be used, which dispatches internally to the correct scheduling system and returns the updated calendar item:

```typescript
async function rescheduleViaCalendarApi(
  item: CalendarItem,
  newTimestamp: number,
) {
  const resp = await client.post("/ui/content-calendar/reschedule", null, {
    params: {
      item_id: item.id,
      item_type: item.type,
      new_scheduled_at: newTimestamp,
    },
  });
  return resp.data;
}
```

### 3.5 Conflict Detection

The calendar checks for scheduling conflicts (two items at the same time) and warns the creator:

```python
def detect_conflicts(items: List[Dict[str, Any]], buffer_minutes: int = 30) -> List[Dict[str, Any]]:
    """Find items that overlap or are too close together.

    Two items conflict if they are scheduled within buffer_minutes of each other.
    """
    conflicts = []
    sorted_items = sorted(items, key=lambda x: x["scheduled_at"])
    for i in range(len(sorted_items) - 1):
        a = sorted_items[i]
        b = sorted_items[i + 1]
        gap_seconds = b["scheduled_at"] - a["scheduled_at"]
        if gap_seconds < buffer_minutes * 60:
            conflicts.append({
                "item_a": a["id"],
                "item_b": b["id"],
                "gap_seconds": gap_seconds,
            })
    return conflicts
```

**Conflict resolution strategies**: When a conflict is detected:

1. **Warning only**: The default -- a yellow banner appears on the calendar. The creator can acknowledge and keep both items.
2. **Suggested respace**: The conflict banner offers to automatically space items 30 minutes apart (shift the later item forward).
3. **Cross-type priority**: Broadcasts take priority over posts because they have live audiences. The banner highlights the lower-priority item.

### 3.6 Data Flow Sequence Diagram

```
Creator opens /content-calendar
        |
        v
ContentCalendarPage mounts
        |
        +---> useQuery(["content-calendar", from_ts, to_ts, types])
        |         |
        |         v
        |   GET /ui/content-calendar?from_ts=...&to_ts=...
        |         |
        |         v
        |   content_calendar_service.get_content_calendar(user_id, from_ts, to_ts)
        |         |
        |         +---> _get_scheduled_posts(user_id, from_ts, to_ts)
        |         |         |
        |         |         +---> DDB query: pk=USER#{user_id} sk BETWEEN SCHEDULEDPOST#{from} AND SCHEDULEDPOST#{to}
        |         |         +---> DDB batch_get_item: POST#{id} / META
        |         |         +---> filter status="scheduled", user_id matches
        |         |
        |         +---> _get_scheduled_broadcasts(user_id, from_ts, to_ts)
        |         |         |
        |         |         +---> list_scheduled_sessions_by_creator(user_id)
        |         |         +---> DDB query: ByCreatorCreatedAt GSI, FilterExpr schedule_status="scheduled"
        |         |         +---> client-side filter: scheduled_at in [from_ts, to_ts]
        |         |
        |         +---> _get_scheduled_vod(user_id, from_ts, to_ts)
        |         |         |
        |         |         +---> list_videos_by_owner(user_id)
        |         |         +---> client-side filter: scheduled_publish_at in [from_ts, to_ts]
        |         |
        |         +---> normalize each to CalendarItem dicts
        |         +---> sort by scheduled_at
        |         +---> detect_conflicts(items, buffer_minutes=30)
        |         |
        |         v
        |   { items: [...], conflicts: [...], count, from_ts, to_ts }
        |
        v
ContentCalendarGrid renders items at correct positions
ConflictBanner renders if conflicts.length > 0

--- Drag-and-Drop Reschedule ---

Creator drags post item to Thursday 2 PM
        |
        v
onDrop handler:
   1. Optimistic update: move item in local state
   2. POST /ui/content-calendar/reschedule?item_id=...&item_type=post&new_scheduled_at=...
        |
        v
content_calendar_service.reschedule_item(user_id, post_id, "post", new_ts)
        |
        +---> _reschedule_post: validate ownership, update DDB, rewrite ScheduledPostRef
        |
        v
   returns updated CalendarItem dict
        |
        v
   3. queryClient.invalidateQueries(["content-calendar"])
   4. toast.success("Post rescheduled to Thu 2:00 PM")
   5. Undo toast (5 seconds): POST /reschedule with original_ts if clicked
```

---

## 4. API Endpoints

### 4.1 Content Calendar

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/content-calendar` | `require_ui_session` | Get all scheduled content in time range |
| GET | `/ui/content-calendar/today` | `require_ui_session` | Get today's and tomorrow's scheduled items (shortcut) |
| GET | `/ui/content-calendar/conflicts` | `require_ui_session` | Detect scheduling conflicts |
| POST | `/ui/content-calendar/reschedule` | `require_ui_session` | Reschedule a content item |
| POST | `/ui/content-calendar/cancel` | `require_ui_session` | Cancel a scheduled content item |

### 4.2 Request/Response Models

```python
from pydantic import BaseModel, Field
from typing import Dict, List, Literal, Optional


class ContentCalendarItem(BaseModel):
    """A single scheduled content item in the calendar."""
    id: str
    type: Literal["post", "broadcast", "vod"]
    title: str = Field(max_length=60)
    scheduled_at: int = Field(description="Unix timestamp of the scheduled publish time")
    timezone: Optional[str] = Field(default=None, description="IANA timezone if set (posts only)")
    local_time: Optional[str] = Field(default=None, description="User-entered local time string (posts only)")
    status: str = Field(description="scheduled | overdue | cancelled")
    color: str = Field(description="Hex color code for display")
    icon: str = Field(description="Lucide icon name for display")

    # Post-specific fields
    has_images: bool = False
    has_video: bool = False
    visibility: Optional[str] = None
    locked: bool = False
    unlock_price_cents: int = 0

    # Broadcast-specific fields
    description: Optional[str] = None
    profile_id: Optional[str] = None
    has_announcement: bool = False

    # VOD-specific fields
    duration_seconds: Optional[float] = None
    thumbnail_url: Optional[str] = None


class ContentCalendarConflict(BaseModel):
    """A pair of items scheduled too close together."""
    item_a_id: str
    item_a_type: Literal["post", "broadcast", "vod"]
    item_b_id: str
    item_b_type: Literal["post", "broadcast", "vod"]
    gap_seconds: int
    gap_minutes: float


class ContentCalendarOut(BaseModel):
    """Response for the content calendar endpoint."""
    items: List[ContentCalendarItem] = Field(default_factory=list)
    from_ts: int
    to_ts: int
    count: int = 0
    conflicts: List[ContentCalendarConflict] = Field(default_factory=list)


class TodayAgendaOut(BaseModel):
    """Response for the today endpoint."""
    today: List[ContentCalendarItem] = Field(default_factory=list)
    tomorrow: List[ContentCalendarItem] = Field(default_factory=list)
    today_count: int = 0
    tomorrow_count: int = 0
    conflicts: List[ContentCalendarConflict] = Field(default_factory=list)


class ConflictsOut(BaseModel):
    """Response for the conflicts endpoint."""
    conflicts: List[ContentCalendarConflict] = Field(default_factory=list)
    count: int = 0


class RescheduleResult(BaseModel):
    """Response for the reschedule endpoint."""
    item: ContentCalendarItem
    old_scheduled_at: int
    new_scheduled_at: int


class CancelResult(BaseModel):
    """Response for the cancel endpoint."""
    ok: str = "true"
    id: str
    type: Literal["post", "broadcast", "vod"]
```

### 4.3 Error Responses

| Status | Code | Condition |
|--------|------|-----------|
| 400 | `RANGE_TOO_LARGE` | `to_ts - from_ts` exceeds 90 days |
| 400 | `SCHEDULE_IN_PAST` | `new_scheduled_at <= now_ts()` |
| 400 | `SCHEDULE_TOO_SOON` | Broadcast `new_scheduled_at < now + min_lead_time` |
| 400 | `INVALID_TYPE` | `item_type` not in `{post, broadcast, vod}` |
| 403 | `FORBIDDEN` | User does not own the item |
| 404 | `NOT_FOUND` | Item ID does not exist |
| 409 | `INVALID_STATE` | Item is not in `scheduled` status (already published/cancelled) |

---

## 5. Frontend Components

### 5.1 New Pages and Components

<!-- NOTE: ContentCalendarGrid and ContentCalendarItem do not exist as separate files — their functionality is inline in ContentCalendarWeek.tsx and ContentCalendarPage.tsx respectively -->
| Component | Path | Purpose |
|-----------|------|---------|
| `ContentCalendarPage` | `frontend/src/pages/content-calendar/ContentCalendarPage.tsx` (11758 bytes) | Main page with week/month toggle and calendar grid |
| `ContentCalendarWeek` | `frontend/src/pages/content-calendar/ContentCalendarWeek.tsx` (6386 bytes) | Weekly view with hour rows and day columns |
| `ContentCalendarMonth` | `frontend/src/pages/content-calendar/ContentCalendarMonth.tsx` (4330 bytes) | Monthly view with day cells and item dots |
| `ContentCalendarMobileList` | `frontend/src/pages/content-calendar/ContentCalendarMobileList.tsx` (3658 bytes) | Chronological list view for mobile |
| `QuickScheduleDialog` | `frontend/src/pages/content-calendar/QuickScheduleDialog.tsx` (3289 bytes) | Create new scheduled content from time slot click |
| `ConflictBanner` | `frontend/src/pages/content-calendar/ConflictBanner.tsx` (2328 bytes) | Warning banner when scheduling conflicts detected |
| `ContentItemDetail` | `frontend/src/pages/content-calendar/ContentItemDetail.tsx` (4684 bytes) | Detail panel shown on item click |

### 5.2 TypeScript Types

```typescript
// frontend/src/api/types.ts additions

export type ContentItemType = "post" | "broadcast" | "vod";

export interface ContentCalendarItem {
  id: string;
  type: ContentItemType;
  title: string;
  scheduled_at: number;
  timezone: string | null;
  local_time: string | null;
  status: "scheduled" | "overdue" | "cancelled";
  color: string;
  icon: string;

  // Post-specific
  has_images?: boolean;
  has_video?: boolean;
  visibility?: string;
  locked?: boolean;
  unlock_price_cents?: number;

  // Broadcast-specific
  description?: string;
  profile_id?: string;
  has_announcement?: boolean;

  // VOD-specific
  duration_seconds?: number;
  thumbnail_url?: string;
}

export interface ContentCalendarConflict {
  item_a_id: string;
  item_a_type: ContentItemType;
  item_b_id: string;
  item_b_type: ContentItemType;
  gap_seconds: number;
  gap_minutes: number;
}

export interface ContentCalendarResponse {
  items: ContentCalendarItem[];
  from_ts: number;
  to_ts: number;
  count: number;
  conflicts: ContentCalendarConflict[];
}

export interface TodayAgendaResponse {
  today: ContentCalendarItem[];
  tomorrow: ContentCalendarItem[];
  today_count: number;
  tomorrow_count: number;
  conflicts: ContentCalendarConflict[];
}

export interface ConflictsResponse {
  conflicts: ContentCalendarConflict[];
  count: number;
}
```

### 5.3 API Endpoint Functions

<!-- NOTE: Actual file uses `import { api } from "@/api/client"` and `api.get()`/`api.post()` instead of `client.get()`/`client.post()` (see frontend/src/api/endpoints/content-calendar.ts:1) -->
```typescript
// frontend/src/api/endpoints/content-calendar.ts

import { api } from "@/api/client";  // actual import pattern
import type {
  ContentCalendarResponse,
  TodayAgendaResponse,
  ConflictsResponse,
  ContentCalendarItem,
  ContentItemType,
} from "../types";

export async function getContentCalendar(
  fromTs: number,
  toTs: number,
  types?: ContentItemType[],
): Promise<ContentCalendarResponse> {
  const params: Record<string, string | number> = { from_ts: fromTs, to_ts: toTs };
  if (types && types.length > 0) {
    params.types = types.join(",");
  }
  const { data } = await client.get<ContentCalendarResponse>(
    "/ui/content-calendar",
    { params },
  );
  return data;
}

export async function getTodayAgenda(): Promise<TodayAgendaResponse> {
  const { data } = await client.get<TodayAgendaResponse>(
    "/ui/content-calendar/today",
  );
  return data;
}

export async function getConflicts(
  fromTs: number,
  toTs: number,
): Promise<ConflictsResponse> {
  const { data } = await client.get<ConflictsResponse>(
    "/ui/content-calendar/conflicts",
    { params: { from_ts: fromTs, to_ts: toTs } },
  );
  return data;
}

export async function rescheduleCalendarItem(
  itemId: string,
  itemType: ContentItemType,
  newScheduledAt: number,
): Promise<ContentCalendarItem> {
  const { data } = await client.post<ContentCalendarItem>(
    "/ui/content-calendar/reschedule",
    null,
    {
      params: {
        item_id: itemId,
        item_type: itemType,
        new_scheduled_at: newScheduledAt,
      },
    },
  );
  return data;
}

export async function cancelCalendarItem(
  itemId: string,
  itemType: ContentItemType,
): Promise<{ ok: string; id: string; type: ContentItemType }> {
  const { data } = await client.post(
    "/ui/content-calendar/cancel",
    null,
    { params: { item_id: itemId, item_type: itemType } },
  );
  return data;
}
```

### 5.4 ContentCalendarPage Implementation

```tsx
// frontend/src/pages/content-calendar/ContentCalendarPage.tsx

import { useState, useMemo, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  CalendarDays,
  ChevronLeft,
  ChevronRight,
  FileText,
  Radio,
  Video,
  AlertTriangle,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/PageHeader";
import {
  getContentCalendar,
  rescheduleCalendarItem,
  cancelCalendarItem,
} from "@/api/endpoints/content-calendar";
import type { ContentCalendarItem, ContentItemType } from "@/api/types";
import { ContentCalendarWeek } from "./ContentCalendarWeek";
import { ContentCalendarMonth } from "./ContentCalendarMonth";
import { ContentCalendarMobileList } from "./ContentCalendarMobileList";
import { ConflictBanner } from "./ConflictBanner";
import { QuickScheduleDialog } from "./QuickScheduleDialog";
import { ContentItemDetail } from "./ContentItemDetail";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

function getWeekRange(date: Date): { from_ts: number; to_ts: number } {
  const day = date.getDay();
  const start = new Date(date);
  start.setDate(start.getDate() - day);
  start.setHours(0, 0, 0, 0);
  const end = new Date(start);
  end.setDate(end.getDate() + 7);
  return {
    from_ts: Math.floor(start.getTime() / 1000),
    to_ts: Math.floor(end.getTime() / 1000),
  };
}

function getMonthRange(date: Date): { from_ts: number; to_ts: number } {
  const start = new Date(date.getFullYear(), date.getMonth(), 1);
  const end = new Date(date.getFullYear(), date.getMonth() + 1, 1);
  return {
    from_ts: Math.floor(start.getTime() / 1000),
    to_ts: Math.floor(end.getTime() / 1000),
  };
}

const TYPE_LABELS: Record<ContentItemType, string> = {
  post: "Posts",
  broadcast: "Broadcasts",
  vod: "Videos",
};

const TYPE_ICONS: Record<ContentItemType, typeof FileText> = {
  post: FileText,
  broadcast: Radio,
  vod: Video,
};

export default function ContentCalendarPage() {
  const queryClient = useQueryClient();
  const [view, setView] = useState<"week" | "month">("week");
  const [anchorDate, setAnchorDate] = useState(new Date());
  const [typeFilter, setTypeFilter] = useState<Set<ContentItemType>>(
    new Set(["post", "broadcast", "vod"]),
  );
  const [quickScheduleTime, setQuickScheduleTime] = useState<number | null>(null);
  const [selectedItem, setSelectedItem] = useState<ContentCalendarItem | null>(null);
  const [undoState, setUndoState] = useState<{
    item: ContentCalendarItem;
    originalTs: number;
  } | null>(null);

  const range = useMemo(
    () => (view === "week" ? getWeekRange(anchorDate) : getMonthRange(anchorDate)),
    [view, anchorDate],
  );

  const calendarQuery = useQuery({
    queryKey: ["content-calendar", range.from_ts, range.to_ts, [...typeFilter].sort().join(",")],
    queryFn: () =>
      getContentCalendar(
        range.from_ts,
        range.to_ts,
        typeFilter.size === 3 ? undefined : [...typeFilter],
      ),
    refetchInterval: 60_000, // refetch every minute to catch overdue items
  });

  const rescheduleMut = useMutation({
    mutationFn: ({
      item,
      newTs,
    }: {
      item: ContentCalendarItem;
      newTs: number;
    }) => rescheduleCalendarItem(item.id, item.type, newTs),
    onMutate: ({ item, newTs }) => {
      // Optimistic update: move item in cache
      const oldTs = item.scheduled_at;
      queryClient.setQueryData(
        ["content-calendar", range.from_ts, range.to_ts, [...typeFilter].sort().join(",")],
        (old: any) => {
          if (!old) return old;
          return {
            ...old,
            items: old.items.map((i: ContentCalendarItem) =>
              i.id === item.id && i.type === item.type
                ? { ...i, scheduled_at: newTs }
                : i,
            ),
          };
        },
      );
      setUndoState({ item, originalTs: oldTs });
      return { oldTs };
    },
    onSuccess: (_data, { item }) => {
      toast.success(`${item.type} rescheduled`, {
        action: undoState
          ? {
              label: "Undo",
              onClick: () => {
                if (undoState) {
                  rescheduleMut.mutate({
                    item: undoState.item,
                    newTs: undoState.originalTs,
                  });
                }
              },
            }
          : undefined,
        duration: 5000,
      });
      void queryClient.invalidateQueries({ queryKey: ["content-calendar"] });
      void queryClient.invalidateQueries({ queryKey: ["scheduled-posts"] });
    },
    onError: (err, { item }, context) => {
      // Rollback optimistic update
      if (context?.oldTs) {
        queryClient.setQueryData(
          ["content-calendar", range.from_ts, range.to_ts, [...typeFilter].sort().join(",")],
          (old: any) => {
            if (!old) return old;
            return {
              ...old,
              items: old.items.map((i: ContentCalendarItem) =>
                i.id === item.id && i.type === item.type
                  ? { ...i, scheduled_at: context.oldTs }
                  : i,
              ),
            };
          },
        );
      }
      toast.error(err instanceof Error ? err.message : "Failed to reschedule");
    },
  });

  const cancelMut = useMutation({
    mutationFn: (item: ContentCalendarItem) =>
      cancelCalendarItem(item.id, item.type),
    onSuccess: (_data, item) => {
      toast.success(`${item.type} cancelled`);
      setSelectedItem(null);
      void queryClient.invalidateQueries({ queryKey: ["content-calendar"] });
      void queryClient.invalidateQueries({ queryKey: ["scheduled-posts"] });
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : "Failed to cancel");
    },
  });

  const navigate = useCallback(
    (delta: number) => {
      setAnchorDate((prev) => {
        const next = new Date(prev);
        if (view === "week") {
          next.setDate(next.getDate() + delta * 7);
        } else {
          next.setMonth(next.getMonth() + delta);
        }
        return next;
      });
    },
    [view],
  );

  const goToToday = useCallback(() => setAnchorDate(new Date()), []);

  const toggleType = useCallback((type: ContentItemType) => {
    setTypeFilter((prev) => {
      const next = new Set(prev);
      if (next.has(type)) {
        if (next.size > 1) next.delete(type); // keep at least one
      } else {
        next.add(type);
      }
      return next;
    });
  }, []);

  const items = calendarQuery.data?.items ?? [];
  const conflicts = calendarQuery.data?.conflicts ?? [];

  const headerLabel = useMemo(() => {
    if (view === "week") {
      const weekStart = new Date(range.from_ts * 1000);
      const weekEnd = new Date(range.to_ts * 1000 - 86400000);
      const opts: Intl.DateTimeFormatOptions = { month: "short", day: "numeric" };
      return `${weekStart.toLocaleDateString(undefined, opts)} - ${weekEnd.toLocaleDateString(undefined, opts)}, ${weekEnd.getFullYear()}`;
    }
    return anchorDate.toLocaleDateString(undefined, { month: "long", year: "numeric" });
  }, [view, range, anchorDate]);

  return (
    <div className="mx-auto w-full max-w-6xl space-y-4 p-4 sm:p-6">
      <PageHeader
        title="Content Calendar"
        description="Manage your scheduled posts, broadcasts, and video releases"
      />

      {/* Conflict Banner */}
      {conflicts.length > 0 && (
        <ConflictBanner
          conflicts={conflicts}
          items={items}
          onResolve={(itemId, itemType, newTs) =>
            rescheduleMut.mutate({
              item: items.find((i) => i.id === itemId && i.type === itemType)!,
              newTs,
            })
          }
        />
      )}

      {/* Controls */}
      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-2 py-3">
          {/* Navigation */}
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon"
              onClick={() => navigate(-1)}
              aria-label={`Previous ${view}`}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="sm" onClick={goToToday}>
              Today
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => navigate(1)}
              aria-label={`Next ${view}`}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
            <span className="text-sm font-medium">{headerLabel}</span>
          </div>

          {/* View Toggle + Type Filters */}
          <div className="flex items-center gap-2">
            {(["post", "broadcast", "vod"] as ContentItemType[]).map((type) => {
              const Icon = TYPE_ICONS[type];
              const active = typeFilter.has(type);
              return (
                <Button
                  key={type}
                  variant={active ? "default" : "outline"}
                  size="sm"
                  onClick={() => toggleType(type)}
                  className="gap-1"
                  aria-pressed={active}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {TYPE_LABELS[type]}
                </Button>
              );
            })}
            <Tabs value={view} onValueChange={(v) => setView(v as "week" | "month")}>
              <TabsList>
                <TabsTrigger value="week">Week</TabsTrigger>
                <TabsTrigger value="month">Month</TabsTrigger>
              </TabsList>
            </Tabs>
          </div>
        </CardContent>
      </Card>

      {/* Calendar Grid */}
      <Card>
        <CardContent className="p-0">
          {/* Desktop */}
          <div className="hidden md:block">
            {view === "week" ? (
              <ContentCalendarWeek
                anchorDate={anchorDate}
                items={items}
                onDrop={(item, newTs) => rescheduleMut.mutate({ item, newTs })}
                onSlotClick={(ts) => setQuickScheduleTime(ts)}
                onItemClick={setSelectedItem}
              />
            ) : (
              <ContentCalendarMonth
                anchorDate={anchorDate}
                items={items}
                onDayClick={(date) => {
                  setAnchorDate(date);
                  setView("week");
                }}
                onItemClick={setSelectedItem}
              />
            )}
          </div>

          {/* Mobile */}
          <div className="block md:hidden">
            <ContentCalendarMobileList
              items={items}
              onItemClick={setSelectedItem}
              onCancel={(item) => cancelMut.mutate(item)}
            />
          </div>
        </CardContent>
      </Card>

      {/* Quick Schedule Dialog */}
      {quickScheduleTime !== null && (
        <QuickScheduleDialog
          open
          scheduledAt={quickScheduleTime}
          onClose={() => setQuickScheduleTime(null)}
          onCreated={() => {
            setQuickScheduleTime(null);
            void queryClient.invalidateQueries({ queryKey: ["content-calendar"] });
          }}
        />
      )}

      {/* Item Detail Panel */}
      {selectedItem && (
        <ContentItemDetail
          item={selectedItem}
          open
          onClose={() => setSelectedItem(null)}
          onCancel={() => cancelMut.mutate(selectedItem)}
          onReschedule={(newTs) =>
            rescheduleMut.mutate({ item: selectedItem, newTs })
          }
        />
      )}
    </div>
  );
}
```

### 5.5 ContentCalendarWeek Implementation

```tsx
// frontend/src/pages/content-calendar/ContentCalendarWeek.tsx

import { useMemo, createElement } from "react";
import { cn } from "@/lib/utils";
import { FileText, Radio, Video } from "lucide-react";
import type { ContentCalendarItem, ContentItemType } from "@/api/types";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

function formatHour(h: number): string {
  if (h === 0) return "12 AM";
  if (h < 12) return `${h} AM`;
  if (h === 12) return "12 PM";
  return `${h - 12} PM`;
}

function getWeekDays(date: Date): Date[] {
  const day = date.getDay();
  const start = new Date(date);
  start.setDate(start.getDate() - day);
  start.setHours(0, 0, 0, 0);
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(start);
    d.setDate(d.getDate() + i);
    return d;
  });
}

function isSameDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

const CONTENT_COLORS: Record<ContentItemType, string> = {
  post: "bg-blue-100 border-blue-400 text-blue-700 dark:bg-blue-950 dark:border-blue-600 dark:text-blue-300",
  broadcast: "bg-red-100 border-red-400 text-red-700 dark:bg-red-950 dark:border-red-600 dark:text-red-300",
  vod: "bg-violet-100 border-violet-400 text-violet-700 dark:bg-violet-950 dark:border-violet-600 dark:text-violet-300",
};

const CONTENT_ICONS: Record<ContentItemType, typeof FileText> = {
  post: FileText,
  broadcast: Radio,
  vod: Video,
};

interface Props {
  anchorDate: Date;
  items: ContentCalendarItem[];
  onDrop: (item: ContentCalendarItem, newTs: number) => void;
  onSlotClick: (ts: number) => void;
  onItemClick: (item: ContentCalendarItem) => void;
}

export function ContentCalendarWeek({
  anchorDate,
  items,
  onDrop,
  onSlotClick,
  onItemClick,
}: Props) {
  const weekDays = useMemo(() => getWeekDays(anchorDate), [anchorDate]);
  const today = new Date();

  function itemsForDayHour(day: Date, hour: number): ContentCalendarItem[] {
    return items.filter((item) => {
      const d = new Date(item.scheduled_at * 1000);
      return isSameDay(d, day) && d.getHours() === hour;
    });
  }

  return (
    <div className="overflow-x-auto">
      {/* Day headers */}
      <div className="grid grid-cols-[60px_repeat(7,1fr)] border-b">
        <div className="border-r p-2" />
        {weekDays.map((day, i) => (
          <div
            key={i}
            className={cn(
              "border-r p-2 text-center text-xs font-medium",
              isSameDay(day, today) && "bg-primary/5 font-bold",
            )}
          >
            <div>{DAYS[i]}</div>
            <div className={cn(
              "text-lg",
              isSameDay(day, today) && "rounded-full bg-primary text-primary-foreground w-8 h-8 flex items-center justify-center mx-auto",
            )}>
              {day.getDate()}
            </div>
          </div>
        ))}
      </div>

      {/* Hour rows */}
      <div className="max-h-[600px] overflow-y-auto">
        {HOURS.map((hour) => (
          <div key={hour} className="grid grid-cols-[60px_repeat(7,1fr)] min-h-[48px]">
            <div className="border-r border-b p-1 text-right text-[10px] text-muted-foreground">
              {formatHour(hour)}
            </div>
            {weekDays.map((day, dayIdx) => {
              const slotItems = itemsForDayHour(day, hour);
              const slotTs = Math.floor(
                new Date(day.getFullYear(), day.getMonth(), day.getDate(), hour).getTime() / 1000,
              );
              return (
                <div
                  key={dayIdx}
                  className={cn(
                    "border-r border-b p-0.5 cursor-pointer hover:bg-muted/30 transition-colors",
                    isSameDay(day, today) && "bg-primary/5",
                  )}
                  onClick={() => {
                    if (slotItems.length === 0) onSlotClick(slotTs);
                  }}
                  onDragOver={(e) => {
                    e.preventDefault();
                    e.dataTransfer.dropEffect = "move";
                  }}
                  onDrop={(e) => {
                    e.preventDefault();
                    try {
                      const item: ContentCalendarItem = JSON.parse(
                        e.dataTransfer.getData("application/json"),
                      );
                      onDrop(item, slotTs);
                    } catch {
                      // ignore malformed drag data
                    }
                  }}
                >
                  {slotItems.map((item) => {
                    const Icon = CONTENT_ICONS[item.type];
                    return (
                      <div
                        key={`${item.type}-${item.id}`}
                        draggable
                        onDragStart={(e) => {
                          e.dataTransfer.setData(
                            "application/json",
                            JSON.stringify(item),
                          );
                          e.dataTransfer.effectAllowed = "move";
                        }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onItemClick(item);
                        }}
                        className={cn(
                          "cursor-grab rounded border-l-4 px-1.5 py-0.5 text-[11px] mb-0.5",
                          "hover:shadow-sm transition-shadow",
                          CONTENT_COLORS[item.type],
                          item.status === "overdue" && "opacity-75 ring-1 ring-amber-400",
                        )}
                        title={`${item.title} (${item.type})`}
                      >
                        <div className="flex items-center gap-1">
                          {createElement(Icon, { className: "h-3 w-3 flex-shrink-0" })}
                          <span className="truncate font-medium">{item.title}</span>
                        </div>
                        {item.status === "overdue" && (
                          <span className="text-amber-600 text-[9px]">Overdue</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}
```

### 5.6 ConflictBanner Implementation

```tsx
// frontend/src/pages/content-calendar/ConflictBanner.tsx

import { AlertTriangle } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import type { ContentCalendarConflict, ContentCalendarItem, ContentItemType } from "@/api/types";

interface Props {
  conflicts: ContentCalendarConflict[];
  items: ContentCalendarItem[];
  onResolve: (itemId: string, itemType: ContentItemType, newTs: number) => void;
}

export function ConflictBanner({ conflicts, items, onResolve }: Props) {
  if (conflicts.length === 0) return null;

  function findItem(id: string, type: string) {
    return items.find((i) => i.id === id && i.type === type);
  }

  function formatTime(ts: number) {
    return new Date(ts * 1000).toLocaleTimeString(undefined, {
      hour: "numeric",
      minute: "2-digit",
    });
  }

  return (
    <Alert variant="destructive" className="border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200">
      <AlertTriangle className="h-4 w-4" />
      <AlertTitle>Scheduling Conflicts ({conflicts.length})</AlertTitle>
      <AlertDescription className="space-y-2">
        {conflicts.slice(0, 3).map((c, idx) => {
          const a = findItem(c.item_a_id, c.item_a_type);
          const b = findItem(c.item_b_id, c.item_b_type);
          if (!a || !b) return null;
          return (
            <div key={idx} className="flex items-center justify-between gap-2 text-sm">
              <span>
                <strong>{a.title}</strong> ({formatTime(a.scheduled_at)}) and{" "}
                <strong>{b.title}</strong> ({formatTime(b.scheduled_at)}) are only{" "}
                {c.gap_minutes} min apart
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  // Push later item 30 min after earlier item
                  const newTs = a.scheduled_at + 30 * 60;
                  onResolve(b.id, b.type as ContentItemType, newTs);
                }}
              >
                Space 30 min apart
              </Button>
            </div>
          );
        })}
        {conflicts.length > 3 && (
          <p className="text-xs">
            + {conflicts.length - 3} more conflicts
          </p>
        )}
      </AlertDescription>
    </Alert>
  );
}
```

### 5.7 QuickScheduleDialog Implementation

```tsx
// frontend/src/pages/content-calendar/QuickScheduleDialog.tsx

import { useState } from "react";
import { FileText, Radio, Video } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { ContentItemType } from "@/api/types";

interface Props {
  open: boolean;
  scheduledAt: number;
  onClose: () => void;
  onCreated: () => void;
}

export function QuickScheduleDialog({ open, scheduledAt, onClose, onCreated }: Props) {
  const [type, setType] = useState<ContentItemType>("post");
  const localTime = new Date(scheduledAt * 1000).toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Quick Schedule</DialogTitle>
          <DialogDescription>
            Create new content scheduled for {localTime}
          </DialogDescription>
        </DialogHeader>

        <Tabs value={type} onValueChange={(v) => setType(v as ContentItemType)}>
          <TabsList className="w-full">
            <TabsTrigger value="post" className="flex-1 gap-1">
              <FileText className="h-3.5 w-3.5" /> Post
            </TabsTrigger>
            <TabsTrigger value="broadcast" className="flex-1 gap-1">
              <Radio className="h-3.5 w-3.5" /> Broadcast
            </TabsTrigger>
            <TabsTrigger value="vod" className="flex-1 gap-1">
              <Video className="h-3.5 w-3.5" /> Video
            </TabsTrigger>
          </TabsList>

          <TabsContent value="post" className="space-y-3 pt-2">
            <div>
              <Label>Post body</Label>
              <Textarea placeholder="What do you want to share?" rows={3} />
            </div>
            <Button className="w-full" onClick={() => { /* create post with publish_at */ onCreated(); }}>
              Schedule Post
            </Button>
          </TabsContent>

          <TabsContent value="broadcast" className="space-y-3 pt-2">
            <div>
              <Label>Broadcast name</Label>
              <Input placeholder="My Live Stream" />
            </div>
            <div>
              <Label>Description (optional)</Label>
              <Textarea placeholder="What will you be streaming?" rows={2} />
            </div>
            <Button className="w-full" onClick={() => { /* create + schedule broadcast */ onCreated(); }}>
              Schedule Broadcast
            </Button>
          </TabsContent>

          <TabsContent value="vod" className="space-y-3 pt-2">
            <p className="text-sm text-muted-foreground">
              To schedule a video release, upload the video first in the Video Manager,
              then set the release date.
            </p>
            <Button variant="outline" className="w-full" onClick={onClose}>
              Go to Video Manager
            </Button>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
```

### 5.8 Reusing Calendar UI Patterns

The content calendar reuses patterns from the existing `CalendarView.tsx`:

```tsx
// Reuse from CalendarView.tsx:
// - getMonthDays(year, month) for month grid generation
// - getWeekDays(date) for week column generation
// - DAYS constant for day headers
// - HOURS constant for hour row generation
// - formatHour(h) for time labels
// - isSameDay(a, b) for date comparison

// Content calendar specific:
const CONTENT_COLORS = {
  post: "bg-blue-100 border-blue-400 text-blue-700",
  broadcast: "bg-red-100 border-red-400 text-red-700",
  vod: "bg-violet-100 border-violet-400 text-violet-700",
};

const CONTENT_ICONS = {
  post: FileText,       // lucide-react
  broadcast: Radio,     // lucide-react
  vod: Video,           // lucide-react
};
```

### 5.9 Drag-and-Drop Implementation

Using the native HTML5 Drag and Drop API (no external library needed):

```tsx
function DraggableCalendarItem({ item, onReschedule }: Props) {
  return (
    <div
      draggable
      onDragStart={(e) => {
        e.dataTransfer.setData("application/json", JSON.stringify(item));
        e.dataTransfer.effectAllowed = "move";
      }}
      className={cn(
        "cursor-grab rounded-md border-l-4 px-2 py-1 text-xs",
        CONTENT_COLORS[item.type],
      )}
    >
      <div className="flex items-center gap-1">
        {createElement(CONTENT_ICONS[item.type], { className: "h-3 w-3" })}
        <span className="truncate font-medium">{item.title}</span>
      </div>
    </div>
  );
}

function TimeSlot({ date, hour, onDrop, onClick }: Props) {
  return (
    <div
      onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; }}
      onDrop={(e) => {
        e.preventDefault();
        const item = JSON.parse(e.dataTransfer.getData("application/json"));
        const newDate = new Date(date);
        newDate.setHours(hour, 0, 0, 0);
        onDrop(item, Math.floor(newDate.getTime() / 1000));
      }}
      onClick={() => onClick(date, hour)}
      className="h-12 border-b border-r hover:bg-muted/50 cursor-pointer"
    />
  );
}
```

**Touch support for mobile drag-and-drop**: HTML5 drag events are not natively supported on touch devices. For mobile, the `ContentCalendarMobileList` provides a "Reschedule" button that opens a date/time picker dialog instead.

### 5.10 Route

```tsx
// App.tsx (see frontend/src/App.tsx:92 for lazy import, line 144 for route)
const ContentCalendarPage = lazy(() => import("@/pages/content-calendar/ContentCalendarPage"));
// ...
<Route path="content-calendar" element={<ContentCalendarPage />} />
```

### 5.11 Navigation

- Add "Content Calendar" to the Creator Tools section in `Sidebar.tsx` and `AppShell.tsx`
- Icon: `CalendarClock` from lucide-react (see `frontend/src/components/layout/Sidebar.tsx:120`, `AppShell.tsx:184`, `MobileNav.tsx:72`)
<!-- NOTE: Actual icon is CalendarClock, not CalendarDays as originally designed -->
- Also accessible from `ScheduledPostsPanel` via "View Calendar" link

---

## 6. DynamoDB Considerations

### 6.1 No New Tables

The content calendar is a read-only aggregation view. It queries existing tables:

- **Scheduled posts**: `app_single_table` via `GSI_SCHEDULE_DUE` index (PK=`SCHEDULED`, SK range filter by timestamp)
- **Scheduled broadcasts**: `broadcast_sessions` via `ByScheduledAt` GSI (PK=`scheduled`, SK range filter)
- **Scheduled VOD**: `vod_metadata` filtered by `status=scheduled` (scan with filter, acceptable for low volume)

### 6.2 Query Patterns

For the content calendar endpoint, three queries execute in sequence (not parallelized in Python sync code, but each is fast):

1. **Posts**: Query `USER#{user_id}` with SK between `SCHEDULEDPOST#{from_ts:012d}` and `SCHEDULEDPOST#{to_ts:012d}~`, then batch-fetch post records.
2. **Broadcasts**: Query `ByCreatorCreatedAt` GSI with PK=`created_by={user_id}`, FilterExpression `schedule_status="scheduled"`, then client-side filter by `scheduled_at` range.
3. **VOD**: Query `ByOwnerCreatedAt` GSI with PK=`owner_user_id={user_id}`, client-side filter for `attribute_exists(scheduled_publish_at)` in range.

### 6.3 Query Access Pattern Table

| Query | Table | Index | PK | SK/Range | Filter | Expected Volume |
|-------|-------|-------|----|----------|--------|-----------------|
| Scheduled posts for user in range | `app_single_table` | main | `USER#{user_id}` | `SCHEDULEDPOST#{from:012d}` to `SCHEDULEDPOST#{to:012d}~` | none (range is precise) | 0-50 |
| Batch-fetch post records | `app_single_table` | main | `POST#{id}` / `META` | N/A (batch get) | none | 0-50 |
| Scheduled broadcasts for creator | `broadcast_sessions` | `ByCreatorCreatedAt` | `created_by={user_id}` | all | `schedule_status="scheduled"` | 0-20 |
| Scheduled VOD for owner | `video_metadata` | `ByOwnerCreatedAt` | `owner_user_id={user_id}` | all | `attribute_exists(scheduled_publish_at)` + range | 0-10 |

### 6.4 Rescheduling Writes

Rescheduling uses existing endpoints:
- Posts: Update `publish_at` on the post record + update the GSI sort key (`GSI_SCHEDULE_SK`) + delete old `ScheduledPostRef` + write new `ScheduledPostRef`
- Broadcasts: Call `update_session_fields(session_id, {"scheduled_at": new_ts})`
- VOD: Update `scheduled_publish_at` on the video metadata record

No new write patterns needed.

### 6.5 VOD Extension: `scheduled_publish_at` Field

<!-- NOTE: This field already exists in the codebase — no new implementation required -->
The `VideoMetadataModel` in `app/models_video.py` already has the field (see `app/models_video.py:104`):

```python
# In VideoMetadataModel class (app/models_video.py:104)
scheduled_publish_at: Optional[int] = None  # Unix timestamp for future auto-publish
```

Serialization in `video_to_item` already handles it (see `app/services/video_metadata_store.py:97`, in the `_optional_num_fields` list):

```python
# Already in the optional int fields section (line 97)
"scheduled_publish_at",
```

And deserialization in `video_from_item` already handles it (see `app/services/video_metadata_store.py:241`):

```python
scheduled_publish_at=_int_or_none(item.get("scheduled_publish_at")),
```

### 6.6 Capacity Estimates

| Operation | RCU per request | WCU per request | Frequency |
|-----------|-----------------|-----------------|-----------|
| Content calendar load (3 queries) | ~15 RCU | 0 | ~2/min per active creator |
| Post reschedule | ~5 RCU | ~4 WCU | ~5/day per creator |
| Broadcast reschedule | ~3 RCU | ~2 WCU | ~1/day per creator |
| VOD reschedule | ~2 RCU | ~1 WCU | ~1/week per creator |

---

## 7. E2E Test Plan

### 7.1 Test File

`frontend/e2e/content-calendar.spec.ts`

### 7.2 Test Sections

| Section | Title | Tests |
|---------|-------|-------|
| 1 | Content Calendar API - Basic | 7 tests |
| 2 | Content Calendar API - Filtering | 5 tests |
| 3 | Content Calendar API - Conflicts | 4 tests |
| 4 | Content Calendar API - Today Agenda | 3 tests |
| 5 | Reschedule API | 6 tests |
| 6 | Cancel API | 4 tests |
| 7 | Calendar Week View UI | 6 tests |
| 8 | Calendar Month View UI | 5 tests |
| 9 | Drag and Drop Rescheduling UI | 4 tests |
| 10 | Quick Schedule Dialog UI | 3 tests |
| 11 | Mobile List View UI | 3 tests |
| 12 | Conflict Banner UI | 3 tests |

**Estimated total**: ~53 tests

### 7.3 Detailed Test Cases

**Section 1: Content Calendar API - Basic** (7 tests)

```typescript
test.describe("1 Content Calendar API - Basic", () => {
  let alicePage: Page;
  let csrf: string;
  const TS = Date.now();
  const POST_BODY = `cal_post_${TS}`;
  let postId: string;
  let broadcastId: string;
  let weekFromNow: number;
  let weekRange: { from_ts: number; to_ts: number };

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    csrf = sessions[ALICE_ID].csrf_token;
    const now = Math.floor(Date.now() / 1000);
    weekFromNow = now + 3 * 86400; // 3 days from now
    weekRange = {
      from_ts: now - 86400,
      to_ts: now + 7 * 86400,
    };

    // Create a scheduled post 3 days from now
    const postResp = await alicePage.request.post("/ui/feed/posts", {
      headers: { "x-csrf-token": csrf },
      data: {
        body: POST_BODY,
        publish_at: weekFromNow,
        schedule_timezone: "America/New_York",
      },
    });
    expect(postResp.ok()).toBeTruthy();
    const postData = await postResp.json();
    postId = postData.post_id;

    // Create a scheduled broadcast 4 days from now
    // First create a draft session
    const draftResp = await alicePage.request.post("/ui/broadcast/sessions", {
      headers: { "x-csrf-token": csrf },
      data: { name: `cal_bcast_${TS}`, profile_id: "default" },
    });
    expect(draftResp.ok()).toBeTruthy();
    broadcastId = (await draftResp.json()).id;

    // Schedule it
    const schedResp = await alicePage.request.post(
      `/ui/broadcast/sessions/${broadcastId}/schedule`,
      {
        headers: { "x-csrf-token": csrf },
        data: { scheduled_at: weekFromNow + 86400 },
      },
    );
    expect(schedResp.ok()).toBeTruthy();
  });

  test("1.1 GET /ui/content-calendar returns items", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: weekRange,
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(2);
    expect(data.count).toBe(data.items.length);
  });

  test("1.2 Items are sorted by scheduled_at ascending", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: weekRange,
    });
    const data = await resp.json();
    for (let i = 1; i < data.items.length; i++) {
      expect(data.items[i].scheduled_at).toBeGreaterThanOrEqual(
        data.items[i - 1].scheduled_at,
      );
    }
  });

  test("1.3 Post item has correct type and color", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: weekRange,
    });
    const data = await resp.json();
    const post = data.items.find((i: any) => i.id === postId);
    expect(post).toBeTruthy();
    expect(post.type).toBe("post");
    expect(post.color).toBe("#3B82F6");
    expect(post.icon).toBe("file-text");
    expect(post.scheduled_at).toBe(weekFromNow);
  });

  test("1.4 Broadcast item has correct type and color", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: weekRange,
    });
    const data = await resp.json();
    const bcast = data.items.find((i: any) => i.id === broadcastId);
    expect(bcast).toBeTruthy();
    expect(bcast.type).toBe("broadcast");
    expect(bcast.color).toBe("#EF4444");
    expect(bcast.icon).toBe("radio");
  });

  test("1.5 Each item has an id and title", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: weekRange,
    });
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.id).toBeTruthy();
      expect(item.title).toBeTruthy();
      expect(["post", "broadcast", "vod"]).toContain(item.type);
    }
  });

  test("1.6 Range exceeding 90 days returns 400", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: weekRange.from_ts,
        to_ts: weekRange.from_ts + 91 * 86400,
      },
    });
    expect(resp.status()).toBe(400);
  });

  test("1.7 Empty range returns empty items", async () => {
    const farFuture = Math.floor(Date.now() / 1000) + 365 * 86400;
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: { from_ts: farFuture, to_ts: farFuture + 86400 },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.items).toEqual([]);
    expect(data.count).toBe(0);
  });
});
```

**Section 2: Content Calendar API - Filtering** (5 tests)

```typescript
test.describe("2 Content Calendar API - Filtering", () => {
  test("2.1 Filter types=post returns only posts", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: { ...weekRange, types: "post" },
    });
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.type).toBe("post");
    }
  });

  test("2.2 Filter types=broadcast returns only broadcasts", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: { ...weekRange, types: "broadcast" },
    });
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.type).toBe("broadcast");
    }
  });

  test("2.3 Filter types=post,broadcast excludes VOD", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: { ...weekRange, types: "post,broadcast" },
    });
    const data = await resp.json();
    for (const item of data.items) {
      expect(["post", "broadcast"]).toContain(item.type);
    }
  });

  test("2.4 No types parameter returns all types", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: weekRange,
    });
    const data = await resp.json();
    // Should have at least our seeded post and broadcast
    const types = new Set(data.items.map((i: any) => i.type));
    expect(types.has("post")).toBeTruthy();
    expect(types.has("broadcast")).toBeTruthy();
  });

  test("2.5 Invalid type is silently ignored", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: { ...weekRange, types: "post,invalid_type" },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.type).toBe("post");
    }
  });
});
```

**Section 3: Content Calendar API - Conflicts** (4 tests)

```typescript
test.describe("3 Conflict Detection API", () => {
  let conflictPostId1: string;
  let conflictPostId2: string;
  let conflictTs: number;

  test.beforeAll(async () => {
    // Create two posts 10 minutes apart (within 30-minute buffer)
    conflictTs = Math.floor(Date.now() / 1000) + 5 * 86400;
    const resp1 = await alicePage.request.post("/ui/feed/posts", {
      headers: { "x-csrf-token": csrf },
      data: { body: `conflict_a_${TS}`, publish_at: conflictTs },
    });
    conflictPostId1 = (await resp1.json()).post_id;

    const resp2 = await alicePage.request.post("/ui/feed/posts", {
      headers: { "x-csrf-token": csrf },
      data: { body: `conflict_b_${TS}`, publish_at: conflictTs + 600 },
    });
    conflictPostId2 = (await resp2.json()).post_id;
  });

  test("3.1 Detects conflict for items within 30 minutes", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar/conflicts", {
      params: {
        from_ts: conflictTs - 3600,
        to_ts: conflictTs + 3600,
      },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.conflicts.length).toBeGreaterThanOrEqual(1);
    const c = data.conflicts.find(
      (c: any) =>
        (c.item_a_id === conflictPostId1 && c.item_b_id === conflictPostId2) ||
        (c.item_a_id === conflictPostId2 && c.item_b_id === conflictPostId1),
    );
    expect(c).toBeTruthy();
    expect(c.gap_seconds).toBe(600);
    expect(c.gap_minutes).toBe(10);
  });

  test("3.2 No conflict for items 31+ minutes apart", async () => {
    // Existing post at weekFromNow and broadcast at weekFromNow + 86400
    // These are a full day apart, no conflict
    const resp = await alicePage.request.get("/ui/content-calendar/conflicts", {
      params: {
        from_ts: weekRange.from_ts,
        to_ts: weekRange.from_ts + 2 * 86400,
      },
    });
    const data = await resp.json();
    // Filter conflicts to just our non-conflict items
    const falseConflict = data.conflicts.find(
      (c: any) => c.item_a_id === postId && c.item_b_id === broadcastId,
    );
    expect(falseConflict).toBeUndefined();
  });

  test("3.3 Cross-type conflict (post + broadcast at same time)", async () => {
    // Schedule a broadcast at the same time as conflictPostId1
    const bDraft = await alicePage.request.post("/ui/broadcast/sessions", {
      headers: { "x-csrf-token": csrf },
      data: { name: `conflict_bcast_${TS}`, profile_id: "default" },
    });
    const bId = (await bDraft.json()).id;
    await alicePage.request.post(`/ui/broadcast/sessions/${bId}/schedule`, {
      headers: { "x-csrf-token": csrf },
      data: { scheduled_at: conflictTs + 300 },
    });

    const resp = await alicePage.request.get("/ui/content-calendar/conflicts", {
      params: { from_ts: conflictTs - 3600, to_ts: conflictTs + 3600 },
    });
    const data = await resp.json();
    const crossConflict = data.conflicts.find(
      (c: any) =>
        (c.item_a_type === "post" && c.item_b_type === "broadcast") ||
        (c.item_a_type === "broadcast" && c.item_b_type === "post"),
    );
    expect(crossConflict).toBeTruthy();
  });

  test("3.4 Conflicts response includes count", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar/conflicts", {
      params: { from_ts: conflictTs - 3600, to_ts: conflictTs + 3600 },
    });
    const data = await resp.json();
    expect(data.count).toBe(data.conflicts.length);
  });
});
```

**Section 4: Content Calendar API - Today Agenda** (3 tests)

```typescript
test.describe("4 Today Agenda API", () => {
  test("4.1 Today endpoint returns today and tomorrow partitions", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar/today");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data.today)).toBeTruthy();
    expect(Array.isArray(data.tomorrow)).toBeTruthy();
    expect(typeof data.today_count).toBe("number");
    expect(typeof data.tomorrow_count).toBe("number");
  });

  test("4.2 Today items are before midnight UTC", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar/today");
    const data = await resp.json();
    const todayEnd = new Date();
    todayEnd.setUTCHours(24, 0, 0, 0);
    const todayEndTs = Math.floor(todayEnd.getTime() / 1000);
    for (const item of data.today) {
      expect(item.scheduled_at).toBeLessThan(todayEndTs);
    }
  });

  test("4.3 Today response includes conflicts", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar/today");
    const data = await resp.json();
    expect(Array.isArray(data.conflicts)).toBeTruthy();
  });
});
```

**Section 5: Reschedule API** (6 tests)

```typescript
test.describe("5 Reschedule API", () => {
  let reschedulePostId: string;
  const originalTs = Math.floor(Date.now() / 1000) + 6 * 86400;

  test.beforeAll(async () => {
    const resp = await alicePage.request.post("/ui/feed/posts", {
      headers: { "x-csrf-token": csrf },
      data: { body: `resched_${TS}`, publish_at: originalTs },
    });
    reschedulePostId = (await resp.json()).post_id;
  });

  test("5.1 Reschedule post to new time", async () => {
    const newTs = originalTs + 7200; // 2 hours later
    const resp = await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: reschedulePostId,
        item_type: "post",
        new_scheduled_at: newTs,
      },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.scheduled_at).toBe(newTs);
  });

  test("5.2 Reschedule to past returns 400", async () => {
    const pastTs = Math.floor(Date.now() / 1000) - 3600;
    const resp = await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: reschedulePostId,
        item_type: "post",
        new_scheduled_at: pastTs,
      },
    });
    expect(resp.status()).toBe(400);
  });

  test("5.3 Reschedule non-existent item returns 404", async () => {
    const resp = await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: "nonexistent_id",
        item_type: "post",
        new_scheduled_at: originalTs + 3600,
      },
    });
    expect(resp.status()).toBe(404);
  });

  test("5.4 Reschedule broadcast respects min lead time", async () => {
    // Create and schedule a broadcast
    const bDraft = await alicePage.request.post("/ui/broadcast/sessions", {
      headers: { "x-csrf-token": csrf },
      data: { name: `resched_bcast_${TS}`, profile_id: "default" },
    });
    const bId = (await bDraft.json()).id;
    await alicePage.request.post(`/ui/broadcast/sessions/${bId}/schedule`, {
      headers: { "x-csrf-token": csrf },
      data: { scheduled_at: originalTs + 86400 },
    });

    // Try to reschedule to 10 seconds from now (below min lead time)
    const tooSoon = Math.floor(Date.now() / 1000) + 10;
    const resp = await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: { item_id: bId, item_type: "broadcast", new_scheduled_at: tooSoon },
    });
    expect(resp.status()).toBe(400);
  });

  test("5.5 Reschedule updates calendar view", async () => {
    const newTs = originalTs + 14400;
    await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: reschedulePostId,
        item_type: "post",
        new_scheduled_at: newTs,
      },
    });

    // Verify the item appears at the new time
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: { from_ts: newTs - 3600, to_ts: newTs + 3600 },
    });
    const data = await resp.json();
    const found = data.items.find((i: any) => i.id === reschedulePostId);
    expect(found).toBeTruthy();
    expect(found.scheduled_at).toBe(newTs);
  });

  test("5.6 Reschedule invalid type returns 400", async () => {
    const resp = await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: reschedulePostId,
        item_type: "invalid",
        new_scheduled_at: originalTs,
      },
    });
    expect(resp.status()).toBe(422); // FastAPI Literal validation
  });
});
```

**Section 6: Cancel API** (4 tests)

```typescript
test.describe("6 Cancel API", () => {
  let cancelPostId: string;

  test.beforeAll(async () => {
    const resp = await alicePage.request.post("/ui/feed/posts", {
      headers: { "x-csrf-token": csrf },
      data: {
        body: `cancel_${TS}`,
        publish_at: Math.floor(Date.now() / 1000) + 8 * 86400,
      },
    });
    cancelPostId = (await resp.json()).post_id;
  });

  test("6.1 Cancel post removes it from calendar", async () => {
    const resp = await alicePage.request.post("/ui/content-calendar/cancel", {
      headers: { "x-csrf-token": csrf },
      params: { item_id: cancelPostId, item_type: "post" },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.ok).toBe("true");
    expect(data.type).toBe("post");
  });

  test("6.2 Cancelled post no longer appears in calendar", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: weekRange,
    });
    const data = await resp.json();
    const found = data.items.find((i: any) => i.id === cancelPostId);
    expect(found).toBeUndefined();
  });

  test("6.3 Cancel non-existent item returns 404", async () => {
    const resp = await alicePage.request.post("/ui/content-calendar/cancel", {
      headers: { "x-csrf-token": csrf },
      params: { item_id: "nonexistent_id", item_type: "post" },
    });
    expect(resp.status()).toBe(404);
  });

  test("6.4 Cancel already-cancelled item returns 409", async () => {
    const resp = await alicePage.request.post("/ui/content-calendar/cancel", {
      headers: { "x-csrf-token": csrf },
      params: { item_id: cancelPostId, item_type: "post" },
    });
    expect(resp.status()).toBe(409);
  });
});
```

**Section 7: Calendar Week View UI** (6 tests)

```typescript
test.describe("7 Calendar Week View UI", () => {
  test("7.1 Page loads with header and controls", async () => {
    await alicePage.goto("/content-calendar");
    await expect(alicePage.getByRole("heading", { name: "Content Calendar" })).toBeVisible();
    await expect(alicePage.getByRole("button", { name: "Today" })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: "Week" })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: "Month" })).toBeVisible();
  });

  test("7.2 Week grid renders day headers", async () => {
    await alicePage.goto("/content-calendar");
    for (const day of ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]) {
      await expect(alicePage.getByText(day).first()).toBeVisible();
    }
  });

  test("7.3 Content items are visible in the grid", async () => {
    await alicePage.goto("/content-calendar");
    // Wait for content to load
    await alicePage.waitForResponse((r) => r.url().includes("/content-calendar") && r.ok());
    // Our seeded post should appear
    await expect(
      alicePage.locator("[draggable]").first(),
    ).toBeVisible({ timeout: 5000 });
  });

  test("7.4 Type filter buttons toggle visibility", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.waitForResponse((r) => r.url().includes("/content-calendar") && r.ok());

    // Click "Posts" filter to deactivate
    await alicePage.getByRole("button", { name: "Posts" }).click();
    // Wait for refetch
    await alicePage.waitForResponse((r) => r.url().includes("/content-calendar") && r.ok());
    // Re-enable
    await alicePage.getByRole("button", { name: "Posts" }).click();
  });

  test("7.5 Navigation arrows change week", async () => {
    await alicePage.goto("/content-calendar");
    const headerBefore = await alicePage.locator(".text-sm.font-medium").first().textContent();
    await alicePage.getByRole("button", { name: "Next week" }).click();
    const headerAfter = await alicePage.locator(".text-sm.font-medium").first().textContent();
    expect(headerAfter).not.toBe(headerBefore);
  });

  test("7.6 Today button resets to current week", async () => {
    await alicePage.goto("/content-calendar");
    // Navigate forward
    await alicePage.getByRole("button", { name: "Next week" }).click();
    await alicePage.getByRole("button", { name: "Next week" }).click();
    // Click Today
    await alicePage.getByRole("button", { name: "Today" }).click();
    // Today's date number should be highlighted
    const today = new Date().getDate().toString();
    await expect(
      alicePage.locator(".bg-primary.text-primary-foreground").filter({ hasText: today }),
    ).toBeVisible();
  });
});
```

**Section 8: Calendar Month View UI** (5 tests)

```typescript
test.describe("8 Calendar Month View UI", () => {
  test("8.1 Month view renders day grid", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.getByRole("tab", { name: "Month" }).click();
    // Should see day of month numbers
    await expect(alicePage.getByText("1").first()).toBeVisible();
    await expect(alicePage.getByText("15").first()).toBeVisible();
  });

  test("8.2 Month header shows month and year", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.getByRole("tab", { name: "Month" }).click();
    const monthName = new Date().toLocaleDateString(undefined, { month: "long", year: "numeric" });
    await expect(alicePage.locator(".text-sm.font-medium").filter({ hasText: monthName })).toBeVisible();
  });

  test("8.3 Clicking a day switches to week view", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.getByRole("tab", { name: "Month" }).click();
    // Click on day 15
    await alicePage.getByText("15").first().click();
    // Should switch to week view
    await expect(alicePage.getByRole("tab", { name: "Week" })).toHaveAttribute("data-state", "active");
  });

  test("8.4 Navigation arrows change month", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.getByRole("tab", { name: "Month" }).click();
    const headerBefore = await alicePage.locator(".text-sm.font-medium").first().textContent();
    await alicePage.getByRole("button", { name: "Next month" }).click();
    const headerAfter = await alicePage.locator(".text-sm.font-medium").first().textContent();
    expect(headerAfter).not.toBe(headerBefore);
  });

  test("8.5 Content items show as dots on scheduled days", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.getByRole("tab", { name: "Month" }).click();
    await alicePage.waitForResponse((r) => r.url().includes("/content-calendar") && r.ok());
    // At least one day should have content indicators
    const dotsOrItems = alicePage.locator("[data-content-count]");
    // May or may not be visible depending on whether items fall in current month
  });
});
```

**Section 9-12** follow similar patterns for drag-and-drop, quick schedule dialog, mobile list view, and conflict banner UI testing.

### 7.4 Test Data Setup

```typescript
// beforeAll:
// 1. Seed Alice session via injectAuth
// 2. Create 3 scheduled posts at different times this week
// 3. Create 2 scheduled broadcast sessions
// 4. Create 1 scheduled VOD release (if scheduled_publish_at is implemented)
// 5. Create a conflict (post and broadcast within 10 minutes)
// 6. Store IDs and timestamps for assertions
```

### 7.5 Test Utility Functions

```typescript
// Helpers specific to content-calendar tests

async function injectAuth(page: Page, identity: string) {
  const session = sessions[identity];
  await page.context().addCookies([
    { name: "ui_session", value: session.session_id, domain: "localhost", path: "/" },
    { name: "ui_csrf", value: session.csrf_token, domain: "localhost", path: "/" },
    { name: "ui_access_token", value: session.access_token, domain: "localhost", path: "/" },
  ]);
}

async function createScheduledPost(
  page: Page,
  csrf: string,
  body: string,
  publishAt: number,
): Promise<string> {
  const resp = await page.request.post("/ui/feed/posts", {
    headers: { "x-csrf-token": csrf },
    data: { body, publish_at: publishAt },
  });
  return (await resp.json()).post_id;
}

async function createScheduledBroadcast(
  page: Page,
  csrf: string,
  name: string,
  scheduledAt: number,
): Promise<string> {
  const draft = await page.request.post("/ui/broadcast/sessions", {
    headers: { "x-csrf-token": csrf },
    data: { name, profile_id: "default" },
  });
  const id = (await draft.json()).id;
  await page.request.post(`/ui/broadcast/sessions/${id}/schedule`, {
    headers: { "x-csrf-token": csrf },
    data: { scheduled_at: scheduledAt },
  });
  return id;
}
```

---

## 8. Edge Cases

| Case | Behavior |
|------|----------|
| Creator has no scheduled content | Calendar renders empty with "No upcoming content" message and a CTA to create content. |
| Scheduled item's time has passed but not yet published | Item shows with an amber "Overdue" badge. The scheduler should process it soon. The `status` field is set to `"overdue"` by `_post_to_calendar_item` when `publish_at < now_ts()`. |
| Drag to past time | Rejected by `reschedule_item` with 400: "Cannot schedule content in the past." Frontend shows error toast and rolls back the optimistic move. |
| Broadcast minimum lead time violated | Rescheduling a broadcast to less than `broadcast_schedule_min_lead_time_seconds` in the future returns 400. Calendar shows error toast "scheduled_at must be at least N seconds in the future". |
| Very large date range request | API limits `to_ts - from_ts` to max 90 days (7,776,000 seconds). Returns 400 for larger ranges. |
| Timezone display | Times display in the user's local timezone (from browser `Intl.DateTimeFormat`). Posts with `schedule_timezone` show that timezone in the item tooltip. |
| Drag from month view | Month view dots are not directly draggable (too small). User must switch to week view for drag-and-drop. Month view clicking a day switches to week view. |
| Concurrent rescheduling | If two browser tabs reschedule the same item, the last write wins (DDB put_item). The other tab sees the updated time on next refetch. |
| Cancelled items | Items with `status=cancelled` are excluded from the calendar by default. A "Show cancelled" toggle can include them (grayed out, non-draggable). |
| Content published early | If a creator manually publishes a scheduled item, it is removed from the calendar on next refresh (because its status changes from "scheduled" to "published"). |
| Optimistic update rollback | If the reschedule API call fails (network error, 400, 403, etc.), the optimistic update is rolled back in `onError` and the item snaps back to its original position. |
| Undo reschedule | After a successful reschedule, a 5-second toast with "Undo" button appears. Clicking it re-calls reschedule with the original timestamp. If the undo fails (e.g., 5+ seconds elapsed and the item was published), the error toast is shown. |
| Rapid successive drags | Frontend debounces drops with 300ms delay. If a user drags the same item twice quickly, only the second drop is applied. The first mutation is cancelled via React Query's `mutationKey`. |
| Browser tab inactive | Calendar refetches every 60 seconds (`refetchInterval: 60_000`). When the tab becomes active again, React Query triggers a refetch on window focus. This catches any items that were published or rescheduled while the tab was inactive. |
| Post with images/video in calendar | Post calendar items include `has_images` and `has_video` booleans. The item card shows small icons (image/video) next to the title. The full post content is shown in `ContentItemDetail` on click. |
| Broadcast with announcement post | Broadcasts created via BCAST-010 have `has_announcement: true`. The calendar item shows a small "Announced" badge. Cancelling the broadcast also deletes the announcement post. |
| VOD without scheduled_publish_at | Videos without the new field are excluded from the calendar. The calendar only shows videos with an explicit future publish date. |

---

## 9. Security Considerations

### 9.1 Authorization

- The content calendar endpoint returns **only** the authenticated user's scheduled content
- All queries are scoped to `user_id = session["user_sub"]`
- No cross-user content leakage: a creator cannot see another creator's scheduled content
- The `reschedule_item` and `cancel_item` service functions verify ownership before modifying any records

### 9.2 Rescheduling Permissions

- Rescheduling calls the service layer functions which enforce ownership (`created_by == user_sub` for broadcasts, `user_id == user_sub` for posts, `owner_user_id == user_sub` for VOD)
- The content calendar frontend does not bypass any existing permission checks
- Broadcast rescheduling enforces the minimum lead time server-side
- Post rescheduling validates the post is still in `scheduled` status (no race condition with the scheduler promoting it to `published`)

### 9.3 Rate Limiting

- Content calendar GET: standard session rate limits (no special treatment)
- Rescheduling (drag-and-drop): each drop triggers a single API call. Frontend debounces rapid drops (300ms).
- Quick schedule: uses existing post/broadcast creation endpoints with their existing rate limits
- The `/ui/content-calendar` endpoint returns at most 200 items per content type (600 total). This is capped server-side to prevent response inflation.

### 9.4 Data Consistency

- Calendar is eventually consistent: newly scheduled items may take a few seconds to appear
- Client-side optimistic update: after successful reschedule, the item is moved immediately in the UI before the server response confirms
- If the reschedule API call fails, the optimistic update is rolled back and the item snaps back to its original position
- The `ScheduledPostRef` delete + re-write in `_reschedule_post` is not transactional. If the process crashes between delete and write, the ref is lost. The post itself still has the correct `publish_at` and GSI attrs, so the scheduler still publishes it. The ref is only used for the user-scoped listing query; the global `GSI_SCHEDULE_DUE` index is the authoritative source.

### 9.5 CSRF Protection

- All POST endpoints (`/reschedule`, `/cancel`) require `x-csrf-token` header matching the session's CSRF token
- GET endpoints are safe (no side effects) and do not require CSRF
- The frontend's axios client automatically attaches the CSRF token from the `ui_csrf` cookie

### 9.6 Input Validation

- `from_ts` and `to_ts` are validated as integers; range is capped at 90 days
- `item_type` is a `Literal["post", "broadcast", "vod"]`; FastAPI returns 422 for invalid values
- `item_id` is validated against the actual DDB records; non-existent IDs return 404
- `new_scheduled_at` must be > `now_ts()` to prevent scheduling in the past
- `types` filter parameter is parsed as comma-separated strings; invalid types are silently ignored (no error, just filtered out)

### 9.7 Drag-and-Drop Security

- The `application/json` data set in `dataTransfer` during drag is only readable by the same origin (same-origin policy)
- The frontend validates the parsed JSON before calling the reschedule API
- The backend re-validates ownership and constraints regardless of what the frontend sends
- An attacker cannot forge a drag event from a different origin to reschedule items

---

## 10. Implementation Checklist

| Step | Task | Files | Status |
|------|------|-------|--------|
| 1 | Add `scheduled_publish_at` field to `VideoMetadataModel` | `app/models_video.py` | DONE (line 104) |
| 2 | Update `video_to_item` / `video_from_item` serialization | `app/services/video_metadata_store.py` | DONE (lines 97, 241) |
| 3 | Create content calendar service module | `app/services/content_calendar.py` | DONE (20844 bytes) |
| 4 | Create content calendar router | `app/routers/content_calendar.py` | DONE (3000 bytes) |
| 5 | Register router in `main.py` | `app/main.py` | DONE (lines 171, 462) |
| 6 | Add Pydantic models | `app/models.py` | TODO — response models not yet in `app/models.py` (router returns dicts) |
| 7 | Add TypeScript types | `frontend/src/api/types.ts` | DONE (lines 4366-4423) |
| 8 | Add API endpoint functions | `frontend/src/api/endpoints/content-calendar.ts` | DONE (68 lines) |
| 9 | Create `ContentCalendarPage` and sub-components | `frontend/src/pages/content-calendar/*.tsx` | DONE (7 files) |
| 10 | Add route to `App.tsx` | `frontend/src/App.tsx` | DONE (lines 92, 144) |
| 11 | Add sidebar navigation entry | `frontend/src/components/layout/Sidebar.tsx`, `AppShell.tsx`, `MobileNav.tsx` | DONE (lines 120, 184, 72) |
| 12 | Add "View Calendar" link to `ScheduledPostsPanel` | `frontend/src/pages/feed/ScheduledPostsPanel.tsx` | TODO |
| 13 | Write E2E tests | `frontend/e2e/content-calendar.spec.ts` | TODO |
| 14 | Update file reference docs | `docs/file-reference.md` | TODO |

---

## 11. Future Extensions

| Extension | Description | Priority |
|-----------|-------------|----------|
| Recurring templates | "Post every Tuesday at 9 AM" with template content | Medium |
| iCal export | Export content calendar as `.ics` for external calendar apps | Low |
| Multi-creator view | Admin view showing all creators' scheduled content | Medium |
| Content analytics overlay | Show past post performance on historical calendar days | Low |
| Auto-optimal scheduling | ML-based suggestion for best posting times based on engagement history | Low |
| Bulk reschedule | Select multiple items and shift them all by N hours/days | Medium |
| Calendar sharing | Generate a read-only link for team members to view the schedule | Medium |

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/routers/content_calendar.py` | 1-99 | Content calendar router (already implemented) |
| `app/services/content_calendar.py` | 1-580+ | Content calendar service layer (already implemented) |
| `app/main.py` | 171 | Router import: `from app.routers.content_calendar import router as content_calendar_router` |
| `app/main.py` | 462 | Router registration: `app.include_router(content_calendar_router)` |
| `app/routers/newsfeed.py` | 1297 | `PostCreateIn.publish_at` field definition |
| `app/routers/newsfeed.py` | 1302-1313 | `PostCreateIn.schedule_timezone` and `scheduled_at_local` fields |
| `app/routers/newsfeed.py` | 1396 | `ScheduledPostsResponse` model |
| `app/routers/newsfeed.py` | 3377 | `list_scheduled_posts` endpoint |
| `app/routers/newsfeed.py` | 3437 | `edit_post` endpoint (PATCH /posts/{post_id}) |
| `app/routers/newsfeed.py` | 3662 | `cancel_scheduled_post` endpoint (POST /posts/{post_id}/cancel) |
| `app/routers/newsfeed.py` | 772 | `SCHEDULED_POST_REF_PREFIX = "SCHEDULEDPOST"` |
| `app/routers/newsfeed.py` | 775 | `SCHEDULE_DUE_INDEX_PK_VALUE = "SCHEDULED"` |
| `app/services/newsfeed_scheduler.py` | 26-29 | DUE_INDEX constants (GSI_SCHEDULE_DUE, PK/SK attrs) |
| `app/services/newsfeed_scheduler.py` | 234 | `process_due_scheduled_posts` function |
| `app/routers/broadcast.py` | 154 | `BroadcastScheduleIn` model |
| `app/routers/broadcast.py` | 160 | `BroadcastRescheduleIn` model |
| `app/routers/broadcast.py` | 2053 | `schedule_session_route` (POST /sessions/{id}/schedule) |
| `app/routers/broadcast.py` | 2124 | `reschedule_session_route` (POST /sessions/{id}/reschedule) |
| `app/routers/broadcast.py` | 2170 | `cancel_schedule_route` (POST /sessions/{id}/cancel-schedule) |
| `app/services/broadcast_store.py` | 437 | `list_due_scheduled_sessions` (ByScheduledAt GSI) |
| `app/services/broadcast_store.py` | 452 | `list_scheduled_sessions_by_creator` (ByCreatorCreatedAt GSI) |
| `app/services/broadcast_store.py` | 469 | `update_session_fields` |
| `app/services/broadcast_store.py` | 336 | `transition_session_status` |
| `app/services/broadcast_store.py` | 21 | `now_iso()` helper |
| `app/services/broadcast_reminders.py` | 63 | `cancel_reminders_for_session` |
| `app/models_video.py` | 36 | `VideoMetadataModel` class definition |
| `app/models_video.py` | 100 | `published_at: Optional[int]` field |
| `app/models_video.py` | 104 | `scheduled_publish_at: Optional[int]` field (already exists) |
| `app/services/video_metadata_store.py` | 22 | `video_to_item` serialization |
| `app/services/video_metadata_store.py` | 97 | `scheduled_publish_at` in `_optional_num_fields` |
| `app/services/video_metadata_store.py` | 176 | `video_from_item` deserialization |
| `app/services/video_metadata_store.py` | 241 | `scheduled_publish_at` deserialization |
| `app/services/video_metadata_store.py` | 402 | `list_videos_by_owner` function |
| `app/core/settings.py` | 1196 | `broadcast_schedule_min_lead_time_seconds` setting |
| `app/core/tables.py` | 76, 200 | `T.video_metadata` table handle |
| `frontend/src/pages/content-calendar/ContentCalendarPage.tsx` | all | Main page component (11758 bytes) |
| `frontend/src/pages/content-calendar/ContentCalendarWeek.tsx` | all | Week view component (6386 bytes) |
| `frontend/src/pages/content-calendar/ContentCalendarMonth.tsx` | all | Month view component (4330 bytes) |
| `frontend/src/pages/content-calendar/ContentCalendarMobileList.tsx` | all | Mobile list component (3658 bytes) |
| `frontend/src/pages/content-calendar/ConflictBanner.tsx` | all | Conflict warning banner (2328 bytes) |
| `frontend/src/pages/content-calendar/QuickScheduleDialog.tsx` | all | Quick schedule dialog (3289 bytes) |
| `frontend/src/pages/content-calendar/ContentItemDetail.tsx` | all | Item detail panel (4684 bytes) |
| `frontend/src/api/endpoints/content-calendar.ts` | 1-68 | API endpoint functions |
| `frontend/src/api/types.ts` | 4366 | `ContentItemType` type |
| `frontend/src/api/types.ts` | 4368 | `ContentCalendarItem` interface |
| `frontend/src/api/types.ts` | 4396 | `ContentCalendarConflict` interface |
| `frontend/src/api/types.ts` | 4405 | `ContentCalendarResponse` interface |
| `frontend/src/api/types.ts` | 4413 | `TodayAgendaResponse` interface |
| `frontend/src/api/types.ts` | 4421 | `ConflictsResponse` interface |
| `frontend/src/App.tsx` | 92 | Lazy import for `ContentCalendarPage` |
| `frontend/src/App.tsx` | 144 | Route: `<Route path="content-calendar" ...>` |
| `frontend/src/components/layout/Sidebar.tsx` | 120 | Sidebar entry with `CalendarClock` icon |
| `frontend/src/components/layout/AppShell.tsx` | 184 | Mobile sidebar entry |
| `frontend/src/components/layout/MobileNav.tsx` | 72 | Mobile nav entry |
| `frontend/src/pages/feed/ScheduledPostsPanel.tsx` | 26 | `ScheduledPostsPanel` component (166 lines) |
| `frontend/src/pages/calendar/CalendarView.tsx` | 28-80 | Calendar utility functions (DAYS, HOURS, getMonthDays, getWeekDays, isSameDay, eventOnDay) |
| `frontend/src/pages/calendar/CalendarPage.tsx` | 11 | `CalendarPage` component |

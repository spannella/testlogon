# SCHED-001: Unified Content Scheduling Across Modules

**Ticket**: SCHED-001
**Author**: Engineering
**Status**: Proposed
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 10-12 days

---

## 1. Executive Summary

The platform has scheduling capabilities in three modules -- messages, broadcasts, and newsfeed posts -- but they are implemented as independent, siloed systems with no shared infrastructure. Each module has its own background loop, its own DynamoDB access patterns, and its own polling interval. Meanwhile, other modules that would benefit from scheduling (file shares, catalog sales) have no scheduling capability at all, and users have no cross-module view of all their scheduled content.

This design introduces a unified scheduling layer consisting of a single `ScheduledActions` DynamoDB table, a central background scheduler that dispatches due actions to module-specific executors, and a cross-module calendar view for users. New scheduling capabilities are added for file shares (scheduled file share messages) and catalog items (scheduled sale activation/deactivation). The existing three module-specific schedulers continue to run in parallel during migration; they are not replaced in Phase 1. Instead, new content types use the unified scheduler exclusively, and existing modules are migrated in follow-up tickets (Phases 2-5).

The unified scheduler polls a single GSI every 15 seconds, uses conditional writes for idempotent action claiming (preventing double-execution in multi-worker deployments), supports configurable pre-execution reminders via `write_alert()`, and automatically retries failed actions up to 3 times with increasing delays. A shared `ScheduleDialog` frontend component provides a consistent scheduling UX across all modules, and the `ScheduledContentCalendar` page gives users a single view of all their scheduled content color-coded by type.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to schedule a newsfeed post for a specific date/time from the UI. | "Schedule" button on CreatePost; date-time picker; post publishes at scheduled time. |
| Creator | I want to schedule a file share message for my team. | Select file from file picker; set delivery time; message appears in conversation at that time. |
| Creator | I want to schedule a sale price on a catalog item. | Set sale start/end dates; product price changes automatically at those times. |
| Creator | I want to see all my scheduled content in one place. | Calendar view shows all scheduled actions across messages, posts, broadcasts, files, and sales. |
| Creator | I want to cancel a scheduled action before it executes. | Cancel button on calendar view; status changes to `cancelled`; action does not execute. |
| Creator | I want to reschedule a pending action to a different time. | Edit the `scheduled_at` time on a pending action; action executes at the new time. |
| Creator | I want a reminder before my scheduled content goes live. | Set "Notify me 15 minutes before"; receive an alert at that time. |
| Admin | I want to see scheduled action metrics. | Dashboard shows pending/completed/failed/cancelled counts and execution latency. |

### 2.2 Pain Points

1. **Three independent schedulers**: Messages (`_messaging_background_loop` at line 11953, every 30s), broadcasts (`run_broadcast_scheduler_loop` at line 14, configurable interval), and newsfeed posts (`run_scheduler_loop` at line 369, configurable interval) each have their own polling loop, table query pattern, and error handling. <!-- VERIFIED: all three exist; broadcast and newsfeed intervals are configurable, not hardcoded 30s --> Bug fixes, monitoring, and optimization must be applied three times.
2. **No scheduled posts from UI**: The newsfeed scheduler infrastructure exists in the backend, but the `CreatePost` component has no date-time picker. Users cannot schedule posts.
3. **No scheduled file shares**: The file share messaging feature (`kind="file_share"`) does not support `send_at`. Content distribution workflows that need timed file delivery are impossible.
4. **No scheduled catalog sales**: The commerce catalog has no concept of sale start/end dates. Creators cannot automate time-limited promotions.
5. **No cross-module calendar**: Users juggle scheduled content across multiple UI sections with no unified view.
6. **No pre-execution notifications**: Only broadcast scheduling sends reminders. Scheduled messages and posts have no pre-publish notification.

### 2.3 Existing Scheduled Content Analysis

| Module | Location | Polling | DDB Pattern | Status |
|--------|----------|---------|-------------|--------|
| Messages | `app/routers/messaging.py` `_messaging_background_loop()` (line 11953) | 30s | Scan messages table where `status="scheduled"` and `deliver_at <= now` | Working | <!-- CORRECTED: was "scheduled=True and send_at <= now"; actual filter is `Attr("status").eq("scheduled") & Attr("deliver_at").lte(now_ts())` (line 11959). Uses full table scan, not query. -->
| Broadcasts | `app/services/broadcast_scheduler.py` `run_broadcast_scheduler_loop()` (line 14) | configurable via `S.broadcast_scheduler_poll_interval_seconds` | Query `BroadcastSessions` `ByScheduledAt` GSI | Working | <!-- VERIFIED: line 14; poll interval is configurable, not hardcoded 30s (line 27) -->
| Newsfeed | `app/services/newsfeed_scheduler.py` `run_scheduler_loop()` (line 369) | configurable via `interval_seconds` param | Query `app_single_table` `GSI_SCHEDULE_DUE` | Working | <!-- VERIFIED: sync function with configurable interval; called from newsfeed router's `startup()` (line 2039) -->
| File shares | N/A | N/A | N/A | Not supported |
| Catalog sales | N/A | N/A | N/A | Not supported |

### 2.4 Competitive Analysis

| Platform | Scheduling Approach |
|----------|---------------------|
| Buffer | Unified scheduling across social platforms with calendar view; queue-based execution |
| Hootsuite | Cross-platform content calendar; bulk scheduling; optimal time recommendations |
| Shopify | Scheduled publication for products, pages, and blog posts; scheduled price changes via apps |
| Later | Visual content calendar; auto-publish for Instagram, TikTok, Pinterest; drag-to-reschedule |

All competitors provide a unified calendar view and cross-module scheduling. This is table stakes for a content platform.

---

## 3. Technical Architecture

### 3.1 System Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Frontend (React/Vite)                            │
│                                                                      │
│  CreatePost.tsx ─── "Schedule" button ── ScheduleDialog               │
│  ComposeBar.tsx ─── (existing schedule) ── ScheduleDialog            │
│  CatalogProductForm.tsx ─── "Schedule Sale" ── ScheduleDialog        │
│                                                                      │
│  ScheduledContentCalendar.tsx (/calendar/scheduled)                   │
│    ├── Month/Week/Day view                                           │
│    ├── Color-coded action types:                                     │
│    │     message=blue, post=green, broadcast=red,                    │
│    │     file_share=purple, catalog_sale=orange                      │
│    ├── Click event → detail popover (preview, edit, cancel)          │
│    └── useQuery(["scheduler", "calendar", {from, to, types}])       │
│                                                                      │
│  ScheduledPostsList.tsx (/feed/scheduled)                             │
│    └── Pending posts with scheduled time, preview, cancel button     │
└──────────────────┬───────────────────────────────────────────────────┘
                   │
          Vite proxy :3000 → :8000
                   │
┌──────────────────▼───────────────────────────────────────────────────┐
│                     FastAPI Backend (:8000)                           │
│                                                                      │
│  app/routers/scheduler.py                                            │
│    ├── POST /ui/scheduler/actions  (create)                          │
│    ├── GET  /ui/scheduler/actions  (list, filter by type/status)     │
│    ├── GET  /ui/scheduler/actions/{id}  (detail)                     │
│    ├── PATCH /ui/scheduler/actions/{id}  (reschedule)                │
│    ├── DELETE /ui/scheduler/actions/{id}  (cancel)                   │
│    ├── GET  /ui/scheduler/calendar  (date range query)               │
│    ├── POST /ui/feed/posts/schedule  (convenience wrapper)           │
│    └── POST /ui/catalog/products/{id}/sale  (schedule sale)          │
│                                                                      │
│  app/services/scheduled_actions.py                                   │
│    ├── create_action(), list_actions(), cancel_action()              │
│    ├── query_due_actions() → GSI ByDue: DUE + scheduled_at <= now   │
│    └── claim_action() → conditional PutItem (idempotent claim)       │
│                                                                      │
│  app/services/unified_scheduler.py                                   │
│    └── run_unified_scheduler_loop() [registered in main.py]          │
│          ├── Poll every 15s                                          │
│          ├── Process due actions (batch of 25)                       │
│          ├── Send pre-execution reminders                            │
│          └── Dispatch to module executors:                            │
│                ├── execute_scheduled_post()                           │
│                ├── execute_scheduled_file_share()                     │
│                └── execute_scheduled_catalog_sale()                   │
│                                                                      │
│  app/services/schedule_executors.py                                  │
│    ├── execute_scheduled_post() → create_post()                      │
│    ├── execute_scheduled_file_share() → create_file_share_message()  │
│    └── execute_scheduled_catalog_sale() → update_product_price()     │
│                                                                      │
│  DDB: scheduled_actions table                                        │
│    PK: USER#{user_sub}                                               │
│    SK: ACTION#{scheduled_at}#{action_id}                             │
│    GSI ByDue: DUE → scheduled_at (N)                                 │
│    GSI ByType: USER#{sub}#TYPE#{type} → scheduled_at (N)            │
│    TTL: ttl_epoch (90 days)                                          │
│                                                                      │
│  Existing schedulers (unchanged in Phase 1):                         │
│    ├── _messaging_background_loop()     [messages]                   │
│    ├── run_broadcast_scheduler_loop()   [broadcasts]                 │
│    └── run_scheduler_loop()             [newsfeed posts]             │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow: Schedule a Post

1. Creator clicks "Schedule" on `CreatePost`, selects date/time in `ScheduleDialog`, confirms.
2. Frontend calls `POST /ui/feed/posts/schedule` with text, images, lock price, visibility, and `scheduled_at`.
3. Router validates `scheduled_at >= now + 300` (5 min minimum lead time), validates payload.
4. Service creates a `ScheduledActions` DDB item with `action_type=post`, `status=pending`, `GSI_DUE_PK=DUE`, `GSI_DUE_SK=scheduled_at`.
5. Returns `{ action_id, status: "pending", scheduled_at }`.

### 3.3 Data Flow: Execute a Scheduled Action

1. `run_unified_scheduler_loop()` polls `ByDue` GSI every 15s: `GSI_DUE_PK=DUE AND GSI_DUE_SK <= now_ts()`.
2. For each due action, calls `claim_action()` which does a conditional update: `SET status = executing IF status = pending`.
3. If claim succeeds (no other worker claimed it), dispatches to the appropriate executor.
4. `execute_scheduled_post()` calls `create_post()` from `app/routers/newsfeed.py` (line 2866). <!-- CORRECTED: was `app/services/newsfeed_feed_query.py`, but `create_post()` is actually in `app/routers/newsfeed.py`. `newsfeed_feed_query.py` has no `create_post` function. -->
5. On success: `mark_action_completed()` sets `status=completed`, `completed_at=now`, removes `GSI_DUE_PK` (so it doesn't appear in future polls).
6. On failure: increments `retry_count`, schedules retry (sets `GSI_DUE_SK = now + delay`), or marks as `failed` if max retries exhausted.

### 3.4 Data Flow: Pre-Execution Reminders

1. In the same poll loop, query for actions where `scheduled_at - notify_before_seconds <= now` and `reminder_sent=False`.
2. For each: call `write_alert(user_sub, event="scheduled_action_reminder", title=...)`.
3. Set `reminder_sent=True` on the action record (conditional write to prevent duplicate reminders).

---

## 4. Data Model Deep Dive

### 4.1 Table: `scheduled_actions`

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | S | `USER#{user_sub}` |
| `sk` | S | `ACTION#{scheduled_at}#{action_id}` |
| `action_id` | S | UUID (`sa_<uuid4_hex>`) |
| `user_sub` | S | Owner who scheduled the action |
| `action_type` | S | `message`, `post`, `broadcast`, `file_share`, `catalog_sale` |
| `status` | S | `pending`, `executing`, `completed`, `failed`, `cancelled` |
| `scheduled_at` | N | Unix timestamp for when to execute |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |
| `completed_at` | N | Unix timestamp (when executed or cancelled) |
| `title` | S | Human-readable label (for calendar display) |
| `description` | S | Optional description |
| `payload` | M | Module-specific data (DDB map) |
| `error` | S | Error message if status=failed |
| `retry_count` | N | Number of execution retries |
| `max_retries` | N | Maximum retry attempts (default 3) |
| `notify_before_seconds` | N | Send reminder N seconds before execution (0 = no reminder) |
| `reminder_sent` | BOOL | Whether pre-execution reminder has been sent |
| `GSI_DUE_PK` | S | `"DUE"` (removed after execution or cancellation) |
| `GSI_DUE_SK` | N | Same as `scheduled_at` |
| `GSI_TYPE_PK` | S | `USER#{user_sub}#TYPE#{action_type}` |
| `GSI_TYPE_SK` | N | `scheduled_at` |
| `ttl_epoch` | N | DDB TTL; completed/cancelled actions expire after 90 days |

### 4.2 GSI Definitions

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|---------------|----------|---------|
| `ByDue` | `GSI_DUE_PK` (S) | `GSI_DUE_SK` (N) | Scheduler: find all due actions across all users |
| `ByType` | `GSI_TYPE_PK` (S) | `GSI_TYPE_SK` (N) | Per-user per-type query (e.g., "my scheduled posts") |

### 4.3 Table Definition for local-ddb-init.py

```python
TableDef(
    _resolve_table_name(S.scheduled_actions_table_name, "scheduled_actions"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByDue", "partition_key": "GSI_DUE_PK", "sort_key": "GSI_DUE_SK"},
        {"index_name": "ByType", "partition_key": "GSI_TYPE_PK", "sort_key": "GSI_TYPE_SK"},
    ],
    attr_types={"GSI_DUE_SK": "N", "GSI_TYPE_SK": "N"},
),
```

**Critical note**: Both `GSI_DUE_SK` and `GSI_TYPE_SK` are numeric (Unix timestamps). They must be declared in `attr_types` or DynamoDB will store them as strings, causing `ValidationException` when queried with integer values.

### 4.4 Payload Schemas by Action Type

**post:**
```json
{
  "text": "New product launch!",
  "image_urls": ["https://..."],
  "lock_price_cents": 0,
  "visibility": "public"
}
```

**file_share:**
```json
{
  "conversation_id": "conv_abc",
  "file_node_id": "node_xyz",
  "file_name": "report.pdf",
  "permission": "view"
}
```

**catalog_sale (activate):**
```json
{
  "product_id": "prod_123",
  "sale_price_cents": 999,
  "original_price_cents": 1999,
  "sale_label": "Summer Sale",
  "activate": true
}
```

**catalog_sale (deactivate):**
```json
{
  "product_id": "prod_123",
  "sale_price_cents": null,
  "sale_label": null,
  "activate": false
}
```

### 4.5 Example DynamoDB Items

**Pending scheduled post:**
```json
{
  "pk": "USER#alice-sub-001",
  "sk": "ACTION#1748448000#sa_a1b2c3d4e5f6789012345678abcdef01",
  "action_id": "sa_a1b2c3d4e5f6789012345678abcdef01",
  "user_sub": "alice-sub-001",
  "action_type": "post",
  "status": "pending",
  "scheduled_at": 1748448000,
  "created_at": 1748361600,
  "updated_at": 1748361600,
  "title": "Product Launch",
  "description": "",
  "payload": {
    "text": "Exciting new product available now!",
    "image_urls": [],
    "lock_price_cents": 0,
    "visibility": "public"
  },
  "retry_count": 0,
  "max_retries": 3,
  "notify_before_seconds": 900,
  "reminder_sent": false,
  "GSI_DUE_PK": "DUE",
  "GSI_DUE_SK": 1748448000,
  "GSI_TYPE_PK": "USER#alice-sub-001#TYPE#post",
  "GSI_TYPE_SK": 1748448000,
  "ttl_epoch": 1756224000
}
```

**Completed scheduled post:**
```json
{
  "pk": "USER#alice-sub-001",
  "sk": "ACTION#1748448000#sa_a1b2c3d4e5f6789012345678abcdef01",
  "action_id": "sa_a1b2c3d4e5f6789012345678abcdef01",
  "user_sub": "alice-sub-001",
  "action_type": "post",
  "status": "completed",
  "scheduled_at": 1748448000,
  "created_at": 1748361600,
  "completed_at": 1748448015,
  "title": "Product Launch",
  "payload": { "text": "Exciting new product available now!", "image_urls": [], "lock_price_cents": 0, "visibility": "public" },
  "retry_count": 0,
  "GSI_TYPE_PK": "USER#alice-sub-001#TYPE#post",
  "GSI_TYPE_SK": 1748448000,
  "ttl_epoch": 1756224000
}
```

Note: `GSI_DUE_PK` and `GSI_DUE_SK` are **removed** after execution (not just updated to a sentinel value). This prevents completed actions from appearing in the due-actions query. DynamoDB allows attribute removal which removes the item from the GSI.

### 4.6 Access Patterns Table

| Access Pattern | Table | Key Condition | Notes |
|----------------|-------|---------------|-------|
| List user's scheduled actions | `scheduled_actions` | PK = `USER#{sub}` | Range query; all types and statuses |
| List user's scheduled posts | `scheduled_actions` GSI `ByType` | PK = `USER#{sub}#TYPE#post` | Filtered to one type |
| Get single action | `scheduled_actions` | PK = `USER#{sub}`, SK = `ACTION#{at}#{id}` | Requires knowing `scheduled_at` for SK |
| Find due actions | `scheduled_actions` GSI `ByDue` | PK = `DUE`, SK <= `now_ts()` | Scheduler poll query |
| Calendar range query | `scheduled_actions` | PK = `USER#{sub}`, SK between `ACTION#{from}` and `ACTION#{to}` | Calendar view data |
| Cancel an action | `scheduled_actions` | PK + SK, conditional: `status=pending` | Sets `status=cancelled`, removes GSI_DUE attrs |

---

## 5. API Contract Design

### 5.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/scheduler/actions` | `require_ui_session` | Create a scheduled action |
| GET | `/ui/scheduler/actions` | `require_ui_session` | List user's scheduled actions |
| GET | `/ui/scheduler/actions/{action_id}` | `require_ui_session` | Get action details |
| PATCH | `/ui/scheduler/actions/{action_id}` | `require_ui_session` | Reschedule (update time or payload) |
| DELETE | `/ui/scheduler/actions/{action_id}` | `require_ui_session` | Cancel a scheduled action |
| GET | `/ui/scheduler/calendar` | `require_ui_session` | Calendar view (date range query) |
| POST | `/ui/feed/posts/schedule` | `require_ui_session` | Schedule a newsfeed post (convenience) |
| POST | `/ui/catalog/products/{product_id}/sale` | `require_ui_session` | Schedule a catalog sale |

### 5.2 Create Scheduled Action (POST /ui/scheduler/actions)

**Request:**
```json
{
  "action_type": "post",
  "scheduled_at": 1748448000,
  "title": "Product Launch",
  "description": "Announce the new product line",
  "payload": {
    "text": "Exciting new product available now!",
    "image_urls": [],
    "lock_price_cents": 0,
    "visibility": "public"
  },
  "notify_before_seconds": 900
}
```

**Response (201):**
```json
{
  "action_id": "sa_a1b2c3d4e5f6789012345678abcdef01",
  "action_type": "post",
  "status": "pending",
  "scheduled_at": 1748448000,
  "created_at": 1748361600,
  "title": "Product Launch",
  "description": "Announce the new product line",
  "payload": { "text": "Exciting new product available now!", "image_urls": [], "lock_price_cents": 0, "visibility": "public" },
  "notify_before_seconds": 900
}
```

**Error responses:**

| Status | Condition | Body |
|--------|-----------|------|
| 400 | `scheduled_at` less than 5 minutes in future | `{ "detail": "scheduled_at must be at least 5 minutes in the future" }` |
| 400 | Invalid `action_type` | `{ "detail": "Invalid action_type: xyz" }` |
| 400 | Invalid payload for action type | `{ "detail": "payload validation error: ..." }` |
| 409 | Max 100 pending actions per user | `{ "detail": "Maximum pending scheduled actions reached (100)" }` |

### 5.3 List Scheduled Actions (GET /ui/scheduler/actions)

**Query params**: `types` (comma-separated), `status` (comma-separated), `cursor`.

**Response (200):**
```json
{
  "actions": [
    {
      "action_id": "sa_abc123",
      "action_type": "post",
      "status": "pending",
      "scheduled_at": 1748448000,
      "created_at": 1748361600,
      "title": "Product Launch"
    }
  ],
  "cursor": null
}
```

### 5.4 Calendar View (GET /ui/scheduler/calendar)

**Query params**: `from_date` (Unix timestamp), `to_date` (Unix timestamp), `types` (comma-separated).

**Response (200):**
```json
{
  "actions": [
    {
      "action_id": "sa_abc123",
      "action_type": "post",
      "status": "pending",
      "scheduled_at": 1748448000,
      "title": "Product Launch"
    },
    {
      "action_id": "sa_def456",
      "action_type": "catalog_sale",
      "status": "completed",
      "scheduled_at": 1748444400,
      "title": "Summer Sale Start"
    }
  ],
  "total": 2
}
```

### 5.5 Schedule a Post (POST /ui/feed/posts/schedule)

Convenience wrapper that creates a `post` action:

**Request:**
```json
{
  "text": "Happy Monday!",
  "image_urls": [],
  "lock_price_cents": 0,
  "visibility": "public",
  "scheduled_at": 1748448000
}
```

**Response (201):** Same as `POST /ui/scheduler/actions` response.

### 5.6 Schedule a Catalog Sale (POST /ui/catalog/products/{product_id}/sale)

**Request:**
```json
{
  "sale_price_cents": 999,
  "sale_starts_at": 1748444400,
  "sale_ends_at": 1748530800,
  "sale_label": "Summer Sale"
}
```

Creates two scheduled actions: one to activate the sale at `sale_starts_at`, and one to deactivate it at `sale_ends_at`.

**Response (201):**
```json
{
  "start_action_id": "sa_start_abc",
  "end_action_id": "sa_end_def",
  "sale_starts_at": 1748444400,
  "sale_ends_at": 1748530800
}
```

### 5.7 Cancel Action (DELETE /ui/scheduler/actions/{action_id})

**Response (200):**
```json
{
  "ok": true,
  "action_id": "sa_abc123",
  "status": "cancelled"
}
```

**Error**: Returns 400 if the action is already completed or cancelled.

### 5.8 Rate Limits

- Action creation: Standard per-user rate limiting. Max 100 pending actions per user.
- Calendar query: No special rate limit (bounded by date range).
- Cancellation: No special rate limit.

---

## 6. Backend Implementation

### 6.1 Unified Scheduler Background Task

```python
# app/services/unified_scheduler.py

POLL_INTERVAL_SECONDS = 15
MAX_BATCH_SIZE = 25

_EXECUTORS = {
    "post": "execute_scheduled_post",
    "file_share": "execute_scheduled_file_share",
    "catalog_sale": "execute_scheduled_catalog_sale",
}

async def run_unified_scheduler_loop():
    if not S.unified_scheduler_enabled:
        logger.info("Unified scheduler disabled")
        return

    logger.info("Unified scheduler started (poll_interval=%ds)", POLL_INTERVAL_SECONDS)
    while True:
        try:
            now = now_ts()
            # 1. Process due actions
            due_actions = query_due_actions(now=now, limit=MAX_BATCH_SIZE)
            for action in due_actions:
                await _process_action(action, now)

            # 2. Send pre-execution reminders
            upcoming = query_upcoming_reminders(now=now, lookahead=300)
            for action in upcoming:
                if not action.get("reminder_sent") and action.get("notify_before_seconds", 0) > 0:
                    remind_at = action["scheduled_at"] - action["notify_before_seconds"]
                    if remind_at <= now:
                        _send_reminder(action)
        except Exception:
            logger.exception("Unified scheduler loop error")

        await asyncio.sleep(POLL_INTERVAL_SECONDS)


async def _process_action(action: dict, now: int):
    action_id = action["action_id"]
    action_type = action["action_type"]

    claimed = claim_action(action_id, action["user_sub"], action["sk"])
    if not claimed:
        return  # Another scheduler instance claimed it

    executor_name = _EXECUTORS.get(action_type)
    if not executor_name:
        mark_action_failed(action, error=f"Unknown action_type: {action_type}")
        return

    try:
        executor = getattr(schedule_executors, executor_name)
        await executor(action["user_sub"], action["payload"])
        mark_action_completed(action)
    except Exception as exc:
        retry_count = action.get("retry_count", 0) + 1
        max_retries = action.get("max_retries", 3)
        if retry_count < max_retries:
            schedule_retry(action, retry_count, delay_seconds=60 * retry_count)
        else:
            mark_action_failed(action, error=str(exc))
```

### 6.2 Module Executors

```python
# app/services/schedule_executors.py

async def execute_scheduled_post(user_sub: str, payload: dict):
    # CORRECTED: create_post is in app/routers/newsfeed.py:2866, not app/services/newsfeed_feed_query.py
    # NOTE: create_post() signature is `create_post(req: CreatePostRequest, user_id: UserIdDep)`,
    # which is a FastAPI endpoint. The executor will need to construct a CreatePostRequest model
    # and call the underlying logic directly, or extract the business logic into a service function.
    from app.routers.newsfeed import create_post
    create_post(
        req=CreatePostRequest(text=payload["text"], ...),
        user_id=user_sub,
    )

async def execute_scheduled_file_share(user_sub: str, payload: dict):
    # CORRECTED: function is `create_file_share_message` (not `create_file_share_message_internal`)
    # at app/routers/messaging.py:8224
    from app.routers.messaging import create_file_share_message
    create_file_share_message(
        conversation_id=payload["conversation_id"],
        sender_id=user_sub,
        file_node_id=payload["file_node_id"],
        file_name=payload["file_name"],
        permission=payload.get("permission", "view"),
    )

async def execute_scheduled_catalog_sale(user_sub: str, payload: dict):
    # CORRECTED: There is no `update_product_price()` function in the codebase.
    # The catalog uses `update_item()` in app/routers/catalog.py:430, which is a
    # FastAPI endpoint accepting CatalogItemPatchIn (includes price_cents field).
    # The executor will need to call the underlying DDB update_item directly:
    #   T.catalog.update_item(Key={"PK": cat_pk(category_id), "SK": item_sk(item_id)}, ...)
    # or a new service-level helper must be created.
    if payload.get("activate"):
        # update product price to sale_price_cents
        pass  # implementation TBD - no existing service function
    else:
        # restore original price
        pass  # implementation TBD
```

### 6.3 Idempotent Action Claiming

```python
def claim_action(action_id: str, user_sub: str, sk: str) -> bool:
    """Atomically claim a due action. Returns True if this worker claimed it."""
    try:
        T.scheduled_actions.update_item(
            Key={"pk": f"USER#{user_sub}", "sk": sk},
            UpdateExpression="SET #status = :executing, updated_at = :now",
            ConditionExpression="#status = :pending",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":executing": "executing",
                ":pending": "pending",
                ":now": now_ts(),
            },
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False  # Another worker claimed it
        raise
```

### 6.4 Registration in main.py

```python
# app/main.py
from app.services.unified_scheduler import run_unified_scheduler_loop

async def start_unified_scheduler_task():
    if S.unified_scheduler_enabled:
        asyncio.create_task(run_unified_scheduler_loop())

app.add_event_handler("startup", start_unified_scheduler_task)
```

---

## 7. Frontend Component Design

### 7.1 Component Tree

```
CalendarPage (/calendar)
  ├── [Existing calendar tabs]
  └── "Scheduled" tab → ScheduledContentCalendar
        ├── CalendarHeader (month/week/day toggle, date navigation)
        ├── CalendarGrid
        │     └── CalendarEvent[] (color-coded by action_type)
        │           └── Click → ActionDetailPopover
        │                 ├── Title, type badge, scheduled time
        │                 ├── Payload preview (first 100 chars)
        │                 └── Edit / Cancel buttons
        └── EmptyState ("No scheduled content")

FeedPage (/feed)
  └── CreatePost
        ├── [Existing post form]
        ├── "Schedule" Button → ScheduleDialog
        └── ScheduledPostsList (expandable section)

CatalogProductForm
  └── "Schedule Sale" Button → ScheduleDialog

ScheduleDialog (shared component)
  ├── Date picker (shadcn Calendar)
  ├── Time picker (select with 15-min increments)
  ├── Timezone display (browser timezone)
  ├── "Notify me before" checkbox + interval select
  └── Confirm / Cancel buttons
```

### 7.2 New Files

| File | Purpose |
|------|---------|
| `frontend/src/pages/calendar/ScheduledContentCalendar.tsx` | Cross-module calendar view |
| `frontend/src/components/shared/ScheduleDialog.tsx` | Reusable date-time picker dialog |
| `frontend/src/pages/feed/ScheduledPostsList.tsx` | Scheduled posts list |
| `frontend/src/api/endpoints/scheduler.ts` | API client |

### 7.3 ScheduleDialog Props

```typescript
interface ScheduleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: (scheduledAt: number, notifyBefore?: number) => void;
  initialScheduledAt?: number;
  isSubmitting?: boolean;
  title?: string;
  minMinutesAhead?: number;    // Default 5
}
```

### 7.4 React Query Keys

```typescript
["scheduler", "actions"]                       // User's actions list
["scheduler", "actions", actionId]             // Single action detail
["scheduler", "calendar", { from, to, types }] // Calendar view data
```

### 7.5 Calendar Color Coding

| Action Type | Color | Badge Text |
|-------------|-------|------------|
| `message` | Blue (`bg-blue-500`) | "Message" |
| `post` | Green (`bg-green-500`) | "Post" |
| `broadcast` | Red (`bg-red-500`) | "Broadcast" |
| `file_share` | Purple (`bg-purple-500`) | "File Share" |
| `catalog_sale` | Orange (`bg-orange-500`) | "Sale" |

---

## 8. Security & Privacy Considerations

### 8.1 Authorization

- All scheduler endpoints require `require_ui_session`.
- Users can only create, view, modify, and cancel their own scheduled actions (enforced by PK = `USER#{user_sub}`).
- The unified scheduler background task runs with system-level access (no user context); it executes actions on behalf of the user who created them.

### 8.2 Payload Validation

- Post payloads are validated against the same rules as `create_post()` (max text length, valid image URLs).
- File share payloads validate `conversation_id` belongs to the user and `file_node_id` exists.
- Catalog sale payloads validate `product_id` belongs to the user and `sale_price_cents > 0`.

### 8.3 Race Conditions

- **Double execution**: The conditional write in `claim_action()` prevents two scheduler instances from executing the same action. Only one succeeds; others silently skip.
- **Cancel-then-execute race**: If a user cancels an action while the scheduler is executing it, the cancel sets `status=cancelled`. The executor checks status before proceeding and aborts if cancelled.

### 8.4 Abuse Prevention

- **Max 100 pending actions per user**: Prevents resource exhaustion from users scheduling thousands of actions.
- **5-minute minimum lead time**: Prevents "instant scheduling" that would bypass normal rate limits on content creation.
- **Retry limit (3 attempts)**: Failed actions do not retry indefinitely.

---

## 9. Performance & Scalability

### 9.1 Query Costs

- **Scheduler poll (ByDue GSI)**: 1 query per 15 seconds. Returns up to 25 items. Cost: 0.5-3 RCU depending on batch size.
- **Action creation**: 1 DDB `put_item` per action. Cost: 1 WCU.
- **Calendar range query**: 1 DDB query with SK range. Returns all actions in the date range. Cost: proportional to result set.
- **Claim action**: 1 conditional `update_item`. Cost: 1 WCU.

### 9.2 Polling Overhead

- **15-second poll interval**: The scheduler queries DDB 4 times per minute. At the minimum RCU per query, this is ~2 RCU/minute of sustained load.
- **No actions due (idle)**: The GSI query returns 0 items but still consumes minimum 0.5 RCU per query.
- **Comparison to existing**: The three existing schedulers poll every 30 seconds each, totaling 6 queries/minute. The unified scheduler polls 4 times/minute -- a slight improvement even before migrating existing schedulers.

### 9.3 Hot Partition Risk

The `ByDue` GSI has a single partition key value: `"DUE"`. All pending actions across all users share this partition. At high volume (>1000 pending actions), this can become a hot partition.

**Mitigation for future scaling**:
- Shard the `GSI_DUE_PK` value: `DUE#0` through `DUE#9`. The scheduler fans out reads across all 10 shards.
- In Phase 1, the single `DUE` partition is sufficient for moderate deployments (~10K total scheduled actions).

### 9.4 Known Bottlenecks

- **Executor latency**: If `create_post()` or `update_product_price()` takes >1 second, the scheduler processes fewer actions per cycle. Consider async execution for slow executors.
- **DDB FilterExpression**: The calendar range query uses SK range condition (not FilterExpression), so it efficiently returns only actions in the date range. No full-scan risk.

---

## 10. Migration & Rollback Plan

### 10.1 Feature Flag

`UNIFIED_SCHEDULER_ENABLED` (default `true`) controls the scheduler background task. When `false`:
- The scheduler loop does not start.
- CRUD endpoints still work (users can create/cancel actions).
- No actions are automatically executed.

### 10.2 Migration Strategy (Phases 2-5, Future Tickets)

The existing three schedulers continue to run unchanged in Phase 1:

| Phase | Module | Migration Approach |
|-------|--------|--------------------|
| 1 (this ticket) | New modules (file shares, catalog sales) | Use unified scheduler exclusively |
| 2 (future) | Newsfeed posts | Dual-write: write to both `app_single_table` GSI and `ScheduledActions`. Scheduler reads from `ScheduledActions`. |
| 3 (future) | Messages | Dual-write: write `send_at` to messages table AND `ScheduledActions`. Unified scheduler calls `promote_scheduled_message()`. |
| 4 (future) | Broadcasts | Dual-write: write to `BroadcastSessions` AND `ScheduledActions`. |
| 5 (future) | Remove legacy | Delete `_messaging_background_loop()`, `run_broadcast_scheduler_loop()`, `run_scheduler_loop()`. |

### 10.3 Rollback Steps

1. Set `UNIFIED_SCHEDULER_ENABLED=false`. Scheduler stops.
2. New content types (file shares, catalog sales) lose scheduling capability.
3. Existing modules (messages, broadcasts, newsfeed) are unaffected (their own schedulers continue running).
4. Pending actions in `ScheduledActions` table remain but are not executed. They can be cleaned up manually or will auto-expire via TTL.

---

## 11. Testing Strategy

### 11.1 Unit Tests (pytest)

| Test | Module | Description |
|------|--------|-------------|
| `test_create_action_validates_lead_time` | `scheduled_actions.py` | `scheduled_at` < now + 300 rejected |
| `test_create_action_validates_max_pending` | `scheduled_actions.py` | 101st pending action returns 409 |
| `test_claim_action_conditional_write` | `scheduled_actions.py` | Only one concurrent claim succeeds |
| `test_claim_action_already_claimed` | `scheduled_actions.py` | Second claim returns False |
| `test_mark_completed_removes_gsi_due` | `scheduled_actions.py` | Completed action has no GSI_DUE_PK |
| `test_schedule_retry_increments_count` | `scheduled_actions.py` | Retry count incremented, new GSI_DUE_SK set |
| `test_mark_failed_after_max_retries` | `scheduled_actions.py` | 3rd failure sets status=failed |
| `test_cancel_action` | `scheduled_actions.py` | Status=cancelled, GSI_DUE attrs removed |
| `test_execute_post` | `schedule_executors.py` | Post created with correct text and visibility |
| `test_execute_file_share` | `schedule_executors.py` | File share message created in conversation |
| `test_execute_catalog_sale_activate` | `schedule_executors.py` | Product sale price updated |
| `test_execute_catalog_sale_deactivate` | `schedule_executors.py` | Product sale price cleared |

### 11.2 E2E Test Matrix

**File**: `frontend/e2e/content-scheduling.spec.ts`

**Section A: Scheduled Actions CRUD API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | User creates a scheduled post action | POST returns action_id with status=pending |
| 2 | scheduled_at must be at least 5 minutes in the future | 400 for too-soon timestamp |
| 3 | User lists their scheduled actions | GET returns array filtered by user |
| 4 | User cancels a scheduled action | DELETE changes status to cancelled |
| 5 | Cancelled actions are excluded from due query | Verify cancelled action not executed |
| 6 | Max 100 pending actions per user | 101st returns 409 |

**Section B: Scheduled Post Execution (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 7 | Scheduled post is published at scheduled_at | Create post action with near-future time; poll until completed; verify post exists in feed |
| 8 | Scheduled post with lock_price_cents creates locked post | Verify published post has correct lock |
| 9 | Cancelled post is not published | Cancel before scheduled_at; verify no post created |
| 10 | Failed post action records error | Schedule with invalid payload; verify status=failed with error message |

**Section C: Scheduled File Share (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | Scheduled file share sends message at scheduled_at | Create file_share action; verify message appears in conversation |
| 12 | File share to non-existent conversation returns error | Invalid conversation_id in payload |
| 13 | User can edit scheduled file share time | PATCH with new scheduled_at |

**Section D: Catalog Sale Scheduling (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 14 | Schedule a catalog sale activates at start time | Create sale action; verify product price changes |
| 15 | Sale with end time creates deactivation action | Verify two actions created |
| 16 | Cancel sale before start prevents price change | Cancel start action; verify price unchanged |
| 17 | Sale end action restores original price | Wait for end action; verify original price restored |

**Section E: Calendar View API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 18 | Calendar returns actions in date range | Create actions at different dates; verify range filter |
| 19 | Calendar filters by action_type | Query with types=post; verify only posts returned |
| 20 | Calendar includes completed and pending actions | Verify both statuses in response |

**Section F: Scheduling UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 21 | Newsfeed CreatePost has Schedule button | Navigate to feed; verify button visible |
| 22 | Schedule dialog validates minimum time | Enter time too soon; verify error |
| 23 | Scheduled content calendar page loads | Navigate to /calendar/scheduled; verify calendar renders |
| 24 | Cancel scheduled post from calendar view | Click cancel on scheduled post; verify removed |

---

## 12. Monitoring & Alerting

### 12.1 Metrics to Track

| Metric | Type | Description |
|--------|------|-------------|
| `scheduler_action_created_total` | Counter | Actions created, labeled by `action_type` |
| `scheduler_action_completed_total` | Counter | Actions successfully executed, labeled by `action_type` |
| `scheduler_action_failed_total` | Counter | Actions that exhausted retries, labeled by `action_type` and `error_class` |
| `scheduler_action_cancelled_total` | Counter | Actions cancelled by users |
| `scheduler_execution_latency_seconds` | Histogram | Time from `scheduled_at` to actual execution (ideally <30s) |
| `scheduler_executor_duration_seconds` | Histogram | Time per executor call, labeled by `action_type` |
| `scheduler_poll_items_found` | Histogram | Number of due items per poll cycle |
| `scheduler_claim_conflict_total` | Counter | Claim attempts that failed (another worker claimed first) |
| `scheduler_reminder_sent_total` | Counter | Pre-execution reminders sent |
| `scheduler_pending_actions` | Gauge | Total pending actions in the system |

### 12.2 Dashboard Queries

- **Execution lag**: `histogram_quantile(0.95, scheduler_execution_latency_seconds)` -- P95 should be <30s (i.e., within 2 poll intervals).
- **Success rate**: `rate(scheduler_action_completed_total[5m]) / rate(scheduler_action_created_total[5m])` -- should be >98%.
- **Pending backlog**: `scheduler_pending_actions` -- should not grow unboundedly. If increasing, check executor latency and scheduler throughput.

### 12.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Scheduler execution lag high | P95 latency > 60s (4 poll intervals) | Warning |
| Scheduler failure rate high | Failed actions > 5% of total in 1 hour | Warning |
| Scheduler not polling | `scheduler_poll_items_found` not updated for 60s | Critical |
| Pending backlog growing | `scheduler_pending_actions` increased by >100 in 1 hour | Warning |

---

## 13. Open Questions & Risks

### 13.1 Unresolved Decisions

1. **Should the unified scheduler replace existing schedulers immediately or run in parallel?** Running in parallel during migration is safer but means maintaining two code paths. **Recommendation**: Parallel in Phase 1 (this ticket), with migration tickets for Phases 2-5.

2. **Idempotency guarantees**: If the scheduler crashes mid-execution, restarted items must not double-execute. The conditional write handles claiming, but downstream executors should also check for an idempotency key derived from the `action_id`.

3. **Time zone handling for UI**: `scheduled_at` is a Unix timestamp (timezone-agnostic), but the `ScheduleDialog` UI needs to display and input times in the user's local timezone. The browser's `Intl.DateTimeFormat` handles this, but the conversion should be clearly documented.

4. **Scheduled action visibility to other users**: Should scheduled posts be visible to followers before they are published? **Recommendation**: No preview for posts and messages; optional "Coming soon" badges for catalog sales.

5. **Bulk scheduling**: Should we support "schedule every Monday at 9 AM for the next 4 weeks"? **Recommendation**: Defer to follow-up ticket.

6. **Interaction with existing scheduled messages UI**: The messaging `ComposeBar` already has a schedule button that uses `send_at`. The unified scheduler adds a 15-second polling delay. For messages, the existing 30-second inline loop may be more responsive. **Recommendation**: Keep message scheduling via the inline mechanism; use the unified scheduler for new content types and the calendar view.

### 13.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Hot partition on ByDue GSI | Medium | High | Shard GSI_DUE_PK in future iteration |
| Executor failure causes action stuck in "executing" | Low | Medium | Timeout-based recovery: if `executing` for >5 min, reset to `pending` for retry |
| Clock skew between scheduler workers | Low | Low | Use DDB server-side `now_ts()` for all timestamps |
| Scheduled action payload drift (API changes after scheduling) | Medium | Medium | Validate payload at execution time, not just creation time |

### 13.3 Dependency Risks

- **Module executor imports**: Executors import from `app/routers/newsfeed.py` (`create_post`, line 2866), `app/routers/messaging.py` (`create_file_share_message`, line 8224), and `app/routers/catalog.py` (`update_item`, line 430). Changes to these module APIs require corresponding executor updates. <!-- CORRECTED: was `newsfeed_feed_query.py` and `catalog_products.py`; actual locations differ. Note: these are FastAPI endpoint functions, not pure service functions -- may warrant extracting business logic into service-layer helpers for cleaner executor imports. -->
- **DDB throughput**: The `ByDue` GSI must handle the combined write throughput of all scheduled action creations plus the read throughput of the poll query. For moderate deployments (~10K scheduled actions), this is well within DDB free-tier capacity.

---

## 14. Settings / Configuration

### 14.1 New Settings (app/core/settings.py)

```python
# Unified scheduler
scheduled_actions_table_name: str = os.environ.get("SCHEDULED_ACTIONS_TABLE_NAME", "scheduled_actions")
unified_scheduler_enabled: bool = os.environ.get("UNIFIED_SCHEDULER_ENABLED", "1") not in ("0", "false", "False")
unified_scheduler_poll_interval_seconds: int = int(os.environ.get("UNIFIED_SCHEDULER_POLL_INTERVAL_SECONDS", "15"))
scheduled_actions_max_per_user: int = int(os.environ.get("SCHEDULED_ACTIONS_MAX_PER_USER", "100"))
scheduled_actions_min_lead_time_seconds: int = int(os.environ.get("SCHEDULED_ACTIONS_MIN_LEAD_TIME_SECONDS", "300"))
scheduled_actions_max_retries: int = int(os.environ.get("SCHEDULED_ACTIONS_MAX_RETRIES", "3"))
scheduled_actions_ttl_days: int = int(os.environ.get("SCHEDULED_ACTIONS_TTL_DAYS", "90"))
```

### 14.2 New Table Handles (app/core/tables.py)

```python
scheduled_actions: Any

# In T initialization:
scheduled_actions=ddb.Table(S.scheduled_actions_table_name),
```

---

## 15. Implementation Timeline

| Day | Task | Deliverable |
|-----|------|-------------|
| 1 | Add settings to `settings.py`; add table definition to `local-ddb-init.py`; add handle to `tables.py` | Infrastructure |
| 1 | Add Pydantic models to `models.py` (`ScheduledActionCreateIn`, `ScheduledActionOut`, etc.) | API models |
| 2 | Create `app/services/scheduled_actions.py` (CRUD, query_due, claim, mark_completed/failed) | Service layer |
| 3 | Create `app/services/schedule_executors.py` (post, file_share, catalog_sale executors) | Executors |
| 3 | Create `app/services/unified_scheduler.py` (background loop) | Scheduler |
| 4 | Create `app/routers/scheduler.py` (CRUD endpoints, calendar, convenience wrappers) | HTTP API |
| 4 | Register scheduler in `main.py` | Wiring |
| 5 | Create `frontend/src/components/shared/ScheduleDialog.tsx` | Shared component |
| 5 | Create `frontend/src/api/endpoints/scheduler.ts` and TypeScript types | Frontend API |
| 6 | Integrate ScheduleDialog into `CreatePost.tsx` | Post scheduling UI |
| 6 | Create `ScheduledPostsList.tsx` | Scheduled posts list |
| 7 | Create `ScheduledContentCalendar.tsx` | Calendar view |
| 7 | Add routes to `App.tsx`; add "Scheduled" link to sidebar | Navigation |
| 8 | Integrate sale scheduling into `CatalogProductForm.tsx` | Sale scheduling UI |
| 9 | Write pytest unit tests (12 tests) | Backend tests |
| 10-11 | Write E2E tests (`content-scheduling.spec.ts`, 24 tests) | E2E suite |
| 12 | Integration testing, monitoring setup | Ship |

---

## 16. Dependencies

| Dependency | Reason |
|------------|--------|
| `app/routers/newsfeed.py::create_post()` (line 2866) | Execute scheduled posts | <!-- CORRECTED: was `app/services/newsfeed_feed_query.py`, actually in `app/routers/newsfeed.py`. Note: this is a FastAPI endpoint function, not a pure service function; may need refactoring. -->
| `app/routers/messaging.py::create_file_share_message()` (line 8224) | Execute scheduled file shares | <!-- CORRECTED: was `create_file_share_message_internal()`, actually `create_file_share_message()`. -->
| `app/routers/catalog.py::update_item()` (line 430) | Execute scheduled catalog sales | <!-- CORRECTED: was `app/services/catalog_products.py::update_product_price()`. There is no `catalog_products.py` service file and no `update_product_price()` function. The catalog uses `update_item()` in `app/routers/catalog.py` which accepts `CatalogItemPatchIn` with optional `price_cents`. A new service-level helper may need to be created. -->
| `app/services/alerts.py::write_alert()` | Pre-execution reminders |
| `app/main.py` | Register unified scheduler background task |
| `app/services/newsfeed_scheduler.py::run_scheduler_loop()` (line 369) | Existing newsfeed scheduler (Phase 2 migration target) | <!-- VERIFIED -->
| `app/services/broadcast_scheduler.py::run_broadcast_scheduler_loop()` (line 14) | Existing broadcast scheduler (Phase 4 migration target) | <!-- VERIFIED -->
| `app/routers/messaging.py::_messaging_background_loop()` (line 11953) | Existing message scheduler (Phase 3 migration target) | <!-- VERIFIED -->

---

## 17. Acceptance Criteria

1. User can schedule a newsfeed post from the UI with a date/time picker.
2. Scheduled post is automatically published at the scheduled time (within 15 seconds).
3. User can schedule a file share message that appears in the conversation at the scheduled time.
4. User can schedule a catalog sale that activates and deactivates at configured times.
5. User can view all scheduled content in a cross-module calendar view.
6. User can cancel a pending scheduled action.
7. User can reschedule a pending action to a different time.
8. Pre-execution reminders are sent via `write_alert()` when configured.
9. Failed actions retry up to 3 times before marking as failed.
10. Existing module-specific schedulers continue to work unchanged.
11. All 24 E2E tests pass.
12. Feature can be disabled via `UNIFIED_SCHEDULER_ENABLED=false`.

---

## Appendix: Codebase Citations

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `_messaging_background_loop()` | `app/routers/messaging.py` | 11953 | VERIFIED |
| `start_scheduled_messages_task()` | `app/routers/messaging.py` | 12020 | VERIFIED |
| Message scheduling filter: `status="scheduled"` + `deliver_at <= now_ts()` | `app/routers/messaging.py` | 11959 | CORRECTED: ticket said `scheduled=True` and `send_at <= now`; actual is `Attr("status").eq("scheduled") & Attr("deliver_at").lte(now_ts())` |
| `_deliver_scheduled_message()` | `app/routers/messaging.py` | 11819 | VERIFIED |
| `run_broadcast_scheduler_loop()` | `app/services/broadcast_scheduler.py` | 14 | VERIFIED (async, polls `ByScheduledAt` GSI) |
| `start_broadcast_scheduler_task()` | `app/services/broadcast_scheduler.py` | 68 | VERIFIED |
| `run_broadcast_reminder_loop()` | `app/services/broadcast_scheduler.py` | 73 | VERIFIED |
| Broadcast poll interval | `app/services/broadcast_scheduler.py` | 27 | VERIFIED: configurable via `S.broadcast_scheduler_poll_interval_seconds` |
| `broadcast_scheduler_enabled` setting | `app/core/settings.py` | 1148 | VERIFIED |
| `BroadcastSessions` `ByScheduledAt` GSI | `scripts/local-ddb-init.py` | 517 | VERIFIED (with `attr_types={"scheduled_at": "N"}`) |
| `run_scheduler_loop()` (newsfeed) | `app/services/newsfeed_scheduler.py` | 369 | VERIFIED (sync function with configurable `interval_seconds`) |
| `process_due_scheduled_posts()` (newsfeed) | `app/services/newsfeed_scheduler.py` | 234 | VERIFIED |
| `newsfeed_startup` (registered in main.py:323) | `app/routers/newsfeed.py` | 2039 | VERIFIED |
| `newsfeed_scheduling_api_enabled` setting | `app/core/settings.py` | 958 | VERIFIED |
| `newsfeed_scheduling_worker_enabled` setting | `app/core/settings.py` | 959 | VERIFIED |
| `app_single_table` `GSI_SCHEDULE_DUE` GSI | `scripts/local-ddb-init.py` | 224 | VERIFIED (`partition_key: GSI_SCHEDULE_PK`, `sort_key: GSI_SCHEDULE_SK`) |
| `create_post()` | `app/routers/newsfeed.py` | 2866 | CORRECTED: ticket said `app/services/newsfeed_feed_query.py`; actually in `app/routers/newsfeed.py`. Note: this is a FastAPI endpoint function (`def create_post(req: CreatePostRequest, user_id: UserIdDep)`) |
| `create_file_share_message()` | `app/routers/messaging.py` | 8224 | CORRECTED: ticket said `create_file_share_message_internal()`; actual name is `create_file_share_message()` |
| `update_product_price()` | N/A | N/A | CORRECTED: does not exist. Nearest equivalent is `update_item()` in `app/routers/catalog.py:430` (FastAPI endpoint accepting `CatalogItemPatchIn`). No `catalog_products.py` service file exists; catalog service is `catalog_commercialization.py` (different purpose). |
| `write_alert()` | `app/services/alerts.py` | 265 | VERIFIED |
| Background task registration pattern | `app/main.py` | 323-328 | VERIFIED |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED |
| `now_ts()` | `app/core/time.py` | 2 | VERIFIED |
| `TableDef` dataclass | `scripts/local-ddb-init.py` | 29 | VERIFIED |
| `_resolve_table_name()` | `scripts/local-ddb-init.py` | 38 | VERIFIED |
| `attr_types` for numeric GSI sort keys | `scripts/local-ddb-init.py` | e.g., 247, 517 | VERIFIED |
| Settings dataclass | `app/core/settings.py` | entire file | VERIFIED (proposed new settings do not exist yet) |
| Tables dataclass | `app/core/tables.py` | entire file | VERIFIED (proposed new table handles do not exist yet) |

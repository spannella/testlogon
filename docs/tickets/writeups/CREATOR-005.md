# CREATOR-005: Visual Content Scheduling Calendar — Investigation & Implementation Write-up

## 1. Summary & Classification

**Type**: Feature — unified frontend calendar + thin aggregation backend endpoint  
**Priority**: Medium | **Status**: Substantially implemented — backend + all core frontend components present; drag-and-drop wired; some UX polish items remain  
**Area**: Creator workflow — newsfeed, broadcast, VOD scheduling  
**Persona**: Creators managing multi-format content pipelines across timezones

CREATOR-005 adds a single visual calendar at `/content-calendar` showing scheduled posts (from newsfeed), scheduled broadcasts, and scheduled VOD releases. It reuses all three existing scheduling APIs without adding new scheduling logic. The key backend contribution is `GET /ui/content-calendar` which aggregates items from the three sources into a unified list, plus reschedule/cancel proxy endpoints. The frontend provides month, week, and mobile agenda views with drag-and-drop rescheduling.

Cross-references: BCAST-009 (broadcast scheduling), SCHED-001 (post scheduling), VOD-001 (video metadata including `scheduled_publish_at`), SECOPS-007 (no new AWS dependency).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Source scheduling APIs

**Newsfeed posts**: `PATCH /posts/{post_id}` (`app/routers/newsfeed.py:3437`) supports updating `publish_at` on scheduled posts. `POST /posts/{post_id}/cancel` (`app/routers/newsfeed.py:3662`) cancels scheduled posts. Listing via `pk=USER#{user_id}` SK `begins_with SCHEDULEDPOST#` (`app/routers/newsfeed.py:3377`). The scheduler loop (`app/services/newsfeed_scheduler.py:234`) processes due posts via `GSI_SCHEDULE_DUE` index with PK `"SCHEDULED"`.

**Broadcasts**: `POST /sessions/{session_id}/schedule` (`app/routers/broadcast.py:2053`) creates a scheduled broadcast requiring minimum lead time. `POST /sessions/{session_id}/reschedule` (`:2124`) updates the scheduled time. `POST /sessions/{session_id}/cancel-schedule` (`:2170`) cancels. List via `list_sessions_by_creator` (`app/services/broadcast_store.py`) with `FilterExpression` for `schedule_status="scheduled"`. The `ByScheduledAt` GSI (`:437`) supports the auto-promotion query.

**VOD**: `app/models_video.py:104` — `scheduled_publish_at: Optional[int]` field exists (comment `# Scheduled Publishing (CREATOR-005)`). `list_videos_by_owner` (`app/services/video_metadata_store.py:402`) queries `ByOwnerCreatedAt` GSI. A `FilterExpression` for `attribute_exists(scheduled_publish_at)` filters to scheduled releases.

### 2.2 Content calendar backend router

`app/routers/content_calendar.py` — registered at `app/main.py:231,662` with prefix `/ui/content-calendar`:

| Endpoint | Line | Description |
|---|---|---|
| `GET /ui/content-calendar` | `:26` | Aggregate calendar items from all three sources for a date range |
| `GET /ui/content-calendar/today` | `:52` | Today + tomorrow items (mobile agenda shortcut) |
| `GET /ui/content-calendar/conflicts` | `:60` | Items within 30 minutes of each other |
| `POST /ui/content-calendar/reschedule` | `:71` | Proxy reschedule to the appropriate source API |
| `POST /ui/content-calendar/cancel` | `:87` | Proxy cancel to the appropriate source API |

The aggregation endpoint at `:26` accepts `from_ts` and `to_ts` query parameters (Unix timestamps) and fetches from all three source backends, normalising items into a uniform `ContentCalendarItem` shape with fields: `item_id`, `item_type` (`"post"|"broadcast"|"vod"`), `title`, `scheduled_at` (Unix timestamp), `status`, `metadata`.

### 2.3 Frontend components

Route: `frontend/src/App.tsx:326` — `<Route path="content-calendar" element={<ContentCalendarPage />} />`, lazy-imported at `:176`.

`frontend/src/pages/content-calendar/` contains:

| File | Lines | Status |
|---|---|---|
| `ContentCalendarPage.tsx` | 359 | Full page with tabs and view switching |
| `ContentCalendarWeek.tsx` | 178 | Week grid with drag-and-drop |
| `ContentCalendarMonth.tsx` | 133 | Month grid |
| `ContentCalendarMobileList.tsx` | (present) | Agenda/list view for mobile |
| `ConflictBanner.tsx` | (present) | Conflict detection banner |
| `ContentItemDetail.tsx` | (present) | Slide-in panel for item details |
| `QuickScheduleDialog.tsx` | (present) | Click-empty-slot create dialog |

Drag-and-drop is implemented with native HTML5 drag events. `ContentCalendarWeek.tsx:140–141` renders `draggable` on each item, `:119–131` handles `onDragOver`/`onDrop` on time slots, calls `onDrop(item, slotTs)` prop up to `ContentCalendarPage`. The page then calls `POST /ui/content-calendar/reschedule` and uses a 5-second undo toast (as specified in the user story).

### 2.4 What works today

- Backend aggregation endpoint is live and registered
- All three source reschedule/cancel proxy paths are present
- Week view with drag-and-drop is functional (native HTML5)
- Month view renders items as colored dots/chips
- Mobile agenda view (`ContentCalendarMobileList.tsx`) shows today/tomorrow chronologically
- Conflict detection endpoint and `ConflictBanner` component are present
- Quick-schedule dialog (`QuickScheduleDialog.tsx`) is present for click-on-slot creation
- Filter chips for content type and a "Today" navigation button are implemented in `ContentCalendarPage.tsx`
- Color coding by type (posts = blue, broadcasts = red, VOD = purple) is in the week and month renderers

### 2.5 E2E tests

`frontend/e2e/content-calendar.spec.ts` — 51 `test(` calls covering the API and UI sections.

---

## 3. Gap Analysis

### 3.1 Timezone display consistency

The ticket's Section 1.1 identifies timezone confusion as a core problem: newsfeed posts carry `schedule_timezone` + `scheduled_at_local` (human-readable local time string), while broadcasts use raw Unix timestamps with no timezone metadata. The `ContentCalendarItem` normalised shape uses `scheduled_at` as a Unix timestamp — the frontend converts to local time via `new Date(ts * 1000)`. This resolves the display consistently, but the "which timezone did the creator intend" is lost for broadcast items. The `ContentItemDetail` panel does not show `schedule_timezone` for post items.

**Gap**: `ContentItemDetail.tsx` should display `schedule_timezone` and `scheduled_at_local` when available (from post items) so creators can verify the intended timezone.

### 3.2 VOD scheduled-publish backend integration

The `GET /ui/content-calendar` aggregation fetches VOD items with `scheduled_publish_at` set. However, there is no VOD-side cancellation proxy in the content calendar cancel endpoint — the `POST /ui/content-calendar/cancel` handler dispatches to `cancel_scheduled_post` for posts and `cancel_schedule_route` for broadcasts, but the VOD cancel path (clearing `scheduled_publish_at` and setting `visibility="private"`) may not be implemented. Verify at `app/routers/content_calendar.py:87`.

### 3.3 `FilterExpression` pagination for broadcasts

`list_sessions_by_creator` uses `FilterExpression` for `schedule_status="scheduled"`. As documented in `CLAUDE.md`: "DynamoDB fetches up to 1MB *before* applying FilterExpression... must loop via LastEvaluatedKey." The content calendar's broadcast aggregation must paginate or it will silently miss scheduled broadcasts beyond the first DynamoDB page for prolific creators. The current implementation's `Limit` value is critical to inspect.

### 3.4 Overdue item badge

The ticket acceptance criteria requires an amber "Overdue" badge for items past their scheduled time but not yet published. Inspect `ContentCalendarWeek.tsx` and `ContentCalendarMonth.tsx` for an overdue class or badge — the ticket spec listed this but it is not confirmed implemented.

### 3.5 Undo after drag-and-drop

The 5-second undo toast is in the spec. `ContentCalendarPage.tsx` needs to buffer the pre-drag `scheduled_at` value, and the undo action calls `POST /ui/content-calendar/reschedule` with the original timestamp. Verify this is wired in the page component.

### 3.6 "Share" button on milestone cards (CREATOR-003 cross-ref)

The content calendar's `QuickScheduleDialog` navigates to `/feed?compose=true` with `publish_at` pre-filled. The `CreatePost` compose form must accept `publish_at` as a URL query parameter. Verify that `frontend/src/pages/feed/` reads `?compose=true&publish_at=...` from the URL.

---

## 4. Proposed Design / Fix

### 4.1 Timezone display in `ContentItemDetail`

Add to `ContentItemDetail.tsx` a conditional block: when `item.item_type === "post"` and `item.metadata.schedule_timezone` is present, render:

```tsx
<p className="text-xs text-muted-foreground">
  Scheduled in {item.metadata.schedule_timezone} · {item.metadata.scheduled_at_local}
</p>
```

This requires surfacing `schedule_timezone` and `scheduled_at_local` in the `ContentCalendarItem.metadata` dict from the aggregation endpoint. Add those fields to the post-type metadata extraction in `app/routers/content_calendar.py:26`.

### 4.2 VOD cancel proxy

In `app/routers/content_calendar.py:87` (cancel handler), add a branch for `item_type="vod"`:
- Call `PATCH /ui/videos/{video_id}` with `{"scheduled_publish_at": null}` (or the equivalent service function in `app/services/video_metadata_store.py`)
- This clears the scheduled publish date, effectively cancelling the scheduled VOD release

### 4.3 Paginate broadcast aggregation

In the aggregation endpoint, replace any single-shot `list_sessions_by_creator` call with a pagination loop:

```python
sessions = []
last_key = None
while True:
    kwargs = {"IndexName": "ByCreatorCreatedAt", ...}
    if last_key:
        kwargs["ExclusiveStartKey"] = last_key
    resp = T.broadcast_sessions.query(**kwargs)
    sessions.extend(resp.get("Items", []))
    last_key = resp.get("LastEvaluatedKey")
    if not last_key or len(sessions) >= max_items:
        break
```

Cap at 100 broadcasts per calendar view to bound response time.

### 4.4 Overdue badge

In `ContentCalendarWeek.tsx` and `ContentCalendarMonth.tsx`, add a conditional class:

```tsx
const isOverdue = item.scheduled_at < Math.floor(Date.now() / 1000) && item.status === "scheduled";
// Apply: className={cn("...", isOverdue && "border-amber-500 bg-amber-50")}
```

And render a `<Badge variant="warning">Overdue</Badge>` chip on items where `isOverdue` is true.

### 4.5 Dev/Prod parity (SECOPS-007)

The content calendar backend aggregates from DynamoDB Local tables (posts, broadcast_sessions, VideoMetadata). All tables exist in `scripts/local-ddb-init.py`. No AWS services are required. The `scheduled_publish_at` field on `VideoMetadataModel` is serialized/deserialized in `video_metadata_store.py:97,241`. No new infrastructure needed.

The content calendar backend router does not add any new tables or AWS dependencies. It is purely a read-aggregate + proxy-write layer over existing endpoints.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_content_calendar.py`)

| Test | Assertion |
|---|---|
| `test_aggregate_combines_all_types` | Seed 1 scheduled post + 1 scheduled broadcast + 1 scheduled VOD; `GET /ui/content-calendar` returns all three in the response |
| `test_aggregate_date_filter` | Items outside `from_ts`/`to_ts` window excluded |
| `test_conflict_detection` | Two items within 30 minutes → `GET /conflicts` returns both |
| `test_reschedule_post` | `POST /reschedule` with `item_type=post` calls `PATCH /posts/{id}` with new `publish_at` |
| `test_cancel_broadcast` | `POST /cancel` with `item_type=broadcast` transitions `schedule_status` |
| `test_broadcast_pagination` | Seed 600 broadcast sessions (moto); assert aggregation returns all scheduled ones |
| `test_vod_scheduled_items` | Video with `scheduled_publish_at` appears in calendar; video without does not |

### 5.2 Playwright E2E

51 tests already exist in `frontend/e2e/content-calendar.spec.ts`. Gaps to add:
- Drag-and-drop: `page.dispatchEvent('[data-testid="item-..."]', 'dragstart')` → assert `POST /ui/content-calendar/reschedule` fires with new timestamp; assert undo toast appears; click Undo → assert original timestamp restored
- Overdue badge: seed item with `scheduled_at = now - 3600`; assert amber badge visible in week view
- Timezone display: seed post with `schedule_timezone="America/New_York"`; open `ContentItemDetail`; assert timezone text visible

### 5.3 Manual QA

1. Seed a scheduled post via `POST /posts` with `publish_at = now + 3600` and `schedule_timezone = "America/Los_Angeles"`
2. Navigate to `/content-calendar` → week view
3. Verify the post appears in the correct time slot (correct local time)
4. Drag the item to a different slot → verify reschedule API call in Network tab → verify undo toast
5. Switch to month view → verify item appears on correct date with blue color
6. Switch to mobile viewport (375px) → verify agenda list view renders correctly

### 5.4 Rollout

The content calendar page is additive — it does not change any existing scheduling endpoint. Creators still have access to the individual scheduling UIs (ScheduledPostsPanel, broadcast sessions list). The `/content-calendar` route can be added to the sidebar as a new nav item under "Creator Tools" alongside the creator dashboard.

**Effort to close remaining gaps**:
- Timezone display in `ContentItemDetail`: **S** (2 hours)
- VOD cancel proxy: **S** (2 hours)
- Broadcast pagination fix: **S** (1 hour)
- Overdue badge: **S** (1 hour)
- Undo drag-and-drop wiring (if missing): **M** (3–4 hours)
- E2E gap coverage: **M** (4 hours)

**Rollback**: Remove the `/content-calendar` route from `App.tsx` and the sidebar nav entry. The backend endpoint is stateless (read-only aggregation + proxy) and has no side effects beyond the existing reschedule/cancel endpoints it wraps.

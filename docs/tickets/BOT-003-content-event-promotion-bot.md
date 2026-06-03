# BOT-003: Content & Event Promotion Bot

**Ticket**: BOT-003
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days
**Dependencies**: BOT-001 (Bot Framework & Lifecycle), BOT-002 (Template & Scheduled Messages)

---

## 1. Overview & Motivation

### 1.1 Purpose

BOT-003 enables bots to promote a creator's content intelligently across conversations. Creators curate "content sets" -- collections of videos, posts, broadcasts, and video call time slots -- that bots automatically promote based on configurable rules. Promotion strategies include round-robin rotation, newest-first ordering, and viewer-aware filtering that avoids re-promoting content a user has already seen or purchased. Bots send rich content cards (thumbnail, title, price, call-to-action button) rather than plain text links, driving higher engagement. The system also integrates with broadcast scheduling and calendar booking to announce upcoming events with countdowns and handle time-slot booking requests directly in chat.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to curate a set of content my bot promotes. | Content set CRUD; add/remove videos, posts, broadcasts, call slots. |
| Creator | As a creator, I want my bot to rotate through promotions so users see variety. | Round-robin or random rotation per user per conversation. |
| Creator | As a creator, I want my bot to promote my newest content first. | Newest-first ordering based on `created_at`. |
| Creator | As a creator, I want my bot to skip content users already purchased. | Viewer history check before selecting next promotion item. |
| Creator | As a creator, I want my bot to announce upcoming broadcasts automatically. | Broadcast promotion with countdown sent to configured chats. |
| Creator | As a creator, I want my bot to share my available time slots for booking. | Calendar integration: bot sends available slots; user picks one to book. |
| Creator | As a creator, I want to limit how often my bot promotes content per conversation. | Frequency cap: max N promotions per conversation per day. |
| User | As a user, I want content promotions to be rich cards, not just text links. | Content card with thumbnail, title, price, CTA button. |
| User | As a user, I want to book a video call slot directly from a bot message. | Tap "Book" on a time slot card; booking confirmed via calendar API. |

### 1.3 Why This Is Needed

Creators produce content across multiple formats (VODs, posts, broadcasts, calls) but have no automated way to cross-promote. Manually sending links to hundreds of fans is impractical. Content promotion bots solve this by systematically surfacing relevant content to each user, increasing discovery and revenue. Smart filtering (skip already-purchased) respects the user experience while maximizing conversion. Broadcast announcements with countdowns drive live viewership. Calendar booking in chat removes friction from scheduling paid calls.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Bot framework** (BOT-001): Bot CRUD, assignments, trigger evaluation, `send_bot_message()`.
- **Templates** (BOT-002): Template engine, variable substitution, scheduled sends, quick-reply buttons.
- **Video listings** (`app/routers/video_listing.py`): Video metadata stored in DDB; listing API returns video cards with thumbnail URLs, title, price, duration. (see `app/routers/video_listing.py` — file exists)
- **Newsfeed** (`app/routers/newsfeed.py`): Posts stored in `app_single_table` with `PK=POST#{post_id}`. `_post_to_dict()` returns post data including `image_url`, `text`, `unlock_price_cents`.
- **Broadcasts** (`app/routers/broadcast.py`): `BroadcastSessionOut` (see `app/routers/broadcast.py:117`) includes title, scheduled start time, thumbnail. Scheduled broadcasts queryable via `list_scheduled_sessions_route` (see line 301).
- **Calendar** (`app/routers/calendar.py`): Calendar events with booking links. `invert_intervals()` (see `app/routers/calendar.py:236`) computes free slots. Public event page at `/event/:calendarId/:eventId`.
- **Messaging content cards**: `MessageOut` (see `app/routers/messaging.py:2325`) supports `video_share`, `calendar_share`, `calendar_event` kinds (see line 2330) with rich metadata. Bot messages can use these kinds.
- **Purchase tracking**: `purchase_transactions` table (see `scripts/local-ddb-init.py:64`) tracks user purchases by `user_sub`.
- **Broadcast reminders** (`app/services/broadcast_reminders.py`): Existing reminder infrastructure for scheduled broadcasts. (see `app/services/broadcast_reminders.py` — file exists)

### 2.2 Gaps

1. No content set model -- no way to curate a collection of mixed content types for promotion.
2. No promotion strategy engine (rotation, newest-first, viewer-aware filtering).
3. No per-user promotion history tracking to avoid re-promoting seen/purchased content.
4. No content card message kind specifically designed for bot promotions.
5. No broadcast announcement bot integration (broadcasts have reminders but not bot-driven announcements).
6. No in-chat calendar booking flow (existing calendar share sends a link, but booking requires navigation to the calendar page).
7. No per-conversation frequency caps for bot promotions.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 BotContentSets Table

Stores content items in a bot's promotion set.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BOT#{bot_id}` |
| `sk` | S | `CONTENT#{content_id}` |
| `content_id` | S | UUID hex |
| `bot_id` | S | Parent bot |
| `creator_id` | S | Bot owner |
| `content_type` | S | `video`, `post`, `broadcast`, `call_slot` |
| `content_ref_id` | S | Reference to the actual content (video_id, post_id, session_id, or calendar event_id) |
| `title` | S | Display title for the content card |
| `description` | S (optional) | Short description (max 200 chars) |
| `thumbnail_url` | S (optional) | Thumbnail image URL |
| `price_cents` | N (optional) | Price in cents (null for free content) |
| `cta_label` | S | Call-to-action button text (default: "Watch Now", "Read More", "Join Live", "Book Now") |
| `cta_url` | S | URL to open when CTA is clicked |
| `priority` | N | Manual sort priority (lower = higher priority, default 0) |
| `enabled` | BOOL | Whether this item is active for promotion |
| `created_at` | N | Unix timestamp |
| `GSI1PK` | S | `BOT#{bot_id}#TYPE#{content_type}` |
| `GSI1SK` | N | `created_at` |

**GSI1** (`GSI1PK`, `GSI1SK`): Query content items by type within a bot, sorted by creation date.

```python
TableDef(
    "bot_content_sets", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"priority": "N", "price_cents": "N", "created_at": "N", "GSI1SK": "N"},
),
```

#### 3.1.2 BotPromotionHistory Table

Tracks which content has been promoted to which user in which conversation, enabling viewer-aware filtering and rotation.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BOT#{bot_id}#USER#{user_id}` |
| `sk` | S | `PROMO#{content_id}` |
| `content_id` | S | Content item promoted |
| `conversation_id` | S | Where it was promoted |
| `promoted_at` | N | Unix timestamp of last promotion |
| `impression_count` | N | Times this content was promoted to this user |
| `clicked` | BOOL | Whether user clicked the CTA |
| `purchased` | BOOL | Whether user purchased the content after promotion |

```python
TableDef(
    "bot_promotion_history", "pk", "sk",
    attr_types={"promoted_at": "N", "impression_count": "N"},
),
```

#### 3.1.3 BotPromotionCaps Table

Tracks daily promotion counts per conversation to enforce frequency caps.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BOT#{bot_id}#CONV#{conversation_id}` |
| `sk` | S | `DAY#{YYYY-MM-DD}` |
| `count` | N | Promotions sent today |
| `ttl` | N | DDB TTL (auto-expire after 7 days) |

```python
TableDef(
    "bot_promotion_caps", "pk", "sk",
    attr_types={"count": "N", "ttl": "N"},
),
```

#### 3.1.4 Promotion Rules (on Bot Record)

Stored as a DDB map on the `ChatBots` record (`promotion_config` field):

```json
{
  "strategy": "round_robin",
  "max_promotions_per_day": 3,
  "skip_purchased": true,
  "skip_viewed": false,
  "promotion_cooldown_hours": 4,
  "broadcast_announce_minutes_before": [60, 15],
  "broadcast_announce_targets": ["all_dms", "all_broadcasts"]
}
```

Strategy options:
- `round_robin` -- cycle through content items in priority order, advancing per user
- `random` -- pick random enabled item (respecting skip filters)
- `newest_first` -- promote by `created_at` descending
- `priority` -- promote by `priority` field ascending (creator-set order)

### 3.2 Content Card Message Kind

A new message kind `content_card` is sent by bots for promotions:

```python
# Extension to MessageOut.kind Literal
kind: Literal[..., "content_card"]

# New field on MessageOut
content_card: Optional[Dict[str, Any]] = None
# Shape:
# {
#   "content_type": "video",
#   "content_ref_id": "abc123",
#   "title": "My Latest Video",
#   "description": "Check out this exclusive content!",
#   "thumbnail_url": "https://...",
#   "price_cents": 999,
#   "cta_label": "Watch Now",
#   "cta_url": "/videos/abc123",
#   "bot_promotion_id": "promo_xyz"  # for click tracking
# }
```

### 3.3 Backend Service (`app/services/bot_promotion.py`)

```python
def add_content_to_set(*, bot_id: str, creator_id: str, content_type: str,
                        content_ref_id: str, title: str,
                        description: str | None = None,
                        thumbnail_url: str | None = None,
                        price_cents: int | None = None,
                        cta_label: str | None = None,
                        cta_url: str | None = None,
                        priority: int = 0) -> dict:
    """Add a content item to a bot's promotion set."""
    # 1. Verify bot ownership
    # 2. Validate content_ref_id exists (check video/post/broadcast/calendar tables)
    # 3. Generate content_id
    # 4. Auto-populate cta_label/cta_url based on content_type if not provided
    # 5. Write to BotContentSets table

def remove_content_from_set(*, bot_id: str, content_id: str, creator_id: str) -> dict:
    """Remove a content item from the promotion set."""

def list_content_set(*, bot_id: str, content_type: str | None = None) -> list[dict]:
    """List content items in a bot's promotion set."""

def update_content_item(*, bot_id: str, content_id: str, creator_id: str,
                         **fields) -> dict:
    """Update content item metadata (title, description, priority, enabled)."""

def select_next_promotion(*, bot_id: str, user_id: str,
                           conversation_id: str) -> dict | None:
    """Select the next content item to promote based on strategy.
    Returns None if all items filtered out or frequency cap reached."""
    # 1. Fetch bot promotion_config
    # 2. Check frequency cap for conversation today
    # 3. Fetch all enabled content items
    # 4. Fetch promotion history for this user
    # 5. Filter: skip purchased (if enabled), skip recently promoted (cooldown)
    # 6. Apply strategy (round_robin/random/newest_first/priority)
    # 7. Return selected content item or None

def send_promotion(*, bot_id: str, conversation_id: str, user_id: str,
                    content_item: dict) -> dict:
    """Send a content card message via the bot."""
    # 1. Build content_card payload from content_item
    # 2. Call send_bot_message with kind="content_card"
    # 3. Record promotion in BotPromotionHistory
    # 4. Increment daily promotion cap counter
    # 5. Return message dict

def record_promotion_click(*, bot_id: str, content_id: str, user_id: str) -> None:
    """Track that a user clicked a promotion CTA."""

def record_promotion_purchase(*, bot_id: str, content_id: str, user_id: str) -> None:
    """Track that a user purchased promoted content."""

def announce_broadcast(*, bot_id: str, session_id: str,
                        minutes_before: int) -> dict[str, int]:
    """Send broadcast announcement to configured targets."""
    # 1. Fetch broadcast session details
    # 2. Build announcement text with countdown
    # 3. Resolve target conversations from bot assignments
    # 4. Send content_card messages to each target
    # 5. Return {"sent": N, "failed": M}

def send_available_slots(*, bot_id: str, conversation_id: str,
                          calendar_id: str, date_range_days: int = 7) -> dict:
    """Send a message with available booking time slots."""
    # 1. Fetch free slots from calendar service (invert_intervals)
    # 2. Format as quick-reply buttons (one per slot)
    # 3. Send bot message with quick_replies for slot selection
    # 4. Return message dict

def handle_slot_booking(*, bot_id: str, conversation_id: str,
                         user_id: str, slot_value: str) -> dict:
    """Process a user's slot selection and create a booking."""
    # 1. Parse slot_value (contains calendar_id + start_time + end_time)
    # 2. Check slot is still available
    # 3. Create calendar event via existing calendar service
    # 4. Send confirmation content_card with event details
    # 5. Return booking result
```

### 3.4 Broadcast Announcement Integration (`app/services/bot_broadcast_announcer.py`)

Background async loop runs every 60 seconds. `_check_and_announce_broadcasts()` queries scheduled broadcasts starting within 120 minutes, finds bots with `broadcast_announce` config, deduplicates announcements already sent at this tier, and calls `announce_broadcast()` for due announcements. `start_broadcast_announcement_task()` is called from `main.py` startup.

### 3.5 Backend Router (`app/routers/bot_promotion.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/bots/{bot_id}/content-set` | `require_ui_session` | Add content item to set |
| GET | `/ui/bots/{bot_id}/content-set` | `require_ui_session` | List content set (optional `?type=` filter) |
| PUT | `/ui/bots/{bot_id}/content-set/{content_id}` | `require_ui_session` | Update content item |
| DELETE | `/ui/bots/{bot_id}/content-set/{content_id}` | `require_ui_session` | Remove content item |
| POST | `/ui/bots/{bot_id}/promote` | `require_ui_session` | Manually trigger a promotion in a conversation |
| GET | `/ui/bots/{bot_id}/promotion-stats` | `require_ui_session` | Promotion analytics (impressions, clicks, purchases) |
| POST | `/ui/bots/{bot_id}/content-set/import` | `require_ui_session` | Bulk import content from videos/posts/broadcasts |
| POST | `/ui/bots/{bot_id}/send-slots` | `require_ui_session` | Manually send available time slots to a conversation |
| POST | `/ui/bots/promotion-click` | `require_ui_session` | Record CTA click (called by frontend) |
| PUT | `/ui/bots/{bot_id}/promotion-config` | `require_ui_session` | Update promotion strategy and rules |

**Key request models**:

```python
class AddContentToSetIn(BaseModel):
    content_type: Literal["video", "post", "broadcast", "call_slot"]
    content_ref_id: str
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=200)
    thumbnail_url: Optional[str] = None
    price_cents: Optional[int] = Field(default=None, ge=0)
    cta_label: Optional[str] = Field(default=None, max_length=40)
    cta_url: Optional[str] = None
    priority: int = Field(default=0, ge=0, le=1000)

class UpdatePromotionConfigIn(BaseModel):
    strategy: Optional[Literal["round_robin", "random", "newest_first", "priority"]] = None
    max_promotions_per_day: Optional[int] = Field(default=None, ge=1, le=20)
    skip_purchased: Optional[bool] = None
    skip_viewed: Optional[bool] = None
    promotion_cooldown_hours: Optional[int] = Field(default=None, ge=0, le=168)
    broadcast_announce_minutes_before: Optional[List[int]] = None
    broadcast_announce_targets: Optional[List[str]] = None
```

Additional models: `UpdateContentItemIn` (all fields optional), `BulkImportContentIn` (content_type + limit), `TriggerPromotionIn` (conversation_id), `SendSlotsIn` (conversation_id + calendar_id + date_range_days), `PromotionClickIn` (bot_id + content_id). Response models `ContentSetItemOut` and `PromotionStatsOut` mirror the DDB fields with aggregated click/purchase rates.

Register in `app/main.py`:

```python
from app.routers.bot_promotion import router as bot_promotion_router
app.include_router(bot_promotion_router, prefix="/ui")
```

### 3.6 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface BotContentSetItem {
  content_id: string;
  bot_id: string;
  content_type: "video" | "post" | "broadcast" | "call_slot";
  content_ref_id: string;
  title: string;
  description?: string;
  thumbnail_url?: string;
  price_cents?: number;
  cta_label: string;
  cta_url: string;
  priority: number;
  enabled: boolean;
  created_at: number;
}

export interface ContentCard {
  content_type: string;
  content_ref_id: string;
  title: string;
  description?: string;
  thumbnail_url?: string;
  price_cents?: number;
  cta_label: string;
  cta_url: string;
  bot_promotion_id?: string;
}
```

Additional types: `BotPromotionConfig` (strategy, caps, skip flags, broadcast announce config), `BotPromotionStats` (aggregate impressions/clicks/purchases + per-item breakdown). Extend `MessageOut` with `content_card?: ContentCard`.

### 3.7 Frontend API (`frontend/src/api/endpoints/bots.ts`)

Standard CRUD wrappers for content set and promotion endpoints (matching router paths in 3.5). Key functions: `addContentToSet`, `listContentSet`, `updateContentItem`, `removeContentFromSet`, `bulkImportContent`, `triggerPromotion`, `getPromotionStats`, `updatePromotionConfig`, `recordPromotionClick`, `sendSlots`.

### 3.8 Frontend Pages

- **ContentSetPage** (`frontend/src/pages/bots/ContentSetPage.tsx`): Route `/bots/:botId/content`. Displays content set as draggable cards (reorder priority). Filter by content type tabs (All / Videos / Posts / Broadcasts / Call Slots). Each card: thumbnail, title, type badge, price, enable/disable toggle. "Import" button opens dialog to bulk-import from existing videos/posts. "Add Custom" for manual entry. `data-testid="content-set-page"`.
- **PromotionConfigPanel** (`frontend/src/pages/bots/PromotionConfigPanel.tsx`): Panel within BotEditorDialog. Strategy selector (dropdown). Frequency cap slider. Toggle switches for skip_purchased, skip_viewed. Broadcast announcement timing config (multi-select minute values). `data-testid="promotion-config-panel"`.
- **PromotionStatsPanel** (`frontend/src/pages/bots/PromotionStatsPanel.tsx`): Analytics panel. Funnel chart: impressions -> clicks -> purchases. Per-item table with click-through rates. Date range selector. `data-testid="promotion-stats-panel"`.

### 3.9 ContentCardBubble Component (`frontend/src/pages/messages/ContentCardBubble.tsx`)

Renders content card messages in the conversation view:

```tsx
<div className="border rounded-lg overflow-hidden max-w-sm" data-testid="content-card">
  {card.thumbnail_url && (
    <img src={card.thumbnail_url} alt={card.title} className="w-full h-40 object-cover" />
  )}
  <div className="p-3">
    <Badge variant="outline">{card.content_type}</Badge>
    <h4 className="font-semibold mt-1">{card.title}</h4>
    {card.description && <p className="text-sm text-muted-foreground">{card.description}</p>}
    {card.price_cents != null && (
      <p className="text-sm font-medium">${(card.price_cents / 100).toFixed(2)}</p>
    )}
    <Button className="mt-2 w-full" size="sm" asChild
            onClick={() => recordPromotionClick(card.bot_promotion_id)}>
      <a href={card.cta_url}>{card.cta_label}</a>
    </Button>
  </div>
</div>
```

Integrated into `MessageBubble.tsx` when `message.kind === "content_card"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/bot_promotion.py` | Content set CRUD, promotion strategy engine, history tracking |
| `app/services/bot_broadcast_announcer.py` | Background broadcast announcement loop |
| `app/routers/bot_promotion.py` | Content set + promotion endpoints |
| `frontend/src/pages/bots/ContentSetPage.tsx` | Content set management UI |
| `frontend/src/pages/bots/PromotionConfigPanel.tsx` | Promotion strategy config panel |
| `frontend/src/pages/bots/PromotionStatsPanel.tsx` | Analytics panel |
| `frontend/src/pages/messages/ContentCardBubble.tsx` | Content card message component |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `bot_content_sets`, `bot_promotion_history`, `bot_promotion_caps` TableDefs <!-- NOTE: None of these tables exist yet — new implementation required --> |
| `app/core/settings.py` | Add table name settings <!-- NOTE: No promotion settings exist yet — new implementation required --> |
| `app/core/tables.py` | Add table handles <!-- NOTE: No promotion table handles exist yet — new implementation required --> |
| `app/main.py` | Register `bot_promotion_router`; start broadcast announcer task <!-- NOTE: Neither exists yet — new implementation required --> |
| `app/routers/messaging.py` | Add `content_card` to `MessageOut.kind` Literal; add `content_card` field <!-- NOTE: content_card kind does not exist on MessageOut at line 2330 — new implementation required --> |
| `app/services/chat_bot.py` | Add `promotion_config` to bot record handling <!-- NOTE: chat_bot.py does not exist yet — depends on BOT-001 --> |
| `frontend/src/api/types.ts` | Add content set, promotion config, stats, content card types |
| `frontend/src/api/endpoints/bots.ts` | Add content set and promotion API functions |
| `frontend/src/pages/messages/MessageBubble.tsx` | Render `ContentCardBubble` for `content_card` kind |
| `frontend/src/App.tsx` | Add `/bots/:botId/content` route |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/bot-promotion.spec.ts` -- 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let botId: string;
let contentId1: string;
let contentId2: string;
let conversationId: string;
// Alice = creator (bot owner), Bob = user in conversation
```

### 5.3 Section 515: Content Set CRUD API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 515.1 | Add video to content set | POST `/ui/bots/{botId}/content-set` with `content_type=video`; 201; `content_id`, `title`, `cta_label="Watch Now"` |
| 515.2 | Add post to content set | POST with `content_type=post`; 201; `cta_label="Read More"` |
| 515.3 | List content set | GET `/ui/bots/{botId}/content-set`; array length >= 2 |
| 515.4 | Remove content item | DELETE; 200; list length decremented |

### 5.4 Section 516: Promotion Strategy API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 516.1 | Configure promotion strategy | PUT `/ui/bots/{botId}/promotion-config` with `strategy=round_robin`, `max_promotions_per_day=3`; 200 |
| 516.2 | Trigger manual promotion | POST `/ui/bots/{botId}/promote` with `conversation_id`; 200; message appears in conversation with `kind=content_card` |
| 516.3 | Content card has correct fields | Fetch latest message; `content_card.title` matches; `content_card.cta_label` present |
| 516.4 | Frequency cap enforced | Trigger 4 promotions (cap=3); 4th returns 429 or empty result |

### 5.5 Section 517: Broadcast Announcement & Slot Booking API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 517.1 | Bulk import videos to content set | POST `/ui/bots/{botId}/content-set/import` with `content_type=video`, `limit=5`; 200; `imported` count returned |
| 517.2 | Update content item priority | PUT with `priority=10`; 200; item priority updated |
| 517.3 | Send time slots to conversation | POST `/ui/bots/{botId}/send-slots` with `conversation_id`, `calendar_id`; 200; message with quick_replies for slot selection |
| 517.4 | Get promotion stats | GET `/ui/bots/{botId}/promotion-stats`; 200; `total_impressions >= 1` |

### 5.6 Section 518: Content Card UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 518.1 | Content set page loads | Navigate `/bots/{botId}/content`; `[data-testid="content-set-page"]` visible |
| 518.2 | Add content via UI | Click "Add Custom"; fill title, type=video; save; card appears |
| 518.3 | Content card renders in conversation | Send promotion via API; navigate to conversation; `[data-testid="content-card"]` visible with title |
| 518.4 | CTA button click tracked | Click CTA button on content card; POST to promotion-click endpoint fires |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Bot not found | 404 | "Bot not found" |
| Not bot owner | 403 | "You do not own this bot" |
| Content item not found | 404 | "Content item not found" |
| Content ref invalid | 404 | "Referenced content not found: {content_ref_id}" |
| Max content set size | 409 | "Maximum of 100 content items per bot" |
| Frequency cap reached | 429 | "Daily promotion limit reached for this conversation" |
| Calendar not found | 404 | "Calendar not found" |
| No available slots | 200 | Returns empty slots array (not an error) |
| Slot no longer available | 409 | "This time slot is no longer available" |
| Duplicate content ref | 409 | "This content is already in the promotion set" |

---

## 7. Security Considerations

- **Ownership enforcement**: All content set and promotion operations verify bot ownership. Users cannot manipulate other creators' promotion sets.
- **Content validation**: `content_ref_id` is validated against the actual content tables (video, post, broadcast, calendar) to ensure the creator owns the referenced content. A creator cannot promote another creator's content.
- **CTA URL validation**: `cta_url` must be a relative URL (same-site) or an allowed external domain. Open redirect prevention: reject `javascript:` and `data:` URLs.
- **Frequency cap anti-bypass**: Caps tracked server-side in DDB (not client-side). Rate limit enforced per bot per conversation, not per API call -- prevents rapid fire even if client retries.
- **Promotion history privacy**: A creator cannot see which specific users clicked or purchased via individual user tracking. Stats are aggregated only.
- **Calendar slot booking**: Booking availability is double-checked at booking time (not just at slot display time) to prevent overbooking.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Content set scan for promotion selection | Content sets capped at 100 items; full scan is ~4KB, fast |
| Promotion history per user grows over time | DDB TTL: auto-expire promotion history records after 90 days |
| Broadcast announcement fan-out | Announcements capped at 500 conversations per bot; processed in batches of 25 with 100ms delay |
| Promotion click tracking writes | Fire-and-forget write; no read-back; atomic counter increment |
| Stats aggregation | Pre-computed in background (aggregated counts on content items), not computed at query time |
| Daily cap counter cleanup | DDB TTL on `bot_promotion_caps` (7-day expiry); no manual cleanup needed |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| BOT-001 (Bot Framework) | BOT-001 | Required (bot CRUD, send_bot_message) |
| BOT-002 (Templates) | BOT-002 | Required (template rendering for announcement text, quick_replies for slot selection) |
| Video listing | Existing | Available (video metadata for content cards) |
| Newsfeed | Existing | Available (post data for content cards) |
| Broadcast | Existing | Available (scheduled broadcasts for announcements) |
| Calendar | Existing | Available (booking slots, event creation) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| ANALYTICS-001 (Creator Analytics) | Promotion stats feed into creator analytics dashboard |

---

## 10. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│            Content & Event Promotion Bot Architecture               │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │ New Content  │   │ Scheduled    │   │ Manual       │
  │ Published    │   │ Promotion    │   │ Broadcast    │
  │ (VOD/post)   │   │ (cron)       │   │ (admin)      │
  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
         └──────────────────┼──────────────────┘
                            ▼
  ┌──────────────────────────────────────┐
  │   Promotion Bot Engine               │
  │                                      │
  │  1. Select content from set          │
  │  2. Check promotion caps             │
  │  3. Render content_card message      │
  │  4. Deliver via send_bot_message     │
  │  5. Track click/conversion           │
  └──────┬──────────┬──────────┬────────┘
         │          │          │
         ▼          ▼          ▼
  ┌──────────┐ ┌──────────┐ ┌──────────┐
  │ Content  │ │ Promotion│ │ Promotion│
  │ Sets     │ │ History  │ │ Caps     │
  │ (DDB)    │ │ (DDB)    │ │ (DDB)    │
  └──────────┘ └──────────┘ └──────────┘
```

---

## 11. DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | GSI | Notes |
|----------------|-------|----|----|-----|-------|
| Get content set | `bot_content_sets` | `BOT#{bot_id}` | `SET#{set_id}` | -- | Single item |
| List sets for bot | `bot_content_sets` | `BOT#{bot_id}` | begins_with `SET#` | -- | All sets |
| List items in set | `bot_content_sets` | `BOT#{bot_id}` | begins_with `SET#{set_id}#ITEM#` | -- | Content items |
| Get promotion history | `bot_promotion_history` | `USER#{user_id}` | `PROMO#{ts}` | -- | Recent promotions |
| Check daily cap | `bot_promotion_caps` | `BOT#{bot_id}#USER#{user_id}` | `DATE#{YYYY-MM-DD}` | -- | Today's count |
| Increment click count | `bot_content_sets` | `BOT#{bot_id}` | `SET#{set_id}#ITEM#{item_id}` | -- | ADD click_count |

---

## 12. API Request/Response Examples

```bash
# --- POST /ui/bots/{bot_id}/content-sets ---
curl -X POST http://localhost:8000/ui/bots/bot-001/content-sets \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Summer VOD Promo",
    "content_type": "vod",
    "items": [
      {"content_id": "vod-001", "title": "Beach Workout", "thumbnail_url": "..."},
      {"content_id": "vod-002", "title": "Sunset Yoga", "thumbnail_url": "..."}
    ],
    "strategy": "round_robin",
    "daily_cap": 3
  }'

# Response 201:
{
  "set_id": "set-abc-123",
  "bot_id": "bot-001",
  "name": "Summer VOD Promo",
  "items_count": 2,
  "strategy": "round_robin",
  "daily_cap": 3,
  "created_at": 1748534400
}

# --- POST /ui/bots/{bot_id}/broadcast ---
curl -X POST http://localhost:8000/ui/bots/bot-001/broadcast \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "Content-Type: application/json" \
  -d '{"content_set_id": "set-abc-123", "message_text": "Check out our new summer content!"}'

# Response 200:
{
  "broadcast_id": "bcast-001",
  "conversations_targeted": 142,
  "messages_sent": 142,
  "status": "completed"
}
```

---

## 13. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------------|-------------|------------|---------------------|-----------------|
| Bot not found | 404 | `BOT_NOT_FOUND` | "Bot not found." | Verify bot_id |
| Content set not found | 404 | `SET_NOT_FOUND` | "Content set not found." | Verify set_id |
| Daily cap reached | 429 | `DAILY_CAP_REACHED` | "Daily promotion limit reached." | Wait until tomorrow |
| Empty content set | 422 | `EMPTY_CONTENT_SET` | "Content set has no items." | Add items first |
| Invalid strategy | 422 | `INVALID_STRATEGY` | "Strategy must be round_robin, random, or weighted." | Fix strategy value |
| Content not found | 404 | `CONTENT_NOT_FOUND` | "Referenced content does not exist." | Check content_id |
| Broadcast too large | 422 | `BROADCAST_TOO_LARGE` | "Max 500 conversations per broadcast." | Reduce scope |

---

## 14. Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional, List

class ContentItemIn(BaseModel):
    content_id: str
    title: str = Field(max_length=200)
    thumbnail_url: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=500)

class CreateContentSetIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    content_type: Literal["vod", "post", "event", "product"]
    items: List[ContentItemIn] = Field(..., min_length=1, max_length=100)
    strategy: Literal["round_robin", "random", "weighted"] = "round_robin"
    daily_cap: int = Field(default=5, ge=1, le=50)

class ContentSetOut(BaseModel):
    set_id: str
    bot_id: str
    name: str
    content_type: str
    items_count: int
    strategy: str
    daily_cap: int
    created_at: int

class BroadcastIn(BaseModel):
    content_set_id: str
    message_text: Optional[str] = Field(default=None, max_length=1000)

class BroadcastOut(BaseModel):
    broadcast_id: str
    conversations_targeted: int
    messages_sent: int
    status: Literal["completed", "partial", "failed"]

class PromotionStatsOut(BaseModel):
    set_id: str
    total_sent: int
    total_clicks: int
    click_rate: float
    top_item: Optional[str] = None
```

---

## 15. Frontend Component Tree

```
PromotionBotPage                      data-testid="promotion-bot-page"
├── Tabs
│   ├── TabsTrigger "Content Sets"
│   ├── TabsTrigger "Broadcast"
│   └── TabsTrigger "Analytics"
├── TabsContent "sets"
│   ├── Button "New Content Set"
│   └── DataTable (content sets)
│       ├── columns: [name, type, items_count, strategy, daily_cap]
│       └── row click → ContentSetDetail
├── TabsContent "broadcast"
│   ├── Select (content_set_id)
│   ├── Textarea (message_text)
│   └── Button "Send Broadcast"
└── TabsContent "analytics"
    ├── StatCard "Total Sent" / "Total Clicks" / "Click Rate"
    └── DataTable (per-item stats)
```

---

## 16. Observability & Monitoring

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `promotion_messages_sent_total` | Counter | `bot_id`, `content_type` | Promotions sent |
| `promotion_clicks_total` | Counter | `bot_id`, `content_type` | Click-throughs |
| `promotion_daily_cap_hits_total` | Counter | `bot_id` | Cap limit reached |
| `broadcast_messages_total` | Counter | `bot_id`, `status` | Broadcast volume |

---

## 17. Rollout Plan

| Flag | Default | Description |
|------|---------|-------------|
| `PROMOTION_BOT_ENABLED` | `false` | Master kill switch |
| `PROMOTION_BROADCAST_ENABLED` | `false` | Allow mass broadcasts |
| `PROMOTION_TRACKING_ENABLED` | `true` | Click/conversion tracking |

### Canary

1. **Week 1**: Single bot, 10 users, round_robin only.
2. **Week 2**: Enable broadcast to all conversations.
3. **Week 3**: Enable analytics tracking.

---

## 18. Expanded E2E Test Details

### Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| E1 | Promotion after cap reset (next day) | Simulate date change; promotion succeeds |
| E2 | Content set with deleted content | Item with invalid content_id; skip gracefully |
| E3 | Broadcast to zero conversations | Bot with no assignments; messages_sent=0 |
| E4 | Concurrent broadcast triggers | Second broadcast gets 409 if first still running |

### Negative Tests (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| N1 | Create set with >100 items | 422 validation error |
| N2 | Non-owner cannot manage content sets | Bob (not bot owner) POSTs set; 403 |
| N3 | Broadcast with non-existent set_id | 404 |

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_bot_content_promotion.py`

**Mock setup**: moto mock for DynamoDB (bot tables, messages table). Mock LLM API for BOT-004.

| Test Function | Description |
|---|---|
| `test_create_bot` | Create bot with name, avatar, description; verify stored |
| `test_list_bots_for_creator` | List bots; returns only creator's bots |
| `test_update_bot_state` | Transition active -> paused -> active; verify state |
| `test_assign_bot_to_conversation` | Assign bot; verify assignment stored |
| `test_trigger_evaluation` | Send message matching keyword trigger; bot responds |
| `test_bot_message_has_sender_type_bot` | Bot message has `sender_type=bot` and bot identity |
| `test_max_bots_per_creator` | Exceed limit (10); returns 409 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Create bot -> assign to conversation -> send trigger message -> verify bot response
2. Bot message appears in conversation with correct sender identity
3. Paused bot does not respond to triggers

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/bot-content-promotion.spec.ts`

**Auth pattern**: `injectAuth(page, "alice")` for creator; `injectAuth(page, "bob")` for user interacting with bot; CSRF header for mutations

| # | Test Name | Assertion |
|---|---|---|
| 1 | API creates bot | POST returns bot with ID |
| 2 | API lists creator bots | GET returns array of bots |
| 3 | API updates bot state | PATCH state to paused; verify |
| 4 | API assigns bot to conversation | POST assignment; verify |
| 5 | Bot responds to trigger | Send keyword message; bot reply appears |
| 6 | Bot message shows bot badge | Bot message has 'Bot' indicator |
| 7 | UI bot management page loads | Navigate to bot management; heading visible |
| 8 | UI create bot form works | Fill form; submit; bot appears in list |
| 9 | Paused bot does not respond | Pause bot; send trigger; no response |
| 10 | Unauthenticated returns 401 | No session -> 401 |
| 11 | Non-owner bot access returns 403 | Bob tries to edit Alice's bot -> 403 |
| 12 | Max bots limit enforced | Create 11th bot -> 409 |

**Negative tests**: 401 unauthenticated, 403 non-owner, 404 non-existent bot, 409 max limit, 422 validation

**Edge cases**: Bot assigned to ALL_DMS wildcard, concurrent trigger messages, empty trigger config, bot in disabled state

### Test Data Requirements

Create test bot via API in `beforeAll`. Create test conversation between Alice and Bob for trigger testing.

**Test users**: Alice (USER, bot creator), Bob (USER, message sender), Root (ROOT, admin)

### CI/Pipeline

Serial execution. Retry-safe (unique bot names per run).

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| BOT-001 | Bot framework and `send_bot_message()` | Implemented | No -- must merge after |
| BOT-002 | Template engine and scheduled sends | Implemented | No -- must merge after |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Sequential after BOT-002. Adds content set CRUD, promotion strategies, and broadcast/calendar integration.

### Merge Checklist

- [ ] DDB table `ChatBots` added to `scripts/local-ddb-init.py`
- [ ] Bot service and router registered in `app/main.py`
- [ ] Frontend bot management page and API wrappers created
- [ ] E2E tests pass in CI
- [ ] No breaking changes to existing messaging system

---

## Codebase References

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `video_listing.py` exists | `app/routers/video_listing.py` | exists | VERIFIED |
| `BroadcastSessionOut` model | `app/routers/broadcast.py` | 117 | VERIFIED |
| Scheduled broadcasts route | `app/routers/broadcast.py` | 301 | VERIFIED (`list_scheduled_sessions_route`) |
| `invert_intervals()` for free slots | `app/routers/calendar.py` | 236 | VERIFIED |
| `MessageOut` with content kinds | `app/routers/messaging.py` | 2325, 2330 | VERIFIED (video_share, calendar_share, calendar_event exist) |
| `purchase_transactions` table | `scripts/local-ddb-init.py` | 64 | VERIFIED |
| `broadcast_reminders.py` exists | `app/services/broadcast_reminders.py` | exists | VERIFIED |
| No `bot_content_sets` DDB table | `scripts/local-ddb-init.py` | full file | VERIFIED (does not exist — new implementation required) |
| No `bot_promotion_history` DDB table | `scripts/local-ddb-init.py` | full file | VERIFIED (does not exist — new implementation required) |
| No `bot_promotion_caps` DDB table | `scripts/local-ddb-init.py` | full file | VERIFIED (does not exist — new implementation required) |
| No `content_card` message kind | `app/routers/messaging.py` | 2330 | VERIFIED (not in MessageOut.kind Literal — new implementation required) |
| BOT-001 dependency (chat_bot.py) | `app/services/chat_bot.py` | N/A | NOT YET IMPLEMENTED (depends on BOT-001) |
| BOT-002 dependency (bot_template.py) | `app/services/bot_template.py` | N/A | NOT YET IMPLEMENTED (depends on BOT-002) |

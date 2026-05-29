# ADS-019: Content Provider Self-Placed Ads

**Ticket**: ADS-019
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 5-6 days

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-019 enables content providers (creators) to place their own promotional content — banners, cards, video segments, text announcements — within their own content for **no charge**. This is distinct from:

- **ADS-012 (Self-Promotion / Boosting)**: Paid boosting that amplifies reach beyond organic distribution.
- **ADS-010 (Provider Ad Controls)**: Controls for third-party ad placement on creator content.
- **VOD-018 (Ad-Supported Video Tier)**: Platform ad system serving advertiser creatives with CPM billing.

Self-placed ads are **creator-owned promotions**: a creator can pin a card promoting their merch store to the top of their feed, insert a "subscribe to my premium tier" interstitial into their video, or announce an upcoming broadcast within their existing posts — all without paying the platform.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to insert a promotional card into my newsfeed that highlights my latest video, without paying for a boost. | Creator can create a self-promo card linked to their own content; card appears inline in their feed at the configured position; no billing entry is created. |
| Creator | I want to add a mid-roll promotional segment to my video advertising my merch store. | Creator can configure self-promo slots on their own video; slots serve creator-provided creative (image/video); no ad impression billing occurs. |
| Creator | I want to pin a promotional banner to the top of my profile page. | Creator can create a profile-pinned promo; viewers see it when visiting the profile; creator can update or remove it anytime. |
| Creator | I want to schedule a self-promo card to go live when my broadcast starts. | Creator can tie a self-promo to a scheduled event (broadcast, video premiere); promo activates automatically at event start time. |
| Creator | I want to promote another creator's content in my feed for free (cross-promo). | Creator can create a self-promo referencing another creator's content; no charge to either party; the referenced content is attributed. |
| Viewer | I want to distinguish between paid ads and creator self-promotions. | Self-promo cards show a "Promoted by @creator" label (not "Sponsored"); clicking reveals it's a free self-promotion. |
| Admin | I want to see analytics on self-promo engagement without billing. | Admin dashboard shows self-promo impression/click counts; no revenue entries in billing ledger. |

### 1.3 Scope

**In scope:**
- Self-promo creative management (CRUD for creator's own promotional content)
- Self-promo placement in newsfeed (inline cards at configurable positions)
- Self-promo placement in VOD (pre-roll / mid-roll / overlay slots using creator content)
- Self-promo placement on creator profile page (pinned banner)
- Self-promo placement in broadcast (creator-triggered promo card overlay)
- Event-linked scheduling (activate/deactivate with broadcast start/end)
- Cross-promotion (creator A promotes creator B's content for free)
- Impression/click tracking (analytics only, no billing)
- Labeling/disclosure ("Promoted by @creator" vs "Sponsored")

**Out of scope:**
- Paid boosting (ADS-012)
- Third-party advertiser creatives (ADS-001 through ADS-009)
- Platform-served ads with CPM billing (VOD-018)
- A/B testing of self-promo creatives (future)

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Ad placement service | `app/services/ad_placement.py` | VOD ad slots, CPM billing, impression tracking — self-promo needs slot resolution WITHOUT billing (verified: exists) |
| Ad config on videos | `app/routers/video_listing.py:1506-1537` | PATCH `/videos/{id}/ad-config` (see line 1506) — self-promo needs a parallel `self_promo_config` (verified: endpoint exists) |
| Newsfeed posts | `app/services/newsfeed_feed_query.py`, `app/services/newsfeed_fanout.py` | Post CRUD and feed query <!-- NOTE: `app/services/newsfeed.py` does not exist; newsfeed logic is split across `newsfeed_feed_query.py`, `newsfeed_fanout.py`, `newsfeed_polls.py`, `newsfeed_scheduler.py` --> |
| Broadcast sessions | `app/services/broadcast_store.py`, `app/services/broadcast_orchestrator.py` | Broadcast lifecycle <!-- NOTE: `app/services/broadcast.py` does not exist; broadcast logic is split across ~20 `broadcast_*.py` files --> |
| Creator profiles | `app/services/profile.py` | Profile page data — pinned promo banner stored here <!-- NOTE: `app/services/creator_profiles.py` does not exist; profile logic is in `app/services/profile.py` and `app/services/profile_discoverability.py` --> |
| AdImpressions table | `scripts/local-ddb-init.py:831-840` | Impression storage — reusable for self-promo analytics (add `promo_type` attribute) (verified: table exists) |
| Billing ledger | `app/services/billing_shared.py` | Ledger entries via `new_ledger_entry()` (line 217) — self-promo MUST NOT create any billing entries (verified: file exists) |

### 2.2 Gaps

1. **No self-promo entity**: No DDB table or model for creator-owned promotional content.
2. **No self-promo creative management**: No CRUD endpoints for creators to manage their own ads/promos.
3. **No self-promo feed injection**: Newsfeed query does not support inserting promo cards at specific positions.
4. **No self-promo video slots**: Ad placement service always serves platform ad creatives; no path for creator-owned creatives.
5. **No promo labeling**: No distinction between "Sponsored" (paid third-party) and "Promoted by @creator" (free self-promo).
6. **No cross-promotion model**: No way to reference another creator's content in a self-promo without being that creator.
7. **No event-linked activation**: No mechanism to auto-activate/deactivate promos tied to broadcast or event start/end times.

---

## 3. Implementation Plan

### 3.1 Data Model

#### DynamoDB Table: `SelfPromos`

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | S | `CREATOR#{user_id}` |
| `sk` | S | `PROMO#{promo_id}` |
| `promo_id` | S | UUID |
| `creator_id` | S | Owning creator's user_id |
| `title` | S | Promo headline (max 120 chars) |
| `description` | S | Promo body text (max 500 chars) |
| `creative_type` | S | `image` / `video` / `text` / `card` |
| `creative_url` | S | S3 URL for image/video creative (null for text-only) |
| `creative_thumbnail_url` | S | Thumbnail for video creatives |
| `click_url` | S | Destination URL when clicked (internal route or external) |
| `click_action` | S | `navigate` / `open_post` / `open_video` / `open_profile` / `external_link` |
| `target_content_id` | S | ID of content being promoted (post_id, video_id, broadcast_id, profile_id) |
| `target_content_type` | S | `post` / `video` / `broadcast` / `profile` / `external` |
| `cross_promo_creator_id` | S | If promoting another creator's content, their user_id (null for self) |
| `placement_types` | L | List of allowed placements: `["feed_inline", "video_preroll", "video_midroll", "video_overlay", "profile_banner", "broadcast_overlay"]` |
| `feed_position` | N | For feed_inline: position in feed (e.g., after every N posts; 0 = pinned top) |
| `schedule_start` | N | Unix timestamp — promo becomes active (null = immediately) |
| `schedule_end` | N | Unix timestamp — promo deactivates (null = indefinite) |
| `linked_event_id` | S | Broadcast/event ID to auto-activate/deactivate with |
| `status` | S | `draft` / `active` / `paused` / `expired` / `deleted` |
| `impression_count` | N | Running count (analytics only) |
| `click_count` | N | Running count (analytics only) |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |

**GSIs:**

| GSI | PK | SK | Purpose |
|-----|----|----|---------|
| `ByStatusCreatedAt` | `status` | `created_at` | Admin: list all active promos |
| `ByLinkedEvent` | `linked_event_id` | `created_at` | Activate/deactivate promos when events start/end |

#### Self-Promo Analytics (reuse AdImpressions table)

Add `promo_type` attribute (`platform_ad` / `self_promo`) to existing `AdImpressions` records. Self-promo impressions are tracked for analytics but generate no billing ledger entries.

### 3.2 Backend — Service Layer

**New file: `app/services/self_promos.py`** (~350 lines)

```python
# Core functions:
def create_self_promo(creator_id, data) -> dict
def update_self_promo(creator_id, promo_id, data) -> dict
def delete_self_promo(creator_id, promo_id) -> None
def get_self_promo(creator_id, promo_id) -> dict
def list_self_promos(creator_id, status=None, cursor=None, limit=20) -> dict
def get_feed_promos(creator_id) -> list  # Active feed_inline promos for a creator
def get_video_promos(creator_id, video_id) -> list  # Active video promos for a specific video
def get_profile_promo(creator_id) -> dict | None  # Active profile_banner promo
def get_broadcast_promo(creator_id, broadcast_id) -> dict | None  # Active broadcast_overlay promo
def record_self_promo_event(promo_id, viewer_id, event_type) -> None  # impression/click tracking (no billing)
def get_promo_analytics(creator_id, promo_id) -> dict  # Impression/click counts + CTR
def activate_event_promos(event_id) -> int  # Activate promos linked to an event
def deactivate_event_promos(event_id) -> int  # Deactivate promos linked to an event
```

Key behaviors:
- `create_self_promo` validates `creator_id` owns `target_content_id` (or validates cross-promo consent).
- `record_self_promo_event` writes to `AdImpressions` with `promo_type=self_promo` — NO billing ledger entry.
- `get_feed_promos` returns active promos with `feed_inline` in `placement_types`, sorted by `feed_position`.
- Video promo slots integrate with existing `calculate_ad_slots` in `ad_placement.py` — self-promo creatives served instead of platform ads when configured.

### 3.3 Backend — Router

**New file: `app/routers/self_promos.py`** (~250 lines)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/self-promos` | `require_ui_session` | Create a self-promo |
| GET | `/ui/self-promos` | `require_ui_session` | List creator's own promos (paginated) |
| GET | `/ui/self-promos/{promo_id}` | `require_ui_session` | Get single promo details |
| PATCH | `/ui/self-promos/{promo_id}` | `require_ui_session` | Update promo (title, creative, placement, schedule) |
| DELETE | `/ui/self-promos/{promo_id}` | `require_ui_session` | Soft-delete promo |
| POST | `/ui/self-promos/{promo_id}/activate` | `require_ui_session` | Set status to active |
| POST | `/ui/self-promos/{promo_id}/pause` | `require_ui_session` | Set status to paused |
| POST | `/ui/self-promos/{promo_id}/event` | `require_ui_session` | Record impression/click (analytics only) |
| GET | `/ui/self-promos/{promo_id}/analytics` | `require_ui_session` | Get impression/click/CTR stats |
| GET | `/ui/self-promos/feed/{creator_id}` | `require_ui_session` | Get active feed promos for a creator (viewer-facing) |
| GET | `/ui/self-promos/video/{video_id}` | `require_ui_session` | Get active video promos for a video (viewer-facing) |
| GET | `/ui/self-promos/profile/{creator_id}` | `require_ui_session` | Get active profile banner for a creator (viewer-facing) |

### 3.4 Backend — Integration Points

#### 3.4.1 Feed Injection (`app/services/newsfeed.py`)

Modify `list_feed_posts` (or the router) to inject self-promo cards at configured positions:

```python
def inject_feed_promos(posts: list, creator_id: str) -> list:
    promos = get_feed_promos(creator_id)
    # Insert promo cards at configured feed_position intervals
    # Position 0 = pinned to top
    # Position N = insert after every N organic posts
    result = []
    promo_idx = 0
    for i, post in enumerate(posts):
        if promo_idx < len(promos) and promos[promo_idx].feed_position == i:
            result.append({"type": "self_promo", "promo": promos[promo_idx]})
            promo_idx += 1
        result.append(post)
    return result
```

#### 3.4.2 Video Ad Slots (`app/services/ad_placement.py`)

Extend `calculate_ad_slots` to check for self-promo creatives before falling back to platform ads:

```python
def get_ad_config(video_id, viewer_user_id):
    # ... existing logic ...
    # Check for self-promo slots on this video
    self_promos = get_video_promos(creator_id, video_id)
    if self_promos:
        # Replace platform ad slots with self-promo creatives
        for slot in slots:
            matching_promo = find_matching_promo(self_promos, slot["type"])
            if matching_promo:
                slot["creative"] = promo_to_creative(matching_promo)
                slot["is_self_promo"] = True
                slot["billing_exempt"] = True
```

#### 3.4.3 Broadcast Overlay (`app/services/broadcast.py`)

Add self-promo overlay support to broadcast sessions:

```python
def get_broadcast_overlay(broadcast_id):
    session = get_broadcast_session(broadcast_id)
    promo = get_broadcast_promo(session.creator_id, broadcast_id)
    if promo:
        return {"type": "self_promo", "promo": promo, "billing_exempt": True}
    return None
```

#### 3.4.4 Event Lifecycle Hooks

When a broadcast starts or a scheduled event begins:
```python
# In broadcast start handler:
activate_event_promos(broadcast_id)

# In broadcast end handler:
deactivate_event_promos(broadcast_id)
```

### 3.5 Frontend

#### 3.5.1 New Page: `frontend/src/pages/self-promos/SelfPromosPage.tsx`

Creator's self-promo management dashboard:
- List of all promos (filterable by status: active/draft/paused/expired)
- Create new promo dialog (creative upload, placement selection, scheduling)
- Edit promo (inline editing or dialog)
- Analytics view per promo (impressions, clicks, CTR chart)
- Activate/Pause/Delete actions

#### 3.5.2 New Components

| Component | Purpose |
|-----------|---------|
| `SelfPromoCard.tsx` | Renders a self-promo inline in the feed (distinct from `PostCard`) |
| `SelfPromoCreativeUpload.tsx` | Image/video upload for promo creatives |
| `SelfPromoPlacementPicker.tsx` | Multi-select for placement types |
| `SelfPromoScheduler.tsx` | Date/time pickers for schedule_start/end + event linking |
| `SelfPromoAnalytics.tsx` | Impression/click/CTR display for a single promo |
| `ProfilePromoBanner.tsx` | Renders pinned promo banner on creator profile page |

#### 3.5.3 Feed Integration (`frontend/src/pages/feed/`)

Modify feed rendering to handle mixed `post` and `self_promo` items:
```tsx
{feedItems.map(item =>
  item.type === "self_promo"
    ? <SelfPromoCard key={item.promo.promo_id} promo={item.promo} />
    : <PostCard key={item.post_id} post={item} />
)}
```

Self-promo cards show:
- "Promoted by @{creator_name}" label (not "Sponsored")
- Creative (image/video/text)
- CTA button (linked action)
- Small "ℹ" icon with tooltip: "This is a free self-promotion by the creator"

#### 3.5.4 Video Player Integration

When video ad config includes `is_self_promo: true` slots:
- Show promo creative in ad slot
- Show "Creator Promo" label instead of "Advertisement"
- Skip button still available
- No "Why this ad?" link (since it's not a paid ad)

#### 3.5.5 Navigation

- Sidebar: "My Promos" link under Creator Tools section
- Route: `/self-promos` in `App.tsx`

### 3.6 DynamoDB Table Definition

Add to `scripts/local-ddb-init.py`:

```python
TableDef(
    os.environ.get("DDB_SELF_PROMOS", "SelfPromos"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "ByLinkedEvent", "partition_key": "linked_event_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

---

## 4. Billing & Financial Impact

### 4.1 Zero-Cost Guarantee

Self-placed promos MUST NOT generate any billing entries:
- `record_self_promo_event` writes to `AdImpressions` with `promo_type=self_promo` for analytics only.
- No `new_ledger_entry` calls for self-promo impressions or clicks.
- The `billing_exempt: true` flag on self-promo ad slots prevents the ad billing pipeline from charging.
- Creator wallet balance is never debited for self-promo activity.

### 4.2 Cross-Promo Financial Rules

When Creator A promotes Creator B's content:
- No charge to Creator A (it's their own promo slot).
- No charge to Creator B (they didn't request the promotion).
- No revenue share between creators (this is voluntary cross-promotion, not a business arrangement).
- If revenue sharing is desired, creators should use the collaboration agreements feature (item #25 in backlog) instead.

### 4.3 Distinction from Paid Features

| Feature | Billing | Label |
|---------|---------|-------|
| ADS-019 Self-Placed Ads | **FREE** | "Promoted by @creator" |
| ADS-012 Self-Promotion Boosting | **PAID** (per impression/click) | "Boosted" |
| ADS-001-009 Third-Party Ads | **PAID** (CPM/CPC) | "Sponsored" |
| VOD-018 Ad-Supported Video | **PAID** (CPM to creator) | "Advertisement" |

---

## 5. E2E Test Plan

### 5.1 Test File: `frontend/e2e/self-promo-ads.spec.ts`

~350 lines, 18 tests across 4 sections.

**Section 419: Self-Promo CRUD API (5 tests)**

1. `Creator creates a self-promo` — POST `/ui/self-promos` with title, creative_type=image, placement_types=["feed_inline"], feed_position=3. Verify 200, promo_id returned, status=draft.
2. `Creator lists own promos` — GET `/ui/self-promos`. Verify array includes the created promo.
3. `Creator updates promo title and placement` — PATCH `/ui/self-promos/{promo_id}` with new title. Verify 200, title updated.
4. `Creator activates a draft promo` — POST `/ui/self-promos/{promo_id}/activate`. Verify status=active.
5. `Non-owner cannot update another creator's promo` — PATCH as Bob on Alice's promo. Verify 403.

**Section 420: Self-Promo Feed Injection (4 tests)**

6. `Active feed promo appears in feed promos endpoint` — GET `/ui/self-promos/feed/{creator_id}`. Verify promo returned.
7. `Paused promo does not appear in feed promos` — Pause the promo, re-query. Verify empty.
8. `Feed promo position=0 means pinned to top` — Create promo with feed_position=0, query feed promos. Verify it's first.
9. `Cross-promo references another creator's content` — Create promo with cross_promo_creator_id=Bob's ID, target_content_type=profile. Verify 200, cross_promo_creator_id stored.

**Section 421: Self-Promo Analytics (No Billing) (5 tests)**

10. `Record self-promo impression` — POST `/ui/self-promos/{promo_id}/event` with event_type=impression. Verify 200.
11. `Record self-promo click` — POST event_type=click. Verify 200.
12. `Analytics show impression and click counts` — GET `/ui/self-promos/{promo_id}/analytics`. Verify impression_count >= 1, click_count >= 1.
13. `Self-promo impression creates NO billing ledger entry` — Query billing ledger for creator. Verify no entry with reason containing "self_promo" or the promo_id.
14. `Self-promo impression writes to AdImpressions with promo_type=self_promo` — Query DDB AdImpressions for the promo_id. Verify record exists with promo_type=self_promo.

**Section 422: Self-Promo Video & Profile Placement (4 tests)**

15. `Creator configures video self-promo` — Create promo with placement_types=["video_preroll"], target_content_id=video_id. Activate it. GET `/ui/self-promos/video/{video_id}`. Verify promo returned with is_self_promo=true.
16. `Creator sets profile banner promo` — Create promo with placement_types=["profile_banner"]. Activate it. GET `/ui/self-promos/profile/{creator_id}`. Verify promo returned.
17. `Deleting a promo removes it from video promos` — DELETE the video promo. Re-query. Verify empty.
18. `Expired promo auto-filters from active queries` — Create promo with schedule_end in the past. Query feed promos. Verify not returned.

### 5.2 Test Setup

```typescript
test.beforeAll(async ({ browser, request }) => {
    // Inject sessions for Alice (creator) and Bob (viewer)
    // Create a test video as Alice
    // Create a test post as Alice
});
```

### 5.3 Test Teardown

```typescript
test.afterAll(async () => {
    // Clean up: delete all test promos
});
```

---

## 6. Security Considerations

### 6.1 Authorization

- All self-promo endpoints require `require_ui_session`.
- CRUD operations validate `creator_id == session.user_sub` — creators can only manage their own promos.
- Cross-promo does NOT require consent from the referenced creator (it's like sharing/reposting — the promoting creator owns the promo slot).
- Admin override: admins can list/moderate all self-promos via admin endpoints (future ADS-018 admin dashboard).

### 6.2 Content Moderation

- Self-promo creatives (images/videos) go through the same upload pipeline as regular content.
- Self-promo text (title, description) should be subject to the same content filters as posts.
- Admins can disable/delete self-promos that violate platform rules.

### 6.3 Abuse Prevention

- **Rate limiting**: Max 20 active self-promos per creator (prevents feed spam).
- **Feed injection limit**: Max 1 self-promo per 5 organic posts in feed view (prevents promo-heavy feeds).
- **Click fraud**: Self-promo clicks don't generate revenue, so click fraud is not a financial risk — but inflated analytics should still be mitigated via deduplication (one click per viewer per promo per hour).

---

## 7. Observability

### 7.1 Metrics

| Metric | Type | Labels |
|--------|------|--------|
| `self_promo_created_total` | counter | `creator_id`, `creative_type` |
| `self_promo_impression_total` | counter | `creator_id`, `placement_type` |
| `self_promo_click_total` | counter | `creator_id`, `placement_type` |
| `self_promo_active_gauge` | gauge | — |

### 7.2 Logging

- `self_promo_created` — promo_id, creator_id, placement_types
- `self_promo_activated` — promo_id
- `self_promo_event` — promo_id, event_type, viewer_id
- `self_promo_event_linked_activate` — event_id, promo_count

---

## 8. Rollout Plan

### Phase 1: Core CRUD + Feed Placement
- Self-promo table + service + router
- Feed injection for newsfeed
- Frontend management page

### Phase 2: Video + Profile + Broadcast
- Video ad slot integration
- Profile banner placement
- Broadcast overlay integration

### Phase 3: Event Linking + Analytics
- Event-linked auto-activation
- Analytics dashboard
- Admin moderation tools

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Newsfeed post system | Existing | Implemented |
| Video ad placement | VOD-018 | Implemented |
| Broadcast sessions | BCAST-001+ | Implemented |
| Creator profiles | Existing | Implemented |
| Ad impression tracking | VOD-018 | Implemented (extend with promo_type) |
| Content upload pipeline | Existing | Implemented |

---

## 10. Open Questions

1. Should cross-promo require consent from the referenced creator? Current design: no (it's like reposting). Could add an opt-out flag on creator profiles.
2. Should self-promos count toward a creator's post limit (if any)? Current design: no (they're separate entities).
3. Should viewers be able to hide/dismiss individual self-promos? Current design: not in MVP. Could add in a follow-up.
4. Should self-promo analytics be included in the creator analytics dashboard (ENGAGE-005)? Current design: separate analytics endpoint, but could be integrated.

---

## 11. Architecture & Data Flow

```
Self-Promo Lifecycle
────────────────────

  Creator → POST /ui/self-promos
       │
       ▼
  ┌────────────────────────────────────┐
  │  Create Self-Promo                 │
  │  SelfPromos table:                 │
  │  pk=CREATOR#{user_id}              │
  │  sk=PROMO#{promo_id}              │
  │  status=draft                      │
  └──────────┬─────────────────────────┘
             │
             ▼ (creator activates)
  POST /ui/self-promos/{id}/activate
       │
       ▼
  status=active
       │
       ▼ (viewer requests feed/video/profile)
  ┌────────────────────────────────────┐
  │  Feed Injection Point              │
  │  get_feed_promos(creator_id)       │
  │  → Query SelfPromos table          │
  │    pk=CREATOR#{id}, status=active  │
  │    placement_types contains        │
  │    "feed_inline"                   │
  │                                    │
  │  Insert at feed_position interval  │
  │  Label: "Promoted by @creator"     │
  │  billing_exempt: true              │
  └──────────┬─────────────────────────┘
             │
             ▼ (viewer sees promo)
  ┌────────────────────────────────────┐
  │  Impression/Click Tracking         │
  │                                    │
  │  POST /self-promos/{id}/event      │
  │  event_type=impression|click       │
  │                                    │
  │  → AdImpressions table             │
  │    promo_type=self_promo           │
  │  → NO billing ledger entry         │
  │  → Increment counter on promo      │
  └────────────────────────────────────┘

  Event-Linked Activation
  ────────────────────────

  Broadcast starts → activate_event_promos(broadcast_id)
       │
       ▼
  Query ByLinkedEvent GSI
  linked_event_id = broadcast_id
       │
       ▼
  Set matching promos status=active
       │
       ▼
  Broadcast ends → deactivate_event_promos(broadcast_id)
```

---

## 12. Detailed DynamoDB Access Patterns

| # | Access Pattern | Table | Key Condition | GSI | Notes |
|---|---------------|-------|---------------|-----|-------|
| 1 | Get promo by ID | `SelfPromos` | `pk=CREATOR#{user_id}, sk=PROMO#{promo_id}` | -- | GetItem |
| 2 | List creator's promos | `SelfPromos` | `pk=CREATOR#{user_id}, sk begins_with PROMO#` | -- | Query, paginated |
| 3 | List active promos (admin) | `SelfPromos` | `status=active` | `ByStatusCreatedAt` | GSI query |
| 4 | Find event-linked promos | `SelfPromos` | `linked_event_id=X` | `ByLinkedEvent` | GSI query |
| 5 | Record impression | `AdImpressions` | `pk=AD_IMP#{date}, sk=PROMO#{promo_id}#{viewer}#{ts}` | -- | PutItem with promo_type=self_promo |
| 6 | Increment promo counters | `SelfPromos` | `pk=CREATOR#{user_id}, sk=PROMO#{promo_id}` | -- | UpdateItem ADD |

---

## 13. API Request/Response Examples

### 13.1 Create Self-Promo

```bash
curl -X POST http://localhost:8000/ui/self-promos \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok" \
  -d '{
    "title": "Check out my new video!",
    "description": "My latest tutorial on React hooks",
    "creative_type": "card",
    "click_action": "open_video",
    "target_content_id": "vid_abc123",
    "target_content_type": "video",
    "placement_types": ["feed_inline"],
    "feed_position": 3
  }'
```

**Response (200)**:
```json
{
  "promo_id": "promo_a1b2c3",
  "creator_id": "alice-sub",
  "title": "Check out my new video!",
  "status": "draft",
  "placement_types": ["feed_inline"],
  "feed_position": 3,
  "impression_count": 0,
  "click_count": 0,
  "created_at": 1748534400
}
```

### 13.2 Activate Promo

```bash
curl -X POST http://localhost:8000/ui/self-promos/promo_a1b2c3/activate \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok"
```

**Response (200)**:
```json
{"ok": true, "status": "active"}
```

### 13.3 Get Promo Analytics

```bash
curl http://localhost:8000/ui/self-promos/promo_a1b2c3/analytics \
  -H "Cookie: ui_session=sess_alice; ui_access_token=jwt_tok"
```

**Response (200)**:
```json
{
  "promo_id": "promo_a1b2c3",
  "impression_count": 142,
  "click_count": 23,
  "ctr_pct": 16.2
}
```

---

## 14. Error Handling Matrix

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------------|-------------|------------|---------------------|-----------------|
| 1 | Promo not found | 404 | `PROMO_NOT_FOUND` | "Self-promo not found." | Verify promo_id |
| 2 | Not promo owner | 403 | `NOT_PROMO_OWNER` | "You do not own this self-promo." | Use own account |
| 3 | Max active promos (20) | 400 | `MAX_PROMOS_REACHED` | "Maximum 20 active self-promos." | Deactivate or delete existing |
| 4 | Invalid creative_type | 422 | `INVALID_CREATIVE_TYPE` | "creative_type must be image, video, text, or card." | Use valid type |
| 5 | Invalid placement_type | 422 | `INVALID_PLACEMENT` | "Invalid placement type." | Use valid placement enum |
| 6 | Invalid click_action | 422 | `INVALID_CLICK_ACTION` | "Invalid click action." | Use valid action enum |
| 7 | Title too long | 422 | `TITLE_TOO_LONG` | "Title must be 120 characters or fewer." | Shorten title |
| 8 | Invalid feed_position | 422 | `INVALID_POSITION` | "feed_position must be >= 0." | Use non-negative integer |

---

## 15. Expanded Pydantic Models

```python
from pydantic import BaseModel, Field, field_validator
from typing import Optional

VALID_CREATIVE_TYPES = {"image", "video", "text", "card"}
VALID_CLICK_ACTIONS = {"navigate", "open_post", "open_video", "open_profile", "external_link"}
VALID_PLACEMENT_TYPES = {"feed_inline", "video_preroll", "video_midroll", "video_overlay", "profile_banner", "broadcast_overlay"}
VALID_CONTENT_TYPES = {"post", "video", "broadcast", "profile", "external"}

class SelfPromoCreateIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    creative_type: str = Field(...)
    creative_url: Optional[str] = None
    click_url: Optional[str] = None
    click_action: str = Field(default="navigate")
    target_content_id: Optional[str] = None
    target_content_type: Optional[str] = None
    cross_promo_creator_id: Optional[str] = None
    placement_types: list[str] = Field(...)
    feed_position: int = Field(default=3, ge=0)
    schedule_start: Optional[int] = None
    schedule_end: Optional[int] = None
    linked_event_id: Optional[str] = None

    @field_validator("creative_type")
    @classmethod
    def validate_creative_type(cls, v):
        if v not in VALID_CREATIVE_TYPES:
            raise ValueError(f"creative_type must be one of {VALID_CREATIVE_TYPES}")
        return v

    @field_validator("click_action")
    @classmethod
    def validate_click_action(cls, v):
        if v not in VALID_CLICK_ACTIONS:
            raise ValueError(f"click_action must be one of {VALID_CLICK_ACTIONS}")
        return v

    @field_validator("placement_types")
    @classmethod
    def validate_placement_types(cls, v):
        for p in v:
            if p not in VALID_PLACEMENT_TYPES:
                raise ValueError(f"Invalid placement type: {p}")
        return v

class SelfPromoOut(BaseModel):
    promo_id: str
    creator_id: str
    title: str
    description: str
    creative_type: str
    status: str
    placement_types: list[str]
    feed_position: int
    impression_count: int = 0
    click_count: int = 0
    created_at: int
    updated_at: int
```

---

## 16. Frontend Component Tree

```
SelfPromosPage (route: /self-promos)
├── PromoStatusFilter (tabs: All / Active / Draft / Paused / Expired)
├── CreatePromoButton → CreatePromoDialog
│   ├── SelfPromoCreativeUpload
│   ├── SelfPromoPlacementPicker (multi-checkbox)
│   ├── SelfPromoScheduler (date pickers + event link)
│   └── CrossPromoCreatorSearch (optional)
├── PromoList
│   └── PromoCard (per promo)
│       ├── Title + CreativeTypeBadge
│       ├── StatusBadge (active/draft/paused/expired)
│       ├── PlacementTags (feed_inline, video_preroll, etc.)
│       ├── AnalyticsMini (impressions, clicks, CTR)
│       └── ActionMenu (Activate / Pause / Edit / Delete)
└── SelfPromoAnalytics (detail panel per promo)
    ├── ImpressionCount
    ├── ClickCount
    └── CTRPercentage

Feed Integration
├── SelfPromoCard (data-testid="self-promo-card")
│   ├── "Promoted by @{creator_name}" label
│   ├── Creative (image/video/text)
│   ├── CTAButton (linked action)
│   └── InfoIcon → tooltip: "Free self-promotion by the creator"

ProfilePromoBanner (on creator profile page)
├── BannerImage or BannerCard
├── Title + Description
└── CTAButton
```

---

## 17. Expanded Observability

### 17.1 Extended Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `self_promo_created_total` | Counter | `creator_id`, `creative_type` | Promos created |
| `self_promo_activated_total` | Counter | `creator_id` | Promos activated |
| `self_promo_impression_total` | Counter | `creator_id`, `placement_type` | Impressions (analytics only) |
| `self_promo_click_total` | Counter | `creator_id`, `placement_type` | Clicks (analytics only) |
| `self_promo_active_gauge` | Gauge | -- | Currently active promos |
| `self_promo_event_linked_total` | Counter | -- | Event-linked activations |
| `self_promo_billing_blocked_total` | Counter | -- | Billing attempts blocked (should be 0) |

### 17.2 Alerting Rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| Billing entry created for self-promo | Any ledger entry with promo_id | P1 (critical) |
| Active promo count exceeds limit | >20 active per creator | P3 |
| Event-linked activation failure | Activate returns 0 promos for valid event | P3 |

---

## 18. Performance Considerations

### 18.1 Latency Targets

| Endpoint | Target p50 | Target p99 |
|----------|-----------|-----------|
| POST /self-promos (create) | 50ms | 200ms |
| GET /self-promos (list) | 40ms | 150ms |
| POST /self-promos/{id}/event | 20ms | 80ms |
| GET /self-promos/feed/{id} | 30ms | 100ms |
| activate_event_promos() | 100ms | 500ms |

### 18.2 Feed Injection Performance

`get_feed_promos()` queries the SelfPromos table with PK=CREATOR#{id} and filters for active status + feed_inline placement. With the 20 active promo limit, this returns at most 20 items. The feed injection iterates through organic posts and inserts promos at configured positions. Total overhead per feed request: ~30ms.

---

## 19. Expanded E2E Tests

### 19.1 Section 423: Input Validation (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 423.1 | Invalid creative_type rejected | POST with creative_type="audio"; 422 |
| 423.2 | Invalid placement_type rejected | POST with placement_types=["sidebar"]; 422 |
| 423.3 | Title too long rejected | POST with 150-char title; 422 |
| 423.4 | Negative feed_position rejected | POST with feed_position=-1; 422 |
| 423.5 | Invalid click_action rejected | POST with click_action="execute"; 422 |

### 19.2 Section 424: Authorization Boundary (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 424.1 | Non-owner cannot update promo | Bob PATCH Alice's promo; 403 |
| 424.2 | Non-owner cannot activate promo | Bob POST activate on Alice's promo; 403 |
| 424.3 | Non-owner cannot delete promo | Bob DELETE Alice's promo; 403 |
| 424.4 | Non-owner cannot view analytics | Bob GET Alice's promo analytics; 403 |

### 19.3 Section 425: Billing Guarantee (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 425.1 | Impression creates no billing entry | Record impression; scan billing ledger; no entry for promo_id |
| 425.2 | Click creates no billing entry | Record click; scan billing ledger; no entry for promo_id |
| 425.3 | AdImpressions records promo_type | Query AdImpressions; record has promo_type=self_promo |
| 425.4 | Wallet balance unchanged after impressions | Check creator wallet before/after; same balance |

### 19.4 Section 426: Event-Linked Promos (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 426.1 | Create event-linked promo | POST with linked_event_id=broadcast_id; 200; linked_event_id stored |
| 426.2 | Activate via event | Call activate_event_promos(broadcast_id); promo status=active |
| 426.3 | Deactivate via event | Call deactivate_event_promos(broadcast_id); promo status=paused |
| 426.4 | Scheduled promo with past end time filtered | Create with schedule_end in past; query feed promos; not returned |

---

## Codebase References

| Reference | Path | Line(s) | Status |
|-----------|------|---------|--------|
| Ad placement service | `app/services/ad_placement.py` | entire file | Verified (VOD-018) |
| Video ad-config endpoint | `app/routers/video_listing.py` | 1506 (PATCH `/{video_id}/ad-config`) | Verified |
| Newsfeed feed query | `app/services/newsfeed_feed_query.py` | entire file | Verified — **not** `app/services/newsfeed.py` (does not exist) |
| Newsfeed fanout | `app/services/newsfeed_fanout.py` | entire file | Verified |
| Broadcast store | `app/services/broadcast_store.py` | entire file | Verified — **not** `app/services/broadcast.py` (does not exist) |
| Profile service | `app/services/profile.py` | entire file | Verified — **not** `app/services/creator_profiles.py` (does not exist) |
| AdImpressions DDB table | `scripts/local-ddb-init.py` | 831-840 | Verified |
| AdImpressions settings | `app/core/settings.py` | 1242 (`ad_impressions_table_name`) | Verified |
| AdImpressions table handle | `app/core/tables.py` | 217 (`T.ad_impressions`) | Verified |
| Billing ledger | `app/services/billing_shared.py` | 217 (`new_ledger_entry`) | Verified |
| UI session auth | `app/auth/deps.py` | (via `require_ui_session` from `app/services/sessions.py`) | Verified |
| Router registration | `app/main.py` | 297-465 | Verified — new router must be registered here |
| `SelfPromos` DDB table | — | — | **Does not exist** — new table required |
| `self_promos` service | — | — | **Does not exist** — new file required |
| `self_promos` router | — | — | **Does not exist** — new file required |

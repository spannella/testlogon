# CREATOR-002: Fan Clubs / Membership Tiers — Investigation & Implementation Write-up

## 1. Summary & Classification

Fan clubs allow creators to define named membership tiers (up to 6 levels) linked to existing subscription plans. Each tier carries a badge, custom benefits, and optional welcome messages. Tiers gate access to exclusive chat channels and early-access content. The backend service layer, router, Pydantic models, DDB tables, TypeScript types, frontend API client, and the main `FanClubPage.tsx` are all implemented. Several planned components are absent or not yet wired into cross-feature integration points: `ExclusiveChatView`, `TierMemberList`, `TierAnalyticsPanel`, `BadgeImageUploader`, `TierMemberOut`/`TierAnalyticsOut` Pydantic models, and badge rendering in broadcast chat / newsfeed comments.

- **Type**: Feature
- **Priority**: Medium
- **Status**: Core backend complete; several frontend components and cross-feature integrations are missing.
- **Area**: Creator tools / Subscriptions / Broadcast Chat / Newsfeed
- **User persona**: Creators who want to build tiered membership communities; subscribers who want to display status and access exclusive channels.
- **Dependencies**: Subscription server (`app/routers/subscription_server.py`), `app/services/subscription_access.py`, `app/services/broadcast_chat_store.py`, `app/routers/newsfeed.py`.
- **Cross-reference**: CREATOR-001 (collaboration system), ANALYTICS-001 (creator analytics).

## 2. Current-State Investigation (what exists today)

### 2.1 Service layer

**`app/services/fan_club_tiers.py` (175 lines)**

Functions: `create_tier`, `get_tier`, `list_tiers`, `update_tier`, `delete_tier`, `reorder_tiers`, `get_tier_members`.

Tiers are stored in `T.subscriptions` table (the existing subscription table) under `PK=CREATOR#{creator_id}`, `SK=TIER#{tier_id}`. This single-table co-location avoids a new table while keeping all subscription-related data in one place. `create_tier` validates: max 6 tiers per creator (`count_pending_outgoing`-style check), `plan_id` must exist for the creator, level must be unique among the creator's tiers.

`get_tier_members` queries the `SUBSCRIBER#` partition of the subscription table (joining subscriptions to tiers by plan_id). Returns a list of subscriber items enriched with tier metadata.

**`app/services/fan_club_channels.py` (244 lines)**

Functions: `create_channel`, `get_channel`, `list_channels_for_user`, `get_channel_messages`, `send_channel_message`, `add_reaction`, `delete_channel_message`, `pin_message`.

Channels are stored in `T.fan_club_channels` table (`PK=channel_id`). Messages in `T.fan_club_messages` (`PK=channel_id`, `SK="{timestamp}#{message_id}"` for chronological ordering). `list_channels_for_user` queries a `ByCreator` GSI on `fan_club_channels` and filters by `user_level >= channel.min_tier_level`. `send_channel_message` resolves the sender's badge via `resolve_member_badge`, enforces slowmode via `_SLOWMODE_BUCKETS` in-memory dict (same pattern as `broadcast_chat_store.py`'s rate limiting), and writes both the message item and updates channel metadata.

**`app/services/fan_club_badges.py` (122 lines)**

Single exported function `resolve_member_badge(user_id, creator_id)`. Uses a 60-second in-memory TTL cache `_BADGE_CACHE`. The lookup chain: get active subscription via `T.subscriptions.query(PK=SUBSCRIBER#{user_id})` → find tier record by `plan_id` via `T.subscriptions.query(PK=CREATOR#{creator_id}, SK begins_with TIER#)`. Returns `{tier_name, tier_level, badge_emoji, badge_color, badge_image_url}` or `None`. `get_subscriber_tier_level` is a thin wrapper that returns `badge["tier_level"]` or `None`.

`invalidate_badge_cache(user_id, creator_id)` removes the cache entry. Must be called on subscription plan change (upgrade/downgrade) to avoid stale badge display for 60 seconds.

**`app/services/fan_club_access.py`**

`can_view_content(user_id, creator_id, content)`: reads `early_access_tier_level` and `general_release_at` from the content item. Before `general_release_at`, requires `get_subscriber_tier_level(user_id, creator_id) >= early_access_tier_level`. After, falls back to `can_access_creator` from `app/services/subscription_access.py:72`.

`get_early_access_status(user_id, creator_id, content)`: returns a detailed dict including `can_view`, `is_early_access`, `user_tier_level`, `required_tier_level`, `general_release_at`, `time_until_release_seconds`. Used by `POST /ui/fan-club/early-access-check` endpoint.

### 2.2 Router (`app/routers/fan_club.py`, 340 lines)

Registered in `app/main.py`. No explicit feature flag check at the router level (unlike `collaborations.py:89`). The settings flag `S.fan_clubs_enabled` exists at `settings.py:1885` but is NOT checked in the router. All endpoints are live whenever the router is included.

Implemented endpoints:

| Path | Method | Line | Notes |
|---|---|---|---|
| `/ui/fan-club/tiers` | POST | 54 | `api_create_tier` — validates plan belongs to caller |
| `/ui/fan-club/tiers` | GET | 72 | `api_list_tiers` — caller's tiers only |
| `/ui/fan-club/tiers/reorder` | PATCH | 79 | `api_reorder_tiers` |
| `/ui/fan-club/tiers/{tier_id}` | GET | 86 | `api_get_tier` |
| `/ui/fan-club/tiers/{tier_id}` | PATCH | 95 | `api_update_tier` |
| `/ui/fan-club/tiers/{tier_id}` | DELETE | 105 | `api_delete_tier` (soft delete, sets `active=false`) |
| `/ui/fan-club/tiers/{tier_id}/members` | GET | 112 | `api_tier_members` |
| `/ui/fan-club/channels` | POST | 125 | `api_create_channel` |
| `/ui/fan-club/channels` | GET | 139 | `api_list_channels` — filtered by `creator_id` query param and caller's tier level |
| `/ui/fan-club/channels/{channel_id}` | GET | 150 | `api_get_channel` |
| `/ui/fan-club/channels/{channel_id}/messages` | POST | 158 | `api_send_channel_message` |
| `/ui/fan-club/channels/{channel_id}/messages` | GET | 180 | `api_get_channel_messages` |
| `/ui/fan-club/channels/{channel_id}/messages/{message_id}` | DELETE | 198 | `api_delete_channel_message` |
| `/ui/fan-club/channels/{channel_id}/messages/{message_id}/react` | POST | 215 | `api_add_reaction` |
| `/ui/fan-club/channels/{channel_id}/pin/{message_id}` | PUT | 234 | `api_pin_message` |
| `/ui/fan-club/badge/{creator_id}` | GET | 252 | `api_get_badge` — caller's badge for a creator |
| `/ui/fan-club/badge/{creator_id}/invalidate` | POST | 261 | `api_invalidate_badge` |
| `/ui/fan-club/early-access-check` | POST | 270 | `api_early_access_check` |
| `/api/creators/{creator_id}/tiers` (public_router) | GET | ~281 | `api_public_tiers` — no auth required |

**Missing**: `DELETE /ui/fan-club/channels/{channel_id}` (channel deletion by creator), `DELETE /ui/fan-club/channels/{channel_id}/messages/{message_id}/react/{emoji}` (reaction removal), `GET /ui/fan-club/analytics`, `PUT /ui/fan-club/tiers/{tier_id}/badge-image` (badge image upload).

### 2.3 Pydantic models (`app/models.py:3421-3527`)

Implemented: `TierBenefit`, `TierCreateIn`, `TierUpdateIn`, `TierOut`, `TierReorderIn`, `ChannelCreateIn`, `ChannelOut`, `ChannelMessageIn`, `ChannelMessageOut`, `MemberBadgeOut`.

**NOT yet implemented** (design only, no model in file):
- `TierMemberOut` — for `GET /ui/fan-club/tiers/{tier_id}/members` responses
- `TierAnalyticsOut` — for `GET /ui/fan-club/analytics`

The `api_tier_members` endpoint at router line 112 currently returns raw DDB items (or a minimal dict) rather than a typed `TierMemberOut`. This causes the frontend to receive untyped data.

Note: `TierOut` in `app/models.py` does NOT include `plan_price_cents`, `plan_currency`, `plan_interval`. However, `frontend/src/api/types.ts:4109-4130` defines `TierOut` with those optional fields (`plan_price_cents?: number`, etc.). The frontend types are more permissive — they handle the missing fields gracefully via `?` optional syntax.

### 2.4 DynamoDB tables

| Table | Settings | DDB Init Line |
|---|---|---|
| `fan_club_channels` | `fan_club_channels_table_name` at `settings.py:1886` | `local-ddb-init.py:1468` |
| `fan_club_messages` | `fan_club_messages_table_name` at `settings.py:1887` | `local-ddb-init.py:1477` |

Both tables are created via `TableDef` in `local-ddb-init.py`. `fan_club_channels` has a `ByCreator` GSI (`creator_id` as partition key) used in `list_channels_for_user`. `fan_club_messages` uses `channel_id` as PK and `sort_key` (`"{ts}#{msg_id}"`) as SK for chronological queries with `ScanIndexForward=False`.

### 2.5 Frontend

**`FanClubPage.tsx` (580 lines)**: All-in-one page. Tabs: "Tiers" (create/edit/delete/reorder tiers), "Channels" (create channels, inline channel message view), "Badge" (shows caller's badge for a selected creator). All core functionality is inline — no separate sub-components. `MemberBadge` component (imported from `@/components/shared/MemberBadge`) is used in the channel message list at line 226 and in the tier member list at line 66.

**`frontend/src/components/shared/MemberBadge.tsx`**: EXISTS. Renders badge emoji + name in a colored pill using inline `style.backgroundColor` with 20% opacity from `badge_color`. Sizes: `xs`, `sm`, `md`.

**Route**: `App.tsx:80` (lazy import) and line 192 (route `/fan-club`). Sidebar nav item at `Sidebar.tsx:110`. MobileNav in `MORE_LINKS`.

**Missing frontend components**:
- `ExclusiveChatView` — inline in `FanClubPage` as a simple message list + input, not a full-featured real-time chat component with SSE subscription
- `TierMemberList` — inline in page; no separate file with proper pagination
- `TierAnalyticsPanel` — NOT implemented anywhere; analytics tab does not exist in the page
- `BadgeImageUploader` — NOT implemented; `PUT /ui/fan-club/tiers/{tier_id}/badge-image` endpoint does not exist in the router

**TypeScript API client** (`frontend/src/api/endpoints/fan-club.ts`): Uses `res.data` pattern (axios response) for all calls. Missing: `deleteTier` calls `api.delete` (correct), but `getMyBadges` (all badges across creators) is not implemented — only `getMyBadge(creatorId)` for one creator at a time.

### 2.6 Integration points NOT yet wired

| Integration point | Status |
|---|---|
| `BroadcastChatMessageOut` badge fields | NOT wired — no `sender_badge` on `BroadcastChatMessageOut` (broadcast.py line 1247) |
| `MessageBubble.tsx` badge for DM sender | NOT wired — `MessageBubble` does not call `resolve_member_badge` |
| `CommentRow.tsx` badge | NOT wired |
| `CreatePost.tsx` early access tier selector | NOT wired |
| `PostCard.tsx` early access indicator | NOT wired |
| Welcome message DM on subscribe | NOT wired in `subscription_server.py` lifecycle |
| Badge cache invalidation on plan change | NOT wired in subscription upgrade/downgrade path |

### 2.7 Dev vs. prod today

| Path | Dev | Prod |
|---|---|---|
| `fan_club_channels` DDB table | DDB Local port 8001 | AWS DynamoDB |
| `fan_club_messages` DDB table | DDB Local | AWS DynamoDB |
| Tier data in `subscriptions` table | DDB Local | AWS DynamoDB |
| Badge in-memory cache | `_BADGE_CACHE` dict in process | same (per-worker; not shared across workers) |
| Badge image upload (future) | Would use moto S3 | Would use real S3 |

No AWS-specific services involved in the implemented paths. The `fan_clubs_enabled` feature flag at `settings.py:1885` defaults to `"1"` in both envs. The router does not check this flag — all endpoints are live. To disable: add `_check_enabled()` at the top of each handler (same pattern as `collaborations.py:89`).

## 3. Gap / Threat Analysis

### 3.1 Feature flag not enforced at router level

`S.fan_clubs_enabled` exists but is never checked in `fan_club.py`. Setting `FAN_CLUBS_ENABLED=0` has no effect — all endpoints remain live. Add `if not S.fan_clubs_enabled: raise HTTPException(404, "Fan clubs not enabled")` to each endpoint handler, or add a middleware dependency.

### 3.2 `TierMemberOut` model missing

`api_tier_members` at router line 112 returns raw items from `get_tier_members`. Without a typed model, the endpoint returns untyped dicts and the OpenAPI schema shows `{}` for the response. Create `TierMemberOut` in `app/models.py` (as specified in the design: `user_id`, `display_name`, `avatar_url`, `subscribed_at`, `tier_name`, `tier_level`, `total_spent_cents`) and use it as the response model.

### 3.3 Badge cache is per-process, not shared

`_BADGE_CACHE` in `fan_club_badges.py` is a module-level dict. With `uvicorn --workers 1` (current dev setting), this works correctly. In production multi-worker or multi-instance deployments, cache is not shared — each worker maintains its own cache. A badge update (tier change) would be stale in all workers except the one that processed the subscription change until the 60-second TTL expires. This is an acceptable tradeoff for v1 but should be documented. The `invalidate_badge_cache` endpoint (`POST /ui/fan-club/badge/{creator_id}/invalidate`) only clears the cache in the worker that receives the request.

### 3.4 Broadcast chat badge not wired

`send_chat_message` in `app/services/broadcast_chat_store.py` (line 136) does not call `resolve_member_badge`. The `BroadcastChatMessageOut` model (broadcast.py line 1247) has no `sender_badge` field. Without this, tier badges do not appear in broadcast chat — one of the core visible benefits of the fan club tier system.

### 3.5 Welcome message not sent on subscribe

The subscription lifecycle events in `app/routers/subscription_server.py` do not call `send_welcome_dm(tier, subscriber_id)` after a new subscription is created. The `welcome_message` field is stored on the tier record but never acted upon.

### 3.6 Missing `TierAnalyticsOut` and analytics endpoint

`GET /ui/fan-club/analytics` (router line listed in design, not in implemented endpoints) is absent. Without this, creators have no visibility into tier distribution, churn, or upgrade rates — key metrics for decision-making about tier pricing and benefits.

### 3.7 Channel reaction deletion missing

`DELETE /ui/fan-club/channels/{channel_id}/messages/{message_id}/react/{emoji}` is listed in the design API table (section 4.2) but not in the implemented router. Users can add reactions but not remove them.

### 3.8 `ExclusiveChatView` has no real-time SSE subscription

The inline channel chat in `FanClubPage.tsx` fetches messages via React Query with `refetchInterval`. There is no WebSocket or SSE subscription. New messages from other members do not appear until the poll interval triggers. The broadcast chat uses `broadcast_sse_publish` for real-time delivery — fan club channels need the same treatment.

## 4. Proposed Design / Fix

### 4.1 Add feature flag check to router

Add at the top of `fan_club.py`:
```python
from app.core.settings import S

def _check_enabled():
    if not S.fan_clubs_enabled:
        raise HTTPException(status_code=404, detail="Fan clubs are not enabled")
```
Call `_check_enabled()` inside each endpoint handler.

### 4.2 Implement `TierMemberOut` and `TierAnalyticsOut` models

In `app/models.py`, add after line 3527:
```python
class TierMemberOut(BaseModel):
    user_id: str
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    subscribed_at: int = 0
    tier_name: str
    tier_level: int
    total_spent_cents: int = 0

class TierAnalyticsOut(BaseModel):
    total_members: int = 0
    tiers: List[Dict[str, Any]] = Field(default_factory=list)
    churn_rate_30d: float = 0.0
    upgrade_rate_30d: float = 0.0
```
Update `api_tier_members` to use `TierMemberOut` as response model. Add `GET /ui/fan-club/analytics` endpoint using `TierAnalyticsOut`.

### 4.3 Wire broadcast chat badge

In `app/services/broadcast_chat_store.py`, extend `send_chat_message` to accept a `creator_id: str` parameter and call `resolve_member_badge(user_id, creator_id)`. Add `sender_badge_emoji`, `sender_badge_color`, `sender_tier_name` to the SSE payload and to `BroadcastChatMessageOut` in `app/routers/broadcast.py:1247`. The broadcast session's `profile_id` (creator's profile) can be used to derive `creator_id`.

### 4.4 Welcome DM on subscribe

In `app/routers/subscription_server.py`, after a successful subscription activation (in the subscribe endpoint, after `T.subscriptions.put_item`):
1. Call `_get_tier_by_plan(creator_id, plan_id)` from `fan_club_badges.py`
2. If `tier.get("welcome_message")`, send a DM from creator to subscriber via the messaging endpoint (or directly via `create_dm_message` from `messaging.py`)
3. Invalidate badge cache via `invalidate_badge_cache(subscriber_id, creator_id)`

### 4.5 Channel real-time SSE

Add SSE publishing to `send_channel_message` in `fan_club_channels.py`:
```python
from app.services.sse import publish_to_user_channel
publish_to_user_channel(
    user_ids=channel_member_ids,  # all users with tier_level >= channel.min_tier_level
    event={"type": "fan_club:message", "channel_id": channel_id, "message": message_out_dict},
)
```
On the frontend, `ExclusiveChatView` should subscribe to this SSE channel and call `queryClient.invalidateQueries(["fan-club", "channel-messages", channelId])` on receipt.

### 4.6 Dev/prod parity

The fan club system is entirely DDB-backed. No parity gap exists for the core CRUD and channel operations. Badge image upload (when implemented) will use the same moto `/mock/s3/` pattern as voice messages in dev and real S3 presigned URLs in prod.

The `fan_clubs_enabled` flag defaults to `"1"` in both dev and prod. Toggle via env var.

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests

`tests/test_fan_club.py` does not exist. Create with moto `@mock_aws`. Test cases:
- `test_create_tier_max_six` — 7th tier → 409
- `test_create_tier_duplicate_level` — level already in use → 409
- `test_resolve_badge_cache_invalidation` — subscription changed → `invalidate_badge_cache` → new badge returned
- `test_channel_access_enforced` — `tier_level=1` subscriber cannot send to `min_tier_level=2` channel → 403
- `test_early_access_visibility` — before `general_release_at`, tier < required → False; tier >= required → True
- `test_channel_slowmode` — two messages within slowmode window → 429

### 5.2 Playwright E2E

`frontend/e2e/fan-club.spec.ts` (745 lines). Run: `cd frontend && npx playwright test e2e/fan-club.spec.ts`.

Sections: tier CRUD, channel CRUD + message send/receive, badge resolution, early access gating, public tiers endpoint, feature flag off.

### 5.3 Manual QA steps

1. `just restart`.
2. Alice creates a subscription plan via `POST /api/plans`.
3. Alice creates a tier linked to that plan with name "VIP", level 2, badge_emoji "👑".
4. Bob subscribes to Alice's plan (`POST /api/subscriptions`).
5. `GET /ui/fan-club/badge/alice-user-id` as Bob — verify badge returned with `tier_name="VIP"`.
6. Alice creates a channel with `min_tier_level=2`.
7. Bob lists channels — verify the VIP channel is visible.
8. Charlie (no subscription) lists channels — verify empty list.
9. Bob sends a message to the VIP channel — verify it appears in Alice's channel view.
10. Alice creates a post with `early_access_tier_level=2` and `general_release_at` = now + 3600.
11. Bob (VIP) views the post — verify visible.
12. Charlie views the post — verify 403 / hidden.

### 5.4 Rollout

1. **Phase 1** (done): Backend service, router, models, DDB tables, frontend page.
2. **Phase 2** (next): Add feature flag enforcement in router; add `TierMemberOut`/`TierAnalyticsOut` models; add analytics endpoint.
3. **Phase 3**: Wire broadcast chat badge; wire welcome DM on subscribe; wire badge cache invalidation on plan change.
4. **Phase 4**: Add real-time SSE to channel chat; extract `ExclusiveChatView` as standalone component.
5. **Phase 5**: Wire early-access indicator in `PostCard.tsx`; add `TierSelector` in `CreatePost.tsx`.
6. **Phase 6**: Add `TierAnalyticsPanel` to `FanClubPage.tsx`; add `BadgeImageUploader` + badge image S3 upload endpoint.

**Rollback**: Set `FAN_CLUBS_ENABLED=0` (once flag check is wired per section 4.1). "Fan Club" sidebar link should be conditionally hidden in `Sidebar.tsx` when the flag is off.

**Effort for remaining work**: Feature flag enforcement (XS). Missing models + analytics endpoint (S, 1 day). Broadcast chat badge wiring (M, 2-3 days). Welcome DM + cache invalidation (S, 1 day). Real-time SSE channels (M, 3 days). Early access post integration (S, 2 days). Analytics panel (S, 2 days). Badge image upload (S, 2 days). Total: ~2-3 weeks.

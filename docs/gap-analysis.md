# Platform Feature Gap Analysis

> Audited 2026-05-27 against branch `feat/media-integrations` (commit 16120696+).
> Suite: 2202 tests passing, 94 routers, 283 services, 128 E2E spec files.

---

## Verified Gaps (30 total)

### Removed from original list (not real gaps)

| # | Claimed Gap | Verdict | Evidence |
|---|-------------|---------|----------|
| 4 | Notification Center Live | **EXISTS** | `GET /ui/alerts/unread-count` (alerts.py:259); SSE stream `/ui/alerts/stream` (alerts.py:451); Header.tsx bell badge (line 247); `useAlertStream.ts` real-time SSE sync |
| 6 | Message Edit/Delete | **EXISTS** | `PATCH /conversations/{id}/messages/{id}` (messaging.py:9891); `DELETE` (messaging.py:9717); MessageBubble edit/delete UI; MessageEdits DDB table |
| 21 | Content Reporting from UI | **EXISTS** | `ReportContentModal.tsx`; `/v1/moderation/reports` endpoint (moderation.py:372); Integrated in PostCard, MessageBubble, CommentsThread, ContactsPage |
| 28 | Health Check | **PARTIAL (acceptable)** | `/api/ping` (misc.py:17); `/healthz` (messaging.py:11983); `/health` (newsfeed.py:4989) — scattered but functional |
| 35 | Two-way Jira Sync | **EXISTS** | `jira_inbound_apply.py` processes webhooks with conflict detection; `jira_outbound_sync.py` + worker exist; E2E tested in `jira-mock.spec.ts` |

---

## P0 — Core User Experience (5 gaps)

### 1. Post Bookmarks / Save Collections

**Status**: MISSING — no implementation exists

**What exists**: Nothing. No DDB entities, no API endpoints, no frontend UI for bookmarking posts or videos.

**Citations**:
- `frontend/src/api/types.ts:1781-1834` — FeedPost interface has no `bookmarked` or `saved` field
- `app/routers/newsfeed.py:711-793` — DDB key builders: `pk_user`, `pk_post`, `pk_hide`, `pk_unlock`, `pk_like` — no `pk_bookmark` or `pk_save`
- `app/routers/contacts.py` — only "favorites" reference is contacts-specific, not posts

**Required**:
- Backend: DDB entity `BOOKMARK#{user_id}#{content_type}#{content_id}`, CRUD endpoints, collections/folders
- Frontend: Bookmark icon on PostCard + VideoCard, "Saved" page with collection management

---

### 2. Post Sharing / Reposts (Public)

**Status**: PARTIAL — share-to-DM exists, public repost missing

**What exists**: `SharePostDialog.tsx` (155 lines) sends posts to conversations via `sendTextMessage()` with a preview. Invoked from PostCard.tsx:621-625.

**What's missing**: No `POST /posts/{id}/repost` endpoint. No repost entity in DDB. No repost count on posts. No "X reposted" attribution in feed.

**Citations**:
- `frontend/src/pages/feed/SharePostDialog.tsx:48-67` — mutation uses `sendTextMessage`, not a dedicated share/repost endpoint
- `app/routers/newsfeed.py` — no repost/share endpoint anywhere in 5000+ lines
- Feed only shows own posts (`GSI1PK = FEED#{viewer_user_id}`) — no repost fan-out mechanism

**Required**:
- Backend: Repost endpoint, repost DDB entity, repost count on PostOut, feed fan-out for reposts
- Frontend: "Repost" button alongside share, repost attribution in FeedTimeline

---

### 3. Global Search

**Status**: MISSING — only per-module searches exist

**What exists**: Per-module search endpoints: `/ui/discover/search` (users), `/ui/catalog/items/search` (catalog), `/messaging/contacts/search` (contacts), `/v1/fs/search` (files), `/ui/alerts/search` (alerts).

**What's missing**: No unified search endpoint. No `/search` route in App.tsx. No SearchPage or GlobalSearch component.

**Citations**:
- `frontend/src/App.tsx:84-147` — no `/search` route
- `app/routers/discovery.py:19-27` — search only returns users
- `frontend/src/api/endpoints/discovery.ts:34-38` — `searchDiscoverUsers` only
- No SearchPage component in `frontend/src/pages/`

**Required**:
- Backend: `GET /ui/search?q=...&types=posts,videos,users,files` aggregating across modules
- Frontend: `/search` page with tabbed results, search bar in header with Ctrl+K trigger

---

### 4. User Blocking

**Status**: PARTIAL — infrastructure exists, no public endpoints

**What exists**: `_is_blocked(blocker_id, blocked_id)` private function in `social.py:393` that checks DDB for `PK=USER#{blocker_id}, SK=BLOCKED#{blocked_id}`. Prevents blocked users from following.

**What's missing**: No public block/unblock endpoints. No "blocked users" list endpoint. No messaging filter for blocked users. No frontend block UI.

**Citations**:
- `app/services/social.py:393-398` — `_is_blocked()` private function reads DDB row
- `app/routers/social.py:1-201` — only follow/unfollow/followers/following/counts/status/mutual endpoints; no block endpoints
- No "block" or "mute" UI in any frontend component

**Required**:
- Backend: `POST /ui/social/block`, `POST /ui/social/unblock`, `GET /ui/social/blocked`
- Messaging: Filter messages from blocked users, prevent DM creation
- Frontend: Block button on profile, blocked users list in settings

---

### 5. Web Push Service Worker

**Status**: MISSING — device registration UI exists, no actual push delivery

**What exists**: `PushDevices.tsx` UI for device management. Backend `push.py` with register/revoke/test endpoints. Push device records in DDB.

**What's missing**: No service worker file. No `navigator.serviceWorker.register()`. No push event handler. Frontend generates placeholder token `web-${Date.now()}-${Math.random()}` instead of real push credentials.

**Citations**:
- `frontend/public/` — no `sw.js`, `service-worker.js`, or `firebase-messaging-sw.js`
- `frontend/src/pages/alerts/PushDevices.tsx:65` — placeholder token generation
- No `navigator.serviceWorker` call in any frontend file
- `app/routers/push.py:14-43` — register/revoke/test endpoints (stores tokens but can't deliver)

**Required**:
- Frontend: Service worker file, browser push permission request, actual VAPID key exchange
- Backend: Web Push protocol delivery (VAPID + encrypted payload to push service)

---

## P1 — Creator Economy (5 gaps)

### 6. Creator Storefront Page

**Status**: PARTIAL — public profile exists, no content showcase

**What exists**: `PublicUserProfilePage.tsx` (224 lines) shows display_name, bio, follower counts, message button. Backend `/api/videos/creator/{creator_id}` lists creator's videos separately.

**What's missing**: Profile page doesn't show videos, posts, or subscription tiers. No "Subscribe" CTA. No content tabs.

**Citations**:
- `frontend/src/pages/profile/PublicUserProfilePage.tsx` — renders name/bio/stats only, no video grid or plan cards
- `app/routers/profile.py:352-362` — returns `has_subscription_plans: bool` but not the actual plans
- `app/routers/video_listing.py:319,328` — `/api/videos/creator/{id}` exists but not integrated into profile

**Required**:
- Frontend: Tabbed content section on PublicUserProfilePage (Videos, Posts, About)
- Frontend: Subscription tier cards with "Subscribe" button
- Backend: Composite endpoint or frontend aggregates from existing endpoints

---

### 7. Payout Dashboard Frontend

**Status**: Backend complete, frontend missing

**What exists**: Full backend API — `GET /ui/payouts/balance`, `POST /ui/payouts/request`, `GET /ui/payouts` list, `POST /ui/payouts/{id}/cancel`. E2E tests pass.

**What's missing**: No frontend page for payouts. No PayoutDashboard component. No payout request form. No earnings breakdown UI.

**Citations**:
- `app/routers/creator_payouts.py:35-105` — 4 working endpoints
- `app/routers/creator_earnings.py:19-61` — summary + transactions endpoints
- `frontend/e2e/creator-payouts.spec.ts` — API tests pass
- `frontend/src/pages/` — no payout or earnings page component

**Required**:
- Frontend: `/payouts` route + PayoutDashboard page with balance cards, request form, history table
- Sidebar: Add Payouts link to Commerce group

---

### 8. Subscription Tier Management UI (Creator-facing)

**Status**: Backend CRUD complete, no creator UI

**What exists**: Backend plan CRUD — `POST /api/creators/{id}/plans`, `PATCH /api/plans/{id}`, `POST /api/plans/{id}/archive`, `PATCH /api/plans/{id}/pricing`. Subscriber-facing `PlanBrowser.tsx` (187 lines) shows plans for purchase.

**What's missing**: No UI for creators to create/edit/archive subscription tiers. No discount code management UI despite backend support.

**Citations**:
- `app/routers/subscription_server.py:706-813` — full plan CRUD endpoints
- `app/routers/subscription_server.py:1573-1639` — discount code CRUD endpoints
- `frontend/src/pages/subscriptions/PlanBrowser.tsx` — subscriber-facing only (browse + subscribe)
- No PlanEditor, TierManager, or DiscountCodeManager component exists

**Required**:
- Frontend: Plan creation/edit form, archive confirmation, pricing management
- Frontend: Discount code creation/list/toggle in a dedicated section

---

### 9. Tip Leaderboards / Top Supporters

**Status**: MISSING — tips logged but never aggregated

**What exists**: `tip_ledger.py` (150 lines) writes paired debit/credit entries with tipper_user_id, recipient_user_id, amount_cents. DDB records exist.

**What's missing**: No aggregation query. No "top supporters" endpoint. No leaderboard UI.

**Citations**:
- `app/services/tip_ledger.py` — write-only service, no query/aggregation functions
- No `GET /api/creators/{id}/top-supporters` or `GET /ui/tips/leaderboard` endpoint
- No frontend leaderboard component

**Required**:
- Backend: Aggregation query endpoint (top N tippers for a creator over period)
- Frontend: Top supporters widget on creator profile/analytics

---

### 10. Creator Analytics Depth

**Status**: Functional but shallow

**What exists**: 7 analytics endpoints (`overview`, `revenue`, `views`, `subscribers`, `top-content`, `audience`, `refresh`). AnalyticsPage.tsx with summary cards, view chart, revenue pie chart, subscriber growth, top content table.

**What's missing**: Per-video drill-down analytics. Revenue-by-source per content. Engagement rate (hardcoded to 0.0). No historical comparison. Limited demographics (country + device only).

**Citations**:
- `app/services/creator_analytics.py:391` — `"engagement_rate": 0.0` hardcoded
- `app/services/creator_analytics.py:389` — top content uses content_id as title (no actual title lookup)
- No per-video endpoint (`GET /ui/analytics/content/{content_id}`)
- Audience only returns `countries` + `devices` arrays (no age, gender, language)

**Required**:
- Backend: Per-content detail endpoint with time series
- Backend: Real engagement rate calculation (likes + comments / views)
- Frontend: Click-through from top content table to per-video analytics

---

## P1 — E-Commerce (3 gaps)

### 11. Inventory Management

**Status**: MISSING — no stock tracking

**What exists**: Catalog item CRUD with name, description, price, image, attributes. No quantity or stock fields.

**What's missing**: No `stock_count` field. No low-stock alerts. No inventory endpoints. No restock workflow.

**Citations**:
- `app/models.py` — CatalogItemOut has no inventory/stock fields
- `app/routers/catalog.py` — 665 lines, no inventory operations
- `frontend/src/pages/shop/ItemEditor.tsx` — no stock quantity input

**Required**:
- Backend: `stock_count` field on catalog items, `PATCH /ui/catalog/items/{id}/stock`
- Backend: Low-stock alert trigger (webhook or notification)
- Frontend: Stock quantity field in ItemEditor, stock column in admin catalog table

---

### 12. Promo Code Integration in Checkout

**Status**: Systems exist separately, not connected

**What exists**: Full promo code system — `promo_codes.py` with create/validate/redeem. `PromoCodesPage.tsx` for code management. Commercial checkout flow.

**What's missing**: Checkout page has no "Apply promo code" input. Checkout doesn't call promo validation. No discount display on order total.

**Citations**:
- `frontend/src/pages/shop/Checkout.tsx:1-267` — no promo code UI (verified all lines)
- `app/services/promo_codes.py:239` — `validate_promo_code()` exists but not called from checkout
- `app/services/promo_codes.py:335` — `_calculate_discount()` ready but unused in checkout flow

**Required**:
- Frontend: "Have a promo code?" expandable section in Checkout.tsx
- Backend: Wire promo validation into `commercial_checkout.py` order creation
- Frontend: Show discount line item on order summary

---

### 13. Cart Abandonment Reminders

**Status**: MISSING — no detection or reminders

**What exists**: Shopping cart service (`shoppingcart.py`, 537 lines). Scheduler infrastructure exists.

**What's missing**: No cart expiration TTL. No abandonment detection. No scheduled reminder. No notification.

**Citations**:
- `app/services/shoppingcart.py` — cart schema: `cart_id, status, created_at, purchased_at` — no expiration/TTL
- `app/services/scheduled_actions.py` — no cart-related executor
- `app/services/schedule_executors.py` — executors for posts, file_share, catalog_sale — no cart_reminder
- Zero results for "abandonment", "abandoned", "cart.*reminder" in codebase

**Required**:
- Backend: Cart TTL field, background job to detect stale carts (>24h)
- Backend: Schedule executor that sends alert/push when cart is abandoned
- Integration: Hook into alerts system for cart reminder notification

---

## P1 — Real-Time Communication (3 gaps)

### 14. Typing Indicators — Real-time Push

**Status**: Works but poll-based (3-second latency)

**What exists**: `TypingIndicator.tsx` UI with animated dots. `POST /conversations/{id}/typing` stores typing status. `GET /conversations/{id}/typing` poll endpoint. Frontend polls every 3 seconds via React Query.

**What's missing**: SSE fanout of typing events exists in backend (`typing:update` event type, messaging.py:11356) but frontend doesn't listen to it. Users see 0-3 second lag.

**Citations**:
- `frontend/src/pages/messages/TypingIndicator.tsx:36-42` — React Query poll every 3 seconds
- `app/routers/messaging.py:11356-11362` — `typing:update` SSE event IS sent to stream
- `frontend/src/hooks/useMessagingStream.ts` — does NOT handle `typing:update` event type

**Required**:
- Frontend: Add `typing:update` handler in `useMessagingStream.ts` to update TypingIndicator state from SSE
- Remove polling fallback (or keep as fallback for SSE disconnects)

---

### 15. Online Presence — Real-time Push

**Status**: Works but poll-based (15-second latency)

**What exists**: `PresenceDot.tsx` renders green/grey dot. `POST /presence/heartbeat` stores presence with TTL. `GET /presence?user_ids=...` batch lookup. Frontend heartbeats every 30s, polls presence every 15s.

**What's missing**: No SSE presence events. Other users must poll to see online/offline transitions.

**Citations**:
- `frontend/src/hooks/usePresence.ts` — `usePresenceStatus()` polls every 15 seconds
- `app/routers/messaging.py:11388-11430` — heartbeat endpoint stores in `tbl_presence`
- No `presence:update` event type in messaging SSE stream

**Required**:
- Backend: Emit `presence:update` SSE event when user heartbeat creates/expires presence
- Frontend: Handle presence events in `useMessagingStream` to update PresenceDot instantly

---

### 16. Read Receipts — Delivery Status + Real-time

**Status**: View tracking works, delivery status not exposed

**What exists**: `ReadReceipts.tsx` shows viewer avatars. `ViewTracker` uses IntersectionObserver to call `POST /messages/{id}/view`. Backend stores `delivered_at` + `read_at` in `tbl_receipts` (when enabled). `message:viewed` SSE event emitted.

**What's missing**: Frontend doesn't display delivery vs read distinction. `message:viewed` SSE event not consumed by frontend. No "delivered" checkmark or "read" double-checkmark.

**Citations**:
- `app/routers/messaging.py:10184-10270` — stores `delivered_at` and `read_at` in receipts table
- `app/routers/messaging.py:10246-10252` — emits `message:viewed` SSE event
- `frontend/src/pages/messages/ReadReceipts.tsx:30-65` — only queries views, not receipts
- `frontend/src/hooks/useMessagingStream.ts` — does NOT handle `message:viewed` event

**Required**:
- Frontend: Handle `message:viewed` SSE event to update read status in real-time
- Frontend: Show delivery/read indicators (single check = delivered, double check = read)
- Backend: Expose receipt data (delivered_at, read_at) in message query response

---

## P2 — Content & Discovery (3 gaps)

### 17. Hashtags / Topics Taxonomy

**Status**: MISSING for posts (gallery videos have tags but not exposed as hashtags)

**What exists**: `VideoMetadataModel` has `tags: List[str]` field. Gallery videos support tags.

**What's missing**: Posts have no tags/hashtags field. No hashtag extraction from post body. No topic taxonomy. No tag-based discovery. Tags on videos not surfaced as clickable hashtags.

**Citations**:
- `frontend/src/api/types.ts:1781-1834` — FeedPost interface has no `tags` or `hashtags` field
- `app/routers/newsfeed.py` — no tag extraction, no tag filter endpoint
- `app/models_video.py:126` — `tags: List[str]` exists for videos only
- `frontend/src/pages/feed/CreatePost.tsx` — no hashtag input

**Required**:
- Backend: `tags` field on posts, auto-extraction from `#hashtag` in body text
- Backend: `GET /ui/discover/tags/{tag}` endpoint for tag-filtered discovery
- Frontend: Clickable hashtags in post body, tag input in CreatePost, tag discovery page

---

### 18. Image Optimization Pipeline

**Status**: MINIMAL — WebP video posters only

**What exists**: FFmpeg extracts video frame → WebP poster (`filemanager.py:1362-1410`). Stored in S3 as `poster_image.webp`.

**What's missing**: No optimization for user-uploaded images (post images, profile photos). No resize. No AVIF. No srcset. No responsive images. No CDN cache headers.

**Citations**:
- `app/services/filemanager.py:1362-1410` — WebP poster for videos only
- `frontend/src/pages/feed/PostCard.tsx:77-82` — `<img src={url}>` single size, no srcset
- No `sharp`, `imagemagick`, or image processing library in requirements
- No image resize endpoint or service

**Required**:
- Backend: Image processing on upload (resize to S/M/L + WebP/AVIF variants)
- Frontend: `<img srcset>` or `<picture>` element for responsive images
- Storage: Multiple size variants per image in S3

---

### 19. SEO / Open Graph Meta Tags

**Status**: MISSING — SPA serves empty meta tags

**What exists**: Client-side React SPA. `index.html` has only viewport and charset meta.

**What's missing**: No Open Graph tags on public pages. No dynamic `document.title`. No SSR for crawlers. Link previews show generic app title.

**Citations**:
- `frontend/index.html:1-19` — no `og:title`, `og:description`, `og:image`, `twitter:card`
- `frontend/src/pages/profile/PublicUserProfilePage.tsx` — no `useEffect` to set `document.title` or inject meta
- `frontend/src/pages/calendar/PublicEventPage.tsx` — no meta tag management
- No `react-helmet` or `@unhead` in package.json

**Required**:
- Frontend: `react-helmet-async` for dynamic meta on public pages
- Backend: Meta endpoint returning og:title/description/image for SSR proxy
- Alternative: Lightweight SSR proxy that injects meta before serving SPA HTML to crawlers

---

## P2 — Platform Infrastructure (3 gaps)

### 20. Email Delivery — Production Config

**Status**: Code exists, not configured for real delivery

**What exists**: `send_alert_email()` in `alerts.py:332-353` uses boto3 SES to send. HTML email templates for 5 event categories. In dev mode logs to `.logs/dev/emails.log`.

**What's missing**: Not enabled in dev/staging. No delivery telemetry dashboard. HTML templates only used when `notification_email_templates_enabled=True`.

**Citations**:
- `app/services/alerts.py:340` — `_write_dev_log(S.dev_email_log, entry)` in dev mode
- `app/services/alerts.py:346-350` — real `ses.send_email()` when not dev mode
- `.env.local` — no `ALERTS_EMAIL_ENABLED=1` set
- No delivery tracking (success/bounce/complaint)

**Required**:
- Config: Enable email delivery in staging
- Backend: Delivery status tracking (SES notifications → DDB)
- Admin: Email delivery metrics dashboard

---

### 21. SMS Delivery — Production Config

**Status**: Code exists, not configured for real delivery

**What exists**: `send_alert_sms()` in `alerts.py:355-372` uses boto3 SNS `publish(PhoneNumber=...)`. Alert preferences have SMS section with phone management. Dev mode logs to `.logs/dev/sms.log`.

**What's missing**: Not enabled in dev/staging. No delivery tracking. Single provider (SNS only).

**Citations**:
- `app/services/alerts.py:368-370` — real SNS publish when not dev mode
- `frontend/src/pages/alerts/AlertPrefs.tsx:32-36` — SMS phone management UI exists
- `.env.local` — no SMS-enabled configuration

**Required**:
- Config: Enable SMS delivery in staging
- Backend: Delivery receipt tracking

---

### 22. Background Job Dashboard

**Status**: MISSING — jobs run but no admin visibility

**What exists**: `unified_scheduler.py` processes scheduled actions with claim/complete/fail lifecycle. `webhook_dispatcher.py` processes deliveries with retry logic. Both run as startup background tasks.

**What's missing**: No admin endpoint to query job queue status. No UI to see pending/failed/completed jobs. No metrics (queue depth, failure rate, latency).

**Citations**:
- `app/services/unified_scheduler.py:33-65` — processes jobs but no status API
- `app/services/webhook_dispatcher.py:26-64` — processes deliveries but no status API
- `app/routers/scheduler.py:78-147` — user-facing only (own scheduled actions)
- No admin job status endpoint in any router

**Required**:
- Backend: `GET /admin/jobs/status` — queue depths, failure counts, last run times
- Backend: `GET /admin/jobs/failed` — list of failed jobs for retry/inspection
- Frontend: Admin page showing job health metrics and failed job list

---

## P3 — Nice to Have (8 gaps)

### 23. Dark Mode — Backend Persistence

**Status**: localStorage only, no cross-device sync

**What exists**: `uiStore.ts` with Zustand persist middleware saves theme to localStorage key `"ui-store"`.

**What's missing**: No backend endpoint to save/retrieve theme preference. Theme resets on new device.

**Citations**:
- `frontend/src/stores/uiStore.ts:28-29` — persist to localStorage only
- No theme field in profile models or settings endpoints

**Required**: `PATCH /ui/settings/preferences` with theme field; load on session init.

---

### 24. Keyboard Shortcuts / Command Palette

**Status**: MISSING — no centralized system

**What exists**: `cmdk` library in package.json but only used for timezone combobox. Scattered ad-hoc keydown listeners in individual components.

**What's missing**: No global keyboard shortcut system. No command palette (Ctrl+K). No shortcut overlay.

**Citations**:
- `frontend/package.json:42` — `cmdk` installed but unused for command palette
- `frontend/src/components/shared/TimezoneCombobox.tsx` — only cmdk usage
- No `useHotkeys` hook, no shortcut registry

**Required**:
- Frontend: Command palette component (Ctrl+K) using cmdk
- Frontend: Global keyboard shortcuts (Ctrl+Enter send, Escape close, arrow navigation)

---

### 25. Drag-and-Drop Reorder

**Status**: MINIMAL — only questionnaire sections have native drag

**What exists**: `QuestionnaireBuilderPage.tsx:66` uses native HTML5 `draggable`. Broadcast product shelf uses arrow buttons.

**What's missing**: No drag-drop for videos, posts, catalog items, calendar events. No DnD library (react-dnd, dnd-kit) installed.

**Citations**:
- `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx:66` — native drag only
- `frontend/src/pages/broadcast/ProductShelfManager.tsx:115-131` — arrow buttons, not drag
- No `react-dnd`, `@dnd-kit/core`, or `react-beautiful-dnd` in package.json

**Required**: Install `@dnd-kit/core`, add sortable lists to: playlist order, catalog arrangement, gallery position.

---

### 26. Bulk Operations (Beyond Files/Admin Video)

**Status**: LIMITED — only admin video review + file move

**What exists**: `VideoReviewQueuePage.tsx` has batch approve/reject with multi-select. FilesPage has bulk move.

**What's missing**: No bulk operations on posts, catalog items, stories, scheduled items.

**Citations**:
- `frontend/src/pages/admin/VideoReviewQueuePage.tsx:112-128` — batch approve/reject
- `frontend/src/pages/feed/NewsFeed.tsx` — no multi-select
- `frontend/src/pages/shop/` — no bulk catalog operations UI

**Required**: Multi-select pattern reusable component; apply to catalog, posts, scheduled actions.

---

### 27. CSV Export

**Status**: MISSING — no user-facing CSV export anywhere

**What exists**: GDPR compliance data export (`privacy.py`). No CSV-specific export.

**What's missing**: No CSV export for analytics, billing history, contacts, questionnaire responses.

**Citations**:
- No "csv" or "export" endpoint in analytics, billing, or contacts routers
- `app/routers/privacy.py` — compliance export only (JSON archive)
- No `text/csv` content type in any response

**Required**:
- Backend: `GET /ui/analytics/export?format=csv`, `GET /ui/billing/export?format=csv`
- Frontend: "Export CSV" button on analytics, billing, and contacts pages

---

### 28. Questionnaire Response Analytics Frontend

**Status**: Backend API exists, no frontend dashboard

**What exists**: `GET /drafts/{id}/analytics` returns funnel stats (starts, completions, completion_rate), average completion time, top 5 dropoff points, validation hotspots.

**What's missing**: No frontend page/component to display this data. Analytics computed but invisible to users.

**Citations**:
- `app/routers/questionnaires.py:604` — `GET /drafts/{id}/analytics` endpoint
- `app/routers/questionnaires.py:150-228` — `_compute_questionnaire_analytics()` computes funnel + dropoff
- No analytics tab or dashboard in questionnaire frontend pages

**Required**:
- Frontend: Analytics tab on QuestionnaireBuilderPage showing funnel chart, dropoff points, completion rate

---

### 29. Google Drive File Picker UI

**Status**: Mock backend exists, no frontend integration UI

**What exists**: `google_drive_mock.py` stateful mock with file CRUD. `file_providers.py` has `GoogleDriveProvider` with configurable URLs. `google-drive-mock.spec.ts` E2E tests pass.

**What's missing**: No frontend UI to browse/select/link Google Drive files. No "Connect Google Drive" flow in the frontend.

**Citations**:
- `app/routers/google_drive_mock.py` — full mock API
- `app/services/file_providers.py` — GoogleDriveProvider with `S.google_drive_api_base_url`
- `frontend/src/pages/files/` — no Google Drive picker or browser component
- `frontend/src/api/endpoints/` — no google-drive endpoint file

**Required**:
- Frontend: Google Drive OAuth connect button in Files settings
- Frontend: Drive file picker dialog (browse folders, select files to mount/import)

---

### 30. Order Tracking — Carrier Integration

**Status**: Manual tracking exists, no carrier auto-update

**What exists**: `TransactionDetail.tsx:441-445` displays tracking_number and carrier. `ShippingTimeline.tsx` renders shipped/delivered status. `PUT /ui/purchase-history/transactions/{id}/shipping` updates shipping info manually.

**What's missing**: No carrier API integration (UPS/FedEx/USPS). No automatic status updates. No tracking URL construction. No webhook from carriers.

**Citations**:
- `frontend/src/pages/purchases/TransactionDetail.tsx:441-445` — shows tracking fields
- `frontend/src/pages/purchases/ShippingTimeline.tsx` — visual timeline
- `app/routers/purchase_history.py:70-78` — manual update endpoint only
- `app/routers/ups.py` — UPS integration stub exists but only for label generation, not tracking

**Required**:
- Backend: Carrier tracking API polling (or webhook receiver) for status updates
- Backend: Auto-construct tracking URL from carrier + tracking number
- Frontend: Clickable tracking link, auto-refreshing status timeline

---

## Summary

| Priority | Gap Count | Key Theme |
|----------|-----------|-----------|
| **P0** | 5 | Social layer (bookmarks, sharing, blocking, search) + push notifications |
| **P1 Creator** | 5 | Frontend UIs for existing backend APIs (payouts, tiers, analytics depth) |
| **P1 Commerce** | 3 | Inventory, promo integration, cart abandonment |
| **P1 Real-time** | 3 | SSE handlers missing in frontend for typing/presence/read (backends emit events already) |
| **P2 Content** | 3 | Hashtags, image optimization, SEO meta |
| **P2 Platform** | 3 | Email/SMS production config, job dashboard |
| **P3** | 8 | Polish: shortcuts, drag-drop, bulk ops, CSV, Drive picker, tracking |
| **Total** | **30** | |

### Quick Wins (small effort, high impact)

1. **Typing indicators real-time** (P1) — just add SSE handler in `useMessagingStream.ts` for existing `typing:update` event
2. **Presence real-time** (P1) — same pattern, add SSE handler for presence events
3. **Read receipts real-time** (P1) — handle `message:viewed` SSE event already being emitted
4. **Promo code in checkout** (P1) — add input field in Checkout.tsx, call existing `validate_promo_code()`
5. **Dark mode backend sync** (P3) — single PATCH endpoint + load on session init

### Largest Efforts

1. **Global Search** (P0) — cross-module index, new page, header integration
2. **Image Optimization Pipeline** (P2) — processing on upload, multiple variants, srcset
3. **Web Push Service Worker** (P0) — VAPID keys, SW registration, push protocol
4. **Post Bookmarks** (P0) — new DDB entity, CRUD endpoints, saved page
5. **Inventory Management** (P1) — model changes, stock tracking, low-stock alerts

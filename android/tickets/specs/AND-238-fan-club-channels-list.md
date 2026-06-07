---
id: AND-238
title: Fan-club channels list
milestone: M5
epic: E32
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-234]
blocks: [AND-239]
---

# AND-238 — Fan-club channels list

## 1. Overview & Goal

Build the fan-club channels overview screen for the TestLogon Android app: a
read surface that lists the channels a creator's fan-club exposes, **grouped and
ordered by subscription tier**, so a subscribed (or browsing) user can see which
channels exist, which tier each belongs to, and which they currently have access
to. This ticket owns the **`fan-club channels` data layer (API call wrapper +
DTOs + repository method), the `ChannelsViewModel` exposing a tier-grouped
`StateFlow<UiState>`, and the `FanClubChannelsScreen` Compose surface that
renders channels sectioned by tier**.

It does **not** own per-channel message reading/posting/reactions — that is
AND-239 (Fan-club channel messages), which navigates from a channel row created
here. It also does not own subscription tier definitions or the subscriptions
endpoint contract themselves: those are owned by AND-234 (Subscriptions API +
DTOs), which this ticket consumes for the `SubscriptionTier` model and tier
ordering.

Success means: an authenticated user opens a creator's fan-club, sees the
channel list render as **tier-grouped sections** (e.g. "Free", "Bronze",
"Gold"), in tier order, with locked channels visually distinguished from
accessible ones, and can tap an accessible channel to navigate toward its
message thread (AND-239). Loading, empty, error, and offline/stale states are
handled against the unreliable dev backend.

## 2. Context & References

- **Module:** `feature-fanclub` (new), namespace
  `com.testlogon.android.feature.fanclub`. Depends on `core-network`,
  `core-model`, `core-data`, `core-ui`, `core-testing`.
- **Upstream (AND-234 — Subscriptions API + DTOs):** provides the
  `SubscriptionTier` model (id, name, ordinal/rank, price), the user's active
  subscription mapping, and the Retrofit/Moshi plumbing for the subscriptions
  domain. This ticket reuses `SubscriptionTier` for grouping/ordering and the
  active-subscription set to compute per-channel access. It must **not** redefine
  the tier model.
- **Downstream (AND-239 — Fan-club channel messages):** consumes the
  `channelId` and access flag emitted by a row here to load
  `/ui/fan-club/channels/{id}/messages`. The row's click contract
  (`onChannelClick(channelId: String)`) is the integration point.
- **Auth:** cookie-authenticated surface. All requests ride the persistent
  cookie jar + `X-CSRF-Token` header (echoed from the `ui_csrf` cookie)
  established by the session stack (AND-027 et al., M1). On `401`, the shared
  OkHttp authenticator performs a single `POST /ui/session/refresh` then retries;
  a persisting `401` becomes a terminal error here (no re-loop).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; design for ~20s timeouts, bounded backoff on
  idempotent GETs, offline/stale UI). OpenAPI at `/openapi.json`. Web reference:
  `src/api/endpoints/fan-club.ts` (`listChannels`, `listTiers`); shared types in
  `src/api/types.ts` (`ChannelOut`, `TierOut`). NOTE: the web `FanClubPage.tsx`
  is a **creator-side management** surface (create/delete tiers & channels, flat
  channel grid with a "Tier N+" badge, inline chat view) — it does **not**
  implement the consumer tier-grouped/locked view this Android ticket specifies,
  so that UX is an Android product decision, not a mirror of the web client.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, Room 2.6 (cache) + DataStore, Coil (avatars). minSdk 24,
  compile/target 35, JDK 17.

## 3. Functional Requirements

FR-1. **Load channels.** On entering the screen for a given creator/fan-club
(`creatorId` route arg), issue `GET /ui/fan-club/channels` (scoped to that
creator) and render the result.

FR-2. **Group by tier.** Channels are grouped into sections, one per fan-club
tier (`TierOut`), matched by the tier's `level` to each channel's
`min_tier_level`, and sorted by tier `level`/`sort_order` ascending (lowest tier
first; the `min_tier_level == 0` "free" group sorts first). Within a tier,
channels are ordered by name (CORRECTED: the backend `ChannelOut` has **no**
`position`/`order` field; ordering by `last_message_at` desc is an acceptable
alternative — document the choice).

FR-3. **Section headers.** Each tier section shows a sticky header with the tier
name (from `TierOut.name`, with optional `badge_emoji`/`color`) and, if the user
is not subscribed at that tier, a lock affordance. Note: the fan-club `TierOut`
has **no price field** — any price/label must come from the linked subscription
plan (`plan_id`) or AND-234's plan data, not from `TierOut` directly.

FR-4. **Per-channel access state.** Each channel row reflects whether the current
user has access (derived from the user's active subscription tier vs the
channel's required tier). Accessible channels are tappable; locked channels show
a lock icon and a muted style, and tapping a locked channel surfaces an "upgrade
required" affordance rather than navigating to messages.

FR-5. **Navigation.** Tapping an **accessible** channel invokes
`onChannelClick(channelId)`, routed by the nav host to the AND-239 messages
screen.

FR-6. **Loading state.** While the initial load is in flight and no cached data
exists, show a full-screen loading state (`core-ui` `LoadingState`).

FR-7. **Empty state.** When the load succeeds and there are zero channels, show a
non-error empty state ("No channels yet").

FR-8. **Error state.** When the load fails on an empty screen, show a full-screen
retriable error (`core-ui` `ErrorState`) with a Retry control. A failure when
cached/previous data is present preserves the list and surfaces a transient
error + stale indicator (see §7).

FR-9. **Refresh.** A Material 3 `PullToRefreshBox` wraps the list; the gesture
re-issues the load. Manual retry from the error state calls the same load.

FR-10. **Channel metadata.** Each row renders: channel name, optional
description/topic (one line, ellipsized), and the access/lock badge. The backend
`ChannelOut` also provides `message_count`, `last_message_at`, and
`last_message_preview`, which may be used as the activity hint (CORRECTED: there
is **no** `avatar_url` field on `ChannelOut`, so the Coil avatar is not backed by
this endpoint — drop it or source an avatar elsewhere; treat as an open item).
Fields absent from the response degrade gracefully.

## 4. Technical Design

### 4.1 Layering

```
FanClubChannelsScreen (Composable)        feature-fanclub/ui
  -> ChannelsViewModel (Hilt)             feature-fanclub/ui
       -> FanClubRepository               feature-fanclub/data (this ticket)
            -> FanClubApi (Retrofit)      feature-fanclub/data (this ticket)
            -> SubscriptionsRepository    core-data / subs (AND-234)
```

This ticket introduces the fan-club API + repository; tier data is read from
AND-234's subscriptions repository and joined in `FanClubRepository` (or the
ViewModel) to produce the grouped view model.

### 4.2 Models (core-model / feature-fanclub)

```kotlin
// CORRECTED to match backend ChannelOut (src/api/types.ts: ChannelOut).
data class FanClubChannel(
    val id: String,                // <- ChannelOut.channel_id
    val name: String,
    val description: String?,
    val minTierLevel: Int,         // <- ChannelOut.min_tier_level (integer LEVEL, NOT a tier id)
    val messageCount: Int,         // <- ChannelOut.message_count
    val lastMessageAt: Long,       // <- ChannelOut.last_message_at (epoch seconds, not ISO)
    val lastMessagePreview: String?, // <- ChannelOut.last_message_preview
    val pinnedMessageId: String?,  // <- ChannelOut.pinned_message_id
    // NOTE: backend ChannelOut has NO avatar_url, NO position, NO required_tier_id,
    // NO last_activity_at. Ordering within a tier uses name (no `position` field exists).
)

// Joined result the UI renders, computed from channels + tiers + active sub.
data class TierSection(
    val tier: TierOut?,            // <- fan-club TierOut matched by level; null => "Tier 0"/free group
    val channels: List<ChannelUiItem>,
)

data class ChannelUiItem(
    val channel: FanClubChannel,
    val isAccessible: Boolean,      // user's active tier level >= channel.minTierLevel
)
```

The fan-club tier model is `TierOut` from `GET /ui/fan-club/tiers` (fields:
`tier_id, name, level, sort_order, color, badge_emoji?, badge_image_url?,
member_count, plan_id, ...`). It has **no price field**; price lives on the
linked `plan_id`/subscription plan (or on the admin-side `SubscriptionTierOut`,
which is a *different* schema with `price_cents`/`display_order`). AND-234 is
expected to expose this tier/plan data; this ticket does not redefine it.

### 4.3 API + Repository

```kotlin
interface FanClubApi {
    // CORRECTED: response is a BARE JSON array of ChannelOut, not a {channels:[...]}
    // wrapper. creator_id is an OPTIONAL query param (omit => caller's own context).
    @GET("ui/fan-club/channels")
    suspend fun getChannels(
        @Query("creator_id") creatorId: String?,
    ): List<ChannelDto>   // ChannelDto mirrors backend ChannelOut
}

interface FanClubRepository {
    /** Channels joined with tiers + the user's access, grouped & ordered. */
    suspend fun getChannelsByTier(creatorId: String): ApiResult<List<TierSection>>
}
```

`FanClubRepositoryImpl` calls `FanClubApi.getChannels`, maps each `ChannelDto`
(backend `ChannelOut`) to `FanClubChannel`, reads tiers (fan-club `TierOut`,
which carries `level`/`sort_order`) + the active subscription level from AND-234,
computes `isAccessible` per channel (active tier `level >= channel.minTierLevel`;
`minTierLevel == 0` => free/all-access), groups channels under the tier whose
`level` matches `minTierLevel`, and sorts sections by tier `level`/`sort_order`
ascending. Network/HTTP failures are surfaced as `ApiResult.Failure` using the
shared `core-network` `detail` mapper. (The web reference's `normalizeErrorDetail`
handles `detail` as `string | [{msg}] | {code,...}`.)

### 4.4 ViewModel

```kotlin
@HiltViewModel
class ChannelsViewModel @Inject constructor(
    private val repository: FanClubRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val creatorId: String = savedStateHandle["creatorId"]!!

    private val _uiState = MutableStateFlow<ChannelsUiState>(ChannelsUiState.Loading)
    val uiState: StateFlow<ChannelsUiState> = _uiState.asStateFlow()

    init { load() }

    fun load() { /* set Loading (if empty), call repo, map to Content/Empty/Error */ }
    fun refresh() { /* same call; keep prior content on failure, set isStale */ }
    fun onChannelClick(item: ChannelUiItem) { /* emit nav or upgrade event */ }
}

sealed interface ChannelsUiState {
    data object Loading : ChannelsUiState
    data class Content(
        val sections: List<TierSection>,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : ChannelsUiState
    data object Empty : ChannelsUiState
    data class Error(val message: String, val retryable: Boolean) : ChannelsUiState
}
```

A one-shot `Channel<ChannelsEvent>` / `SharedFlow` carries navigation
(`NavigateToMessages(channelId)`) and `ShowUpgrade(tier)` events so the screen
stays a pure function of `uiState`.

### 4.5 Compose host

```kotlin
@Composable
fun FanClubChannelsScreen(
    viewModel: ChannelsViewModel = hiltViewModel(),
    onChannelClick: (channelId: String) -> Unit,
    onUpgrade: (tierId: String) -> Unit,
)

@Composable private fun ChannelsList(
    sections: List<TierSection>,
    isStale: Boolean,
    onChannelClick: (ChannelUiItem) -> Unit,
    modifier: Modifier = Modifier,
)
@Composable private fun TierSectionHeader(tier: SubscriptionTier?, locked: Boolean)
@Composable private fun ChannelRow(item: ChannelUiItem, onClick: () -> Unit)
```

`FanClubChannelsScreen` collects `uiState` via
`collectAsStateWithLifecycle()`, wraps a `PullToRefreshBox` (refresh ->
`viewModel.refresh()`), and switches on state: `Loading` -> `LoadingState`;
`Empty` -> empty state; `Error` -> `ErrorState(onRetry = viewModel::load)`;
`Content` -> `ChannelsList`. `ChannelsList` is a `LazyColumn` using
`stickyHeader { TierSectionHeader(...) }` per section followed by `items(section.channels, key = { it.channel.id })` rendering `ChannelRow`. A stale
banner (`core-ui` offline/stale composable) renders above the list when
`isStale`.

### 4.6 Hilt wiring

A `FanClubModule` (`@Module @InstallIn(SingletonComponent::class)`) provides
`FanClubApi` from the shared Retrofit instance and `@Binds`
`FanClubRepositoryImpl` to `FanClubRepository`. `ChannelsViewModel` is
`@HiltViewModel`; the route is registered in the authenticated nav graph with a
`creatorId` argument.

## 5. API Contract

This ticket **consumes** the existing fan-club channels read endpoint (it does
not define a new one — the endpoint already exists in the backend). Subscription
tier shapes are owned by AND-234. Verified against `openapi.index.txt`
(`GET /ui/fan-club/channels`) and the web reference
(`src/api/endpoints/fan-club.ts: listChannels`, `src/api/types.ts: ChannelOut`).

**Request** — `GET /ui/fan-club/channels` (VERIFIED): `creator_id` is an
**optional query param**; auth via cookie jar + `X-CSRF-Token` (echoed from the
`ui_csrf` cookie). The OpenAPI also declares optional `user_sub`, `X-SESSION-ID`,
and `X-IMPERSONATION-TOKEN` params (impersonation; not used by this ticket).

```
GET /ui/fan-club/channels?creator_id=usr_creator_123
Cookie: <session cookies, incl. ui_csrf>
X-CSRF-Token: <ui_csrf value>
```

**Response 200** — a **bare JSON array** of `ChannelOut` (CORRECTED: not a
`{channels:[...]}` wrapper). OpenAPI declares the 200 body as an untyped schema
`{}`; the authoritative shape is the web client's `ChannelOut`:

```json
[
  {
    "channel_id": "chan_01HZ...",
    "creator_id": "usr_creator_123",
    "name": "general",
    "description": "Open chat for everyone",
    "min_tier_level": 0,
    "message_count": 42,
    "last_message_at": 1749114720,
    "last_message_preview": "see you all tonight",
    "pinned_message_id": null,
    "slowmode_seconds": 0,
    "max_message_length": 2000,
    "created_at": 1748000000,
    "updated_at": 1749114720
  },
  {
    "channel_id": "chan_02HZ...",
    "creator_id": "usr_creator_123",
    "name": "gold-lounge",
    "description": "Gold-tier perks & AMAs",
    "min_tier_level": 3,
    "message_count": 7,
    "last_message_at": 1749110400,
    "last_message_preview": null,
    "pinned_message_id": null,
    "slowmode_seconds": 5,
    "max_message_length": 2000,
    "created_at": 1748000000,
    "updated_at": 1749110400
  }
]
```

DTO mapping (CORRECTED): top-level array `-> List<FanClubChannel>`; `channel_id
-> id`; `min_tier_level -> minTierLevel` (`0` => free/all-access group);
`last_message_at` is **epoch seconds** (Long), not an ISO `last_activity_at`
string. There is **no** `avatar_url`, `position`, or `required_tier_id` field —
grouping keys off `min_tier_level` matched to the tier's `level`. Tier
name/level/sort order for grouping and headers come from AND-234's fan-club
`TierOut` (`GET /ui/fan-club/tiers`), matched by `level == min_tier_level`.

**Error responses.** FastAPI `detail` may be `string | [{msg}] | {code,...}`;
mapping is owned by `core-network`. `401` triggers the single
refresh-then-retry interceptor; a persisting `401`, any `5xx`, `404` (unknown
creator), or socket/timeout becomes `ApiResult.Failure` mapped to a user-facing
`ChannelsUiState.Error` (retryable for network/5xx/timeout; non-retryable for
`404`/`403` with an explanatory message).

## 6. Data & State Management

- **Source of truth:** `StateFlow<ChannelsUiState>` in `ChannelsViewModel`,
  derived from `FanClubRepository.getChannelsByTier`.
- **Tier join:** grouping/ordering is computed in the data layer from the channel
  list + AND-234 tiers + active subscription; the ViewModel does not re-fetch
  tiers per recomposition.
- **Caching (Room, optional-but-specified):** the channels response is cached in
  a `fan_club_channels` Room table keyed by `creatorId` so a re-entry or offline
  open renders last-known channels immediately (marked `isStale`). The repository
  follows cache-then-network: emit cached (stale) then refresh; on network
  success replace cache. If Room scope proves heavy for M5, a single in-memory
  cache in the repository is the acceptable fallback (document the choice).
- **Access computation (CORRECTED):** `isAccessible = activeTierLevel >=
  channel.minTierLevel` (where `activeTierLevel` is the user's active fan-club
  tier `level`, or `0` when not subscribed). `minTierLevel == 0` => always
  accessible; no active subscription => only `min_tier_level == 0` channels are
  accessible. (Levels are integers; there is no `required_tier_id` join.)
- **Keys:** `LazyColumn` items keyed by `channel.id` (= `channel_id`); section
  headers keyed by `tier?.tier_id ?: "level0"`.
- **Saved state:** `creatorId` is read from `SavedStateHandle`; the loaded
  content survives configuration change via the retained ViewModel.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (core-network). Timeout => retryable
  `Error` (empty) or stale-banner (content present).
- **Retry:** the channels GET is idempotent, so the shared bounded-backoff retry
  interceptor for idempotent GETs applies at the network layer. UI Retry calls
  `load()`.
- **Empty list:** show empty state only on a successful response with zero
  channels — never conflate with error.
- **Failure with cached content:** keep showing cached channels, set
  `isStale = true`, and surface a transient error (snackbar via shared host).
- **Failure on empty screen:** full-screen `ErrorState` with Retry.
- **401 loop guard:** rely on the interceptor's single-refresh contract; a
  persisting `401` is terminal (re-route to login is owned by the auth-gated
  routing, AND-025).
- **Locked channel tap:** never navigate; emit `ShowUpgrade(tier)` so locked
  content is never requested.
- **Offline:** with no network and a cache present, render stale content + banner;
  with no cache, render the error/offline state.

## 8. Security & Privacy

- All requests are cookie-authenticated over the persistent cookie jar with the
  `X-CSRF-Token` header; this ticket adds no new auth handling and must use the
  shared OkHttp client only.
- **Access enforcement is server-authoritative.** Client-side `isAccessible` is a
  UX affordance only; the backend remains the source of truth and AND-239 must
  not assume client gating. This ticket never fetches messages for locked
  channels.
- No cookies, CSRF tokens, or session identifiers are logged (see §10).
- Dev backend is **plaintext HTTP** (dev-only posture); production must use HTTPS,
  gated via build config (owned by network/build tickets).
- If channels are cached to Room, only non-sensitive channel metadata is stored
  (id/name/description/tier/avatar); no message content and no PII beyond what the
  channel list already exposes.

## 9. Accessibility & i18n

- All user-facing strings (`channels_loading`, `channels_empty`,
  `channels_error_generic`, `channels_retry`, `channel_locked`,
  `channel_upgrade_cta`, tier-header format) live in
  `feature-fanclub/res/values/strings.xml`; no hardcoded literals.
- Tier section headers expose a merged semantics node ("Gold tier, locked");
  locked channel rows announce locked state and the upgrade action via
  `contentDescription` / a custom accessibility action.
- Tappable rows and Retry/Upgrade controls meet the 48x48dp minimum touch
  target.
- Coil avatars supply `contentDescription` (channel name) or null for purely
  decorative images.
- RTL-safe: start/end padding only; tier/price formatting respects locale (use
  the price formatter from AND-234/core-ui).
- Sticky headers remain operable under TalkBack linear navigation.

## 10. Telemetry & Logging

- Structured debug logs (Timber, debug builds only):
  `fanclub_channels_load_start{creatorIdHash}`,
  `fanclub_channels_load_result{success, sectionCount, channelCount, durationMs, stale}`,
  `fanclub_channels_load_error{type, httpStatus}`,
  `fanclub_channel_click{accessible}`. The `creatorId` is logged as a hash, never
  raw; no cookies/tokens/descriptions are logged.
- Analytics (if the core analytics facade is available): `fanclub_channels_viewed`,
  `fanclub_channels_refresh`, `fanclub_channel_opened{tier}`,
  `fanclub_locked_channel_tapped{tier}`, `fanclub_channels_load_failed{type}`.
  Counts/enums only; no free text.

## 11. Testing Strategy

**Unit — `FanClubRepositoryImpl` (JUnit + coroutines-test + Turbine):**
- Channels + tiers join produces sections sorted by tier ordinal, free/no-tier
  group first.
- Within-tier ordering by `position` then name.
- `isAccessible` true for null `requiredTier`; true when active rank >= required;
  false when below / no active subscription.
- `ApiResult.Failure` from the API surfaces as repository failure (no partial
  sections).

**Unit — `ChannelsViewModel`:**
- Initial `Loading` -> `Content` on success; `Empty` on zero channels;
  `Error(retryable)` on failure with no cache.
- Failure with cached content keeps `Content`, sets `isStale = true`.
- `refresh()` toggles `isRefreshing` and updates content.
- Tapping a locked channel emits `ShowUpgrade`; an accessible channel emits
  `NavigateToMessages(channelId)`.

**Integration — MockWebServer (core-network rig, AND-046 harness):**
- 200 with mixed-tier fixture renders the expected grouped order.
- `401` then (post-refresh) `200` succeeds; persistent `401` => terminal error.
- `503`/timeout => retryable error; subsequent `200` recovers.
- `404` (unknown creator) => non-retryable error message.

**Compose UI (`createComposeRule`):**
- Loading shows full-screen progress; loaded shows tier headers + rows in order.
- Locked channel shows lock badge; tapping it shows upgrade affordance and does
  **not** navigate.
- Accessible channel tap invokes `onChannelClick` with the right id.
- Empty result shows empty state (not error); error state shows Retry that
  re-invokes load.
- Stale banner renders when `isStale`.

**Manual / live backend (acceptance):** against `http://18.222.237.167:8000`,
signed in: channels render grouped by tier in tier order; locked vs accessible
visibly distinguished; tapping an accessible channel proceeds toward messages.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-234 (Subscriptions API + DTOs):** must land first;
  provides `SubscriptionTier` (incl. rank/ordinal + price) and the active
  subscription mapping used for grouping, ordering, and access computation.
- **Transitive:** AND-027 (auth/session stack), `core-network`
  (`ApiResult` + cookie/CSRF + 401-refresh + idempotent-GET retry),
  `core-ui` state composables, and the authenticated nav graph (AND-024/AND-025),
  all in place by M1/earlier M5.
- **Blocks — AND-239 (Fan-club channel messages):** consumes `channelId` and the
  access flag from a row here to load
  `/ui/fan-club/channels/{id}/messages`. The `onChannelClick(channelId)` contract
  is the integration seam.
- **Sequencing:** AND-234 -> **AND-238** -> AND-239.

## 13. Risks & Open Questions

- **OQ-1 (endpoint shape) — RESOLVED.** Verified: `GET /ui/fan-club/channels`
  with an **optional** `creator_id` **query** param (openapi.index.txt;
  `src/api/endpoints/fan-club.ts: listChannels`). Not a path-scoped variant.
- **OQ-2 (tier on channel) — RESOLVED.** The channel carries `min_tier_level`
  (an integer LEVEL), **not** a `required_tier_id` and **not** an embedded tier
  object (`src/api/types.ts: ChannelOut`). Grouping joins `min_tier_level` to the
  fan-club `TierOut.level`.
- **OQ-3 (access flag source) — RESOLVED (derive).** `ChannelOut` exposes **no**
  per-channel `accessible`/`locked` flag, so the client must derive access from
  `min_tier_level` vs the user's active tier level (treated as advisory; server
  remains authoritative — see §8).
- **OQ-4 (pagination):** assumes the channel list is small and unpaginated. If the
  backend paginates, this becomes a Paging-3 surface (small contained change,
  mirror AND-098).
- **Risk-1 (flaky dev host):** ~20s timeouts slow manual acceptance; mitigate via
  the retry interceptor, cache-then-network, and stale UI.
- **Risk-2 (client/server access drift):** client-derived `isAccessible` could
  diverge from server enforcement; mitigated by treating it as advisory and
  letting AND-239 rely on server gating.

## 14. Acceptance Criteria

AC-1. Against the dev backend, a signed-in user opening a creator's fan-club sees
the channel list **render grouped by tier**, with tier sections ordered by tier
rank and channels ordered within each tier. *(maps to source Acceptance:
"Channels render by tier".)*

AC-2. Each tier section shows a header with the tier name (and a lock affordance
for tiers the user is not subscribed to), sourced from the fan-club `TierOut`
(`name`/`level`); any price shown derives from the linked plan, not `TierOut`.

AC-3. Locked vs accessible channels are visually distinguished; tapping an
accessible channel invokes `onChannelClick(channelId)` (routing toward AND-239),
while tapping a locked channel shows an upgrade affordance and does not navigate.

AC-4. A successful empty response shows the empty state, distinct from the error
state.

AC-5. A load failure on an empty screen shows a full-screen retriable error; a
failure with cached/previous content preserves the list and shows a stale
indicator + transient error.

AC-6. Pull-to-refresh re-issues the load and reflects refreshing state.

AC-7. Unit tests (repository grouping/ordering/access + ViewModel state
transitions), MockWebServer integration (401-refresh, timeout-retry, 404), and
Compose tests (grouped render, locked tap, empty/error/retry) all pass.

## 15. Definition of Done

- `feature-fanclub` module created with `FanClubApi`, `FanClubRepository`
  (+ impl), `ChannelsViewModel`, `FanClubChannelsScreen` + `ChannelsList` /
  `TierSectionHeader` / `ChannelRow`; package
  `com.testlogon.android.feature.fanclub`.
- Consumes AND-234's `SubscriptionTier` + active subscription for grouping,
  ordering, and access; no tier-model duplication.
- All FR-1..FR-10 implemented; AC-1..AC-7 verified.
- Route registered in the authenticated nav graph with a `creatorId` arg;
  `onChannelClick` wired toward the AND-239 messages destination.
- All user-facing strings externalized; a11y semantics, sticky-header support,
  and 48dp touch targets in place; RTL-safe.
- No sensitive data logged; uses the shared cookie/CSRF OkHttp client only;
  cache (if Room) stores non-sensitive channel metadata only.
- Unit + integration + Compose tests added and green in CI;
  `./gradlew :feature-fanclub:test :feature-fanclub:connectedDebugAndroidTest`
  (or instrumented equivalent) passes.
- `ChannelRow`'s click contract documented as the AND-239 integration point
  (KDoc + `// TODO(AND-239)`).
- Lint/detekt clean; merged to `android-port` with a passing review against this
  spec.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Endpoint is `GET /ui/fan-club/channels`.** VERIFIED.
   Source: openapi.index.txt `GET /ui/fan-club/channels`
   (op=`api_list_channels_ui_fan_club_channels_get`); `src/api/endpoints/fan-club.ts: listChannels`.
2. **`creator_id` is an optional query param (not a path segment).** VERIFIED.
   Source: openapi.pretty.json (op `api_list_channels_...`, `in: query`,
   `required: false`); `src/api/endpoints/fan-club.ts: listChannels` (`params = creatorId ? { creator_id } : undefined`).
3. **Response 200 is a bare JSON array of channels, not a `{channels:[...]}` wrapper (`FanClubChannelsResponseDto`).** CORRECTED.
   Source: `src/api/endpoints/fan-club.ts: listChannels` returns `Promise<ChannelOut[]>`. (OpenAPI declares the 200 body as untyped `{}`, so the frontend is authoritative.)
4. **Channel DTO is `ChannelOut`: `channel_id, creator_id, name, description?, min_tier_level, message_count, last_message_at, last_message_preview?, pinned_message_id?, slowmode_seconds, max_message_length, created_at, updated_at`.** VERIFIED.
   Source: `src/api/types.ts: ChannelOut`.
5. **Per-channel access is keyed by integer `min_tier_level`, NOT a `required_tier_id` string.** CORRECTED (spec said `required_tier_id`).
   Source: `src/api/types.ts: ChannelOut.min_tier_level: number`; web UI renders `Tier {min_tier_level}+` (`src/pages/fan-club/FanClubPage.tsx` line 146).
6. **`ChannelOut` has no `avatar_url`, no `position`, no `last_activity_at` (ISO).** CORRECTED.
   Source: `src/api/types.ts: ChannelOut` (no such fields; activity is `last_message_at`, an epoch-seconds number).
7. **Fan-club tier model is `TierOut` from `GET /ui/fan-club/tiers`: `tier_id, creator_id, plan_id, name, level, color, badge_emoji?, badge_image_url?, description?, benefits, member_count, sort_order, active, ...`.** VERIFIED.
   Source: `src/api/types.ts: TierOut`; openapi.index.txt `GET /ui/fan-club/tiers`; `src/api/endpoints/fan-club.ts: listTiers`.
8. **Fan-club `TierOut` has no price field; price lives on the linked plan / a different `SubscriptionTierOut` schema (`price_cents`).** CORRECTED (spec sourced "price" from the tier).
   Source: `src/api/types.ts: TierOut` (no price); `src/api/types.ts: SubscriptionTierOut` (has `price_cents`, `display_order` — a distinct admin schema).
9. **Tier grouping/order is by `level`/`sort_order`, joined to channel `min_tier_level`.** CORRECTED (spec said "ordinal/rank" + `requiredTierId` join).
   Source: `src/api/types.ts: TierOut.level` / `TierOut.sort_order`, `ChannelOut.min_tier_level`.
10. **Auth: CSRF token read from the `ui_csrf` cookie and sent as the `X-CSRF-Token` header.** VERIFIED.
    Source: `src/api/client.ts` lines 168-171 (`getCookie("ui_csrf")` -> `headers.set("X-CSRF-Token", csrf)`).
11. **On 401, a single `POST /ui/session/refresh` is issued, then the request is retried once; a persisting 401 logs out.** VERIFIED.
    Source: `src/api/client.ts: refreshSession()` (line 121-130, path `/ui/session/refresh`) and the 401 handler (lines 194-237, single `refreshPromise`, one retry, `logout("session_expired")` on repeat 401).
12. **Error `detail` may be `string | [{msg}] | {code,...}`.** VERIFIED.
    Source: `src/api/client.ts: normalizeErrorDetail` (lines 66-102) and `mapAuthorizationError` (structured `code` handling, e.g. `role_required`, `geo_blocked`).
13. **Offline/network error surfaces distinctly (status 0).** VERIFIED.
    Source: `src/api/client.ts` lines 185-189 (`catch` -> `new ApiError(0, "Network error", err)`).
14. **404 = unknown creator -> non-retryable error.** UNVERIFIED-ASSUMPTION.
    The endpoint declares only 200 and 422 in OpenAPI; `creator_id` is optional so an unknown creator may return 200 with `[]` rather than 404. Treat the 404 mapping as defensive, not contract-guaranteed.
15. **Validation failures return HTTP 422 (`HTTPValidationError`).** VERIFIED.
    Source: openapi.index.txt `GET /ui/fan-club/channels | ... resp=200:;422:HTTPValidationError`.
16. **AND-239 messages path is `GET /ui/fan-club/channels/{channel_id}/messages` (params `limit`, `before`).** VERIFIED (integration seam).
    Source: openapi.index.txt line for `api_get_channel_messages_...`; `src/api/endpoints/fan-club.ts: getChannelMessages`.
17. **Consumer-facing tier-grouped sections + locked/upgrade affordance + per-user access derivation.** UNVERIFIED-ASSUMPTION (Android product decision).
    The web reference (`src/pages/fan-club/FanClubPage.tsx`) is a creator-side management screen: a flat channel grid (no tier sections), a "Tier N+" badge, no per-user lock/upgrade gating, and an inline chat view (no separate messages route). The grouped/locked consumer UX is not mirrored by the web client.
18. **`creator_id` route arg + per-creator scoping.** UNVERIFIED-ASSUMPTION.
    The query param exists, but the web client calls `listChannels()` with no `creator_id` (own-context). Scoping a fan view to another creator's `creator_id` is plausible from the param but not demonstrated by the reference.
19. **Caching via Room table `fan_club_channels` keyed by `creatorId`; cache-then-network/stale UI.** UNVERIFIED-ASSUMPTION (Android-local design; no backend/web contract governs it).
20. **Framework choices: Compose Material 3 `PullToRefreshBox`, `stickyHeader`, `collectAsStateWithLifecycle`, Hilt, Retrofit/Moshi.** Framework refs (not backend contract):
    `PullToRefreshBox` — https://developer.android.com/reference/kotlin/androidx/compose/material3/pulltorefresh/package-summary ;
    `LazyColumn`/`stickyHeader` — https://developer.android.com/develop/ui/compose/lists ;
    `collectAsStateWithLifecycle` — https://developer.android.com/topic/libraries/architecture/coroutines#lifecycle-aware .

### Corrections made

- §4.2 model: replaced `id/avatarUrl/requiredTierId/position/lastActivityAt(Instant)` with the real `ChannelOut` fields (`channel_id`, `min_tier_level: Int`, `last_message_at: Long` epoch, `message_count`, `last_message_preview`, `pinned_message_id`); `TierSection.tier` retyped to fan-club `TierOut`. (Claims 4,5,6,7)
- §4.3 + §5: response type changed from `FanClubChannelsResponseDto` `{channels:[...]}` to a bare `List<ChannelOut>`; `creator_id` marked optional; response example rewritten to real `ChannelOut` JSON; mapping notes corrected. (Claims 2,3,4,5,6)
- FR-2 / §6: grouping/ordering rewritten to join `min_tier_level` to tier `level`/`sort_order` (no `position` field; no `required_tier_id`). Access formula corrected to `activeTierLevel >= min_tier_level`. (Claims 5,9)
- FR-3 / AC-2: tier "price" no longer sourced from `TierOut` (it has none). (Claim 8)
- FR-10: removed `avatar_url` reliance (not on `ChannelOut`). (Claim 6)
- §2: web-reference filename corrected to `src/api/endpoints/fan-club.ts`/`types.ts` and the creator-vs-consumer distinction documented. (Claim 17)
- §13: OQ-1/OQ-2/OQ-3 marked RESOLVED with verified outcomes.

### Open assumptions

- **Consumer UX (tier sections, locked rows, upgrade CTA, navigation to a messages route)** is an Android product decision not present in the web client (creator-side, flat grid, inline chat). (Claim 17)
- **404-on-unknown-creator** is not contract-guaranteed; the endpoint may instead return `200 []`. (Claim 14)
- **Per-creator scoping via `creator_id`** is supported by the param but unexercised by the reference (which omits it). (Claim 18)
- **Room caching / stale-then-network** is local design with no governing backend/web contract. (Claim 19)
- **Channel avatars** have no backing field on `ChannelOut`; if shown, the source is undefined and must be resolved before relying on FR-10's avatar. (Claim 6)
- **Active subscription / tier-level lookup** comes from AND-234, which is not yet landed; the exact "active tier level" accessor is assumed and must be reconciled with AND-234's API.

## 17. Test Plan

Test-target legend: **JVM** = local JVM/Robolectric unit (no device); **MWS** =
contract test against MockWebServer; **emu test35** = headless x86_64 AVD,
API 35 (fast CI UI/instrumented); **A15** = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a) over adb. Most cases here are device-agnostic UI/logic,
so the emulator is sufficient; the physical device is only mandatory for the
ABI/API-parity smoke (TC-13).

- **TC-AND-238-01** — Repository grouping & tier ordering.
  Type: unit (JVM). Target: `FanClubRepositoryImpl`.
  Preconditions: fake `FanClubApi` returns channels with `min_tier_level` 0/1/3; fake tiers `TierOut` levels 0,1,3 with `sort_order`.
  Steps: call `getChannelsByTier("creator_1")`.
  Expected: one `TierSection` per tier, ordered ascending by `level`/`sort_order` (level-0/free section first); channels filed under the tier whose `level == min_tier_level`. Traces: AC-1.

- **TC-AND-238-02** — Within-tier channel ordering.
  Type: unit (JVM). Target: `FanClubRepositoryImpl`.
  Preconditions: multiple channels share one `min_tier_level`, unsorted names.
  Steps: invoke the join.
  Expected: channels within the section are ordered by name (or the documented `last_message_at` desc) deterministically; no `position` field is referenced. Traces: AC-1.

- **TC-AND-238-03** — Access derivation by tier level.
  Type: unit (JVM). Target: `FanClubRepositoryImpl` / access mapper.
  Preconditions: active tier level = 1; channels at `min_tier_level` 0,1,3; also a no-subscription case (level 0).
  Steps: compute `isAccessible`.
  Expected: level 0 -> accessible always; level 1 -> accessible when active>=1; level 3 -> locked at active=1; with no subscription only level-0 channels accessible. Traces: AC-3.

- **TC-AND-238-04** — Contract: 200 returns a bare array of `ChannelOut`.
  Type: contract/MockWebServer (MWS). Target: `FanClubApi.getChannels` + Moshi adapter.
  Preconditions: MWS enqueues `200` with a top-level JSON array body matching §5 (no `{channels:...}` wrapper).
  Steps: call `getChannels("creator_1")`; assert the request line is `GET /ui/fan-club/channels?creator_id=creator_1` and carries `X-CSRF-Token`.
  Expected: deserializes to `List<ChannelDto>`; `channel_id`,`min_tier_level`,`last_message_at` map correctly; absent optional fields (`description`,`last_message_preview`,`pinned_message_id`) are null. Traces: AC-1, AC-7.

- **TC-AND-238-05** — ViewModel happy path -> Content.
  Type: unit (JVM, coroutines-test + Turbine). Target: `ChannelsViewModel`.
  Preconditions: repo returns non-empty sections.
  Steps: construct VM (init load), collect `uiState`.
  Expected: `Loading` then `Content(sections=…, isRefreshing=false, isStale=false)`. Traces: AC-1, AC-7.

- **TC-AND-238-06** — ViewModel empty vs error distinction.
  Type: unit (JVM). Target: `ChannelsViewModel`.
  Preconditions: (a) repo returns zero channels; (b) repo returns `ApiResult.Failure` with empty cache.
  Steps: run each.
  Expected: (a) `Empty` (never `Error`); (b) `Error(retryable=true)`. Traces: AC-4, AC-5, AC-7.

- **TC-AND-238-07** — Failure with cached content keeps list + stale.
  Type: unit (JVM). Target: `ChannelsViewModel` + repo cache.
  Preconditions: prior successful `Content`; refresh then fails.
  Steps: `refresh()` with network failure.
  Expected: state stays `Content` with `isStale=true` and a transient error event; cached channels remain visible. Traces: AC-5, AC-6.

- **TC-AND-238-08** — 401 -> refresh -> retry success; persistent 401 terminal.
  Type: contract/MockWebServer (MWS). Target: `FanClubApi` through the shared OkHttp 401-refresh interceptor.
  Preconditions: MWS enqueues `401`, then `POST /ui/session/refresh` -> `200`, then channels `200`; a second scenario enqueues `401`, refresh `200`, channels `401` again.
  Steps: trigger the load in each scenario.
  Expected: scenario 1 succeeds with exactly one refresh + one retry; scenario 2 surfaces a terminal auth error (no re-loop), matching client.ts contract. Traces: AC-5, AC-7.

- **TC-AND-238-09** — Timeout/503 retryable; offline (status 0) handling.
  Type: contract/MockWebServer (MWS). Target: repo + `core-network` mapping.
  Preconditions: MWS returns `503` / no-response (socket timeout); plus a simulated network failure (no connectivity).
  Steps: load on an empty screen, then with cached content.
  Expected: empty screen -> retryable `Error`; with cache -> stale banner + transient error; offline maps to the network/offline error, not a generic 500. (Mirrors the dev-host flakiness path.) Traces: AC-5.

- **TC-AND-238-10** — 422 / malformed response surfaces a mapped error.
  Type: contract/MockWebServer (MWS). Target: repo error mapping.
  Preconditions: MWS returns `422` with `HTTPValidationError` (`detail: [{msg}]`), and separately a `404`.
  Steps: load.
  Expected: `detail` normalized per the `string|[{msg}]|{code}` rule into a user-facing message; 422/404 are non-retryable. (404-as-unknown-creator is treated defensively per §16 open assumption.) Traces: AC-5, AC-7.

- **TC-AND-238-11** — Compose: grouped render, loading/empty/error/retry.
  Type: Compose-UI (emu test35). Target: `FanClubChannelsScreen` / `ChannelsList`.
  Preconditions: fake VM emitting each state.
  Steps: assert `Loading` shows progress; `Content` shows sticky tier headers in order with `ChannelRow`s; `Empty` shows empty (not error) copy; `Error` shows Retry and tapping it calls `load()`; `isStale` shows the stale banner.
  Expected: all assertions pass; locked rows show a lock badge, accessible rows do not. Traces: AC-1, AC-2, AC-4, AC-5, AC-6.

- **TC-AND-238-12** — Compose: locked tap vs accessible tap (navigation/security).
  Type: Compose-UI (emu test35). Target: `ChannelRow` + event flow.
  Preconditions: one accessible and one locked channel.
  Steps: tap each.
  Expected: accessible -> `onChannelClick(channelId)` invoked with the correct `channel_id`; locked -> `ShowUpgrade` affordance shown and **no** navigation and **no** messages request (client never fetches locked content — server remains authoritative). Traces: AC-3.

- **TC-AND-238-13** — Compose: accessibility checks.
  Type: Compose-UI (emu test35). Target: headers + rows.
  Preconditions: a locked tier section.
  Steps: assert TalkBack semantics.
  Expected: tier header exposes a merged node ("Gold tier, locked"); locked row announces locked state + upgrade action; tap targets >= 48dp; decorative images have null `contentDescription`. Traces: AC-2, AC-3.

- **TC-AND-238-14** — ABI/API parity smoke on physical device.
  Type: instrumented/e2e (A15 — physical device REQUIRED).
  Target: `FanClubChannelsScreen` end-to-end against MWS or the dev host.
  Preconditions: app installed on SM-A156U (arm64-v8a, API 34).
  Rationale: emulator is x86_64/API 35; this confirms no arm64-vs-x86 / API-34-vs-35 regressions in Compose rendering, Moshi codegen, and the OkHttp stack for this screen.
  Steps: launch the screen, load channels, scroll sticky sections, tap an accessible channel.
  Expected: identical grouped render and behavior as on emu test35; no ABI/codegen crashes. Traces: AC-1, AC-7.

### Coverage matrix

| AC  | Covered by |
| --- | --- |
| AC-1 (render grouped by tier, ordered) | TC-01, TC-02, TC-04, TC-05, TC-11, TC-14 |
| AC-2 (tier header / lock) | TC-11, TC-13 |
| AC-3 (locked vs accessible; nav vs upgrade) | TC-03, TC-12, TC-13 |
| AC-4 (empty state distinct from error) | TC-06, TC-11 |
| AC-5 (error on empty; stale on cached failure) | TC-06, TC-07, TC-08, TC-09, TC-10, TC-11 |
| AC-6 (pull-to-refresh + refreshing state) | TC-07, TC-11 |
| AC-7 (unit + MWS + Compose suites green) | TC-04, TC-05, TC-06, TC-08, TC-10, TC-14 |

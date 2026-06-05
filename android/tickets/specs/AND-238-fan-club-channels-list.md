---
id: AND-238
title: Fan-club channels list
milestone: M5
epic: E32
priority: P1
size: M
status: draft
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
  `frontend/src/api/endpoints/subscriptions.ts` (tiers) and the fan-club
  endpoints file (confirm exact filename during impl); shared types in
  `frontend/src/api/types.ts`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, Room 2.6 (cache) + DataStore, Coil (avatars). minSdk 24,
  compile/target 35, JDK 17.

## 3. Functional Requirements

FR-1. **Load channels.** On entering the screen for a given creator/fan-club
(`creatorId` route arg), issue `GET /ui/fan-club/channels` (scoped to that
creator) and render the result.

FR-2. **Group by tier.** Channels are grouped into sections, one per
`SubscriptionTier`, sorted by the tier's ordinal/rank ascending (lowest tier
first; a "Free"/no-tier group, if present, sorts first). Within a tier, channels
are ordered by the backend-provided `position`/`order`, falling back to name.

FR-3. **Section headers.** Each tier section shows a sticky header with the tier
name and (if the user is not subscribed at that tier) a lock affordance plus the
tier's price/label sourced from AND-234's `SubscriptionTier`.

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
description/topic (one line, ellipsized), optional unread/last-activity hint if
provided by the backend, optional channel avatar via Coil, and the access/lock
badge. Fields absent from the response degrade gracefully.

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
data class FanClubChannel(
    val id: String,
    val name: String,
    val description: String?,
    val avatarUrl: String?,
    val requiredTierId: String?,   // null => free / all-access
    val position: Int?,            // backend ordering within a tier
    val lastActivityAt: Instant?,  // optional, may be null
)

// Joined result the UI renders, computed from channels + tiers + active sub.
data class TierSection(
    val tier: SubscriptionTier?,   // null => "Free"/no-tier group
    val channels: List<ChannelUiItem>,
)

data class ChannelUiItem(
    val channel: FanClubChannel,
    val isAccessible: Boolean,      // user's active tier rank >= required tier rank
)
```

`SubscriptionTier` is imported from AND-234; not redefined here.

### 4.3 API + Repository

```kotlin
interface FanClubApi {
    @GET("ui/fan-club/channels")
    suspend fun getChannels(
        @Query("creator_id") creatorId: String,
    ): FanClubChannelsResponseDto
}

interface FanClubRepository {
    /** Channels joined with tiers + the user's access, grouped & ordered. */
    suspend fun getChannelsByTier(creatorId: String): ApiResult<List<TierSection>>
}
```

`FanClubRepositoryImpl` calls `FanClubApi.getChannels`, maps the DTO to
`FanClubChannel`, reads tiers + the active subscription from AND-234's
`SubscriptionsRepository`, computes `isAccessible` per channel (active tier
rank >= `requiredTier` rank; null required tier => always accessible), groups by
tier, and sorts sections by tier ordinal. Network/HTTP failures are surfaced as
`ApiResult.Failure` using the shared `core-network` `detail` mapper.

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

This ticket **defines and consumes** the fan-club channels read endpoint;
subscription tier shapes are owned by AND-234. Confirm exact path/params against
`/openapi.json` and the web reference during implementation.

**Request** — `GET /ui/fan-club/channels`:

```
GET /ui/fan-club/channels?creator_id=usr_creator_123
Cookie: <session cookies>
X-CSRF-Token: <ui_csrf value>
```

**Response 200** (`FanClubChannelsResponseDto`):

```json
{
  "channels": [
    {
      "id": "chan_01HZ...",
      "name": "general",
      "description": "Open chat for everyone",
      "avatar_url": null,
      "required_tier_id": null,
      "position": 0,
      "last_activity_at": "2026-06-05T09:12:00Z"
    },
    {
      "id": "chan_02HZ...",
      "name": "gold-lounge",
      "description": "Gold-tier perks & AMAs",
      "avatar_url": "https://.../g.png",
      "required_tier_id": "tier_gold",
      "position": 0,
      "last_activity_at": "2026-06-05T08:00:00Z"
    }
  ]
}
```

DTO mapping: `channels[] -> List<FanClubChannel>`; `required_tier_id ->
requiredTierId` (null => free group); `position`/`last_activity_at` optional.
Tier name/rank/price for grouping and headers come from AND-234's
`SubscriptionTier` joined by `requiredTierId`.

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
- **Access computation:** `isAccessible = activeTier.rank >= requiredTier.rank`
  (null `requiredTier` => true; no active subscription => only null-tier channels
  accessible).
- **Keys:** `LazyColumn` items keyed by `channel.id`; section headers keyed by
  `tier?.id ?: "free"`.
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

- **OQ-1 (endpoint shape):** exact path/params for the channels list
  (`/ui/fan-club/channels` vs a creator-scoped path like
  `/ui/fan-club/{creatorId}/channels`, and `creator_id` query vs path param) must
  be confirmed against `/openapi.json` and the web reference. This spec assumes
  `GET /ui/fan-club/channels?creator_id=`.
- **OQ-2 (tier on channel):** whether the backend returns `required_tier_id`
  (assumed) or an embedded tier object. If embedded, drop the join and read tier
  fields directly; grouping logic is otherwise unchanged.
- **OQ-3 (access flag source):** whether the backend returns a per-channel
  `accessible`/`locked` flag (authoritative) or the client must derive it from the
  active subscription. Prefer the server flag if present; otherwise derive per
  §6 and treat as advisory only.
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

AC-2. Each tier section shows a header with the tier name (and price/lock for
tiers the user is not subscribed to), sourced from AND-234's `SubscriptionTier`.

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

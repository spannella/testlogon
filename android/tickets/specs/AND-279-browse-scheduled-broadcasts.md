---
id: AND-279
title: Browse / scheduled broadcasts
milestone: M6
epic: E38
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-278]
blocks: []
---

# AND-279 — Browse / scheduled broadcasts

## 1. Overview & Goal

Deliver the `feature-broadcast` browse experience for the TestLogon native Android app: a single screen that surfaces broadcast sessions across three logical buckets — **Live now**, **Upcoming / Scheduled**, and **Past / Ended** — and lets the signed-in user toggle a **remind-me** subscription on any scheduled session that has not yet started. The screen consumes the data layer introduced in AND-278 (`Broadcast API + DTOs`) via `BroadcastRepository`; this ticket owns the presentation layer: the view-state machine, list composition, bucket segmentation, and the optimistic remind-me toggle with rollback.

The acceptance bar from the backlog is concrete and binary: **lists render** (Live/Scheduled/Upcoming) and **remind-me toggles** (persist server-side, reflect in UI, survive recreation). The screen must degrade gracefully against the unreliable plaintext dev backend — offline/stale states, bounded retries on idempotent reads only, and no blind retry of the remind-me mutation.

This ticket explicitly does **not** own DTO/Retrofit/Moshi definitions or repository data access (those are AND-278), the broadcast player / live playback surface (Media3/ExoPlayer, owned by the M5 media foundation tickets AND-166–AND-172 and any later broadcast-player ticket), or push delivery of the reminder itself (FCM plumbing in AND-105–AND-110). It exposes navigation and reminder-scheduling callbacks only.

## 2. Context & References

- **Module:** `feature-broadcast` (new), layered `app -> feature-broadcast -> core-*`. Consumes `core-model`, `core-ui`, `core-data`, `core-network`, `core-testing`.
- **Package root:** `com.testlogon.android.feature.broadcast`.
- **Upstream dependency (AND-278):** provides `BroadcastRepository`, the `BroadcastSession` domain model, scheduled/upcoming/session-detail DTOs, Moshi mapping, and the Room cache. This ticket consumes that surface; the assumed contract is documented in §5.
- **Web reference (verified):** `src/api/endpoints/broadcastSchedule.ts` (scheduled/upcoming list + remind-me calls) and `src/api/endpoints/broadcast.ts` (`BroadcastSession` DTO, `BroadcastSessionStatus` enum, base `/broadcast/sessions` list). Screen behavior: `src/pages/broadcast/BroadcastSchedulePage.tsx`. **Correction:** the web reminder control is a one-shot **"Set Reminder" button** (`registerReminder` POST only, fire-and-forget toast), not a stateful toggle, and the session DTO carries **no `reminder_set` flag** — see §5 and §16. Match field names, status vocabulary, and timestamp semantics exactly.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie + `ui_csrf` / `X-CSRF-Token` auth; on 401 the network layer refreshes once via `POST /ui/session/refresh` then retries (handled in `core-network`, not here). A persistent cookie jar is required (already provided by AND-011).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single-Activity), Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Paging 3, Coil for thumbnails, `java.time` via core-library desugaring. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **State convention:** ViewModels expose `StateFlow<UiState>`; network results are typed `ApiResult<T>`; FastAPI `detail` mapped per AND-015 (`string | [{msg}] | {code,...}`).

## 3. Functional Requirements

FR-1 **Three buckets.** The screen presents broadcast sessions segmented into **Live**, **Upcoming** (scheduled, not yet started), and **Past** (ended). Segmentation is derived from the session status/timestamps (§6), not from three separate network calls unless AND-278 exposes them as distinct endpoints.

FR-2 **Bucket selection.** A Material 3 segmented control / tab row toggles the visible bucket. The selected bucket persists across configuration changes (`SavedStateHandle`) and process death. A live count badge appears on the Live tab when ≥1 session is live.

FR-3 **List rendering.** Each bucket renders a vertically scrolling list (Paging 3 where AND-278 exposes paged endpoints; otherwise a single page sorted client-side). A `BroadcastCard` shows: thumbnail (Coil), title, host display name, status pill (LIVE / SCHEDULED / ENDED), localized start time (Upcoming) or relative "started Nm ago" (Live) or "ended" timestamp (Past), and viewer count when present.

FR-4 **Sort order.** Live: by start time descending (most recently started first). Upcoming: by scheduled start ascending (soonest first). Past: by end/start descending (most recent first).

FR-5 **Remind-me toggle.** Each **Upcoming** card (and only sessions whose scheduled start is in the future) exposes a remind-me toggle control. Tapping it **optimistically** flips local state, calls the repository mutation (§5), and on failure rolls back with an inline, dismissible error. Live and Past sessions do not show the toggle (Live: already started; Past: nothing to remind). **Correction / assumption (see §16):** the backend session DTO (`BroadcastSessionOut`) carries **no `reminder_set` field**, and the web reference uses a fire-and-forget "Set Reminder" button with no read-back of reminder state. Server-authoritative reminder state is therefore **not retrievable on load** from the verified endpoints. This ticket's toggle is an Android-side enhancement: on-state is held only as client/local state for the current session (and via the DELETE `/remind-me` endpoint, which exists and is verified). Do **not** assume the list response echoes a per-user reminder flag; if AND-278 cannot source one, treat the toggle as write-only (set/clear) with optimistic local reflection, not as a server-synced switch.

FR-6 **Reminder local scheduling hook.** On a successful remind-me set, the ViewModel invokes `onReminderScheduled(session: BroadcastSession)`; on clear it invokes `onReminderCleared(sessionId)`. Actual notification delivery (FCM-driven or local-alarm fallback) is owned downstream (AND-105–AND-110); this ticket only emits the callbacks and persists the server flag.

FR-7 **Selection callback.** Tapping a card invokes `onSessionClick(sessionId: String, status: BroadcastStatus)`. Routing to the live player or session detail is owned downstream; this ticket exposes the callback only.

FR-8 **Refresh.** Pull-to-refresh and a programmatic `refresh()` re-query the repository. Live data is time-sensitive; the screen issues a foreground refresh on resume and a lightweight periodic refresh (60s) of the Live bucket while it is visible and the screen is in `RESUMED` state.

FR-9 **Loading / empty / error / offline states.** Each bucket shows skeletons while loading, a stale badge when serving cached data, an empty placeholder when the bucket has no sessions, and an inline retry on error (§7), reusing `core-ui` state composables from AND-021.

## 4. Technical Design

Module `feature-broadcast` with public entry point `BroadcastRoute` (Composable) and `BroadcastViewModel` (Hilt). Composables observe a single `StateFlow<BroadcastUiState>`; the ViewModel orchestrates the repository, derives buckets via a pure, testable `BroadcastBucketizer`, and owns optimistic toggle bookkeeping. Pure logic carries no Android dependencies so it is JVM-unit-testable.

```kotlin
package com.testlogon.android.feature.broadcast

enum class BroadcastBucket { LIVE, UPCOMING, PAST }
// CORRECTED to match web `BroadcastSessionStatus` (src/api/endpoints/broadcast.ts) and
// `BroadcastSessionOut.status` (free string). NOTE: there is NO "ended" status — ended == "stopped".
enum class BroadcastStatus { DRAFT, SCHEDULED, PROVISIONING, READY, LIVE, STOPPING, STOPPED, CANCELLED, ERROR, UNKNOWN }

sealed interface BroadcastUiState {
    data object Loading : BroadcastUiState
    data class Content(
        val selected: BroadcastBucket,
        val live: List<BroadcastItem>,
        val upcoming: List<BroadcastItem>,
        val past: List<BroadcastItem>,
        val isStale: Boolean,
        val isRefreshing: Boolean,
    ) : BroadcastUiState
    data class Error(val cause: BroadcastError, val cached: Content?) : BroadcastUiState
}

// Field names CORRECTED against BroadcastSessionOut (src/api/endpoints/broadcast.ts; openapi BroadcastSessionOut):
//   title    <- `name` (nullable; fall back to "Untitled Broadcast" per web)
//   hostName <- DERIVED from `created_by` (a user-sub string); the DTO has NO host display-name object.
//               Resolving a display name requires a separate lookup (out of scope; see §16 open assumption).
//   scheduledStart <- `scheduled_at` (epoch SECONDS integer, NOT an ISO string)
//   actualStart    <- `started_at` (ISO-8601 string)
//   endedAt        <- `stopped_at`  (ISO-8601 string); also `cancelled_at` for CANCELLED
//   viewerCount    <- NOT on the session DTO; only via separate viewer-count API (out of scope this ticket).
//   reminderSet    <- NOT server-sourced (no such field); client/local state only — see FR-5 / §16.
data class BroadcastItem(
    val sessionId: String,          // <- id
    val title: String,              // <- name ?: "Untitled Broadcast"
    val hostName: String?,          // <- derived from created_by; may be raw sub if unresolved
    val thumbnailUrl: String?,      // <- thumbnail_url
    val status: BroadcastStatus,
    val scheduledStart: Instant?,   // <- scheduled_at (epoch seconds) -> Instant.ofEpochSecond
    val actualStart: Instant?,      // <- started_at (ISO string)
    val endedAt: Instant?,          // <- stopped_at / cancelled_at (ISO string)
    val viewerCount: Int?,          // <- NOT in session DTO; null unless separately fetched
    val reminderSet: Boolean,       // <- client/local only (no server flag)
    val reminderPending: Boolean,   // mutation in-flight (UI shows progress, disables control)
)

sealed interface BroadcastError { 
    data object Network : BroadcastError
    data class Server(val message: String) : BroadcastError
    data object Auth : BroadcastError
    data object Unknown : BroadcastError
}
```

```kotlin
@HiltViewModel
class BroadcastViewModel @Inject constructor(
    private val repo: BroadcastRepository,        // from AND-278
    private val bucketizer: BroadcastBucketizer,
    private val savedState: SavedStateHandle,
    private val clock: Clock,                       // injectable for tests
) : ViewModel() {
    val uiState: StateFlow<BroadcastUiState>
    fun selectBucket(bucket: BroadcastBucket)
    fun refresh()
    fun toggleReminder(sessionId: String, enable: Boolean)
    fun retry()
    fun dismissError()
}
```

```kotlin
// Pure, no Android deps — fully unit-tested.
object BroadcastBucketizer {
    fun bucketize(
        sessions: List<BroadcastSession>,   // domain model from AND-278
        now: Instant,
    ): Triple<List<BroadcastItem>, List<BroadcastItem>, List<BroadcastItem>> // live, upcoming, past
    fun bucketOf(session: BroadcastSession, now: Instant): BroadcastBucket
}
```

Composables: `BroadcastRoute` (collects state, wires callbacks), `BroadcastScreen` (Scaffold + `SecondaryTabRow` / segmented control + pull-to-refresh), `BroadcastList` (`LazyColumn`, or `collectAsLazyPagingItems()` when paged), `BroadcastCard`, `ReminderToggle`, and reused `core-ui` `LoadingState` / `EmptyState` / `ErrorState` / `StaleBadge`. Thumbnails via Coil `AsyncImage` with a placeholder/error tint. `java.time` via core-library desugaring (required for minSdk 24); add `coreLibraryDesugaring` and the Paging-Compose dependency to `feature-broadcast/build.gradle.kts`.

Optimistic toggle: `toggleReminder` immediately copies the in-state item with `reminderSet = enable, reminderPending = true`, launches the mutation in `viewModelScope`, and on success sets `reminderPending = false` (keeping `reminderSet`), or on failure reverts `reminderSet` to its prior value, clears `reminderPending`, and surfaces a transient error. The mutation is **not** auto-retried (non-idempotent write).

## 5. API Contract

This ticket performs **no direct HTTP**. All network access is owned by **AND-278**, consumed through `BroadcastRepository`. The assumed AND-278 repository surface (confirm field names against `/openapi.json` and `frontend/src/api/endpoints/*.ts` before build):

```kotlin
interface BroadcastRepository {
    // Idempotent GET: bounded backoff retry + cache (per project policy, in core-network/AND-278).
    fun sessions(): Flow<ApiResult<CachedList<BroadcastSession>>>

    // Non-idempotent writes: NO auto-retry. Carry X-CSRF-Token via core-network.
    // CORRECTED: POST /remind-me returns {ok, remind_at}, NOT a session. DELETE returns {ok}.
    suspend fun setReminder(sessionId: String): ApiResult<ReminderResult>   // {ok: Boolean, remindAt: Long}
    suspend fun clearReminder(sessionId: String): ApiResult<Unit>          // server returns {ok}
}
```

Underlying endpoints — **CORRECTED against OpenAPI index + `src/api/endpoints/`** (reference only; owned by AND-278):

```
# Base list (all statuses; optional status filter, single value per OpenAPI `status` query param):
GET    /broadcast/sessions?status=<status>          -> BroadcastSessionListOut { items[], has_more }
# Scheduled-only families used by the web Schedule page:
GET    /broadcast/sessions/scheduled?limit=<n>       -> BroadcastScheduledListOut { items[], count }
GET    /broadcast/sessions/upcoming?limit=<n>        -> BroadcastScheduledListOut { items[], count }
# Reminder (path is /remind-me, NOT /reminder):
POST   /broadcast/sessions/{session_id}/remind-me    -> 200 (untyped; web types it {ok, remind_at})
DELETE /broadcast/sessions/{session_id}/remind-me    -> 200 (untyped; web types it {ok})
```

CORRECTIONS vs. the original draft: path was `/reminder` (wrong) → `/remind-me`; the list wrapper key was `sessions`/`next_cursor` (wrong) → `items`/`has_more` (base) or `items`/`count` (scheduled/upcoming); no cursor pagination is exposed (only a `limit` param + `has_more`). There is no combined `status=scheduled,live,ended` multi-value query — the OpenAPI `status` param is a single optional value; for a 3-bucket Live/Upcoming/Past view, fetch the base list (optionally per-status) and bucketize client-side, OR consume `/scheduled` + `/upcoming` for scheduled buckets. The web Schedule page only renders two scheduled buckets ("My Schedule" via `/scheduled`, "Upcoming" via `/upcoming`); the Android Live/Past buckets are a port-specific design and must be derived from `status`/timestamps.

Actual session object shape — **CORRECTED** (`BroadcastSessionOut`; epoch fields are integer seconds, ISO fields are strings):

```json
{
  "id": "bcs_01H...",
  "name": "Friday AMA",
  "description": "...",
  "status": "scheduled",
  "schedule_status": null,
  "scheduled_at": 1749232800,
  "started_at": null,
  "stopped_at": null,
  "cancelled_at": null,
  "thumbnail_url": "https://.../thumb.jpg",
  "created_by": "u_123",
  "created_at": "2026-06-05T12:00:00Z",
  "profile_id": "prof_..."
}
```

Notes on the shape (all verified): there is **no** `title` (use `name`), **no** `host` object (only `created_by`, a user-sub string), **no** `viewer_count` on the session, **no** `reminder_set`, **no** `actual_start`/`ended_at` (use `started_at`/`stopped_at`). `status` is a free string; the valid vocabulary is `draft | scheduled | provisioning | ready | live | stopping | stopped | cancelled | error` — note **`stopped`, not `ended`**.

Reminder responses — **CORRECTED** (neither echoes a session):

```json
// POST /remind-me (registers at T-30m before broadcast, per OpenAPI description):
{ "ok": true, "remind_at": 1749231000 }
// DELETE /remind-me:
{ "ok": true }
```

Error envelope: FastAPI `detail` mapped by `core-network`/AND-015 to `ApiResult.Failure` (`detail` may be `string | [{msg}] | {code,...}`). The reminder + list endpoints' only declared error response is **422 `HTTPValidationError`** (verified in OpenAPI); there is **no documented 409/410** on `/remind-me` — the original draft's "409/410 on reminder set" is an unverified assumption (kept as defensive handling, but flagged in §16). 401 triggers one `POST /ui/session/refresh` + retry inside `core-network` (verified in `src/api/client.ts`). This ticket maps `ApiResult.Failure` → `BroadcastError` for the UI; any non-2xx on reminder set is treated as a non-retryable `Server`/`Network` error and triggers optimistic rollback.

## 6. Data & State Management

- **Single source of truth:** `BroadcastViewModel.uiState: StateFlow<BroadcastUiState>`, started `WhileSubscribed(5_000)`.
- **Bucketization (client-side) — CORRECTED to actual field/status names** (`started_at`/`stopped_at`/`scheduled_at`; status `stopped` not `ended`): `status == "live"` (or `started_at != null && stopped_at == null && cancelled_at == null`) → **Live**; `status == "scheduled" && (scheduled_at epoch) > now && stopped_at == null && cancelled_at == null` → **Upcoming**; `stopped_at != null || cancelled_at != null || status in {stopped, cancelled, error}` → **Past**. The pre-go-live statuses `provisioning`/`ready` (broadcast spinning up) should bucket as **Upcoming** unless `started_at != null`. `scheduled_at` is epoch **seconds** → convert via `Instant.ofEpochSecond`. `now` comes from the injected `Clock` for deterministic tests. The verified server endpoints `/broadcast/sessions/scheduled` and `/broadcast/sessions/upcoming` return only scheduled sessions; if AND-278 surfaces them, prefer them for the Upcoming bucket and bucketize the base `/broadcast/sessions` list for Live/Past.
- **Reactive query:** `repo.sessions()` collected with `flatMapLatest`/`stateIn`; re-bucketized on each emission. `refresh()` triggers a repository re-fetch; cache-hit renders immediately with `isStale = true` while the network refresh runs.
- **Live auto-refresh:** while the Live tab is selected and lifecycle is `RESUMED`, a `flow { while (true) { emit(Unit); delay(60_000) } }` keyed to the lifecycle scope triggers `refresh()`; cancelled on pause/tab-change to respect the unreliable backend.
- **Optimistic toggle bookkeeping:** the ViewModel holds a transient `Map<sessionId, priorReminderState>` to support rollback; cleared on success. Toggles applied to the in-state `Content` lists (all three buckets) so the item stays consistent if the user switches tabs mid-flight.
- **Persisted UI state:** `selected` bucket persisted via `SavedStateHandle` (`key = broadcast_bucket`). No new at-rest storage is added beyond AND-278's existing Room cache. **Correction:** `reminder_set` is NOT a server field (verified — see §5/§16), so reminder on-state cannot be re-read on refresh from the verified endpoints; treat it as ephemeral client/local state for the session. If durable reminder state is required, it must be tracked locally (e.g., a local set of `sessionId`s that the user reminded) — an open assumption pending AND-278.
- **De-duplication & sort:** items keyed by `sessionId`; per-bucket sort applied after bucketization per FR-4.

## 7. Error Handling & Resilience

- **Timeouts/retries (reads):** owned by `core-network`/AND-278 (≈20s timeout, bounded exponential backoff for idempotent GETs only). This screen never blind-retries; it surfaces a manual `retry()` and pull-to-refresh.
- **Reminder mutation (writes):** **no auto-retry** (non-idempotent). On failure: optimistic rollback + transient inline error ("Couldn't update reminder — tap to retry"), where retry is an explicit user action, not automatic.
- **`BroadcastError` taxonomy:** `Network` (offline/timeout), `Server` (5xx / 422 mapped `detail`; the only documented non-auth error for these endpoints is **422 HTTPValidationError** — 409/410 are NOT documented, treated defensively), `Auth` (terminal 401 after refresh), `Unknown`.
- **Stale-while-error:** `BroadcastUiState.Error(cause, cached)` retains the last good `Content` so lists stay populated with a dismissible banner + Retry, rather than blanking.
- **Empty vs error:** an empty successful fetch shows the per-bucket empty placeholder, never the error UI.
- **Offline:** when the connectivity/health probe (AND-017) reports offline, the screen shows cached content with an offline badge and disables the reminder toggle (queueing reminders offline is out of scope for M6; see §13 OQ).
- **Clock skew / boundary:** sessions exactly at `now` are treated as Live if `started_at != null`, else Upcoming; guards against `DateTimeException` on null/garbage timestamps (note `scheduled_at` is epoch seconds; `started_at`/`stopped_at` are ISO strings) by treating unparseable sessions as Past and logging at WARN.

## 8. Security & Privacy

- No new endpoints or credential handling. Auth rides existing cookie + `ui_csrf` / `X-CSRF-Token` plumbing in `core-network` (AND-011/AND-012/AND-013); the reminder POST/DELETE are state-changing writes and **must** carry the CSRF header (already injected by the CSRF interceptor).
- The dev backend is plaintext HTTP; cleartext is permitted only for the dev host via the existing network-security config owned by `core-network`. No broadcast or host PII is logged (see §10).
- Thumbnails loaded over the configured host only; Coil uses the shared OkHttp client so cookies/CSRF and cleartext policy are consistent. No thumbnail caching to external storage.
- No new at-rest storage; reminder state is server-authoritative. No analytics payload includes host or session titles.

## 9. Accessibility & i18n

- All interactive elements (bucket tabs, cards, remind-me toggle, retry, pull-to-refresh) carry `contentDescription` / semantics. The reminder toggle exposes a `Role.Switch` with on/off state and announces "Remind me for {title}". Cards announce title + host + status + localized start/relative time.
- Touch targets ≥ 48dp; the toggle and overflow controls meet the minimum independent of card density.
- Status pills convey status via text/icon, not color alone (color-blind safe); LIVE pill includes an "LIVE" label.
- TalkBack reading order: top bar → bucket tabs → list in sort order. Live count badge announced as part of the Live tab.
- i18n: all strings in `strings.xml`; dates/times via `DateTimeFormatter.ofLocalizedDateTime` / relative time via `java.time` with `Locale.getDefault()`; no hardcoded date formats. RTL mirroring for tab order, card layout, and chevrons. Pluralized counts ("1 viewer" / "N viewers") via `plurals`.

## 10. Telemetry & Logging

- Analytics via the `core-data` analytics facade: `broadcast_list_shown {bucket}`, `broadcast_bucket_switched {from, to}`, `broadcast_session_opened {status}`, `broadcast_reminder_set {result}`, `broadcast_reminder_cleared {result}`, `broadcast_refresh {trigger: manual|resume|live_poll}`, `broadcast_load_error {error_type}`.
- Logging via the shared logger: DEBUG for bucketization and load-state transitions; INFO for bucket switches and reminder results. **Never** log session titles, host identity, thumbnail URLs, or full payloads. Error logs include `BroadcastError` type and HTTP status only.
- Performance: log Live-bucket first-frame and list first-page render durations under a `broadcast_perf` tag for triage; log live-poll cycle outcomes at DEBUG.

## 11. Testing Strategy

**Unit (JVM, core-testing + Turbine):**
- `BroadcastBucketizer.bucketOf` for each status/timestamp permutation: scheduled-future → Upcoming; live (`started_at` set, `stopped_at` null) → Live; stopped/cancelled/error → Past; boundary at `now`; unparseable/null timestamps → Past + WARN. Uses fixed `Clock`/`Instant`. (Field names corrected to `started_at`/`stopped_at`; status `stopped` not `ended`.)
- Per-bucket sort order (FR-4) on a mixed dataset.
- `BroadcastViewModel`: state transitions Loading → Content → Error(cached); stale badge on cache hit; bucket selection persists via `SavedStateHandle`; live-poll triggers refresh only while Live tab selected.
- **Remind-me (critical for acceptance):** `toggleReminder(enable=true)` optimistically flips `reminderSet`/`reminderPending`, success clears pending; failure rolls back to prior state and emits a transient error; mutation is invoked exactly once (no auto-retry); 409/410 rolls back and refreshes.

**Instrumented (Compose UI, AndroidJUnit4 + Hilt test + fake `BroadcastRepository`):**
- Seeded sessions render in the correct bucket lists (the literal acceptance: "lists render"), asserted via `contentDescription`/semantics.
- Switching tabs shows the correct list; selection persists across recreation.
- **Remind-me toggle (the literal acceptance: "remind-me toggles"):** tapping the switch flips its semantics state, calls the fake mutation, and reflects the result; a failing fake mutation rolls the switch back and shows the inline error with a working retry.
- Live/Past cards do not render the reminder toggle.
- Loading skeletons, stale badge, empty placeholder, and error banner with working Retry.
- Pull-to-refresh re-queries; offline state disables the toggle.
- Accessibility: semantics assertions for switch role/state, tab labels, and 48dp targets.

**Test infra:** `FakeBroadcastRepository` in `core-testing` mirroring the §5 contract (configurable per-call success/failure, latency). MockWebServer harness (AND-046) reused if integration-level repo tests are desired.

## 12. Dependencies & Sequencing

- **Hard upstream:** **AND-278** (Broadcast API + DTOs) — must land first; provides `BroadcastRepository`, `BroadcastSession`, scheduled/upcoming/detail DTOs, Moshi mapping, and Room cache. Until merged, develop against a `FakeBroadcastRepository` in `core-testing` mirroring §5.
- **Transitive:** AND-027 (session endpoints) / AND-011–AND-015 (cookie jar, CSRF, 401 refresh, error mapping) via core-network; AND-017 (connectivity/health probe); AND-018 (`ApiResult`); AND-021 (state composables); AND-022 (nav host); `core-ui` Material 3 tokens (AND-019); `core-data` analytics + DataStore.
- **Soft downstream (not blocking this ticket):** broadcast live-player / session-detail screen consumes `onSessionClick`; FCM/local reminder delivery (AND-105–AND-110) consumes `onReminderScheduled` / `onReminderCleared`. Per backlog, AND-279 has no declared `blocks`.
- **Build:** add core-library desugaring (`java.time` on minSdk 24), Paging-Compose (if AND-278 exposes paged endpoints), and Coil to `feature-broadcast/build.gradle.kts`.
- **Sequencing:** (1) module scaffold + DI wiring, (2) `BroadcastBucketizer` + unit tests, (3) ViewModel + state + optimistic toggle, (4) list + card UI + tabs, (5) remind-me toggle + rollback, (6) refresh / live-poll, (7) loading/empty/error/offline states, (8) instrumented tests.

## 13. Risks & Open Questions

- **R1 (bucketing source):** §6 assumes client-side bucketization from status/timestamps. If AND-278 exposes distinct scheduled/upcoming/live endpoints, prefer those and reduce client logic. **OQ:** confirm endpoint shape against `/openapi.json` and `frontend/src/api/endpoints/*.ts`.
- **R2 (reminder semantics) — RESOLVED via review:** verified there is **no `reminder_set` flag** on the session DTO and the web reference uses a fire-and-forget POST `/remind-me` button (registers at T-30m server-side) with no read-back. The DELETE `/remind-me` endpoint exists, so a toggle is implementable, but on-load reminder state is not retrievable from the verified endpoints. Treat the toggle as write-only with optimistic local reflection (see §5/§16). Open: whether AND-278 will expose a derived/local reminder flag.
- **R3 (status vocabulary) — RESOLVED via review:** verified enum is `draft | scheduled | provisioning | ready | live | stopping | stopped | cancelled | error` (`src/api/endpoints/broadcast.ts`; `BroadcastSessionOut.status` is a free string). There is **no `ended`** — ended == `stopped`. Bucketization updated accordingly (§6).
- **R4 (live freshness vs. flaky host):** 60s live-poll against an unreliable dev backend may produce frequent transient errors; mitigation is stale-while-error + manual refresh, and poll suppression on repeated failures. **OQ:** is SSE/real-time (AND-143) the intended source for live status, deferring polling?
- **R5 (offline reminder queueing):** spec disables the toggle offline rather than queueing. **OQ:** does product require offline-queued reminders in M6? Deferred unless confirmed.
- **R6 (delivery ownership):** actual reminder notification delivery is out of scope (callbacks only). If no downstream consumer exists at ship time, remind-me sets the server flag but no device notification fires — acceptable for this ticket's acceptance ("toggles"), flagged for product.

## 14. Acceptance Criteria

AC-1 **Lists render** (source-ticket acceptance): for a seeded dataset, Live, Upcoming/Scheduled, and Past sessions appear in their correct bucket lists, in the specified sort order, asserted via Compose semantics in instrumented tests.

AC-2 Bucket tabs switch the visible list; the selected bucket persists across rotation and process death.

AC-3 **Remind-me toggles** (source-ticket acceptance): toggling the switch on an Upcoming card optimistically flips state, calls the repository mutation exactly once (POST/DELETE `/broadcast/sessions/{id}/remind-me`), and reflects the mutation result — verified by unit and instrumented tests. **Note (corrected):** because the backend exposes no `reminder_set` flag, "persists across refresh" is satisfied by locally tracked reminder state, not by a server-echoed flag; if AND-278 provides no local persistence, on-state is ephemeral for the session (see §5/§16).

AC-4 On a failing reminder mutation, the toggle rolls back to its prior state and a dismissible inline error with a working manual Retry is shown; no automatic retry occurs.

AC-5 The reminder toggle appears only on Upcoming sessions with a future start; Live and Past cards never show it.

AC-6 Loading shows skeletons; cache hits show content with a stale badge; failures show a dismissible error banner preserving last-good content; empty buckets show the empty placeholder; offline shows cached content with an offline badge and a disabled toggle.

AC-7 Live bucket auto-refreshes on a 60s cadence only while selected and resumed, and refreshes on resume and pull-to-refresh.

AC-8 No session/host PII appears in logs; the toggle exposes a switch role with correct on/off state; all interactive elements meet the 48dp target; status is conveyed by text/icon, not color alone.

## 15. Definition of Done

- `feature-broadcast` module created under `com.testlogon.android.feature.broadcast`, wired into the app via Navigation-Compose and Hilt; builds on the `android-port` branch with AGP 8.7.3 / Gradle 8.9 / JDK 17.
- All FRs and ACs implemented; `BroadcastBucketizer`, ViewModel (incl. optimistic remind-me with rollback), tabs, list/card UI, and all four states complete.
- Unit + instrumented tests pass in CI; bucketization, sort, and remind-me success/failure/rollback cases explicitly covered and green.
- Lint and detekt clean; no hardcoded strings/date formats; core-library desugaring enabled.
- `onSessionClick(sessionId, status)`, `onReminderScheduled(session)`, and `onReminderCleared(sessionId)` callbacks exposed and documented for downstream consumers; no live-player or notification-delivery logic included here.
- Telemetry events emitted; no PII logged; accessibility semantics (switch role/state, tab labels, 48dp) verified by test.
- Reminder mutation carries `X-CSRF-Token` and is never auto-retried; reads use the shared bounded-backoff GET policy from core-network/AND-278.
- Code reviewed and merged; spec status moved from `draft` to `accepted` once AC-1–AC-8 are demonstrated.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Reminder endpoint paths are `POST`/`DELETE /broadcast/sessions/{session_id}/remind-me`.** VERDICT: **Corrected** (draft said `/reminder`). SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/remind-me` and `DELETE /broadcast/sessions/{session_id}/remind-me`; `src/api/endpoints/broadcastSchedule.ts: registerReminder / cancelReminder`.
2. **POST `/remind-me` returns `{ ok, remind_at }`; DELETE returns `{ ok }` — neither echoes a session.** VERDICT: **Corrected** (draft said the set call echoes the updated session). SOURCE: `src/api/endpoints/broadcastSchedule.ts: ReminderResponse` and `cancelReminder`; OpenAPI both responses are untyped `{}` (200). The "register at T-30m before the broadcast" semantics: OpenAPI description on `register_reminder_route...remind_me_post`.
3. **The session DTO has no `reminder_set` field; reminder on-state is not retrievable on load.** VERDICT: **Corrected / Unverified-assumption** (draft claimed the toggle reflects a server `reminder_set` flag). SOURCE: `src/api/endpoints/broadcast.ts: BroadcastSession` (no such field); OpenAPI `components.schemas.BroadcastSessionOut` (no `reminder_set`); grep of `openapi.pretty.json` for `reminder_set` returns no schema field.
4. **The web reminder control is a fire-and-forget "Set Reminder" button, not a stateful toggle, and DELETE is not invoked from the schedule page.** VERDICT: **Verified** (informs the FR-5 correction). SOURCE: `src/pages/broadcast/BroadcastSchedulePage.tsx: ScheduledCard` (`registerReminder` via `remindMut`, toast on success/error; no read-back, no cancel).
5. **List response wrappers: base `/broadcast/sessions` → `{ items, has_more }`; `/scheduled` and `/upcoming` → `{ items, count }`.** VERDICT: **Corrected** (draft said `{ sessions, next_cursor }`). SOURCE: OpenAPI `components.schemas.BroadcastSessionListOut` (`items`, `has_more`) and `BroadcastScheduledListOut` (`items`, `count`); `src/api/endpoints/broadcast.ts: SessionListResponse`, `src/api/endpoints/broadcastSchedule.ts: ScheduledListResponse`.
6. **No cursor pagination; only a `limit` query param (+ `has_more`).** VERDICT: **Corrected** (draft modeled `next_cursor`). SOURCE: OpenAPI `GET /broadcast/sessions/scheduled|upcoming` params=`limit`; `BroadcastSessionListOut.has_more`.
7. **`/broadcast/sessions` `status` query param is a single optional value (no `status=scheduled,live,ended` multi-value).** VERDICT: **Corrected**. SOURCE: OpenAPI `GET /broadcast/sessions` params=`status` (single); `src/api/endpoints/broadcast.ts: listSessions(params?: { status?: string })`.
8. **Distinct `GET /broadcast/sessions/scheduled` and `GET /broadcast/sessions/upcoming` endpoints exist (both scheduled-only, returning `BroadcastScheduledListOut`).** VERDICT: **Verified** (resolves R1). SOURCE: OpenAPI `list_scheduled_sessions_route...` and `list_upcoming_sessions_route...`; `src/api/endpoints/broadcastSchedule.ts: listScheduledSessions / listUpcomingSessions`.
9. **Status enum = `draft | scheduled | provisioning | ready | live | stopping | stopped | cancelled | error`; there is NO `ended`.** VERDICT: **Corrected** (draft used `LIVE/SCHEDULED/ENDED/CANCELLED`). SOURCE: `src/api/endpoints/broadcast.ts: BroadcastSessionStatus`; OpenAPI `BroadcastSessionOut.status` is a free `string`.
10. **Session field names: `name` (not `title`), `created_by` string (no `host` object), `scheduled_at` epoch-seconds integer (not ISO `scheduled_start`), `started_at`/`stopped_at`/`cancelled_at` ISO strings (not `actual_start`/`ended_at`), no `viewer_count` on the session.** VERDICT: **Corrected**. SOURCE: OpenAPI `components.schemas.BroadcastSessionOut`; `src/api/endpoints/broadcast.ts: BroadcastSession`; epoch-seconds handling in `src/pages/broadcast/BroadcastSchedulePage.tsx: formatWhen` (`new Date(ts * 1000)`) and `BroadcastScheduleCountdown.tsx` (`scheduledAt - Math.floor(Date.now()/1000)`).
11. **Viewer count is served by a separate API, not the session DTO.** VERDICT: **Verified** (informs §4 correction). SOURCE: `src/api/endpoints/broadcast.ts: getViewerCount / ViewerCountResponse` (`GET /broadcast/sessions/{sessionId}/viewers/count`).
12. **Auth/CSRF: cookie session + `ui_csrf` cookie copied to `X-CSRF-Token` header; one 401 refresh via `POST /ui/session/refresh` then retry.** VERDICT: **Verified**. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `refreshSession()` → `fetch(withApiBase("/ui/session/refresh"))`; single-flight `refreshPromise` on 401). Android needs a persistent cookie jar (browser uses `document.cookie`).
13. **Only documented error response for list + remind-me endpoints is `422 HTTPValidationError`; no `409`/`410`.** VERDICT: **Corrected** (draft asserted 409/410 on reminder set). SOURCE: OpenAPI `responses` on `GET /broadcast/sessions*`, `POST`/`DELETE .../remind-me` (each `200` + `422:HTTPValidationError`). 409/410 retained only as defensive client handling.
14. **60s live/upcoming refresh cadence.** VERDICT: **Verified** (web applies it to the Upcoming query; Android applies it to the Live bucket — a port choice). SOURCE: `src/pages/broadcast/BroadcastSchedulePage.tsx` (`upcomingQuery ... refetchInterval: 60_000`).
15. **OpenAPI endpoints also accept `user_sub` (query) and `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` (headers).** VERDICT: **Verified** (not set by the browser client; `core-network` should default these or rely on cookie auth). SOURCE: OpenAPI params on the `/broadcast/sessions*` and `/remind-me` operations; absent from `src/api/client.ts`.
16. **Android stack/framework choices (Compose Material 3 `SecondaryTabRow`, Paging 3, Coil, core-library desugaring for `java.time` on minSdk 24, `Role.Switch` semantics, 48dp touch targets).** VERDICT: **Unverified-assumption (framework ref)** — not derivable from backend/frontend sources; standard Android guidance. SOURCE (framework ref): developer.android.com/jetpack/compose/components/tab-row; developer.android.com/topic/libraries/architecture/paging/v3-overview; developer.android.com/studio/write/java8-support#library-desugaring; developer.android.com/develop/ui/compose/accessibility; m3.material.io accessibility (min 48dp).

### Corrections made
- Reminder path `/reminder` → `/remind-me` (POST + DELETE). [§5]
- Reminder responses corrected: POST → `{ ok, remind_at }`, DELETE → `{ ok }`; neither returns a session. [§5]
- Removed reliance on a server `reminder_set` flag (does not exist); toggle reframed as write-only with optimistic local state. [§3 FR-5, §4, §5, §6, AC-3, R2]
- List wrappers corrected: `{ sessions, next_cursor }` → `{ items, has_more }` (base) / `{ items, count }` (scheduled/upcoming); no cursor pagination, only `limit`. [§5]
- `status` query is single-value, not `scheduled,live,ended`. [§5]
- Status enum corrected to the real 9 values; `ended` → `stopped`. [§4, §6, §11, R3]
- Session field renames: `title`→`name`, host object → `created_by`, `scheduled_start`(ISO)→`scheduled_at`(epoch seconds), `actual_start`/`ended_at`→`started_at`/`stopped_at` (+`cancelled_at`); `viewer_count` not on session. [§4, §5, §6, §7, §11]
- Error model corrected: documented errors are 422 only; 409/410 demoted to defensive-only. [§5, §7]

### Open assumptions
- **Durable/server reminder state.** No endpoint returns per-user reminder state; "persists across refresh" (AC-3) can only be met by local persistence. Whether AND-278 provides it is unconfirmed. Why unverifiable: no such field/endpoint in OpenAPI or frontend.
- **Host display name.** The DTO exposes only `created_by` (user sub); rendering a human host name needs a separate user lookup not covered by these sources. Why unverifiable: no host object in `BroadcastSessionOut`.
- **Three-bucket Live/Upcoming/Past model.** The web app shows only two scheduled buckets; Live/Past is an Android-port design requiring client bucketization of the base list. Why unverifiable: not present in the web reference.
- **AND-278 repository surface** (`BroadcastRepository`, `BroadcastSession` domain model, Room cache, paging). Why unverifiable: AND-278 is an upstream Android ticket, not represented in backend/frontend sources.
- **Android framework/library choices** (item 16). Why unverifiable: design decisions, not contract facts; cited as framework refs.
- **`X-CSRF-Token` on the reminder writes via Android `core-network`.** The header name + cookie source are verified from `client.ts`; that the Android CSRF interceptor injects it on these specific calls is an integration assumption owned by AND-011–AND-013.

## 17. Test Plan

Test-target legend: JVM = JVM unit/Robolectric (local, no device); EMU = headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). MockWebServer (MWS) cases run on JVM/EMU. Traces link to §14 Acceptance Criteria.

- **TC-AND-279-01** — Type: unit (JVM). Target: JVM. Precondition: fixed `Clock`; dataset with one session per status across `scheduled`(future `scheduled_at`), `live`(`started_at` set, `stopped_at` null), `stopped`, `cancelled`, `provisioning`/`ready`, plus a future `scheduled` exactly at `now+1`. Steps: call `BroadcastBucketizer.bucketize(sessions, now)`. Expected: scheduled-future + provisioning/ready(no `started_at`) → Upcoming; live → Live; stopped/cancelled/error → Past; `scheduled_at` parsed as epoch seconds. Traces: AC-1, AC-5.
- **TC-AND-279-02** — Type: unit (JVM). Target: JVM. Precondition: boundary + malformed dataset: session at exactly `now` with/without `started_at`; null `scheduled_at`; garbage timestamp string in `started_at`. Steps: bucketize. Expected: at-`now` with `started_at` → Live else Upcoming; unparseable/null → Past with a WARN log; no exception thrown. Traces: AC-1.
- **TC-AND-279-03** — Type: unit (JVM). Target: JVM. Precondition: mixed dataset in each bucket. Steps: apply per-bucket sort. Expected: Live by start desc, Upcoming by `scheduled_at` asc, Past by end/start desc (FR-4). Traces: AC-1.
- **TC-AND-279-04** — Type: unit (JVM, Turbine + fake repo). Target: JVM. Precondition: fake repo emits cache hit then network success. Steps: collect `uiState`. Expected: `Loading → Content(isStale=true on cache) → Content(isStale=false)`; selected-bucket survives via `SavedStateHandle`. Traces: AC-2, AC-6.
- **TC-AND-279-05** — Type: unit (JVM, Turbine). Target: JVM. Precondition: fake repo `setReminder` succeeds. Steps: `toggleReminder(id, true)`. Expected: item immediately `reminderSet=true, reminderPending=true`; on success `reminderPending=false`, `reminderSet=true`; `setReminder` called **exactly once** (no auto-retry); applied across all bucket lists. Traces: AC-3.
- **TC-AND-279-06** — Type: unit (JVM, Turbine). Target: JVM. Precondition: fake repo `setReminder` fails (mapped Failure). Steps: `toggleReminder(id, true)`. Expected: optimistic flip, then rollback to prior `reminderSet=false`, `reminderPending=false`, transient `BroadcastError` surfaced; **no** automatic retry. Traces: AC-4.
- **TC-AND-279-07** — Type: contract/MockWebServer. Target: JVM/EMU. Precondition: MWS serves `GET /broadcast/sessions/scheduled` → `{ "items": [ {BroadcastSessionOut...} ], "count": 1 }` and `/upcoming` likewise; `POST /broadcast/sessions/{id}/remind-me` → `{ "ok": true, "remind_at": 1749231000 }`; `DELETE` → `{ "ok": true }`. Steps: drive repository/ViewModel against MWS. Expected: real wire shapes (`items`/`count`, `name`, `scheduled_at` epoch seconds, `created_by`) deserialize; reminder set/clear parse `ok`/`remind_at`; request path is `/remind-me`; `X-CSRF-Token` header present on POST/DELETE. Traces: AC-1, AC-3, AC-8.
- **TC-AND-279-08** — Type: contract/MockWebServer. Target: JVM/EMU. Precondition: MWS returns `422` with FastAPI `detail` (`string`, `[{msg}]`, and `{code}`) variants on list and on `remind-me`. Steps: invoke read + reminder mutation. Expected: each `detail` shape maps to `BroadcastError.Server` with a usable message (per AND-015); list 422 → error banner preserving last-good content; reminder 422 → rollback + inline error. Traces: AC-4, AC-6.
- **TC-AND-279-09** — Type: contract/MockWebServer. Target: JVM/EMU. Precondition: MWS first returns `401`, then `POST /ui/session/refresh` succeeds, then the retried list returns `200`. Steps: trigger a list load. Expected: exactly one refresh, then a successful retry renders content; a terminal 401 (refresh also 401) maps to `BroadcastError.Auth`. Traces: AC-6, AC-8.
- **TC-AND-279-10** — Type: Compose-UI (instrumented, Hilt + fake repo). Target: EMU. Precondition: seeded sessions across all three buckets. Steps: launch `BroadcastRoute`; assert via semantics; switch tabs; rotate + simulate process death; verify selected bucket restored. Expected: correct lists render in sort order ("lists render"); selection persists. Traces: AC-1, AC-2.
- **TC-AND-279-11** — Type: Compose-UI (instrumented). Target: EMU. Precondition: one Upcoming session; fake `setReminder` success then a failing variant. Steps: tap the reminder switch (success path); reset; tap with failing fake. Expected: switch flips and reflects success ("remind-me toggles"); on failure it rolls back and shows a dismissible inline error with a working manual Retry; no auto-retry. Traces: AC-3, AC-4.
- **TC-AND-279-12** — Type: Compose-UI (instrumented). Target: EMU. Precondition: one Live, one Past, one Upcoming card. Steps: inspect each card. Expected: reminder toggle present only on Upcoming-with-future-start; absent on Live and Past. Traces: AC-5.
- **TC-AND-279-13** — Type: Compose-UI (instrumented). Target: EMU. Precondition: fake repo configurable for loading/cache/empty/error and an offline-probe stub (AND-017). Steps: exercise loading (skeletons), cache hit (stale badge), empty bucket (placeholder), error (dismissible banner + Retry preserving content), offline (cached content + offline badge + disabled toggle). Expected: each state renders as specified. Traces: AC-6.
- **TC-AND-279-14** — Type: Compose-UI / accessibility (instrumented). Target: EMU. Precondition: seeded buckets with one Upcoming card. Steps: assert reminder control exposes `Role.Switch` with on/off state and "Remind me for {title}"; tabs labelled with Live count badge announced; all interactive targets ≥ 48dp; status conveyed by text/icon (LIVE label), not color alone; TalkBack order top bar → tabs → list. Expected: all assertions pass. Traces: AC-8.
- **TC-AND-279-15** — Type: integration/instrumented (flaky-host + live-poll). Target: EMU (logic) then DEV (real-network confirmation). Precondition: MWS/toxiproxy injecting timeouts + intermittent 5xx on the Live list while Live tab selected and RESUMED. Steps: select Live tab, leave resumed; induce transient failures; switch tab / move to paused. Expected: 60s poll fires only while Live tab selected AND resumed; transient errors keep last-good content (stale-while-error) without blanking; polling cancels on pause/tab-change; repeated failures suppress polling. Traces: AC-6, AC-7. MUST also be sanity-checked on **DEV** (physical device) against the real plaintext dev host to confirm real-network timeout/offline behavior and arm64/API-34 parity vs. the API-35 emulator.
- **TC-AND-279-16** — Type: instrumented/security (CSRF + cleartext + PII). Target: EMU (assertions) + DEV (real cleartext path). Precondition: capture outbound requests (MWS interceptor) and Logcat. Steps: perform reminder set/clear and a list load; inspect headers, scheme, and logs. Expected: `X-CSRF-Token` present on POST/DELETE `/remind-me`; cleartext HTTP permitted only for the dev host (network-security-config); logs contain no session title/name, host/`created_by`, thumbnail URL, or full payloads (only `BroadcastError` type + HTTP status). Traces: AC-8. The real-cleartext leg MUST run on **DEV** against the actual dev host to validate the production-like network-security policy on API 34.

### Coverage matrix
- **AC-1 (lists render in correct buckets + sort):** TC-01, TC-02, TC-03, TC-07, TC-10.
- **AC-2 (tabs switch; selection persists across rotation + process death):** TC-04, TC-10.
- **AC-3 (remind-me toggles; mutation once; reflects result):** TC-05, TC-07, TC-11.
- **AC-4 (failed reminder rolls back; manual Retry; no auto-retry):** TC-06, TC-08, TC-11.
- **AC-5 (toggle only on future Upcoming; never Live/Past):** TC-01, TC-12.
- **AC-6 (loading/stale/empty/error/offline states):** TC-04, TC-08, TC-09, TC-13, TC-15.
- **AC-7 (60s live auto-refresh only while selected+resumed; resume + pull-to-refresh):** TC-15.
- **AC-8 (no PII in logs; switch role/state; 48dp; text/icon not color; CSRF):** TC-07, TC-09, TC-14, TC-16.

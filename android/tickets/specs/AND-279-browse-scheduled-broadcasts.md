---
id: AND-279
title: Browse / scheduled broadcasts
milestone: M6
epic: E38
priority: P0
size: L
status: draft
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
- **Web reference:** `frontend/src/api/endpoints/*.ts` for broadcast endpoint shapes (the `/broadcast/sessions` family) and `frontend/src/api/types.ts` for shared session/status enums. Match field names, status vocabulary, and timestamp semantics exactly.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie + `ui_csrf` / `X-CSRF-Token` auth; on 401 the network layer refreshes once via `POST /ui/session/refresh` then retries (handled in `core-network`, not here). A persistent cookie jar is required (already provided by AND-011).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single-Activity), Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Paging 3, Coil for thumbnails, `java.time` via core-library desugaring. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **State convention:** ViewModels expose `StateFlow<UiState>`; network results are typed `ApiResult<T>`; FastAPI `detail` mapped per AND-015 (`string | [{msg}] | {code,...}`).

## 3. Functional Requirements

FR-1 **Three buckets.** The screen presents broadcast sessions segmented into **Live**, **Upcoming** (scheduled, not yet started), and **Past** (ended). Segmentation is derived from the session status/timestamps (§6), not from three separate network calls unless AND-278 exposes them as distinct endpoints.

FR-2 **Bucket selection.** A Material 3 segmented control / tab row toggles the visible bucket. The selected bucket persists across configuration changes (`SavedStateHandle`) and process death. A live count badge appears on the Live tab when ≥1 session is live.

FR-3 **List rendering.** Each bucket renders a vertically scrolling list (Paging 3 where AND-278 exposes paged endpoints; otherwise a single page sorted client-side). A `BroadcastCard` shows: thumbnail (Coil), title, host display name, status pill (LIVE / SCHEDULED / ENDED), localized start time (Upcoming) or relative "started Nm ago" (Live) or "ended" timestamp (Past), and viewer count when present.

FR-4 **Sort order.** Live: by start time descending (most recently started first). Upcoming: by scheduled start ascending (soonest first). Past: by end/start descending (most recent first).

FR-5 **Remind-me toggle.** Each **Upcoming** card (and only sessions whose scheduled start is in the future) exposes a remind-me toggle control. Tapping it **optimistically** flips local state, calls the repository mutation (§5), and on failure rolls back with an inline, dismissible error. Live and Past sessions do not show the toggle (Live: already started; Past: nothing to remind). The toggle reflects the server's `reminder_set` flag on load.

FR-6 **Reminder local scheduling hook.** On a successful remind-me set, the ViewModel invokes `onReminderScheduled(session: BroadcastSession)`; on clear it invokes `onReminderCleared(sessionId)`. Actual notification delivery (FCM-driven or local-alarm fallback) is owned downstream (AND-105–AND-110); this ticket only emits the callbacks and persists the server flag.

FR-7 **Selection callback.** Tapping a card invokes `onSessionClick(sessionId: String, status: BroadcastStatus)`. Routing to the live player or session detail is owned downstream; this ticket exposes the callback only.

FR-8 **Refresh.** Pull-to-refresh and a programmatic `refresh()` re-query the repository. Live data is time-sensitive; the screen issues a foreground refresh on resume and a lightweight periodic refresh (60s) of the Live bucket while it is visible and the screen is in `RESUMED` state.

FR-9 **Loading / empty / error / offline states.** Each bucket shows skeletons while loading, a stale badge when serving cached data, an empty placeholder when the bucket has no sessions, and an inline retry on error (§7), reusing `core-ui` state composables from AND-021.

## 4. Technical Design

Module `feature-broadcast` with public entry point `BroadcastRoute` (Composable) and `BroadcastViewModel` (Hilt). Composables observe a single `StateFlow<BroadcastUiState>`; the ViewModel orchestrates the repository, derives buckets via a pure, testable `BroadcastBucketizer`, and owns optimistic toggle bookkeeping. Pure logic carries no Android dependencies so it is JVM-unit-testable.

```kotlin
package com.testlogon.android.feature.broadcast

enum class BroadcastBucket { LIVE, UPCOMING, PAST }
enum class BroadcastStatus { LIVE, SCHEDULED, ENDED, CANCELLED }   // mirrors AND-278 / web types

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

data class BroadcastItem(
    val sessionId: String,
    val title: String,
    val hostName: String,
    val thumbnailUrl: String?,
    val status: BroadcastStatus,
    val scheduledStart: Instant?,   // null for ad-hoc live
    val actualStart: Instant?,
    val endedAt: Instant?,
    val viewerCount: Int?,
    val reminderSet: Boolean,
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
    suspend fun setReminder(sessionId: String): ApiResult<BroadcastSession>
    suspend fun clearReminder(sessionId: String): ApiResult<Unit>
}
```

Underlying endpoints (reference only; owned by AND-278):

```
GET    /broadcast/sessions?status=scheduled,live,ended
POST   /broadcast/sessions/{sessionId}/reminder
DELETE /broadcast/sessions/{sessionId}/reminder
```

Expected list response shape (status vocabulary mirrors the web reference):

```json
{
  "sessions": [
    {
      "id": "bcs_01H...",
      "title": "Friday AMA",
      "host": { "id": "u_123", "display_name": "Ava" },
      "status": "scheduled",
      "scheduled_start": "2026-06-06T18:00:00Z",
      "actual_start": null,
      "ended_at": null,
      "viewer_count": null,
      "thumbnail_url": "https://.../thumb.jpg",
      "reminder_set": false
    }
  ],
  "next_cursor": null
}
```

Reminder set response (echoes the updated session; UI trusts `reminder_set`):

```json
{ "id": "bcs_01H...", "reminder_set": true, "status": "scheduled", "scheduled_start": "2026-06-06T18:00:00Z" }
```

Error envelope: FastAPI `detail` mapped by `core-network`/AND-015 to `ApiResult.Failure` (`detail` may be `string | [{msg}] | {code,...}`). 401 triggers one `POST /ui/session/refresh` + retry inside `core-network`. This ticket maps `ApiResult.Failure` → `BroadcastError` for the UI. A `409`/`410` on reminder set (e.g., session already started or cancelled) maps to a non-retryable `Server` error and triggers optimistic rollback plus a refresh of that session's bucket.

## 6. Data & State Management

- **Single source of truth:** `BroadcastViewModel.uiState: StateFlow<BroadcastUiState>`, started `WhileSubscribed(5_000)`.
- **Bucketization (client-side):** `BroadcastBucketizer.bucketOf` rules — `status == LIVE` (or `actual_start != null && ended_at == null`) → **Live**; `status in {SCHEDULED} && (scheduled_start ?: actual_start) > now && ended_at == null` → **Upcoming**; `ended_at != null || status == ENDED || status == CANCELLED` → **Past**. `now` comes from the injected `Clock` for deterministic tests. If AND-278 returns server-pre-bucketed endpoints, those are preferred and the bucketizer only validates/sorts.
- **Reactive query:** `repo.sessions()` collected with `flatMapLatest`/`stateIn`; re-bucketized on each emission. `refresh()` triggers a repository re-fetch; cache-hit renders immediately with `isStale = true` while the network refresh runs.
- **Live auto-refresh:** while the Live tab is selected and lifecycle is `RESUMED`, a `flow { while (true) { emit(Unit); delay(60_000) } }` keyed to the lifecycle scope triggers `refresh()`; cancelled on pause/tab-change to respect the unreliable backend.
- **Optimistic toggle bookkeeping:** the ViewModel holds a transient `Map<sessionId, priorReminderState>` to support rollback; cleared on success. Toggles applied to the in-state `Content` lists (all three buckets) so the item stays consistent if the user switches tabs mid-flight.
- **Persisted UI state:** `selected` bucket persisted via `SavedStateHandle` (`key = broadcast_bucket`). No new at-rest storage is added beyond AND-278's existing Room cache; `reminder_set` is server-authoritative and re-read on refresh.
- **De-duplication & sort:** items keyed by `sessionId`; per-bucket sort applied after bucketization per FR-4.

## 7. Error Handling & Resilience

- **Timeouts/retries (reads):** owned by `core-network`/AND-278 (≈20s timeout, bounded exponential backoff for idempotent GETs only). This screen never blind-retries; it surfaces a manual `retry()` and pull-to-refresh.
- **Reminder mutation (writes):** **no auto-retry** (non-idempotent). On failure: optimistic rollback + transient inline error ("Couldn't update reminder — tap to retry"), where retry is an explicit user action, not automatic.
- **`BroadcastError` taxonomy:** `Network` (offline/timeout), `Server` (5xx / mapped `detail` / 409 / 410), `Auth` (terminal 401 after refresh), `Unknown`.
- **Stale-while-error:** `BroadcastUiState.Error(cause, cached)` retains the last good `Content` so lists stay populated with a dismissible banner + Retry, rather than blanking.
- **Empty vs error:** an empty successful fetch shows the per-bucket empty placeholder, never the error UI.
- **Offline:** when the connectivity/health probe (AND-017) reports offline, the screen shows cached content with an offline badge and disables the reminder toggle (queueing reminders offline is out of scope for M6; see §13 OQ).
- **Clock skew / boundary:** sessions exactly at `now` are treated as Live if `actual_start != null`, else Upcoming; guards against `DateTimeException` on null/garbage timestamps by treating unparseable sessions as Past and logging at WARN.

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
- `BroadcastBucketizer.bucketOf` for each status/timestamp permutation: scheduled-future → Upcoming; live (actual_start set, ended_at null) → Live; ended/cancelled → Past; boundary at `now`; unparseable/null timestamps → Past + WARN. Uses fixed `Clock`/`Instant`.
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
- **R2 (reminder semantics):** unclear whether the server stores a per-user reminder flag returned as `reminder_set`, or whether reminders are managed via the notifications subsystem. Spec assumes a session-scoped `reminder_set` flag with POST/DELETE; verify with the web reference.
- **R3 (status vocabulary):** the exact `status` enum values (`scheduled`/`live`/`ended`/`cancelled`) must match the backend; mismatch breaks bucketization. Pin against shared types before build.
- **R4 (live freshness vs. flaky host):** 60s live-poll against an unreliable dev backend may produce frequent transient errors; mitigation is stale-while-error + manual refresh, and poll suppression on repeated failures. **OQ:** is SSE/real-time (AND-143) the intended source for live status, deferring polling?
- **R5 (offline reminder queueing):** spec disables the toggle offline rather than queueing. **OQ:** does product require offline-queued reminders in M6? Deferred unless confirmed.
- **R6 (delivery ownership):** actual reminder notification delivery is out of scope (callbacks only). If no downstream consumer exists at ship time, remind-me sets the server flag but no device notification fires — acceptable for this ticket's acceptance ("toggles"), flagged for product.

## 14. Acceptance Criteria

AC-1 **Lists render** (source-ticket acceptance): for a seeded dataset, Live, Upcoming/Scheduled, and Past sessions appear in their correct bucket lists, in the specified sort order, asserted via Compose semantics in instrumented tests.

AC-2 Bucket tabs switch the visible list; the selected bucket persists across rotation and process death.

AC-3 **Remind-me toggles** (source-ticket acceptance): toggling the switch on an Upcoming card optimistically flips state, calls the repository mutation exactly once, reflects the server result, and persists `reminder_set` across refresh — verified by unit and instrumented tests.

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

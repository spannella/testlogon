---
id: AND-090
title: Notifications tests
milestone: M2
epic: E12
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-085, AND-089]
blocks: []
---

# AND-090 — Notifications tests

## 1. Overview & Goal

The Notifications feature (`feature-notifications`) is delivered across two upstream tickets: **AND-089** owns the data plumbing — a Paging 3 `PagingSource`/`Pager`, the `NotificationsRepository`, and the `NotificationsViewModel` that exposes a `StateFlow<NotificationsUiState>` plus an unread-badge count — and **AND-085** owns the `NotificationCenterScreen`, including the paged lazy list, per-item read/unread treatment, tap → deep-link routing, and the "mark all read" affordance. Both tickets ship with the bare minimum of inline tests; this ticket makes the feature *verifiable* by delivering the complete, headless test suite that locks down its behavior.

AND-090 is a **Test** ticket. It adds **no production behavior** beyond small, non-invasive testability hooks (e.g. a `TestTag` on the list and on item rows, an injectable `Clock`/`TimeProvider` for relative-time copy if not already present). Concretely it delivers:

1. **Repository / paging tests** (`testDebugUnitTest`, JVM) — exercise `NotificationsRepository`, the `NotificationPagingSource`, the FastAPI `detail` → `ApiError` mapping path, mark-read / mark-all-read mutations, and the unread-badge derivation in `NotificationsViewModel` using fakes and a `TestDispatcher`.
2. **Compose UI tests** (`NotificationCenterScreenTest`) — drive `NotificationCenterScreen` from a fake state / fake `Pager` and assert that list rows render, paginate (append on scroll), read vs. unread styling differs, tapping a row emits the correct deep-link route, and "mark all read" clears the unread treatment and badge.

The goal is **completeness and verifiability** of the notifications surface, run **headlessly in CI** (`testDebugUnitTest` for JVM/Robolectric, `connectedDebugAndroidTest` on the headless emulator). The acceptance bar is simply: tests pass headlessly. No new endpoints, no new screens, no new ViewModel state shapes are introduced here — this ticket consumes the AND-089 and AND-085 contracts and asserts against them.

## 2. Context & References

- Repo `spannella/testlogon`; monorepo Android app under `android/`; branch `android-port`.
- Module under test: `feature-notifications`, package root `com.testlogon.android.feature.notifications`. Depends on `core-ui`, `core-model`, `core-data`, `core-network`, `core-testing`.
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose (single Activity), Hilt (KSP), Coroutines/Flow, Paging 3, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **AND-089 — Notifications ViewModel + paging** (P0, dep): owns `NotificationsRepository`, `NotificationPagingSource`, `Pager`/`Flow<PagingData<NotificationUi>>`, `NotificationsViewModel`, `NotificationsUiState`, and `unreadCount: StateFlow<Int>`. This ticket tests those types; it does not redefine them.
- **AND-085 — Notification center screen** (P0, dep): owns `NotificationCenterScreen`, the `LazyColumn` of `collectAsLazyPagingItems()`, `NotificationRow`, the deep-link routing callback, and "mark all read". This ticket tests its rendering and interactions.
- Backend (FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`, plaintext HTTP, unreliable): notifications are read via `GET /ui/notifications` (cursor paging via `cursor`/`limit`; resp `NotificationListResponse`) and an explicit unread count via `GET /ui/notifications/unread-count` (resp `{ "count": <int> }`); they are mutated via `POST /ui/notifications/mark-read` (req `MarkNotificationsReadIn = { notification_ids: string[] }`) and `POST /ui/notifications/mark-all-read` (empty body). **[CORRECTED]** earlier draft cited `POST /ui/notifications/{id}/read` and `/ui/notifications/read_all` — neither exists; the real paths are `mark-read` (bulk, id array in body) and `mark-all-read`. **No real network calls occur in this ticket** — all backend interaction is faked via `MockWebServer` (network-layer tests) or in-memory fakes (ViewModel/UI tests).
- `core-testing` provides: `MainDispatcherRule` (sets `Dispatchers.Main` to a `StandardTestDispatcher`), `MockWebServer` extensions, Moshi/Retrofit test builders, `createComposeRule()` plumbing, and shared fakes (`FakeNotificationsRepository`, `FakeAuthSession`).
- Web reference: `src/api/endpoints/notifications.ts` (`getNotifications`, `getNotificationUnreadCount`, `markNotificationsRead`, `markAllNotificationsRead`, `sendNotification`), `src/api/types.ts` (`NotificationOut`, `NotificationListResponse`, `MarkNotificationsReadReq`), `src/api/client.ts` (auth/CSRF/transport), and `src/pages/notifications/NotificationsPage.tsx` (web screen behavior); OpenAPI at `/openapi.json`. **[NOTE]** the web screen does NOT implement tap→deep-link routing or Paging-3-style append; it uses a "Load more" button and per-item "Mark read". Android's paged list + deep-link routing is an Android-only design owned by AND-085/AND-089, not mirrored from the web client.
- Cross-reference test conventions established by AND-047 (repository contract tests), AND-048/049 (Compose UI tests), AND-069/076/083 (feature state/UI test suites). AND-050 (CI unit tests) and AND-051 (CI instrumented tests) run this suite.

## 3. Functional Requirements

FR-1. A JVM unit-test suite covers `NotificationsRepository` and `NotificationPagingSource`: first-page load, append (next-cursor) load, end-of-pagination, empty page, and HTTP error → `ApiResult.Error` with mapped `ApiError` message.

FR-2. The repository tests assert the request contract: path `GET /ui/notifications` with `cursor`/`limit` query params; `POST /ui/notifications/mark-read` carrying a JSON body `{ "notification_ids": [...] }` (schema `MarkNotificationsReadIn`); `POST /ui/notifications/mark-all-read` with an empty/`{}` body; and that the `X-CSRF-Token` header is present on the mutations (POST). **[NOTE]** the web `client.ts` interceptor actually attaches `X-CSRF-Token` (from the `ui_csrf` cookie) to *every* request when the cookie is present, not just mutations; the Android contract test asserts presence-on-mutation (the security-relevant case) and does not assert absence-on-GET. GETs are idempotent and eligible for bounded backoff retry (AND-016); mutations are not retried.

FR-3. FastAPI `detail` mapping is tested for all three shapes: `detail` as a plain `string`, as `[{msg, ...}]`, and as `{code, ...}` — each resolves to the expected human-readable `ApiError.message`.

FR-4. `NotificationsViewModel` tests assert: `unreadCount` (`StateFlow<Int>`) reflects the server-supplied count and stays consistent with loaded items; marking a single item read decrements the badge and flips that item's `read` flag; "mark all read" drives `unreadCount` to 0 and flips all items; a failed mutation leaves state unchanged and surfaces an error event/state. **[CORRECTED]** the unread count is authoritative from the backend (`NotificationListResponse.unread_count`, default 0, and the dedicated `GET /ui/notifications/unread-count` → `{ "count": <int> }`), NOT purely derived from the in-memory loaded page; the field on each item is `read: boolean` (the draft's `isRead` is the Android-side mapping name — confirm against AND-089's `NotificationUi`, otherwise treat as unverified). The test should both (a) assert the badge tracks the server count and (b) assert mutation-driven optimistic flips, rather than assuming the badge is computed solely by counting unread rows in the current page.

FR-5. `NotificationsUiState` transitions are asserted via Turbine: initial → loading → content; loading → error (non-connectivity); loading → offline (connectivity/timeout against the unreliable host).

FR-6. Compose UI test `NotificationCenterScreenTest` renders the screen from a fake `Flow<PagingData<NotificationUi>>` and asserts: rows render with title/body/timestamp; the list paginates (scrolling to the end appends the next page); the empty state renders when paging is empty; the error/append-error footer renders on page-load failure with a retry affordance.

FR-7. UI test asserts **read vs. unread** rows are visually distinguishable via a stable, testable signal (a `Modifier.semantics` `stateDescription` of "unread"/"read" and/or an unread-dot node tagged `notif_unread_dot`), not by pixel color.

FR-8. UI test asserts **tap → deep-link**: tapping a `NotificationRow` invokes the routing callback with the correct route string. **[CORRECTED]** the backend `NotificationOut` has **no** `deep_link` / `target` field; the routable payload lives in the free-form `data: Record<string, unknown>` map (e.g. `data["deep_link"]`, `data["run_id"]`, etc.) plus `notification_type`. The exact key(s) and the route-derivation logic are owned by AND-085/AND-089 (Android-only — the web `NotificationsPage.tsx` does no tap-routing at all). The test captures the emitted route from a fixture whose `data` map mirrors AND-085's mapping and asserts equality; this mapping is an **unverified assumption** until AND-085 lands.

FR-9. UI test asserts **mark all read**: invoking the top-bar action clears every row's unread treatment and the unread badge node disappears (or reads 0).

FR-10. The entire suite runs **headlessly** and passes in CI: JVM/Robolectric portions via `./gradlew :feature-notifications:testDebugUnitTest`, instrumented Compose portions via `:feature-notifications:connectedDebugAndroidTest` on the headless emulator (AND-051). No manual interaction, no real device features, no real network.

FR-11. Test-only production hooks are additive and minimal: stable `testTag`s (`notif_list`, `notif_row`, `notif_unread_dot`, `notif_mark_all_read`, `notif_unread_badge`) and an injectable time source for relative timestamps. These must not regress AND-085/AND-089 behavior.

## 4. Technical Design

Tests live under `feature-notifications/src/test/...` (JVM/Robolectric) and `feature-notifications/src/androidTest/...` (instrumented Compose), package `com.testlogon.android.feature.notifications`.

### 4.1 Fakes and rules (from `core-testing`)

```kotlin
class FakeNotificationsRepository(
    private val pages: MutableList<List<NotificationUi>> = mutableListOf(),
    var unread: Int = 0,                       // server-authoritative unread count (NotificationListResponse.unread_count / unread-count endpoint)
    var failOnPage: Int? = null,
    var markAllResult: ApiResult<Unit> = ApiResult.Success(Unit),
) : NotificationsRepository {
    val marked = mutableListOf<String>()
    override fun pager(): Flow<PagingData<NotificationUi>> = /* PagingData.from(...) */
    // markRead is bulk on the wire (POST /ui/notifications/mark-read, body {notification_ids:[...]});
    // the repo may expose a single-id convenience that wraps a 1-element array. Confirm against AND-089.
    override suspend fun markRead(id: String): ApiResult<Unit> { marked += id; return ApiResult.Success(Unit) }
    override suspend fun markAllRead(): ApiResult<Unit> = markAllResult
    override val unreadCount: Flow<Int> get() = /* emits `unread`, updated on mutation success */
}
```

```kotlin
@get:Rule val mainDispatcherRule = MainDispatcherRule()          // StandardTestDispatcher
@get:Rule val composeRule = createComposeRule()                   // androidTest
```

### 4.2 Paging source tests

`NotificationPagingSourceTest` constructs the source against a `MockWebServer`-backed `NotificationsApi` and asserts `PagingSource.load(...)` results directly:

```kotlin
@Test fun load_firstPage_returnsPageWithNextKey() = runTest {
    server.enqueue(jsonResponse(PAGE_1_JSON))            // items + next_cursor
    val result = pagingSource.load(LoadParams.Refresh(key = null, loadSize = 20, false))
    val page = result as LoadResult.Page
    assertThat(page.data).hasSize(20)
    assertThat(page.nextKey).isEqualTo("cursor_2")
    assertThat(page.prevKey).isNull()
}

@Test fun load_lastPage_nextKeyNull() = runTest { /* next_cursor == null -> nextKey null */ }

@Test fun load_httpError_returnsLoadResultError() = runTest {
    server.enqueue(MockResponse().setResponseCode(500).setBody(DETAIL_OBJ_JSON))
    val result = pagingSource.load(LoadParams.Refresh(null, 20, false))
    assertThat(result).isInstanceOf(LoadResult.Error::class.java)
}
```

### 4.3 ViewModel tests (Turbine)

```kotlin
// NOTE: per the corrected FR-4, unreadCount is authoritative from the backend
// (NotificationListResponse.unread_count / GET /ui/notifications/unread-count -> {count}),
// so the fake exposes a settable unread count rather than counting unread rows itself.
@Test fun unreadCount_reflectsServerCount() = runTest {
    val vm = NotificationsViewModel(FakeNotificationsRepository(unread = 2, pages = listOf(twoUnreadOneRead)))
    vm.unreadCount.test { assertThat(awaitItem()).isEqualTo(2) }
}

@Test fun markAllRead_zeroesBadge() = runTest { /* invoke, assert unreadCount emits 0 */ }

@Test fun markAllRead_failure_keepsState() = runTest { /* markAllResult = Error; badge unchanged + error event */ }
```

### 4.4 Compose UI tests

`NotificationCenterScreenTest` injects a fake state into `NotificationCenterScreen` and uses `composeRule.onNodeWithTag(...)` / `performScrollToIndex` / `performClick`:

```kotlin
@Test fun rows_render_andPaginate() {
    composeRule.setContent { NotificationCenterScreen(state = fakeState(pages = 3), onOpen = {}, onMarkAllRead = {}) }
    composeRule.onAllNodesWithTag("notif_row").assertCountAtLeast(20)
    composeRule.onNodeWithTag("notif_list").performScrollToIndex(40)
    composeRule.waitUntil { composeRule.onAllNodesWithTag("notif_row").fetchSemanticsNodes().size > 40 }
}

@Test fun tap_emitsDeepLinkRoute() {
    var route: String? = null
    composeRule.setContent { NotificationCenterScreen(state = single(deepLink = "tl://run/abc"), onOpen = { route = it }, onMarkAllRead = {}) }
    composeRule.onAllNodesWithTag("notif_row").onFirst().performClick()
    composeRule.runOnIdle { assertThat(route).isEqualTo("tl://run/abc") }
}

@Test fun markAllRead_clearsUnread() { /* click notif_mark_all_read; assert no node with stateDescription "unread"; badge gone */ }

@Test fun unreadRow_hasUnreadSemantics() { /* assertContentDescriptionOrStateDescription contains "unread" */ }
```

Relative timestamps are made deterministic by injecting a fixed `Clock`/`TimeProvider` into the fake state so "2h ago" assertions are stable.

## 5. API Contract

This is a test ticket; it defines **no new API**. It asserts against the contract owned by AND-089 / AND-084 (core-network). The fixtures below are **corrected** to match the authoritative OpenAPI schemas (`NotificationListResponse`, `NotificationOut`, `MarkNotificationsReadIn`) and the web client (`src/api/endpoints/notifications.ts`, `src/api/types.ts`):

`GET /ui/notifications?cursor=<c>&limit=30` → 200 `NotificationListResponse`:

```json
{
  "items": [
    {
      "notification_id": "n_01",
      "notification_type": "system",
      "title": "Run finished",
      "body": "Suite #482 passed",
      "data": { "deep_link": "tl://run/482", "run_id": "482" },
      "read": false,
      "created_at": 1749121320,
      "batch_key": null,
      "batch_count": 1,
      "batch_actors": []
    }
  ],
  "next_cursor": "cursor_2",
  "unread_count": 1
}
```

**[CORRECTED]** field names vs. the original draft: `id`→`notification_id`, `category`→`notification_type`, `is_read`→`read`, `deep_link` is **not** a top-level field (it lives inside the free-form `data` object if present at all), and `created_at` is an **epoch integer (seconds)**, not an ISO-8601 string. The list response also carries a top-level `unread_count: integer` (default 0); `items` is the only required field, and `notification_id` is the only required field of `NotificationOut`.

Mutations (corrected paths/shapes):

- `POST /ui/notifications/mark-read` — req body `MarkNotificationsReadIn = { "notification_ids": ["n_01", ...] }`; web returns `{ "ok": true, "marked_count": <int> }` on 200. (The draft's `POST /ui/notifications/{id}/read` does not exist.)
- `POST /ui/notifications/mark-all-read` — empty/`{}` body; web returns `{ "ok": true, "marked_count": <int> }` on 200. (The draft's `/ui/notifications/read_all` does not exist.)
- `GET /ui/notifications/unread-count` → 200 `{ "count": <int> }` (note key is `count`, not `unread_count`, on this endpoint).

All POSTs carry `X-CSRF-Token` (echoed from the `ui_csrf` cookie); the web transport additionally sends `Authorization: Bearer <token>` and `credentials: include` (cookie session) on every request — so the contract is **Bearer + cookie + CSRF**, not cookie-only. Error fixtures cover FastAPI `detail` as `string`, `[{msg}]`, and `{code,...}`, plus the documented `422 HTTPValidationError`. Exact paths/params are owned upstream; if they differ at integration time, the fixtures and `MockWebServer` `RecordedRequest` path/body assertions are the single point of update.

## 6. Data & State Management

No persistent state is created by this ticket. Tests assert the in-memory state contracts:

- `NotificationsUiState` (sealed) values rendered/asserted: `Loading`, `Content(items, ...)`, `Empty`, `Error(message)`, `Offline`.
- `unreadCount: StateFlow<Int>` derivation and reactivity.
- `PagingData<NotificationUi>` / `LoadState` (`Loading`, `NotLoading(endOfPaginationReached)`, `Error`) for refresh and append.

Room (cache) and DataStore are involved only insofar as upstream uses them; this suite injects fakes and does **not** open real Room or DataStore instances except for any Robolectric-backed in-memory `Room.inMemoryDatabaseBuilder` fixture if a repository test requires the cache path — kept isolated and torn down per test.

## 7. Error Handling & Resilience

The suite explicitly verifies error/resilience behavior rather than implementing it:

- Page-load HTTP error → `LoadResult.Error` → screen shows append/refresh error footer with retry; clicking retry re-invokes `retry()` (asserted on a spy `LoadStateAdapter`/callback).
- Connectivity/timeout (simulated via `MockWebServer` `setSocketPolicy(NO_RESPONSE)` / dispatcher throwing `SocketTimeoutException`) → `Offline` state, distinct from `Error`.
- Mutation failure (mark read / mark all read) → state unchanged, error surfaced, badge not decremented.
- Idempotent GET retry policy (AND-016): test asserts a transient 5xx then 200 yields success within the retry budget; mutations are asserted to make exactly one request (no retry).

## 8. Security & Privacy

No new attack surface. Tests assert security-relevant contracts: mark-read mutations send `X-CSRF-Token`; the suite uses `MockWebServer` (no real cookies/credentials leave the process); no real backend, tokens, or PII appear in fixtures (synthetic ids/titles only). The unreliable plaintext dev host is never contacted from tests. No secrets in fixtures or logs.

## 9. Accessibility & i18n

UI tests assert accessibility affordances rather than introducing them: every `NotificationRow` exposes a non-empty content description / merged semantics; read/unread is exposed via `stateDescription` (machine-readable, not color-only) so the test — and TalkBack — can distinguish them; the "mark all read" action and unread badge have semantics labels (`notif_mark_all_read`, `notif_unread_badge`). All asserted copy is read via `stringResource` so i18n is preserved; tests assert against resource ids / fake `Strings`, not hardcoded English where avoidable. Minimum touch-target on rows is implicitly covered by interaction tests.

## 10. Telemetry & Logging

No production telemetry is added. Test logging uses JUnit/Compose default output. CI publishes the standard JUnit XML and the Compose UI test reports (`build/reports/tests/`, `build/outputs/androidTest-results/`) consumed by AND-050/AND-051. Failures must include semantic node-tree dumps (`composeRule.onRoot().printToLog(...)`) on assertion failure to aid headless triage.

## 11. Testing Strategy

This ticket *is* the testing strategy for the feature. Layers:

1. **JVM unit (`src/test`, Robolectric where Compose/Android types are needed):** `NotificationPagingSourceTest`, `NotificationsRepositoryTest` (MockWebServer + `detail` mapping), `NotificationsViewModelTest` (Turbine + `MainDispatcherRule`). Frameworks: JUnit4, Truth, Turbine, MockWebServer, `kotlinx-coroutines-test`, `androidx.paging:paging-testing` (`asSnapshot { }`).
2. **Instrumented Compose (`src/androidTest`):** `NotificationCenterScreenTest` via `createComposeRule()` / `createAndroidComposeRule`, fed fake `PagingData` (`PagingData.from(...)`). Asserts rendering, pagination append, read/unread semantics, deep-link emission, mark-all-read.
3. **Paging-specific:** use `paging-testing` `asSnapshot` to assert ordered emission and `LoadState` transitions without a UI; use `TestPager` for `PagingSource` refresh/append.

Determinism: all dispatchers via `StandardTestDispatcher`; time via injected fixed `Clock`; `composeRule.mainClock.autoAdvance` controlled where animations would race assertions; `waitUntil` for paging append rather than fixed sleeps. Coverage target: every branch of `NotificationsUiState`, every `LoadState`, both mutation outcomes, all three `detail` shapes.

## 12. Dependencies & Sequencing

- **Depends on AND-089** (ViewModel + paging + repository contracts) and **AND-085** (screen + rows + routing + mark-all-read) — both must be merged; their public types are the test targets. Transitively relies on AND-084 (notifications API/data), core-network (AND-009–AND-018: OkHttp, CSRF interceptor, 401 refresh, `ApiResult`, `detail` mapping, retry/backoff), and `core-testing`.
- **Consumed by** AND-050 (`testDebugUnitTest` in CI) and AND-051 (instrumented tests on headless emulator). It does not block feature tickets but gates the M2 E12 quality bar.
- Sequencing: land after AND-085/AND-089; coordinate the small additive `testTag`/time-source hooks via a thin follow-up commit on those files if not already present.

## 13. Risks & Open Questions

- **R1 — Paging test flakiness:** append-on-scroll can race in headless Compose. Mitigation: prefer `paging-testing` `asSnapshot`/`TestPager` for ordering and reserve the instrumented scroll test for one append assertion guarded by `waitUntil`.
- **R2 — Deep-link route shape:** the exact route/scheme emitted on tap is owned by AND-085 (and the nav graph). Open question: is it a `tl://` URI, a Navigation-Compose route string, or a `NotificationTarget` sealed type? Tests assert whatever AND-085 exposes; fixtures updated at integration.
- **R3 — Endpoint paths/params** — RESOLVED against OpenAPI: paging is cursor-based (`cursor`/`limit` query → `next_cursor` in body), mutations are `POST /ui/notifications/mark-read` (body `{notification_ids:[...]}`) and `POST /ui/notifications/mark-all-read` (the draft's `read_all`/`{id}/read` were wrong; see §5 and §16). `RecordedRequest` path/body assertions remain the single point of update if upstream changes again.
- **R4 — Read/unread signal:** if AND-085 conveys unread via color only, a `stateDescription` hook must be added there (FR-7); this is the one likely production touch.
- **R5 — Robolectric vs instrumented split:** if Paging Compose interop misbehaves under Robolectric, the UI test stays instrumented-only; resolved by running both in CI.

## 14. Acceptance Criteria

AC-1. `./gradlew :feature-notifications:testDebugUnitTest` passes headlessly, covering paging source (first/append/end/empty/error), repository request-contract + `detail` mapping (all 3 shapes), and ViewModel badge/mark-read/mark-all-read (success + failure) with Turbine state assertions.

AC-2. `./gradlew :feature-notifications:connectedDebugAndroidTest` passes on the headless emulator, with `NotificationCenterScreenTest` asserting row rendering, pagination append, empty/error footer, read vs. unread semantics, tap → correct deep-link route, and mark-all-read clearing unread + badge.

AC-3. Tests are deterministic (no real network, fixed clock, controlled dispatchers/`mainClock`); no `Thread.sleep`; reruns are stable across 3 consecutive CI runs.

AC-4. CSRF header presence on mutations and one-request-no-retry on mutations vs. retry-on-transient-5xx for GETs are both asserted.

AC-5. No production behavior regressions in AND-085/AND-089; any added hooks are limited to `testTag`s, semantics, and an injectable time source.

AC-6. JUnit XML + Compose test reports are produced and green in CI (AND-050/AND-051).

## 15. Definition of Done

- All test classes implemented under `feature-notifications/src/test` and `.../src/androidTest`, named per §4, green locally and in CI.
- AC-1 through AC-6 satisfied; suite runs fully headlessly with zero manual steps.
- Additive testability hooks (if any) merged into AND-085/AND-089 sources without behavior change; reviewed against those tickets' owners.
- Fixtures (`PAGE_1_JSON`, `detail` variants, error/offline simulations) checked in under test resources; no real hosts, cookies, or PII.
- Code passes `ktlint`/`detekt` (AND-005); reports archived in CI; PR linked to AND-085 and AND-089; merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer.

1. **`GET /ui/notifications` lists notifications with `cursor`/`limit` paging.** — Verified. OpenAPI `GET /ui/notifications` (op `list_notifications_ui_notifications_get`, `resp=200:NotificationListResponse`, `params=cursor,limit,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`); frontend `src/api/endpoints/notifications.ts: getNotifications` (sends `limit`/`cursor`).
2. **Mark-read endpoint is `POST /ui/notifications/mark-read` with body `{ notification_ids: string[] }`.** — Corrected (draft said `POST /ui/notifications/{id}/read`). OpenAPI `POST /ui/notifications/mark-read` (op `mark_read_ui_notifications_mark_read_post`, `req=MarkNotificationsReadIn`); schema `MarkNotificationsReadIn = { notification_ids: array<string> }`; frontend `src/api/endpoints/notifications.ts: markNotificationsRead`, `src/api/types.ts: MarkNotificationsReadReq`.
3. **Mark-all-read endpoint is `POST /ui/notifications/mark-all-read` (empty body).** — Corrected (draft said `/ui/notifications/read_all`). OpenAPI `POST /ui/notifications/mark-all-read` (op `mark_all_read_ui_notifications_mark_all_read_post`, no `req`); frontend `src/api/endpoints/notifications.ts: markAllNotificationsRead` (posts `{}`).
4. **A dedicated unread-count endpoint exists: `GET /ui/notifications/unread-count` → `{ count: int }`.** — Verified (draft omitted it). OpenAPI `GET /ui/notifications/unread-count` (op `get_unread_count_ui_notifications_unread_count_get`); frontend `src/api/endpoints/notifications.ts: getNotificationUnreadCount` returns `{ count: number }`.
5. **List response shape is `NotificationListResponse = { items: NotificationOut[], next_cursor?: string|null, unread_count: int }`.** — Corrected/expanded. OpenAPI `components.schemas.NotificationListResponse` (`required: [items]`, `unread_count` default 0); frontend `src/api/types.ts: NotificationListResponse` (lines 5270-5274).
6. **Item shape: `notification_id`, `notification_type`, `title`, `body`, `data` (object), `read` (bool), `created_at` (epoch int), `batch_key?`, `batch_count` (int, default 1), `batch_actors` (string[]).** — Corrected. The draft used `id`/`category`/`is_read`/`deep_link`/ISO `created_at`, none of which exist. OpenAPI `components.schemas.NotificationOut` (`required: [notification_id]`, `created_at` type integer); frontend `src/api/types.ts: NotificationOut` (lines 5257-5268).
7. **`created_at` is an epoch integer (seconds), not an ISO-8601 string.** — Corrected. OpenAPI `NotificationOut.created_at` `type: integer`; frontend `src/pages/notifications/NotificationsPage.tsx: formatTimeAgo` computes `Math.floor(Date.now()/1000) - ts`, confirming epoch seconds.
8. **There is no top-level `deep_link`/`target` field; routable data (if any) is in the free-form `data: Record<string,unknown>` map.** — Corrected. OpenAPI `NotificationOut.data` `type: object, additionalProperties: true`; no `deep_link`/`target` property in the schema. The Android tap→route mapping over `data` is an **Unverified-assumption** (owned by AND-085; the web `NotificationsPage.tsx` does no tap-routing).
9. **Unread badge count is server-authoritative, not derived solely from loaded items.** — Corrected. Source: `NotificationListResponse.unread_count` (OpenAPI + `src/api/types.ts`) and `GET /ui/notifications/unread-count`; web `NotificationsPage.tsx` uses `unreadData?.count ?? data?.unread_count ?? 0` (line 114).
10. **Mutations send `X-CSRF-Token` from the `ui_csrf` cookie.** — Verified, with nuance. `src/api/client.ts` lines 167-170 set `X-CSRF-Token` from `getCookie("ui_csrf")` on **every** request (not only mutations) whenever the cookie is present. Asserting presence-on-mutation is correct; the "only on mutations" framing was Corrected.
11. **Transport is cookie-session-only.** — Corrected. `src/api/client.ts` uses `Authorization: Bearer <accessToken>` (lines 158-159) **and** `credentials: "include"` (cookie session, lines 124/183/220), plus optional `X-IMPERSONATION-TOKEN` (lines 163-164). So the contract is Bearer + cookie + CSRF.
12. **`422 HTTPValidationError` is a documented error response for these endpoints.** — Verified. OpenAPI index shows `resp=...;422:HTTPValidationError` on `GET /ui/notifications`, `mark-read`, and `mark-all-read`.
13. **FastAPI `detail` appears as plain `string`, `[{msg,...}]`, or `{code,...}` and maps to `ApiError.message`.** — Unverified-assumption for the `{code,...}` variant. The standard FastAPI/`HTTPValidationError` shape (`detail: [{loc,msg,type}]`) and a plain-string `detail` are conventional, but the `{code,...}` object form was not located as a named schema in the index; the `detail`→`ApiError` mapping itself is owned by core-network (AND-016/AND-018), outside this spec's verifiable sources. Treat as assumption; pin fixtures at integration.
14. **Web uses `limit: 30` for the list query.** — Verified. `src/pages/notifications/NotificationsPage.tsx` line 89 (`getNotifications({ limit: 30, cursor })`). The draft's fixtures used `limit=20`; Android may choose its own page size — noted as an Android design choice, not a contract violation.
15. **Android stack/framework choices (Compose UI test, Paging 3 `paging-testing` `asSnapshot`/`TestPager`, Robolectric, MockWebServer, Turbine).** — Unverified by backend/frontend sources (framework ref). Compose testing: https://developer.android.com/develop/ui/compose/testing ; Paging testing: https://developer.android.com/topic/libraries/architecture/paging/test ; Robolectric: https://robolectric.org ; MockWebServer: https://github.com/square/okhttp/tree/master/mockwebserver. These are tool/framework conventions, accepted as-is.

### Corrections made

- **Mutation paths/shapes** (§2, §5, §13-R3, FR-2): `POST /ui/notifications/{id}/read` → `POST /ui/notifications/mark-read` with bulk body `{notification_ids:[...]}`; `POST /ui/notifications/read_all` → `POST /ui/notifications/mark-all-read`.
- **Item field names** (§5 fixture, FR-4, FR-8): `id`→`notification_id`, `category`→`notification_type`, `is_read`→`read`; removed top-level `deep_link` (moved into `data` map); `created_at` ISO-string → epoch integer; added `batch_key`/`batch_count`/`batch_actors` and `notification_type`.
- **Unread count** (FR-4, §4.3, §4.1 fake): changed from "derived from loaded items" to server-authoritative (`unread_count` in list response + `/unread-count` endpoint).
- **Transport/CSRF framing** (FR-2, §5, §8): corrected "cookie-session-only" to Bearer + cookie + CSRF; clarified CSRF is attached to all requests, asserted on mutations.
- **Added unread-count endpoint** (§2, §5) which the draft omitted.
- **Frontend file paths** (§2): `frontend/src/...` → actual `src/...` layout; named the real page `src/pages/notifications/NotificationsPage.tsx` and noted it has no tap-routing/append.

### Open assumptions

- **Deep-link route derivation from `data`** (FR-8, claim 8): the exact key inside `data` (e.g. `deep_link` vs `run_id`) and the route format (`tl://` URI vs Nav-Compose route vs sealed `NotificationTarget`) are owned by AND-085 and not present in any verifiable source. Tests pin a fixture and update at integration.
- **`detail` as `{code,...}`** (claim 13): the object-with-code error variant is not a named OpenAPI schema here; the `detail`→`ApiError` mapping lives in core-network (AND-016/018). Unverifiable from this ticket's sources.
- **Android-side type names** (`NotificationUi`, `NotificationsUiState`, `NotificationsRepository`, `markRead(id)` signature): owned by AND-089; assumed from the draft and not independently verifiable here.
- **Page size** for the Android list (20 vs the web's 30): an Android design choice; not a contract requirement.

## 17. Test Plan

Acceptance-criteria references (AC-1..AC-6) are from §14. Test targets: **JVM** = JVM/Robolectric local (no device); **emulator** = headless AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This suite is fully headless and uses no real hardware, so all instrumented cases run on the **emulator**; the one ABI/API-skew smoke case optionally also runs on the **device**.

- **TC-AND-090-01** — Paging first page. Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: `NotificationPagingSource` wired to a MockWebServer-backed `NotificationsApi`; `PAGE_1_JSON` enqueued (corrected shape: `items[].notification_id/read/created_at:int/data`, `next_cursor:"cursor_2"`, `unread_count`). Steps: call `load(Refresh(key=null, loadSize=20))`. Expected: `LoadResult.Page`, `data.size == items`, `nextKey == "cursor_2"`, `prevKey == null`; `RecordedRequest` path is `/ui/notifications` with `cursor`/`limit` query. Traces: AC-1.
- **TC-AND-090-02** — Paging append + end-of-pagination. Type: contract/MockWebServer (JVM, `TestPager`/`asSnapshot`). Target: JVM. Preconditions: two pages enqueued; second has `next_cursor: null`. Steps: refresh then append via `TestPager`; assert ordered emission with `asSnapshot`. Expected: append succeeds with prior `nextKey`; final page `nextKey == null` → `LoadState.NotLoading(endOfPaginationReached=true)`. Traces: AC-1.
- **TC-AND-090-03** — Empty page. Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: response `{ "items": [], "next_cursor": null, "unread_count": 0 }`. Steps: `load(Refresh)`. Expected: `LoadResult.Page` with empty `data`, `nextKey == null`. Traces: AC-1.
- **TC-AND-090-04** — HTTP error → `LoadResult.Error` with mapped `ApiError`. Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue 500 with `detail` object body. Steps: `load(Refresh)`. Expected: `LoadResult.Error`; the wrapped `ApiError.message` matches the mapped `detail`. Traces: AC-1.
- **TC-AND-090-05** — FastAPI `detail` mapping, all three shapes. Type: unit (JVM, parameterized). Target: JVM. Preconditions: three 4xx/5xx bodies: `detail` as `"string"`, as `[{ "msg": "..." }]`, and as `{ "code": "...", ... }`. Steps: drive each through the repo/error mapper. Expected: each resolves to the expected human-readable `ApiError.message`; the `{code,...}` case is flagged as an assumption fixture (see §16 open assumptions) and asserted against AND-016's mapper once available. Traces: AC-1.
- **TC-AND-090-06** — Mutation request contract: mark-read body + CSRF, single request, no retry. Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: repo with a valid `ui_csrf`-equivalent CSRF source; enqueue 200 `{ "ok": true, "marked_count": 1 }`. Steps: call `markRead("n_01")`. Expected: exactly **one** `RecordedRequest`, `POST /ui/notifications/mark-read`, JSON body `{"notification_ids":["n_01"]}`, header `X-CSRF-Token` present and non-empty; no retry on success. Traces: AC-4.
- **TC-AND-090-07** — Mark-all-read contract. Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue 200 `{ "ok": true, "marked_count": 5 }`. Steps: call `markAllRead()`. Expected: one `POST /ui/notifications/mark-all-read`, empty/`{}` body, `X-CSRF-Token` present; no retry. Traces: AC-4.
- **TC-AND-090-08** — GET retry-on-transient-5xx vs mutation no-retry. Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: list GET: enqueue 503 then 200; mark-read: enqueue single 500. Steps: trigger a list load and a mark-read. Expected: list load succeeds within the bounded retry budget (AND-016) issuing 2 requests; mark-read issues exactly 1 request and surfaces the error (no retry). Traces: AC-4.
- **TC-AND-090-09** — ViewModel unread badge is server-authoritative + mutation flips. Type: unit (JVM, Turbine + `MainDispatcherRule`). Target: JVM. Preconditions: `FakeNotificationsRepository(unread=2, pages=[twoUnreadOneRead])`. Steps: collect `unreadCount`; call `markRead` on one unread item (fake decrements `unread`); call `markAllRead`. Expected: emits `2`, then `1` after single mark, then `0` after mark-all; corresponding item `read` flags flip. Traces: AC-1.
- **TC-AND-090-10** — Mutation failure leaves state unchanged + surfaces error. Type: unit (JVM, Turbine). Target: JVM. Preconditions: `markAllResult = ApiResult.Error(...)`, `unread=3`. Steps: call `markAllRead()`. Expected: `unreadCount` stays `3`, no items flip, an error event/state is emitted; no crash. Traces: AC-1.
- **TC-AND-090-11** — UiState transitions incl. offline. Type: unit (JVM, Turbine). Target: JVM. Preconditions: fakes for (a) success, (b) non-connectivity error, (c) timeout via `SocketTimeoutException`/`NO_RESPONSE` socket policy. Steps: drive each path. Expected: `Loading → Content`; `Loading → Error` (non-connectivity, distinct message); `Loading → Offline` (connectivity/timeout). Traces: AC-1, AC-3.
- **TC-AND-090-12** — Screen renders rows + paginates (append). Type: Compose-UI/instrumented. Target: emulator. Preconditions: `NotificationCenterScreen` fed a fake `Flow<PagingData<NotificationUi>>` of ≥3 pages; `mainClock` controlled. Steps: assert `onAllNodesWithTag("notif_row")` count ≥ first page; `onNodeWithTag("notif_list").performScrollToIndex(...)`; `waitUntil` row count grows. Expected: rows render with title/body/timestamp; append adds a page; no fixed sleeps. Traces: AC-2, AC-3.
- **TC-AND-090-13** — Read vs unread is machine-readable (semantics, not color). Type: Compose-UI/instrumented + accessibility. Target: emulator. Preconditions: fake state with one read + one unread row. Steps: query nodes by `stateDescription`/`notif_unread_dot` tag; assert unread row exposes `stateDescription == "unread"` and read row `"read"`; assert every row has non-empty merged content description. Expected: read/unread distinguishable without pixel color; TalkBack-readable. Traces: AC-2, AC-5.
- **TC-AND-090-14** — Tap → deep-link route. Type: Compose-UI/instrumented. Target: emulator. Preconditions: single-item fake whose `data` map carries the routable key (fixture mirrors AND-085's mapping; see §16 open assumption); `onOpen` callback captured. Steps: `onAllNodesWithTag("notif_row").onFirst().performClick()`. Expected: captured route equals the expected derived route (e.g. `tl://run/482`); assertion lives behind a single integration point so it updates if AND-085's mapping differs. Traces: AC-2.
- **TC-AND-090-15** — Mark-all-read clears unread treatment + badge. Type: Compose-UI/instrumented. Target: emulator. Preconditions: fake state with ≥1 unread row and `notif_unread_badge` showing a count. Steps: `onNodeWithTag("notif_mark_all_read").performClick()`. Expected: no node reports `stateDescription "unread"`; `notif_unread_badge` is gone or reads 0. Traces: AC-2.
- **TC-AND-090-16** — Empty state + append/refresh error footer with retry. Type: Compose-UI/instrumented. Target: emulator. Preconditions: (a) empty `PagingData`; (b) `PagingData` whose append `LoadState` is `Error`. Steps: assert empty-state node renders for (a); for (b) assert error footer + retry affordance, `performClick()` retry and assert `retry()` invoked (spy). Expected: empty and error footers render correctly; retry re-invokes load. Traces: AC-2.
- **TC-AND-090-17** — Headless suite green + reports + 3x stability (CI gate). Type: integration (CI). Target: JVM + emulator. Preconditions: clean checkout on `android-port`. Steps: run `:feature-notifications:testDebugUnitTest` and `:feature-notifications:connectedDebugAndroidTest` 3 consecutive times. Expected: all green all 3 runs; JUnit XML (`build/reports/tests/`) and Compose results (`build/outputs/androidTest-results/`) produced; no `Thread.sleep`; no real network/host contacted. Traces: AC-3, AC-6.
- **TC-AND-090-18** — Security: no real host/cookies/PII; CSRF-only-on-MockWebServer. Type: unit/contract (JVM). Target: JVM. Preconditions: scan test fixtures/resources. Steps: assert no fixture contains `18.222.237.167`, real cookies, tokens, or PII; assert all traffic targets the in-process MockWebServer; assert `X-CSRF-Token` value originates from a test-supplied source, not a real cookie jar. Expected: all assertions hold; synthetic ids/titles only. Traces: AC-5.
- **TC-AND-090-19** — ABI/API-skew smoke (optional hardware). Type: instrumented/e2e. Target: device (SM-A156U, arm64-v8a, API 34) — also runs on emulator (x86_64, API 35). Preconditions: full `NotificationCenterScreenTest` installable on both. Steps: run the instrumented subset on emulator API 35 and on the physical device API 34. Expected: identical pass results on both; no arm64-vs-x86 or API-34-vs-35 divergence in Compose/Paging behavior. **MUST run on the physical device** to validate arm64-v8a/API-34 (the emulator cannot cover that ABI/API pairing). Traces: AC-2, AC-3.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (JVM: paging, repo+detail mapping, VM badge/mark success+failure, Turbine) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-09, TC-10, TC-11 |
| AC-2 (instrumented screen: render, append, empty/error footer, read/unread, tap→route, mark-all) | TC-12, TC-13, TC-14, TC-15, TC-16, TC-19 |
| AC-3 (determinism, no sleep, 3x stable) | TC-11, TC-12, TC-17, TC-19 |
| AC-4 (CSRF on mutations; 1-request-no-retry on mutations vs retry-on-5xx for GET) | TC-06, TC-07, TC-08 |
| AC-5 (no prod regressions; hooks limited to tags/semantics/time; no PII) | TC-13, TC-18 |
| AC-6 (JUnit XML + Compose reports green in CI) | TC-17 |

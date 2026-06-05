---
id: AND-090
title: Notifications tests
milestone: M2
epic: E12
priority: P1
size: M
status: draft
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
- Backend (FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`, plaintext HTTP, unreliable): notifications are read via `GET /ui/notifications` (cursor/offset paging) and mutated via mark-read endpoints. **No real network calls occur in this ticket** — all backend interaction is faked via `MockWebServer` (network-layer tests) or in-memory fakes (ViewModel/UI tests).
- `core-testing` provides: `MainDispatcherRule` (sets `Dispatchers.Main` to a `StandardTestDispatcher`), `MockWebServer` extensions, Moshi/Retrofit test builders, `createComposeRule()` plumbing, and shared fakes (`FakeNotificationsRepository`, `FakeAuthSession`).
- Web reference: `frontend/src/api/endpoints/notifications.ts` and `frontend/src/api/types.ts` (notification shape, read flags); OpenAPI at `/openapi.json`.
- Cross-reference test conventions established by AND-047 (repository contract tests), AND-048/049 (Compose UI tests), AND-069/076/083 (feature state/UI test suites). AND-050 (CI unit tests) and AND-051 (CI instrumented tests) run this suite.

## 3. Functional Requirements

FR-1. A JVM unit-test suite covers `NotificationsRepository` and `NotificationPagingSource`: first-page load, append (next-cursor) load, end-of-pagination, empty page, and HTTP error → `ApiResult.Error` with mapped `ApiError` message.

FR-2. The repository tests assert the request contract: path `GET /ui/notifications`, paging query params, and that the `X-CSRF-Token` header is present on the mark-read **mutations** (POST). GETs are idempotent and eligible for bounded backoff retry (AND-016); mutations are not retried.

FR-3. FastAPI `detail` mapping is tested for all three shapes: `detail` as a plain `string`, as `[{msg, ...}]`, and as `{code, ...}` — each resolves to the expected human-readable `ApiError.message`.

FR-4. `NotificationsViewModel` tests assert: `unreadCount` (`StateFlow<Int>`) is derived correctly from loaded items; marking a single item read decrements the badge and flips that item's `isRead`; "mark all read" drives `unreadCount` to 0 and flips all items; a failed mutation leaves state unchanged and surfaces an error event/state.

FR-5. `NotificationsUiState` transitions are asserted via Turbine: initial → loading → content; loading → error (non-connectivity); loading → offline (connectivity/timeout against the unreliable host).

FR-6. Compose UI test `NotificationCenterScreenTest` renders the screen from a fake `Flow<PagingData<NotificationUi>>` and asserts: rows render with title/body/timestamp; the list paginates (scrolling to the end appends the next page); the empty state renders when paging is empty; the error/append-error footer renders on page-load failure with a retry affordance.

FR-7. UI test asserts **read vs. unread** rows are visually distinguishable via a stable, testable signal (a `Modifier.semantics` `stateDescription` of "unread"/"read" and/or an unread-dot node tagged `notif_unread_dot`), not by pixel color.

FR-8. UI test asserts **tap → deep-link**: tapping a `NotificationRow` invokes the routing callback with the correct route string derived from the notification's `deepLink`/`target` payload; the test captures the emitted route and asserts equality.

FR-9. UI test asserts **mark all read**: invoking the top-bar action clears every row's unread treatment and the unread badge node disappears (or reads 0).

FR-10. The entire suite runs **headlessly** and passes in CI: JVM/Robolectric portions via `./gradlew :feature-notifications:testDebugUnitTest`, instrumented Compose portions via `:feature-notifications:connectedDebugAndroidTest` on the headless emulator (AND-051). No manual interaction, no real device features, no real network.

FR-11. Test-only production hooks are additive and minimal: stable `testTag`s (`notif_list`, `notif_row`, `notif_unread_dot`, `notif_mark_all_read`, `notif_unread_badge`) and an injectable time source for relative timestamps. These must not regress AND-085/AND-089 behavior.

## 4. Technical Design

Tests live under `feature-notifications/src/test/...` (JVM/Robolectric) and `feature-notifications/src/androidTest/...` (instrumented Compose), package `com.testlogon.android.feature.notifications`.

### 4.1 Fakes and rules (from `core-testing`)

```kotlin
class FakeNotificationsRepository(
    private val pages: MutableList<List<NotificationUi>> = mutableListOf(),
    var failOnPage: Int? = null,
    var markAllResult: ApiResult<Unit> = ApiResult.Success(Unit),
) : NotificationsRepository {
    val marked = mutableListOf<String>()
    override fun pager(): Flow<PagingData<NotificationUi>> = /* PagingData.from(...) */
    override suspend fun markRead(id: String): ApiResult<Unit> { marked += id; return ApiResult.Success(Unit) }
    override suspend fun markAllRead(): ApiResult<Unit> = markAllResult
    override val unreadCount: Flow<Int> get() = /* derived from pages */
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
@Test fun unreadCount_derivedFromItems() = runTest {
    val vm = NotificationsViewModel(FakeNotificationsRepository(pages = listOf(twoUnreadOneRead)))
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

This is a test ticket; it defines **no new API**. It asserts against the contract owned by AND-089 / AND-084 (core-network). For fixtures, the suite pins the expected shapes:

`GET /ui/notifications?cursor=<c>&limit=20` → 200:

```json
{
  "items": [
    { "id": "n_01", "title": "Run finished", "body": "Suite #482 passed",
      "created_at": "2026-06-05T11:02:00Z", "is_read": false,
      "deep_link": "tl://run/482", "category": "runs" }
  ],
  "next_cursor": "cursor_2"
}
```

`POST /ui/notifications/{id}/read` and `POST /ui/notifications/read_all` → 200 `{ "ok": true }`; both carry `X-CSRF-Token` (echoed from `ui_csrf` cookie) and ride the cookie session. Error fixtures cover FastAPI `detail` as `string`, `[{msg}]`, and `{code,...}`. Exact paths/params are owned upstream; if they differ at integration time, the fixtures and `MockWebServer` `RecordedRequest` path assertions are the single point of update.

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
- **R3 — Endpoint paths/params** (`next_cursor` vs offset; `read_all` path) may differ from upstream; `RecordedRequest` assertions centralize the fix.
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

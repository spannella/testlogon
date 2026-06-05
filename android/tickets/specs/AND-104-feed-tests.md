---
id: AND-104
title: Feed tests
milestone: M2
epic: E14
priority: P1
size: M
status: draft
depends_on: [AND-098, AND-102]
blocks: []
---

# AND-104 — Feed tests

## 1. Overview & Goal

This ticket delivers the automated test suite that locks in the behavior of the
newsfeed feature implemented in AND-097 (API + DTOs), AND-098 (Paging 3 list +
UI), and AND-102 (Feed ViewModel + state). It produces no new production code;
its single deliverable is a reliable, fast, headless test corpus that proves the
feed loads, paginates, refreshes, and degrades gracefully under the unreliable
dev backend.

The goal is concrete and measurable: a green `./gradlew :feature-feed:test
:feature-feed:connectedDebugAndroidTest` (or, preferably, an emulator-free
Robolectric + Compose UI test run) that exercises the `PagingSource`/`PagingData`
flow, the `FeedViewModel` state machine, the FastAPI `detail` error mapping, and
the Compose list rendering including loading/error footers and the paywall-locked
post variant. "Tests pass headlessly" (the source acceptance bullet) means every
test in scope runs in CI on a JVM/Robolectric runtime with no attached device,
no live network, and no flakiness across 20 consecutive runs.

Out of scope: changing feed production behavior, adding new feed endpoints,
end-to-end tests against the live `http://18.222.237.167:8000` host (covered by a
separate smoke-test ticket), and screenshot/snapshot regression tooling.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Feature module under test: `feature-feed`. Namespace base:
  `com.testlogon.android`; feature package `com.testlogon.android.feature.feed`.
- Upstream tickets supplying the system under test:
  - **AND-097** — `FeedApi` Retrofit interface, DTOs (`PostDto`, `MediaDto`,
    paywall flags), `FeedRepository`, page mapping incl. locked/paywall metadata.
  - **AND-098** — `FeedPagingSource`, `FeedScreen`/`FeedList` Composables,
    refresh, pagination loading/error footers.
  - **AND-102** — `FeedViewModel` exposing `StateFlow<FeedUiState>`, refresh,
    error/offline handling.
- Web reference for parity: `frontend/src/api/endpoints/newsfeed.ts` and shared
  types in `frontend/src/api/types.ts`; OpenAPI at `/openapi.json`.
- Test infrastructure module: `core-testing` (shared rules, fakes, dispatcher
  control, `MockWebServer` helpers, JSON fixtures). This ticket extends
  `core-testing` only with feed-specific fixtures, not with new generic utilities.
- Stack relevant to testing: Kotlin 2.0.21, Coroutines/Flow, Paging 3, Retrofit
  2.11 + OkHttp 4.12 + Moshi 1.15, Jetpack Compose + Material 3, Hilt (KSP).
  JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

The test suite must verify the following observable behaviors of the feed:

1. **Paging happy path.** Given a backend returning a first page with a
   `next_cursor`, the `FeedPagingSource` loads page 1, then loads page 2 when the
   `next_cursor` is supplied, and stops paging (sets `nextKey = null`) when the
   backend returns `next_cursor: null`.
2. **Refresh.** Invoking refresh re-invalidates the `PagingSource` and emits a
   fresh first page; the ViewModel surfaces `LoadState.Loading` during refresh
   and `NotLoading` on completion.
3. **Append error footer.** A failing page-2 request produces
   `LoadState.Error` for `append`, mapped to a typed, user-facing message; a
   subsequent `retry()` succeeds and clears the error.
4. **Empty feed.** A first page with zero items yields the empty UI state, not a
   spinner or an error.
5. **Paywall/locked posts.** Posts with `is_locked: true` map to the locked
   variant; the test asserts the locked post DTO -> domain mapping and the
   Compose rendering of the lock affordance (no media URL leaked for locked
   items).
6. **Error/offline state.** Network failure on the initial load yields
   `FeedUiState` refresh-error/offline (per AND-102), distinguishable from an
   append error.
7. **FastAPI `detail` mapping.** The three `detail` shapes — `string`,
   `[{msg}]`, `{code,...}` — each map to the correct `ApiResult.Failure`/message,
   verified at the repository layer.
8. **401 refresh-and-retry.** A 401 on a feed GET triggers exactly one
   `POST /ui/session/refresh` then one retry; a second 401 surfaces an auth
   error and does not loop.

All tests run headlessly (JVM + Robolectric for Compose/Android-framework
classes) with no live network and deterministic dispatchers.

## 4. Technical Design

### Source set layout

```
feature-feed/
  src/test/kotlin/com/testlogon/android/feature/feed/
    FeedPagingSourceTest.kt
    FeedViewModelTest.kt
    FeedRepositoryErrorMappingTest.kt
  src/test/kotlin/com/testlogon/android/feature/feed/ui/   // Robolectric
    FeedScreenTest.kt
    FeedListFootersTest.kt
core-testing/
  src/main/kotlin/com/testlogon/android/core/testing/
    MainDispatcherRule.kt          // existing
    MockWebServerExtensions.kt     // existing; extend enqueueJson(...)
    feed/FeedFixtures.kt           // NEW: JSON + DTO/domain fixtures
  src/main/resources/fixtures/feed/
    page1.json  page2.json  page_empty.json  locked_post.json
    error_detail_string.json  error_detail_list.json  error_detail_obj.json
```

Compose UI tests live in `src/test` (not `src/androidTest`) using Robolectric so
they run on the JVM headlessly. The module enables this in
`feature-feed/build.gradle.kts`:

```kotlin
android {
    testOptions {
        unitTests {
            isIncludeAndroidResources = true   // Robolectric resources
            isReturnDefaultValues = true
        }
    }
}
dependencies {
    testImplementation(project(":core-testing"))
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)        // runTest, StandardTestDispatcher
    testImplementation(libs.turbine)                         // StateFlow assertions
    testImplementation(libs.androidx.paging.testing)         // asSnapshot, TestPager
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
```

### Deterministic concurrency

A shared `MainDispatcherRule(testDispatcher: TestDispatcher = StandardTestDispatcher())`
in `core-testing` installs `Dispatchers.setMain`. All ViewModel and repository
tests use `runTest { ... }`. Production code must already inject a
`@Dispatcher(IO)` `CoroutineDispatcher` (verify AND-097/AND-102 expose it via
Hilt); tests pass `StandardTestDispatcher()` so paging emissions are advanced
explicitly with `advanceUntilIdle()`.

### Paging tests

Use Paging 3's `TestPager` for unit-level `PagingSource` assertions and
`AsyncPagingDataDiffer`/`PagingData.asSnapshot {}` for ViewModel-level flow
assertions.

```kotlin
class FeedPagingSourceTest {
    @get:Rule val mainRule = MainDispatcherRule()
    private val server = MockWebServer()
    private lateinit var api: FeedApi
    private lateinit var source: FeedPagingSource

    @Test fun `loads first page and exposes next cursor`() = runTest {
        server.enqueueJson("fixtures/feed/page1.json")
        val pager = TestPager(PagingConfig(pageSize = 20), source)
        val result = pager.refresh() as PagingSource.LoadResult.Page
        assertEquals(20, result.data.size)
        assertEquals("CURSOR_P2", result.nextKey)
    }

    @Test fun `stops paging when next cursor is null`() = runTest {
        server.enqueueJson("fixtures/feed/page1.json")
        server.enqueueJson("fixtures/feed/page2.json")   // next_cursor: null
        val pager = TestPager(PagingConfig(pageSize = 20), source)
        pager.refresh()
        val last = pager.append() as PagingSource.LoadResult.Page
        assertNull(last.nextKey)
    }

    @Test fun `append failure returns LoadResult Error`() = runTest {
        server.enqueueJson("fixtures/feed/page1.json")
        server.enqueue(MockResponse().setResponseCode(503))
        val pager = TestPager(PagingConfig(pageSize = 20), source)
        pager.refresh()
        assertTrue(pager.append() is PagingSource.LoadResult.Error)
    }
}
```

### ViewModel tests

```kotlin
class FeedViewModelTest {
    @get:Rule val mainRule = MainDispatcherRule()

    @Test fun `pagingData snapshot reflects two pages`() = runTest {
        val vm = FeedViewModel(FakeFeedRepository(pages = listOf(PAGE1, PAGE2)))
        val items = vm.feed.asSnapshot { scrollTo(index = 25) }
        assertEquals(40, items.size)
    }

    @Test fun `refresh emits Loading then NotLoading`() = runTest {
        val repo = FakeFeedRepository(pages = listOf(PAGE1))
        val vm = FeedViewModel(repo)
        vm.uiState.test {
            vm.refresh()
            assertEquals(FeedUiState.Refreshing, awaitItem())
            assertTrue(awaitItem() is FeedUiState.Content)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test fun `initial network failure yields offline state`() = runTest {
        val vm = FeedViewModel(FakeFeedRepository(failWith = IOException()))
        vm.uiState.test {
            assertEquals(FeedUiState.Offline, awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }
}
```

`FakeFeedRepository` is a feed-specific fake in `core-testing/feed`, configurable
with a list of canned pages, a `failWith` throwable, and a per-call hook to
simulate the 401-then-success sequence.

## 5. API Contract

This is a Test ticket; it defines no new API surface. It consumes the AND-097
contract and asserts against it. The relevant feed endpoint and JSON shapes the
fixtures must mirror:

`GET /ui/newsfeed?cursor={cursor}&limit=20` (cookie-authenticated, with
`X-CSRF-Token` echoing the `ui_csrf` cookie). Success `200`:

```json
{
  "items": [
    {
      "id": "post_01H...",
      "author": { "id": "u_1", "display_name": "Ada", "avatar_url": "https://.../a.jpg" },
      "created_at": "2026-06-01T12:00:00Z",
      "text": "hello world",
      "media": [{ "id": "m_1", "type": "image", "url": "https://.../1.jpg", "hls_url": null }],
      "is_locked": false,
      "paywall": null
    },
    {
      "id": "post_01H...Z",
      "author": { "id": "u_2", "display_name": "Grace", "avatar_url": null },
      "created_at": "2026-06-01T11:00:00Z",
      "text": null,
      "media": [],
      "is_locked": true,
      "paywall": { "tier": "gold", "price_cents": 999 }
    }
  ],
  "next_cursor": "CURSOR_P2"
}
```

Last page sets `"next_cursor": null`. Error responses use the FastAPI `detail`
field; fixtures cover all three shapes:

```json
{ "detail": "Feed temporarily unavailable" }
{ "detail": [{ "loc": ["query","cursor"], "msg": "invalid cursor", "type": "value_error" }] }
{ "detail": { "code": "RATE_LIMITED", "retry_after": 30 } }
```

Tests assert that the locked item exposes no consumable `media[].url` in the
mapped domain model (paywall enforcement parity with the web app) and that each
`detail` shape maps to the corresponding `ApiResult.Failure` message/code.

## 6. Data & State Management

Tests assert the contract of the existing state types; they do not introduce new
ones. Expected shapes under test (owned by AND-102):

```kotlin
sealed interface FeedUiState {
    data object Loading : FeedUiState
    data object Refreshing : FeedUiState
    data class Content(val isEmpty: Boolean) : FeedUiState
    data object Offline : FeedUiState
    data class Error(val message: String) : FeedUiState
}
// vm.feed: Flow<PagingData<FeedPost>>; vm.uiState: StateFlow<FeedUiState>
```

State assertions are made with Turbine on `StateFlow<FeedUiState>` and with
`PagingData.asSnapshot {}` on the paging flow. Append/prepend `LoadState`
transitions are asserted via the `CombinedLoadStates` captured from the
`AsyncPagingDataDiffer` the snapshot API builds internally. No Room or DataStore
state is mutated by these tests; if AND-097 added a Room-backed
`RemoteMediator`, an additional in-memory Room (`Room.inMemoryDatabaseBuilder`)
fixture is added and torn down per test. Fixtures are loaded from classpath
resources via `MockWebServerExtensions.enqueueJson(path)` so the same JSON serves
both Moshi-decode unit tests and `MockWebServer` integration tests.

## 7. Error Handling & Resilience

The suite exists largely to prove resilience behavior:

- **Append vs refresh errors** are asserted separately so the UI can show a
  footer-retry vs a full-screen error.
- **Bounded retry for idempotent GETs.** A test enqueues N transient `503`s
  followed by a `200` and asserts the repository/OkHttp interceptor retries the
  GET up to the configured bound, then succeeds; a test with `bound+1` failures
  asserts the error surfaces rather than retrying forever.
- **Timeout.** Using `MockWebServer` `setBodyDelay`/`throttleBody` beyond the
  ~20s production timeout, a test (with a shortened test timeout injected via the
  OkHttp builder) asserts an `IOException`/timeout maps to `FeedUiState.Offline`.
- **401 single-refresh-then-retry.** A scripted dispatcher returns `401` for the
  feed GET, `200` for `POST /ui/session/refresh`, then `200` for the retried
  feed GET; the test asserts exactly one refresh call (`server.requestCount` /
  recorded paths) and a successful result. A second consecutive `401` asserts no
  refresh loop and an auth error.
- **Malformed JSON / null fields** (e.g., `avatar_url: null`, missing `media`)
  decode without crashing and map to safe defaults.

Test flakiness is itself a resilience concern: all timing uses
`StandardTestDispatcher` + `advanceUntilIdle()`; no `Thread.sleep` or wall-clock
delays are permitted.

## 8. Security & Privacy

- **Paywall enforcement test.** Asserts locked posts never expose a playable
  `url`/`hls_url` in the mapped domain object — preventing a client-side paywall
  bypass regression.
- **CSRF header.** A test asserts outgoing feed requests carry the
  `X-CSRF-Token` header sourced from the `ui_csrf` cookie (verified via
  `server.takeRequest().getHeader("X-CSRF-Token")`).
- **No real credentials or PII** in fixtures; author names/URLs are synthetic.
  Fixtures use `https://example.invalid/...` media URLs so a leaked fetch in a
  test cannot hit a real host.
- Tests must not log cookie values or tokens; assertions reference header
  presence, not value echoing into test logs.

## 9. Accessibility & i18n

- Compose UI tests assert key nodes carry content descriptions / merged
  semantics: the locked-post lock icon (`contentDescription = "Locked post"`),
  the retry footer button (`onNodeWithText` / role `Button`), and the empty-state
  message. Example:
  `composeRule.onNodeWithContentDescription("Locked post").assertIsDisplayed()`.
- User-facing error strings under assertion must come from string resources
  (`R.string.feed_error_*`), not hardcoded literals; a test reads the expected
  text via Robolectric's resource access so localization does not break the test.
- No new translatable strings are introduced by this ticket; it validates that
  AND-098's strings are resource-backed.

## 10. Telemetry & Logging

This ticket adds no production telemetry. It may assert (via a fake
`FeedAnalytics`/`Logger` injected into the ViewModel, if AND-102 defined one)
that a `feed_load_failed` event is emitted on refresh error and a
`feed_page_loaded` event on successful append, ensuring the analytics contract
is honored. If no analytics seam exists upstream, this section is N/A and the
event contract is owned by the future analytics ticket; tests will not stub a
non-existent interface. Test output itself logs via JUnit/Gradle to the CI
console for headless inspection.

## 11. Testing Strategy

| Layer | Test file | Runtime | Tooling | Key cases |
|---|---|---|---|---|
| PagingSource | `FeedPagingSourceTest` | JVM | `TestPager`, `MockWebServer` | first page, cursor end, append error, retry |
| Repository mapping | `FeedRepositoryErrorMappingTest` | JVM | Moshi, `MockWebServer` | 3 `detail` shapes, locked mapping, 401 refresh, retry bound, timeout |
| ViewModel | `FeedViewModelTest` | JVM | Turbine, `asSnapshot`, fakes | state transitions, offline, refresh, empty |
| Compose UI | `FeedScreenTest`, `FeedListFootersTest` | Robolectric | `createComposeRule` | list render, loading/error footers, locked variant, empty, a11y semantics |

Conventions: JUnit4 with backtick test names; one behavioral assertion theme per
test; AAA structure; `@After server.shutdown()`. Compose tests use
`createComposeRule()` (not `createAndroidComposeRule`) and drive `PagingData` via
`MutableStateFlow<PagingData<FeedPost>>` fed `PagingData.from(items)` and
`PagingData.from(items, sourceLoadStates = ...)` to force `LoadState.Loading`/
`Error` footers deterministically. Stability target: green across 20 repeated
runs (`./gradlew :feature-feed:test --rerun-tasks` x N in CI). Coverage goal:
all `FeedUiState` branches and all `LoadResult`/`LoadState` branches exercised.

Run commands (headless):
```
./gradlew :feature-feed:testDebugUnitTest
./gradlew :feature-feed:test     # includes Robolectric UI tests, no device
```

## 12. Dependencies & Sequencing

- **Blocked by AND-098** (Paging source + UI list/footers) and **AND-102**
  (ViewModel + state) — both must be merged before these tests can compile, since
  they reference `FeedPagingSource`, `FeedViewModel`, `FeedUiState`, and the feed
  Composables. Transitively depends on **AND-097** for `FeedApi`/DTOs/repository.
- Requires `core-testing` with `MainDispatcherRule`, `MockWebServer` helpers, and
  Turbine/Paging-testing dependencies wired into the version catalog (`libs`). If
  `androidx.paging:paging-testing` and `turbine` are absent from `libs.versions.toml`,
  this ticket adds them.
- Blocks: none directly, but is a release gate for the M2 feed milestone (E14)
  and a prerequisite for enabling the feed in CI's required-checks list.
- Sequencing: implement repository/PagingSource tests first (most stable
  surface), then ViewModel, then Robolectric UI last.

## 13. Risks & Open Questions

1. **Robolectric + Compose flakiness/perf.** Compose-on-Robolectric can be slow
   and occasionally flaky. Mitigation: keep UI tests focused on footers/locked/
   empty rendering; if instability persists, fall back to a thin
   `connectedAndroidTest` subset gated behind a CI emulator job. Open question:
   does CI already provision Robolectric SDK jars offline?
2. **Paging testing API surface.** `asSnapshot`/`TestPager` are still evolving;
   pin `androidx.paging:paging-testing` to the version matching Paging 3.x in the
   catalog. Open question: exact version aligned with the app's Paging dependency.
3. **Upstream seams.** Tests assume injectable `CoroutineDispatcher` and a
   repository interface that a fake can implement. If AND-097/AND-102 used
   concrete classes, a small refactor (extract interface) is required — flag to
   those tickets rather than mocking finals.
4. **Analytics seam** existence (see §10) is unconfirmed.
5. **RemoteMediator?** If the feed caches to Room, additional in-memory DB tests
   are needed; confirm whether AND-097 added a `RemoteMediator`.

## 14. Acceptance Criteria

1. `./gradlew :feature-feed:testDebugUnitTest` and the Robolectric Compose tests
   pass **headlessly** with no attached device and no live network — directly
   satisfying the source acceptance bullet "Tests pass headlessly."
2. `FeedPagingSourceTest` proves: first-page load, `next_cursor` propagation,
   end-of-pagination (`nextKey == null`), append error -> `LoadResult.Error`, and
   successful `retry`.
3. `FeedViewModelTest` proves: two-page snapshot via `asSnapshot`, refresh
   `Refreshing -> Content` transition, empty-feed state, and initial-failure ->
   `Offline`.
4. `FeedRepositoryErrorMappingTest` proves all three FastAPI `detail` shapes map
   correctly, locked posts expose no media URL, the 401-> single
   `/ui/session/refresh` -> retry sequence, the bounded GET retry, and timeout ->
   offline.
5. Compose tests assert loading footer, error footer + retry, locked-post
   variant, empty state, and required a11y semantics (lock content description,
   retry button).
6. Suite is green across 20 consecutive CI runs (no flakes); no `Thread.sleep`
   or wall-clock delays present.
7. New shared fixtures/fakes live in `core-testing`; no production feed code is
   modified except non-behavioral seam extraction explicitly attributed to
   AND-097/AND-102.

## 15. Definition of Done

- All test files above implemented under `feature-feed/src/test`, compiling and
  green headlessly on CI (JDK 17, Gradle 8.9, AGP 8.7.3).
- `feature-feed/build.gradle.kts` enables `unitTests.isIncludeAndroidResources`
  and declares the test dependencies; `libs.versions.toml` updated with
  `turbine` and `paging-testing` if missing.
- Feed JSON fixtures and `FakeFeedRepository`/`FeedFixtures` added to
  `core-testing` and reused by tests.
- Branch off `android-port`, PR opened with the green CI run linked; the feed
  test job added to required checks for E14/M2.
- All AND-104 acceptance criteria (§14) verified; no new lint/detekt warnings;
  reviewer sign-off obtained. Open questions in §13 either resolved or filed as
  follow-up tickets referencing AND-097/AND-102.

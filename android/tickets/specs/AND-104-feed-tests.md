---
id: AND-104
title: Feed tests
milestone: M2
epic: E14
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- Web reference for parity: `src/api/endpoints/newsfeed.ts` (the feed list call is
  `getFeed()` -> `GET /feed`), `src/api/client.ts` (auth/CSRF/401-refresh
  transport), and shared types in `src/api/types.ts` (`FeedPost`); OpenAPI at
  `/openapi.json`. NOTE (review): there is **no** `GET /ui/newsfeed` list
  endpoint — the canonical feed read is `GET /feed`; see §16.
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
5. **Paywall/locked posts.** Posts with `locked: true` and `unlocked: false`
   (corrected from the draft's `is_locked` — see §16) map to the locked variant;
   the test asserts the locked post DTO -> domain mapping and the Compose
   rendering of the lock affordance (no `image_urls`/`video` URL leaked for
   locked items).
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
contract and asserts against it.

> **Review correction (see §16):** the earlier draft of this section asserted a
> `GET /ui/newsfeed` endpoint and a `{id, author{}, text, media[], is_locked,
> paywall{}}` post shape. Both are **wrong**. Verified against the OpenAPI index
> (`GET /feed | op=view_feed_feed_get`), the web client
> (`src/api/endpoints/newsfeed.ts: getFeed`), and the DTO
> (`src/api/types.ts: FeedPost`). The corrected contract the fixtures must mirror:

`GET /feed` with optional query params `cursor, author_id, q, from, to,
has_media` (the OpenAPI index also lists `limit`, but the web client does **not**
send it; the page size is server-defaulted). Transport is **bearer + cookie**:
`Authorization: Bearer <accessToken>` from the auth store, browser cookies via
`credentials: include`, and an `X-CSRF-Token` header echoing the `ui_csrf`
cookie (verified in `src/api/client.ts`). Success `200` returns
`{ items: FeedPost[]; next_cursor?: string }`:

```json
{
  "items": [
    {
      "post_id": "post_01H...",
      "author_id": "u_1",
      "created_at": "2026-06-01T12:00:00Z",
      "body": "hello world",
      "image_urls": ["https://example.invalid/1.jpg"],
      "video": null,
      "like_count": 0,
      "comment_count": 0,
      "locked": false,
      "unlocked": true
    },
    {
      "post_id": "post_01H...Z",
      "author_id": "u_2",
      "created_at": "2026-06-01T11:00:00Z",
      "body": "",
      "image_urls": [],
      "video": null,
      "like_count": 0,
      "comment_count": 0,
      "locked": true,
      "unlocked": false,
      "lock_type": "fixed_price",
      "unlock_price_cents": 999
    }
  ],
  "next_cursor": "CURSOR_P2"
}
```

Field notes (verified against `src/api/types.ts: FeedPost` and
`src/pages/feed/PostCard.tsx`): the id is `post_id` (not `id`); the author is a
flat `author_id` string (not a nested `author` object — display name/avatar are
resolved separately); post text is `body` (not `text`); media is `image_urls:
string[]` plus an optional `video` object with `hls_manifest_url` (not a generic
`media[]` array with `type`/`url`/`hls_url`); lock state is the pair `locked` +
`unlocked` (web computes `isLocked = !!post.locked && !post.unlocked`), with
pricing in `unlock_price_cents` and `lock_type` in `{"fixed_price",
"tip_lottery"}` (there is no `is_locked` boolean and no `paywall{tier,
price_cents}` object). The Android DTO names owned by AND-097 should match these
wire names; if AND-097 chose different Kotlin field names, the fixtures and the
`@Json(name=...)` mapping under test must still decode the wire shape above.

Last page sets `"next_cursor": null` (or omits it — the client types it
`next_cursor?: string`). Error responses use the FastAPI `detail` field;
fixtures cover all three shapes (verified against
`src/api/client.ts: normalizeErrorDetail`, which handles `string`, an array of
`{msg}`, and an object that may carry a `code`/`msg`):

```json
{ "detail": "Feed temporarily unavailable" }
{ "detail": [{ "loc": ["query","cursor"], "msg": "invalid cursor", "type": "value_error" }] }
{ "detail": { "code": "RATE_LIMITED", "retry_after": 30 } }
```

Tests assert that the locked item exposes no consumable media (no `image_urls`
entries and no `video.hls_manifest_url`) in the mapped domain model when
`locked && !unlocked` — paywall-enforcement parity with the web app, which gates
exactly on that condition (`src/pages/feed/PostCard.tsx`) — and that each
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

- **Paywall enforcement test.** Asserts locked posts (`locked && !unlocked`)
  never expose a playable URL — no populated `image_urls` and no
  `video.hls_manifest_url` — in the mapped domain object, preventing a
  client-side paywall bypass regression. (Corrected from the draft's
  `url`/`hls_url` field names — see §16.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`, `METHOD /path | op=..`), the
frontend reference app (`reference/src/...`), and Android framework docs (labeled
`framework ref`).

1. **Feed list endpoint is `GET /ui/newsfeed`.** VERDICT: **Corrected** ->
   `GET /feed`. SOURCE: OpenAPI `GET /feed | op=view_feed_feed_get`;
   `src/api/endpoints/newsfeed.ts: getFeed` calls `api.get("/feed", ...)`. There
   is no `GET /ui/newsfeed` in the index (only `/ui/newsfeed/delegate/*`
   creator-management routes).
2. **Query params are `cursor` + `limit=20`.** VERDICT: **Corrected**. SOURCE:
   OpenAPI `GET /feed ... params=limit,cursor,author_id,q,from,to,has_media`;
   `src/api/endpoints/newsfeed.ts: FeedQueryParams` sends `cursor, author_id, q,
   from, to, has_media` and does **not** send `limit` (server default page size).
   `limit` is accepted by the API but unused by the web client.
3. **Success response shape is `{ items, next_cursor }`.** VERDICT: **Verified**.
   SOURCE: `src/api/endpoints/newsfeed.ts: getFeed` ->
   `api.get<{ items: FeedPost[]; next_cursor?: string }>("/feed")`. `next_cursor`
   is optional (omitted/absent on last page); the spec's "`next_cursor: null`"
   convention is compatible with the optional field.
4. **Post id field is `id`.** VERDICT: **Corrected** -> `post_id`. SOURCE:
   `src/api/types.ts: FeedPost.post_id`.
5. **Post has a nested `author { id, display_name, avatar_url }`.** VERDICT:
   **Corrected** -> flat `author_id: string`; no nested author object on the post
   DTO. SOURCE: `src/api/types.ts: FeedPost.author_id`.
6. **Post text field is `text`.** VERDICT: **Corrected** -> `body: string`
   (with optional `body_plain`/`body_markdown`/`body_format`). SOURCE:
   `src/api/types.ts: FeedPost.body`.
7. **Media is a `media[]` array of `{ id, type, url, hls_url }`.** VERDICT:
   **Corrected** -> `image_urls: string[]` plus optional `video` object
   (`{ video_id, hls_manifest_url, playback_token, ... }`); no generic `media[]`.
   SOURCE: `src/api/types.ts: FeedPost.image_urls`, `FeedPost.video`.
8. **Locked posts use `is_locked: true`.** VERDICT: **Corrected** -> the pair
   `locked` + `unlocked`; web computes `isLocked = !!post.locked &&
   !post.unlocked`. SOURCE: `src/pages/feed/PostCard.tsx` (`const isLocked =
   !!post.locked && !post.unlocked`). Note: `locked` is read on `FeedPost` in the
   page but is not explicitly declared in the `FeedPost` interface excerpt —
   treat `locked`/`unlocked` as the authoritative wire fields per PostCard usage.
9. **Paywall metadata is `paywall { tier, price_cents }`.** VERDICT:
   **Corrected** -> `lock_type` (`"fixed_price" | "tip_lottery"`),
   `unlock_price_cents`, `unlock_limit`/`unlock_count`/`unlock_limit_reached`,
   `lock_expired`. There is no `paywall` object or `tier`/`price_cents` fields.
   SOURCE: `src/api/types.ts: FeedPost` (lock_type/unlock_price_cents/...),
   `src/pages/feed/PostCard.tsx` (`post.unlock_price_cents`, `post.lock_type`).
10. **Locked posts must not expose playable media.** VERDICT: **Verified**
    (premise valid; field names corrected). SOURCE: `src/pages/feed/PostCard.tsx`
    gates `image_urls`, `video`, attachments, tags, polls behind `!isLocked`.
11. **CSRF: requests carry `X-CSRF-Token` sourced from the `ui_csrf` cookie.**
    VERDICT: **Verified**. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")`
    -> `headers.set("X-CSRF-Token", csrf)`).
12. **Auth is "cookie-authenticated".** VERDICT: **Corrected/expanded** -> the
    web client sends `Authorization: Bearer <accessToken>` (from the auth store)
    **and** cookies via `credentials: "include"` **and** `X-CSRF-Token`. SOURCE:
    `src/api/client.ts` (Authorization header + `credentials: "include"`).
    `/feed` in the index also lists `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` header
    params; the web client sets `X-IMPERSONATION-TOKEN` only when impersonating.
13. **401 triggers exactly one `POST /ui/session/refresh` then one retry; a
    second 401 surfaces an auth error and does not loop.** VERDICT: **Verified**.
    SOURCE: OpenAPI `POST /ui/session/refresh | op=ui_session_refresh_...`;
    `src/api/client.ts: refreshSession` (`fetch("/ui/session/refresh", { method:
    "POST", credentials: "include" })`) guarded by a single shared
    `refreshPromise`, retried once; a retry 401 calls `logout("session_expired")`.
14. **FastAPI `detail` has three shapes: `string`, `[{msg}]`, `{code,...}`.**
    VERDICT: **Verified**. SOURCE: `src/api/client.ts: normalizeErrorDetail`
    (handles `typeof detail === "string"`, `Array.isArray(detail)` mapping
    `item.msg`, and an object branch via `mapAuthorizationError` reading
    `detail.code`, plus a `detail.msg` fallback). The validation array item shape
    `{loc, msg, type}` matches FastAPI `HTTPValidationError`/`ValidationError`
    (OpenAPI `components.schemas.HTTPValidationError`).
15. **Network error maps to an offline state.** VERDICT: **Verified** (parity).
    SOURCE: `src/api/client.ts` catches `fetch` failure and throws
    `ApiError(0, "Network error")`; the Android equivalent maps an `IOException`
    to `FeedUiState.Offline`. The exact Android mapping is owned by AND-102 (see
    Open assumptions).
16. **Compose-on-JVM via Robolectric runs headlessly with
    `createComposeRule()`.** VERDICT: **Verified (framework ref)**. SOURCE:
    framework ref — Jetpack Compose testing
    (https://developer.android.com/develop/ui/compose/testing) and Robolectric
    (https://robolectric.org/). `createComposeRule()` is the host-side rule;
    `createAndroidComposeRule` is for an Activity.
17. **Paging 3 test APIs `TestPager` and `PagingData.asSnapshot {}` exist in
    `androidx.paging:paging-testing`.** VERDICT: **Verified (framework ref)**.
    SOURCE: framework ref — Paging testing guide
    (https://developer.android.com/topic/libraries/architecture/paging/test).
18. **Last-page sentinel `nextKey == null` ends pagination.** VERDICT:
    **Verified (framework ref)**, consistent with claim 3's wire data. SOURCE:
    framework ref — `PagingSource.LoadResult.Page.nextKey` semantics
    (https://developer.android.com/reference/kotlin/androidx/paging/PagingSource).

### Corrections made

- §2 / §5 / §16: feed list endpoint `GET /ui/newsfeed` -> **`GET /feed`**
  (`op=view_feed_feed_get`); the `/ui/newsfeed/*` routes are creator-delegation
  management, not the consumer feed read.
- §5: query params `cursor`+`limit=20` -> `cursor, author_id, q, from, to,
  has_media` (client omits `limit`).
- §5: post DTO field names rewritten to the verified `FeedPost` wire shape —
  `id`->`post_id`, `author{}`->`author_id`, `text`->`body`,
  `media[]`->`image_urls[]`+`video{}`, `is_locked`->`locked`(+`unlocked`),
  `paywall{tier,price_cents}`->`lock_type`+`unlock_price_cents`(+`unlock_*`).
- §5: example media URLs changed to `https://example.invalid/...` to align with
  the §8 no-real-host fixture rule.
- §2 / §5: auth description corrected from "cookie-authenticated" to bearer
  token + cookies (`credentials: include`) + `X-CSRF-Token`.
- §3.5 / §8: locked-post field references updated to `locked`/`unlocked` and
  `image_urls`/`video.hls_manifest_url`.
- Verified-and-kept (no change needed): `{ items, next_cursor }` response shape,
  CSRF-from-`ui_csrf`-cookie, the 401 -> single `/ui/session/refresh` -> one-retry
  -> logout-on-second-401 sequence, and the three FastAPI `detail` shapes.

### Open assumptions

- **Android-side DTO/domain names (AND-097).** The Kotlin `PostDto`/`FeedPost`
  field names and the `@Json(name=...)` wire mapping are owned by AND-097 and not
  present in the reference sources; tests must assert the **wire** shape in §5
  regardless of Kotlin property names. Unverifiable here because AND-097 code is
  not in the reference tree.
- **`FeedUiState` / `FeedViewModel` / `FeedPagingSource` exact APIs (AND-098,
  AND-102).** The state sealed interface, the `vm.feed`/`vm.uiState` surface, the
  injectable `CoroutineDispatcher`, and a fakeable repository interface are
  assumed from the spec; they are Android-port artifacts not in the reference
  app. Unverifiable until those tickets land (flagged in §13).
- **Exact `IOException` -> `Offline` mapping.** Web maps a fetch failure to a
  toast + `ApiError(0)`; the Android `Offline` mapping is an AND-102 contract,
  assumed but not verifiable from sources.
- **Bounded GET retry (§7).** The "retry transient 503s up to a bound" behavior
  (OkHttp interceptor) is not present in the web client (which has no
  feed-GET retry) and is an Android-port design assumption owned by AND-097.
- **Analytics seam (`feed_load_failed`/`feed_page_loaded`).** No such interface
  exists in the reference app; existence in AND-102 is unconfirmed (§10, §13).
- **`RemoteMediator`/Room caching.** Not evidenced in the reference (the web
  client uses `withOfflineCache`, a PWA IndexedDB layer, not Room); whether
  AND-097 added a Room `RemoteMediator` is unconfirmed (§13).
- **`limit` page size.** Server default is unknown from the sources; the spec's
  fixtures assume 20 items/page, which is a fixture convention, not a verified
  server constant.

## 17. Test Plan

Test IDs `TC-AND-104-NN`. All cases are designed to satisfy AC-1 (headless, no
device, no live network); the device/emulator column notes the runtime. Because
this is a pure-test ticket with no hardware-dependent production behavior
(no camera/biometrics/FCM/WebRTC/Telecom/streaming), **every case runs on the
JVM (JVM unit/Robolectric)** — none requires the physical Samsung A15 or the
`test35` emulator. The physical device / emulator are intentionally *not* used;
see the note after the coverage matrix.

- **TC-AND-104-01 — Paging happy path: first page + next cursor.**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric (local).
  Preconditions: `MockWebServer` enqueues `fixtures/feed/page1.json` (20 items,
  `next_cursor: "CURSOR_P2"`); `FeedApi` bound to `GET /feed`. Steps: build
  `TestPager(PagingConfig(pageSize=20), source)`; call `pager.refresh()`.
  Expected: result is `LoadResult.Page`, `data.size == 20`, `nextKey ==
  "CURSOR_P2"`; the recorded request path is `/feed` (not `/ui/newsfeed`) and
  carries no `limit` query param. Traces: AC-2.

- **TC-AND-104-02 — End of pagination (`nextKey == null`).**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric (local).
  Preconditions: enqueue `page1.json` then `page2.json` (`next_cursor` absent/
  null). Steps: `pager.refresh()`, then `pager.append()`. Expected: final
  `LoadResult.Page.nextKey == null`; no further append is attempted. Traces:
  AC-2.

- **TC-AND-104-03 — Append failure -> `LoadResult.Error`, then `retry()`
  succeeds.** Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
  Preconditions: enqueue `page1.json`, then `503`, then `page2.json`. Steps:
  `refresh()`; `append()` (gets Error); re-`append()` after the success is
  enqueued. Expected: first append is `LoadResult.Error`; the retried append is
  `LoadResult.Page`; error is cleared. Traces: AC-2, AC-5.

- **TC-AND-104-04 — Two-page ViewModel snapshot via `asSnapshot`.**
  Type: unit (JVM). Target: JVM unit/Robolectric (local). Preconditions:
  `FakeFeedRepository(pages = [PAGE1, PAGE2])`; `MainDispatcherRule`. Steps:
  `vm.feed.asSnapshot { scrollTo(25) }`. Expected: 40 items materialized in
  order. Traces: AC-3.

- **TC-AND-104-05 — Refresh emits `Refreshing -> Content`.**
  Type: unit (JVM, Turbine). Target: JVM unit/Robolectric. Preconditions:
  `FakeFeedRepository(pages = [PAGE1])`. Steps: `vm.uiState.test { vm.refresh();
  ... }`. Expected: `awaitItem()` yields `FeedUiState.Refreshing` then
  `FeedUiState.Content`. Traces: AC-3.

- **TC-AND-104-06 — Empty feed -> empty `Content`, not spinner/error.**
  Type: unit (JVM). Target: JVM unit/Robolectric. Preconditions:
  `page_empty.json` (`items: []`, `next_cursor: null`). Steps: load feed via
  fake/repo. Expected: `FeedUiState.Content(isEmpty = true)`; paging snapshot is
  empty; no `Error`/`Loading` terminal state. Traces: AC-3.

- **TC-AND-104-07 — Initial network failure -> `Offline`.**
  Type: unit (JVM). Target: JVM unit/Robolectric. Preconditions:
  `FakeFeedRepository(failWith = IOException())` (mirrors web's `ApiError(0,
  "Network error")`). Steps: collect `vm.uiState`. Expected: first emitted state
  is `FeedUiState.Offline` (distinct from append error). Traces: AC-3, AC-4.
  Note: this is the flaky-dev-host/offline path, simulated deterministically;
  no real network is used (AC-1).

- **TC-AND-104-08 — FastAPI `detail` mapping, all three shapes.**
  Type: contract/MockWebServer + unit (JVM). Target: JVM unit/Robolectric.
  Preconditions: `error_detail_string.json` (`{"detail":"..."}`),
  `error_detail_list.json` (`{"detail":[{"loc":[...],"msg":"invalid
  cursor","type":"value_error"}]}`), `error_detail_obj.json`
  (`{"detail":{"code":"RATE_LIMITED","retry_after":30}}`). Steps: decode each at
  the repository layer. Expected: string -> message = the string; list ->
  message = joined `msg` values ("invalid cursor"); object -> `code` surfaced
  (e.g. `RATE_LIMITED`) per `mapAuthorizationError`/fallback parity. Each maps to
  `ApiResult.Failure`. Traces: AC-4.

- **TC-AND-104-09 — 401 -> single `/ui/session/refresh` -> one retry succeeds.**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
  Preconditions: scripted dispatcher: `GET /feed`->401, `POST
  /ui/session/refresh`->200, `GET /feed`->200(`page1.json`). Steps: trigger feed
  load. Expected: result succeeds; exactly one `/ui/session/refresh` recorded
  (assert via recorded paths / `requestCount`); exactly one feed retry. Traces:
  AC-4. Security-adjacent.

- **TC-AND-104-10 — Second consecutive 401 -> auth error, no refresh loop.**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
  Preconditions: `GET /feed`->401, `/ui/session/refresh`->200, retried `GET
  /feed`->401. Steps: trigger load. Expected: an auth error surfaces (parity:
  web calls `logout("session_expired")`); only one refresh attempted; no
  infinite loop. Traces: AC-4. Security case.

- **TC-AND-104-11 — Paywall enforcement: locked post leaks no media URL.**
  Type: unit (JVM). Target: JVM unit/Robolectric. Preconditions:
  `locked_post.json` with `locked:true, unlocked:false, lock_type:"fixed_price",
  unlock_price_cents:999, image_urls:["https://example.invalid/x.jpg"]`. Steps:
  map DTO -> domain. Expected: domain model for a locked post exposes **no**
  playable `image_urls` and no `video.hls_manifest_url`; only the
  unlock-affordance fields (`unlock_price_cents`, `lock_type`) remain. Traces:
  AC-4. Security case (paywall bypass regression).

- **TC-AND-104-12 — CSRF header present on the feed GET.**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
  Preconditions: a `ui_csrf` value available to the OkHttp CSRF interceptor;
  `page1.json` enqueued. Steps: perform feed load; `server.takeRequest()`.
  Expected: request to `/feed` carries `X-CSRF-Token` equal to the `ui_csrf`
  value; the token value is **not** written to test logs (assert presence/equality
  only). Traces: AC-4. Security case.

- **TC-AND-104-13 — Timeout -> `Offline`.**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
  Preconditions: `MockWebServer` `setBodyDelay`/`throttleBody` beyond a shortened
  OkHttp read timeout injected for the test. Steps: trigger initial load.
  Expected: timeout `IOException` maps to `FeedUiState.Offline`; no
  `Thread.sleep` in the test (uses MockWebServer delay + test dispatcher).
  Traces: AC-4, AC-6.

- **TC-AND-104-14 — Compose UI: loading footer, error footer + retry, locked
  variant, empty state, and a11y semantics.** Type: Compose-UI / Robolectric
  (JVM, `createComposeRule`). Target: JVM unit/Robolectric (local, headless).
  Preconditions: drive `FeedScreen`/`FeedList` via
  `MutableStateFlow<PagingData<FeedPost>>` using `PagingData.from(items)` and
  `PagingData.from(items, sourceLoadStates = ...)` to force `LoadState.Loading`
  and `LoadState.Error` footers. Steps: render each variant. Expected: loading
  footer shown on `append=Loading`; error footer + a retry `Button` shown on
  `append=Error` and `retry()` is invocable; locked post renders the lock
  affordance and **no** media; empty state shows the empty message; a11y:
  `onNodeWithContentDescription("Locked post").assertIsDisplayed()` and the retry
  button is reachable by role/text. Error/empty strings come from
  `R.string.feed_error_*` resources (Robolectric resource access), not literals.
  Traces: AC-5. Accessibility coverage.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
|---|---|
| AC-1 (headless, no device, no live network) | All TCs (TC-01..TC-14 run on JVM/Robolectric) |
| AC-2 (PagingSource: first page, cursor, end, append error, retry) | TC-01, TC-02, TC-03 |
| AC-3 (ViewModel: 2-page snapshot, refresh, empty, offline) | TC-04, TC-05, TC-06, TC-07 |
| AC-4 (repo: 3 `detail` shapes, locked no media, 401 refresh+retry, bounded retry, timeout->offline) | TC-08, TC-09, TC-10, TC-11, TC-12, TC-13 |
| AC-5 (Compose: loading/error footers + retry, locked variant, empty, a11y) | TC-03 (retry), TC-14 |
| AC-6 (green x20, no `Thread.sleep`/wall-clock) | TC-07, TC-13 (deterministic dispatchers/MockWebServer delay); enforced repo-wide by convention across all TCs |
| AC-7 (fixtures/fakes in `core-testing`; no prod change) | TC-04..TC-08, TC-11 (use `FakeFeedRepository`/`FeedFixtures`) |

**Device-selection note.** Per the available CI targets, the physical Samsung
Galaxy A15 (SM-A156U, API 34) and the `test35` emulator (API 35) are reserved
for hardware/ABI-sensitive behavior (camera/KYC, biometrics/passkeys, FCM,
WebRTC, Telecom, real HLS, arm64-vs-x86 / API34-vs-35). AND-104 exercises none of
those — it is paging/state/error/UI logic — so all cases are pinned to the
JVM/Robolectric runtime to satisfy the "tests pass headlessly" acceptance bullet
with maximum speed and determinism. If §13's Robolectric-Compose flakiness risk
materializes, TC-AND-104-14 may be promoted to an instrumented variant on the
`test35` emulator (KVM-accelerated CI), not the physical device.

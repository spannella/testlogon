---
id: AND-096
title: Tests
milestone: M2
epic: E13
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-095]
blocks: []
---

# AND-096 — Tests

## 1. Overview & Goal

This ticket delivers the automated test coverage for Epic E13 ("Activity, Saved & Achievements") of the TestLogon native Android port. E13 ships four user-facing surfaces — the Activity feed (AND-091), Saved/Bookmarks (AND-092), Achievements — earned badges + progress (AND-093; the web "earned/locked" framing maps to the My Badges tab `/ui/achievements` for earned and the Progress tab `/ui/achievements/progress` for not-yet-earned) and the Achievements leaderboard (AND-094) — plus the shared ViewModel/paging layer that drives them (AND-095). Those tickets each carry a thin "tested" acceptance bullet; AND-096 is the consolidating test ticket whose scope is **"Repo + UI smoke tests"** and whose acceptance is simply **"Tests pass."**

The goal is a deterministic, offline (no live backend) test suite that:

1. **Repository tests** — verify the four E13 repositories correctly map FastAPI JSON to `core-model` types, surface `ApiResult<T>` success/error/loading states, honour the unsave mutation flow, and feed Paging 3 `PagingSource` pages.
2. **ViewModel tests** — verify the AND-095 ViewModels reduce repository output into `StateFlow<UiState>` transitions (Loading → Content/Empty/Error), and that user intents (refresh, unsave, paginate) produce the expected state.
3. **UI smoke tests** — Compose UI tests that launch each of the four screens against fake ViewModels and assert that the primary content, empty, and error states render and that the key interaction (unsave) is wired.

"Tests pass" is interpreted concretely: `./gradlew :feature-activity:test :feature-saved:test :feature-achievements:test` (JVM unit tests) and the Compose UI smoke suite (instrumented or Robolectric) are green in CI, with the E13 line coverage gate met (see §11, §15).

This is a **test-only** ticket. It must not change production behaviour; any production code touched is limited to test-visibility refactors (e.g. extracting an interface, exposing a constructor for injection) explicitly called out in code review.

## 2. Context & References

- **Epic E13 feature tickets** (the code under test):
  - AND-091 Activity feed — `activityFeed.ts` API + paged screen.
  - AND-092 Saved / bookmarks — `bookmarks.ts` (`/ui/bookmarks`) API + screen; unsave via bookmark delete. (CORRECTION: there is no `/ui/saved` endpoint; "Saved" is the bookmarks surface — verified against `src/api/endpoints/bookmarks.ts` and OpenAPI `GET /ui/bookmarks`.)
  - AND-093 Achievements — `achievements.ts` API + screen. (CORRECTION: the web client has no single "earned/locked" response. `GET /ui/achievements` returns only EARNED achievements `{achievements, total_points, achievement_count}`; "locked"/progress-to-next is the separate Progress tab via `GET /ui/achievements/progress`.)
  - AND-094 Achievements leaderboard — `GET /ui/achievements/leaderboard/me?period={p}` (my rank) and `GET /ui/achievements/leaderboard?period=&limit=&cursor=` (full board).
  - **AND-095 ViewModels (activity/saved/achievements)** — direct dependency; supplies the `StateFlow<UiState>` + Paging 3 layer this ticket exercises. AND-096 cannot start until AND-095 lands.
- **Web reference**: `src/api/endpoints/activityFeed.ts`, `src/api/endpoints/bookmarks.ts`, `src/api/endpoints/achievements.ts`; shared types `src/api/types.ts`; transport/auth/CSRF in `src/api/client.ts`; screens `src/pages/activity/ActivityFeedPage.tsx`, `src/pages/saved/SavedPage.tsx`, `src/pages/achievements/{AchievementsPage,BadgeGrid,ProgressTracker,LeaderboardTable}.tsx`. Use these to confirm field names/shapes for fixtures. (Note: the bookmark DTOs `BookmarkItem`/`BookmarkListResponse` are declared inline in `bookmarks.ts`, not in `types.ts`.)
- **OpenAPI**: `http://18.222.237.167:8000/openapi.json` — source of truth for path params, query params, and error bodies. Captured fixtures must be byte-validated against schemas, not hand-invented.
- **Core test module**: `core-testing` — provides `MainDispatcherRule`, `TestDispatcherProvider`, a `MockWebServer` harness, JSON fixture loading, and Turbine helpers. AND-096 extends this module with E13 fixtures rather than duplicating infra.
- **Stack**: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Paging 3, JUnit4, MockWebServer, Turbine, Truth, Robolectric, Compose UI test. Namespace `com.testlogon.android`.

## 3. Functional Requirements

FR-1. Provide JVM unit tests for the four E13 repositories: `ActivityFeedRepository`, `SavedRepository`, `AchievementsRepository`, `LeaderboardRepository` (names per AND-091..094 implementations).

FR-2. Provide JVM unit tests for the three E13 ViewModels from AND-095: `ActivityFeedViewModel`, `SavedViewModel`, `AchievementsViewModel` (the latter backing both the achievements grid and the leaderboard tab).

FR-3. Provide Compose UI **smoke** tests for the four screens: `ActivityFeedScreen`, `SavedScreen`, `AchievementsScreen`, `LeaderboardScreen`. Smoke = render + one happy-path interaction + empty/error state visibility; not exhaustive snapshot coverage.

FR-4. All network interactions are faked. Repository tests use `MockWebServer`; ViewModel and UI tests use fakes/test-doubles of the repository interface. No test may contact `18.222.237.167` or any live host.

FR-5. Paging is tested deterministically: `PagingSource.load()` is invoked directly with `LoadParams.Refresh`/`LoadParams.Append`, asserting `LoadResult.Page` keys; `AsyncPagingDataDiffer` is used to assert items flow into the UI layer for at least one screen (Activity).

FR-6. The unsave mutation (AND-092) is tested end-to-end through the layer under test: a successful `DELETE` removes the item from emitted state; a failed `DELETE` leaves the list intact and emits a recoverable error.

FR-7. Error-state coverage: each repository test asserts mapping of FastAPI `detail` (string | `[{msg}]` | `{code,...}`) and of HTTP 401 → refresh-once-then-retry behaviour delegated to the network layer (asserted at the ViewModel boundary as a single retried success).

FR-8. The suite is runnable via Gradle without a device for the JVM portion and via a single Gradle task for the full E13 set; CI wires these (§12).

## 4. Technical Design

### Test source set layout

```
feature-activity/src/test/java/com/testlogon/android/feature/activity/
    ActivityFeedRepositoryTest.kt
    ActivityFeedViewModelTest.kt
    ActivityPagingSourceTest.kt
feature-activity/src/androidTest/java/.../ActivityFeedScreenTest.kt   // or test/ if Robolectric
feature-saved/src/test/java/com/testlogon/android/feature/saved/
    SavedRepositoryTest.kt
    SavedViewModelTest.kt
feature-saved/src/androidTest/java/.../SavedScreenTest.kt
feature-achievements/src/test/java/com/testlogon/android/feature/achievements/
    AchievementsRepositoryTest.kt
    LeaderboardRepositoryTest.kt
    AchievementsViewModelTest.kt
feature-achievements/src/androidTest/java/.../{AchievementsScreenTest,LeaderboardScreenTest}.kt
core-testing/src/main/java/com/testlogon/android/core/testing/e13/
    E13Fixtures.kt                // JSON loaders
    FakeActivityFeedRepository.kt
    FakeSavedRepository.kt
    FakeAchievementsRepository.kt
    fixtures/*.json
```

### Shared harness (in `core-testing`)

```kotlin
// Reused from core-testing; not re-implemented here.
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher()
) : TestWatcher()

fun MockWebServer.enqueueFixture(path: String, code: Int = 200)

object E13Fixtures {
    fun activityPage1(): String = load("fixtures/activity_feed_page1.json")
    fun activityPage2(): String = load("fixtures/activity_feed_page2.json")
    fun savedList(): String     = load("fixtures/saved_list.json")
    fun achievements(): String  = load("fixtures/achievements.json")
    fun leaderboardMe(): String = load("fixtures/leaderboard_me.json")
    fun errorDetailString(): String  // {"detail":"Not authorized"}
    fun errorDetailArray(): String   // {"detail":[{"msg":"..."}]}
    fun errorDetailObject(): String  // {"detail":{"code":"RATE_LIMITED"}}
}
```

### Repository test pattern (MockWebServer)

```kotlin
class ActivityFeedRepositoryTest {
    @get:Rule val mainRule = MainDispatcherRule()
    private val server = MockWebServer()
    private lateinit var repo: ActivityFeedRepository

    @Before fun setup() {
        server.start()
        val api = Retrofit.Builder()
            .baseUrl(server.url("/"))
            .addConverterFactory(MoshiConverterFactory.create(testMoshi))
            .build().create(ActivityApi::class.java)
        repo = ActivityFeedRepositoryImpl(api, mainRule.dispatcher)
    }
    @After fun tearDown() = server.shutdown()

    @Test fun `first page maps items and exposes next cursor`() = runTest {
        server.enqueueFixture("activity_feed_page1.json")
        val result = repo.loadActivity(cursor = null, limit = 20)
        assertThat(result).isInstanceOf(ApiResult.Success::class.java)
        val page = (result as ApiResult.Success).data
        assertThat(page.items).hasSize(20)
        assertThat(page.nextCursor).isEqualTo("eyJvIjoyMH0=")
        val req = server.takeRequest()
        assertThat(req.path).isEqualTo("/ui/activity/feed?limit=20")
    }

    @Test fun `401 surfaces Unauthorized for the auth interceptor to refresh`() = runTest {
        server.enqueueFixture("error_unauthorized.json", code = 401)
        assertThat(repo.loadActivity(null, 20))
            .isInstanceOf(ApiResult.Error.Unauthorized::class.java)
    }
}
```

### ViewModel test pattern (fake repo + Turbine)

```kotlin
class SavedViewModelTest {
    @get:Rule val mainRule = MainDispatcherRule()
    private val repo = FakeSavedRepository()
    private val vm by lazy { SavedViewModel(repo, mainRule.dispatcher) }

    @Test fun `unsave removes item and keeps list on success`() = runTest {
        repo.savedResult = ApiResult.Success(SavedList(items = sample3))
        vm.uiState.test {
            assertThat(awaitItem()).isEqualTo(SavedUiState.Loading)
            val loaded = awaitItem() as SavedUiState.Content
            assertThat(loaded.items).hasSize(3)
            repo.unsaveResult = ApiResult.Success(Unit)
            vm.onUnsave(loaded.items.first().id)
            assertThat((awaitItem() as SavedUiState.Content).items).hasSize(2)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test fun `unsave failure restores item and emits transient error`() = runTest {
        repo.savedResult = ApiResult.Success(SavedList(items = sample3))
        repo.unsaveResult = ApiResult.Error.Network
        vm.uiState.test {
            skipItems(2)
            vm.onUnsave(sample3.first().id)
            val s = awaitItem() as SavedUiState.Content
            assertThat(s.items).hasSize(3)        // optimistic rollback
            assertThat(s.transientError).isNotNull()
            cancelAndIgnoreRemainingEvents()
        }
    }
}
```

### Paging test pattern

```kotlin
class ActivityPagingSourceTest {
    @Test fun `append returns next page keyed by cursor`() = runTest {
        val source = ActivityPagingSource(FakeActivityApi(twoPages))
        val refresh = source.load(LoadParams.Refresh(null, 20, false)) as Page
        assertThat(refresh.nextKey).isEqualTo("eyJvIjoyMH0=")
        val append = source.load(LoadParams.Append("eyJvIjoyMH0=", 20, false)) as Page
        assertThat(append.data).hasSize(5)
        assertThat(append.nextKey).isNull()
    }
}
```

### Compose UI smoke pattern

```kotlin
@RunWith(AndroidJUnit4::class)
class AchievementsScreenTest {
    @get:Rule val compose = createComposeRule()

    @Test fun rendersEarnedAndLockedSections() {
        compose.setContent {
            TestLogonTheme {
                AchievementsScreen(state = AchievementsUiState.Content(earned, locked))
            }
        }
        compose.onNodeWithText("Earned").assertIsDisplayed()
        compose.onNodeWithTag("achievement_progress_${earned.first().id}").assertExists()
    }

    @Test fun showsErrorRetry() {
        compose.setContent {
            TestLogonTheme { AchievementsScreen(state = AchievementsUiState.Error("offline")) }
        }
        compose.onNodeWithTag("retry_button").assertIsDisplayed().performClick()
    }
}
```

UI tests prefer **stateless screen overloads** (state + lambdas) so no Hilt graph or live ViewModel is needed; this is the AND-095 contract (`@Composable fun ActivityFeedScreen(state, onRefresh, onUnsave, ...)`).

## 5. API Contract

AND-096 defines **no new endpoints**. It consumes the contracts owned by AND-091..094 and freezes them as fixtures. The contracts under test, captured from `/openapi.json`:

> CORRECTION: the shapes below were rewritten to match `/openapi.json` (`openapi.pretty.json`) and `src/api/types.ts`. The previously-listed `id/type/actor/target`, `/ui/saved`, `204`, and `{earned,locked}` / `{entries,me}` shapes were inaccurate.

- `GET /ui/activity/feed?cursor={c}&limit={n}` → `200 ActivityFeedResponse = {"items": ActivityOut[], "next_cursor": string|null, "total_unread": int}`. `ActivityOut`/`ActivityItem` fields: `activity_id`, `activity_type`, `actor_id`, `target_type`, `target_id`, `metadata` (object), `created_at` (int epoch), `read` (bool). (Verified: OpenAPI `GET /ui/activity/feed` → `ActivityFeedResponse`/`ActivityOut`; `src/api/types.ts: ActivityItem`, `ActivityFeedPageResponse`.) The web client sends `limit`/`cursor` only when truthy.
- `GET /ui/bookmarks?limit={n}&cursor={c}&content_type={t}&collection_id={id}` → `200 BookmarkListResponse = {"bookmarks": BookmarkItem[], "next_cursor"?: string, "total_count": int}`. `BookmarkItem` is keyed by composite (`content_type` ∈ {post,video}, `content_id`) plus `collection_id`, `created_at` (string), `content_preview {author_id, author_display_name?, body_snippet?, image_url?, like_count?}`. (Verified: OpenAPI `GET /ui/bookmarks`; `src/api/endpoints/bookmarks.ts: BookmarkListResponse`/`BookmarkItem`.) NOTE: response key is `bookmarks`, NOT `items`.
- `DELETE /ui/bookmarks/{content_type}/{content_id}` → `200 {"ok": true}` (unsave; mutation, NOT retried on failure). (Verified: OpenAPI `DELETE /ui/bookmarks/{content_type}/{content_id}`; `src/api/endpoints/bookmarks.ts: removeBookmark`.) NOTE: it is `200`, not `204`, and the key is the `(content_type, content_id)` pair, not a single `item_id`.
- `GET /ui/achievements?displayed=&category=` → `200 {"achievements": UserAchievement[], "total_points": int, "achievement_count": int}` (EARNED only). `UserAchievement` fields: `achievement_id`, `label`, `description`, `icon_url`, `rarity`, `points`, `unlocked_at` (int), `trigger_event`, `displayed` (bool). For "locked"/progress: `GET /ui/achievements/progress` → `{"progress": AchievementProgress[]}` where `AchievementProgress` has `metric_key`, `current_value`, `highest_value`, `next_threshold?`, `next_achievement?`. (Verified: OpenAPI `GET /ui/achievements`, `GET /ui/achievements/progress`; `src/api/endpoints/achievements.ts`, `src/api/types.ts: UserAchievement`/`AchievementProgress`.) NOTE: there is no `{earned, locked}` envelope; the web UI splits this across the "My Badges" tab (earned) and the "Progress" tab.
- `GET /ui/achievements/leaderboard/me?period={p}` → `200 LeaderboardEntry & {period}` (a flat single entry: `rank`, `user_sub`, `display_name`, `total_points`, `achievement_count`, `display_badges`, `period`). Full board: `GET /ui/achievements/leaderboard?period=&limit=&cursor=` → `{"entries": LeaderboardEntry[], "next_cursor"?: string, "period": string}`. (Verified: OpenAPI `GET /ui/achievements/leaderboard/me` + `/leaderboard`; `src/api/endpoints/achievements.ts: getMyRank`/`getLeaderboard`, `src/api/types.ts: LeaderboardEntry`.) NOTE: `me` is NOT `{entries, me:{rank,score,percentile}}` — it is one `LeaderboardEntry` row, and `period` is a REQUIRED query param. There is no `score`/`percentile` field; ranking uses `total_points`.

Error bodies tested for all GETs: FastAPI `detail` as string, `[{msg}]`, and `{code,...}`; plus `401` (refresh-once path) and `5xx`/timeout (offline/stale). All endpoints declare `422 HTTPValidationError` for validation failures (verified in OpenAPI index). Fixtures live in `core-testing/.../fixtures/`. A guard test asserts each fixture deserializes into its `core-model` DTO so drift from the real schema fails CI. Ownership of the live contracts remains with the feature tickets; AND-096 only validates fixtures against them.

## 6. Data & State Management

The suite asserts the `UiState` state machines defined by AND-095. Canonical sealed shapes the tests pin:

```kotlin
sealed interface ActivityUiState {
    data object Loading : ActivityUiState
    data class Content(val items: Flow<PagingData<ActivityItem>>) : ActivityUiState
    data object Empty : ActivityUiState
    data class Error(val message: String, val stale: Boolean) : ActivityUiState
}
sealed interface SavedUiState {
    data object Loading; data object Empty
    data class Content(val items: List<SavedItem>, val transientError: String? = null)
    data class Error(val message: String)
}
sealed interface AchievementsUiState { /* Loading / Content(earned,locked) / Empty / Error */ }
sealed interface LeaderboardUiState { /* Loading / Content(entries, me) / Empty / Error */ }
```

Assertions:
- Initial emission is always `Loading`.
- Successful load → `Content` (or `Empty` when the list is empty — a dedicated empty fixture per screen).
- Unsave: state drops the item, then commits on the `200 {"ok":true}` delete response or rolls back + sets `transientError` on failure. (CORRECTION: success status is `200`, not `204`.) UNVERIFIED ASSUMPTION — the *web* reference (`src/pages/saved/SavedPage.tsx`) is **pessimistic**: it calls `removeBookmark`, then `invalidateQueries(["bookmarks"])` to refetch on success and only shows a toast on error; it does NOT optimistically remove + roll back. The optimistic-with-rollback behaviour pinned here is an Android-side design choice owned by AND-092/AND-095, not a web contract. Tests must follow whatever AND-092/AND-095 actually ship; see §13 R4.
- `stale = true` is set when an error occurs but a previously cached `Content` exists (offline/stale path), asserted with a fake repo that first succeeds then fails on refresh.
- Paging state transitions (`LoadState.Loading`/`Error`/`NotLoading`) are asserted via `AsyncPagingDataDiffer.loadStateFlow` for Activity. No Room/DataStore writes are asserted here (cache behaviour is owned by `core-data` tickets); tests inject in-memory fakes.

## 7. Error Handling & Resilience

The tests are the resilience contract for E13:

- **Timeout / unreliable host**: a `MockWebServer` `SocketPolicy.NO_RESPONSE_BODY` / dispatcher delay > client timeout asserts the repository returns `ApiResult.Error.Network` (not a hang) and the ViewModel surfaces `Error(stale=…)` rather than crashing.
- **Bounded retry, GET-only**: assert idempotent GET repositories retry per the configured backoff (count requests on `MockWebServer`), while the unsave `DELETE` is attempted **exactly once** (assert `server.requestCount == 1` after a failed unsave). This guards the "retry idempotent GETs only" rule.
- **401 refresh-once**: enqueue `401` then `200`; assert the consumer observes a single successful result and that exactly one `/ui/session/refresh` occurred (the auth interceptor is exercised via an integration-style repo test with the real OkHttp client + MockWebServer).
- **Malformed JSON / null fields**: a corrupt fixture asserts a mapped `ApiResult.Error.Parse`, never an uncaught `JsonDataException`.
- **Empty vs error** are kept distinct (empty list ≠ failure).
- Test flakiness resilience: all coroutine tests use `runTest` with injected `TestDispatcher`; no `Thread.sleep`, no real time, `advanceUntilIdle()` for scheduled work.

## 8. Security & Privacy

No production security surface is added. Constraints for this ticket:
- **No real credentials, cookies, or CSRF tokens** in fixtures; auth headers in MockWebServer assertions use dummy values (`X-CSRF-Token: test-csrf`). Fixtures must not embed PII from the dev backend — actor/user names are synthetic (`user_001`).
- Tests must never write a persistent cookie jar to disk; the OkHttp client under test uses an in-memory `CookieJar` test double.
- No fixture or test log may contain the dev host IP as a *reachable* target — it appears only as documentation. A lint/CI check (`assertNoLiveHosts`) greps the test classpath for `18.222.237.167` outside comments and fails the build.
- Logging assertions confirm that auth tokens/cookie values are not emitted by the code under test (see §10).

## 9. Accessibility & i18n

UI smoke tests include lightweight a11y assertions, since they are the cheapest place to catch regressions:
- Each interactive node asserted via Compose UI test must have a content description or text label: `onNodeWithContentDescription("Remove from saved")` for the unsave affordance; `assertHasClickAction()` on retry.
- Assert no hard-coded user-visible string is passed where a `stringResource` is expected — UI tests read expected copy from `context.getString(R.string.…)` rather than literals, which also validates that strings are externalized for i18n.
- Touch-target/merge-semantics correctness is out of scope for *smoke* tests and deferred to a dedicated a11y audit ticket (not in E13). Note this explicitly so reviewers do not expect full a11y coverage here.

## 10. Telemetry & Logging

AND-096 does not emit telemetry. It asserts the telemetry/logging contract of the code under test where cheap:
- A fake `Analytics` interface is injected into ViewModels; tests assert that an `unsave` success logs `event = "saved_item_removed"` exactly once and that a failure logs `event = "saved_unsave_failed"` — guarding the analytics wiring without a real sink.
- A `RecordingLogger` (test double of the app's `Logger`) asserts that on a `401`/refresh path no cookie or CSRF value is logged (security cross-check, §8).
- Test execution itself produces a JUnit XML report and a JaCoCo coverage report consumed by CI (§11/§12). No production logging is added.

## 11. Testing Strategy

This ticket *is* the testing strategy for E13. Layers and counts (minimums):

| Layer | Tool | Files | Min cases |
|---|---|---|---|
| Repository | JUnit4 + MockWebServer + Moshi | 4 | 16 (success, empty, 401, parse/error-detail variants per repo) |
| Paging | JUnit4 + Paging 3 test APIs | 1+ | 3 (refresh, append, end-of-pagination) |
| ViewModel | JUnit4 + Turbine + fakes | 3 | 12 (loading→content, empty, error/stale, unsave success/rollback) |
| UI smoke | Compose UI test (Robolectric for JVM speed; instrumented fallback) | 4 | 8 (content + error/empty + 1 interaction per screen) |

- **Determinism**: injected `TestDispatcher`, `runTest`, no wall-clock, no network. Robolectric chosen for UI smoke so the JVM `test` task can run them in CI without a device; if a screen relies on a real `LazyColumn` scroll that Robolectric mis-renders, that single test falls back to `androidTest`.
- **Coverage gate**: JaCoCo line coverage ≥ 70% across the three E13 feature modules' `…repository` and `…viewmodel` packages. Screens are exempted from the line gate (smoke only) but must have ≥1 render test each.
- **Run commands**:
  - `./gradlew :feature-activity:testDebugUnitTest :feature-saved:testDebugUnitTest :feature-achievements:testDebugUnitTest`
  - `./gradlew :feature-activity:testDebugUnitTest` includes Robolectric UI smoke.
  - Optional instrumented: `./gradlew :feature-saved:connectedDebugAndroidTest`.
- **Fixtures-vs-schema guard**: `E13FixtureSchemaTest` deserializes every fixture into its DTO; failure means the contract drifted.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-095** — the ViewModels and `UiState`/Paging shapes must exist before their tests. AND-096 starts only after AND-095 merges.
- **Transitively** depends on AND-091, AND-092, AND-093, AND-094 (the repositories/screens) and on `core-testing` (harness) and `core-network` (auth interceptor under test in the 401 path).
- **Blocks**: nothing functionally, but it is the gate that lets the E13 epic be marked "done" and is wired into the CI quality gate, so feature merges to `android-port` should not be considered complete until AND-096's suite is green.
- **CI wiring**: add E13 test tasks to the existing `android-ci.yml` `unit-tests` job; add the JaCoCo report merge for the three feature modules. No new runner/device matrix needed if Robolectric is used for smoke.
- Sequencing note: write repository + paging tests first (most stable contract), then ViewModel tests, then UI smoke last (most likely to churn with design).

## 13. Risks & Open Questions

- **R1 — ViewModel API churn (AND-095):** if the `UiState` sealed shapes change after tests are written, the suite breaks. Mitigation: keep AND-096 PR stacked on the AND-095 PR; pin shapes in §6 and review together.
- **R2 — Robolectric vs Compose fidelity:** some Compose interactions (paging scroll, ExoPlayer-adjacent surfaces) render poorly under Robolectric. Mitigation: per-test fallback to instrumented `androidTest`; keep smoke tests shallow.
- **R3 — Fixture drift from the unreliable dev backend:** the dev host may return shapes not in `/openapi.json`. Mitigation: `E13FixtureSchemaTest` + capture fixtures from OpenAPI examples, not ad-hoc curl, where possible.
- **R4 — Optimistic unsave semantics undefined:** AND-092 says "unsave updates" but does not specify optimistic vs pessimistic. VERIFIED against the web reference: `src/pages/saved/SavedPage.tsx` is **pessimistic** — `removeBookmark(content_type, content_id)` then `invalidateQueries(["bookmarks"])` (refetch) on success, toast on error; no optimistic removal or rollback. **Open question for AND-092 owner**: does the Android port keep web parity (pessimistic) or intentionally go optimistic-with-rollback (as the §6/§4 examples assume)? Tests follow whatever AND-092/AND-095 ship; if pessimistic, the §6 rollback assertion is replaced by "item reappears after the failed refetch / list unchanged on error." NOTE: the delete returns `200 {"ok":true}`, not `204`.
- **R5 — Coverage gate strictness:** 70% may be unreachable if AND-095 ViewModels contain heavy paging glue. Mitigation: gate on repository+viewmodel packages only, exempt screens.

## 14. Acceptance Criteria

AC-1. Running `./gradlew :feature-activity:testDebugUnitTest :feature-saved:testDebugUnitTest :feature-achievements:testDebugUnitTest` exits 0 with **all** E13 unit + Robolectric smoke tests passing (satisfies source acceptance "Tests pass.").
AC-2. Each of the four repositories has a test asserting: success mapping, empty list, and at least one error path (401 and one `detail` variant).
AC-3. Paging is verified by direct `PagingSource.load()` assertions covering refresh, append, and end-of-pagination (`nextKey == null`).
AC-4. The unsave flow has both a success test (item removed) and a failure test (item restored + transient error, `DELETE` attempted exactly once).
AC-5. Each of the four screens has at least one Compose render test plus an error/empty-state test, and one screen (Activity) verifies `PagingData` reaches the UI via `AsyncPagingDataDiffer`.
AC-6. A 401-then-200 test proves refresh-once-and-retry is observed as a single success with exactly one `/ui/session/refresh`.
AC-7. `E13FixtureSchemaTest` passes, proving every fixture deserializes into its `core-model` DTO.
AC-8. `assertNoLiveHosts` confirms no test code targets `18.222.237.167`; no real credentials/cookies in fixtures.
AC-9. JaCoCo line coverage ≥ 70% over the E13 `repository` + `viewmodel` packages; report published in CI.
AC-10. No production behaviour change beyond reviewed test-visibility refactors.

## 15. Definition of Done

- All §14 acceptance criteria met and verified in CI on branch `android-port`.
- Test files created under the source-set layout in §4 with package root `com.testlogon.android.feature.{activity,saved,achievements}`.
- E13 fixtures and fakes added to `core-testing`; no duplication of harness code.
- E13 test tasks + JaCoCo merge wired into `android-ci.yml`; the `unit-tests` job is green and required for merge.
- Suite is deterministic: 50 consecutive local runs of the JVM suite show zero flakes (`--rerun-tasks` loop spot-check).
- No `Thread.sleep`, no live network, no hard-coded secrets in any test.
- Code reviewed and approved; coverage report attached to the PR; ticket linked to AND-095 and the E13 feature tickets it validates.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI index/spec (`reference/openapi.index.txt`, `reference/openapi.pretty.json`), frontend (`reference/src/...`), or framework refs (Android docs).

1. **Activity feed endpoint is `GET /ui/activity/feed` with `cursor`/`limit` query params.** Verified. OpenAPI `GET /ui/activity/feed` (op `get_activity_feed_...`, resp `200:ActivityFeedResponse`, params `cursor,limit,...`); `src/api/endpoints/activityFeed.ts: getActivityFeed`.
2. **Activity feed response is `{items, next_cursor, total_unread}`; items are `ActivityOut`/`ActivityItem` with `activity_id, activity_type, actor_id, target_type, target_id, metadata, created_at, read`.** Corrected (spec previously said items had `id/type/actor/target`). `components.schemas.ActivityFeedResponse` + `ActivityOut` in `openapi.pretty.json`; `src/api/types.ts: ActivityItem`, `ActivityFeedPageResponse`.
3. **"Saved" is the bookmarks surface; list is `GET /ui/bookmarks`, response `{bookmarks, next_cursor, total_count}`.** Corrected (spec previously claimed `GET /ui/saved` returning `{items, next_cursor}`). OpenAPI `GET /ui/bookmarks` (op `list_bookmarks_...`, params `limit,cursor,content_type,collection_id,...`); `src/api/endpoints/bookmarks.ts: BookmarkListResponse`, `getBookmarks`; `src/pages/saved/SavedPage.tsx`.
4. **Unsave is `DELETE /ui/bookmarks/{content_type}/{content_id}` → `200 {"ok":true}`.** Corrected (spec previously said `DELETE /ui/saved/{item_id}` → `204`). OpenAPI `DELETE /ui/bookmarks/{content_type}/{content_id}` (op `delete_bookmark_...`, resp `200`); `src/api/endpoints/bookmarks.ts: removeBookmark`.
5. **`GET /ui/achievements` returns EARNED achievements only: `{achievements, total_points, achievement_count}`; there is no `{earned, locked}` envelope.** Corrected. OpenAPI `GET /ui/achievements` (op `get_my_achievements_...`, params `displayed,category,...`); `src/api/endpoints/achievements.ts: getMyAchievements`; `src/pages/achievements/BadgeGrid.tsx` (renders `data.achievements`).
6. **Not-yet-earned / progress is the separate `GET /ui/achievements/progress` → `{progress: AchievementProgress[]}` (with `next_threshold`/`next_achievement`).** Verified. OpenAPI `GET /ui/achievements/progress` (op `get_all_progress_...`); `src/api/types.ts: AchievementProgress`; `src/pages/achievements/ProgressTracker.tsx`.
7. **`UserAchievement` fields: `achievement_id, label, description, icon_url, rarity, points, unlocked_at, trigger_event, displayed`.** Corrected (spec §5 had `id/name/progress/earned_at`). `src/api/types.ts: UserAchievement`.
8. **`GET /ui/achievements/leaderboard/me` requires a `period` query param and returns a single flat `LeaderboardEntry & {period}` (rank, user_sub, display_name, total_points, achievement_count, display_badges) — not `{entries, me}`, no `score`/`percentile`.** Corrected. OpenAPI `GET /ui/achievements/leaderboard/me` (op `get_my_rank_...`, params `period,...`); `src/api/endpoints/achievements.ts: getMyRank`; `src/api/types.ts: LeaderboardEntry`.
9. **Full leaderboard is `GET /ui/achievements/leaderboard?period=&limit=&cursor=` → `{entries, next_cursor, period}`.** Verified. OpenAPI `GET /ui/achievements/leaderboard` (op `get_leaderboard_endpoint_...`, params `period,limit,cursor,...`); `src/api/endpoints/achievements.ts: getLeaderboard`.
10. **CSRF: token is read from the `ui_csrf` cookie and sent as the `X-CSRF-Token` header.** Verified. `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`). Spec's `X-CSRF-Token: test-csrf` dummy is the correct header name.
11. **401 handling: refresh once via `POST /ui/session/refresh` (credentials included), then retry the original request exactly once; refresh is deduped via a shared promise, and only attempted if the user was already authenticated.** Verified. OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_...`, resp `200`); `src/api/client.ts` (`refreshSession`, `refreshPromise`, single `retryRes`, `isAuthenticated` guard).
12. **FastAPI `detail` normalization handles string, `[{msg}]` arrays, and object `{code,...}` forms.** Verified. `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError`. All listed endpoints also declare `422:HTTPValidationError` (OpenAPI index).
13. **Unsave UI semantics on the web are pessimistic (mutate → invalidate/refetch on success, toast on error), not optimistic-with-rollback.** Verified (web); the optimistic-rollback model in §4/§6 is an Android-side design choice. `src/pages/saved/SavedPage.tsx` (`removeMutation` + `invalidateQueries(["bookmarks"])`).
14. **Network error path: a fetch throwable maps to a network error (status 0), distinct from HTTP errors.** Verified. `src/api/client.ts` catch block (`new ApiError(0, "Network error", err)`). Supports the spec's `ApiResult.Error.Network` distinction.
15. **`createComposeRule`/`AndroidJUnit4` + `onNodeWith*`/`assertIsDisplayed`/`performClick` are the correct Compose UI test APIs; Robolectric can host these on the JVM `test` task.** Verified (framework ref): Compose testing — https://developer.android.com/develop/ui/compose/testing ; Robolectric — https://robolectric.org/ .
16. **Paging 3 is tested by invoking `PagingSource.load(LoadParams.Refresh/Append)` directly and via `AsyncPagingDataDiffer` for UI flow.** Verified (framework ref): https://developer.android.com/topic/libraries/architecture/paging/test .
17. **MockWebServer supports enqueued responses and `SocketPolicy` for timeout/no-response simulation.** Verified (framework ref): https://github.com/square/okhttp/tree/master/mockwebserver .

### Corrections made

- §1, §2, §5: "Saved" surface corrected from non-existent `/ui/saved` to the bookmarks API (`/ui/bookmarks`); list response key corrected from `items` to `bookmarks` (`{bookmarks, next_cursor, total_count}`).
- §5, §6, §13: Unsave corrected from `DELETE /ui/saved/{item_id}` → `204` to `DELETE /ui/bookmarks/{content_type}/{content_id}` → `200 {"ok":true}` (composite key, 200 not 204).
- §1, §2, §5: Achievements corrected — `GET /ui/achievements` returns earned-only `{achievements, total_points, achievement_count}`; the `{earned, locked}` envelope does not exist; "locked"/progress is `/ui/achievements/progress`. `UserAchievement` field names corrected.
- §5: Leaderboard-me corrected from `{entries, me:{rank,score,percentile}}` to a flat `LeaderboardEntry & {period}` with a REQUIRED `period` param; added the separate full-board endpoint shape.
- §5, §2: Activity item field names corrected to `activity_id/activity_type/actor_id/target_type/target_id/metadata/created_at/read`; response gains `total_unread`.
- §6, §13 R4: Flagged that the web reference is pessimistic (not optimistic-with-rollback); marked the optimistic model as an Android-side assumption pending AND-092/AND-095.

### Open assumptions

- **Android repository/ViewModel/screen class names** (`SavedRepository`, `ActivityFeedViewModel`, `SavedUiState`, `AchievementsScreen`, etc.) and the `ApiResult<T>`/`UiState` sealed shapes: Unverified-assumption. They originate in AND-091..095, which are not present in the reference sources (only the web client + OpenAPI are). Tests must pin to whatever those tickets actually ship.
- **Optimistic-vs-pessimistic unsave on Android**: Unverified-assumption. Web is pessimistic; the Android choice is owned by AND-092/AND-095 (see §13 R4).
- **`core-testing` harness APIs** (`MainDispatcherRule`, `enqueueFixture`, Turbine helpers): Unverified-assumption — not in the provided sources; assumed per the stack in §2.
- **JaCoCo 70% gate feasibility and exact package boundaries**: Unverified-assumption — depends on AND-095 implementation size (see §13 R5).
- **Activity feed request path exactly `/ui/activity/feed?limit=20` (param order/omission)**: Partially unverified — the web client omits `cursor`/`limit` when falsy, so the precise query string for the Android client depends on AND-091's Retrofit interface; treat the §4 path assertion as illustrative.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device). **emu(test35)** = headless AVD, x86_64, Android 15/API 35. **device** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R), Android 14/API 34, arm64-v8a. Most cases are deterministic JVM/Robolectric; UI smoke runs on JVM (Robolectric) with an `emu(test35)` fallback for any LazyColumn/scroll Robolectric mis-renders. No case here strictly requires the physical device (this ticket has no camera/biometric/FCM/WebRTC/Telecom/streaming surface); the device is named only where ABI/API-34-vs-35 parity is the point (TC-13).

- **TC-AND-096-01** — Activity feed first page maps DTO + cursor.
  Type: contract/MockWebServer. Target: JVM. Preconditions: `activity_feed_page1.json` fixture (20 `ActivityOut` items, `next_cursor` non-null). Steps: enqueue 200; call `repo.loadActivity(cursor=null, limit=20)`; inspect `ApiResult.Success`; `takeRequest()`. Expected: `Success`; `items.size==20`; `nextCursor` equals fixture value; mapped fields `activity_id/actor_id/created_at/read` populated; request hits `/ui/activity/feed` with `limit=20`. Traces: AC-2, AC-7.
- **TC-AND-096-02** — Empty activity feed → `Empty`/empty page.
  Type: contract/MockWebServer + unit. Target: JVM. Preconditions: empty fixture `{"items":[],"next_cursor":null,"total_unread":0}`. Steps: enqueue 200; load; pipe through ViewModel. Expected: repo returns `Success` with empty list; ViewModel emits `Loading` then `Empty` (not `Error`). Traces: AC-2.
- **TC-AND-096-03** — Bookmarks list maps `{bookmarks,next_cursor,total_count}`.
  Type: contract/MockWebServer. Target: JVM. Preconditions: `saved_list.json` shaped as bookmarks response (note key `bookmarks`, items keyed by `content_type`+`content_id`). Steps: enqueue 200; call saved repo list; `takeRequest()`. Expected: `Success`; items mapped from `bookmarks` array (NOT `items`); request path `/ui/bookmarks` with `limit`. Traces: AC-2, AC-7.
- **TC-AND-096-04** — Unsave success removes item (`DELETE /ui/bookmarks/{content_type}/{content_id}` → 200).
  Type: integration (ViewModel + fake/MockWebServer). Target: JVM. Preconditions: list of 3 saved items loaded. Steps: invoke `onUnsave(content_type, content_id)`; delete returns `200 {"ok":true}`. Expected: removed item gone from emitted `Content`; per AND-092 semantics (optimistic drop+commit, OR pessimistic refetch); exactly one DELETE issued to the composite path. Traces: AC-4.
- **TC-AND-096-05** — Unsave failure leaves list intact + surfaces transient error, DELETE attempted exactly once.
  Type: contract/MockWebServer. Target: JVM. Preconditions: 3 items loaded; delete enqueued as 500 (or network drop). Steps: `onUnsave(...)`. Expected: after failure the list still has 3 items (rollback if optimistic, or unchanged if pessimistic); `transientError != null`; `server.requestCount == 1` for the DELETE (no retry on mutations). Traces: AC-4.
- **TC-AND-096-06** — PagingSource refresh + append + end-of-pagination.
  Type: unit (Paging 3 test APIs). Target: JVM. Preconditions: two-page fake (`page1` next_cursor `eyJvIjoyMH0=`, page2 5 items next null). Steps: `load(Refresh(null,20))` then `load(Append("eyJvIjoyMH0=",20))`. Expected: refresh `Page.nextKey == "eyJvIjoyMH0="`; append `data.size==5`, `nextKey == null`. Traces: AC-3.
- **TC-AND-096-07** — 401 → refresh-once via `POST /ui/session/refresh` → single retried success.
  Type: integration (real OkHttp + MockWebServer + auth interceptor). Target: JVM. Preconditions: authenticated session; enqueue 401, then 200 to `/ui/session/refresh`, then 200 to the original GET. Steps: call a GET repo method. Expected: consumer observes ONE `Success`; exactly one `POST /ui/session/refresh` recorded; original request retried exactly once. (Mirrors `src/api/client.ts` refresh-once.) Traces: AC-6.
- **TC-AND-096-08** — FastAPI `detail` variants + parse error mapping.
  Type: contract/MockWebServer. Target: JVM. Preconditions: fixtures for `detail` string, `[{msg}]`, `{code,...}`, plus a malformed-JSON body. Steps: enqueue each as the error body (e.g. 422/403) and one corrupt 200. Expected: each maps to a typed `ApiResult.Error` carrying the normalized message; malformed JSON → `ApiResult.Error.Parse`, never an uncaught `JsonDataException`. Traces: AC-2, AC-7.
- **TC-AND-096-09** — Timeout / unreliable dev host → `Error.Network`, no hang, `stale` set when cache exists.
  Type: contract/MockWebServer. Target: JVM. Preconditions: `SocketPolicy.NO_RESPONSE` or dispatcher delay > client timeout; a fake that first succeeds then times out on refresh. Steps: trigger load, then a refresh that times out. Expected: repo returns `ApiResult.Error.Network` (bounded, no hang); ViewModel emits `Error(stale=true)` because prior `Content` existed; no crash. Traces: AC-2.
- **TC-AND-096-10** — Compose smoke: Activity & Saved render content + empty + error/retry.
  Type: Compose-UI (Robolectric). Target: JVM (fallback emu(test35)). Preconditions: stateless screen overloads with fake state. Steps: set `Content`, `Empty`, `Error` states; click retry. Expected: content nodes displayed; empty state copy shown; `retry_button` displayed + clickable (invokes `onRefresh`). Traces: AC-5.
- **TC-AND-096-11** — Compose smoke: Achievements (earned badges) & Leaderboard render + interaction.
  Type: Compose-UI (Robolectric). Target: JVM (fallback emu(test35)). Preconditions: achievements `Content` (earned `UserAchievement` list) and leaderboard `Content(entries, me)` fakes. Steps: set states; assert badge + rank rows; perform one interaction (e.g. tap a badge / period toggle). Expected: badge label/rarity/points and leaderboard rank/display_name rendered; interaction wired. Traces: AC-5.
- **TC-AND-096-12** — Accessibility smoke on interactive nodes + externalized strings.
  Type: Compose-UI (Robolectric). Target: JVM (fallback emu(test35)). Preconditions: Saved screen with unsave affordance + retry. Steps: query `onNodeWithContentDescription("Remove from saved")`; `assertHasClickAction()` on retry; read expected copy via `context.getString(R.string.…)`. Expected: every interactive node has a content description/label; retry has a click action; UI uses string resources (i18n externalization), not literals. Traces: AC-5.
- **TC-AND-096-13** — `PagingData` reaches UI via `AsyncPagingDataDiffer` (Activity) incl. LoadState transitions, on real ABI/API.
  Type: instrumented/e2e. Target: **device (SM-A156U, arm64-v8a, API 34)** primary; also emu(test35) for API-35/x86_64 parity. Preconditions: fake repo emitting a `PagingData` flow from two pages. Steps: collect into `AsyncPagingDataDiffer`; assert snapshot + `loadStateFlow` Loading→NotLoading; append. Expected: items diff into the UI layer; LoadState transitions observed; behaviour identical on arm64/API34 and x86_64/API35 (catches ABI/API-34-vs-35 regressions in Paging glue). Traces: AC-3, AC-5.
- **TC-AND-096-14** — `E13FixtureSchemaTest`: every fixture deserializes into its `core-model` DTO.
  Type: unit. Target: JVM. Preconditions: all E13 fixtures present. Steps: load each fixture; Moshi-parse into its DTO (`ActivityFeedResponse`/`BookmarkListResponse`/achievements/leaderboard). Expected: all parse with no unknown-required-field failures; failure means contract drift → CI red. Traces: AC-7.
- **TC-AND-096-15** — Security: `assertNoLiveHosts` + no secrets in fixtures + no token/cookie logging.
  Type: unit. Target: JVM. Preconditions: `RecordingLogger` test double; in-memory `CookieJar`. Steps: grep test classpath for `18.222.237.167` outside comments; scan fixtures for real PII/credentials; exercise the 401/refresh path and inspect `RecordingLogger`. Expected: no reachable live-host target; fixtures use synthetic identifiers (`user_001`); no `ui_csrf`/cookie/`Authorization` value emitted to logs. Traces: AC-8, AC-10.

### Coverage matrix

| AC | Covered by |
|---|---|
| AC-1 (suite green) | All TCs (the suite passing IS AC-1) |
| AC-2 (per-repo success/empty/error) | TC-01, TC-02, TC-03, TC-08, TC-09 |
| AC-3 (paging refresh/append/end) | TC-06, TC-13 |
| AC-4 (unsave success + failure-once) | TC-04, TC-05 |
| AC-5 (screen render + error/empty + PagingData→UI) | TC-10, TC-11, TC-12, TC-13 |
| AC-6 (401 refresh-once-and-retry) | TC-07 |
| AC-7 (fixtures deserialize to DTO) | TC-01, TC-03, TC-08, TC-14 |
| AC-8 (no live hosts / no secrets) | TC-15 |
| AC-9 (JaCoCo ≥70%) | Aggregate of TC-01..TC-09 (repository+viewmodel coverage); enforced by the CI JaCoCo gate, not a single TC |
| AC-10 (no prod behaviour change) | TC-15 (logging cross-check) + code review gate |

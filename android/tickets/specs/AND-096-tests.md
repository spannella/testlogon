---
id: AND-096
title: Tests
milestone: M2
epic: E13
priority: P2
size: M
status: draft
depends_on: [AND-095]
blocks: []
---

# AND-096 — Tests

## 1. Overview & Goal

This ticket delivers the automated test coverage for Epic E13 ("Activity, Saved & Achievements") of the TestLogon native Android port. E13 ships four user-facing surfaces — the Activity feed (AND-091), Saved/Bookmarks (AND-092), Achievements earned/locked (AND-093) and the Achievements leaderboard (AND-094) — plus the shared ViewModel/paging layer that drives them (AND-095). Those tickets each carry a thin "tested" acceptance bullet; AND-096 is the consolidating test ticket whose scope is **"Repo + UI smoke tests"** and whose acceptance is simply **"Tests pass."**

The goal is a deterministic, offline (no live backend) test suite that:

1. **Repository tests** — verify the four E13 repositories correctly map FastAPI JSON to `core-model` types, surface `ApiResult<T>` success/error/loading states, honour the unsave mutation flow, and feed Paging 3 `PagingSource` pages.
2. **ViewModel tests** — verify the AND-095 ViewModels reduce repository output into `StateFlow<UiState>` transitions (Loading → Content/Empty/Error), and that user intents (refresh, unsave, paginate) produce the expected state.
3. **UI smoke tests** — Compose UI tests that launch each of the four screens against fake ViewModels and assert that the primary content, empty, and error states render and that the key interaction (unsave) is wired.

"Tests pass" is interpreted concretely: `./gradlew :feature-activity:test :feature-saved:test :feature-achievements:test` (JVM unit tests) and the Compose UI smoke suite (instrumented or Robolectric) are green in CI, with the E13 line coverage gate met (see §11, §15).

This is a **test-only** ticket. It must not change production behaviour; any production code touched is limited to test-visibility refactors (e.g. extracting an interface, exposing a constructor for injection) explicitly called out in code review.

## 2. Context & References

- **Epic E13 feature tickets** (the code under test):
  - AND-091 Activity feed — `activityFeed.ts` API + paged screen.
  - AND-092 Saved / bookmarks — `bookmarks.ts`/saved API + screen; unsave.
  - AND-093 Achievements — `achievements.ts` API + screen (earned/locked).
  - AND-094 Achievements leaderboard — `/ui/achievements/leaderboard/me`.
  - **AND-095 ViewModels (activity/saved/achievements)** — direct dependency; supplies the `StateFlow<UiState>` + Paging 3 layer this ticket exercises. AND-096 cannot start until AND-095 lands.
- **Web reference**: `frontend/src/api/endpoints/activityFeed.ts`, `bookmarks.ts`, `achievements.ts`; shared types `frontend/src/api/types.ts`. Use these to confirm field names/shapes for fixtures.
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

- `GET /ui/activity/feed?limit={n}&cursor={c}` → `200 {"items":[{"id","type","actor","target","created_at",...}],"next_cursor": string|null}`
- `GET /ui/saved?limit={n}&cursor={c}` → `200 {"items":[{"id","kind","title","saved_at",...}],"next_cursor"}`
- `DELETE /ui/saved/{item_id}` → `204` (unsave; mutation, NOT retried on failure)
- `GET /ui/achievements` → `200 {"earned":[{"id","name","progress","earned_at"}],"locked":[{"id","name","progress","target"}]}`
- `GET /ui/achievements/leaderboard/me` → `200 {"entries":[{"rank","user","score"}],"me":{"rank","score","percentile"}}`

Error bodies tested for all GETs: FastAPI `detail` as string, `[{msg}]`, and `{code,...}`; plus `401` (refresh-once path) and `5xx`/timeout (offline/stale). Fixtures live in `core-testing/.../fixtures/`. A guard test asserts each fixture deserializes into its `core-model` DTO so drift from the real schema fails CI. Ownership of the live contracts remains with the feature tickets; AND-096 only validates fixtures against them.

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
- Unsave is optimistic: state drops the item immediately, then commits on `204` or rolls back + sets `transientError` on failure.
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
- **R4 — Optimistic unsave semantics undefined:** AND-092 says "unsave updates" but does not specify optimistic vs pessimistic. **Open question for AND-092 owner**: is the unsave optimistic with rollback (assumed here) or does it await `204` before removing? Tests follow whatever AND-092 ships; this spec assumes optimistic.
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

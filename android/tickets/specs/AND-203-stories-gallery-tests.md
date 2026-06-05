---
id: AND-203
title: Stories/gallery tests
milestone: M4
epic: E27
priority: P2
size: M
status: draft
depends_on: [AND-202]
blocks: []
---

# AND-203 — Stories/gallery tests

## 1. Overview & Goal

This ticket delivers the **automated test suite** for the Stories and Gallery
feature area of the TestLogon native Android client. It ships **no product
code** and introduces **no new user-facing behavior**; its single deliverable
is a green, durable set of **`core-data`/ViewModel unit tests** and **Compose
UI / instrumented smoke tests** that lock down the behavior implemented by the
Stories/gallery feature tickets — AND-199 (stories tray + full-screen viewer),
AND-200 (segment progress, tap navigation, reactions/replies), AND-201 (gallery
grid + lightbox), and AND-202 (Stories/gallery ViewModels: state + Paging 3).

The backlog records exactly one acceptance line — **"Tests pass"** — and one
scope line — **"UI smoke tests."** Concretely that means: new test classes
exercising the Stories/gallery repositories, ViewModels, DTO↔domain mapping,
Paging sources, and the Compose viewer/tray/grid/lightbox surfaces run **green
in CI on every push to `android-port`**, use **deterministic fixtures** (no live
calls to the unreliable dev backend), and meaningfully cover the success,
loading, empty, stale/offline, error, paging, auto-advance, and
tap-navigation/reaction paths.

This ticket owns: (a) ViewModel + repository unit tests using MockWebServer +
Turbine + coroutine test dispatchers; (b) **UI smoke tests** for the stories
tray, full-screen story viewer (auto-advance + tap nav + reactions), gallery
grid, and lightbox; (c) shared test fixtures/fakes added to `core-testing`; and
(d) wiring these suites into the required CI gate. It does **not** own the
production implementation under test — that is AND-199/AND-200/AND-201/AND-202.
Where production lacks a seam needed for deterministic testing (notably an
**injectable `Clock`** for auto-advance timing and a **fake auto-advance ticker
/ time source**), this ticket adds the seam in coordination with AND-202/AND-199
rather than asserting against wall-clock behavior.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Test sources land under `feature-stories/src/test` and
  `feature-stories/src/androidTest` (covering both stories and the sibling
  gallery surfaces in the same feature module), with shared fakes/fixtures in
  `core-testing`. No production package gains new classes except agreed test
  seams.
- **Namespace:** `com.testlogon.android` everywhere a package appears — e.g.
  `com.testlogon.android.feature.stories`,
  `com.testlogon.android.feature.stories.viewer`,
  `com.testlogon.android.feature.stories.gallery`,
  `com.testlogon.android.core.testing`.
- **Subjects under test (hard dep):**
  - **AND-202 — Stories/gallery ViewModels** (state + Paging): the primary
    contract this suite asserts against. Its `StateFlow<UiState>` shapes and
    Paging sources are the source of truth for ViewModel/paging assertions.
  - **AND-199 — Stories tray + viewer** (`stories.ts` port; tray +
    full-screen viewer, auto-advance).
  - **AND-200 — Story progress + reactions** (segment progress, tap nav,
    reactions/replies).
  - **AND-201 — Gallery browsing** (`gallery.ts` port; grid + lightbox).
- **Web reference (behavioral parity):** `frontend/src/api/endpoints/stories.ts`
  and `frontend/src/api/endpoints/gallery.ts`, plus shared types in
  `frontend/src/api/types.ts`, define the wire shapes and behaviors the fixtures
  and assertions reproduce.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). Tests **must not** contact this host. The wire
  contract (story tray/feed, story reactions/replies, gallery list, FastAPI
  `detail` error shapes) is reproduced as canned JSON fixtures served from
  MockWebServer. OpenAPI lives at `/openapi.json` for fixture validation.
- **Stack under test:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room
  2.6, DataStore, Coil, Media3/ExoPlayer 1.4 (video stories), Paging 3. minSdk
  24 / target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Test libraries:** JUnit4, `kotlinx-coroutines-test` (1.8+,
  `StandardTestDispatcher`/`runTest`), Turbine 1.x (Flow assertions), OkHttp
  `mockwebserver`, Truth/AssertJ, `androidx.compose.ui:ui-test-junit4` +
  `createComposeRule`/`createAndroidComposeRule`, `androidx.paging:paging-testing`,
  Robolectric (JVM-side Android-dependent units), and Hilt
  `HiltAndroidRule`/`HiltTestRunner` for instrumented DI.

## 3. Functional Requirements

These are the **coverage obligations** the suite must satisfy. Each maps to
assertions, not new product behavior.

1. **Repository success path.** Given a 200 JSON fixture, the Stories/gallery
   repository emits cache-then-network (or network) `ApiResult.Success<T>` with
   correctly mapped domain models (`StoryTray`, `StoryReel`/`StorySegment`,
   `GalleryItem`/`GalleryPage`).
2. **DTO↔domain mapping.** snake_case → camelCase, optional/missing fields,
   `null` handling, unknown-field tolerance, and segment-type discrimination
   (image vs. video story) asserted for story tray DTO, story segment DTO,
   reaction/reply DTO, and gallery item DTO.
3. **Cache-first / stale.** A cached tray/gallery renders first; a subsequent
   refresh failure preserves cached content and sets `isStale = true`.
4. **Paging.** The gallery Paging 3 source (and stories tray paging, if paged)
   loads pages, surfaces `LoadState.Loading/Error/NotLoading(endOfPagination)`,
   and presents empty state — asserted via `paging-testing` `asSnapshot`.
5. **Error mapping.** FastAPI `detail` in all three shapes (`string`,
   `[{msg}]`, `{code,...}`) and HTTP `401/404/5xx/timeout` map to the documented
   `ApiResult.Error(message, code)` and the documented UI messages.
6. **Retry / backoff (idempotent GET).** Transient `5xx`/`IOException`/timeout
   triggers bounded retry for GETs; `4xx` does not. Reaction/reply POSTs are
   **not** retried.
7. **ViewModel state transitions.** `Loading → Content`, `Content(stale)`,
   `error` (no cache), `retry()` re-issues the fetch; viewer-specific
   transitions: open reel, **auto-advance to next segment**, tap-forward/back,
   pause-on-hold, reaction-sent optimistic update + rollback on failure.
8. **UI smoke — stories tray + viewer.** Tray renders rings/avatars; tapping a
   tray item opens the viewer; segment progress bar advances; tap-right
   advances, tap-left goes back; sending a reaction invokes the callback;
   loading/empty/error states render.
9. **UI smoke — gallery grid + lightbox.** Grid renders items; tapping an item
   opens the lightbox; lightbox shows the selected item and supports
   next/previous; loading/empty/error states render.
10. **Determinism & isolation.** No test reaches the network, the filesystem
    (beyond in-memory Room), or wall-clock time; auto-advance is driven by
    virtual time / a fake ticker; all suites are repeatable and order-independent.

## 4. Technical Design

### Module / source layout

```
feature-stories/
  src/test/java/com/testlogon/android/feature/stories/
    StoriesTrayViewModelTest.kt
    StoryViewerViewModelTest.kt
    GalleryViewModelTest.kt
    StoriesRepositoryImplTest.kt
    GalleryRepositoryImplTest.kt
    GalleryPagingSourceTest.kt
    mapping/StoryDtoMappingTest.kt
    mapping/GalleryDtoMappingTest.kt
  src/androidTest/java/com/testlogon/android/feature/stories/
    StoriesTrayScreenTest.kt
    StoryViewerScreenTest.kt
    GalleryScreenTest.kt
    GalleryLightboxTest.kt
core-testing/
  src/main/java/com/testlogon/android/core/testing/
    MainDispatcherRule.kt
    MockBackend.kt                  // MockWebServer + canned responder
    FakeTicker.kt                   // controllable auto-advance time source
    fixtures/StoryFixtures.kt       // JSON + domain fixtures
    fixtures/GalleryFixtures.kt
    fakes/FakeStoriesRepository.kt
    fakes/FakeGalleryRepository.kt
```

### Coroutine + Flow test infrastructure (`core-testing`)

```kotlin
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}
```

ViewModels are constructed directly (Hilt not required for JVM unit tests).
`StateFlow` emissions are asserted with Turbine:

```kotlin
viewModel.uiState.test {
    assertThat(awaitItem()).isEqualTo(StoryViewerUiState(isLoading = true))
    val opened = awaitItem()
    assertThat(opened.currentReelId).isEqualTo("reel_1")
    assertThat(opened.currentSegmentIndex).isEqualTo(0)
    cancelAndIgnoreRemainingEvents()
}
```

### Auto-advance / timing seam (the key Stories-specific concern)

Auto-advance is duration-driven and must be made deterministic. The viewer
ViewModel must accept an injectable time source so the suite advances segments
on command instead of by wall-clock. The suite asserts via a `FakeTicker`
backed by `runTest` virtual time:

```kotlin
interface SegmentTicker {                       // seam provided by AND-202/AND-199
    fun start(durationMs: Long, onTick: (fraction: Float) -> Unit, onComplete: () -> Unit)
    fun pause(); fun resume(); fun stop()
}

@Test fun viewer_autoAdvances_toNextSegment_afterDuration() = runTest {
    val vm = StoryViewerViewModel(repo = fakeRepo, ticker = FakeTicker(this))
    vm.open(reelId = "reel_1")
    advanceUntilIdle()
    assertThat(vm.uiState.value.currentSegmentIndex).isEqualTo(0)
    advanceTimeBy(STORY_SEGMENT_MS + 1)          // virtual time, no real delay
    assertThat(vm.uiState.value.currentSegmentIndex).isEqualTo(1)
}
```

If AND-202 implements auto-advance directly with `delay(...)`, virtual time via
`StandardTestDispatcher` + `advanceTimeBy` suffices and `FakeTicker` is omitted;
the seam is added only if real timers/`postDelayed` are used.

### MockWebServer harness (`core-testing`)

```kotlin
class MockBackend : AutoCloseable {
    val server = MockWebServer()
    fun start() = server.start()
    fun enqueueJson(@Language("JSON") body: String, code: Int = 200) =
        server.enqueue(MockResponse().setResponseCode(code)
            .setHeader("Content-Type", "application/json").setBody(body))
    fun enqueueError(code: Int, detail: String) =
        enqueueJson("""{"detail":"$detail"}""", code)
    fun failThenSucceed(failures: Int, @Language("JSON") success: String) {
        repeat(failures) { server.enqueue(MockResponse().setResponseCode(503)) }
        enqueueJson(success)
    }
    fun baseUrl(): String = server.url("/").toString()
    override fun close() = server.shutdown()
}
```

Retrofit/OkHttp under test is built against `MockBackend.baseUrl()` with the same
Moshi converter, error mapper, and cookie/CSRF interceptors as production so the
mapping and retry behavior exercised matches runtime.

### UI smoke tests (Compose)

`createAndroidComposeRule`/`createComposeRule` drive screens with hand-built
`UiState` values and fake callbacks. Auto-advance UI is driven by the Compose
test clock (`composeRule.mainClock.autoAdvance = false` + `advanceTimeBy`) so
the progress bar is observed deterministically.

```kotlin
@get:Rule val compose = createComposeRule()

@Test fun viewer_tapRight_advancesSegment() {
    var advanced = false
    compose.setContent {
        StoryViewerScreen(
            state = StoryViewerUiState(
                isLoading = false, currentReelId = "reel_1",
                currentSegmentIndex = 0, segmentCount = 3),
            onTapForward = { advanced = true },
            onTapBack = {}, onSendReaction = {}, onClose = {},
        )
    }
    compose.onNodeWithContentDescription("Next segment").performClick()
    assertThat(advanced).isTrue()
}

@Test fun gallery_itemClick_opensLightbox() {
    var openedId: String? = null
    compose.setContent {
        GalleryScreen(state = GalleryUiState(items = GalleryFixtures.items),
            onItemClick = { openedId = it })
    }
    compose.onAllNodesWithContentDescription("Gallery image")[0].performClick()
    assertThat(openedId).isEqualTo("g_1")
}
```

Instrumented tests needing DI use `HiltAndroidRule` with `HiltTestRunner` and
bind `FakeStoriesRepository`/`FakeGalleryRepository` via a `@TestInstallIn` test
module replacing the production `RepositoryModule`.

## 5. API Contract

This ticket introduces **no new endpoints**. It exercises the existing contracts
owned by AND-199/AND-200/AND-201 and consumed by AND-202. The contract
obligation here is **fixture fidelity**: canned JSON served by `MockBackend`
must match the live `/openapi.json` shapes (snake_case keys, optionality) and
the web reference (`stories.ts`, `gallery.ts`).

Endpoints exercised (paths mirror the web reference; exact paths inherited from
the implementation tickets):

- `GET /stories` (or `/stories/tray`) → story tray reels.
- `GET /stories/{reelId}` → story segments for a reel.
- `POST /stories/{reelId}/segments/{segmentId}/reactions` → reaction (not
  retried).
- `POST /stories/{reelId}/segments/{segmentId}/replies` → reply (not retried).
- `GET /gallery` (paged) → gallery items.

Representative story tray + segment fixture:

```json
{
  "reels": [
    {
      "reel_id": "reel_1",
      "author": {"u_identifier": "u_jane", "display_name": "Jane",
                 "avatar_url": "https://cdn.example/u_jane.jpg"},
      "has_unseen": true,
      "segments": [
        {"segment_id": "seg_1", "type": "image",
         "media_url": "https://cdn.example/seg_1.jpg",
         "duration_ms": 5000, "created_at": "2026-06-01T10:00:00Z"},
        {"segment_id": "seg_2", "type": "video",
         "media_url": "https://cdn.example/seg_2/master.m3u8",
         "duration_ms": 8000, "created_at": "2026-06-01T10:05:00Z"}
      ]
    }
  ]
}
```

Representative gallery page fixture:

```json
{
  "items": [
    {"id": "g_1", "media_url": "https://cdn.example/g_1.jpg",
     "thumbnail_url": "https://cdn.example/g_1_t.jpg",
     "width": 1080, "height": 1350, "created_at": "2026-05-20T09:00:00Z"}
  ],
  "next_cursor": "eyJvZmZzZXQiOjI0fQ=="
}
```

Error fixtures cover all three FastAPI `detail` shapes:

```json
{"detail": "Not found"}
{"detail": [{"loc": ["path","reel_id"], "msg": "invalid id", "type": "value_error"}]}
{"detail": {"code": "story_expired", "message": "This story is no longer available"}}
```

A "minimal" fixture (only required keys) and a "forward-compatible" fixture
(extra unknown keys) are included to assert null-handling and unknown-field
tolerance.

## 6. Data & State Management

The suite asserts against existing state/domain models; it defines no new ones
except test fixtures and fakes.

- **Domain fixtures** (`StoryFixtures`, `GalleryFixtures`) expose canonical
  `StoryTray`/`StoryReel`/`StorySegment` and `GalleryItem`/`GalleryPage` domain
  instances plus their matching JSON so mapping tests assert
  `dto.toDomain() == expectedDomain`.
- **Room cache** uses an **in-memory** database
  (`Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries()`) seeded before
  each test to drive cache-first/stale assertions; closed in `@After`.
- **UI state** assertions compare full `data class` instances
  (`StoriesTrayUiState`, `StoryViewerUiState`, `GalleryUiState`) for exact
  equality at each transition, including `isLoading`, `isStale`, `isOffline`,
  `error`, and viewer fields (`currentReelId`, `currentSegmentIndex`,
  `segmentProgress`, `isPaused`, `pendingReaction`).
- **Paging state** is captured with `paging-testing`:
  `pager.flow.asSnapshot { scrollTo(...) }` for page contents, plus `LoadState`
  assertions for loading/error/end-of-pagination, and cursor pagination
  (`next_cursor`) correctness.
- **Optimistic reaction state**: a reaction is added optimistically, then on a
  POST failure the state rolls back to the prior value — both transitions
  asserted with Turbine.
- **Time/IDs** are deterministic via injected fixed `Clock` (`Clock.fixed`) and
  the auto-advance ticker/virtual time, so `created_at` mapping, "expired" logic,
  and segment timing are repeatable.

## 7. Error Handling & Resilience

Resilience here means **test reliability**, plus verifying the product's
resilience paths.

- **No network flakiness:** every HTTP interaction goes through MockWebServer;
  the dev backend is never contacted. A CI guard (lint/check) fails the build if
  any test references `18.222.237.167`.
- **Deterministic timing:** `runTest` virtual time + `StandardTestDispatcher`;
  `advanceUntilIdle()`/`advanceTimeBy()` drive auto-advance, backoff, and
  timeout logic. No `Thread.sleep`. Compose tests use
  `mainClock.autoAdvance=false` + `advanceTimeBy` and `waitUntil { }` for async
  readiness — never fixed sleeps.
- **Retry/backoff coverage:** `MockBackend.failThenSucceed(2, json)` asserts a
  tray/gallery GET succeeds after bounded retries; a `4xx`-then-`200` enqueue
  asserts no retry on `4xx` (exactly one request via `server.requestCount`); a
  reaction/reply POST that returns `5xx` asserts **no** retry (non-idempotent).
- **401 refresh path:** enqueue `401` → `200` for `/ui/session/refresh` → `200`
  retry, asserting exactly one refresh and the original GET succeeds; a second
  consecutive `401` asserts the re-auth surface is signaled.
- **Stale/offline:** with seeded cache + a forced network failure, assert the
  ViewModel keeps cached content and flips `isStale`/`isOffline`, and the Compose
  banner renders.
- **Flake controls & cleanup:** animations disabled in test config; `@After`
  closes MockWebServer, in-memory Room, and the fake ticker;
  `MainDispatcherRule` resets `Dispatchers.Main`. Flakes are fixed at the source,
  not masked with blanket retries.

## 8. Security & Privacy

- Tests use **synthetic** credentials/cookies/CSRF values only; no real session
  tokens, no production data, and no secrets in fixtures.
- A redaction test asserts that with a signed `media_url`/`playback_url`
  containing query params, captured log lines contain no cookie, no
  `X-CSRF-Token`, and no query string — guarding the logging-redaction contract
  rather than introducing risk.
- CSRF header behavior on reaction/reply POSTs is asserted at the
  MockWebServer level: the recorded request carries `X-CSRF-Token` echoing the
  `ui_csrf` cookie, with a synthetic value.
- Fixtures and fakes contain no PII beyond synthetic `u_identifier`/display
  names; cached domain objects under test hold only public story/gallery
  attributes.

## 9. Accessibility & i18n

- **A11y is asserted, not just consumed.** Compose smoke tests verify
  `contentDescription`/`stateDescription` on tray rings (seen/unseen), the
  viewer next/previous/close controls, the reaction control, gallery items, and
  lightbox next/previous; and assert the segment progress bar exposes a
  progress/`stateDescription` semantic.
- **No hardcoded strings:** UI tests reference string resources
  (`context.getString(R.string.story_expired)`) rather than literals, so a
  missing/renamed resource fails the test, enforcing externalization.
- **Locale/format:** mapping/format tests pin a fixed `Locale` and time zone so
  relative timestamps ("2h ago") and any date formatting are deterministic and
  locale-aware logic is verified.
- The suite itself produces no user-facing UI; i18n obligations are limited to
  asserting the product's compliance.

## 10. Telemetry & Logging

- A `FakeAnalytics` (recording `TestLogonAnalytics` double) is injected to assert
  the product emits the documented events with correct params, e.g.
  `story_reel_opened{reelId}`, `story_segment_viewed{reelId, segmentId, index}`,
  `story_auto_advanced{reelId, fromIndex, toIndex}`,
  `story_reaction_sent{reelId, segmentId, reaction}`,
  `story_load_error{reelId, httpStatus, cause}`,
  `gallery_viewed{}`, `gallery_lightbox_opened{itemId}`,
  `gallery_load_error{httpStatus, cause}`. Tests assert event name + payload, not
  ordering of unrelated events.
- Test logging is concise; failures emit the full `UiState`/response diff to ease
  triage. No third-party analytics SDK is initialized in tests.
- A redaction test (see §8) verifies sensitive fields never appear in emitted log
  lines.

## 11. Testing Strategy

This *is* the testing ticket; the strategy is the deliverable.

**Unit / JVM (`src/test`, JUnit4 + coroutines-test + Turbine + MockWebServer):**

- `StoriesRepositoryImplTest` / `GalleryRepositoryImplTest`: cache-first emission
  order; network success mapping; refresh-failure-keeps-cache (`isStale`);
  404/401/5xx mapping; retry-on-5xx and no-retry-on-4xx for GETs; no-retry on
  reaction/reply POSTs (assert `requestCount`).
- `StoriesTrayViewModelTest`: `Loading → Content`; `Content(stale)`; `error`
  with no cache; `retry()` re-issues fetch; tray ordering (unseen first if
  specified).
- `StoryViewerViewModelTest`: open reel sets index 0; **auto-advance** to next
  segment after `duration_ms` (virtual time); end-of-reel advances to next reel
  or closes; `onTapForward`/`onTapBack` change index with bounds; pause/resume
  halts/resumes the ticker; `sendReaction()` optimistic update + rollback on POST
  failure.
- `GalleryViewModelTest`: `Loading → Content`; empty; error; `retry()`; lightbox
  open/next/previous selection state.
- `GalleryPagingSourceTest`: `load()` returns `Page` with correct `next_cursor`
  keys; error → `LoadResult.Error`; empty → empty page + end-of-pagination.
- `*DtoMappingTest`: snake_case mapping, segment-type discrimination (image vs.
  video), missing optionals → `null`/defaults, unknown fields ignored, all three
  error-`detail` shapes parsed.

**Instrumented / Compose UI smoke (`src/androidTest`, `createComposeRule` + Hilt
test runner):**

- `StoriesTrayScreenTest`: loading → tray; empty; error + Retry invokes callback;
  unseen-ring semantics; item click emits open with the right `reelId`.
- `StoryViewerScreenTest`: opens with segment 0; progress bar advances under
  controlled clock; tap-right/left navigates; reaction control invokes callback;
  close invokes callback.
- `GalleryScreenTest`: loading skeleton → grid; empty; error + Retry; item click
  opens lightbox with right id; offline/stale banner shown.
- `GalleryLightboxTest`: shows selected item; next/previous navigate; close
  returns to grid.

**Coverage target:** ≥ 80% line coverage on Stories/gallery repository, mapping,
paging, and ViewModel classes (JaCoCo); UI smoke tests cover every named
`UiState` branch. Playback of a real HLS video story remains a **manual/smoke**
gate owned by AND-199/AND-166–168 and is out of scope for the deterministic CI
suite.

**Execution:** `./gradlew :feature-stories:testDebugUnitTest` for JVM;
`./gradlew :feature-stories:connectedDebugAndroidTest` (or a Gradle-managed
device / emulator in CI) for instrumented.

## 12. Dependencies & Sequencing

- **Hard dep:** **AND-202 (Stories/gallery ViewModels)** — the primary
  implementation under test. Its ViewModels, `UiState` shapes, and Paging
  sources must exist and be API-stable. Test seams required: an injectable
  `Clock` and a controllable auto-advance time source (`SegmentTicker` /
  `delay`-based timing usable with virtual time); coordinate as small PRs against
  AND-202/AND-199 if absent.
- **Behavioral contracts:** AND-199 (tray + viewer, auto-advance), AND-200
  (segment progress, tap nav, reactions/replies), AND-201 (gallery grid +
  lightbox) define the exact behaviors the assertions encode.
- **Transitive infra (assumed present):** the shared authenticated
  `OkHttpClient` + persistent cookie jar + CSRF interceptor and the
  `ApiResult`/FastAPI error mapper from the M-series network tickets (AND-009–018,
  AND-027); `core-testing` rules/harness (extended here).
- **Sequencing:** land `core-testing` fixtures/fakes/rules first (reusable), then
  JVM unit tests (fast feedback), then Compose/instrumented smoke tests, then
  wire all suites into the required CI gate.
- **Blocks:** none currently recorded.

## 13. Risks & Open Questions

1. **AND-202 API churn (Risk):** the ViewModels/Paging may still be evolving;
   brittle assertions could break. Mitigate by asserting against public
   `UiState`/domain contracts and fixtures, not internals, and by landing AND-203
   right after AND-202 stabilizes.
2. **Auto-advance testability (Risk/OQ):** if auto-advance uses real timers
   (`Handler.postDelayed`/`CountDownTimer`) rather than coroutine `delay`, it is
   non-deterministic in tests. OQ: confirm AND-199/AND-202 implement timing with
   coroutine `delay` (virtual-time friendly) or expose a `SegmentTicker` seam.
3. **Video-story playback nondeterminism (Risk):** `ExoPlayer` cannot be reliably
   driven to ready in CI; video-segment auto-advance that depends on real
   playback completion is relegated to a manual smoke gate, with logic tests
   using image segments or a fake player from AND-166–168.
4. **Instrumented test infra (OQ):** does CI provide an emulator / Gradle-managed
   device? If not, smoke tests may run via Robolectric
   (`@RunWith(RobolectricTestRunner)` + `ComposeContentTestRule`).
5. **Fixture drift (Risk):** canned JSON can diverge from `/openapi.json` /
   `stories.ts`/`gallery.ts`. Add a lightweight, network-gated contract check
   (excluded from the default gate) or a fixture-refresh step in AND-199/AND-201
   DoD.
6. **CSRF/refresh path testability (OQ):** confirm the auth interceptor exposes
   enough seams (or is configured against MockWebServer) to assert the single
   `/ui/session/refresh` + retry and `X-CSRF-Token` on POSTs without a live
   session.

## 14. Acceptance Criteria

1. **Tests pass:** all new Stories/gallery unit and UI smoke suites run green
   locally and in CI on `android-port`.
2. Repository tests assert cache-first emission, success mapping,
   stale-on-refresh-failure, and 404/401/5xx error mapping for both stories and
   gallery paths.
3. Mapping tests assert snake_case mapping, image/video segment-type
   discrimination, missing-optional handling, unknown-field tolerance, and all
   three FastAPI `detail` shapes.
4. Retry tests prove bounded retry on transient `5xx`/timeout for GETs and **no**
   retry on `4xx` (verified via `MockWebServer.requestCount`), **no** retry on
   reaction/reply POSTs, and the `401`→`refresh`→retry path asserted exactly once.
5. ViewModel tests (Turbine) assert `Loading → Content`, `Content(stale)`,
   `error`, retry re-fetch, **auto-advance to next segment under virtual time**,
   tap-forward/back navigation with bounds, pause/resume, and reaction
   optimistic-update + rollback.
6. Paging test asserts page load with cursor, error `LoadState`, and
   empty/end-of-pagination for the gallery.
7. UI smoke tests assert: tray loading/empty/error/open; viewer segment-0 open,
   progress advance under controlled clock, tap navigation, reaction + close
   callbacks; gallery loading/empty/error and item-click-opens-lightbox; lightbox
   selected item + next/previous; offline/stale banner.
8. Telemetry tests assert the documented stories/gallery analytics events and
   payloads; a redaction test confirms no cookie/CSRF/URL-query data is logged.
9. No test contacts the dev backend or relies on wall-clock; auto-advance is
   driven by virtual time / a fake ticker; suites are repeatable and
   order-independent; a guard fails the build on a hardcoded dev-host reference.

## 15. Definition of Done

- All test classes in §4 implemented and merged to `android-port`, in the correct
  `src/test`/`src/androidTest` trees, with shared fixtures/fakes/rules in
  `core-testing`.
- Every acceptance criterion in §14 verified; the full Stories/gallery unit + UI
  smoke suites pass in CI and are configured as a **required** check (JVM unit
  always; instrumented on the agreed emulator/managed-device or via Robolectric).
- ≥ 80% line coverage on Stories/gallery repository, mapping, paging, and
  ViewModel classes (JaCoCo report attached to the PR); all named `UiState`
  branches covered by smoke tests.
- Tests are deterministic: virtual-time coroutines, MockWebServer, in-memory
  Room, fixed `Clock`/`Locale`, controllable auto-advance ticker; no
  `Thread.sleep`, no live network; CI guard against hardcoded dev-host references.
- Any test seams added to production (injectable `Clock`, `SegmentTicker`/
  `delay`-based timing) are reviewed/merged in coordination with
  AND-202/AND-199 and introduce no behavior change.
- Lint + detekt clean on test sources; flaky tests resolved at the source (no
  blanket retries).
- README/CI docs updated with the commands to run the Stories/gallery suites
  locally; no regressions to existing `feature-stories` suites.

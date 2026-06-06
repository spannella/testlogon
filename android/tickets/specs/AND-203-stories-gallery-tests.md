---
id: AND-203
title: Stories/gallery tests
milestone: M4
epic: E27
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
   correctly mapped domain models. **[CORRECTED]** The web reference exposes the
   story bar as `StoryBarResp { bar: StoryBarEntry[] }` and a user's stories as
   `UserStoriesResp { stories: Story[] }` (a flat list of `Story`, each with its
   own `media_type`/`media_url`/`duration_seconds`) — there is **no** `StoryReel`
   or `StorySegment` wire type. Android domain names may differ, but mapping tests
   must target `StoryBarEntry` / `Story` (and `GalleryVideoItem` for the video
   gallery), not invented "reel/segment" DTOs. See §16.
2. **DTO↔domain mapping.** snake_case → camelCase, optional/missing fields,
   `null` handling, unknown-field tolerance, and media-type discrimination
   (`media_type: "image" | "video"` on `Story`) asserted for the story bar entry
   DTO (`StoryBarEntry`), the story DTO (`Story`), and the gallery video item DTO
   (`GalleryVideoItem`). **[CORRECTED]** No reaction/reply DTO exists for stories
   (no such endpoint — see §5/§16).
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
   transitions: open a user's story set, **auto-advance to the next story in the
   set**, tap-forward/back, pause-on-hold. **[CORRECTED]** "reactions" on stories
   are not part of the wire contract; the closest real story interaction is
   **view tracking** via `POST /ui/stories/{story_id}/view` (returns
   `StoryViewResp { ok, already_viewed }`). Optimistic-update + rollback tests
   should target view recording (idempotent-ish) or a like, not a non-existent
   story-reaction POST. See §16.
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

Endpoints exercised — **[CORRECTED against `openapi.index.txt` and
`src/api/endpoints/stories.ts` / `gallery.ts`]**. The spec's earlier draft listed
hypothetical `/stories`, `/stories/{reelId}`, `/stories/.../reactions`,
`/stories/.../replies`, and `/gallery` paths; **none of those exist**. The real
contract is:

- `GET /ui/stories/bar` → story bar (`StoryBarResp { bar: StoryBarEntry[] }`).
- `GET /ui/stories/user/{userId}` → a user's stories
  (`UserStoriesResp { stories: Story[] }`).
- `GET /ui/stories/{storyId}` → a single story (`Story`).
- `POST /ui/stories/{storyId}/view` → record a view
  (`StoryViewResp { ok, already_viewed }`) — POST, **not retried**.
- `GET /ui/stories/{storyId}/viewers` → `StoryViewersResp { viewers, total_count }`.
- `GET /ui/videos/gallery` (paged, params `category,limit,cursor`) →
  `GalleryListOut`/`GalleryListResponse { videos: GalleryVideoItem[],
  categories, cursor? }`. **There is no story-reaction or story-reply endpoint.**
  (A `react` endpoint exists only for fan-club channel messages, posts, and
  messaging — out of scope here.)

Representative story bar fixture (`GET /ui/stories/bar`):

```json
{
  "bar": [
    {"user_id": "u_jane", "latest_story_id": "story_1",
     "latest_media_url": "https://cdn.example/story_1.jpg",
     "story_count": 3, "has_unseen": true, "is_own": false}
  ]
}
```

Representative user-stories fixture (`GET /ui/stories/user/u_jane`):

```json
{
  "stories": [
    {"story_id": "story_1", "author_id": "u_jane", "media_type": "image",
     "media_url": "https://cdn.example/story_1.jpg",
     "duration_seconds": 5, "created_at": "2026-06-01T10:00:00Z",
     "expires_at": 1717322400, "view_count": 12, "highlighted": false},
    {"story_id": "story_2", "author_id": "u_jane", "media_type": "video",
     "media_url": "https://cdn.example/story_2/master.m3u8",
     "duration_seconds": 8, "created_at": "2026-06-01T10:05:00Z",
     "expires_at": 1717322700, "view_count": 9, "highlighted": false}
  ]
}
```

Note: `Story` uses `media_type` (not `type`), `media_url`, `duration_seconds`
(seconds, **not** `duration_ms`), `created_at` is an ISO string while
`expires_at` is a **numeric** epoch — assert this mixed-shape carefully in
mapping tests.

Representative video-gallery page fixture (`GET /ui/videos/gallery`):

```json
{
  "videos": [
    {"video_id": "g_1", "title": "Clip One",
     "thumbnail_url": "https://cdn.example/g_1_t.jpg",
     "duration_seconds": 42, "category": "music", "tags": ["a","b"],
     "view_count": 100, "like_count": 4, "comment_count": 1,
     "owner_user_id": "u_jane", "created_at": 1716195600}
  ],
  "categories": [{"slug": "music", "label": "Music"}],
  "cursor": "eyJvZmZzZXQiOjI0fQ=="
}
```

Note: the video-gallery item is `GalleryVideoItem` keyed by `video_id` (not
`id`), with `thumbnail_url`, `tags`/`view_count`/`like_count`/`comment_count`,
`owner_user_id`, and a **numeric** `created_at`. There are **no** `width`/`height`
fields. The page wrapper is `{ videos, categories, cursor }` — pagination uses a
single `cursor` token, **not** `next_cursor`. (`GalleryPageOut { items,
next_cursor }` is a *different* schema used by `/messaging/conversations/{id}/
gallery`, not this video gallery.)

Error fixtures cover all three FastAPI `detail` shapes:

```json
{"detail": "Not found"}
{"detail": [{"loc": ["path","story_id"], "msg": "invalid id", "type": "value_error"}]}
{"detail": {"code": "story_expired", "message": "This story is no longer available"}}
```

**[VERIFIED with caveat]** `src/api/client.ts: normalizeErrorDetail` handles
exactly these three `detail` shapes: a plain string (returned as-is); an array of
`{msg}` objects (joined with `", "`); and an object — but for the object shape it
only returns the embedded `message` for a *known* `code` via `mapAuthorizationError`
(`role_required*`, `helpdesk_*`, plus the `403 geo_blocked` special case handled
earlier in `api()`). An *unknown* `code` like `story_expired` falls back to the
`{msg}` lookup and then to the generic fallback string — it does **not**
automatically surface `detail.message`. Android's error mapper should match this
behavior (or deliberately diverge and document it); the FastAPI `422` validation
shape is the `[{loc,msg,type}]` array (`HTTPValidationError`).

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
- CSRF header behavior is asserted at the MockWebServer level: the recorded
  request carries `X-CSRF-Token` echoing the `ui_csrf` cookie, with a synthetic
  value. **[CORRECTED]** Per `src/api/client.ts`, the web client sets
  `X-CSRF-Token` on **every** request when the `ui_csrf` cookie is present (not
  only on POSTs), so the natural targets here are the story-`view` POST and any
  gallery write; the assertion should cover at least one GET and one POST to
  mirror the web client. (There are no story reaction/reply POSTs — see §5/§16.)
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
  `story_opened{userId}`, `story_viewed{userId, storyId, index}` (mirrors the
  real `POST /ui/stories/{story_id}/view`), `story_auto_advanced{userId,
  fromIndex, toIndex}`, `story_load_error{userId, httpStatus, cause}`,
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
- `StoryViewerViewModelTest`: open user-story-set sets index 0; **auto-advance**
  to the next story after `duration_seconds` (virtual time — note the wire unit is
  **seconds**, convert to ms in the ticker); end-of-set advances to the next
  user's set or closes; `onTapForward`/`onTapBack` change index with bounds;
  pause/resume halts/resumes the ticker; `recordView()` optimistic update +
  rollback on `POST /ui/stories/{storyId}/view` failure. **[CORRECTED]** no
  `sendReaction` — stories have no reaction endpoint (§5/§16).
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
   retry on `4xx` (verified via `MockWebServer.requestCount`), **no** retry on the
   story `view` POST (`POST /ui/stories/{storyId}/view`) or any gallery write, and
   the `401`→`POST /ui/session/refresh`→retry path asserted exactly once.
5. ViewModel tests (Turbine) assert `Loading → Content`, `Content(stale)`,
   `error`, retry re-fetch, **auto-advance to the next story under virtual time**
   (driven by `duration_seconds`), tap-forward/back navigation with bounds,
   pause/resume, and **view-record (`POST /ui/stories/{storyId}/view`)
   optimistic-update + rollback**. **[CORRECTED]** prior wording said "reaction" —
   there is no story-reaction endpoint (§5/§16).
6. Paging test asserts page load with cursor, error `LoadState`, and
   empty/end-of-pagination for the gallery.
7. UI smoke tests assert: bar loading/empty/error/open; viewer first-story (index
   0) open, progress advance under controlled clock, tap navigation, close
   callback (and a view-record/like callback where present); gallery
   loading/empty/error and item-click-opens-lightbox; lightbox selected item +
   next/previous; offline/stale banner.
8. Telemetry tests assert the stories/gallery analytics events and payloads
   **that the product actually emits** (event names in §10 are illustrative and
   unverified — see §16 Open assumptions); a redaction test confirms no
   cookie/CSRF/URL-query data is logged.
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

## 16. Citations & Assumption Audit

Each key technical claim, with VERDICT and an exact SOURCE pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend paths are
under `reference/src/`.

1. **Story bar/tray endpoint.** Claim: a `GET` returns the story tray. VERDICT:
   **Corrected** (was `GET /stories` / `/stories/tray`). SOURCE:
   `GET /ui/stories/bar` (OpenAPI index line 1900,
   op `get_story_bar_endpoint_...`) and `src/api/endpoints/stories.ts: getStoryBar`
   → `StoryBarResp`.
2. **Story-bar response shape.** Claim/Corrected: `StoryBarResp { bar:
   StoryBarEntry[] }`, each entry `{ user_id, latest_story_id, latest_media_url,
   story_count, has_unseen, is_own }`. VERDICT: **Verified**. SOURCE:
   `src/api/types.ts: StoryBarResp` / `StoryBarEntry` (lines 3636, 3674).
3. **Per-user stories endpoint.** Claim: `GET /stories/{reelId}` returns
   "segments". VERDICT: **Corrected**. SOURCE: `GET /ui/stories/user/{user_id}`
   (index line 1904) → `UserStoriesResp { stories: Story[] }`
   (`src/api/endpoints/stories.ts: getUserStories`, `types.ts: UserStoriesResp`
   line 3688). A single story is `GET /ui/stories/{story_id}` → `Story`
   (index 1906, `getStory`).
4. **No "reel"/"segment" concept on the wire.** VERDICT: **Corrected**. SOURCE:
   no `reel`/`segment` match in `openapi.index.txt`; `types.ts: Story` (line 3620)
   is a flat object — a user's stories are an array of `Story`, not a reel of
   segments.
5. **Story media discriminator + duration unit.** Claim: `type: image|video`,
   `duration_ms`. VERDICT: **Corrected**. SOURCE: `types.ts: Story` →
   `media_type: "image" | "video"`, `media_url`, `duration_seconds` (seconds),
   `created_at` (ISO string), `expires_at` (numeric epoch) (lines 3620-3634).
6. **Story reactions/replies POST.** Claim: `POST /stories/{reelId}/segments/
   {segmentId}/reactions` and `.../replies`. VERDICT: **Corrected — endpoints do
   not exist.** SOURCE: no story reaction/reply path in `openapi.index.txt`;
   `react` endpoints exist only for posts (index 509), messaging messages (358),
   and fan-club channels (1447). `stories.ts` has no reaction/reply call. The real
   story-interaction write is `POST /ui/stories/{story_id}/view` (index 1909,
   `recordStoryView` → `StoryViewResp { ok, already_viewed }`, `types.ts` 3678).
7. **Story viewers.** VERDICT: **Verified** (supporting, not asserted by draft).
   SOURCE: `GET /ui/stories/{story_id}/viewers` (index 1910) →
   `StoryViewersResp { viewers, total_count }` (`types.ts` 3683).
8. **Video gallery endpoint.** Claim: `GET /gallery` paged. VERDICT:
   **Corrected**. SOURCE: `GET /ui/videos/gallery` (index 1999,
   op `browse_gallery_endpoint_...`, params `category,limit,cursor`) →
   `GalleryListOut`; `src/api/endpoints/gallery.ts: browseGallery`.
9. **Video gallery response/item shape.** Claim: `{ items:[{id, media_url,
   thumbnail_url, width, height, created_at}], next_cursor }`. VERDICT:
   **Corrected**. SOURCE: `gallery.ts: GalleryListResponse { videos:
   GalleryVideoItem[], categories, cursor? }`; `GalleryVideoItem` keyed by
   `video_id` (not `id`), `thumbnail_url`, `tags`, `view_count`, `like_count`,
   `comment_count`, `owner_user_id`, numeric `created_at`, no `width`/`height`
   (`gallery.ts` lines 5-32). OpenAPI `GalleryListOut` (spec line 35324, required
   `videos`) and `GalleryVideoItem` (spec line 35413) confirm.
10. **`GalleryPageOut {items,next_cursor}` is a different feature.** VERDICT:
    **Corrected** (draft's `next_cursor`/`items` matched the wrong schema). SOURCE:
    `GalleryPageOut` (spec line 35359) is the response of
    `GET /messaging/conversations/{conversation_id}/gallery` (index line 325), not
    the video gallery.
11. **Gallery like toggle.** VERDICT: **Verified** (supporting). SOURCE:
    `POST /ui/videos/{video_id}/like` (`gallery.ts: toggleLike` →
    `LikeToggleResponse { liked, like_count }`).
12. **CSRF behavior.** Claim: `X-CSRF-Token` echoes the `ui_csrf` cookie on POSTs.
    VERDICT: **Verified, refined** — applied to *every* request when the cookie
    exists, not POST-only. SOURCE: `src/api/client.ts` lines 167-171.
13. **401 → refresh → retry path.** Claim: single `POST /ui/session/refresh` then
    one retry of the original request. VERDICT: **Verified**. SOURCE:
    `src/api/client.ts: refreshSession` (line 121, `POST /ui/session/refresh`) and
    the 401 branch (lines 194-237): a shared `refreshPromise` ensures one refresh,
    then the request is retried once; a second 401 logs the user out.
14. **Unauthenticated 401 not refreshed.** VERDICT: **Verified** (useful test
    nuance). SOURCE: `client.ts` lines 196-203 — when `!isAuthenticated`, the 401
    propagates without a refresh.
15. **FastAPI `detail` shapes.** Claim: string, `[{msg}]`, `{code,...}` all map to
    `ApiResult.Error`. VERDICT: **Verified, with caveat**. SOURCE:
    `client.ts: normalizeErrorDetail` (lines 66-102) handles string, `[{msg}]`
    array, and object — but for objects it returns the embedded `message` only for
    *known* codes (`mapAuthorizationError`, lines 34-64) or the `403 geo_blocked`
    case (lines 245-250); unknown `code` objects fall through to a generic
    fallback. `422` validation = `HTTPValidationError` array (ubiquitous in index).
16. **Network/offline error.** VERDICT: **Verified**. SOURCE: `client.ts` lines
    185-189 — a `fetch` throw yields `ApiError(0, "Network error")`; Android's
    `isOffline` mapping should key off the transport-level failure equivalently.
17. **Stack/test-lib choices (Kotlin/Compose/Turbine/MockWebServer/paging-testing
    /Robolectric/Hilt; emulator vs. device).** VERDICT: **Unverified-assumption**
    (framework choices, not derivable from backend/frontend sources). SOURCE:
    framework ref — Android testing docs
    (https://developer.android.com/training/testing) and Compose testing
    (https://developer.android.com/jetpack/compose/testing); coroutines-test virtual
    time (https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-test/).
18. **Dev host `http://18.222.237.167:8000` / OpenAPI at `/openapi.json`.**
    VERDICT: **Unverified-assumption** — no host/base-URL appears in the provided
    sources. SOURCE: none; carried from the backlog/infra context.

### Corrections made

- §1, §3.1/3.2/3.7: replaced invented `StoryTray`/`StoryReel`/`StorySegment`
  domain/DTO names with the real `StoryBarResp`/`StoryBarEntry` and
  `UserStoriesResp`/`Story`; replaced `type`/`duration_ms` with
  `media_type`/`duration_seconds`.
- §5: rewrote the endpoint list to the real paths (`/ui/stories/bar`,
  `/ui/stories/user/{userId}`, `/ui/stories/{storyId}`,
  `/ui/stories/{storyId}/view`, `/ui/videos/gallery`); replaced the fictional
  tray/segment and gallery fixtures with shapes matching `StoryBarResp`,
  `UserStoriesResp`/`Story`, and `GalleryListResponse`/`GalleryVideoItem`; noted
  `cursor` (not `next_cursor`) and `video_id` (not `id`), no `width`/`height`.
- §5: clarified the `{code,message}` `detail` handling caveat in
  `normalizeErrorDetail`.
- §3.7, §11, §14 (AC4, AC5, AC7, AC8): removed/replaced "story reaction/reply"
  assertions (no such endpoint) with view-record (`POST /ui/stories/{storyId}/
  view`) optimistic-update/rollback and corrected the refresh path name.
- §8: refined CSRF claim — header is sent on every request, not POST-only.
- §10: relabeled telemetry event names as illustrative/unverified.

### Open assumptions

- **Analytics event names/payloads (§10)** — no analytics contract exists in the
  provided sources (no analytics endpoint/type); event names are illustrative.
  Confirm against the Android analytics module (AND-199/200) before asserting.
- **Dev backend host / `/openapi.json` reachability (§2, §7)** — not present in
  the references; treated as infra context for the CI guard only.
- **Android test seams (`SegmentTicker`, injectable `Clock`, `delay`-based
  auto-advance, exact `UiState` field names)** — owned by AND-199/AND-202 and not
  visible in any provided source; assertions must track those tickets' public API.
- **Whether the Android client retries idempotent GETs / honors `Retry-After`** —
  the web `client.ts` does **not** implement retry/backoff at all; the retry
  behavior in §6/§7 is an Android-side design assumption, not a web-parity fact.
- **CI emulator/managed-device availability (§13 OQ4)** — environment-dependent.

## 17. Test Plan

Test-target legend: **JVM** = local JVM unit/Robolectric (no device); **EMU** =
headless AVD `test35` (x86_64, API 35) on the CI build server; **DEVICE** =
physical Samsung Galaxy A15 5G (SM-A156U, serial `R5CX821TA9R`, Android 14 / API
34, arm64-v8a) on the build host. Most cases here are deterministic JVM/Compose
tests; the physical device is reserved for the real-HLS-playback smoke and an
arm64/API-34 ABI sanity pass, since the rest is network/clock-faked.

- **TC-AND-203-01 — Story-bar repository success mapping.**
  Type: contract/MockWebServer (JVM). Target: JVM. Pre: MockWebServer enqueued
  with the `GET /ui/stories/bar` fixture (`{ bar:[…] }`, §5). Steps: build
  Retrofit against `MockBackend.baseUrl()`; call `storiesRepository.getStoryBar()`;
  inspect the recorded request and emitted result. Expected: request path is
  `/ui/stories/bar`; result is `ApiResult.Success` with one `StoryBarEntry`
  (`user_id=u_jane`, `has_unseen=true`, `story_count=3`). Traces: AC-1, AC-2.

- **TC-AND-203-02 — Per-user stories mapping (image vs video, duration unit).**
  Type: unit (JVM). Target: JVM. Pre: `UserStoriesResp` fixture with one `image`
  and one `video` story (§5). Steps: map DTO→domain. Expected: two stories;
  `media_type` discriminates image/video; `duration_seconds` mapped as **seconds**
  (5s, 8s); `created_at` parsed as ISO instant, `expires_at` as numeric epoch; a
  forward-compat fixture with an unknown extra key still parses. Traces: AC-3.

- **TC-AND-203-03 — Missing-optional / null tolerance.**
  Type: unit (JVM). Target: JVM. Pre: minimal `Story` fixture omitting
  `text_overlay`, `link_url`, `link_label`, `duration_seconds`,
  `highlight_group_id`. Steps: map DTO→domain. Expected: optionals → `null`/
  defaults, no crash; required fields (`story_id`, `media_type`, `media_url`,
  `expires_at`, `view_count`, `highlighted`) present. Traces: AC-3.

- **TC-AND-203-04 — FastAPI `detail` error shapes → ApiResult.Error.**
  Type: contract/MockWebServer (JVM). Target: JVM. Pre: three enqueued error
  bodies — `"detail":"Not found"` (404), `[{loc,msg,type}]` (422), and
  `{code:"story_expired",message:…}` (410). Steps: call the repo for each.
  Expected: string → message verbatim; array → joined `msg` values; unknown-code
  object → generic fallback (NOT `detail.message`, per
  `normalizeErrorDetail`); each yields `ApiResult.Error(message, code)`. Traces:
  AC-2, AC-3.

- **TC-AND-203-05 — Cache-first then stale on refresh failure.**
  Type: unit (JVM, in-memory Room). Target: JVM. Pre: in-memory DB seeded with a
  prior story bar; MockWebServer enqueues a `503` for the refresh. Steps: call the
  repo; collect emissions with Turbine. Expected: first emission is cached content
  (`isStale=false`), second preserves the same content with `isStale=true`
  (and `isOffline` if transport-level); no exception surfaces to the UI. Traces:
  AC-2.

- **TC-AND-203-06 — Retry on transient 5xx for GET; no retry on 4xx; no retry on
  view POST.** Type: contract/MockWebServer (JVM). Target: JVM. Pre:
  `failThenSucceed(2, barJson)` for `GET /ui/stories/bar`; separately a `404`
  then `200`; separately a `503` for `POST /ui/stories/{id}/view`. Steps: run each
  scenario; read `server.requestCount`. Expected: bar GET succeeds after bounded
  retries (requestCount == failures+1); the `404` GET is **not** retried
  (requestCount == 1); the `view` POST is **not** retried (requestCount == 1) and
  surfaces an error. Traces: AC-4.

- **TC-AND-203-07 — 401 → /ui/session/refresh → single retry.**
  Type: contract/MockWebServer (JVM). Target: JVM. Pre: enqueue `401` for the bar
  GET, `200` for `POST /ui/session/refresh`, then `200` for the retried bar GET.
  Steps: call the repo while "authenticated"; inspect recorded requests. Expected:
  exactly one `POST /ui/session/refresh`; original GET retried once and succeeds; a
  second consecutive `401` instead signals re-auth/logout (no infinite loop).
  Traces: AC-4.

- **TC-AND-203-08 — Viewer auto-advance under virtual time.**
  Type: unit (JVM, `runTest`). Target: JVM. Pre: fake repo returns a 2-story set
  (5s, 8s); viewer VM built with `FakeTicker`/virtual-time dispatcher. Steps:
  `open(userId)`, `advanceUntilIdle()`, assert index 0; `advanceTimeBy(5_000+1)`.
  Expected: index advances to 1 with no real delay; after the last story the VM
  advances to the next user's set or closes; `segmentProgress` updates
  monotonically. Traces: AC-5.

- **TC-AND-203-09 — Viewer tap navigation, bounds, pause/resume, view-record
  rollback.** Type: unit (JVM, Turbine). Target: JVM. Pre: viewer VM on a 3-story
  set; fake repo where `recordView` can be forced to fail. Steps: `onTapForward`
  past the end (bounded), `onTapBack` below 0 (bounded), `pause()`/`resume()` halt
  and resume the ticker, then `recordView()` with a forced POST failure. Expected:
  index stays within `[0, count-1]`; ticker pauses/resumes; optimistic view state
  applies then rolls back on failure (both transitions observed via Turbine).
  Traces: AC-5.

- **TC-AND-203-10 — Video-gallery Paging 3 source (cursor, empty, end).**
  Type: unit (JVM, `paging-testing`). Target: JVM. Pre: MockWebServer enqueues a
  `GET /ui/videos/gallery` page with `cursor`, then a final page with `cursor`
  null/absent; plus an empty-page scenario and a `503` scenario. Steps: drive the
  pager via `asSnapshot { … }` and assert `LoadState`. Expected: items keyed by
  `video_id` load in order; the `cursor` token (not `next_cursor`) drives the next
  load; absent cursor → `NotLoading(endOfPaginationReached=true)`; empty page →
  empty snapshot + end; `503` → `LoadState.Error`. Traces: AC-6.

- **TC-AND-203-11 — Story bar Compose smoke (loading/empty/error/open + a11y).**
  Type: Compose-UI (EMU; Robolectric fallback). Target: EMU. Pre: `StoriesBarScreen`
  driven with hand-built `UiState` (loading, empty, error, content). Steps: render
  each state; assert loading indicator, empty copy, error + Retry callback; tap an
  entry. Expected: tapping emits open with the right `userId`; unseen ring exposes a
  `contentDescription`/`stateDescription` semantic (seen vs unseen); error Retry
  invokes its callback; strings come from `R.string.*` (renamed resource fails the
  test). Traces: AC-7, AC-8 (a11y/i18n).

- **TC-AND-203-12 — Viewer Compose smoke (progress under controlled clock, taps,
  close).** Type: Compose-UI (EMU). Target: EMU. Pre: `StoryViewerScreen` with
  `mainClock.autoAdvance=false`; state at index 0 of a 3-story set. Steps: assert
  index 0 rendered; `advanceTimeBy` and observe the progress bar advance;
  `performClick` on "Next"/"Previous" content descriptions; click "Close".
  Expected: progress bar advances deterministically; tap-right/left invoke the
  forward/back callbacks; close invokes its callback; next/prev/close controls each
  expose a `contentDescription`. Traces: AC-5, AC-7.

- **TC-AND-203-13 — Gallery grid + lightbox Compose smoke (incl. offline/stale
  banner).** Type: Compose-UI (EMU). Target: EMU. Pre: `GalleryScreen` with
  `GalleryFixtures` items; lightbox composable. Steps: render grid; tap an item;
  assert lightbox shows the selected `video_id` and supports next/previous; render
  the `isOffline`/`isStale` state. Expected: item click opens the lightbox with the
  correct `video_id`; next/previous change the selected item within bounds; the
  offline/stale banner renders with an accessible description; gallery items expose
  `contentDescription`. Traces: AC-7.

- **TC-AND-203-14 — Telemetry + log redaction.**
  Type: unit (JVM). Target: JVM. Pre: `FakeAnalytics` injected; a story/gallery
  flow exercised with a signed `media_url` carrying query params. Steps: drive
  open/auto-advance/view + a load error; capture emitted events and log lines.
  Expected: the events the product emits carry the expected payload keys (assert
  by name+payload, not order); **no** log line contains a cookie, `X-CSRF-Token`,
  or any URL query string. (Event names per §10 are illustrative — assert the
  product's real names.) Traces: AC-8.

- **TC-AND-203-15 — Determinism / dev-host guard / order independence.**
  Type: integration (JVM + CI lint check). Target: JVM. Pre: full suite + the CI
  guard that greps test/fixture sources. Steps: run the suite twice in shuffled
  order; run the guard against a deliberately seeded `18.222.237.167` string in a
  scratch fixture. Expected: identical green results across runs (no wall-clock,
  no real network, no `Thread.sleep`); the guard **fails** the build on the
  hardcoded dev-host reference and passes when absent. Traces: AC-9.

- **TC-AND-203-16 — Real-HLS video-story playback smoke (physical device).**
  Type: instrumented/e2e (manual smoke). Target: **DEVICE (required)** — real
  Media3/ExoPlayer HLS decode and codec behavior cannot be driven reliably on the
  emulator and differs by ABI (arm64-v8a) / API 34. Pre: app installed on
  SM-A156U; a real or staged HLS `media_url`. Steps: open a video story; let it
  play and auto-advance on real playback completion; rotate; background/foreground.
  Expected: video renders and audio plays; auto-advance fires after the real clip
  ends; no ANR/crash; ABI/API-34 path behaves as on API 35. This is the
  out-of-CI gate noted in §11; the deterministic CI suite uses image stories or a
  fake player. Traces: AC-1 (smoke), AC-5 (real-playback variant).

### Coverage matrix (AC § → TC)

| §14 AC | Covered by |
|--------|------------|
| AC-1 Tests pass / suites green | TC-01, TC-15, TC-16 (smoke) |
| AC-2 Repo cache-first/success/stale/error mapping | TC-01, TC-04, TC-05 |
| AC-3 Mapping: snake_case, media-type, optionals, detail shapes | TC-02, TC-03, TC-04 |
| AC-4 Retry/no-retry + 401→refresh | TC-06, TC-07 |
| AC-5 ViewModel transitions + auto-advance + nav + rollback | TC-08, TC-09, TC-12, TC-16 |
| AC-6 Paging cursor/error/empty/end | TC-10 |
| AC-7 UI smoke (bar/viewer/gallery/lightbox/banner) | TC-11, TC-12, TC-13 |
| AC-8 Telemetry + redaction (+ i18n/a11y) | TC-11, TC-14 |
| AC-9 Determinism / no wall-clock / dev-host guard | TC-08, TC-15 |

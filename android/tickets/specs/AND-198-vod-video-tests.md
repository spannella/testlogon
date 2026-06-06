---
id: AND-198
title: VOD/video tests
milestone: M4
epic: E26
priority: P2
size: M
depends_on: [AND-197]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-198 — VOD/video tests

## 1. Overview & Goal

This ticket delivers the **automated test suite** for the VOD/video feature of
the TestLogon native Android client. It does **not** ship product code or new
user-facing behavior; its single deliverable is a green, durable set of
**repository (`core-data`) unit tests** and **Compose UI / instrumented tests**
that lock down the behavior implemented by the VOD/video feature ticket
**AND-197** (catalog, detail, and HLS player wiring) and its sibling screens
(AND-190 video detail + player, AND-191 VOD catalog).

The success bar is concrete and the only acceptance the backlog records:
**tests pass.** Concretely that means new test classes exercising the VOD/video
repositories, ViewModels, DTO↔domain mapping, and Compose screens run green in
CI on every push to `android-port`, with deterministic fixtures (no live calls
to the unreliable dev backend), and they meaningfully cover the success,
loading, empty, stale/offline, error, and playback-lifecycle paths.

This ticket owns: (a) repository/ViewModel unit tests using MockWebServer +
Turbine + coroutine test dispatchers; (b) Compose UI tests for the catalog,
detail, and player surfaces; (c) shared test fixtures and fakes added to
`core-testing`; and (d) the CI wiring that makes these suites a required gate. It
does **not** own the production implementation under test — that is AND-197 (and
the screens it builds on, AND-190/AND-191). Where production code is missing a
seam needed to test it deterministically (e.g. an injectable clock or a fake
player factory), this ticket adds the seam in coordination with AND-197 rather
than asserting against wall-clock or real network behavior.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Test sources land under `feature-vod/src/test` and
  `feature-vod/src/androidTest` (and the equivalent `feature-videos` trees),
  with shared fakes/fixtures in `core-testing`. No production package gains new
  classes except test seams agreed with AND-197.
- **Namespace:** `com.testlogon.android` everywhere a package appears — e.g.
  `com.testlogon.android.feature.vod`, `com.testlogon.android.feature.videos.detail`,
  `com.testlogon.android.core.testing`.
- **Subject under test (hard dep):** **AND-197 — VOD/video** feature implementation
  (catalog list/grid, detail, stream-URL resolution, Media3/ExoPlayer wiring).
  AND-198 is purely additive test coverage for AND-197 and cannot land
  meaningfully before AND-197's APIs and screens exist.
- **Related specs reused as behavioral contracts:** AND-190 (`feature-videos`
  detail + player: `VideoDetailViewModel`, `VideoRepository.observeVideo`,
  `VideoDetailUiState`), AND-191 (`feature-vod` catalog + detail: `VodApi`,
  `feature.vod` routes, Paging 3 source). The acceptance criteria and state
  models in those specs are the source of truth for the assertions written here.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). Tests **must not** hit this host. The wire
  contract (`GET /ui/videos/{video_id}` → `VideoDetailOut`, the `/ui/videos`
  cursor-paged list, FastAPI `detail` error shapes) is reproduced as canned JSON
  fixtures served from MockWebServer. **[Corrected]** The detail path is
  `/ui/videos/{video_id}` (not `/videos/{id}`) and the response schema is
  `VideoDetailOut` (not `VideoDetailDto`); verified against OpenAPI
  `GET /ui/videos/{video_id}` and `src/api/endpoints/videos.ts: getVideoDetail`.
- **Stack under test:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6,
  DataStore, Coil, Media3/ExoPlayer 1.4 (HLS), Paging 3. minSdk 24 / target 35,
  JDK 17, AGP 8.7.3, Gradle 8.9.
- **Test libraries:** JUnit4, `kotlinx-coroutines-test` (1.8+,
  `StandardTestDispatcher`/`runTest`), Turbine 1.x (Flow assertions), OkHttp
  `mockwebserver`, Truth/AssertJ for fluent assertions, `androidx.compose.ui:ui-test-junit4`
  + `createComposeRule`, `androidx.paging:paging-testing`, Robolectric (for
  JVM-side Android-dependent unit tests where useful), and Hilt
  `HiltAndroidRule`/`HiltTestRunner` for instrumented DI.

## 3. Functional Requirements

This ticket's "functional requirements" are the **coverage obligations** the
suite must satisfy. Each maps to assertions, not product behavior.

1. **Repository success path.** Given a 200 JSON fixture, the VOD/video
   repository emits cache-then-network (or network) `ApiResult.Success<T>` with
   correctly mapped domain models.
2. **DTO↔domain mapping.** Snake_case → camelCase mapping, optional/missing
   fields, `null` handling, and unknown-field tolerance are asserted for the VOD
   catalog DTO, VOD detail DTO, and `VideoDetailDto`.
3. **Cache-first / stale.** A cached record renders first; a subsequent refresh
   failure preserves cached content and sets `isStale = true`.
4. **Error mapping.** FastAPI `detail` in all three shapes (`string`,
   `[{msg}]`, `{code,...}`) and HTTP `401/404/5xx/timeout` map to the documented
   `ApiResult.Error(message, code)` and the documented UI messages
   (e.g. 404 → "Video not available").
5. **Retry / backoff (idempotent GET).** Transient `5xx`/`IOException`/timeout
   triggers bounded retry; `4xx` does not. Asserted via MockWebServer dispatcher
   that fails N times then succeeds.
6. **ViewModel state transitions.** `Loading → Content`, `Content(stale)`,
   `detailError` (no cache), `retry*()` re-issues the fetch, playback-error and
   playback-retry-token transitions — all asserted with Turbine.
7. **Paging (VOD catalog).** The Paging 3 source loads pages, surfaces
   `LoadState.Loading/Error`, and presents empty state, asserted via
   `paging-testing` `asSnapshot`.
8. **Compose UI states.** Loading skeleton, populated metadata, empty catalog,
   error + Retry, offline/stale banner, and player surface enablement
   (`playbackUrl != null`) are rendered and asserted with the Compose test rule.
9. **Player lifecycle.** Using a **fake/fakeable player**, assert pause on
   `ON_PAUSE`, release on `ON_DESTROY` (no leak), and playback-position
   preservation across rotation/state restoration.
10. **Determinism & isolation.** No test reaches the network, the filesystem
    (beyond in-memory Room), or wall-clock time; all suites are repeatable and
    order-independent.

## 4. Technical Design

### Module / source layout

```
feature-vod/
  src/test/java/com/testlogon/android/feature/vod/
    VodCatalogViewModelTest.kt
    VodDetailViewModelTest.kt
    VodRepositoryImplTest.kt
    VodPagingSourceTest.kt
    mapping/VodDtoMappingTest.kt
  src/androidTest/java/com/testlogon/android/feature/vod/
    VodCatalogScreenTest.kt
    VodDetailScreenTest.kt
feature-videos/
  src/test/java/com/testlogon/android/feature/videos/detail/
    VideoDetailViewModelTest.kt
    VideoRepositoryImplTest.kt
    mapping/VideoDetailDtoMappingTest.kt
  src/androidTest/java/com/testlogon/android/feature/videos/detail/
    VideoDetailScreenTest.kt
core-testing/
  src/main/java/com/testlogon/android/core/testing/
    MainDispatcherRule.kt
    MockBackend.kt                 // MockWebServer + canned responder
    fixtures/VodFixtures.kt        // JSON + domain fixtures
    fixtures/VideoFixtures.kt
    fakes/FakeVideoRepository.kt
    fakes/FakeVodRepository.kt
    player/FakePlayer.kt           // androidx.media3.common.Player test double
    player/FakeExoPlayerFactory.kt
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
    assertThat(awaitItem()).isEqualTo(VideoDetailUiState(isLoading = true))
    val content = awaitItem()
    assertThat(content.video?.id).isEqualTo("vid_123")
    cancelAndIgnoreRemainingEvents()
}
```

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
mapping and retry behavior actually exercised matches runtime.

### Fake player (lifecycle tests without real ExoPlayer)

Real `ExoPlayer` is heavyweight and non-deterministic in CI. Lifecycle/leak and
state tests use a `FakePlayer : androidx.media3.common.Player` (or a thin
`PlayerController` test double from AND-168) injected through an
`ExoPlayerFactory` seam that AND-197 must expose:

```kotlin
class FakePlayer : Player by NoOpPlayer() {
    var prepareCount = 0; var paused = false; var released = false
    var mediaItem: MediaItem? = null
    override fun setMediaItem(item: MediaItem) { mediaItem = item }
    override fun prepare() { prepareCount++ }
    override fun pause() { paused = true }
    override fun release() { released = true }
}
```

### Compose UI tests

`createAndroidComposeRule` (or `createComposeRule` for stateless screens) drives
the screen with hand-built `UiState` values and fake callbacks:

```kotlin
@get:Rule val compose = createComposeRule()

@Test fun detailError_showsRetry_andInvokesCallback() {
    var retried = false
    compose.setContent {
        VideoDetailScreen(
            state = VideoDetailUiState(isLoading = false,
                detailError = UiMessage.Text("Video not available")),
            onRetryDetail = { retried = true },
            onPlaybackError = {}, onRetryPlayback = {},
        )
    }
    compose.onNodeWithText("Video not available").assertIsDisplayed()
    compose.onNodeWithText("Retry").performClick()
    assertThat(retried).isTrue()
}
```

Instrumented tests that need DI use `HiltAndroidRule` with the `HiltTestRunner`
and bind `FakeVodRepository`/`FakeVideoRepository` via a `@TestInstallIn` test
module replacing the production `RepositoryModule`.

## 5. API Contract

This ticket introduces **no new endpoints**. It exercises the existing,
already-specified contracts owned by AND-197/AND-190/AND-191:

- `GET /ui/videos/{video_id}` → `VideoDetailOut` (see AND-190 §5).
  **[Corrected]** was `GET /videos/{id}` → `VideoDetailDto`; the real path is
  prefixed `/ui` and the schema is `VideoDetailOut`. Verified: OpenAPI
  `GET /ui/videos/{video_id}` (op `get_video_detail_...`, resp `200:VideoDetailOut`)
  and `src/api/endpoints/videos.ts: getVideoDetail`.
- VOD catalog is **cursor-paged** (`items[] + cursor`, e.g. `GET /ui/videos`,
  `GET /ui/videos/public`, `GET /ui/videos/gallery`) — **not** page-numbered;
  `GET /ui/videos/{video_id}` returns the same `VideoDetailOut` for detail
  (see AND-191 §5). Verified: OpenAPI `GET /ui/videos` → `VideoListOut`,
  `src/api/endpoints/videos.ts: listMyVideos`/`VideoListResponse { items, cursor }`.

The contract obligation here is **fidelity of fixtures**: the canned JSON served
by `MockBackend` must match the live `/openapi.json` shapes (snake_case keys,
optionality). Representative detail fixture used across tests:

**[Corrected fixture]** keyed to `VideoDetailOut` (verified against OpenAPI
`components.schemas.VideoDetailOut` and `src/api/endpoints/videos.ts: VideoDetail`):
the id key is `video_id`; the HLS URL is `hls_manifest_url` (with `playback_token`
/ `playback_expires_at`), not `playback_url`; timestamps (`created_at`,
`updated_at`, `published_at`) are **epoch integers**, not ISO strings; there is no
`view_count` or `tags` field (`purchase_count` exists instead). Required keys:
`video_id, owner_user_id, title, status, visibility, created_at, updated_at`.

```json
{
  "video_id": "vid_123",
  "owner_user_id": "usr_42",
  "title": "Intro to TestLogon",
  "description": "Walkthrough of the login flow.",
  "status": "ready",
  "visibility": "public",
  "created_at": 1746100800,
  "updated_at": 1746100800,
  "published_at": 1746100800,
  "duration_seconds": 372,
  "thumbnail_url": "https://cdn.example/poster.jpg",
  "hls_manifest_url": "https://cdn.example/vid_123/master.m3u8",
  "playback_token": "pt_abc",
  "playback_expires_at": 1746104400,
  "renditions": [],
  "purchase_count": 1042
}
```

Error fixtures cover all three FastAPI `detail` shapes (all verified against
`src/api/client.ts: normalizeErrorDetail`/`mapAuthorizationError`; the array shape
is FastAPI's `HTTPValidationError` returned with **HTTP 422**, items match
`components.schemas.ValidationError` = `{loc[], msg, type}`):

```json
{"detail": "Not found"}
{"detail": [{"loc": ["path","video_id"], "msg": "invalid id", "type": "value_error"}]}
{"detail": {"code": "video_unavailable", "message": "Video not available"}}
```

Note the object shape `{code, message}` is real and meaningful: the web client
special-cases `code == "geo_blocked"` on **403** (renders a geo-blocked page) and
maps `role_required*`/`helpdesk_*` codes to friendly text. The `loc` entry uses
the parameter name `video_id` (corrected from `id`).

A "minimal" fixture (only required keys, all optionals omitted) and a
"forward-compatible" fixture (extra unknown keys present) are also included to
assert null-handling and unknown-field tolerance.

## 6. Data & State Management

The suite asserts against the existing state and domain models; it defines no new
ones except test fixtures and fakes.

- **Domain fixtures** (`VideoFixtures`, `VodFixtures`) expose canonical
  `Video`/VOD domain instances plus their matching JSON strings so mapping tests
  assert `dto.toDomain() == expectedDomain`.
- **Room cache** uses an **in-memory** database
  (`Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries()`) seeded before
  each test to drive cache-first/stale assertions; closed in `@After`.
- **UI state** assertions compare full `data class` instances
  (`VideoDetailUiState`, the VOD catalog/detail UI states) for exact equality at
  each transition, including `isLoading`, `isStale`, `isOffline`, `detailError`,
  `playbackError`, and `playbackRetryToken`.
- **Paging state** is captured with `paging-testing`:
  `pager.flow.asSnapshot { scrollTo(...) }` to assert page contents, and
  `LoadState` assertions for loading/error/end-of-pagination.
- **Time/IDs** are made deterministic by injecting a fixed `Clock`
  (`Clock.fixed`) wherever timestamps/`Instant` are produced, so
  `published_at` mapping and any "stale since" logic are repeatable.

## 7. Error Handling & Resilience

Resilience here means **test reliability**, plus verifying the product's
resilience paths:

- **No network flakiness:** every HTTP interaction goes through MockWebServer;
  the dev backend is never contacted. A CI guard (lint/check) fails the build if
  a test references `18.222.237.167`.
- **Deterministic timing:** `runTest` virtual time + `StandardTestDispatcher`;
  `advanceUntilIdle()`/`advanceTimeBy()` drive backoff/timeout logic rather than
  real delays. No `Thread.sleep`. Compose tests rely on the auto-sync test clock
  and `waitUntil { }` for async readiness — never fixed sleeps.
- **Retry/backoff coverage:** `MockBackend.failThenSucceed(2, json)` asserts the
  GET succeeds after bounded retries; a `4xx`-then-`200` enqueue asserts the
  client does **not** retry `4xx` (exactly one request observed via
  `server.requestCount`).
- **401 refresh path:** enqueue `401` → `200` for `/ui/session/refresh` → `200`
  retry, and assert exactly one refresh occurred and the original call
  succeeded; a second `401` asserts the re-auth surface is signaled.
- **Flake controls:** instrumented tests use `@RetryRule`-free design (fix flakes
  at the source); animations disabled via test config; idling resources or
  `composeRule.mainClock` used for any deferred work.
- **Resource cleanup:** `@After` closes MockWebServer, in-memory Room, and the
  fake player to prevent cross-test leakage; `MainDispatcherRule` resets
  `Dispatchers.Main`.

## 8. Security & Privacy

- Tests use **synthetic** credentials/cookies/CSRF values only; no real session
  tokens, no production data, and no secrets are committed in fixtures.
- A test asserts the **logging redaction** contract from AND-190/AND-197: with a
  signed playback URL containing query params, captured log lines contain no
  cookie, no `X-CSRF-Token`, and no query string — guarding the privacy
  requirement rather than introducing risk.
- The cleartext-only-on-dev-host policy is not exercised over real HTTP; if a
  `network-security-config` assertion is desired it is a Robolectric/unit check
  that the config scopes cleartext to the dev host only and not app-wide.
- Fixtures and fakes contain no PII; cached domain objects under test hold only
  public video attributes.

## 9. Accessibility & i18n

- **A11y is asserted, not just consumed.** Compose tests verify
  `contentDescription`/`stateDescription` on play, Retry, and back controls and
  on the player surface (`onNodeWithContentDescription("Video player: …")`), and
  assert touch-target/semantics presence for key affordances.
- **No hardcoded strings:** UI tests reference string resources
  (`context.getString(R.string.video_unavailable)`) rather than literals so a
  missing/renamed resource fails the test, enforcing externalization.
- **Locale/format:** mapping/format tests pin a fixed `Locale` and time zone so
  duration (`H:MM:SS` / `M:SS`) and date formatting are deterministic and
  locale-aware logic is verified.
- The suite itself produces no user-facing UI; i18n obligations are limited to
  asserting the product's compliance.

## 10. Telemetry & Logging

- A `FakeAnalytics` (recording `TestLogonAnalytics` double) is injected to assert
  the product emits the documented events with correct params:
  `video_detail_viewed{videoId}`, `video_playback_started{videoId, startupMs}`,
  `video_playback_error{videoId, errorCode}`,
  `video_detail_load_error{videoId, httpStatus, cause}`,
  `video_detail_served_stale{videoId}` (and the VOD-catalog equivalents from
  AND-191). Tests assert event name + payload, not ordering of unrelated events.
- Test logging is concise; failures emit the full `UiState`/response diff to ease
  triage. No third-party analytics SDK is initialized in tests.
- A redaction test (see §8) verifies sensitive fields never appear in emitted log
  lines.

## 11. Testing Strategy

This *is* the testing ticket; the strategy is the deliverable.

**Unit / JVM (`src/test`, JUnit4 + coroutines-test + Turbine + MockWebServer):**

- `VideoRepositoryImplTest` / `VodRepositoryImplTest`: cache-first emission order;
  network success mapping; refresh-failure-keeps-cache (`isStale`); 404/401/5xx
  mapping; retry-on-5xx and no-retry-on-4xx (assert `requestCount`).
- `VideoDetailViewModelTest` / `VodDetailViewModelTest` / `VodCatalogViewModelTest`:
  `Loading → Content`; `Content(stale)`; `detailError` with no cache;
  `retryDetail()/retry()` re-issues fetch; `onPlaybackError`→`playbackError`;
  `retryPlayback()` increments `playbackRetryToken`.
- `*DtoMappingTest`: snake_case mapping, missing optionals → `null`/defaults,
  unknown fields ignored, all three error-`detail` shapes parsed by the mapper.
- `VodPagingSourceTest`: `load()` returns `Page` with correct keys; error →
  `LoadResult.Error`; empty → empty page + end-of-pagination.

**Instrumented / Compose (`src/androidTest`, `createComposeRule` + Hilt test
runner):**

- `VodCatalogScreenTest`: loading skeleton → grid; empty state; error + Retry
  invokes callback; offline/stale banner shown; item click emits navigation with
  the right id.
- `VideoDetailScreenTest` / `VodDetailScreenTest`: skeleton → metadata; play
  enabled only when `playbackUrl != null`; detail error + Retry; playback error +
  Retry; rotation preserves playback position (state-restoration test via
  `StateRestorationTester`).
- Player lifecycle test with `FakePlayer`: `ON_PAUSE`→`paused == true`,
  `ON_DESTROY`→`released == true`, no second player instantiated across
  recomposition.

**Coverage target:** ≥ 80% line coverage on the VOD/video repository, mapping,
and ViewModel classes (measured via JaCoCo); Compose tests cover every named
`UiState` branch. Playback against a real HLS stream remains a **manual/smoke**
gate owned by AND-197/AND-190 and is out of scope for the deterministic CI suite.

**Execution:** `./gradlew :feature-vod:testDebugUnitTest :feature-videos:testDebugUnitTest`
for JVM; `./gradlew connectedDebugAndroidTest` (or a managed/Gradle-managed
device / emulator in CI) for instrumented.

## 12. Dependencies & Sequencing

- **Hard dep:** **AND-197 (VOD/video)** — the implementation under test. Its
  repositories, ViewModels, DTOs, routes, and player wiring must exist and be
  API-stable. Test seams required from AND-197: an injectable `ExoPlayerFactory`
  (or `PlayerController` interface) and an injectable `Clock`; coordinate these
  as small PRs against AND-197 if absent.
- **Behavioral contracts:** AND-190 (video detail + player) and AND-191 (VOD
  catalog) define the exact state models and acceptance behaviors the assertions
  encode.
- **Transitive infra (assumed present):** the shared authenticated `OkHttpClient`
  + cookie jar + CSRF interceptor and the `ApiResult`/FastAPI error mapper from
  the M-series network tickets (e.g. AND-027); `core-testing` test rules.
- **Sequencing:** land `core-testing` fixtures/fakes/rules first (reusable),
  then JVM unit tests (fast feedback), then Compose/instrumented tests, then wire
  all suites into the required CI gate.
- **Blocks:** none currently recorded.

## 13. Risks & Open Questions

1. **AND-197 API churn (Risk):** the implementation it tests may still be
   evolving; brittle assertions could break. Mitigate by asserting against
   public `UiState`/domain contracts and fixtures, not internals, and by landing
   AND-198 immediately after AND-197 stabilizes.
2. **Real-player nondeterminism (Risk):** `ExoPlayer` cannot be reliably driven
   to `STATE_READY` in CI. Mitigated by `FakePlayer` for logic/lifecycle tests
   and relegating real-stream playback to a manual smoke gate (OQ: should a
   nightly instrumented job run one known-good HLS stream end-to-end?).
3. **Instrumented test infra (OQ):** does CI provide an emulator / Gradle-managed
   device? If not, Compose UI tests may need to run via Robolectric
   (`@RunWith(RobolectricTestRunner)` + `ComposeContentTestRule`) instead of a
   device.
4. **Fixture drift (Risk):** canned JSON can diverge from `/openapi.json`. Add a
   lightweight contract check (optional, network-gated, excluded from the default
   gate) or a documented fixture-refresh step in AND-197's DoD.
5. **CSRF/refresh path testability (OQ):** confirm the auth interceptor exposes
   enough seams (or is configured against MockWebServer) to assert the single
   `/ui/session/refresh` + retry without a live session.
6. **Flaky Compose timing (Risk):** async content + animations can flake;
   mitigated by disabling animations, using `waitUntil`/idling resources, and
   never using fixed sleeps.

## 14. Acceptance Criteria

1. **Tests pass:** all new VOD/video unit and Compose/instrumented suites run
   green locally and in CI on `android-port`.
2. Repository tests assert cache-first emission, success mapping, stale-on-refresh
   -failure, and 404/401/5xx error mapping for both the VOD and `videos` paths.
3. Mapping tests assert snake_case mapping, missing-optional handling, unknown-
   field tolerance, and all three FastAPI `detail` shapes.
4. Retry tests prove bounded retry on transient `5xx`/timeout and **no** retry on
   `4xx` (verified via `MockWebServer.requestCount`); the `401`→`refresh`→retry
   path is asserted exactly once.
5. ViewModel tests (Turbine) assert `Loading → Content`, `Content(stale)`,
   `detailError`, retry re-fetch, and playback-error / `playbackRetryToken`
   transitions.
6. Paging test asserts page load, error `LoadState`, and empty/end-of-pagination
   for the VOD catalog.
7. Compose tests assert loading skeleton, populated metadata/grid, empty, error +
   working Retry, offline/stale banner, play-enabled-only-when-`playbackUrl`, and
   rotation/state-restoration of playback position.
8. Player-lifecycle test (`FakePlayer`) asserts pause on background, release on
   destroy (no leak), and no duplicate player across recomposition.
9. Telemetry tests assert the documented VOD/video analytics events and payloads;
   a redaction test confirms no cookie/CSRF/URL-query data is logged.
10. No test contacts the dev backend or relies on wall-clock; suites are
    repeatable and order-independent; a guard fails the build on a hardcoded dev
    host reference.

## 15. Definition of Done

- All test classes in §4 implemented and merged to `android-port`, residing in
  the correct `src/test`/`src/androidTest` trees with shared fixtures/fakes/rules
  in `core-testing`.
- Every acceptance criterion in §14 verified; the full VOD/video unit + Compose
  suites pass in CI and are configured as a **required** check (JVM unit always;
  instrumented on the agreed emulator/managed-device or via Robolectric).
- ≥ 80% line coverage on VOD/video repository, mapping, and ViewModel classes
  (JaCoCo report attached to the PR); all named `UiState` branches covered by
  Compose tests.
- Tests are deterministic: virtual-time coroutines, MockWebServer, in-memory
  Room, fixed `Clock`/`Locale`, `FakePlayer`; no `Thread.sleep`, no live network,
  CI guard against hardcoded dev-host references in tests.
- Any test seams added to production (`ExoPlayerFactory`, injectable `Clock`) are
  reviewed/merged in coordination with AND-197 and introduce no behavior change.
- Lint + detekt clean on test sources; flaky tests resolved at the source (no
  blanket retries).
- README/CI docs updated with the commands to run the VOD/video suites locally;
  no regressions to existing `feature-vod`/`feature-videos` suites.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec
(`reference/openapi.pretty.json`, `components.schemas.*`), and frontend
(`reference/src/...`).

1. **Video detail endpoint is `GET /videos/{id}`.** VERDICT: **Corrected** → the
   real path is `GET /ui/videos/{video_id}`. SOURCE: OpenAPI
   `GET /ui/videos/{video_id}` (op `get_video_detail_ui_videos__video_id__get`);
   `src/api/endpoints/videos.ts: getVideoDetail`.
2. **Detail response schema is `VideoDetailDto`.** VERDICT: **Corrected** → the
   backend schema is `VideoDetailOut`; the web DTO is `VideoDetail` /
   `VideoDetailResponse`. SOURCE: OpenAPI `resp=200:VideoDetailOut` for the above
   op; `components.schemas.VideoDetailOut`; `src/api/endpoints/videos.ts: VideoDetail`,
   `src/api/endpoints/vod.ts: VideoDetailResponse`.
3. **HLS/playback URL field is `playback_url`.** VERDICT: **Corrected** → the
   field is `hls_manifest_url` (with companion `playback_token` and
   `playback_expires_at`). SOURCE: `components.schemas.VideoDetailOut.hls_manifest_url`
   / `.playback_token` / `.playback_expires_at`; `src/api/endpoints/vod.ts:
   VideoDetailResponse.hls_manifest_url`.
4. **Id field is `id`.** VERDICT: **Corrected** → the wire field is `video_id`.
   SOURCE: `components.schemas.VideoDetailOut.video_id` (also in `required`);
   `src/api/endpoints/videos.ts: VideoDetail.video_id`.
5. **Timestamps (`published_at`, `created_at`) are ISO-8601 strings.** VERDICT:
   **Corrected** → they are **epoch integers**. SOURCE:
   `components.schemas.VideoDetailOut.created_at`/`.updated_at`/`.published_at`
   (`type: integer`); `src/api/endpoints/videos.ts: VideoDetail.created_at: number`.
6. **`view_count` and `tags` fields exist on the detail DTO.** VERDICT:
   **Corrected** → neither exists in `VideoDetailOut`; the closest is
   `purchase_count` (integer, default 0). SOURCE:
   `components.schemas.VideoDetailOut` property list (no `view_count`/`tags`).
7. **VOD catalog is page-numbered (Paging 3 over numeric pages).** VERDICT:
   **Corrected (partial)** → the backend list contract is **cursor-based**
   (`items[] + cursor`); a Paging 3 `PagingSource` is a valid Android design but
   must use `cursor`, not page indices. SOURCE: OpenAPI `GET /ui/videos` →
   `VideoListOut`, `GET /ui/videos/public` → `VideoListOut`;
   `src/api/endpoints/videos.ts: VideoListResponse { items, cursor }`,
   `listMyVideos`/`listPublicVideos`.
8. **FastAPI `detail` has three shapes: string, `[{...msg...}]`, `{code,...}`.**
   VERDICT: **Verified.** The array shape is `HTTPValidationError` (HTTP 422) with
   items = `{loc[], msg, type}`; the object shape with `code` is handled
   explicitly (e.g. `geo_blocked`, `role_required*`). SOURCE:
   `components.schemas.HTTPValidationError` + `components.schemas.ValidationError`;
   `src/api/client.ts: normalizeErrorDetail` and `mapAuthorizationError`.
9. **`401` triggers a single session refresh then one retry.** VERDICT:
   **Verified.** Refresh is `POST /ui/session/refresh`, single-flight via a shared
   `refreshPromise`, retried exactly once; a second `401` logs out
   (`session_expired`). An *unauthenticated* `401` propagates without refresh.
   SOURCE: `src/api/client.ts: refreshSession` / 401 branch (lines ~119–237).
10. **Auth/CSRF transport: cookie session + `Authorization: Bearer` +
    `X-CSRF-Token`.** VERDICT: **Verified.** `credentials: "include"` (cookies);
    `Authorization: Bearer <accessToken>`; CSRF read from the `ui_csrf` cookie and
    sent as header `X-CSRF-Token`; impersonation via `X-IMPERSONATION-TOKEN`.
    SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")`, `X-CSRF-Token`,
    `Authorization`, `credentials: "include"`).
11. **Retry/backoff on transient `5xx`/`IOException`/timeout for idempotent GET.**
    VERDICT: **Unverified-assumption.** The *web* client performs **no** generic
    5xx/timeout retry (only the 401-refresh-once path). This is an Android-side
    resilience design (OkHttp interceptor) not reflected in the reference client.
    SOURCE (counter-evidence): `src/api/client.ts` has no retry loop for non-401
    errors. Treat as an AND-197 design decision to confirm.
12. **404 maps to UI message "Video not available".** VERDICT:
    **Unverified-assumption** (Android UI-string mapping). The backend may return
    404 with a string `detail` or the `{code:"video_unavailable", message:...}`
    object, but the specific Android copy is not in the sources. SOURCE:
    `src/api/client.ts: normalizeErrorDetail` returns the server `detail`/fallback;
    the exact string is an app resource owned by AND-190/AND-197.
13. **`ApiResult.Success/Error`, `ApiResult.Error(message, code)`, FastAPI error
    mapper, cookie jar + CSRF interceptor.** VERDICT: **Unverified-assumption** —
    these are Android-internal abstractions from the M-series network tickets
    (e.g. AND-027), not present in the reference sources. The error-mapper inputs
    (the three `detail` shapes) are verified (see #8); the wrapper type is not.
14. **Analytics events `video_detail_viewed`, `video_playback_started`,
    `video_playback_error`, `video_detail_load_error`, `video_detail_served_stale`
    (+ payloads).** VERDICT: **Unverified-assumption** — no analytics contract is
    visible in the reference frontend or OpenAPI; owned by AND-190/AND-191/AND-197.
15. **Log redaction of cookie/`X-CSRF-Token`/URL query.** VERDICT:
    **Unverified-assumption** — a privacy requirement asserted by the spec; not
    expressible from the sources (no logging contract in the reference client).
16. **State models `VideoDetailUiState`, `playbackRetryToken`, `isStale`,
    `VodCatalog*`/`VodDetail*` UI states; `ExoPlayerFactory`/`PlayerController`
    seams; injectable `Clock`.** VERDICT: **Unverified-assumption** — Android
    implementation details defined in AND-190/AND-191/AND-197, not in the
    backend/frontend sources. These are correctly framed by the spec as contracts
    inherited from those tickets.
17. **Media3/ExoPlayer 1.4 for HLS; Compose UI test via `createComposeRule`;
    `paging-testing asSnapshot`; Turbine; `kotlinx-coroutines-test`.** VERDICT:
    **Unverified-assumption (framework ref)** — standard Android tooling choices,
    not derivable from this repo's sources. Framework refs:
    https://developer.android.com/media/media3/exoplayer/hls ,
    https://developer.android.com/develop/ui/compose/testing ,
    https://developer.android.com/topic/libraries/architecture/paging/test .

### Corrections made

- §2 and §5: detail endpoint corrected from `GET /videos/{id}` to
  `GET /ui/videos/{video_id}`; response schema corrected from `VideoDetailDto` to
  `VideoDetailOut`.
- §5 representative fixture rewritten to match `VideoDetailOut`: `id`→`video_id`,
  `playback_url`→`hls_manifest_url` (+ `playback_token`/`playback_expires_at`),
  ISO timestamps→epoch integers, removed non-existent `view_count`/`tags`, added
  the required keys (`owner_user_id`, `status`, `visibility`, `created_at`,
  `updated_at`) and `purchase_count`.
- §5: VOD catalog clarified as cursor-paged (`items[] + cursor`), not
  page-numbered; the validation-error `detail` example now uses HTTP 422 and the
  `loc` parameter name `video_id`; noted the `{code,...}` object shape is real
  (e.g. 403 `geo_blocked`).
- These are surgical corrections; assertion logic, state-transition coverage, and
  test infrastructure described in §3/§4/§6–§13 remain unchanged where they were
  already framework- or AND-197-contract-based.

### Open assumptions

- **Generic 5xx/timeout retry/backoff (§3.5, §7, AC-4):** not present in the web
  client; an Android-only design. Confirm the OkHttp retry policy and bounds with
  AND-197 before asserting exact retry counts.
- **UI error strings (e.g. "Video not available", §3.4, §9):** app resources owned
  by AND-190/AND-197; tests should assert via `R.string.*`, not literals.
- **`ApiResult` wrapper and error-mapper type, telemetry events, log-redaction
  contract, all `UiState`/seam types:** Android-internal contracts from
  AND-027/AND-190/AND-191/AND-197; not verifiable from backend/frontend sources.
- **Whether CI provides an emulator/Gradle-managed device vs Robolectric for
  instrumented Compose tests (§13.3):** infra question, unresolved here.
- **Fixture drift vs live `/openapi.json`:** mitigated by an optional,
  network-gated contract check; fixtures in this spec were aligned to the OpenAPI
  snapshot in `reference/` as of this review.

## 17. Test Plan

Test IDs `TC-AND-198-NN`. "Traces" links to §14 Acceptance Criteria (AC-1..AC-10).
Targets: **JVM** (local JUnit/Robolectric), **emu test35** (headless x86_64 AVD,
API 35), **device A15** (physical Samsung Galaxy A15 5G, SM-A156U, API 34,
arm64-v8a). Since this ticket's product-under-test is a fake-player /
MockWebServer deterministic suite, most cases run on **JVM** or **emu test35**;
only the real-HLS smoke case needs the **physical device**.

- **TC-AND-198-01 — Repository success maps `VideoDetailOut`→domain.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `MockBackend` started; Retrofit/Moshi built against `baseUrl()`
  with the production converter + error mapper.
  Steps: enqueue 200 with the §5 corrected fixture; call
  `repository.observeVideo("vid_123")`; collect with Turbine.
  Expected: emits `ApiResult.Success`; domain `id == "vid_123"`,
  `playbackUrl == hls_manifest_url`, `durationSeconds == 372`, timestamps parsed
  from epoch integers; exactly one request to `/ui/videos/vid_123`.
  Traces: AC-2.

- **TC-AND-198-02 — DTO↔domain mapping: snake_case, optionals, unknown fields.**
  Type: unit (JVM). Target: JVM.
  Preconditions: fixed `Clock`/`Locale`/timezone.
  Steps: map (a) full fixture, (b) "minimal" fixture (only the 7 required keys),
  (c) "forward-compatible" fixture (extra unknown keys).
  Expected: required keys map; omitted optionals → `null`/defaults
  (`purchase_count`→0, `hls_manifest_url`→null); unknown keys ignored (no throw);
  epoch `published_at` → expected `Instant`.
  Traces: AC-3.

- **TC-AND-198-03 — Error mapping: all three FastAPI `detail` shapes + statuses.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `MockBackend` started.
  Steps: enqueue, in turn, `{"detail":"Not found"}` (404),
  `{"detail":[{"loc":["path","video_id"],"msg":"invalid id","type":"value_error"}]}`
  (422), `{"detail":{"code":"video_unavailable","message":"Video not available"}}`
  (403/404), and a `500`.
  Expected: mapper yields `ApiResult.Error(message, code)` with the normalized
  message per `normalizeErrorDetail` semantics (string passthrough; array→joined
  `msg`; object→`message`/code-mapped); 404→the documented "Video not available"
  UI string (see Open assumption #12).
  Traces: AC-3, AC-2.

- **TC-AND-198-04 — Cache-first then stale-on-refresh-failure.**
  Type: integration (JVM/Robolectric, in-memory Room). Target: JVM.
  Preconditions: in-memory Room seeded with a cached `vid_123`.
  Steps: enqueue a `503` for the refresh; observe the flow.
  Expected: cached content emitted first; after refresh failure the cached content
  is preserved and `isStale == true` (no error surfaced over cached data).
  Traces: AC-2.

- **TC-AND-198-05 — Retry on transient 5xx/timeout; no retry on 4xx.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: bounded-retry policy configured (per AND-197 — see Open
  assumption; if no retry policy exists, this case asserts a single attempt).
  Steps: (a) `failThenSucceed(2, fixture)` → expect success with
  `requestCount == 3`; (b) enqueue `400` then `200` → expect failure with
  `requestCount == 1` (no retry on 4xx); use `runTest` virtual time for backoff.
  Expected: as above; backoff advanced via `advanceUntilIdle()`, no `Thread.sleep`.
  Traces: AC-4.

- **TC-AND-198-06 — 401 → single `/ui/session/refresh` → retry once.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: authenticated test session; auth interceptor pointed at
  `MockBackend`.
  Steps: enqueue `401` for `/ui/videos/vid_123`, `200` for
  `POST /ui/session/refresh`, `200` retry of the original; then a separate case
  enqueues `401`→refresh `200`→`401` again.
  Expected: first case: exactly one refresh, original call succeeds; second case:
  re-auth/logout surface signaled (`session_expired`), no infinite loop. Assert
  request order and that `X-CSRF-Token` header is present on mutating refresh.
  Traces: AC-4.

- **TC-AND-198-07 — ViewModel state transitions (Turbine).**
  Type: unit (JVM, `MainDispatcherRule`). Target: JVM.
  Preconditions: ViewModel constructed with fakes; `StandardTestDispatcher`.
  Steps: drive success, stale, no-cache-error, `retryDetail()`, `onPlaybackError`,
  `retryPlayback()`.
  Expected: `Loading → Content`; `Content(isStale=true)`; `detailError` when no
  cache; `retryDetail()` re-issues the fetch; `playbackError` set on error;
  `retryPlayback()` increments `playbackRetryToken`.
  Traces: AC-5.

- **TC-AND-198-08 — VOD catalog Paging (cursor) source.**
  Type: unit (JVM, `paging-testing`). Target: JVM.
  Preconditions: `FakeVodRepository`/MockWebServer serving cursor pages.
  Steps: `asSnapshot { scrollTo(...) }`; force an error page; force an empty page.
  Expected: pages load with correct **cursor** keys; `LoadState.Error` surfaced on
  failure; empty → empty snapshot + end-of-pagination (`endOfPaginationReached`).
  Traces: AC-6.

- **TC-AND-198-09 — Compose catalog screen states + navigation.**
  Type: Compose-UI (instrumented). Target: emu test35 (CI); JVM/Robolectric
  acceptable as fallback.
  Preconditions: `createComposeRule`; animations disabled.
  Steps: render loading skeleton → grid; render empty; render error + click
  "Retry"; render offline/stale banner; click an item.
  Expected: each state visible; Retry invokes callback; item click emits
  navigation with the right `video_id`. Strings asserted via `R.string.*`.
  Traces: AC-7.

- **TC-AND-198-10 — Compose detail screen: metadata, play-gating, errors,
  rotation.**
  Type: Compose-UI (instrumented). Target: emu test35.
  Preconditions: `createComposeRule` / `StateRestorationTester`.
  Steps: skeleton → metadata; assert play control enabled **only** when
  `playbackUrl != null` (i.e. `hls_manifest_url` present); detail error + Retry;
  playback error + Retry; rotate (state restoration) and assert playback position
  preserved.
  Expected: as described; restoration retains position.
  Traces: AC-7, AC-5.

- **TC-AND-198-11 — Player lifecycle with `FakePlayer`.**
  Type: instrumented (Compose lifecycle) / JVM unit for the controller. Target:
  emu test35 (lifecycle events) or JVM for the seam.
  Preconditions: `FakePlayer` injected via `ExoPlayerFactory` seam.
  Steps: drive `ON_PAUSE`, `ON_DESTROY`; recompose the player host.
  Expected: `paused == true` on background; `released == true` on destroy (no
  leak); no second player instantiated across recomposition.
  Traces: AC-8.

- **TC-AND-198-12 — Telemetry events + log redaction.**
  Type: unit (JVM). Target: JVM.
  Preconditions: `FakeAnalytics` injected; a signed `hls_manifest_url` with query
  params; log capture.
  Steps: exercise detail-view, playback-start/error, load-error, served-stale;
  capture emitted log lines.
  Expected: documented events fire with payloads (`videoId`, etc.); captured logs
  contain no cookie, no `X-CSRF-Token`, and no URL query string. (Event names are
  an Open assumption — assert against the AND-197 contract once fixed.)
  Traces: AC-9.

- **TC-AND-198-13 — Determinism / no-network / dev-host guard.**
  Type: unit + CI lint (JVM). Target: JVM (lint runs in CI).
  Preconditions: full suite + a source-scanning check.
  Steps: run suites twice with shuffled order; run the guard that greps test +
  fixture sources for `18.222.237.167`.
  Expected: identical pass results regardless of order; no wall-clock/network use;
  build **fails** if a hardcoded dev-host reference is found.
  Traces: AC-10, AC-1.

- **TC-AND-198-14 — Real-HLS playback smoke (manual gate).**
  Type: instrumented/e2e + manual. Target: **physical device A15** (REQUIRED — real
  Media3/ExoPlayer HLS decode, arm64-v8a, real network; emulator HLS/codec
  behavior is not representative).
  Preconditions: a known-good HLS master playlist; signed-in build.
  Steps: open a video detail, start playback, observe ExoPlayer reaches
  `STATE_READY` and renders; rotate; background/foreground.
  Expected: playback starts and survives rotation/lifecycle; no crash/leak. This
  is a smoke gate owned jointly with AND-197 and is **excluded from the
  deterministic CI suite**.
  Traces: AC-1 (and validates AC-7/AC-8 against real hardware).

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (tests pass green in CI) | TC-13, TC-14 (all TCs collectively) |
| AC-2 (repo cache-first/success/stale/404·401·5xx) | TC-01, TC-03, TC-04 |
| AC-3 (mapping: snake_case, optionals, unknown, 3 `detail` shapes) | TC-02, TC-03 |
| AC-4 (retry on 5xx/timeout, no retry on 4xx, 401→refresh×1) | TC-05, TC-06 |
| AC-5 (ViewModel Turbine transitions, playbackRetryToken) | TC-07, TC-10 |
| AC-6 (Paging: load, error LoadState, empty/end-of-pagination) | TC-08 |
| AC-7 (Compose: skeleton/grid/empty/error+Retry/stale/play-gate/rotation) | TC-09, TC-10 |
| AC-8 (player lifecycle: pause/release/no-duplicate) | TC-11, TC-14 |
| AC-9 (telemetry events + redaction) | TC-12 |
| AC-10 (no dev backend/wall-clock; repeatable; dev-host guard) | TC-13 |

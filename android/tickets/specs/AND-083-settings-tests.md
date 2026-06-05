---
id: AND-083
title: Settings tests
milestone: M2
epic: E11
priority: P2
size: M
status: draft
depends_on: [AND-078, AND-079, AND-080, AND-081]
blocks: []
---

# AND-083 — Settings tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the Settings/Preferences feature area in the TestLogon native Android port (`com.testlogon.android`). It is a **Test-type** ticket: it adds no new production behaviour and ships no user-visible UI. Its goal is to lock down the *preferences round-trip* — the path that takes a user toggle in a Settings screen, persists it through `PreferencesRepository` (defined by AND-078), pushes it to the FastAPI backend, reads it back, and reflects the canonical server state in the UI — with deterministic, hermetic, fast tests.

Concretely, "preferences round-trip" means verifying that:

1. A `GET` of the relevant preferences endpoint maps the server DTO to the domain model and into `StateFlow<SettingsUiState>` correctly.
2. A user mutation (toggle/select) optimistically updates UI state, issues the correct `PATCH/PUT` request with the correct body and `X-CSRF-Token` header, and on success commits the server-confirmed value.
3. On failure (HTTP error, network timeout, 401) the repository surfaces a typed `ApiResult.Error` / `ApiResult.NetworkError` and the ViewModel rolls back the optimistic value and exposes an error state.
4. Local DataStore caching (where AND-078 caches preferences) round-trips the values across process death.

The deliverable is "**Tests pass**" (per the backlog acceptance) — a green unit + instrumentation suite wired into CI, with measurable coverage of the repository and Settings ViewModels.

This ticket does **not** modify `PreferencesRepository`, DTOs, or any Settings UI. If a test exposes a defect, the fix lands in the owning feature ticket (AND-078 for repo/DTO/data; AND-079/080/081/082 for screen behaviour) and this ticket only adds the regression test.

## 2. Context & References

- **Module layering:** `feature-settings -> core-data -> core-network -> core-model`, with `core-testing` providing shared fakes/fixtures. Tests for the repository live in `core-data` (or wherever AND-078 placed `PreferencesRepository`); ViewModel tests live in `feature-settings`.
- **Upstream tickets under test:**
  - **AND-078 — Preferences API + DTOs (P0):** owns `preferences.ts`-equivalent endpoints/DTOs and the `PreferencesRepository`. This is the primary system under test; AND-083 hard-depends on it.
  - **AND-079 — Media preferences:** `/ui/media/preferences` (autoplay, data saver, quality).
  - **AND-080 — Notification preferences UI:** per-category push/email/SMS toggles.
  - **AND-081 — Appearance/theme settings:** light/dark/system + dynamic color (persisted locally in DataStore, not server-side).
  - **AND-077 — Settings hub IA:** navigation entry points (light smoke coverage only).
- **Web reference:** `frontend/src/api/endpoints/preferences.ts`, media endpoints under `frontend/src/api/endpoints/*.ts`, and shared shapes in `frontend/src/api/types.ts`. Test fixtures should be derived from these and from `/openapi.json` so DTO shapes stay faithful to the backend.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable). **Tests never touch the live host.** All HTTP is served by an in-process `MockWebServer` (OkHttp) with canned JSON.
- **Stack:** Kotlin 2.0.21, JUnit4, Coroutines `kotlinx-coroutines-test` 1.9.x (`runTest`, `StandardTestDispatcher`), Turbine for `Flow` assertions, MockWebServer 4.12, Truth assertions, Robolectric for JVM-side Android deps (DataStore), Compose UI test (`createAndroidComposeRule`) for instrumentation, Hilt test runner for DI.

## 3. Functional Requirements

This being a test ticket, "functional requirements" are the behaviours the suite must assert.

FR-1. **GET round-trip (load).** Given a stubbed `200` response for each preferences endpoint, the repository returns `ApiResult.Success<T>` with a domain model whose fields equal the DTO-mapped JSON. Null/absent optional fields map to documented defaults.

FR-2. **Mutation round-trip (save).** A repository `update*` call issues exactly one request to the correct path with the correct HTTP method, a body matching the expected JSON, and a non-empty `X-CSRF-Token` header sourced from the cookie jar. The returned value reflects the server response body, not the request body.

FR-3. **Optimistic update + commit.** A ViewModel toggle emits an immediate UI state change (optimistic), then a confirmed state once the network call resolves. Asserted via Turbine on `StateFlow<SettingsUiState>`.

FR-4. **Rollback on error.** On `4xx/5xx`, timeout, or `IOException`, the ViewModel reverts the optimistic value to the prior committed value and exposes a user-facing error (`SettingsUiState.error`).

FR-5. **401 refresh-once.** A first `401` triggers exactly one `POST /ui/session/refresh` then a single retry of the original request; a second `401` surfaces an auth error and no infinite loop occurs (assert request count on MockWebServer).

FR-6. **Local persistence round-trip.** Appearance/theme prefs (AND-081, DataStore-backed) survive a simulated process restart: write via repository, recreate the DataStore/repository against the same file, read back identical values.

FR-7. **Error `detail` mapping.** FastAPI error bodies in all three shapes — `{"detail":"msg"}`, `{"detail":[{"msg":"..."}]}`, `{"detail":{"code":"...","message":"..."}}` — map to a stable typed error message via the shared mapper.

FR-8. **UI smoke (instrumentation).** Each Settings subsection screen renders its controls, reflects seeded state, and on user interaction calls the (fake) repository with the expected argument. No real network.

## 4. Technical Design

### 4.1 Test source sets & placement

```
core-data/src/test/kotlin/com/testlogon/android/core/data/
    PreferencesRepositoryTest.kt
    PreferencesErrorMappingTest.kt
core-data/src/test/kotlin/com/testlogon/android/core/data/datastore/
    AppearancePreferencesStoreTest.kt        // Robolectric for DataStore
feature-settings/src/test/kotlin/com/testlogon/android/feature/settings/
    MediaPreferencesViewModelTest.kt
    NotificationPreferencesViewModelTest.kt
    AppearanceSettingsViewModelTest.kt
feature-settings/src/androidTest/kotlin/com/testlogon/android/feature/settings/
    MediaPreferencesScreenTest.kt
    NotificationPreferencesScreenTest.kt
    AppearanceSettingsScreenTest.kt
    SettingsHubNavigationTest.kt
core-testing/src/main/kotlin/com/testlogon/android/core/testing/
    MockWebServerExtensions.kt
    MainDispatcherRule.kt
    PreferencesFixtures.kt
    FakePreferencesRepository.kt
```

### 4.2 Shared test infrastructure (added to `core-testing`)

```kotlin
class MainDispatcherRule(
    private val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}
```

Retrofit-against-MockWebServer builder, reused by repository tests:

```kotlin
fun preferencesApi(server: MockWebServer): PreferencesApi =
    Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient.Builder()
            .callTimeout(20, TimeUnit.SECONDS)
            .cookieJar(InMemoryCookieJar(seedCsrf = "test-csrf"))
            .addInterceptor(CsrfHeaderInterceptor())   // production interceptor under test
            .build())
        .addConverterFactory(MoshiConverterFactory.create(testMoshi))
        .build()
        .create(PreferencesApi::class.java)
```

`FakePreferencesRepository` implements the production `PreferencesRepository` interface (from AND-078) backed by `MutableStateFlow`s, with a programmable `nextResult: ApiResult<*>` and a recorded `calls: List<Recorded>` list for ViewModel-level assertions without a network.

### 4.3 Repository tests (JVM, no Android)

`PreferencesRepositoryTest` exercises the real repository against MockWebServer:

```kotlin
@get:Rule val mainRule = MainDispatcherRule()

@Test fun `loadMediaPreferences maps dto to domain`() = runTest {
    server.enqueue(jsonResponse(200, PreferencesFixtures.MEDIA_PREFS_JSON))
    val result = repository.getMediaPreferences()
    assertThat(result).isInstanceOf(ApiResult.Success::class.java)
    val prefs = (result as ApiResult.Success).data
    assertThat(prefs.autoplay).isTrue()
    assertThat(prefs.dataSaver).isFalse()
    assertThat(prefs.quality).isEqualTo(VideoQuality.AUTO)
    val recorded = server.takeRequest()
    assertThat(recorded.path).isEqualTo("/ui/media/preferences")
    assertThat(recorded.method).isEqualTo("GET")
}

@Test fun `updateMediaPreferences sends csrf header and patch body`() = runTest {
    server.enqueue(jsonResponse(200, PreferencesFixtures.MEDIA_PREFS_DATASAVER_JSON))
    val result = repository.setDataSaver(enabled = true)
    val req = server.takeRequest()
    assertThat(req.method).isEqualTo("PATCH")
    assertThat(req.getHeader("X-CSRF-Token")).isEqualTo("test-csrf")
    assertThat(req.body.readUtf8()).isEqualTo("""{"data_saver":true}""")
    assertThat((result as ApiResult.Success).data.dataSaver).isTrue()
}
```

### 4.4 ViewModel tests (JVM, Turbine)

```kotlin
@Test fun `toggling autoplay is optimistic then committed`() = runTest {
    val repo = FakePreferencesRepository(initial = mediaPrefs(autoplay = false))
    val vm = MediaPreferencesViewModel(repo, savedStateHandle)
    vm.uiState.test {
        assertThat(awaitItem().autoplay).isFalse()       // initial
        vm.onAutoplayChanged(true)
        assertThat(awaitItem().autoplay).isTrue()         // optimistic
        repo.completeNext(ApiResult.Success(mediaPrefs(autoplay = true)))
        expectNoEvents()                                  // confirmed == optimistic
    }
}

@Test fun `failed save rolls back and surfaces error`() = runTest {
    val repo = FakePreferencesRepository(initial = mediaPrefs(autoplay = false))
    val vm = MediaPreferencesViewModel(repo, savedStateHandle)
    vm.uiState.test {
        awaitItem()
        vm.onAutoplayChanged(true)
        awaitItem()                                       // optimistic true
        repo.completeNext(ApiResult.Error(code = 500, message = "boom"))
        val rolled = awaitItem()
        assertThat(rolled.autoplay).isFalse()             // rollback
        assertThat(rolled.error).isNotNull()
    }
}
```

### 4.5 DataStore persistence test (Robolectric)

Uses a `tmpFolder`-backed `PreferenceDataStoreFactory`; writes, closes, recreates against the same file, asserts equality (FR-6).

### 4.6 Compose UI tests (instrumentation)

```kotlin
@get:Rule val composeRule = createAndroidComposeRule<HiltTestActivity>()

@Test fun toggling_data_saver_calls_repository() {
    val fake = FakePreferencesRepository(initial = mediaPrefs(dataSaver = false))
    composeRule.setContent { MediaPreferencesScreen(viewModel = vmWith(fake)) }
    composeRule.onNodeWithTag("pref_data_saver").assertIsOff().performClick()
    composeRule.runOnIdle {
        assertThat(fake.calls).contains(Recorded.SetDataSaver(true))
    }
}
```

UI uses Hilt test components with `FakePreferencesRepository` bound via `@TestInstallIn` replacing the production data binding module.

## 5. API Contract

This ticket asserts contracts owned by AND-078/079/080; it defines no new endpoints. The fixtures must mirror these shapes (canonical, derived from `/openapi.json` and `frontend/src/api/types.ts`):

`GET /ui/media/preferences` → `200`:
```json
{ "autoplay": true, "data_saver": false, "quality": "auto" }
```
`PATCH /ui/media/preferences` request body (single field example):
```json
{ "data_saver": true }
```
Notification preferences (AND-080), `GET /ui/notifications/preferences` → `200`:
```json
{ "categories": [
  { "key": "social", "push": true, "email": false, "sms": false },
  { "key": "security", "push": true, "email": true, "sms": true }
] }
```
FastAPI error bodies that fixtures must include (FR-7), one per shape:
```json
{ "detail": "Invalid preference value" }
{ "detail": [ { "msg": "quality: invalid enum", "loc": ["body","quality"] } ] }
{ "detail": { "code": "PREF_CONFLICT", "message": "Stale preferences" } }
```
401 refresh path: first request → `401`; `POST /ui/session/refresh` → `200` (sets refreshed cookie); retried original request → `200`. Appearance prefs (AND-081) are local-only DataStore values with no API contract; that is owned downstream and exercised purely via FR-6.

## 6. Data & State Management

- **State under test:** `data class SettingsUiState(...)` exposed as `StateFlow<SettingsUiState>` per subsection ViewModel, including `isLoading`, the typed preference values, a transient `error: UiText?`, and a `pendingFields: Set<PrefKey>` for in-flight optimism. Tests assert each emission sequence with Turbine.
- **Determinism:** all coroutines run on an injected `TestDispatcher`; no `Dispatchers.IO`/`Main` references in production code may be hard-coded — if a test reveals one, the fix is filed against the owning ticket. `runTest` virtual time advances retry/backoff windows so timeout tests complete in milliseconds.
- **Cache:** if AND-078 caches preferences (DataStore/Room), tests assert read-through (cache miss → network → cache write) and read-from-cache-on-offline. Fixtures seed cache state directly via the fake/test DataStore.
- **No shared mutable state across tests:** each test constructs its own `MockWebServer`, repository, and temp DataStore file; `@After` shuts down the server.

## 7. Error Handling & Resilience

The suite is the *verifier* of resilience behaviour rather than its implementer. Required assertions:

- **Timeout:** enqueue a response with `setBodyDelay(25, SECONDS)`; with virtual time advanced past the 20s call timeout, the repository yields `ApiResult.NetworkError` (timeout), not a hang. (Verified with MockWebServer's throttle + `advanceTimeBy`.)
- **Backoff retry (idempotent GET only):** stub two `503`s then a `200`; assert the GET is retried per the bounded policy and ultimately succeeds, and that a `PATCH` returning `503` is **not** retried (request count == 1).
- **401 single refresh:** FR-5 — exactly one refresh, one retry, no loop.
- **Malformed JSON:** enqueue invalid body; assert `ApiResult.Error` (parse) rather than crash.
- **Offline/stale UI:** ViewModel exposes a `stale` or offline state when load fails but cache exists; asserted via Turbine.

## 8. Security & Privacy

- Tests assert the `X-CSRF-Token` header is present and equals the `ui_csrf` cookie value on every mutating request (FR-2); a mutation missing the header is a test failure.
- Tests assert no preference payloads, cookies, CSRF tokens, or session identifiers are written to logs by the code under test (capture a test logger / Timber test tree and assert redaction).
- All test traffic targets `localhost` MockWebServer; the suite must contain **no** reference to `18.222.237.167` or any plaintext production host. A lint/CI grep guard fails the build if such a literal appears in test sources.
- No real credentials or PII in fixtures; usernames/emails are synthetic (`test@example.com`).

## 9. Accessibility & i18n

- Compose UI tests assert each interactive control has a non-empty content description / accessible label and a stable `testTag`, indirectly enforcing the a11y requirement on the Settings screens.
- Tests assert toggle state is exposed via `assertIsOn()/assertIsOff()` (semantics `ToggleableState`), confirming switches are programmatically inspectable by TalkBack.
- i18n: error strings asserted as resource-backed `UiText` (string-res references), not hard-coded literals, so localization is preserved. No new user-facing strings are introduced by this ticket.

## 10. Telemetry & Logging

No production telemetry is added. The suite may assert that expected analytics events (if defined by AND-079/080/081) are emitted to a `FakeAnalytics` recorder on preference change — but only where the owning ticket specifies such events; otherwise this is N/A and owned downstream. CI publishes the JUnit XML and JaCoCo coverage report as build artifacts; test logs go to `--info` Gradle output only.

## 11. Testing Strategy

- **Unit (JVM, `test/`):** repository mapping + CSRF + error-mapping + retry/timeout (MockWebServer); ViewModel optimism/rollback/state (FakeRepository + Turbine). Fast, no emulator. This is the bulk of the suite.
- **Robolectric (JVM):** DataStore persistence round-trip (FR-6).
- **Instrumentation (`androidTest/`):** Compose screen smoke + interaction-calls-repository (Hilt + fakes); one navigation smoke for the Settings hub (AND-077).
- **Coverage target:** ≥ 85% line coverage on `PreferencesRepository` and the Settings ViewModels (measured via JaCoCo); enforced as a soft CI gate (report; warn below threshold).
- **Test data:** `PreferencesFixtures` holds all canned JSON, derived from `/openapi.json`. A single golden-fixture test deserializes each fixture into its DTO to catch fixture/DTO drift.
- **CI wiring:** `./gradlew :core-data:testDebugUnitTest :feature-settings:testDebugUnitTest` runs on every PR; `connectedDebugAndroidTest` (or Gradle Managed Devices, API 34) runs the instrumentation tier on the `android-port` branch. Flake budget: instrumentation tests use idling resources / `runOnIdle`; no `Thread.sleep`.

## 12. Dependencies & Sequencing

- **Hard depends on AND-078** (repository + DTOs must exist and expose a testable interface). The repository must be an interface (for `FakePreferencesRepository`) and accept an injectable dispatcher.
- **Soft depends on AND-079, AND-080, AND-081** for the subsection ViewModels/screens to exist; UI tests for a given subsection land as that subsection merges. Repository/data tests can land as soon as AND-078 is in.
- **Uses AND-077** for the hub navigation smoke test.
- **Provides** to `core-testing`: `MainDispatcherRule`, `FakePreferencesRepository`, `PreferencesFixtures`, MockWebServer helpers — reusable by sibling test tickets.
- Sequencing: implement shared `core-testing` infra → repository tests → ViewModel tests → instrumentation tests.

## 13. Risks & Open Questions

- **R1 — Endpoint/method shapes unconfirmed.** The exact paths/verbs/body keys for media and notification preferences must be confirmed against `/openapi.json` before fixtures are frozen. *Mitigation:* golden-fixture deserialization test + derive from OpenAPI.
- **R2 — Optimistic-update semantics may not yet be implemented** in AND-079/080. If the ViewModels save without optimism, FR-3/FR-4 assertions must follow whatever AND-078/079 actually specify; align with those tickets, do not implement behaviour here.
- **R3 — Instrumentation flakiness / emulator availability in CI.** *Mitigation:* prefer Gradle Managed Devices; keep instrumentation tier thin (smoke only), push logic coverage to JVM.
- **R4 — Retry/backoff policy location.** If retry lives in an OkHttp interceptor vs. repository, timeout/retry tests target the correct layer; confirm with AND-027 (network core) owners.
- **Open Q1:** Are appearance prefs purely local (DataStore) or also synced server-side? Assumed local-only per AND-081; revisit if AND-078 syncs them.
- **Open Q2:** Is there a server-side conflict/version field requiring `PREF_CONFLICT` handling beyond FR-7? Pending OpenAPI confirmation.

## 14. Acceptance Criteria

1. `:core-data:testDebugUnitTest` and `:feature-settings:testDebugUnitTest` pass green locally and in CI (satisfies backlog "Tests pass").
2. Repository tests assert GET mapping (FR-1), mutation path/method/body/CSRF header (FR-2) for media and notification preferences.
3. ViewModel tests assert optimistic update (FR-3) and rollback-with-error (FR-4) via Turbine for at least the media and notification subsections.
4. A 401 → single `/ui/session/refresh` → single retry test passes and proves no retry loop via MockWebServer request count (FR-5).
5. A DataStore persistence round-trip test proves appearance prefs survive store recreation (FR-6).
6. All three FastAPI `detail` shapes map to stable typed errors (FR-7).
7. Timeout (20s) and bounded-GET-retry / no-mutation-retry behaviours are asserted with virtual time (Section 7).
8. Instrumentation smoke tests render each Settings subsection, reflect seeded state, and verify interaction calls the repository with the expected argument (FR-8).
9. No test references the live dev host; CI grep guard for `18.222.237.167` in test sources passes (no matches).
10. JaCoCo coverage report is produced; `PreferencesRepository` + Settings ViewModels ≥ 85% line coverage (soft gate).

## 15. Definition of Done

- All test files in Section 4.1 implemented and passing on the `android-port` branch.
- Shared test utilities added to `core-testing` and reused (no duplicated MockWebServer/dispatcher boilerplate).
- Unit + Robolectric tiers run on every PR; instrumentation tier runs in CI on `android-port`; both green.
- Fixtures derive from `/openapi.json` and pass the golden deserialization test; no fixture/DTO drift.
- No new production source modified except, if strictly required, making `PreferencesRepository` injectable/interface-shaped — and only via the owning ticket; any defect found is filed against AND-078/079/080/081, not patched here.
- No flaky tests (`Thread.sleep` free; idling-resource based); suite runtime for the JVM tier under ~30s.
- JaCoCo and JUnit XML published as CI artifacts; coverage gate reported.
- Code reviewed and merged; ticket linked to the defects it surfaced (if any).

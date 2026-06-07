---
id: AND-083
title: Settings tests
milestone: M2
epic: E11
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-078, AND-079, AND-080, AND-081]
blocks: []
---

# AND-083 — Settings tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the Settings/Preferences feature area in the TestLogon native Android port (`com.testlogon.android`). It is a **Test-type** ticket: it adds no new production behaviour and ships no user-visible UI. Its goal is to lock down the *preferences round-trip* — the path that takes a user toggle in a Settings screen, persists it through `PreferencesRepository` (defined by AND-078), pushes it to the FastAPI backend, reads it back, and reflects the canonical server state in the UI — with deterministic, hermetic, fast tests.

Concretely, "preferences round-trip" means verifying that:

1. A `GET` of the relevant preferences endpoint maps the server DTO to the domain model and into `StateFlow<SettingsUiState>` correctly.
2. A user mutation (toggle/select) optimistically updates UI state, issues the correct request with the correct method and body — **`PUT /ui/media/preferences`** for media, **`PATCH /ui/settings/preferences`** for appearance, **`POST /ui/alerts/type-preferences`** (or the per-channel `/ui/alerts/*_prefs` POSTs) for notifications — plus the `X-CSRF-Token` header (verified: sourced from the `ui_csrf` cookie in `src/api/client.ts`), and on success commits the server-confirmed value.
3. On failure (HTTP error, network timeout, 401) the repository surfaces a typed `ApiResult.Error` / `ApiResult.NetworkError` and the ViewModel rolls back the optimistic value and exposes an error state.
4. Local DataStore caching (where AND-078 caches preferences) round-trips the values across process death.

The deliverable is "**Tests pass**" (per the backlog acceptance) — a green unit + instrumentation suite wired into CI, with measurable coverage of the repository and Settings ViewModels.

This ticket does **not** modify `PreferencesRepository`, DTOs, or any Settings UI. If a test exposes a defect, the fix lands in the owning feature ticket (AND-078 for repo/DTO/data; AND-079/080/081/082 for screen behaviour) and this ticket only adds the regression test.

## 2. Context & References

- **Module layering:** `feature-settings -> core-data -> core-network -> core-model`, with `core-testing` providing shared fakes/fixtures. Tests for the repository live in `core-data` (or wherever AND-078 placed `PreferencesRepository`); ViewModel tests live in `feature-settings`.
- **Upstream tickets under test:**
  - **AND-078 — Preferences API + DTOs (P0):** owns `preferences.ts`-equivalent endpoints/DTOs and the `PreferencesRepository`. This is the primary system under test; AND-083 hard-depends on it.
  - **AND-079 — Media preferences:** `GET`/`PUT /ui/media/preferences`. **Correction:** the real `MediaPreferencesIn`/`MediaPreferencesOut` fields are `default_audio_muted`, `default_video_off`, `video_resolution` (enum `"360"|"480"|"720"|"1080"`, default `"720"`), and device-selection IDs (`preferred_audio_input_id`/`preferred_audio_output_id`/`preferred_video_input_id`); `MediaPreferencesOut` also carries server-injected ad fields (`is_house_ad`, `skip_after_seconds`, `user_sub`, `updated_at`, etc.). There are **no** `autoplay`, `data_saver`, or `quality` fields.
  - **AND-080 — Notification preferences UI:** per-channel/per-type toggles. **Correction:** there is no `/ui/notifications/preferences` endpoint. The web client uses `src/api/endpoints/alerts.ts`: `POST /ui/alerts/type-preferences` (`AlertTypePreferenceUpdate`: `alert_type` + nullable `email`/`push`/`sms`/`in_app`/`enabled`), and per-channel list endpoints `GET`/`POST /ui/alerts/{email_prefs,sms_prefs,toast_prefs,webhook_prefs}`.
  - **AND-081 — Appearance/theme settings:** light/dark/system + accent/density/font. **Correction:** appearance prefs are **server-synced**, not local-only — `PATCH /ui/settings/preferences` (`PreferencesPatchReq`) accepts `theme` (`system|light|dark`), `accent_color`, `custom_accent_hex`, `font_size`, `density`, `high_contrast`, `sidebar_collapsed`. A DataStore cache may still front them locally, but the server is authoritative (see Section 13 Open Q1).
  - **AND-077 — Settings hub IA:** navigation entry points (light smoke coverage only).
- **Web reference (verified paths):** `src/api/endpoints/preferences.ts` (UI/appearance prefs → `GET`/`PATCH /ui/settings/preferences`, `POST /ui/settings/validate-color`), `src/api/endpoints/mediaPreferences.ts` (`GET`/`PUT /ui/media/preferences`), `src/api/endpoints/alerts.ts` (notification/alert channel prefs), `src/api/client.ts` (auth header, CSRF, 401-refresh transport), and shared shapes in `src/api/types.ts` (`MediaPreferencesIn`/`MediaPreferencesOut`). Test fixtures should be derived from these and from `openapi.pretty.json` so DTO shapes stay faithful to the backend. **Note:** there is NO `frontend/src/api/endpoints/preferences.ts` "media" call and no `/ui/notifications/preferences` endpoint — see Section 5 corrections.
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

// NOTE: fields/method below are corrected against MediaPreferencesOut / MediaPreferencesIn
// and the verified PUT verb (openapi.index: PUT /ui/media/preferences).
@Test fun `loadMediaPreferences maps dto to domain`() = runTest {
    server.enqueue(jsonResponse(200, PreferencesFixtures.MEDIA_PREFS_JSON))
    val result = repository.getMediaPreferences()
    assertThat(result).isInstanceOf(ApiResult.Success::class.java)
    val prefs = (result as ApiResult.Success).data
    assertThat(prefs.defaultAudioMuted).isFalse()
    assertThat(prefs.defaultVideoOff).isFalse()
    assertThat(prefs.videoResolution).isEqualTo(VideoResolution.P720)
    val recorded = server.takeRequest()
    assertThat(recorded.path).isEqualTo("/ui/media/preferences")
    assertThat(recorded.method).isEqualTo("GET")
}

@Test fun `updateMediaPreferences sends csrf header and put body`() = runTest {
    server.enqueue(jsonResponse(200, PreferencesFixtures.MEDIA_PREFS_MUTED_JSON))
    val result = repository.setDefaultAudioMuted(muted = true)
    val req = server.takeRequest()
    assertThat(req.method).isEqualTo("PUT")            // verified PUT, not PATCH
    assertThat(req.getHeader("X-CSRF-Token")).isEqualTo("test-csrf")
    // Body is the full MediaPreferencesIn (server merges by overwrite on PUT);
    // assert the mutated field is present and correct.
    assertThat(req.body.readUtf8()).contains("\"default_audio_muted\":true")
    assertThat((result as ApiResult.Success).data.defaultAudioMuted).isTrue()
}
```

### 4.4 ViewModel tests (JVM, Turbine)

```kotlin
// Uses real media field `default_video_off` (no `autoplay` field exists).
@Test fun `toggling defaultVideoOff is optimistic then committed`() = runTest {
    val repo = FakePreferencesRepository(initial = mediaPrefs(defaultVideoOff = false))
    val vm = MediaPreferencesViewModel(repo, savedStateHandle)
    vm.uiState.test {
        assertThat(awaitItem().defaultVideoOff).isFalse()   // initial
        vm.onDefaultVideoOffChanged(true)
        assertThat(awaitItem().defaultVideoOff).isTrue()    // optimistic
        repo.completeNext(ApiResult.Success(mediaPrefs(defaultVideoOff = true)))
        expectNoEvents()                                    // confirmed == optimistic
    }
}

@Test fun `failed save rolls back and surfaces error`() = runTest {
    val repo = FakePreferencesRepository(initial = mediaPrefs(defaultVideoOff = false))
    val vm = MediaPreferencesViewModel(repo, savedStateHandle)
    vm.uiState.test {
        awaitItem()
        vm.onDefaultVideoOffChanged(true)
        awaitItem()                                         // optimistic true
        repo.completeNext(ApiResult.Error(code = 500, message = "boom"))
        val rolled = awaitItem()
        assertThat(rolled.defaultVideoOff).isFalse()        // rollback
        assertThat(rolled.error).isNotNull()
    }
}
```

### 4.5 DataStore persistence test (Robolectric)

Uses a `tmpFolder`-backed `PreferenceDataStoreFactory`; writes, closes, recreates against the same file, asserts equality (FR-6).

### 4.6 Compose UI tests (instrumentation)

```kotlin
@get:Rule val composeRule = createAndroidComposeRule<HiltTestActivity>()

@Test fun toggling_default_audio_muted_calls_repository() {
    val fake = FakePreferencesRepository(initial = mediaPrefs(defaultAudioMuted = false))
    composeRule.setContent { MediaPreferencesScreen(viewModel = vmWith(fake)) }
    composeRule.onNodeWithTag("pref_default_audio_muted").assertIsOff().performClick()
    composeRule.runOnIdle {
        assertThat(fake.calls).contains(Recorded.SetDefaultAudioMuted(true))
    }
}
```

UI uses Hilt test components with `FakePreferencesRepository` bound via `@TestInstallIn` replacing the production data binding module.

## 5. API Contract

This ticket asserts contracts owned by AND-078/079/080/081; it defines no new endpoints. The fixtures must mirror these shapes (canonical, verified against `openapi.pretty.json` `components.schemas.*` and `src/api/types.ts` / `src/api/endpoints/*.ts`):

**Media preferences (AND-079).** `GET /ui/media/preferences` → `200:MediaPreferencesOut`; mutation is **`PUT /ui/media/preferences`** (verified — NOT `PATCH`), request body `MediaPreferencesIn`, response `200:MediaPreferencesOut`.

`GET /ui/media/preferences` → `200` (`MediaPreferencesOut`; `user_sub` is the only required field; ad/server fields shown abbreviated):
```json
{ "user_sub": "test-user", "default_audio_muted": false, "default_video_off": false,
  "video_resolution": "720", "preferred_audio_input_id": null,
  "preferred_audio_output_id": null, "preferred_video_input_id": null,
  "is_house_ad": false, "skip_after_seconds": 5, "updated_at": 0 }
```
`PUT /ui/media/preferences` request body (`MediaPreferencesIn`; all fields optional, defaults shown):
```json
{ "default_audio_muted": true, "default_video_off": false, "video_resolution": "720",
  "preferred_audio_input_id": null, "preferred_audio_output_id": null,
  "preferred_video_input_id": null }
```
`video_resolution` is the enum `"360" | "480" | "720" | "1080"` (default `"720"`). There are **no** `autoplay`/`data_saver`/`quality` fields.

**Appearance/UI preferences (AND-081 — server-synced).** `GET /ui/settings/preferences` → `200` wraps the prefs object: `{ "preferences": { ... } }` (web `getPreferences()` reads `resp.preferences`). Mutation is **`PATCH /ui/settings/preferences`**, request body `PreferencesPatchReq` (all fields optional/nullable, merge-update):
```json
{ "preferences": { "theme": "system", "accent_color": "blue", "custom_accent_hex": null,
  "font_size": "default", "density": "comfortable", "high_contrast": false,
  "sidebar_collapsed": false } }
```
Enums: `theme` ∈ {`system`,`light`,`dark`}; `accent_color` ∈ {`blue`,`purple`,`green`,`orange`,`pink`,`red`,`teal`,`custom`}; `font_size` ∈ {`small`,`default`,`large`,`xlarge`}; `density` ∈ {`compact`,`comfortable`,`spacious`}.

**Notification/alert preferences (AND-080).** There is **no** `/ui/notifications/preferences` endpoint and no `{ "categories": [...] }` shape. The verified contract is `POST /ui/alerts/type-preferences` (`AlertTypePreferenceUpdate`):
```json
{ "alert_type": "social", "push": true, "email": false, "sms": false,
  "in_app": true, "enabled": true }
```
(`alert_type` is the only required field; `email`/`push`/`sms`/`in_app`/`enabled` are nullable booleans). Per-channel list endpoints (`src/api/endpoints/alerts.ts`) are `GET`/`POST /ui/alerts/{email_prefs,sms_prefs,toast_prefs,webhook_prefs}` taking arrays of event-type strings (e.g. `{ "email_event_types": ["new_follower"] }`).

**Error bodies (FR-7).** The preference endpoints declare `422:HTTPValidationError` (FastAPI validation: `{ "detail": [ { "msg": "...", "loc": [...], "type": "..." } ] }`). Domain endpoints elsewhere use `ErrorEnvelope` = `{ "error": { "code": "...", "message": "...", "details": {...}? } }` (schema `ErrorDetail`). The web client's `normalizeErrorDetail` (`src/api/client.ts`) handles three `detail` shapes — string, array-of-`{msg}`, and object-with-`code`/`message` — so fixtures must cover all three:
```json
{ "detail": "Invalid preference value" }
{ "detail": [ { "msg": "video_resolution: invalid enum", "loc": ["body","video_resolution"], "type": "enum" } ] }
{ "detail": { "code": "PREF_CONFLICT", "message": "Stale preferences" } }
```
Note: `PREF_CONFLICT`/409 is **not** declared on the preference endpoints in the OpenAPI (only `422`); treat it as an unverified forward-compat assumption (Section 13 Open Q2). Also include an `ErrorEnvelope` fixture to exercise the alternate envelope mapper.

**401 refresh path (verified, `src/api/client.ts`):** first request → `401`; a single shared refresh fires **`POST /ui/session/refresh`** → `200` (refreshes the session cookie); the original request is retried exactly once with the same headers. A second `401` on retry triggers logout, not a loop. Refresh only fires when the user is already authenticated; an unauthenticated `401` propagates directly without a refresh attempt.

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

- Tests assert the `X-CSRF-Token` header is present and equals the `ui_csrf` cookie value on every mutating request (FR-2); a mutation missing the header is a test failure. (Verified: `src/api/client.ts` sets `X-CSRF-Token` from the `ui_csrf` cookie on *every* request — including GETs — whenever the cookie exists; the Android port may scope it to mutations, but the source of truth is the `ui_csrf` cookie value.)
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

- **R1 — Endpoint/method shapes (now confirmed; was a real defect).** This review confirmed the shapes against `openapi.pretty.json` and the web client, and corrected several errors in the original draft: media mutation is **`PUT`** not `PATCH`; media fields are `default_audio_muted`/`default_video_off`/`video_resolution`/device-IDs, not `autoplay`/`data_saver`/`quality`; there is **no** `/ui/notifications/preferences` endpoint (use `/ui/alerts/type-preferences` + `/ui/alerts/*_prefs`); appearance prefs are server-synced via `PATCH /ui/settings/preferences`. *Mitigation:* golden-fixture deserialization test + derive from OpenAPI; keep fixtures in sync with `MediaPreferencesIn/Out`, `PreferencesPatchReq`, `AlertTypePreferenceUpdate`.
- **R2 — Optimistic-update semantics may not yet be implemented** in AND-079/080. If the ViewModels save without optimism, FR-3/FR-4 assertions must follow whatever AND-078/079 actually specify; align with those tickets, do not implement behaviour here.
- **R3 — Instrumentation flakiness / emulator availability in CI.** *Mitigation:* prefer Gradle Managed Devices; keep instrumentation tier thin (smoke only), push logic coverage to JVM.
- **R4 — Retry/backoff policy location.** If retry lives in an OkHttp interceptor vs. repository, timeout/retry tests target the correct layer; confirm with AND-027 (network core) owners.
- **Open Q1 (resolved):** Appearance prefs are **server-synced**, not local-only. `PATCH /ui/settings/preferences` (`PreferencesPatchReq`) and `GET /ui/settings/preferences` (`{ "preferences": {...} }`) carry `theme`/`accent_color`/`font_size`/`density`/`high_contrast`/`sidebar_collapsed`/`custom_accent_hex`. FR-6's local-DataStore round-trip is still valid as a *cache* test, but a server round-trip (load/PATCH) must also be asserted. AND-081 should be confirmed to sync, and any "local-only" assumption removed.
- **Open Q2 (partially resolved):** The preference endpoints declare only `422:HTTPValidationError` in OpenAPI — no `409`/`PREF_CONFLICT` and no version field are documented for media/settings prefs. `PREF_CONFLICT` remains an **unverified forward-compat assumption**; keep the FR-7 object-shape fixture but do not assume a real 409 path exists until AND-078 confirms it.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact authoritative source.

1. **`GET /ui/media/preferences` exists and returns `MediaPreferencesOut`.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/media/preferences` (op `ui_get_media_preferences_..._get`, `resp=200:MediaPreferencesOut`); `src/api/endpoints/mediaPreferences.ts: getMediaPreferences`.
2. **Media mutation HTTP method.** Claim (original): `PATCH /ui/media/preferences`. VERDICT: Corrected → **`PUT`**. SOURCE: OpenAPI `PUT /ui/media/preferences` (op `ui_save_media_preferences_..._put`, `req=MediaPreferencesIn`, `resp=200:MediaPreferencesOut`); `src/api/endpoints/mediaPreferences.ts: saveMediaPreferences` (`api.put<MediaPreferencesOut>`).
3. **Media preference fields.** Claim (original): `autoplay`, `data_saver`, `quality`. VERDICT: Corrected → real fields are `default_audio_muted`, `default_video_off`, `video_resolution` (enum `"360"|"480"|"720"|"1080"`, default `"720"`), `preferred_audio_input_id`, `preferred_audio_output_id`, `preferred_video_input_id`; `MediaPreferencesOut` adds `user_sub` (required), `updated_at`, and ad fields (`is_house_ad`, `skip_after_seconds`, `click_url`, etc.). SOURCE: `components.schemas.MediaPreferencesIn` / `components.schemas.MediaPreferencesOut`; `src/api/types.ts: MediaPreferencesIn / MediaPreferencesOut` (lines ~12732–12748).
4. **Notification preferences endpoint.** Claim (original): `GET /ui/notifications/preferences` with `{ "categories": [{ key, push, email, sms }] }`. VERDICT: Corrected → no such endpoint exists. Real contract: `POST /ui/alerts/type-preferences` (`AlertTypePreferenceUpdate`) and per-channel `GET`/`POST /ui/alerts/{email_prefs,sms_prefs,toast_prefs,webhook_prefs}`. SOURCE: OpenAPI `GET`/`POST /ui/alerts/type-preferences`; `components.schemas.AlertTypePreferenceUpdate` (`alert_type` required; nullable `email`/`push`/`sms`/`in_app`/`enabled`); `src/api/endpoints/alerts.ts: getEmailPrefs/setEmailPrefs/getSmsPrefs/...`. (No `/ui/notifications/preferences` row in `openapi.index.txt`.)
5. **Appearance/theme prefs are local-only (DataStore).** Claim (original, §2/§5/§13). VERDICT: Corrected → server-synced. SOURCE: OpenAPI `GET`/`PATCH /ui/settings/preferences`; `components.schemas.PreferencesPatchReq` (`theme`/`accent_color`/`custom_accent_hex`/`font_size`/`density`/`high_contrast`/`sidebar_collapsed`); `src/api/endpoints/preferences.ts: getPreferences/patchPreferences` (GET wraps as `{ preferences }`, mutation is `api.patch`).
6. **Settings prefs mutation method is `PATCH`.** VERDICT: Verified. SOURCE: OpenAPI `PATCH /ui/settings/preferences` (op `ui_update_preferences_..._patch`, `req=PreferencesPatchReq`); `src/api/endpoints/preferences.ts: patchPreferences`.
7. **CSRF: `X-CSRF-Token` header sourced from the `ui_csrf` cookie.** VERDICT: Verified (and broadened — sent on every request, not only mutations). SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, lines ~168–171).
8. **401 → single `POST /ui/session/refresh` → single retry, no loop.** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_..._post`, `resp=200`); `src/api/client.ts` (`refreshSession()` + shared `refreshPromise`, single retry, logout on second 401, lines ~119–237); `src/api/endpoints/auth.ts: refreshSession` (`api.post<StatusResp>("/ui/session/refresh")`).
9. **Unauthenticated 401 does NOT trigger refresh.** VERDICT: Verified (nuance added). SOURCE: `src/api/client.ts` (`if (!useAuthStore.getState().isAuthenticated) { ... throw }`, lines ~196–203).
10. **Network error surfaces a typed error (no hang).** VERDICT: Verified. SOURCE: `src/api/client.ts` (`catch (err) { ... throw new ApiError(0, "Network error", err) }`, lines ~185–189). Android equivalent: `ApiResult.NetworkError`.
11. **FastAPI error `detail` shapes (string / array-of-`{msg}` / object-with-`code`+`message`) map to a stable message.** VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` (lines ~66–102) + `mapAuthorizationError`; OpenAPI `components.schemas.HTTPValidationError` (`detail: ValidationError[]`, each `{msg, loc, type}`) and `components.schemas.ErrorEnvelope`/`ErrorDetail` (`{ error: { code, message, details? } }`).
12. **Preference endpoints' declared error responses.** VERDICT: Verified (corrects an implicit assumption). SOURCE: OpenAPI rows for `/ui/media/preferences`, `/ui/settings/preferences`, `/ui/alerts/type-preferences` declare only `422:HTTPValidationError`; richer `ErrorEnvelope` codes (e.g. `409`) appear on other domains (e.g. `/integrations/jira/preferences`).
13. **`PREF_CONFLICT` / 409 conflict handling for preferences.** VERDICT: Unverified-assumption. SOURCE: not present on any preference endpoint in `openapi.index.txt`; only `422` is declared. Keep the fixture for forward-compat but do not assert a live 409 path.
14. **Dev host `http://18.222.237.167:8000` is plaintext/unreliable and must never be hit by tests.** VERDICT: Verified (project constraint, consistent with task brief). SOURCE: task environment brief; spec §2/§8. Not independently in OpenAPI (servers list not asserted here).
15. **Test stack choices (JUnit4, kotlinx-coroutines-test `runTest`/`StandardTestDispatcher`, Turbine, MockWebServer, Truth, Robolectric, Compose UI test, Hilt).** VERDICT: Unverified-assumption (framework choices, not backend contract). SOURCE (framework ref): `https://developer.android.com/training/testing`, `https://developer.android.com/jetpack/compose/testing`, `https://developer.android.com/topic/libraries/architecture/datastore#testing`, `https://github.com/cashapp/turbine`, `https://github.com/square/okhttp/tree/master/mockwebserver`, `https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-test/`.
16. **Optimistic-update + rollback semantics in the ViewModels (FR-3/FR-4).** VERDICT: Unverified-assumption (behaviour owned by AND-079/080/081; not derivable from backend or web client, which is fire-and-forget for prefs — see `patchPreferences` "frontend does not wait"). SOURCE: `src/api/endpoints/preferences.ts` doc comment (fire-and-forget); behaviour must be confirmed against AND-078/079.
17. **GET retry/backoff + timeout layer location.** VERDICT: Unverified-assumption. The web client does **not** implement retry/backoff for GETs (only the 401 single-refresh path); whether the Android core-network adds bounded GET retry is owned by AND-027. SOURCE: `src/api/client.ts` (no retry loop beyond 401); spec §13 R4.

### Corrections made

- §2 / §5 / §13: media mutation verb `PATCH` → **`PUT`** (citation 2).
- §1 / §4.3 / §4.4 / §4.6 / §5: media fields `autoplay`/`data_saver`/`quality` → `default_audio_muted`/`default_video_off`/`video_resolution`(+device IDs) (citation 3).
- §2 / §5: removed non-existent `GET /ui/notifications/preferences` + `categories` shape; replaced with `POST /ui/alerts/type-preferences` (`AlertTypePreferenceUpdate`) and `/ui/alerts/*_prefs` (citation 4).
- §2 / §5 / §13 (Open Q1): appearance prefs reclassified from "local-only DataStore" to **server-synced** via `PATCH /ui/settings/preferences` / `PreferencesPatchReq`; GET response wraps as `{ "preferences": {...} }` (citation 5).
- §5: clarified declared error responses are `422:HTTPValidationError`; `PREF_CONFLICT`/409 flagged as unverified (citations 12, 13); added `ErrorEnvelope` fixture note.
- §8: clarified `X-CSRF-Token` is set on every request from the `ui_csrf` cookie, not only mutations (citation 7).
- §5: 401-refresh path annotated as verified, including the unauthenticated-401 no-refresh nuance (citations 8, 9).

### Open assumptions

- **A1 — Optimistic UI + rollback (FR-3/FR-4).** Not verifiable from backend/web (web is fire-and-forget). Confirm with AND-078/079/080 before freezing the Turbine emission sequences.
- **A2 — `PREF_CONFLICT`/409 + version field.** Not in OpenAPI; forward-compat only (citation 13).
- **A3 — GET retry/backoff policy + which layer owns it.** Web client has none; depends on AND-027 core-network design (citation 17).
- **A4 — Android DataStore caching of prefs (FR-6 cache test).** Whether AND-078 fronts server prefs with a DataStore cache is its design choice; the cache round-trip test is valid only if such a cache exists. Appearance still needs a *server* round-trip test regardless (citation 5).
- **A5 — Exact notification subsection mapping.** Which alert endpoint(s) AND-080's screen drives (`type-preferences` vs per-channel `*_prefs`) is a UI-design choice owned by AND-080; fixtures provided for both.

## 17. Test Plan

All HTTP is served by an in-process OkHttp `MockWebServer`; no test touches the live dev host. Target legend per the CI/dev inventory: JVM = local Robolectric/unit (no device); emulator = headless AVD `test35` (x86_64, API 35); device = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Compose-UI/instrumented cases run on the emulator unless a real-hardware reason forces the device.

- **TC-AND-083-01 — Media GET maps DTO → domain (happy path).** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: `MockWebServer` enqueues `200` with `PreferencesFixtures.MEDIA_PREFS_JSON` (real `MediaPreferencesOut` shape). Steps: call `repository.getMediaPreferences()`; take request. Expected: `ApiResult.Success`; `defaultAudioMuted=false`, `defaultVideoOff=false`, `videoResolution=720`; request path `/ui/media/preferences`, method `GET`. Traces: AC-2.
- **TC-AND-083-02 — Media mutation uses PUT + CSRF + correct body.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: cookie jar seeded with `ui_csrf=test-csrf`; enqueue `200` with mutated `MediaPreferencesOut`. Steps: call `repository.setDefaultAudioMuted(true)`; take request. Expected: method `PUT` (not PATCH); `X-CSRF-Token: test-csrf`; body contains `"default_audio_muted":true`; result reflects server body. Traces: AC-2.
- **TC-AND-083-03 — Appearance prefs server round-trip (GET wraps `{preferences}`, PATCH merge).** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue `200 {"preferences":{"theme":"system",...}}` then `200` for PATCH. Steps: `getPreferences()`; assert unwrap; `patchPreferences(theme=dark)`; take requests. Expected: GET `/ui/settings/preferences` unwraps `preferences`; PATCH method `PATCH`, body `{"theme":"dark"}` (only provided field), `X-CSRF-Token` present. Traces: AC-2, AC-5.
- **TC-AND-083-04 — Notification type-preference POST shape.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue `200`. Steps: call repo to set a type pref (e.g. `social` push on); take request. Expected: `POST /ui/alerts/type-preferences`; body includes `"alert_type":"social"` and the toggled channel boolean; `X-CSRF-Token` present. Traces: AC-2. (Uses corrected endpoint; covers assumption A5.)
- **TC-AND-083-05 — ViewModel optimistic-then-committed.** Type: unit (JVM, Turbine + FakeRepository). Target: JVM. Preconditions: `FakePreferencesRepository(initial defaultVideoOff=false)`. Steps: collect `uiState`; call `onDefaultVideoOffChanged(true)`; complete fake with `Success(defaultVideoOff=true)`. Expected: emissions initial=false → optimistic=true → no further change after commit. Traces: AC-3. (Depends on assumption A1.)
- **TC-AND-083-06 — ViewModel rollback + error on failed save.** Type: unit (JVM, Turbine). Target: JVM. Preconditions: fake initial `defaultVideoOff=false`. Steps: toggle to true (optimistic); complete fake with `ApiResult.Error(500)`. Expected: state rolls back to false; `error != null` (resource-backed `UiText`). Traces: AC-3, AC-6.
- **TC-AND-083-07 — 401 → single refresh → single retry, no loop.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue `401`, then `200` for `POST /ui/session/refresh`, then `200` for retried original. Steps: issue a preferences GET/mutation; inspect dispatched requests. Expected: exactly one `/ui/session/refresh`; original retried once; success returned; total request count == 3. Also assert: second-`401`-on-retry case yields auth error/logout and request count == 3 (no further retries). Traces: AC-4.
- **TC-AND-083-08 — FastAPI error `detail` shapes map to stable typed errors.** Type: unit (JVM, parameterized). Target: JVM. Preconditions: three fixtures — string detail, array-of-`{msg}`, object-`{code,message}` — plus one `ErrorEnvelope` `{error:{code,message}}`. Steps: feed each to the shared error mapper. Expected: each yields a non-empty stable message; array joins `msg`s; object uses `message`/mapped code; envelope maps via `error`. Traces: AC-6.
- **TC-AND-083-09 — Timeout yields NetworkError, not a hang (virtual time).** Type: unit (JVM, MockWebServer + `runTest`). Target: JVM. Preconditions: enqueue response with `setBodyDelay(25, SECONDS)`; call timeout 20s. Steps: launch request; `advanceTimeBy` past 20s. Expected: `ApiResult.NetworkError` (timeout); no deadlock; completes in ms of wall time. Traces: AC-7. (Covers offline/flaky-dev-host path at the transport layer.)
- **TC-AND-083-10 — Retry policy: GET bounded-retry vs mutation no-retry.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: GET case enqueues `503,503,200`; mutation case enqueues `503`. Steps: run GET and PUT. Expected: GET retried per bounded policy and ultimately `Success`; PUT returns error with request count == 1 (no retry). Traces: AC-7. NOTE: gated on assumption A3 — if core-network (AND-027) implements no GET retry, downgrade to asserting "no retry on either" and file against AND-027.
- **TC-AND-083-11 — Malformed JSON → typed parse error (no crash).** Type: unit (JVM, MockWebServer). Target: JVM. Preconditions: enqueue `200` with invalid body. Steps: call `getMediaPreferences()`. Expected: `ApiResult.Error` (parse), no exception escapes. Traces: AC-6.
- **TC-AND-083-12 — DataStore appearance-cache survives process restart.** Type: integration/Robolectric (JVM). Target: JVM. Preconditions: `tmpFolder`-backed `PreferenceDataStoreFactory`. Steps: write theme=dark; close store; recreate against same file; read back. Expected: theme=dark persists; plus assert server round-trip exists separately (per correction 5). Traces: AC-5.
- **TC-AND-083-13 — Compose smoke: render + seeded state + interaction calls repo.** Type: Compose-UI/instrumented. Target: emulator `test35`. Preconditions: Hilt test graph binds `FakePreferencesRepository(initial defaultAudioMuted=false)`. Steps: set `MediaPreferencesScreen`; assert switch reflects seeded off state; `performClick`. Expected: `fake.calls` contains `Recorded.SetDefaultAudioMuted(true)`; no real network. Traces: AC-8.
- **TC-AND-083-14 — Accessibility: controls labelled, toggle semantics inspectable.** Type: Compose-UI/instrumented. Target: emulator `test35`. Preconditions: each Settings subsection screen rendered with seeded state. Steps: query nodes by `testTag`; assert non-empty content description; assert `assertIsOn()/assertIsOff()` toggle semantics; one `SettingsHub` navigation smoke (AND-077). Expected: every interactive control has an accessible label and a stable `testTag`; toggle state is programmatically readable (TalkBack-compatible). Traces: AC-8.
- **TC-AND-083-15 — Security: no live host literal + no secret leakage in logs.** Type: unit + manual (CI grep guard). Target: JVM. Preconditions: test sources tree. Steps: (a) grep-guard test sources for `18.222.237.167`; (b) capture a Timber test tree during a mutation and inspect logs. Expected: no match for the dev-host literal (build fails if present); no CSRF token, cookie, session id, or preference payload appears in logs (redacted). Traces: AC-9.

### Coverage matrix

| AC (Section 14) | Test case(s) |
|---|---|
| AC-1 (`testDebugUnitTest` suites green) | All TC (suite-level; aggregate green) |
| AC-2 (GET mapping + mutation path/method/body/CSRF) | TC-01, TC-02, TC-03, TC-04 |
| AC-3 (optimistic + rollback via Turbine) | TC-05, TC-06 |
| AC-4 (401 single refresh + single retry, no loop) | TC-07 |
| AC-5 (persistence round-trip) | TC-12 (cache) + TC-03 (server round-trip) |
| AC-6 (three `detail` shapes → typed errors) | TC-08, TC-06, TC-11 |
| AC-7 (timeout + bounded-GET-retry / no-mutation-retry) | TC-09, TC-10 |
| AC-8 (instrumentation smoke + interaction + a11y) | TC-13, TC-14 |
| AC-9 (no live-host reference; grep guard) | TC-15 |
| AC-10 (JaCoCo coverage ≥85% soft gate) | Enforced by TC-01..TC-12 coverage of repo + ViewModels (reported, not a standalone case) |

---
id: AND-076
title: Profile tests
milestone: M2
epic: E10
priority: P1
size: M
status: draft
depends_on: [AND-070, AND-071, AND-072, AND-073]
blocks: []
---

# AND-076 — Profile tests

## 1. Overview & Goal

This ticket delivers the test suite that pins the **profile feature** (epic E10):
the `ProfileRepository` data layer and the Compose UI for viewing, editing, and
opening a public profile. The goal is to lock the behavior built across
AND-070 (`ProfileApi` + DTOs), AND-071 (own profile screen), AND-072 (edit
profile basics), and AND-073 (public profile + App Link / not-found / private)
to the real backend wire shapes and to the documented UI contracts, so that
regressions in mapping, state transitions, validation, save-and-reload, deep
linking, and the not-found/private branches are caught before they reach a
device.

Concretely the suite is two complementary layers:

- **Repository / contract tests** (pure JVM, `core-data/src/test/`): exercise the
  production `ProfileRepositoryImpl` through the real Retrofit/OkHttp/Moshi stack
  against `MockWebServer` (AND-046 harness) with fixtures captured from the live
  dev backend. They assert typed `ApiResult<T>` outputs, DTO→domain mapping, the
  exact request bytes (path, body, `X-CSRF-Token`), and FastAPI `detail` error
  mapping for own-profile, public-profile, and save flows.
- **Compose UI tests** (`feature-profile/src/androidTest/` for emulator runs,
  Robolectric-eligible portions under `src/test/`): drive `OwnProfileScreen`,
  `EditProfileScreen`, and `PublicProfileScreen` against a fake repository,
  asserting each `ProfileUiState` renders the correct surface and user actions
  produce the correct ViewModel intents.

Out of scope: the feature/repository implementations themselves (owned by
AND-070…073), the MockWebServer harness and fixtures (AND-046), avatar **upload**
(a later E10 ticket, not AND-072), and CI wiring (owned by AND-050 / AND-051).
This ticket only adds test sources. The single acceptance bar from the backlog —
"Tests pass headlessly" — is met when both layers run green with no manual
interaction, no real network, and no manual device features.

## 2. Context & References

- **Repo / modules:** `spannella/testlogon`, branch `android-port`, monorepo
  subfolder `android/`. Repository tests live in `core-data`
  (`android/core-data/src/test/java/com/testlogon/android/core/data/profile/`);
  UI tests live in `feature-profile`
  (`android/feature-profile/src/androidTest/java/com/testlogon/android/feature/profile/`
  and, for Robolectric-eligible state-rendering tests,
  `.../feature-profile/src/test/java/...`).
- **Systems under test:**
  - `com.testlogon.android.core.data.profile.ProfileRepository` / `…Impl`
    (AND-070/AND-071/AND-072) and `com.testlogon.android.core.network.profile.ProfileApi`
    (AND-070).
  - `com.testlogon.android.feature.profile.own.OwnProfileScreen` + `OwnProfileViewModel`
    (AND-071), `com.testlogon.android.feature.profile.edit.EditProfileScreen` +
    `EditProfileViewModel` (AND-072), `com.testlogon.android.feature.profile.public.PublicProfileScreen`
    + `PublicProfileViewModel` (AND-073).
- **Test infrastructure:** AND-046 `AuthTestHarness` / `MockWebServer` wiring and
  JSON fixtures; `core-testing` `MainDispatcherRule`, `FakeProfileRepository`, and
  Compose test helpers; `createAndroidComposeRule` / `createComposeRule`.
- **Backend reference:** FastAPI dev host `http://18.222.237.167:8000` (PLAINTEXT,
  unreliable — used only for fixture capture, never in CI). OpenAPI at
  `/openapi.json`. Web reference: `frontend/src/api/endpoints/profile.ts` and
  shared types in `frontend/src/api/types.ts`.
- **Auth model:** cookie-based session + `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header; the persistent cookie jar and 401-refresh-once
  authenticator are shared infra (AND-011/AND-013) and assumed working — this
  suite verifies CSRF presence on the profile-save call, not the auth handshake.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP), Retrofit
  2.11 / OkHttp 4.12 (+ `mockwebserver`) / Moshi 1.15, Coroutines/Flow, Coil
  (avatar), JUnit4, `kotlinx-coroutines-test`, Truth/AssertJ, Robolectric, JDK 17.

## 3. Functional Requirements

The suite MUST provide deterministic coverage of the following:

- **FR-1 Own-profile load & map.** A `GET` of the authenticated user's profile is
  mapped DTO→domain (`ProfileDto` → `Profile`): id, display name, username/handle,
  bio, avatar URL, stats (counts), and links list parsed exactly, including
  nullable/absent fields (`bio=null`, empty `links`).
- **FR-2 Public-profile load & map.** `GET /ui/profile/meta/{identifier}` for a
  public identifier maps to `Profile` with `viewerIsOwner=false` and any
  owner-only fields absent/redacted.
- **FR-3 Public not-found.** A `404` for an unknown identifier maps to a typed
  `ProfileResult.NotFound` (distinct from a generic error).
- **FR-4 Public private.** A private profile (per the backend's private signal —
  `403`, or a flagged `200` body; see §13) maps to a typed `ProfileResult.Private`.
- **FR-5 Edit validation.** `EditProfileViewModel` validation rejects an
  over-length display name, an over-length bio, and a malformed link URL **before**
  any network call; valid input enables save.
- **FR-6 Save & reload.** A successful profile update (`PATCH`/`PUT` per §5)
  returns the updated `Profile`; a subsequent reload reflects the new values
  (asserted via the repository returning the post-save shape and the UI rendering
  it).
- **FR-7 Save error mapping.** A `422` validation error from the backend maps
  field-level `detail[{loc,msg}]` entries onto the correct edit fields; string and
  `{code,...}` `detail` shapes map to a form-level error. No throw on any shape.
- **FR-8 CSRF on mutation.** The save request carries `X-CSRF-Token` equal to the
  current `ui_csrf` cookie value.
- **FR-9 UI state rendering.** Each screen renders the correct surface for each
  `ProfileUiState` branch (`Loading`, `Loaded`, `Error`, `Offline`, plus
  `NotFound`/`Private` for public), using stable test tags.
- **FR-10 UI intents.** User actions emit the correct ViewModel intents:
  tapping "Edit" navigates to edit; editing a field updates form state; "Save"
  invokes `onSave`; "Retry" invokes `onRetry`; tapping a link invokes the link
  handler.
- **FR-11 Deep-link routing.** A `testlogon://u/{identifier}` / App Link
  (`https://<host>/u/{identifier}`, AND-022/AND-073) resolves to
  `PublicProfileScreen` with the parsed `identifier` argument.
- **FR-12 Headless determinism.** The whole suite runs headlessly — virtual-time
  dispatchers, fixed clock, no `Thread.sleep`, no real network, no manual device
  interaction — and passes repeatably under `--rerun-tasks` and parallel workers.

## 4. Technical Design

### 4.1 Repository / contract tests (JVM)

JUnit4 classes under
`core-data/src/test/java/com/testlogon/android/core/data/profile/`, each building
a real `ProfileRepositoryImpl` wired to a real Retrofit client whose `baseUrl` is
the `MockWebServer` URL (production serialization + interceptors exercised end to
end). A shared base reuses the AND-046 harness:

```kotlin
abstract class ProfileRepositoryTest {
    @get:Rule val mainDispatcherRule = MainDispatcherRule()      // core-testing

    protected lateinit var server: MockWebServer
    protected lateinit var harness: ApiTestHarness               // from AND-046
    protected lateinit var repository: ProfileRepository

    @Before fun setUp() {
        harness = ApiTestHarness()                               // starts server
        server = harness.server
        repository = harness.buildProfileRepository(
            scheduler = TestCoroutineScheduler(),                // virtual time
        )
    }

    @After fun tearDown() = harness.shutdown()

    protected fun enqueue(fixture: String, code: Int = 200) =
        server.enqueue(harness.jsonResponse(fixture, code))
}
```

Representative classes / methods:

```kotlin
class OwnProfileContractTest : ProfileRepositoryTest() {
    @Test fun ownProfile_maps_all_fields() = runTest {
        enqueue("profile_own_full.json")
        val r = repository.getOwnProfile()
        assertThat(r).isInstanceOf(ApiResult.Success::class.java)
        val p = (r as ApiResult.Success).data
        assertThat(p.viewerIsOwner).isTrue()
        assertThat(p.links).hasSize(2)
        assertThat(server.takeRequest().path).isEqualTo("/ui/me/profile")
    }

    @Test fun ownProfile_nullable_fields_default_safely() = runTest {
        enqueue("profile_own_minimal.json")                      // bio=null, links=[]
        val p = (repository.getOwnProfile() as ApiResult.Success).data
        assertThat(p.bio).isNull(); assertThat(p.links).isEmpty()
    }
}

class PublicProfileContractTest : ProfileRepositoryTest() {
    @Test fun public_found() = runTest { /* FR-2 */ }
    @Test fun public_notFound_maps_NotFound() = runTest {        // FR-3
        enqueue("profile_not_found.json", code = 404)
        assertThat(repository.getPublicProfile("ghost"))
            .isInstanceOf(ProfileResult.NotFound::class.java)
    }
    @Test fun public_private_maps_Private() = runTest { /* FR-4 */ }
}

class SaveProfileContractTest : ProfileRepositoryTest() {
    @Test fun save_success_returns_updated_and_sends_csrf() = runTest { /* FR-6,8 */ }
    @Test fun save_422_maps_field_errors() = runTest { /* FR-7 */ }
}
```

`ProfileResult` is a small sealed type owned by the repository layer:
`Found(Profile)` | `NotFound` | `Private` | `Error(ApiError)`; own-profile and
save use the generic `ApiResult<Profile>`. Request assertions read
`server.takeRequest()` for method, path, decoded body JSON, and headers. Response
fixtures are loaded by name from `core-testing` resources captured against the
live backend.

### 4.2 Compose UI tests

State-rendering and intent tests live in `feature-profile/src/test/` where
Robolectric can run them under `testDebugUnitTest`; full instrumentation (deep
link, Coil image, navigation) lives in `feature-profile/src/androidTest/` and
runs via `connectedAndroidTest`. Both drive the production screens with a
`FakeProfileRepository` (or directly with a `ProfileUiState`), never the real
network.

```kotlin
class OwnProfileScreenTest {
    @get:Rule val composeRule = createComposeRule()

    @Test fun loaded_rendersAvatarBioStatsLinks() {
        composeRule.setContent {
            OwnProfileScreen(
                state = ProfileUiState.Loaded(sampleProfile),
                onEdit = {}, onLinkClick = {}, onRetry = {},
            )
        }
        composeRule.onNodeWithTag("profile_displayName").assertIsDisplayed()
        composeRule.onNodeWithTag("profile_bio").assertIsDisplayed()
        composeRule.onNodeWithTag("profile_stats").assertIsDisplayed()
        composeRule.onNodeWithTag("profile_edit").assertHasClickAction()
    }

    @Test fun edit_tap_invokesOnEdit() {
        var edited = false
        composeRule.setContent {
            OwnProfileScreen(ProfileUiState.Loaded(sampleProfile),
                onEdit = { edited = true }, onLinkClick = {}, onRetry = {})
        }
        composeRule.onNodeWithTag("profile_edit").performClick()
        assertThat(edited).isTrue()
    }
}

class EditProfileScreenTest {                                    // FR-5, FR-10
    @get:Rule val composeRule = createComposeRule()
    @Test fun overlongBio_showsError_and_disablesSave() { /* ... */ }
    @Test fun validEdit_enablesSave_and_invokesOnSave() { /* ... */ }
}

class PublicProfileScreenTest {                                  // FR-9 branches
    @get:Rule val composeRule = createComposeRule()
    @Test fun notFound_rendersNotFoundState() { /* ... */ }
    @Test fun private_rendersPrivateState() { /* ... */ }
}
```

ViewModel-level tests (`EditProfileViewModelTest`,
`PublicProfileViewModelTest`) drive the StateFlow with a `FakeProfileRepository`
and `runTest`, asserting state transitions (`Loading → Loaded`,
`Loading → NotFound`, validation gating, `save → reload`).

Deep-link routing (FR-11) is an `androidTest` using a `NavHost` test:

```kotlin
@Test fun appLink_u_identifier_routes_to_public_profile() {
    composeRule.activity.handleDeepLink(
        Uri.parse("https://app.testlogon.com/u/alice"))
    composeRule.onNodeWithTag("public_profile_root").assertIsDisplayed()
    // assert nav back-stack arg identifier == "alice"
}
```

## 5. API Contract

This ticket **asserts** (does not define) the profile contract; AND-070 owns the
definitions. The endpoints and shapes the tests pin, matching the live backend
captured by AND-046 (verify exact own-profile path against `/openapi.json` and
`frontend/src/api/endpoints/profile.ts` — see §13):

- `GET /ui/me/profile` (own profile) →
  ```json
  {
    "id": "u_123", "username": "alice", "display_name": "Alice A.",
    "bio": "hi", "avatar_url": "https://.../a.png",
    "stats": {"followers": 12, "following": 7, "posts": 3},
    "links": [{"label": "site", "url": "https://alice.dev"}],
    "viewer_is_owner": true, "is_private": false
  }
  ```
- `GET /ui/profile/meta/{identifier}` (public) → same `Profile` shape with
  `viewer_is_owner: false`; `404` for unknown identifier; private signalled per
  §13.
- Save (basics): `PATCH /ui/me/profile` (confirm method vs `PUT` against OpenAPI)
  with body `{"display_name": "...", "bio": "...", "links": [{"label","url"}]}` →
  `200` returning the updated `Profile`.
- Error `detail` shapes tested: `{"detail":"..."}` (string),
  `{"detail":[{"loc":["body","bio"],"msg":"too long","type":"value_error"}]}`
  (422 field array → FR-7 field mapping), `{"detail":{"code":"PRIVATE_PROFILE","message":"..."}}`
  (object). Each fixture is a byte-for-byte capture; tests assert the parsed typed
  result and that the repository never throws.

## 6. Data & State Management

- **Domain model:** `Profile` (immutable data class) and `ProfileLink`; nullable
  `bio`/`avatarUrl`, list `links`, `stats: ProfileStats`, flags `viewerIsOwner`,
  `isPrivate`. Tests assert structural equality via Truth/AssertJ — no
  `toString()` matching.
- **UI state:** `sealed interface ProfileUiState { Loading; Loaded(profile);
    Error(message); Offline(staleAsOf?); NotFound; Private }` for the public
  screen; the own screen omits `NotFound`/`Private`. `EditProfileUiState` carries
  the editable form (`displayName`, `bio`, `links`, per-field `errors`,
  `isSaving`, `canSave`). Tests assert each branch renders / each transition
  occurs.
- **No persistence under test here:** the cookie jar is the AND-046 in-memory
  test jar; Room cache for profiles (if any) is owned by its feature ticket and
  not asserted in this suite beyond mapping. UI tests use `FakeProfileRepository`
  holding an in-memory `Profile`, so "save then reload" (FR-6) is observable
  without I/O.
- **Isolation:** fresh harness/server/repository in `@Before`; fresh compose rule
  per test; no shared mutable global state.

## 7. Error Handling & Resilience

- **NotFound vs Error (FR-3):** a `404` maps to `ProfileResult.NotFound` and the
  public screen renders the not-found surface, distinct from the generic
  `Error` surface; a 5xx maps to `Error`.
- **Private (FR-4):** the private signal maps to `ProfileResult.Private` and a
  dedicated private surface; it is not conflated with not-found.
- **Save validation (FR-7):** `422` `detail[{loc,msg}]` entries are routed to the
  matching field error (`loc` last segment → field key); unmapped/string/object
  `detail` falls back to a form-level banner. A test asserts no uncaught
  exception on any `detail` shape, malformed JSON, or empty body.
- **Offline / timeout:** simulate via `MockResponse().setSocketPolicy(NO_RESPONSE)`
  or `setBodyDelay`, advance virtual time past the ~20s read timeout, and assert a
  connectivity/`Offline` category; the public/own screen renders the offline
  surface with a "Retry" action. No real waiting.
- **Idempotency:** profile GETs are idempotent and may be retried with bounded
  backoff (AND-016); the save mutation is **not** auto-retried. A test asserts the
  save endpoint is hit exactly once on a non-401 failure.
- **Determinism guard:** a test asserts the suite uses the virtual scheduler so
  resilience paths complete in milliseconds.

## 8. Security & Privacy

- **CSRF (FR-8):** the save request asserts `X-CSRF-Token` equals the current
  `ui_csrf` cookie value; a missing/stale token is a test failure.
- **Owner-only redaction (FR-2):** a public payload must not surface owner-only
  fields; a test asserts `viewerIsOwner=false` and that any private field
  (e.g. email, if present in own payload) is absent from the public mapping.
- **No real network:** CI runs fully offline; any non-`MockWebServer` host call is
  a failure. The plaintext dev host is never contacted by the suite.
- **No secrets in fixtures:** profile fixtures use synthetic users; a convention
  check asserts no real PII/tokens appear in fixture files.
- **Logging:** assert interceptor/repository logs do not emit cookie values or the
  `X-CSRF-Token` during the save flow.

## 9. Accessibility & i18n

This is a test ticket, so it adds no UI of its own, but the UI-test layer
**enforces** the a11y/i18n contracts of the screens it covers:

- **Content descriptions:** the avatar `Image` (Coil) has a non-empty
  `contentDescription`; decorative icons are marked decorative. A test asserts the
  avatar node exposes a content description.
- **Semantics & touch targets:** "Edit", "Save", "Retry", and each link expose a
  click action and a readable label via `onNodeWithText`/`onNodeWithContentDescription`;
  interactive nodes meet the 48dp minimum (assert via semantics where feasible).
- **i18n:** UI tests resolve user-facing copy through string resources
  (`context.getString(R.string.profile_*)`) rather than hard-coded literals, so
  the screens stay localizable; error copy comes from the `detail`→message mapping,
  asserted by category/key not by free-text English.

## 10. Telemetry & Logging

No production telemetry is added by this ticket. Test-time logging invariants:

- The OkHttp test logger output is captured and asserted to contain **no** cookie
  or `X-CSRF-Token` values for the profile-save call.
- Results are surfaced through standard Gradle/JUnit XML reports (unit) and the
  Android instrumentation runner listener (instrumented), consumable by AND-050 /
  AND-051 CI without extra wiring.
- If the screens emit analytics events (e.g. `profile_viewed`,
  `profile_saved`), the UI tests assert the event is dispatched once per action
  via a fake analytics sink; if no analytics exist yet, this is N/A and owned by a
  future telemetry ticket.

## 11. Testing Strategy

- **Frameworks:** JUnit4, `kotlinx-coroutines-test` (`runTest`,
  `TestCoroutineScheduler`, `MainDispatcherRule`), Truth/AssertJ, OkHttp
  `MockWebServer` (repository layer); Compose UI test (`createComposeRule` /
  `createAndroidComposeRule`), Robolectric (for `src/test/` UI rendering), and the
  `FakeProfileRepository` from `core-testing` (UI layer).
- **Repository layer:** contract tests through the production
  Retrofit/Moshi/OkHttp stack; mock only at the socket and clock/dispatcher
  boundaries; fixtures loaded by name from AND-046 resources.
- **UI layer:** stateless screens are driven with explicit `ProfileUiState`
  values for rendering tests; ViewModel tests drive the StateFlow with the fake
  repository and assert transitions; the deep-link test runs in `androidTest`.
- **Coverage matrix (maps to FRs):** own load full + minimal (FR-1); public found
  / not-found / private (FR-2, FR-3, FR-4); edit validation name/bio/url (FR-5);
  save success + reload (FR-6); save 422 field map + string/object fallback
  (FR-7); CSRF on save (FR-8); UI states Loading/Loaded/Error/Offline/NotFound/
  Private (FR-9); intents edit/field-edit/save/retry/link (FR-10); deep-link route
  (FR-11). Each row is an independent test method.
- **Commands:**
  `./gradlew :core-data:testDebugUnitTest`,
  `./gradlew :feature-profile:testDebugUnitTest` (JVM + Robolectric),
  `./gradlew :feature-profile:connectedDebugAndroidTest` (instrumented, headless
  emulator).
- **Determinism (FR-12):** no `Thread.sleep`; virtual time; fixed clock; fresh
  server/jar/compose-rule per test; passes under `--rerun-tasks` and parallel
  workers. Coverage gate: 100% of `ProfileRepositoryImpl` public functions and
  every `ProfileUiState`/`ProfileResult` branch hit at least once (JaCoCo on the
  `profile` packages, target ≥90% line).

## 12. Dependencies & Sequencing

- **Depends on AND-070** (`ProfileApi` + DTOs) — defines the wire/domain shapes
  the contract tests pin; **AND-071** (own profile screen + `OwnProfileViewModel`)
  and **AND-072** (edit profile basics + validation/save) and **AND-073** (public
  profile screen + App Link + not-found/private) — the UI/state contracts under
  test. The backlog lists AND-071 and AND-073 explicitly; AND-070 and AND-072 are
  added as hard prerequisites because their surfaces (DTOs, save flow, validation)
  are directly asserted.
- **Depends on AND-046** (MockWebServer harness + fixtures) for the contract
  layer, and on `core-testing` `FakeProfileRepository` / Compose helpers for the
  UI layer.
- **Relies on** AND-022 (App Links / deep-link infra) for FR-11 routing.
- **Blocks:** nothing formally, but acts as the E10 regression gate. Feeds the CI
  test aggregation in AND-050 (unit) and AND-051 (instrumented); recommended
  sequencing: AND-070 → AND-071 → AND-072 → AND-073 → AND-076, then add the three
  Gradle test tasks to required PR checks on `android-port`.

## 13. Risks & Open Questions

- **Own-profile endpoint path:** `GET /ui/me/profile` vs returning the profile
  inline on `GET /ui/me`. Confirm against `/openapi.json` and
  `frontend/src/api/endpoints/profile.ts` before finalizing fixtures.
- **Save method/path:** `PATCH /ui/me/profile` vs `PUT`; whether links are saved
  in the same call or a separate endpoint. Verify before writing save fixtures.
- **Private signal shape:** is a private profile a `403`, a `404` (indistinguishable
  from not-found), or a `200` with `is_private:true` and redacted body? This
  determines whether FR-4 is testable as a distinct branch; resolve with the
  AND-073 author / backend.
- **Fixture drift:** the dev backend is unreliable and may change shapes; stale
  AND-046 fixtures pin stale shapes. Mitigate with periodic manual re-capture and a
  capture-date/endpoint comment in each fixture.
- **Robolectric vs instrumented split:** confirm which Compose tests are stable
  under Robolectric (Coil image loading often is not) so the headless `src/test/`
  set stays green without an emulator; push image/deep-link tests to `androidTest`.
- **App Link host:** the exact verified host for `https://<host>/u/{identifier}`
  (AND-022) must match the manifest `<intent-filter>` for FR-11 to pass.

## 14. Acceptance Criteria

- **AC-1:** Own-profile load tests exist and pass for a full payload and a minimal
  payload (`bio=null`, empty `links`), asserting DTO→domain mapping and
  `viewerIsOwner=true` (FR-1).
- **AC-2:** Public-profile tests cover found, not-found (`ProfileResult.NotFound`),
  and private (`ProfileResult.Private`) — three distinct typed outcomes (FR-2,
  FR-3, FR-4).
- **AC-3:** Edit validation tests reject over-length name, over-length bio, and a
  malformed link URL before any network call, and enable save for valid input
  (FR-5).
- **AC-4:** Save tests assert a successful update returns the updated `Profile`
  and a reload reflects the new values, and that the save request carries
  `X-CSRF-Token` equal to the `ui_csrf` cookie (FR-6, FR-8).
- **AC-5:** Save-error tests map `detail[{loc,msg}]` (422) to field errors and
  map string / `{code}` `detail` to a form-level error, with no throw on any
  shape, malformed JSON, or empty body (FR-7).
- **AC-6:** UI tests render the correct surface for each `ProfileUiState`
  (Loading/Loaded/Error/Offline, plus NotFound/Private on public) via stable test
  tags (FR-9).
- **AC-7:** UI intent tests assert edit, field-edit, save, retry, and link taps
  emit the correct ViewModel intents/callbacks (FR-10), and the App Link
  `https://<host>/u/{identifier}` routes to `PublicProfileScreen` with the parsed
  identifier (FR-11).
- **AC-8:** The full suite runs **headlessly** and is deterministic — passes
  repeatably under `--rerun-tasks` and parallel execution with no real network,
  no wall-clock delay, and no manual interaction (FR-12). This satisfies the
  backlog acceptance "Tests pass headlessly."

## 15. Definition of Done

- Repository contract classes under
  `core-data/src/test/java/com/testlogon/android/core/data/profile/`
  (`OwnProfileContractTest`, `PublicProfileContractTest`, `SaveProfileContractTest`)
  and UI/ViewModel classes under `feature-profile/src/test/` and
  `feature-profile/src/androidTest/` (`OwnProfileScreenTest`,
  `EditProfileScreenTest`, `EditProfileViewModelTest`, `PublicProfileScreenTest`,
  `PublicProfileViewModelTest`, deep-link routing test) implemented, consuming the
  AND-046 harness/fixtures and `core-testing` fakes, with AC-1…AC-8 satisfied.
- `./gradlew :core-data:testDebugUnitTest`, `:feature-profile:testDebugUnitTest`,
  and `:feature-profile:connectedDebugAndroidTest` are green locally and in CI on
  `android-port`; the tasks are added to required PR checks (via AND-050/AND-051).
- JaCoCo shows 100% of `ProfileRepositoryImpl` public functions and every
  `ProfileUiState`/`ProfileResult` branch covered, ≥90% line on the `profile`
  packages; uncovered lines justified in the PR.
- No `Thread.sleep`, no real-network calls, no shared mutable state between tests;
  suite passes under `--rerun-tasks` and parallel workers and runs headlessly.
- No cookie/CSRF values or PII appear in test logs or fixtures (asserted).
- Code reviewed and merged; §13 open questions either resolved or filed as
  follow-up tickets referenced from the PR.

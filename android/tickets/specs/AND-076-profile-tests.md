---
id: AND-076
title: Profile tests
milestone: M2
epic: E10
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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

- **FR-1 Own-profile load & map.** A `GET /ui/profile` of the authenticated user's
  profile (response is wrapped as `{ "profile": Profile }`) is mapped DTO→domain
  (`ProfileDto` → `Profile`): `display_name`, `first_name`/`middle_name`/`last_name`,
  `title`, `description`, `location`, `profile_photo_url`, `cover_photo_url`,
  `languages`, etc., parsed exactly, including nullable/absent fields
  (`description=null`, absent optionals). NOTE (corrected): the backend `Profile`
  has **no** `username`/`bio`/`avatar_url`/`stats`/`links`/`viewer_is_owner`/
  `is_private` fields — earlier drafts assumed those; bio→`description`,
  avatar→`profile_photo_url`. See §5 and §16.
- **FR-2 Public/cross-user-profile load & map.** `GET /ui/profiles/{identifier}`
  returns `CrossUserProfileResp` (`{ identifier, canonical_identifier?, user_sub,
  audience, profile }`) where `audience ∈ {"owner","member","public"}` — the
  backend infers viewer audience from session context. Tests map this to the domain
  with `viewerIsOwner = (audience == "owner")` and assert owner-only fields are
  absent for `audience="public"`. (The storefront `GET /ui/profile/public/{identifier}`
  → `PublicProfileData` is a separate read that also carries `follower_count`/
  `following_count`/`post_count`; see §5.)
- **FR-3 Public not-found / suppressed.** A `404` for an unknown OR suppressed/
  private identifier maps to a typed `ProfileResult.NotFound` (the web client codes
  this `not_found_or_suppressed`). Distinct from a generic error.
- **FR-4 Rate-limited lookup.** CORRECTED: the backend does **not** expose a distinct
  "private" signal — private profiles return `404` (indistinguishable from not-found,
  collapsed into FR-3). The real distinct error branch is `429` rate-limiting on
  cross-user lookup, which maps to a typed `ProfileResult.RateLimited` (web:
  `rate_limited`, honoring `Retry-After`). See §16 corrections.
- **FR-5 Edit validation.** `EditProfileViewModel` validation rejects an
  over-length display name and an over-length `description` (bio) **before** any
  network call; valid input enables save. (CORRECTED: there is no `links` field in
  the backend `Profile`/`ProfilePatchReq`, so the "malformed link URL" rule is
  dropped; a representative URL-shaped field to validate instead is
  `profile_photo_url`/`cover_photo_url`. See §16.)
- **FR-6 Save & reload.** A successful profile update via `PATCH /ui/profile`
  (partial; `PUT /ui/profile` for full replace — both exist, see §5) returns the
  updated profile wrapped as `{ "profile": Profile }`; a subsequent
  `GET /ui/profile` reload reflects the new values (asserted via the repository
  returning the post-save shape and the UI rendering it).
- **FR-7 Save error mapping.** A `422` validation error from the backend maps
  field-level `detail[{loc,msg}]` entries onto the correct edit fields; string and
  `{code,...}` `detail` shapes map to a form-level error. No throw on any shape.
- **FR-8 CSRF header.** The save request carries `X-CSRF-Token` equal to the
  current `ui_csrf` cookie value. NOTE (verified against `src/api/client.ts`): the
  web client attaches `X-CSRF-Token` from the `ui_csrf` cookie to **every** request
  (GET included), not only mutations — so the Android client/tests should expect the
  header on all profile calls; the save call is simply the most security-relevant
  assertion.
- **FR-9 UI state rendering.** Each screen renders the correct surface for each
  `ProfileUiState` branch (`Loading`, `Loaded`, `Error`, `Offline`, plus
  `NotFound`/`RateLimited` for public), using stable test tags.
- **FR-10 UI intents.** User actions emit the correct ViewModel intents:
  tapping "Edit" navigates to edit; editing a field updates form state; "Save"
  invokes `onSave`; "Retry" invokes `onRetry`. (CORRECTED: the "tap a link" intent
  is dropped — the backend `Profile` has no `links`; the analogous tappable element
  is the avatar/cover image or an external `profile_photo_url`, asserted via
  `onAvatarClick` if the screen exposes one.)
- **FR-11 Deep-link routing.** A `testlogon://u/{identifier}` / App Link
  (`https://<host>/u/{identifier}`, AND-022/AND-073) resolves to
  `PublicProfileScreen` with the parsed `identifier` argument. UNVERIFIED: the exact
  web URL path (`/u/{identifier}` vs `/profile/{identifier}`) and the verified App
  Link host are not derivable from the OpenAPI/backend sources; treat as an
  assumption pending the AND-022/AND-073 manifest (see §16 open assumptions).
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
        assertThat(p.displayName).isEqualTo("Alice A.")
        assertThat(p.profilePhotoUrl).isNotNull()
        assertThat(server.takeRequest().path).isEqualTo("/ui/profile")
    }

    @Test fun ownProfile_nullable_fields_default_safely() = runTest {
        enqueue("profile_own_minimal.json")                      // description=null, optionals absent
        val p = (repository.getOwnProfile() as ApiResult.Success).data
        assertThat(p.description).isNull(); assertThat(p.coverPhotoUrl).isNull()
    }
}

class PublicProfileContractTest : ProfileRepositoryTest() {
    @Test fun public_found() = runTest {                         // FR-2
        enqueue("profile_crossuser_public.json")                 // audience="public"
        val r = repository.getProfileByIdentifier("alice")
        val f = (r as ProfileResult.Found)
        assertThat(f.profile.viewerIsOwner).isFalse()
        assertThat(server.takeRequest().path).isEqualTo("/ui/profiles/alice")
    }
    @Test fun public_notFound_maps_NotFound() = runTest {        // FR-3
        enqueue("profile_not_found.json", code = 404)            // private also lands here
        assertThat(repository.getProfileByIdentifier("ghost"))
            .isInstanceOf(ProfileResult.NotFound::class.java)
    }
    @Test fun public_rateLimited_maps_RateLimited() = runTest {  // FR-4 (corrected)
        enqueue("profile_rate_limited.json", code = 429)
        assertThat(repository.getProfileByIdentifier("alice"))
            .isInstanceOf(ProfileResult.RateLimited::class.java)
    }
}

class SaveProfileContractTest : ProfileRepositoryTest() {
    @Test fun save_success_returns_updated_and_sends_csrf() = runTest { /* FR-6,8 */ }
    @Test fun save_422_maps_field_errors() = runTest { /* FR-7 */ }
}
```

`ProfileResult` is a small sealed type owned by the repository layer:
`Found(Profile)` | `NotFound` | `RateLimited(retryAfterSeconds?)` | `Error(ApiError)`;
own-profile and save use the generic `ApiResult<Profile>`. (CORRECTED: an earlier
draft had a `Private` member; the backend conflates private into the `404`
not-found path, so `NotFound` covers "not found or suppressed" and `RateLimited`
replaces `Private` as the distinct typed branch — see §16.) Request assertions read
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
                onEdit = {}, onAvatarClick = {}, onRetry = {},
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
                onEdit = { edited = true }, onAvatarClick = {}, onRetry = {})
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
    @Test fun rateLimited_rendersRateLimitedState() { /* ... */ }  // FR-4 (corrected)
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
definitions. The endpoints and shapes the tests pin are VERIFIED against
`reference/openapi.index.txt`, `reference/openapi.pretty.json`
(`components.schemas.*`), and `frontend/src/api/endpoints/profile.ts` +
`src/api/types.ts` (see §16 audit):

- **Own profile** — `GET /ui/profile` (op `ui_get_profile_ui_profile_get`). Web
  client (`profile.ts: getProfile`) types the response as `{ profile: Profile }` (a
  **wrapper object**, not the bare profile). The backend `Profile`
  (`types.ts: Profile`) shape — note **all fields optional** — is:
  ```json
  {
    "profile": {
      "display_name": "Alice A.", "first_name": "Alice", "last_name": "A.",
      "title": "Engineer", "description": "hi", "location": "NYC",
      "displayed_email": "a@example.com", "displayed_telephone_number": "…",
      "birthday": "1990-01-01", "gender": "…", "languages": [],
      "profile_photo_url": "https://.../a.png",
      "cover_photo_url": "https://.../c.png"
    }
  }
  ```
  There is **no** `id`/`username`/`bio`/`avatar_url`/`stats`/`links`/
  `viewer_is_owner`/`is_private` on `Profile` (corrected from earlier draft:
  bio→`description`, avatar→`profile_photo_url`).
- **Cross-user / public profile** — `GET /ui/profiles/{identifier}` (op
  `ui_get_profile_by_identifier_…`), web `profile.ts: getProfileByIdentifier` →
  `CrossUserProfileResp` (`types.ts`):
  `{ "identifier", "canonical_identifier"?, "user_sub", "audience":
  "owner"|"member"|"public", "profile": Profile }`. `404` ⇒ not-found-or-suppressed
  (includes private); `429` ⇒ rate-limited (honors `Retry-After`). A separate
  storefront read `GET /ui/profile/public/{identifier}` → `PublicProfileData`
  carries `follower_count`/`following_count`/`post_count`/`is_following`/
  `has_subscription_plans` etc. (NOTE: `GET /ui/profile/meta/{identifier}` exists but
  is the OG/meta-tag endpoint `profile_meta_tags_…`, NOT the profile read — earlier
  draft cited it incorrectly.)
- **Save (basics)** — `PATCH /ui/profile` (op `ui_patch_profile_…`, req schema
  `ProfilePatchReq`, partial update) and `PUT /ui/profile` (op `ui_put_profile_…`,
  req `ProfilePutReq`, full replace) BOTH exist; web `profile.ts` exposes both
  (`patchProfile` / `replaceProfile`). Body fields (per `ProfilePatchReq`):
  `display_name, first_name, middle_name, last_name, title, description, birthday,
  gender, location, locale, languages, displayed_email,
  displayed_telephone_number, profile_photo_url, cover_photo_url` — **no `links`**.
  `200` returns `{ "profile": Profile }`.
- **Error `detail` shapes tested:** FastAPI `422` is
  `{"detail":[{"loc":["body","description"],"msg":"…","type":"…"}]}`
  (`HTTPValidationError`; array → FR-7 field mapping), `{"detail":"…"}` (string),
  and object-detail e.g. the geo-block `{"detail":{"code":"geo_blocked","message":"…"}}`
  shape the web client special-cases in `client.ts`. Each fixture is a byte-for-byte
  capture; tests assert the parsed typed result and that the repository never throws.

## 6. Data & State Management

- **Domain model:** `Profile` (immutable data class) mapping the backend `Profile`
  fields — nullable `displayName`, `firstName`/`lastName`, `title`, `description`
  (the "bio"), `location`, `profilePhotoUrl`, `coverPhotoUrl`, `languages`; plus a
  derived `viewerIsOwner` set from `CrossUserProfileResp.audience == "owner"` on the
  cross-user path. (CORRECTED: no `ProfileLink`/`links`, no `stats`/`ProfileStats`,
  no `isPrivate` on the backend `Profile`; follower/post counts live only on
  `PublicProfileData`.) Tests assert structural equality via Truth/AssertJ — no
  `toString()` matching.
- **UI state:** `sealed interface ProfileUiState { Loading; Loaded(profile);
    Error(message); Offline(staleAsOf?); NotFound; RateLimited(retryAfterSeconds?) }`
  for the public screen; the own screen omits `NotFound`/`RateLimited`.
  `EditProfileUiState` carries the editable form (`displayName`, `description`,
  per-field `errors`, `isSaving`, `canSave`). Tests assert each branch renders /
  each transition occurs. (CORRECTED: `Private` branch removed — backend has no
  distinct private signal; see §16.)
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
- **Rate-limited (FR-4, corrected):** a `429` on cross-user lookup maps to
  `ProfileResult.RateLimited(retryAfterSeconds?)` and a dedicated surface, parsing
  `Retry-After` (header or `detail.retry_after_seconds`) per
  `profile.ts: getProfileByIdentifier`. (Private profiles are NOT a distinct branch —
  they return `404` and fold into `NotFound`.)
- **Save validation (FR-7):** `422` `detail[{loc,msg}]` entries are routed to the
  matching field error (`loc` last segment → field key, e.g. `description`,
  `display_name`); unmapped/string/object `detail` falls back to a form-level banner. A test asserts no uncaught
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
- **Owner-only redaction (FR-2):** the backend infers `audience` and returns the
  audience-appropriate `Profile`; a test asserts that for `audience="public"` the
  mapped domain has `viewerIsOwner=false` and that fields the backend omits for a
  public viewer (the test asserts via the captured `audience="public"` fixture, not
  by assuming a specific field is stripped, since redaction is backend-driven).
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
- **Coverage matrix (maps to FRs):** own load full + minimal (FR-1); cross-user
  found / not-found / rate-limited (FR-2, FR-3, FR-4); edit validation
  name/description (FR-5); save success + reload (FR-6); save 422 field map +
  string/object fallback (FR-7); CSRF header on calls (FR-8); UI states
  Loading/Loaded/Error/Offline/NotFound/RateLimited (FR-9); intents
  edit/field-edit/save/retry/link (FR-10); deep-link route (FR-11). Each row is an
  independent test method.
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

- **Own-profile endpoint path:** RESOLVED (§16) — it is `GET /ui/profile`
  (response wrapped `{ profile: Profile }`), NOT `/ui/me/profile`; `GET /ui/me`
  is a separate "who am I" endpoint. Fixtures must use `/ui/profile`.
- **Save method/path:** RESOLVED (§16) — BOTH `PATCH /ui/profile`
  (`ProfilePatchReq`, partial) and `PUT /ui/profile` (`ProfilePutReq`, full) exist;
  there is **no** `links` field, so no separate links endpoint applies here. Use
  `PATCH` for the basics-save flow.
- **Private signal shape:** RESOLVED (§16) — private/suppressed profiles return
  `404` (indistinguishable from not-found; web codes both `not_found_or_suppressed`).
  There is no `403`/`is_private` distinct signal, so FR-4 is re-scoped to the real
  distinct branch: `429` rate-limiting (`ProfileResult.RateLimited`).
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
- **AC-2:** Cross-user-profile tests cover found (`audience`-mapped), not-found/
  suppressed (`ProfileResult.NotFound`), and rate-limited (`ProfileResult.RateLimited`)
  — three distinct typed outcomes (FR-2, FR-3, FR-4). (CORRECTED: "private" is folded
  into not-found per backend behavior; rate-limited is the third distinct branch.)
- **AC-3:** Edit validation tests reject over-length display name and over-length
  `description` (bio) before any network call, and enable save for valid input
  (FR-5). (CORRECTED: no `links` field exists, so no malformed-link-URL rule; a
  URL-shaped `profile_photo_url` may be validated instead.)
- **AC-4:** Save tests assert a successful update returns the updated `Profile`
  and a reload reflects the new values, and that the save request carries
  `X-CSRF-Token` equal to the `ui_csrf` cookie (FR-6, FR-8).
- **AC-5:** Save-error tests map `detail[{loc,msg}]` (422) to field errors and
  map string / `{code}` `detail` to a form-level error, with no throw on any
  shape, malformed JSON, or empty body (FR-7).
- **AC-6:** UI tests render the correct surface for each `ProfileUiState`
  (Loading/Loaded/Error/Offline, plus NotFound/RateLimited on public) via stable
  test tags (FR-9).
- **AC-7:** UI intent tests assert edit, field-edit, save, retry, and avatar taps
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Own-profile read is `GET /ui/profile`, response wrapped `{ profile: Profile }`.**
   VERDICT: Corrected (draft said `GET /ui/me/profile`, bare body).
   SOURCE: OpenAPI `GET /ui/profile` (op `ui_get_profile_ui_profile_get`);
   `src/api/endpoints/profile.ts: getProfile` → `api.get<{ profile: Profile }>("/ui/profile")`.
2. **`GET /ui/me` is a separate "who am I" endpoint, not the profile read.**
   VERDICT: Verified. SOURCE: OpenAPI `GET /ui/me` (op `ui_me_ui_me_get`);
   `src/api/endpoints/auth.ts: api.get<MeResp>("/ui/me")`.
3. **Backend `Profile` fields = `display_name, first_name, middle_name, last_name,
   title, description, birthday, gender, location, displayed_email,
   displayed_telephone_number, languages, profile_photo_url, cover_photo_url,
   mailing_address` — NO `id/username/bio/avatar_url/stats/links/viewer_is_owner/
   is_private`.** VERDICT: Corrected (draft invented `username/bio/avatar_url/stats/
   links/viewer_is_owner/is_private`). SOURCE: `src/api/types.ts: Profile` (lines
   473–489); `components.schemas.ProfilePatchReq` in `openapi.pretty.json` (same
   field set). bio→`description`, avatar→`profile_photo_url`.
4. **Cross-user/public read is `GET /ui/profiles/{identifier}` →
   `CrossUserProfileResp { identifier, canonical_identifier?, user_sub, audience, profile }`,
   audience ∈ owner|member|public.** VERDICT: Corrected (draft used
   `GET /ui/profile/meta/{identifier}` for the public read).
   SOURCE: OpenAPI `GET /ui/profiles/{identifier}` (op
   `ui_get_profile_by_identifier_…`); `src/api/endpoints/profile.ts:
   getProfileByIdentifier`; `src/api/types.ts: CrossUserProfileResp` (493–499);
   `src/pages/profile/PublicUserProfilePage.tsx` uses `detail.audience`.
5. **`GET /ui/profile/meta/{identifier}` exists but is the OG/meta-tags endpoint,
   not the profile read.** VERDICT: Corrected. SOURCE: OpenAPI
   `GET /ui/profile/meta/{identifier}` (op `profile_meta_tags_ui_profile_meta__identifier__get`).
6. **A storefront read `GET /ui/profile/public/{identifier}` → `PublicProfileData`
   carries `follower_count/following_count/post_count/is_following/has_subscription_plans`.**
   VERDICT: Verified. SOURCE: OpenAPI `GET /ui/profile/public/{identifier}` (op
   `get_public_profile_…`); `src/api/endpoints/profile.ts: getPublicProfile`;
   `src/api/types.ts: PublicProfileData` (503–522).
7. **Save = `PATCH /ui/profile` (`ProfilePatchReq`, partial) AND `PUT /ui/profile`
   (`ProfilePutReq`, full) both exist; return `{ profile: Profile }`.**
   VERDICT: Corrected/confirmed (draft hedged "PATCH vs PUT"; both exist).
   SOURCE: OpenAPI `PATCH /ui/profile` (op `ui_patch_profile_…`, req `ProfilePatchReq`)
   and `PUT /ui/profile` (op `ui_put_profile_…`, req `ProfilePutReq`);
   `src/api/endpoints/profile.ts: patchProfile` / `replaceProfile`.
8. **`ProfilePatchReq` has no `links` field.** VERDICT: Corrected (draft saved
   `links` in the body). SOURCE: `components.schemas.ProfilePatchReq` field titles in
   `openapi.pretty.json` (Birthday, Cover Photo Url, Description, Display Name,
   Displayed Email, Displayed Telephone Number, First Name, Gender, Languages, Last
   Name, Locale, Location, Middle Name, Profile Photo Url, Title).
9. **Private profiles are not a distinct signal — they return `404`
   (`not_found_or_suppressed`), and rate-limiting returns `429` (`rate_limited`,
   honors `Retry-After`).** VERDICT: Corrected (draft posited a `ProfileResult.Private`
   from a 403 / flagged 200). SOURCE: `src/api/endpoints/profile.ts:
   mapProfileLookupError` (404→`not_found_or_suppressed`, 429→`rate_limited`) and
   `parseRetryAfterSeconds`/`parseRetryAfterSecondsFromBody`;
   `src/pages/profile/PublicUserProfilePage.tsx` renders 404 as "Profile Not Available".
10. **`X-CSRF-Token` is set from the `ui_csrf` cookie on EVERY request, not only
    mutations.** VERDICT: Corrected/clarified (draft framed it as mutation-only).
    SOURCE: `src/api/client.ts` lines 167–171 (`const csrf = getCookie("ui_csrf"); …
    headers.set("X-CSRF-Token", csrf)`) — unconditional in the shared `api()` wrapper.
11. **401 triggers a single session-refresh-then-retry; a still-401 retry logs out.**
    VERDICT: Verified (this suite assumes the shared authenticator; AND-011/AND-013).
    SOURCE: `src/api/client.ts` lines 194–237 (refresh-once + retry).
12. **422 error shape is FastAPI `HTTPValidationError` =
    `{"detail":[{"loc":[…],"msg":…,"type":…}]}`; string and object `detail` also
    occur (e.g. `{"detail":{"code":"geo_blocked","message":…}}`).** VERDICT: Verified.
    SOURCE: every profile op in `openapi.index.txt` lists `422:HTTPValidationError`;
    `src/api/client.ts` 239–248 special-cases object `detail.code` (geo_blocked);
    `normalizeErrorDetail` handles string/object.
13. **`audience="owner"` ⇒ `viewerIsOwner=true`; redaction is backend-driven by
    audience.** VERDICT: Verified. SOURCE: `src/pages/profile/PublicUserProfilePage.tsx`
    (`isOwnerAudience = detail?.audience === "owner"`).
14. **Stack/framework choices (Compose UI test, Robolectric for `src/test/`,
    MockWebServer for transport contract, `connectedAndroidTest` for instrumented).**
    VERDICT: Verified (framework refs).
    SOURCE: framework ref https://developer.android.com/jetpack/compose/testing ;
    framework ref https://robolectric.org/ ;
    framework ref https://github.com/square/okhttp/tree/master/mockwebserver ;
    framework ref https://developer.android.com/training/testing/instrumented-tests .
15. **App Links / deep-link `https://<host>/u/{identifier}` for FR-11.** VERDICT:
    Unverified-assumption. SOURCE: not derivable from OpenAPI/frontend API sources;
    owned by AND-022/AND-073 manifest. framework ref
    https://developer.android.com/training/app-links .

### Corrections made

- Own-profile path `/ui/me/profile` → **`GET /ui/profile`**, and response is the
  **`{ profile: Profile }` wrapper** (claims 1, 7). (§3 FR-1/FR-6, §4.1, §5)
- Public read endpoint `/ui/profile/meta/{identifier}` → **`GET /ui/profiles/{identifier}`
  returning `CrossUserProfileResp`** with an `audience` field; clarified the
  `/ui/profile/public/{identifier}` storefront read and the meta-tags endpoint
  (claims 4, 5, 6). (§3 FR-2, §4.1, §5)
- Domain/wire fields: removed invented `username/bio/avatar_url/stats/links/
  is_private`; mapped bio→`description`, avatar→`profile_photo_url`; counts moved to
  `PublicProfileData` (claims 3, 8). (§3, §5, §6)
- Removed the **`ProfileResult.Private` / `ProfileUiState.Private`** branch; private
  folds into `NotFound` (404); added **`RateLimited` (429)** as the real distinct
  third branch (claim 9). (§3 FR-3/FR-4, §4.1, §4.2, §6, §7, §11, §13, §14 AC-2/AC-6)
- Edit validation: dropped the malformed-link-URL rule (no `links`), kept
  display-name/`description` length, suggested validating `profile_photo_url`
  (claim 8). (§3 FR-5, §14 AC-3)
- CSRF: clarified `X-CSRF-Token` is sent on **all** requests, not just mutations
  (claim 10). (§3 FR-8)
- Dropped the "tap a link" intent (no links) in favor of an avatar/image tap
  (claim 8). (§3 FR-10, §4.2 samples, §14 AC-7)

### Open assumptions

- **App Link host + path** (`https://<host>/u/{identifier}` vs `/profile/{identifier}`)
  for FR-11: not present in OpenAPI or the frontend API layer; depends on the
  AND-022/AND-073 manifest `<intent-filter>` and the web router. Treat as assumption
  until that manifest is available (claim 15).
- **Custom-scheme `testlogon://u/{identifier}`**: assumed; not derivable from the
  reviewed sources — confirm with AND-022.
- **Exact field-level max lengths** for `display_name`/`description` validation:
  `ProfilePatchReq` declares the fields as nullable strings with no `maxLength` in
  the captured schema; the over-length thresholds are an assumption to be pinned to
  the AND-072 validator (tests should reference the validator constant, not a magic
  number).
- **Per-audience redaction specifics** (which `Profile` fields the backend omits for
  `audience="public"`): inferred to be backend-driven; tests assert against captured
  `audience="public"`/`"owner"` fixtures rather than a hardcoded redaction list.
- **Analytics events** (`profile_viewed`/`profile_saved`): existence not confirmed in
  sources; §10 keeps these N/A-conditional.

## 17. Test Plan

Cases trace to the §14 Acceptance Criteria (AC-1…AC-8). Test targets: JVM =
JVM/Robolectric local (no device); Emulator = headless AVD `test35` (x86_64, API
35); Device = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This
ticket is a headless test suite with no camera/biometric/FCM/WebRTC/streaming
surface, so almost everything runs on JVM or the emulator; one ABI/API-parity case
is called out for the physical device.

- **TC-AND-076-01 — Own-profile full mapping.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `MockWebServer` up; fixture `profile_own_full.json` =
  `{"profile":{...all fields...}}`.
  Steps: enqueue 200 + fixture; call `repository.getOwnProfile()`.
  Expected: `ApiResult.Success`; `display_name`, `description`, `profile_photo_url`,
  `cover_photo_url`, `languages` mapped exactly; request was `GET /ui/profile`.
  Traces: AC-1.
- **TC-AND-076-02 — Own-profile minimal/nullable mapping.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: fixture `profile_own_minimal.json` (`description=null`, optionals
  absent).
  Steps: enqueue 200; call `getOwnProfile()`.
  Expected: Success; `description==null`, `coverPhotoUrl==null`, no NPE/throw.
  Traces: AC-1.
- **TC-AND-076-03 — Cross-user public found + audience mapping.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: fixture `profile_crossuser_public.json` (`audience:"public"`).
  Steps: enqueue 200; call `getProfileByIdentifier("alice")`.
  Expected: `ProfileResult.Found`; `viewerIsOwner==false`; request path
  `/ui/profiles/alice`; owner-only fields absent for the public audience.
  Traces: AC-2.
- **TC-AND-076-04 — Cross-user owner audience maps viewerIsOwner=true.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: fixture `profile_crossuser_owner.json` (`audience:"owner"`).
  Steps: enqueue 200; call `getProfileByIdentifier("self")`.
  Expected: `Found` with `viewerIsOwner==true`. Traces: AC-2.
- **TC-AND-076-05 — Not-found/suppressed maps NotFound (404).**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: fixture `profile_not_found.json`, code 404.
  Steps: enqueue 404; call `getProfileByIdentifier("ghost")`.
  Expected: `ProfileResult.NotFound` (not `Error`); repository does not throw;
  covers private-profile-folds-into-404. Traces: AC-2, AC-5.
- **TC-AND-076-06 — Rate-limited maps RateLimited (429 + Retry-After).**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: fixture `profile_rate_limited.json`, code 429, header
  `Retry-After: 30` (and/or `detail.retry_after_seconds`).
  Steps: enqueue 429; call `getProfileByIdentifier("alice")`.
  Expected: `ProfileResult.RateLimited(retryAfterSeconds=30)`; no throw.
  Traces: AC-2, AC-5.
- **TC-AND-076-07 — Save success returns updated profile + reload reflects it.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: fixtures `profile_save_ok.json` (`{"profile":{...updated...}}`) then
  `profile_own_full_v2.json` for reload.
  Steps: enqueue 200 (save) then 200 (reload); call `repository.saveProfile(patch)`
  then `getOwnProfile()`.
  Expected: save request is `PATCH /ui/profile` with JSON body matching
  `ProfilePatchReq` (e.g. `display_name`, `description`; no `links`); save returns the
  updated `Profile`; reload reflects new values. Traces: AC-4.
- **TC-AND-076-08 — Save carries X-CSRF-Token from ui_csrf cookie.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: harness cookie jar seeded with `ui_csrf=<v>`; fixture
  `profile_save_ok.json`.
  Steps: enqueue 200; call `saveProfile(...)`; read `server.takeRequest().headers`.
  Expected: `X-CSRF-Token == <v>`; header also present (security check) on a
  preceding `GET /ui/profile` per claim 10; no cookie/token value appears in captured
  logs. Traces: AC-4, AC-8.
- **TC-AND-076-09 — Save 422 maps field errors + string/object/empty fallbacks, no throw.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: fixtures for (a) `HTTPValidationError`
  `{"detail":[{"loc":["body","description"],"msg":"too long","type":"value_error"}]}`,
  (b) `{"detail":"bad request"}`, (c) `{"detail":{"code":"geo_blocked","message":"…"}}`,
  (d) malformed JSON, (e) empty body — all code 422/4xx.
  Steps: enqueue each; call `saveProfile(...)`.
  Expected: (a) `description` field error mapped via `loc` last segment; (b)/(c)/(d)/(e)
  form-level error; repository never throws on any shape. Traces: AC-5.
- **TC-AND-076-10 — Offline/timeout maps to Offline with Retry, headlessly.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `MockResponse().setSocketPolicy(NO_RESPONSE)` (or body delay);
  virtual-time scheduler.
  Steps: enqueue no-response; call `getOwnProfile()`; advance virtual time past the
  read timeout.
  Expected: connectivity/`Offline` result (not crash); completes in virtual ms, no
  `Thread.sleep`. Traces: AC-8.
- **TC-AND-076-11 — Loaded screen renders display name / description / avatar / Edit.**
  Type: Compose-UI (Robolectric). Target: JVM.
  Preconditions: `OwnProfileScreen(state=Loaded(sampleProfile))`.
  Steps: set content; query test tags.
  Expected: `profile_displayName`, `profile_description`, `profile_avatar` displayed;
  `profile_edit` has click action. Traces: AC-6.
- **TC-AND-076-12 — Public screen renders NotFound and RateLimited surfaces.**
  Type: Compose-UI (Robolectric). Target: JVM.
  Preconditions: `PublicProfileScreen` driven with `NotFound` then `RateLimited`.
  Steps: set each state; assert tags `public_notfound` / `public_ratelimited`
  displayed and distinct from `public_error`.
  Expected: each branch renders its own surface. Traces: AC-6.
- **TC-AND-076-13 — Edit validation gates Save; valid input enables it.**
  Type: Compose-UI + ViewModel (Robolectric). Target: JVM.
  Preconditions: `EditProfileViewModel` with `FakeProfileRepository`.
  Steps: set over-length `display_name`, then over-length `description`; then valid
  values; observe state.
  Expected: per-field errors set and `canSave=false` while invalid (no network call
  issued by the fake); `canSave=true` for valid input. Traces: AC-3.
- **TC-AND-076-14 — Intents: Edit/field-edit/Save/Retry/avatar callbacks fire.**
  Type: Compose-UI (Robolectric). Target: JVM.
  Preconditions: screens with lambda spies.
  Steps: click Edit; type a field; click Save; click Retry (Error state); tap avatar.
  Expected: `onEdit`, form-state update, `onSave`, `onRetry`, `onAvatarClick` each
  invoked once. Traces: AC-7.
- **TC-AND-076-15 — Accessibility: avatar contentDescription + 48dp touch targets + string-res copy.**
  Type: Compose-UI (instrumented). Target: Emulator.
  Preconditions: `OwnProfileScreen(Loaded)` with Coil avatar (instrumented so Coil
  loads).
  Steps: assert avatar node exposes a non-empty content description; Edit/Save/Retry
  expose click action + readable label; assert min 48dp via semantics; assert copy
  resolves from `R.string.profile_*`.
  Expected: all a11y assertions pass. Traces: AC-6, AC-7.
- **TC-AND-076-16 — App Link `https://<host>/u/{identifier}` routes to PublicProfileScreen.**
  Type: instrumented (NavHost deep link). Target: Emulator.
  Preconditions: test `NavHost`; manifest intent-filter host (assumption per §16).
  Steps: `handleDeepLink(Uri.parse("https://app.testlogon.com/u/alice"))`.
  Expected: `public_profile_root` displayed; back-stack arg `identifier=="alice"`.
  Traces: AC-7.
- **TC-AND-076-17 — Headless determinism + ABI/API parity smoke.**
  Type: instrumented/e2e. Target: Device (physical, arm64-v8a / API 34) AND Emulator
  (x86_64 / API 35) — run on BOTH to catch ABI/API differences; the suite otherwise
  has no hardware dependency so the physical device is used only for this parity
  smoke.
  Preconditions: full `:feature-profile:connectedDebugAndroidTest` suite.
  Steps: run the instrumented suite twice (`--rerun-tasks`) on each target.
  Expected: green on both targets, identical results, no flake, no wall-clock waits,
  no real network. Traces: AC-8.

### Coverage matrix (AC → TCs)

| Acceptance criterion | Covered by |
|---|---|
| AC-1 own load full + minimal | TC-01, TC-02 |
| AC-2 cross-user found / not-found / rate-limited | TC-03, TC-04, TC-05, TC-06 |
| AC-3 edit validation gating | TC-13 |
| AC-4 save success + reload + CSRF | TC-07, TC-08 |
| AC-5 save-error mapping (422/string/object/malformed/empty) | TC-09, TC-05, TC-06 |
| AC-6 UI state surfaces | TC-11, TC-12, TC-15 |
| AC-7 UI intents + deep-link route | TC-14, TC-16, TC-15 |
| AC-8 headless determinism / offline / parity | TC-08, TC-10, TC-17 |

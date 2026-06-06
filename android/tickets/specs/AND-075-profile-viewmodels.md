---
id: AND-075
title: Profile ViewModels
milestone: M2
epic: E10
priority: P0
size: M
depends_on: [AND-070]
blocks: [AND-071, AND-072, AND-073, AND-076]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-075 — Profile ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer state machines for the Profile feature: three Hilt-injected `ViewModel`s — `OwnProfileViewModel`, `PublicProfileViewModel`, and `EditProfileViewModel` — living in the `feature-profile` module. Each owns a single immutable `StateFlow<UiState>`, consumes one-shot user intents through an `onEvent(...)` entry point, and emits one-shot side effects (navigation, snackbars, toasts) through a `SharedFlow`/`Channel`. They are the sole orchestration point between the `ProfileRepository` (built on the `ProfileApi` from AND-070) and the Compose screens that will be built on top of them in AND-071 (own profile), AND-072 (edit profile), and AND-073 (public profile).

The goal is to land fully unit-tested, side-effect-free-on-construction ViewModels with deterministic, explicitly-enumerated state transitions for load, refresh, retry, edit-field, validate, save, and error paths — including the offline/stale and 401-refresh behavior mandated by the unreliable dev backend. No Compose UI is in scope here; screens that render these states are downstream tickets. The acceptance bar is unit-tested state transitions (per the backlog), so the deliverable is the ViewModels, their UiState/Event/Effect contracts, the repository interface they depend on, and a `core-testing`-backed test suite covering every transition.

## 2. Context & References

- **Backlog (authoritative):** AND-075 — Profile ViewModels. Type: Feature · Priority: P0 · Deps: AND-070. Scope: "Own/public/edit view models with state + events." Acceptance: "Unit-tested state transitions."
- **Dependency AND-070 (Profile API + DTOs):** provides `ProfileApi` derived from `frontend/src/api/endpoints/profile.ts` plus `GET /ui/profile/meta/{identifier}`, and the Moshi DTOs. AND-075 consumes the repository/mapped domain models built on top of it; it does **not** redefine DTOs.
- **Downstream consumers:** AND-071 (own profile screen), AND-072 (edit profile basics — name/bio/links validation + save), AND-073 (public profile `/u/:identifier` + App Link, not-found/private handling). AND-076 adds repository + UI tests on top.
- **Web reference:** `frontend/src/api/endpoints/profile.ts`, `frontend/src/api/types.ts` (shared `Profile`/`ProfileMeta` shapes), and the corresponding profile screens under `frontend/src/`.
- **Project conventions:** Module layering `app -> feature-* -> core-*`; ViewModels expose `StateFlow<UiState>`; typed `ApiResult<T>`; FastAPI `detail` mapping (`string | [{msg}] | {code,...}`); cookie-based session with single `POST /ui/session/refresh` retry on 401; namespace `com.testlogon.android`.
- **Source tree (this ticket):** `android/feature-profile/src/main/java/com/testlogon/android/feature/profile/`.

## 3. Functional Requirements

**FR-1 — Own profile load.** `OwnProfileViewModel` loads the authenticated user's profile via the repository (backed by `GET /ui/profile`, which the web client calls as `getProfile()` and which returns `{ profile: Profile }`) on first collection, exposing `Loading -> Content | Error` with the mapped domain `Profile` (display name, description/bio, photo + cover URLs, title, location). [CORRECTED — the previous draft cited `GET /ui/me` / `GET /ui/profile/meta/{identifier}`; `/ui/me` is the identity/session endpoint and `/ui/profile/meta/{identifier}` serves meta tags, not the editable own-profile payload. Note: domain `Profile` does not include nested `stats` or `links` fields — see §5.]

**FR-2 — Public profile load by identifier.** `PublicProfileViewModel` takes an `identifier` (username or id) from `SavedStateHandle` (route arg from AND-073) and loads the public profile via `GET /ui/profile/public/{identifier}` (web `getPublicProfile`, returns `PublicProfileData`), optionally enriched by `GET /ui/profiles/{identifier}` (web `getProfileByIdentifier`, returns `CrossUserProfileResp` with an `audience` field). It maps the distinct outcomes **found**, **not-found-or-suppressed (404)**, and **rate-limited (429)** into discrete UI states, falling back to a generic error otherwise. [CORRECTED — the previous draft assumed a `403 → Private` outcome; neither the OpenAPI spec (only 200/422 documented) nor the web client distinguishes 403. The web `PublicUserProfilePage` collapses private/suppressed profiles into the 404 "Profile Not Available" path and additionally handles 429. The `Private` UI state is retained only as an OPTIONAL/UNVERIFIED rendering of the 404 `not_found_or_suppressed` code, never a separate 403; see §16.]

**FR-3 — Edit profile.** `EditProfileViewModel` seeds an editable form from the current profile, exposes field-level edit events (display name, description/bio, and other editable basics such as title/location), runs synchronous client-side validation, tracks dirty state, and performs save via `PATCH /ui/profile` (web `patchProfile`, request schema `ProfilePatchReq`, response `{ profile: Profile }`). It blocks save while invalid or in-flight and surfaces field errors and server-side `detail` errors. [CORRECTED — the backend `ProfilePatchReq` has `display_name`, `description`, `profile_photo_url`, `cover_photo_url`, `title`, `location`, `first/middle/last_name`, etc.; there is NO `bio` field (the equivalent is `description`) and NO `links` field. The `links` form field from the original draft is unsupported by the API and is dropped / flagged as an open assumption in §16.]

**FR-4 — Refresh & retry.** Own and public ViewModels support pull-to-refresh (non-blocking, preserves last content) and a retry action from the error state (re-runs the load).

**FR-5 — Events in, effects out.** Each ViewModel exposes `fun onEvent(event: XEvent)` and a one-shot effects stream (`SharedFlow<XEffect>`). Effects include navigation requests (e.g., edit -> back with result), snackbar messages, and the "open external link" intent for profile links.

**FR-6 — Offline/stale.** When the load fails due to no connectivity but cached/last-known content exists, ViewModels surface a `Content(..., isStale = true)` state rather than a hard error, with a `staleReason`.

**FR-7 — No work on construction.** Loads are triggered lazily on first subscriber (or by an explicit `init`-time launch guarded for testability); construction must be free of network calls so tests can assert the initial `Loading`/`Idle` state.

**FR-8 — Unsaved-changes guard.** `EditProfileViewModel` reports `hasUnsavedChanges` so the screen can intercept back navigation.

## 4. Technical Design

All types live under `com.testlogon.android.feature.profile`. ViewModels are `@HiltViewModel`-annotated and inject a `ProfileRepository` (interface owned here for the presentation contract; concrete impl is part of the data layer landed with AND-070/AND-072). `SavedStateHandle` is injected for route args. Coroutines run on an injected `DispatcherProvider` (from `core-testing`/`core-data`) so tests can substitute `StandardTestDispatcher`.

### 4.1 Repository contract (consumed)

```kotlin
package com.testlogon.android.feature.profile.data

interface ProfileRepository {
    /** Authenticated user's own profile. */
    suspend fun getOwnProfile(forceRefresh: Boolean = false): ApiResult<Profile>

    /** Public profile by username or id. */
    suspend fun getPublicProfile(identifier: String): ApiResult<Profile>

    /** Partial update of own profile basics. */
    suspend fun updateProfile(patch: ProfilePatch): ApiResult<Profile>

    /** Last cached own profile for stale-while-error rendering, or null. */
    fun cachedOwnProfile(): Profile?
}
```

`Profile`, `ProfileLink`, `ProfileStats` are `core-model` domain types mapped from AND-070 DTOs. `ApiResult<T>` is the project-standard sealed result (`Success`, `Failure(error: AppError)`); `AppError` carries the mapped FastAPI `detail` plus a coarse `kind` (`Network`, `Timeout`, `Unauthorized`, `NotFound`, `Forbidden`, `Validation(fieldErrors)`, `Server`, `Unknown`).

### 4.2 OwnProfileViewModel

```kotlin
@HiltViewModel
class OwnProfileViewModel @Inject constructor(
    private val repo: ProfileRepository,
    private val dispatchers: DispatcherProvider,
) : ViewModel() {

    private val _state = MutableStateFlow(OwnProfileUiState())
    val state: StateFlow<OwnProfileUiState> = _state.asStateFlow()

    private val _effects = MutableSharedFlow<OwnProfileEffect>(extraBufferCapacity = 8)
    val effects: SharedFlow<OwnProfileEffect> = _effects.asSharedFlow()

    fun onEvent(event: OwnProfileEvent) { /* see §6 */ }

    private fun load(forceRefresh: Boolean) { /* maps ApiResult -> state */ }
}
```

```kotlin
data class OwnProfileUiState(
    val phase: Phase = Phase.Loading,
    val profile: Profile? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val staleReason: StaleReason? = null,
    val error: UiError? = null,
) {
    enum class Phase { Loading, Content, Error }
}

sealed interface OwnProfileEvent {
    data object Load : OwnProfileEvent
    data object Refresh : OwnProfileEvent
    data object Retry : OwnProfileEvent
    data object EditClicked : OwnProfileEvent
    data class LinkClicked(val url: String) : OwnProfileEvent
}

sealed interface OwnProfileEffect {
    data object NavigateToEdit : OwnProfileEffect
    data class OpenUrl(val url: String) : OwnProfileEffect
    data class ShowSnackbar(val message: UiText) : OwnProfileEffect
}
```

### 4.3 PublicProfileViewModel

Reads `identifier` from `SavedStateHandle` (route arg key `identifier`, defined by AND-073). Distinct phases for `NotFound` and (optionally) `Private` so the screen renders dedicated empty states. NOTE (corrected): the backend does not emit a 403 for private profiles — it returns 404 `not_found_or_suppressed`. The `Private` phase is therefore reachable only if AND-070's mapping chooses to distinguish a suppressed-but-existing profile from a true 404; absent that signal, treat 404 as `NotFound`. A `RateLimited` outcome (429) should also be representable; if the enum below does not yet carry it, it maps to `Error` (retryable after `Retry-After`).

```kotlin
@HiltViewModel
class PublicProfileViewModel @Inject constructor(
    private val repo: ProfileRepository,
    private val dispatchers: DispatcherProvider,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    private val identifier: String = requireNotNull(savedStateHandle["identifier"])
    private val _state = MutableStateFlow(PublicProfileUiState())
    val state: StateFlow<PublicProfileUiState> = _state.asStateFlow()
    // effects/onEvent as above
}

data class PublicProfileUiState(
    val phase: Phase = Phase.Loading,
    val profile: Profile? = null,
    val isRefreshing: Boolean = false,
    val error: UiError? = null,
) { enum class Phase { Loading, Content, NotFound, Private, Error } }
```

### 4.4 EditProfileViewModel

Holds a `form` snapshot plus the immutable `original` for dirty-diffing.

```kotlin
@HiltViewModel
class EditProfileViewModel @Inject constructor(
    private val repo: ProfileRepository,
    private val dispatchers: DispatcherProvider,
) : ViewModel() {

    private val _state = MutableStateFlow(EditProfileUiState())
    val state: StateFlow<EditProfileUiState> = _state.asStateFlow()
    val effects: SharedFlow<EditProfileEffect> = /* ... */

    fun onEvent(event: EditProfileEvent)
    private fun validate(form: ProfileForm): FieldErrors
    private fun save()
}

data class EditProfileUiState(
    val phase: Phase = Phase.Loading,         // Loading | Editing | Saving
    val form: ProfileForm = ProfileForm(),
    val original: ProfileForm = ProfileForm(),
    val fieldErrors: FieldErrors = FieldErrors(),
    val saveError: UiError? = null,
) {
    enum class Phase { Loading, Editing, Saving }
    val hasUnsavedChanges: Boolean get() = form != original
    val canSave: Boolean get() = phase == Phase.Editing && fieldErrors.isEmpty() && hasUnsavedChanges
}

data class ProfileForm(
    val displayName: String = "",
    val bio: String = "",
    val links: List<String> = emptyList(),
)

data class FieldErrors(
    val displayName: UiText? = null,
    val bio: UiText? = null,
    val links: Map<Int, UiText> = emptyMap(),
) { fun isEmpty() = displayName == null && bio == null && links.isEmpty() }

sealed interface EditProfileEvent {
    data object Load : EditProfileEvent
    data class DisplayNameChanged(val value: String) : EditProfileEvent
    data class BioChanged(val value: String) : EditProfileEvent
    data class LinkChanged(val index: Int, val value: String) : EditProfileEvent
    data object Save : EditProfileEvent
    data object BackPressed : EditProfileEvent
}

sealed interface EditProfileEffect {
    data class NavigateBackWithResult(val updated: Profile) : EditProfileEffect
    data object ConfirmDiscard : EditProfileEffect
    data class ShowSnackbar(val message: UiText) : EditProfileEffect
}
```

`validate` runs on every field-change event (synchronous, pure) so `canSave` is always current; `UiText` is the `core-ui` string-resource-or-literal wrapper for testable, localizable messages.

## 5. API Contract

This ticket consumes — it does not define — HTTP contracts; the Retrofit `ProfileApi` and DTOs are owned by AND-070. The endpoints reached transitively (all VERIFIED against the OpenAPI index and `src/api/endpoints/profile.ts`) are:

- `GET /ui/profile` → own profile; web `getProfile()` returns `{ profile: Profile }`. [CORRECTED from `GET /ui/profile/meta/{identifier}` + `GET /ui/me`.]
- `GET /ui/profile/public/{identifier}` → public storefront profile; web `getPublicProfile()` returns `PublicProfileData` (includes `follower_count`, `following_count`, `post_count`, `is_following`, etc.).
- `GET /ui/profiles/{identifier}` → cross-user lookup; web `getProfileByIdentifier()` returns `CrossUserProfileResp` (`{ identifier, canonical_identifier?, user_sub, audience: "owner"|"member"|"public", profile }`); used for audience/canonical-redirect enrichment.
- `PATCH /ui/profile` → partial update; request schema `ProfilePatchReq`, response `{ profile: Profile }`. [CORRECTED — body type was `ProfilePatch`; the backend schema is `ProfilePatchReq`.]
- `GET /ui/me` and `GET /ui/profile/meta/{identifier}` DO exist but are NOT the own-/public-profile data endpoints (`/ui/me` = identity/session; `/ui/profile/meta/{identifier}` = social meta tags).

The web `Profile` DTO (`src/api/types.ts: Profile`, the shape AND-070 maps from) — CORRECTED; the original illustrative JSON used fabricated field names:

```json
{
  "display_name": "Jane Doe",
  "first_name": "Jane",
  "last_name": "Doe",
  "title": "Builder",
  "description": "Builder.",
  "location": "NYC",
  "displayed_email": "jane@example.com",
  "profile_photo_url": "https://.../a.jpg",
  "cover_photo_url": "https://.../c.jpg",
  "languages": []
}
```

Notes on the corrected shape: the field is `description` (NOT `bio`), `profile_photo_url`/`cover_photo_url` (NOT `avatar_url`/`cover_url`); there is NO `links`, NO nested `stats`, NO `is_self`, NO `is_private` on `Profile`. Social counts live on `PublicProfileData` as flat `follower_count`/`following_count`/`post_count`; viewer-relationship is `is_following`/`is_followed_by`/`is_mutual`; the "owner vs member vs public" distinction is `CrossUserProfileResp.audience`, not an `is_self` boolean. The mapped domain `Profile` and any `stats`/`links` convenience aggregation must be agreed with AND-070 (see §13 R-1 and §16 Open assumptions).

`PATCH /ui/profile` request body the edit VM emits (CORRECTED — `bio`→`description`, `links` removed; all `ProfilePatchReq` fields are optional/nullable so the patch may carry any subset):

```json
{ "display_name": "Jane Doe", "description": "Builder.", "title": "Builder", "location": "NYC" }
```

Error mapping (handled in repository, surfaced to VM as `AppError.kind`): HTTP 401 → repository performs the single `POST /ui/session/refresh` retry before returning (web dedupes concurrent refreshes via a shared `refreshPromise`; on refresh failure the web client logs out with `session_expired`); 404 → `NotFound` (web `getProfileByIdentifier` maps this to `ProfileLookupError("not_found_or_suppressed")`, i.e. it ALSO covers private/suppressed profiles); 429 → rate-limited (web parses `Retry-After`); 422 `detail:[{msg,loc?}]` → `Validation(fieldErrors)` keyed by `loc` tail; timeouts (~20s) → `Timeout`. The FastAPI `detail` may be `string | [{msg,...}] | {code,...}` (web `normalizeErrorDetail`/`mapAuthorizationError`). [CORRECTED — a discrete `403 → Forbidden/Private` mapping is NOT supported by the sources; OpenAPI documents only 200/422 for these routes and the web client has no 403 branch. `loc` is present on standard FastAPI 422 items but its exact field-mapping table is unverified — see §16.] All write requests carry the `X-CSRF-Token` header from the `ui_csrf` cookie; that plumbing belongs to `core-network`, not this ticket.

## 6. Data & State Management

- **Single source of truth:** each VM exposes exactly one `StateFlow<UiState>` built from `MutableStateFlow`, updated via `_state.update { it.copy(...) }`. No derived state lives in the screen.
- **Lazy load:** `state` triggers the initial load on first subscriber using `onSubscription`/an `init { onEvent(Load) }` guard that is overridable in tests; construction performs no I/O (FR-7).
- **Event reducer:** `onEvent` is the only mutation entry point. Representative own-profile transitions:
  - `Load` from `Loading`: success → `phase=Content, profile=…`; failure with cache → `phase=Content, isStale=true, staleReason=Offline`; failure without cache → `phase=Error, error=…`.
  - `Refresh` from `Content`: set `isRefreshing=true` (content retained); success → updated `profile, isRefreshing=false`; failure → `isRefreshing=false` + emit `ShowSnackbar` (content retained).
  - `Retry` from `Error`: → `phase=Loading` → load.
  - `EditClicked` → emit `NavigateToEdit`. `LinkClicked` → emit `OpenUrl`.
- **Edit transitions:** field events → `form` updated + `validate` re-run; `Save` when `canSave` → `phase=Saving` → success emits `NavigateBackWithResult` + updates cache; `422` → populate `fieldErrors` + `phase=Editing`; other failures → `saveError` + `phase=Editing`. `BackPressed` with `hasUnsavedChanges` → emit `ConfirmDiscard`, else `NavigateBackWithResult`-free back.
- **Effects:** buffered `MutableSharedFlow(extraBufferCapacity = 8, onBufferOverflow = DROP_OLDEST)` to avoid losing one-shot events while preserving testability with `turbine`.
- **Persistence:** no new persistence here; stale content is sourced from `repo.cachedOwnProfile()` (Room cache wired in AND-070). DataStore is not touched.
- **Process death:** route arg `identifier` survives via `SavedStateHandle`; in-flight edit form is intentionally not persisted in this ticket (tracked as open question Q-2).

## 7. Error Handling & Resilience

- **Typed mapping:** `AppError` → `UiError(message: UiText, retryable: Boolean)`; the VM never inspects raw HTTP or Retrofit exceptions (that is the repository's job).
- **401:** repository performs the single `POST /ui/session/refresh` + retry once; if it still fails, VM receives `Unauthorized` and emits a `ShowSnackbar` plus (for own profile) a navigation-to-login effect contract reserved for the auth feature — here it surfaces as `Error` with `retryable=false`.
- **Timeouts/network:** ~20s timeout and bounded-backoff retry for idempotent GETs are configured in `core-network`/`OkHttp`; the VM treats a returned `Timeout`/`Network` failure as `Error` (retryable) or, when cache exists, `isStale` (FR-6).
- **No retry on writes:** `PATCH /ui/profile` is non-idempotent; VM/repository must not auto-retry it — only the user-triggered `Save` re-attempts.
- **Validation precedence:** client-side `validate` blocks save before any request; server `422` errors are merged into `fieldErrors` afterward.
- **Cancellation:** all work runs in `viewModelScope`; refresh/save jobs are tracked so a second `Save`/`Refresh` while in-flight is ignored (guarded by `phase`).

## 8. Security & Privacy

- No credentials, cookies, or CSRF tokens are handled in this layer; the session cookie jar and `X-CSRF-Token` injection are owned by `core-network`. ViewModels must never log raw profile payloads or URLs containing tokens.
- Private/suppressed/not-found profiles (surfaced by the backend as **404 `not_found_or_suppressed`**, not 403 — corrected) must render the dedicated empty (`NotFound`/optional `Private`) state with **no** leaked fields — the VM discards any partial body on 404 (and on 403 should one ever occur) and stores only the phase.
- Outbound `OpenUrl` effects carry user-controlled link strings; the VM validates they are `http(s)` schemes in `validate`/before emit to avoid `intent://`/`javascript:` smuggling; non-http links are rejected with a field/snackbar error.
- "Is this my own profile?" gates the `EditClicked` affordance state (`canEdit` flag) so a public VM never exposes edit actions. [CORRECTED — there is no `is_self` field on the payload; the web client derives ownership from `CrossUserProfileResp.audience == "owner"` and/or `viewerUserId == PublicProfileData.user_id`. AND-070's mapping should expose this as a derived `isSelf`/`audience` value.]

## 9. Accessibility & i18n

No Compose UI ships in this ticket, so contrast/touch-target/semantics requirements are owned by AND-071/072/073. The ViewModel-side obligations are:

- All user-facing strings are `UiText` references to `strings.xml` resources (e.g., `R.string.profile_error_offline`, `R.string.profile_edit_name_required`) — never hardcoded literals — so downstream screens and TalkBack announcements are translatable and testable.
- Field error and snackbar messages are returned as `UiText` with format args, enabling RTL/locale-correct rendering by the screen.
- Stale/offline reasons are enumerated (`StaleReason.Offline`, `.Timeout`) so screens can map to localized, accessible status text.

## 10. Telemetry & Logging

- Structured, payload-free logs via the project logger at boundaries: `profile_load_start`, `profile_load_success{phase,is_stale}`, `profile_load_error{kind}`, `profile_save_start`, `profile_save_success`, `profile_save_error{kind}`. Log the `AppError.kind` enum, never the message body, identifiers (beyond a hashed user id), or URLs.
- Analytics events (interface only, no vendor wiring here): `profile_viewed{is_self}`, `profile_edit_opened`, `profile_saved`, `profile_link_opened`. Events are emitted via an injected `Analytics` interface (from `core-data`) so tests can assert emission without a backend.
- Verbose state-transition logging is gated behind `BuildConfig.DEBUG`.

## 11. Testing Strategy

Acceptance is "unit-tested state transitions," so this is the core of the deliverable. Tooling: JUnit4, `kotlinx-coroutines-test` (`runTest`, `StandardTestDispatcher` via injected `DispatcherProvider`), Turbine for `StateFlow`/`SharedFlow`, MockK for a fake `ProfileRepository`, and `core-testing` helpers (`MainDispatcherRule`, `FakeProfileRepository`, `profileFixture()`).

Required test cases (each asserts the exact emitted state sequence):

1. Own: construction emits initial `Loading` with no repo call (FR-7).
2. Own: `Load` success → `Loading` then `Content` with mapped profile.
3. Own: `Load` failure + cache present → `Content(isStale=true, staleReason=Offline)`.
4. Own: `Load` failure + no cache → `Error(retryable=true)`.
5. Own: `Refresh` keeps content, toggles `isRefreshing`; failure emits `ShowSnackbar`, retains content.
6. Own: `Retry` from `Error` re-loads.
7. Own: `EditClicked` emits `NavigateToEdit`; `LinkClicked` emits `OpenUrl`; non-http link rejected.
8. Public: 200 → `Content`; 404 → `NotFound`; 403 → `Private`; 5xx/timeout → `Error`.
9. Public: `identifier` missing from `SavedStateHandle` throws at construction (documented contract).
10. Edit: `Load` seeds `form == original`, `hasUnsavedChanges == false`.
11. Edit: field change makes `hasUnsavedChanges` true and updates `canSave`.
12. Edit: validation — empty display name, over-length bio, non-http link each set the right `fieldErrors` and force `canSave == false`.
13. Edit: `Save` success → `Saving` then `NavigateBackWithResult` + cache update.
14. Edit: `Save` 422 → merges server `fieldErrors`, returns to `Editing`.
15. Edit: `Save` other failure → `saveError` set, `Editing`.
16. Edit: `BackPressed` with changes emits `ConfirmDiscard`; without changes does not.
17. All: double `Save`/`Refresh` while in-flight is ignored (phase guard).

Coverage target ≥ 90% line/branch on the three VM classes. Tests run headlessly under `./gradlew :feature-profile:testDebugUnitTest`. No instrumentation/Compose tests here (owned by AND-076).

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-070 (Profile API + DTOs) — provides `ProfileApi`, DTOs, mapping to domain `Profile`, and the `ProfileRepository` concrete impl + Room cache that `cachedOwnProfile()` reads. AND-075 defines the `ProfileRepository` interface it consumes; if AND-070 has not yet introduced it, this ticket introduces the interface and AND-070's impl conforms.
- **Shared infra (assumed landed):** `core-model` (`Profile`), `core-network` (`ApiResult`, `AppError`, cookie jar, CSRF, 401-refresh), `core-ui` (`UiText`), `core-testing` (`MainDispatcherRule`, fakes, `DispatcherProvider`).
- **Blocks:** AND-071 (own profile screen), AND-072 (edit profile basics), AND-073 (public profile screen) all bind to these ViewModels via `hiltViewModel()`. AND-076 (profile tests) builds repository+UI tests atop this contract.
- **Sequencing:** land after AND-070; the three VMs can be built in parallel but share the `ProfileRepository` interface, so define that first. AND-072's `PATCH /ui/profile` field set must be agreed before finalizing `ProfilePatch`/`validate`.

## 13. Risks & Open Questions

- **R-1:** AND-070's exact `Profile` field names / `ProfilePatch` shape may differ from the web `profile.ts`; mitigate by mapping at the repository boundary and keeping VM coupled only to domain `Profile`. (Owner: AND-070.)
- **R-2 (RESOLVED):** Own-identifier resolution. Confirmed against OpenAPI + `src/api/endpoints/profile.ts`: a dedicated `GET /ui/profile` returns the own profile directly as `{ profile: Profile }` — no `/ui/me` round-trip and no `/ui/profile/meta/{identifier}` are needed for `getOwnProfile`. Q-1 closed.
- **Q-2:** Should an in-progress edit form survive process death via `SavedStateHandle`? Deferred; current design re-seeds from server on reload.
- **Q-3:** Server-side `422` `loc` paths must map cleanly to `FieldErrors`; the `loc`→field mapping table should be confirmed once AND-072 finalizes the PATCH contract.
- **R-4:** Unreliable dev host means flaky integration; this ticket avoids real network in tests entirely (fakes), so risk is contained to downstream integration tickets.

## 14. Acceptance Criteria

1. Three `@HiltViewModel` classes — `OwnProfileViewModel`, `PublicProfileViewModel`, `EditProfileViewModel` — exist under `com.testlogon.android.feature.profile`, each exposing one `StateFlow<UiState>`, an `onEvent(...)` entry point, and a one-shot effects `SharedFlow`.
2. Each documented state transition in §6 is implemented and covered by a passing unit test (test list §11), with deterministic emitted-state-sequence assertions via Turbine.
3. Construction performs no I/O; initial state is `Loading`/`Idle` and asserted in tests (FR-7).
4. Public VM maps 200/404/403/error to `Content`/`NotFound`/`Private`/`Error` respectively.
5. Edit VM enforces client validation (`canSave` gating), dirty tracking (`hasUnsavedChanges`), merges server `422` field errors, and emits `NavigateBackWithResult` on save success.
6. Offline-with-cache renders `Content(isStale=true)`; offline-without-cache renders retryable `Error`; writes are never auto-retried.
7. No raw payloads/URLs/tokens are logged; all user-facing strings are `UiText`/resource-backed.
8. `./gradlew :feature-profile:testDebugUnitTest` passes headlessly with ≥ 90% line/branch coverage on the three VMs.

## 15. Definition of Done

- All §14 acceptance criteria met; code merged to `android-port` under `android/feature-profile/`.
- `ProfileRepository` interface (or conformance to AND-070's) finalized and injected via Hilt; no `runBlocking`/eager I/O in constructors.
- Unit test suite green in CI headlessly; coverage gate satisfied; lint/detekt/ktlint clean.
- KDoc on each public VM, UiState, Event, and Effect type; effect-vs-state separation documented.
- Strings extracted to `strings.xml`; no hardcoded user-facing literals.
- Telemetry/analytics emitted via injected interfaces with no payload leakage; debug-gated verbose logs.
- Downstream owners (AND-071/072/073) reviewed and signed off on the UiState/Event/Effect contracts; open questions Q-1..Q-3 resolved or explicitly deferred with owners.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI index/spec (`reference/openapi.index.txt`, `reference/openapi.pretty.json`) and the web reference app under `reference/src/`.

1. **Own profile is fetched from a dedicated `GET /ui/profile` returning `{ profile: Profile }`.** VERDICT: Corrected (the draft said `GET /ui/me` + `GET /ui/profile/meta/{identifier}`). SOURCE: OpenAPI `GET /ui/profile` (op `ui_get_profile_ui_profile_get`); `src/api/endpoints/profile.ts: getProfile`.
2. **`GET /ui/me` is identity/session, not the own-profile data endpoint.** VERDICT: Corrected. SOURCE: OpenAPI `GET /ui/me` (op `ui_me_ui_me_get`).
3. **`GET /ui/profile/meta/{identifier}` is a meta-tags endpoint, not the profile payload.** VERDICT: Corrected. SOURCE: OpenAPI `GET /ui/profile/meta/{identifier}` (op `profile_meta_tags_ui_profile_meta__identifier__get`).
4. **Public profile is fetched from `GET /ui/profile/public/{identifier}` returning `PublicProfileData`.** VERDICT: Corrected (draft used `/ui/profile/meta/{identifier}`). SOURCE: OpenAPI `GET /ui/profile/public/{identifier}` (op `get_public_profile_...`); `src/api/endpoints/profile.ts: getPublicProfile`; `src/api/types.ts: PublicProfileData`.
5. **Cross-user lookup `GET /ui/profiles/{identifier}` returns `CrossUserProfileResp` with an `audience` field ("owner"|"member"|"public").** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/profiles/{identifier}` (op `ui_get_profile_by_identifier_...`); `src/api/endpoints/profile.ts: getProfileByIdentifier`; `src/api/types.ts: CrossUserProfileResp` / `ProfileViewAudience`.
6. **Edit save uses `PATCH /ui/profile` with request schema `ProfilePatchReq` and response `{ profile: Profile }`.** VERDICT: Corrected (draft body type `ProfilePatch`; method/path were right). SOURCE: OpenAPI `PATCH /ui/profile` (op `ui_patch_profile_ui_profile_patch`, `req=ProfilePatchReq`); `src/api/endpoints/profile.ts: patchProfile`.
7. **The `Profile` field for the long-text field is `description`, NOT `bio`.** VERDICT: Corrected. SOURCE: `src/api/types.ts: Profile`; `components.schemas.ProfilePatchReq.description` in `openapi.pretty.json`.
8. **Photo fields are `profile_photo_url` / `cover_photo_url`, NOT `avatar_url` / `cover_url`.** VERDICT: Corrected. SOURCE: `src/api/types.ts: Profile`; `ProfilePatchReq.profile_photo_url`/`cover_photo_url`.
9. **`Profile` has no `links` field and `ProfilePatchReq` accepts no `links`.** VERDICT: Corrected (draft's `links` form field and PATCH body key are unsupported). SOURCE: `src/api/types.ts: Profile`; `components.schemas.ProfilePatchReq` (full property list contains no `links`).
10. **`Profile` has no nested `stats` object; social counts are flat fields (`follower_count`/`following_count`/`post_count`) on `PublicProfileData`.** VERDICT: Corrected. SOURCE: `src/api/types.ts: PublicProfileData`.
11. **`Profile` has no `is_self`/`is_private` booleans; ownership comes from `CrossUserProfileResp.audience == "owner"` or `viewerUserId == PublicProfileData.user_id`.** VERDICT: Corrected. SOURCE: `src/api/types.ts: Profile` / `CrossUserProfileResp` / `PublicProfileData`; `src/pages/profile/PublicUserProfilePage.tsx` (`isOwnerAudience`, `isOwnProfile`).
12. **Private/suppressed profiles surface as 404 `not_found_or_suppressed`, not 403.** VERDICT: Corrected (draft mapped `403 → Private`). SOURCE: `src/api/endpoints/profile.ts: getProfileByIdentifier` (`mapProfileLookupError`, `ProfileLookupErrorCode`); `src/pages/profile/PublicUserProfilePage.tsx` (only 404/429/else branches, no 403). OpenAPI documents only 200/422 for these routes.
13. **A 429 rate-limited outcome exists for profile lookups (with `Retry-After`).** VERDICT: Verified. SOURCE: `src/api/endpoints/profile.ts` (`rate_limited`, `parseRetryAfterSeconds`); `PublicUserProfilePage.tsx` 429 branch.
14. **401 triggers a single `POST /ui/session/refresh` retry, deduped, with logout-on-failure.** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_...`, no request body); `src/api/client.ts: refreshSession` + the 401 handler (`refreshPromise` dedupe, `logout("session_expired")`).
15. **Write requests carry `X-CSRF-Token` sourced from the `ui_csrf` cookie; session is cookie-based (`credentials: include`).** VERDICT: Verified. SOURCE: `src/api/client.ts` (CSRF header from `getCookie("ui_csrf")`, `credentials: "include"`); same pattern in `src/api/endpoints/profile.ts`.
16. **FastAPI `detail` may be `string | [{msg,...}] | {code,...}`; 422 errors carry `loc`.** VERDICT: Verified (shape) / Unverified (exact `loc`→field table). SOURCE: `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`; OpenAPI `HTTPValidationError` (standard FastAPI 422). The precise `loc` tail per editable field is not enumerated in the sources.
17. **ViewModel framework choices (Hilt `@HiltViewModel`, `StateFlow`, `SavedStateHandle`, `viewModelScope`).** VERDICT: Verified (framework ref). SOURCE: framework ref — Android docs: developer.android.com/topic/libraries/architecture/viewmodel, developer.android.com/training/dependency-injection/hilt-jetpack (`@HiltViewModel`), kotlinlang.org/api/kotlinx.coroutines (StateFlow/SharedFlow).
18. **`extraBufferCapacity` + `BufferOverflow.DROP_OLDEST` for one-shot effect `SharedFlow`.** VERDICT: Verified (framework ref). SOURCE: framework ref — kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/-mutable-shared-flow.
19. **`http(s)`-only validation of outbound link strings to block `intent://`/`javascript:`.** VERDICT: Unverified-assumption (the web `Profile` has no `links`, so there is no web precedent to cite). SOURCE: n/a — see Open assumptions.
20. **Stale-while-error from a local Room cache via `repo.cachedOwnProfile()`.** VERDICT: Unverified-assumption (no web equivalent; web uses an in-memory etag `profileLookupCache` only, not offline content). SOURCE: `src/api/endpoints/profile.ts` (in-memory `profileLookupCache`, `If-None-Match`/etag) shows caching exists but not an offline-content store; the Room cache is an AND-070 design choice.

### Corrections made

- §FR-1 / §5: own profile endpoint changed from `GET /ui/me` + `GET /ui/profile/meta/{identifier}` to `GET /ui/profile` (`{ profile: Profile }`).
- §FR-2 / §4.3 / §5 / §8: public profile endpoint changed to `GET /ui/profile/public/{identifier}` (+ optional `GET /ui/profiles/{identifier}`); removed the `403 → Private` mapping (private/suppressed = 404 `not_found_or_suppressed`); added 429 rate-limited handling.
- §FR-3 / §5: PATCH body corrected — `bio`→`description`, `links` removed; request schema named `ProfilePatchReq`; response wrapped as `{ profile: Profile }`.
- §5: replaced the fabricated `Profile` JSON (had `bio`, `avatar_url`, `cover_url`, `links`, nested `stats`, `is_self`, `is_private`) with the real `src/api/types.ts: Profile` shape; clarified social counts live flat on `PublicProfileData` and ownership comes from `audience`.
- §8: removed reliance on a non-existent `is_self` field; ownership derived from `audience`/`user_id`.
- §13 R-2 / Q-1: marked RESOLVED — dedicated `GET /ui/profile` confirmed.

### Open assumptions

- **`stats`/`links` on domain `Profile`:** the API exposes neither on `Profile`; counts exist only on `PublicProfileData` and there is no links concept. Whether AND-070's domain `Profile` synthesizes `stats`/drops `links` must be agreed (R-1). Unverifiable here because it depends on AND-070's not-yet-landed mapping.
- **`Private` UI phase:** retained as optional; only reachable if AND-070 distinguishes suppressed-from-true-404. No backend 403 signal exists to drive it.
- **`loc`→`FieldErrors` mapping table (Q-3):** the 422 `loc` shape is standard FastAPI but the exact per-field tail for `display_name`/`description`/etc. is not enumerated in the sources; confirm once AND-072 finalizes the PATCH contract.
- **`http(s)`-only link validation:** no web precedent (no links feature); kept as a defensive Android-side assumption.
- **Offline/stale Room cache (`cachedOwnProfile()`):** web has only in-memory etag caching, not an offline content store; the Room-backed stale path is an AND-070 design decision, not a verified web behavior.
- **~20s timeout / bounded backoff for GETs:** an OkHttp/`core-network` configuration assumption; not specified by the sources.

## 17. Test Plan

Test IDs `TC-AND-075-NN`. Unless noted, cases are pure JVM unit tests (no device) using `runTest` + `StandardTestDispatcher` (injected `DispatcherProvider`), Turbine for `StateFlow`/`SharedFlow`, and a fake/mock `ProfileRepository` — appropriate because this ticket ships ViewModels with no Compose UI and no real network. "Traces" link to §14 Acceptance Criteria (AC-1..AC-8).

**Test targets:** `JVM unit/Robolectric` (local, no device) is the primary target for every VM case here. The emulator AVD `test35` (API 35) and the physical Samsung Galaxy A15 5G (SM-A156U, API 34) targets are listed for the small number of cases that benefit from a device; none of this ticket's logic is hardware-dependent (no camera/biometrics/FCM/WebRTC/Telecom), so device runs are only forward-looking smoke checks deferred to AND-071/072/073/076 and are flagged accordingly.

- **TC-AND-075-01 — Own: no I/O on construction.** Type: unit (JVM). Target: JVM unit. Preconditions: fake repo records all calls; VM constructed but `state` not yet collected. Steps: construct `OwnProfileViewModel`; assert no repo method invoked; collect `state` once. Expected: initial emission is `phase=Loading` with `profile=null` and zero repo calls until first subscription/`Load`. Traces: AC-3.
- **TC-AND-075-02 — Own: load happy path.** Type: unit (JVM). Target: JVM unit. Preconditions: repo returns `Success(profileFixture())`. Steps: send `Load`; advance dispatcher. Expected: emitted sequence `Loading → Content` with mapped `Profile` (display_name/description/profile_photo_url populated). Traces: AC-1, AC-2.
- **TC-AND-075-03 — Own: offline with cache → stale content.** Type: unit (JVM). Target: JVM unit. Preconditions: repo `getOwnProfile` returns `Failure(Network)`; `cachedOwnProfile()` returns a profile. Steps: send `Load`. Expected: `phase=Content, isStale=true, staleReason=Offline` (no hard error). Traces: AC-2, AC-6.
- **TC-AND-075-04 — Own: offline without cache → retryable error.** Type: unit (JVM). Target: JVM unit. Preconditions: repo `Failure(Network)`, `cachedOwnProfile()` null. Steps: send `Load`. Expected: `phase=Error, error.retryable=true`. Traces: AC-2, AC-6.
- **TC-AND-075-05 — Own: refresh retains content; failure snackbars.** Type: unit (JVM). Target: JVM unit. Preconditions: VM in `Content`. Steps: send `Refresh` (repo success) → assert `isRefreshing` toggles true→false and content updates; then `Refresh` (repo `Failure`) → assert content retained, `isRefreshing=false`, and a `ShowSnackbar` effect emitted. Expected: as described; content never cleared on refresh failure. Traces: AC-2.
- **TC-AND-075-06 — Own: retry from error re-loads.** Type: unit (JVM). Target: JVM unit. Preconditions: VM in `Error`. Steps: repo now returns `Success`; send `Retry`. Expected: `Error → Loading → Content`. Traces: AC-2.
- **TC-AND-075-07 — Own: effects (edit/link) + non-http link rejected.** Type: unit (JVM). Target: JVM unit. Preconditions: VM in `Content`. Steps: send `EditClicked` → assert `NavigateToEdit`; send `LinkClicked("https://ok")` → assert `OpenUrl`; send `LinkClicked("javascript:alert(1)")` and `LinkClicked("intent://x")` → assert NO `OpenUrl`, a rejection `ShowSnackbar`/field error instead. Expected: only `http(s)` URLs produce `OpenUrl`. Security case. Traces: AC-2, AC-7.
- **TC-AND-075-08 — Public: 200/404/429/error mapping.** Type: contract/MockWebServer (or unit with fake mapping repo). Target: JVM unit (MockWebServer JVM-local). Preconditions: repo/MockWebServer scripted per sub-case. Steps: load with (a) 200 `PublicProfileData` → `Content`; (b) 404 `not_found_or_suppressed` → `NotFound`; (c) 429 with `Retry-After` → rate-limited/`Error(retryable)`; (d) 5xx/timeout → `Error`. Expected: discrete phases per real backend outcomes; note there is NO 403/Private path. Traces: AC-4, AC-6.
- **TC-AND-075-09 — Public: missing `identifier` arg throws at construction.** Type: unit (JVM). Target: JVM unit. Preconditions: empty `SavedStateHandle`. Steps: construct `PublicProfileViewModel`. Expected: `IllegalArgumentException` (documented `requireNotNull` contract). Traces: AC-1.
- **TC-AND-075-10 — Edit: seed form, no dirty.** Type: unit (JVM). Target: JVM unit. Preconditions: repo `getOwnProfile` Success. Steps: send `Load`. Expected: `phase=Editing`, `form == original`, `hasUnsavedChanges == false`, `canSave == false`. Traces: AC-5.
- **TC-AND-075-11 — Edit: field change → dirty + canSave.** Type: unit (JVM). Target: JVM unit. Preconditions: loaded, valid. Steps: send `DisplayNameChanged("New Name")`. Expected: `hasUnsavedChanges == true`, `canSave == true`. Traces: AC-5.
- **TC-AND-075-12 — Edit: client validation blocks save.** Type: unit (JVM). Target: JVM unit. Preconditions: loaded. Steps: set empty `displayName`; set over-length `bio`/description; (if links supported in form) a non-http link. Expected: corresponding `fieldErrors` populated as `UiText`, `canSave == false`. Note: link validation only applies if a links field is retained; per §16 the API has no `links`. Traces: AC-5, AC-7.
- **TC-AND-075-13 — Edit: save success → navigate + cache.** Type: unit (JVM). Target: JVM unit. Preconditions: dirty + valid; repo `updateProfile` returns `Success(updated)`. Steps: send `Save`. Expected: `Editing → Saving`, then `NavigateBackWithResult(updated)` effect; cache updated; the PATCH body carries `description` (not `bio`) and no `links` key. Traces: AC-5.
- **TC-AND-075-14 — Edit: save 422 merges server field errors.** Type: contract/MockWebServer. Target: JVM unit (MockWebServer JVM-local). Preconditions: repo/server returns 422 `detail:[{msg,loc:["body","display_name"]}]`. Steps: send `Save`. Expected: server `fieldErrors` merged (keyed by `loc` tail), `phase` returns to `Editing`, no auto-retry. Uses the real FastAPI 422 shape. Traces: AC-5, AC-7.
- **TC-AND-075-15 — Edit: save other failure → saveError, no retry.** Type: unit (JVM). Target: JVM unit. Preconditions: repo `updateProfile` returns `Failure(Server)`. Steps: send `Save`. Expected: `saveError` set, `phase=Editing`, repo `updateProfile` called exactly once (writes never auto-retried). Traces: AC-5, AC-6.
- **TC-AND-075-16 — Edit: back-press guard.** Type: unit (JVM). Target: JVM unit. Steps: with changes send `BackPressed` → assert `ConfirmDiscard` effect; without changes send `BackPressed` → assert NO `ConfirmDiscard`. Expected: as described (FR-8). Traces: AC-5.
- **TC-AND-075-17 — All: in-flight double-action guarded.** Type: unit (JVM). Target: JVM unit. Steps: while a `Save` (or `Refresh`) is suspended, send a second `Save`/`Refresh`. Expected: second action ignored; repo write/refresh invoked once. Traces: AC-2, AC-6.
- **TC-AND-075-18 — 401 surfaces after refresh exhausted.** Type: contract/MockWebServer. Target: JVM unit (MockWebServer JVM-local). Preconditions: server returns 401, then 401 again on the post-`session/refresh` retry (or refresh 401). Steps: send `Load`. Expected: repository performs exactly one `POST /ui/session/refresh` then surfaces `Unauthorized`; VM renders `Error(retryable=false)` and emits a `ShowSnackbar` (own profile). Verifies the single-retry contract. Traces: AC-6, AC-7.
- **TC-AND-075-19 — No payload/token logging.** Type: unit (JVM). Target: JVM unit. Preconditions: inject a capturing logger; load a profile and trigger an error. Steps: drive load/save/error paths. Expected: emitted log records contain only enum `kind`/event names — no `description`, URLs, identifiers (beyond hashed user id), or tokens. Security/privacy case. Traces: AC-7.
- **TC-AND-075-20 — Strings are UiText/resource-backed (i18n/a11y).** Type: unit (JVM, Robolectric for resource resolution). Target: JVM unit/Robolectric. Preconditions: trigger each error/snackbar/field-error path. Steps: assert every user-facing message is a `UiText` resource reference (e.g., `R.string.profile_error_offline`) and resolves under a non-default locale. Expected: no hardcoded literals; messages resolve for TalkBack/RTL downstream. Accessibility/i18n case. Traces: AC-7.
- **TC-AND-075-21 — (Forward-looking) device smoke of VM-backed screens.** Type: instrumented/e2e. Target: PREFER emulator AVD `test35` (API 35) for CI; ALSO run once on the physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) to catch API-34-vs-35 / arm64-vs-x86 differences once AND-071/072/073 land screens. Preconditions: a debug build wiring these VMs to Compose screens (downstream). Steps: launch own/public/edit screens, exercise load + save. Expected: states render; no crashes across both ABIs/API levels. NOTE: this case is DEFERRED to AND-076 (no UI in this ticket) and is listed only to flag the device matrix. Traces: AC-1, AC-4 (indirect).

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (three VMs: state/onEvent/effects) | TC-01, TC-02, TC-09, TC-21 |
| AC-2 (each §6 transition unit-tested via Turbine) | TC-02, TC-03, TC-04, TC-05, TC-06, TC-07, TC-08, TC-17 |
| AC-3 (no I/O on construction; initial Loading) | TC-01 |
| AC-4 (public 200/404/(no-403)/error mapping) | TC-08, TC-21 |
| AC-5 (edit validation/dirty/422 merge/navigate) | TC-10, TC-11, TC-12, TC-13, TC-14, TC-15, TC-16 |
| AC-6 (stale-with-cache / retryable error / no write retry) | TC-03, TC-04, TC-08, TC-15, TC-17, TC-18 |
| AC-7 (no raw payloads/tokens; UiText/resource strings) | TC-07, TC-12, TC-14, TC-18, TC-19, TC-20 |
| AC-8 (`testDebugUnitTest` headless, ≥90% coverage) | All TC-01..TC-20 (headless JVM/Robolectric suite) |

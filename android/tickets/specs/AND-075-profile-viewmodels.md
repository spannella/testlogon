---
id: AND-075
title: Profile ViewModels
milestone: M2
epic: E10
priority: P0
size: M
status: draft
depends_on: [AND-070]
blocks: [AND-071, AND-072, AND-073, AND-076]
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

**FR-1 — Own profile load.** `OwnProfileViewModel` loads the authenticated user's profile via the repository (backed by `GET /ui/me` / `GET /ui/profile/meta/{identifier}` for the current user) on first collection, exposing `Loading -> Content | Error` with the mapped domain `Profile` (avatar, bio, display name, stats, links).

**FR-2 — Public profile load by identifier.** `PublicProfileViewModel` takes an `identifier` (username or id) from `SavedStateHandle` (route arg from AND-073) and loads the public profile, mapping the distinct outcomes **found**, **not-found (404)**, and **private/forbidden (403)** into discrete UI states.

**FR-3 — Edit profile.** `EditProfileViewModel` seeds an editable form from the current profile, exposes field-level edit events (display name, bio, links), runs synchronous client-side validation, tracks dirty state, and performs save via `PATCH /ui/profile`. It blocks save while invalid or in-flight and surfaces field errors and server-side `detail` errors.

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

Reads `identifier` from `SavedStateHandle` (route arg key `identifier`, defined by AND-073). Distinct phases for `NotFound` and `Private` so the screen renders dedicated empty states.

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

This ticket consumes — it does not define — HTTP contracts; the Retrofit `ProfileApi` and DTOs are owned by AND-070. The endpoints reached transitively are:

- `GET /ui/profile/meta/{identifier}` → public/own profile payload.
- `GET /ui/me` → authenticated identity used to resolve the own-profile identifier.
- `PATCH /ui/profile` → partial update (body `ProfilePatch`).

The mapped domain `Profile` (post-AND-070 mapping) the ViewModels rely on:

```json
{
  "identifier": "jane",
  "user_id": "u_123",
  "display_name": "Jane Doe",
  "bio": "Builder.",
  "avatar_url": "https://.../a.jpg",
  "cover_url": "https://.../c.jpg",
  "links": ["https://jane.dev"],
  "stats": { "followers": 12, "following": 9, "posts": 4 },
  "is_self": true,
  "is_private": false
}
```

`PATCH /ui/profile` request body the edit VM emits:

```json
{ "display_name": "Jane Doe", "bio": "Builder.", "links": ["https://jane.dev"] }
```

Error mapping (handled in repository, surfaced to VM as `AppError.kind`): HTTP 401 → repository performs the single `POST /ui/session/refresh` retry before returning; 403 → `Forbidden` (→ `Private`); 404 → `NotFound`; 422 `detail:[{msg,loc}]` → `Validation(fieldErrors)` keyed by `loc` tail; timeouts (~20s) → `Timeout`. All write requests carry the `X-CSRF-Token` header from the `ui_csrf` cookie; that plumbing belongs to `core-network`, not this ticket.

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
- Private/forbidden profiles (403) must render the dedicated `Private` state with **no** leaked fields — the VM discards any partial body on 403/404 and stores only the phase.
- Outbound `OpenUrl` effects carry user-controlled link strings; the VM validates they are `http(s)` schemes in `validate`/before emit to avoid `intent://`/`javascript:` smuggling; non-http links are rejected with a field/snackbar error.
- `is_self` from the payload gates the presence of `EditClicked` affordance state (`canEdit` flag) so a public VM never exposes edit actions.

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
- **R-2:** Own-identifier resolution — whether own profile is fetched via `/ui/me` then `/ui/profile/meta/{identifier}` or a dedicated own endpoint affects `getOwnProfile`. Confirm against `/openapi.json`. (Q-1)
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

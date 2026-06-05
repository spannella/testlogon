---
id: AND-073
title: "Public profile (`/u/:identifier`)"
milestone: M2
epic: E10
priority: P1
size: M
status: draft
depends_on: [AND-070, AND-022]
blocks: []
---

# AND-073 — Public profile (`/u/:identifier`)

## 1. Overview & Goal

This ticket delivers the **public profile screen** for TestLogon Android: a read-only view of any user's public profile, addressable by an opaque `identifier` (username or stable user id). The screen must be reachable two ways — (a) by in-app navigation from anywhere a user is referenced (avatars, mentions, follower lists), and (b) by an **Android App Link** that maps the web URL `https://<host>/u/:identifier` directly onto the native screen so that tapping a shared profile URL opens the app instead of the browser.

The web reference behaviour is the canonical contract: `/u/:identifier` renders the public-facing subset of a profile (display name, handle, avatar, bio, public stats, and a public activity preview) and gracefully degrades for two terminal states — **not found** (no such identifier) and **private** (the profile exists but the viewer is not permitted to see it). This ticket owns the **screen, the deep-link wiring, and the three UI states** (loaded / not-found / private), plus loading, offline, and error affordances.

It does **not** own the network/DTO layer (that is AND-070, `ProfileApi` + DTOs) nor the NavHost/route plumbing (AND-022). This ticket consumes both. The goal is a production-quality, accessible, deep-linkable public profile screen that is correct against the unreliable dev backend.

Out of scope: editing one's own profile, follow/unfollow actions, blocking/reporting, and the authenticated "own profile" tab. Those are separate E10 tickets; this screen renders the **public** projection only.

## 2. Context & References

- **Module**: new `feature-profile` module under `android/feature/feature-profile/`, namespace `com.testlogon.android.feature.profile`. Layering: `app -> feature-profile -> core-network, core-model, core-ui, core-data, core-testing`.
- **Upstream deps**:
  - **AND-070 — Profile API + DTOs**: provides `ProfileApi`, the `GET /ui/profile/meta/{identifier}` endpoint binding, and the DTO→domain mapping for both own and public payloads. This ticket calls into that API and renders the public domain model.
  - **AND-022 — Navigation host & routes**: provides the single-Activity `NavHost` and typed route registration. This ticket registers its route and deep link into that host.
- **Web reference**: `frontend/src/api/endpoints/profile.ts` (endpoint shapes), `frontend/src/api/types.ts` (shared `PublicProfile` / error types), and the route `/u/:identifier` in the web router. OpenAPI: `GET http://18.222.237.167:8000/openapi.json` (path `/ui/profile/meta/{identifier}`).
- **Stack**: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Coil (avatar), Paging 3 (activity preview, optional), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15. minSdk 24, compileSdk/targetSdk 35.
- **Backend reality**: dev host is **plaintext HTTP**, unreliable. App Links require HTTPS for verification; see §8 for the dev-vs-prod host split.

## 3. Functional Requirements

FR-1 **Route**: The screen is registered as a typed route `ProfileRoute.Public(identifier: String)` rendering at the in-app path `profile/public/{identifier}`.

FR-2 **App Link**: Tapping `https://<verified-host>/u/<identifier>` opens the app directly to this screen with `identifier` extracted from the path. The link must be an **autoVerified** App Link in production. Custom-scheme fallback (`testlogon://u/<identifier>`) is also accepted for share flows.

FR-3 **Load**: On entry, the screen fetches the public profile by `identifier` via `GET /ui/profile/meta/{identifier}` and shows a skeleton/loading state until the result resolves.

FR-4 **Loaded state**: Render display name, `@handle`, avatar (Coil), bio, join date, and public counters (followers/following/posts where present). Null/absent optional fields are omitted, never shown as empty rows.

FR-5 **Not-found state**: HTTP 404 (or backend `detail` indicating no such user) renders a dedicated empty state ("This profile doesn't exist") with a Back action. No retry button (retrying a 404 is pointless).

FR-6 **Private state**: HTTP 403 (or a payload marked private) renders a "This profile is private" state showing only the minimal public stub the backend returns (handle/avatar if provided) and an explanatory message. No activity/bio shown.

FR-7 **Offline/stale**: If the request fails due to connectivity and a cached copy exists (Room cache via AND-070's layer), render the cached profile with a non-blocking "Showing saved copy" banner. If no cache, show an offline error state with **Retry**.

FR-8 **Retry**: Generic/transient errors (timeout, 5xx, network) show an error state with a Retry action that re-issues the GET (idempotent).

FR-9 **Back**: System Back and the top-app-bar up affordance pop the screen; if the screen was the deep-link entry point (empty back stack), Back routes to the app's home/start destination rather than exiting.

FR-10 **Identifier passthrough**: `identifier` is treated as opaque; it is URL-decoded once on extraction and passed verbatim to the API. No client-side normalization or validation beyond non-empty.

## 4. Technical Design

### Module & files

```
feature-profile/
  src/main/kotlin/com/testlogon/android/feature/profile/public/
    PublicProfileScreen.kt
    PublicProfileViewModel.kt
    PublicProfileUiState.kt
    PublicProfileNav.kt
  src/main/AndroidManifest.xml         // intent-filter merged into app manifest
```

### Route registration (consumes AND-022)

```kotlin
// PublicProfileNav.kt
@Serializable
data class PublicProfileRoute(val identifier: String)

fun NavGraphBuilder.publicProfileScreen(onBack: () -> Unit) {
    composable<PublicProfileRoute>(
        deepLinks = listOf(
            navDeepLink<PublicProfileRoute>(
                basePath = "https://${'$'}{BuildConfig.APP_LINK_HOST}/u"
            ),
            navDeepLink<PublicProfileRoute>(basePath = "testlogon://u")
        )
    ) {
        PublicProfileScreen(onBack = onBack)
    }
}

fun NavController.navigateToPublicProfile(identifier: String) =
    navigate(PublicProfileRoute(identifier))
```

The `{identifier}` path segment maps onto the route's `identifier` field via type-safe Navigation-Compose deep linking. `APP_LINK_HOST` is a `BuildConfig` field per build type (§8).

### ViewModel

```kotlin
@HiltViewModel
class PublicProfileViewModel @Inject constructor(
    private val profileRepository: ProfileRepository,   // from AND-070/core-data
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val args = savedStateHandle.toRoute<PublicProfileRoute>()
    val identifier: String = args.identifier

    private val _uiState = MutableStateFlow<PublicProfileUiState>(PublicProfileUiState.Loading)
    val uiState: StateFlow<PublicProfileUiState> = _uiState.asStateFlow()

    init { load() }

    fun load() {
        if (identifier.isBlank()) {
            _uiState.value = PublicProfileUiState.NotFound; return
        }
        viewModelScope.launch {
            _uiState.value = PublicProfileUiState.Loading
            _uiState.value = when (val r = profileRepository.getPublicProfile(identifier)) {
                is ApiResult.Success      -> PublicProfileUiState.Loaded(r.data, stale = false)
                is ApiResult.Stale        -> PublicProfileUiState.Loaded(r.data, stale = true)
                is ApiResult.Error        -> r.toUiState()
            }
        }
    }

    fun retry() = load()
}
```

`ProfileRepository.getPublicProfile(identifier): ApiResult<PublicProfile>` and the `PublicProfile` domain model are owned by **AND-070**; this ticket only consumes them. If AND-070 does not yet expose an `ApiResult.Stale` variant, fall back to mapping a cache hit to `Success(stale=true)` via a repository flag.

### UI state

```kotlin
sealed interface PublicProfileUiState {
    data object Loading : PublicProfileUiState
    data class Loaded(val profile: PublicProfile, val stale: Boolean) : PublicProfileUiState
    data object NotFound : PublicProfileUiState
    data class Private(val stub: PublicProfileStub?) : PublicProfileUiState
    data class Error(val message: String, val retryable: Boolean) : PublicProfileUiState
}
```

### Composable

```kotlin
@Composable
fun PublicProfileScreen(
    onBack: () -> Unit,
    viewModel: PublicProfileViewModel = hiltViewModel(),
)
```

A single `Scaffold` with a `TopAppBar` (title = handle once known, up icon → `onBack`) hosts a `when (state)` dispatch into `LoadingSkeleton`, `LoadedContent`, `NotFoundState`, `PrivateState`, and `ErrorState` composables. `LoadedContent` shows the stale banner when `stale == true`. Avatar loads via Coil `AsyncImage` with a circular placeholder. The activity preview, if rendered, uses Paging 3's `collectAsLazyPagingItems()` but is **optional** for this ticket and may be a follow-up; the public stats row is mandatory.

## 5. API Contract

Single endpoint, owned by AND-070, consumed here.

**Request**
```
GET /ui/profile/meta/{identifier}
Headers: X-CSRF-Token: <ui_csrf cookie>   (sent if a session cookie jar exists; public reads also work unauthenticated)
```
`{identifier}` is the URL-encoded path segment.

**200 — public profile**
```json
{
  "identifier": "ada",
  "display_name": "Ada Lovelace",
  "handle": "ada",
  "avatar_url": "https://cdn.testlogon.dev/a/ada.png",
  "bio": "First programmer.",
  "joined_at": "2025-01-04T12:00:00Z",
  "is_private": false,
  "stats": { "followers": 1280, "following": 73, "posts": 211 }
}
```

**200/403 — private**
```json
{ "identifier": "ada", "handle": "ada", "avatar_url": null, "is_private": true }
```
Treat either a 403 **or** a 200 with `"is_private": true` as the Private state. Map the minimal fields into `PublicProfileStub`.

**404 — not found**
```json
{ "detail": "Profile not found" }
```

**FastAPI `detail` mapping** (string | `[{ "msg": ... }]` | `{ "code", ... }`) is normalized by core-network's error mapper. This screen only needs the resulting human string for the generic Error state; 404 and 403 are classified by status code before message extraction.

Behaviour: GET is **idempotent** → eligible for the bounded backoff retry on transient failures (timeout/5xx) per the network policy; 404/403 are **not** retried.

## 6. Data & State Management

- **Source of truth**: `ProfileRepository` (core-data, AND-070). It performs the network GET, maps DTO→`PublicProfile`, and writes/reads a Room cache keyed by `identifier`. This ticket adds no new persistence.
- **Cache key**: `identifier`. TTL and eviction are AND-070's concern; this ticket relies on `ApiResult.Stale`/cache-hit semantics for FR-7.
- **UI state holder**: `PublicProfileViewModel` exposes `StateFlow<PublicProfileUiState>`, single immutable state. Collected with `collectAsStateWithLifecycle()`.
- **Process death**: `identifier` is recovered from `SavedStateHandle.toRoute()`; the screen re-fetches in `init`. No transient UI fields need saving beyond the route arg.
- **Recomposition**: avatar URL stability ensures Coil does not reload on unrelated recompositions; the `Loaded` data class is value-equal so identical payloads cause no recomposition.

## 7. Error Handling & Resilience

| Condition | Classification | UI |
|---|---|---|
| 404 / `detail` "not found" | terminal | `NotFound`, no retry |
| 403 / `is_private==true` | terminal | `Private(stub)`, no retry |
| Timeout (~20s), 5xx, conn reset | transient | `Error(retryable=true)` with Retry; or `Loaded(stale=true)` if cache hit |
| Offline, no cache | transient | `Error(retryable=true)` |
| Offline, cache present | degraded | `Loaded(stale=true)` + "Showing saved copy" banner |
| Malformed body / parse error | terminal | `Error("Couldn't load profile", retryable=true)` (allow one retry) |

- Honour the **~20s** OkHttp timeout and the **bounded backoff** retry for the idempotent GET (network-layer policy; this screen does not implement its own retry loop beyond the user-driven Retry button).
- On 401, the network layer performs the single `POST /ui/session/refresh` + retry transparently; this screen never handles 401 directly.
- Retry is debounced (ignore taps while `Loading`).

## 8. Security & Privacy

- **App Link host split**: App Links require HTTPS + Digital Asset Links verification. The dev backend (`18.222.237.167:8000`) is plaintext HTTP and **cannot** be an autoVerified App Link host. Define `APP_LINK_HOST` per build type: production verified host for `release`; `debug`/`internal` builds rely on the `testlogon://u/<id>` custom scheme only and set `android:autoVerify="false"`. Cleartext is restricted to the dev API host via the existing network-security-config; the App Link host is always HTTPS.
- Intent-filter (release):
```xml
<intent-filter android:autoVerify="true">
  <action android:name="android.intent.action.VIEW"/>
  <category android:name="android.intent.category.DEFAULT"/>
  <category android:name="android.intent.category.BROWSABLE"/>
  <data android:scheme="https" android:host="@string/app_link_host" android:pathPrefix="/u/"/>
</intent-filter>
```
A matching `/.well-known/assetlinks.json` on the production host is a release-ops prerequisite (tracked in the release/CI ticket, not here).
- **Privacy**: respect `is_private` strictly — never render bio, stats, or activity for a private profile even if a stale cache contains richer data; private state must render from the stub only and the repository must not serve cached private-richer data.
- **No PII logging**: do not log full profile payloads; log only `identifier` (already public in the URL) and status codes.
- Public GET works unauthenticated; the cookie/CSRF header is attached opportunistically when a session exists but is not required.

## 9. Accessibility & i18n

- All strings in `feature-profile/src/main/res/values/strings.xml`; no hardcoded text. Keys: `profile_not_found_title`, `profile_private_title`, `profile_private_body`, `profile_error_retry`, `profile_stale_banner`, `profile_followers`, etc.
- Avatar `AsyncImage` has `contentDescription` = "Avatar of <display name or handle>"; decorative dividers `contentDescription = null`.
- Stats counters use a `pluralResources` `quantityString` (followers/following/posts) and locale-aware number formatting (`NumberFormat.getInstance()`).
- Touch targets (Back, Retry) ≥ 48dp; TalkBack reading order: title → stale banner (if any) → identity → bio → stats. Error/empty states are announced via `liveRegion = Polite`.
- Dynamic type and dark theme via Material 3 tokens from `core-ui`; no fixed font sizes.
- `joined_at` rendered with `DateTimeFormatter` in the device locale/zone.

## 10. Telemetry & Logging

- Events (via core analytics facade): `profile_public_viewed { source: "applink"|"in_app"|"deep_scheme", result: "loaded"|"private"|"not_found"|"error", stale: Boolean }`. `source` is derived from the launching intent (App Link vs in-app navigate).
- `profile_public_retry_tapped { identifier_present: Boolean }`.
- Logging at `DEBUG` only: `tag=PublicProfile`, fields `identifier`, `httpStatus`, `elapsedMs`. No payload bodies, no tokens/cookies. Errors logged at `WARN` with classification (`transient`/`terminal`).

## 11. Testing Strategy

**Unit (core-testing, JUnit + Turbine + coroutines-test)**
- `PublicProfileViewModelTest`:
  - 200 public → `Loaded(stale=false)`.
  - 200 `is_private=true` → `Private(stub)`.
  - 403 → `Private`.
  - 404 → `NotFound`.
  - timeout/5xx → `Error(retryable=true)`.
  - cache hit on network failure → `Loaded(stale=true)`.
  - blank identifier → `NotFound` without a network call (verify repository not invoked).
  - `retry()` re-invokes repository and transitions `Error → Loading → Loaded`.
- Fake `ProfileRepository` returning seeded `ApiResult`s.

**Compose UI (createAndroidComposeRule)**
- Each state renders its hallmark node (private body text, not-found title, retry button present only when `retryable`, stale banner visible iff `stale`).
- Retry button click invokes `viewModel.retry()`.
- contentDescription assertions for avatar and Back.

**Deep-link / instrumentation**
- `adb shell am start -W -a android.intent.action.VIEW -d "https://<host>/u/ada"` opens `PublicProfileScreen` with `identifier == "ada"`.
- `testlogon://u/ada` custom scheme resolves the same route.
- URL-encoded identifier (`/u/a%20b`) decodes to `"a b"`.
- Back from deep-link entry routes to home, not app exit.

**Acceptance mapping**: deep-link test covers "public link opens the profile"; the private/404 unit+UI tests cover "private/missing handled".

## 12. Dependencies & Sequencing

- **Blocked by AND-070** (Profile API + DTOs): must land first — provides `ProfileApi`, `ProfileRepository.getPublicProfile`, `PublicProfile` model, and cache. If AND-070 slips, this screen can be built against a fake repository and the wiring swapped on merge.
- **Blocked by AND-022** (Navigation host & routes): provides the `NavHost` and typed-route + deep-link registration mechanism used in §4.
- **Blocks**: none recorded in backlog. Likely future consumers (follow button, share sheet, own-profile) will navigate via `navigateToPublicProfile`, so keep that function and the route type stable/public API.
- Release/CI must publish `/.well-known/assetlinks.json` for App Link autoVerify; flagged as an external prerequisite for the verified-host behaviour (not a code dependency of this ticket).

## 13. Risks & Open Questions

- **R1 — App Link verification on plaintext dev host**: cannot autoVerify HTTP. Mitigation: per-build `APP_LINK_HOST`, custom scheme for non-release. *Open*: confirm the production HTTPS host and assetlinks publishing owner.
- **R2 — Private vs not-found ambiguity**: backend may return 404 for private profiles to avoid existence leakage. *Open*: confirm whether private profiles return 403+stub or 404. If 404, the Private state is unreachable and we render NotFound (handle both regardless).
- **R3 — Identifier type**: is `:identifier` a handle, a numeric id, or either? Treated as opaque (FR-10); confirm against `profile.ts` so cache keying matches AND-070.
- **R4 — Stale private data**: ensure the repository never serves a richer cached payload for a now-private profile (privacy regression). Covered by §8 but depends on AND-070 cache semantics.
- **R5 — Activity preview scope**: deferred/optional this ticket; confirm whether public activity is in M2 scope or a later E10 ticket.

## 14. Acceptance Criteria

- AC-1 Tapping a verified `https://<host>/u/<identifier>` link (release build) opens the app on `PublicProfileScreen` with the correct `identifier`; `testlogon://u/<identifier>` does the same on all builds. *(Source: "Public link opens the profile.")*
- AC-2 A valid public identifier renders display name, handle, avatar, bio, and stats from `GET /ui/profile/meta/{identifier}`.
- AC-3 A private profile renders the Private state (message + stub only, no bio/stats/activity), whether signalled by 403 or `is_private==true`. *(Source: "private … handled.")*
- AC-4 A missing identifier (404) renders the NotFound state with no Retry button. *(Source: "missing handled.")*
- AC-5 Transient failures render an Error state with a working Retry; a cache hit during failure renders the stale-copy banner.
- AC-6 Back from a deep-link cold start navigates to home, not app exit.
- AC-7 All listed unit, Compose, and deep-link instrumentation tests pass in CI.

## 15. Definition of Done

- `feature-profile` module created/extended with `PublicProfileScreen`, `PublicProfileViewModel`, `PublicProfileUiState`, and route/deep-link registration under `com.testlogon.android.feature.profile.public`.
- Route registered in the AND-022 `NavHost`; `navigateToPublicProfile(identifier)` exposed as stable public API.
- App Link intent-filter merged (autoVerify on release host, custom scheme on all builds); `APP_LINK_HOST` `BuildConfig` field set per build type.
- All five UI states implemented, accessible (TalkBack-verified), and fully externalized strings.
- Unit + Compose + deep-link tests written and green; coverage of all branches in §11.
- Telemetry events emitted with no PII/payload/token logging.
- Code review approved; merged to `android-port`; CI (build + lint + tests) green.
- Open questions R1–R3 resolved or explicitly deferred with owners before release tagging.

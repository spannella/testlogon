---
id: AND-071
title: Own profile screen
milestone: M2
epic: E10
priority: P0
size: M
status: draft
depends_on: [AND-070]
blocks: [AND-072]
---

# AND-071 — Own profile screen

## 1. Overview & Goal

Implement the read-only "own profile" screen: the screen that renders the
currently authenticated user's profile — avatar, display name/handle, bio,
aggregate stats (followers / following / posts and any backend-provided
counters), and the user's external links. The screen is the entry point for
the profile feature surface and the anchor for later editing work (AND-072)
and the public/other-user profile variant (E10 follow-on tickets).

Scope is strictly **view** of the authenticated user's own profile. This
ticket consumes the `ProfileApi` and DTO mapping delivered by AND-070; it does
not add new network endpoints, does not implement editing, and does not
implement the public-profile-by-identifier route beyond reusing shared UI
components where practical.

Goal / success condition (from the backlog acceptance bullet): the
authenticated user's profile renders correctly from live data, with proper
loading, empty, error, and offline/stale states, and is covered by tests.

## 2. Context & References

- Repo `spannella/testlogon`, Android app in `android/` on branch
  `android-port`. Namespace/applicationId base `com.testlogon.android`.
- Module layering: `app -> feature-* -> core-*`. This ticket lands a new
  feature module `feature-profile` (or, if AND-070 already created it, extends
  it) that depends on `core-network`, `core-model`, `core-ui`, `core-data`,
  `core-testing`.
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp
  4.12 / Moshi 1.15, Room 2.6 + DataStore, Coil for images. minSdk 24,
  compile/target 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- AND-070 (Profile API + DTOs) is the authoritative source of the `ProfileApi`
  Retrofit interface, the profile DTOs, and the DTO→domain mapping. This
  ticket treats those as fixed inputs.
- Backend: FastAPI + DynamoDB; dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). Cookie-based session established in M1 auth flow;
  `X-CSRF-Token` echoed from the `ui_csrf` cookie; on 401 a single
  `POST /ui/session/refresh` + retry is performed by the OkHttp auth/refresh
  interceptor delivered earlier (AND-027 / auth foundation). Web reference:
  `frontend/src/api/endpoints/profile.ts`, `frontend/src/api/types.ts`.
- Endpoint relevant to "own profile": `GET /ui/me` for identity and
  `GET /ui/profile/meta/{identifier}` for profile metadata (per AND-070). The
  own-profile case uses the authenticated user's identifier (from
  `/ui/me`) — or, where the backend supports it, the literal `me` sentinel —
  to fetch profile meta.

## 3. Functional Requirements

FR-1. A composable destination `OwnProfileScreen` is reachable from the app
shell (bottom-nav "Profile" tab or equivalent) via a typed
Navigation-Compose route `ProfileRoute.Own`.

FR-2. On entry the screen loads the authenticated user's profile and renders:
- Avatar (Coil, circular, placeholder + error fallback).
- Display name and handle/username.
- Bio (multi-line, link-aware text; URLs in bio are not required to be
  tappable in this ticket but must not break layout).
- Stats row: followers, following, and post count (and any additional
  numeric counters present in the DTO), each formatted compactly
  (e.g. 1.2K, 3.4M) and labeled.
- External links list: each link renders label + URL and opens in the
  browser via an `Intent.ACTION_VIEW` (Custom Tabs not required).

FR-3. Loading state: skeleton/placeholder UI while the first load is in
flight; no blank flash.

FR-4. Error state: a retriable error surface (message + Retry button) when the
load fails and no cached data exists.

FR-5. Offline / stale state: if cached profile data exists (Room, written by
the data layer) it is rendered immediately; a non-blocking "showing cached
data" indicator is shown when the live refresh failed.

FR-6. Pull-to-refresh re-fetches the profile (Material 3 pull-to-refresh).

FR-7. An "Edit profile" affordance (button) is present and navigates to the
edit route owned by AND-072. In this ticket the button is wired to a
navigation callback; the destination may be a stub until AND-072 lands.

FR-8. The screen must render correctly for a profile with missing optional
fields (no bio, no avatar, no links, zero stats).

## 4. Technical Design

New/modified files under `feature-profile`
(`com.testlogon.android.feature.profile`):

```
feature/profile/
  ui/own/OwnProfileScreen.kt
  ui/own/OwnProfileViewModel.kt
  ui/own/OwnProfileUiState.kt
  ui/components/ProfileHeader.kt
  ui/components/ProfileStatsRow.kt
  ui/components/ProfileLinksList.kt
  navigation/ProfileNavigation.kt
  data/ProfileRepository.kt          // if not already from AND-070
```

State holder:

```kotlin
sealed interface OwnProfileUiState {
    data object Loading : OwnProfileUiState
    data class Content(
        val profile: Profile,        // domain model from core-model (AND-070)
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false // true when content came from cache after a failed refresh
    ) : OwnProfileUiState
    data class Error(val message: String, val canRetry: Boolean = true) : OwnProfileUiState
}
```

ViewModel:

```kotlin
@HiltViewModel
class OwnProfileViewModel @Inject constructor(
    private val profileRepository: ProfileRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<OwnProfileUiState>(OwnProfileUiState.Loading)
    val uiState: StateFlow<OwnProfileUiState> = _uiState.asStateFlow()

    init { load(forceRefresh = false) }

    fun onRefresh() = load(forceRefresh = true)
    fun onRetry() = load(forceRefresh = true)

    private fun load(forceRefresh: Boolean) {
        viewModelScope.launch {
            val current = _uiState.value
            if (current is OwnProfileUiState.Content) {
                _uiState.value = current.copy(isRefreshing = true)
            }
            when (val result = profileRepository.getOwnProfile(forceRefresh)) {
                is ApiResult.Success -> _uiState.value =
                    OwnProfileUiState.Content(result.data, isRefreshing = false, isStale = false)
                is ApiResult.Stale -> _uiState.value =
                    OwnProfileUiState.Content(result.data, isRefreshing = false, isStale = true)
                is ApiResult.Failure ->
                    if (current is OwnProfileUiState.Content)
                        _uiState.value = current.copy(isRefreshing = false, isStale = true)
                    else
                        _uiState.value = OwnProfileUiState.Error(result.error.toUserMessage())
            }
        }
    }
}
```

Repository surface (extends the AND-070 repository; `getOwnProfile` resolves
the current user's identifier via `/ui/me`, then loads profile meta, and
caches the merged result):

```kotlin
interface ProfileRepository {
    suspend fun getOwnProfile(forceRefresh: Boolean): ApiResult<Profile>
    fun observeOwnProfile(): Flow<Profile?>            // Room-backed, optional
}
```

Composable entry point:

```kotlin
@Composable
fun OwnProfileScreen(
    onEditProfile: () -> Unit,
    onOpenLink: (url: String) -> Unit,
    viewModel: OwnProfileViewModel = hiltViewModel(),
)
```

Navigation registration:

```kotlin
fun NavGraphBuilder.profileGraph(navController: NavController) {
    composable<ProfileRoute.Own> {
        OwnProfileScreen(
            onEditProfile = { navController.navigate(ProfileRoute.Edit) }, // AND-072
            onOpenLink = { url -> /* ACTION_VIEW intent */ },
        )
    }
}
```

Image loading uses Coil `AsyncImage` with a circular placeholder and a
neutral fallback for null/blank avatar URLs. Stat formatting lives in a
`core-ui` util `compactCount(n: Long): String`.

## 5. API Contract

This ticket adds no new endpoints; it consumes endpoints defined by AND-070 /
auth foundation.

1) Identity — `GET /ui/me` (cookie-authenticated):

```json
{
  "id": "usr_123",
  "username": "spannella",
  "display_name": "Sean P.",
  "is_authenticated": true
}
```

2) Profile meta — `GET /ui/profile/meta/{identifier}` where `{identifier}` is
the authenticated user's id/username (or `me` if supported):

```json
{
  "id": "usr_123",
  "username": "spannella",
  "display_name": "Sean P.",
  "avatar_url": "https://.../avatar.jpg",
  "bio": "Builder. Coffee.",
  "links": [
    { "label": "Website", "url": "https://example.com" }
  ],
  "stats": {
    "followers": 1234,
    "following": 56,
    "posts": 89
  }
}
```

Both requests carry session cookies and `X-CSRF-Token` (from `ui_csrf`).
GETs are idempotent: subject to ~20s timeout and bounded backoff retry, plus
the single-shot 401 → `POST /ui/session/refresh` → retry handled by the
shared interceptor.

Error body follows the FastAPI `detail` convention and is mapped centrally
(string | `[{msg}]` | `{code,...}`) by the AND-070/core-network error mapper;
this screen only renders the resulting user-facing message.

## 6. Data & State Management

- Single source of truth is `OwnProfileViewModel.uiState: StateFlow<OwnProfileUiState>`,
  collected with `collectAsStateWithLifecycle()`.
- Domain `Profile` model and DTO mapping are owned by AND-070 (`core-model`).
- Caching: the repository persists the fetched profile in Room
  (`profile` table keyed by user id) so re-entry and offline both render
  instantly. `forceRefresh = false` serves cache-then-network; `true`
  (pull-to-refresh / retry) hits network and updates cache.
- `ApiResult<T>` is the typed result wrapper (`Success` / `Stale` / `Failure`);
  `Stale` carries cached data when the network refresh failed but cache exists.
- No DataStore writes here (DataStore holds prefs/session only).
- Process-death survival: state is reconstructed by re-running `init` load,
  which reads cache first; no `SavedStateHandle` payload is required because
  the own-profile route takes no arguments.

## 7. Error Handling & Resilience

- First-load failure with no cache → `OwnProfileUiState.Error` with Retry.
- Refresh failure with existing content → keep content, set `isStale = true`,
  show a dismissible inline banner ("Couldn't refresh — showing saved data").
- Timeouts: rely on the OkHttp client's ~20s call timeout; treat
  `SocketTimeoutException` / `IOException` as a transient failure mapped to a
  generic retriable message.
- Retry/backoff for the two GETs is provided by the shared network layer
  (idempotent GETs only); the ViewModel does not implement its own retry loop
  beyond user-triggered retry.
- 401 handling (refresh-once-then-retry) is owned by the auth interceptor; if
  refresh ultimately fails, the mapped error surfaces as a normal failure and
  the app shell handles re-auth/navigation to login (out of scope here).
- Empty/missing fields are rendered as graceful empties, never as crashes
  (null-safe rendering, empty links list → links section hidden).

## 8. Security & Privacy

- All requests are cookie-based and ride the persistent cookie jar + CSRF
  header established in M1; this screen sets no auth state of its own.
- No credentials, tokens, or PII are logged. Avatar/link URLs may be logged
  only at DEBUG and only in non-release builds.
- External links open via `Intent.ACTION_VIEW`; URLs are validated to be
  `http`/`https` before launching to avoid intent redirection to arbitrary
  schemes.
- Dev backend is plaintext HTTP; cleartext is permitted only for the dev host
  via the existing network-security-config (M1). No new cleartext exemptions
  are added here.
- Cached profile data is stored in app-private Room storage; no export.

## 9. Accessibility & i18n

- Avatar `AsyncImage` has a `contentDescription` ("Your profile photo");
  decorative dividers use `null` description.
- Stats row exposes a combined semantics string per stat
  (e.g. "1,234 followers") so screen readers announce value + label together;
  raw compacted glyphs (1.2K) are paired with full-number contentDescription.
- Touch targets (Edit button, link rows, retry) are ≥ 48dp.
- All strings live in `feature-profile` `strings.xml`; counts use
  locale-aware formatting (`NumberFormat`/compact). No hardcoded user-facing
  strings in Kotlin.
- Supports dynamic type / font scaling and dark theme via Material 3 theming
  from `core-ui`.

## 10. Telemetry & Logging

- Emit analytics events via the shared analytics interface (core layer):
  `profile_own_viewed`, `profile_own_refresh` (with `trigger=pull|retry`),
  `profile_link_opened` (with link index, not URL), and `profile_load_error`
  (with mapped error category, no PII).
- Logging uses the project logger at INFO for load lifecycle and WARN/ERROR
  for failures; never log response bodies or cookies.
- A single timing log/metric for own-profile load latency (start→first
  content) to monitor the unreliable dev backend.

## 11. Testing Strategy

Unit (JVM, `core-testing` + Turbine + coroutines-test):
- `OwnProfileViewModel` emits `Loading → Content` on success.
- Emits `Loading → Error` on first-load failure with no cache.
- On refresh failure with prior content, retains content and sets `isStale`.
- `onRetry` re-issues the load and transitions out of `Error` on success.
- Fake `ProfileRepository` returning `Success` / `Stale` / `Failure`.

Repository:
- `getOwnProfile` resolves `/ui/me` then `/ui/profile/meta/{id}`, maps DTOs,
  and writes cache (using MockWebServer or the AND-070 fakes).
- Cache-then-network: returns cached `Stale` when network fails but cache
  present.

Compose UI tests (`createAndroidComposeRule`):
- Content state renders name, handle, bio, stats labels, and link rows.
- Loading state shows skeleton; Error state shows Retry and invokes callback.
- Missing optional fields (no bio/avatar/links) render without crashing and
  hide empty sections.
- Edit button invokes `onEditProfile`; link row invokes `onOpenLink` with the
  expected URL.

Acceptance test: with a stubbed authenticated session, the screen renders the
authenticated user's profile (satisfies the backlog acceptance bullet).

## 12. Dependencies & Sequencing

- **Depends on AND-070** (Profile API + DTOs): provides `ProfileApi`, DTOs,
  domain `Profile`, mapping, and the base repository. This ticket cannot start
  rendering real data until AND-070's mapping is available, but UI shell and
  ViewModel state machine can be built in parallel against the domain model
  and a fake repository.
- Depends transitively on the M1 auth foundation (cookie jar, CSRF,
  refresh-on-401 interceptor; AND-027) and the app shell navigation host.
- **Blocks AND-072** (Edit profile basics): provides the screen and the
  "Edit profile" navigation hook and the read surface that edits must reflect
  on reload.
- Provides reusable `ProfileHeader` / `ProfileStatsRow` / `ProfileLinksList`
  components for the public-profile variant later in E10.

## 13. Risks & Open Questions

- R1: Whether the backend accepts a literal `me` identifier for
  `/ui/profile/meta/{identifier}` or requires the resolved id/username from
  `/ui/me`. Mitigation: resolve via `/ui/me` first (one extra GET); revisit if
  `me` is confirmed.
- R2: Exact DTO shape of `stats` and `links` is owned by AND-070; if field
  names differ from the assumptions in §5, only mapping (AND-070) changes —
  this screen consumes the domain model. Open: confirm against
  `frontend/src/api/types.ts`.
- R3: Dev host unreliability may make manual QA flaky; mitigate with cache +
  stale state and MockWebServer-based tests.
- R4: Whether stats should be tappable (followers/following lists). Assumed
  **non-tappable** in this ticket; list screens are separate E10 tickets.
- R5: Bio link auto-linking deferred (not in scope); confirm not required for
  P0.

## 14. Acceptance Criteria

AC-1. Navigating to the Profile tab renders the authenticated user's profile
(avatar, display name/handle, bio, stats, links) from live data — the backlog
acceptance condition.
AC-2. First load shows a loading/skeleton state, then content; no blank flash.
AC-3. Load failure with no cache shows a retriable error; Retry recovers on a
successful subsequent fetch.
AC-4. With cached data present, a failed refresh keeps showing content and
indicates stale data.
AC-5. Pull-to-refresh re-fetches and updates the displayed profile.
AC-6. A profile with missing optional fields renders without crashing and
hides empty sections.
AC-7. The "Edit profile" affordance invokes the navigation callback to the
AND-072 route.
AC-8. Tapping a link opens it in the browser via `ACTION_VIEW` (http/https
validated).
AC-9. Unit + Compose UI tests above pass in CI.

## 15. Definition of Done

- `feature-profile` own-profile screen, ViewModel, state, and reusable
  components implemented per §4 under `com.testlogon.android.feature.profile`.
- Wired into the app-shell navigation (Profile tab) with the Edit hook to
  AND-072 (stub destination acceptable until AND-072 lands).
- All §14 acceptance criteria met.
- Unit, repository, and Compose UI tests from §11 added and green in CI;
  no decrease in module coverage gate.
- No new lint/detekt warnings; strings externalized; accessibility semantics
  in place per §9.
- No PII/credentials in logs; cleartext config unchanged.
- Code reviewed and merged to `android-port`.

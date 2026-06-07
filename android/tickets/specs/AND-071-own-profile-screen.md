---
id: AND-071
title: Own profile screen
milestone: M2
epic: E10
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- Endpoint relevant to "own profile" (**CORRECTED** — verified against the
  frontend `src/api/endpoints/profile.ts: getProfile` and the OpenAPI index):
  the authenticated user's own profile is fetched with a single
  `GET /ui/profile` (no identifier path segment), which returns a
  **wrapped** body `{ "profile": Profile }`. There is **no** `/ui/me` +
  `meta/{identifier}` two-call dance: `GET /ui/me` returns only
  `{ user_sub, session_id, ip }` (schema `MeResp`, no profile data), and
  `GET /ui/profile/meta/{identifier}` is the SEO **meta-tags** endpoint
  (op `profile_meta_tags_…`), not a profile-data source. Cross-user / public
  reads use `GET /ui/profiles/{identifier}` (`CrossUserProfileResp`) and
  `GET /ui/profile/public/{identifier}` (`PublicProfileData`) — those are E10
  follow-on tickets, not this one.

## 3. Functional Requirements

FR-1. A composable destination `OwnProfileScreen` is reachable from the app
shell (bottom-nav "Profile" tab or equivalent) via a typed
Navigation-Compose route `ProfileRoute.Own`.

FR-2. On entry the screen loads the authenticated user's profile and renders
the fields that actually exist on the `Profile` DTO (**CORRECTED** against
`src/api/types.ts: Profile`):
- Avatar (Coil, circular, placeholder + error fallback) sourced from
  `profile_photo_url` (the DTO field is **`profile_photo_url`**, not
  `avatar_url`). The DTO also carries `cover_photo_url`, which MAY be rendered
  as a banner.
- Display name (`display_name`) and, where present, `title` and `location`.
  Note: the own-profile `Profile` DTO has **no `username`/handle field**; the
  account handle/username is not part of `GET /ui/profile`. Render the handle
  only if AND-070's domain model sources it elsewhere (e.g. from `MeResp`/
  account data); otherwise omit it. (See §13 R6.)
- Bio (multi-line). **The field is `description`, not `bio`.** URLs in the bio
  are not required to be tappable in this ticket but must not break layout.
- Stats row (followers, following, post count): **CORRECTED — these counters
  are NOT on the own-profile `Profile` DTO.** `follower_count`,
  `following_count` and `post_count` exist only on `PublicProfileData`
  (`GET /ui/profile/public/{identifier}`). For the own-profile screen, either
  (a) omit the stats row for this ticket, or (b) source counts from a separate
  call that AND-070 must expose. Treated as an **open assumption** (§16); do
  not claim the counts come from `GET /ui/profile`.
- External links list: **CORRECTED — the `Profile` DTO has no `links` array.**
  The closest fields are `displayed_email`, `displayed_telephone_number`, and
  `languages`. If a true links list is required it must be added by AND-070/
  backend first; for this ticket render the displayed contact fields, and open
  any URL-shaped value in the browser via `Intent.ACTION_VIEW` (Custom Tabs
  not required). Tappable links are an **open assumption** (§16).

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

Repository surface (extends the AND-070 repository; `getOwnProfile` issues a
single `GET /ui/profile`, unwraps the `{ profile: … }` envelope, maps the DTO
to the domain `Profile`, and caches it — **CORRECTED**: no `/ui/me` lookup or
`meta/{identifier}` second call is involved):

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
auth foundation. **This section was rewritten in review — the prior two-call
`/ui/me` + `/ui/profile/meta/{identifier}` contract was incorrect.**

1) Own profile — `GET /ui/profile` (single call, cookie-authenticated). This
is exactly what the web client uses (`src/api/endpoints/profile.ts:
getProfile → api.get<{ profile: Profile }>("/ui/profile")`). The response body
is **wrapped** in a `profile` key, and the `Profile` shape
(`src/api/types.ts: Profile`) is:

```json
{
  "profile": {
    "display_name": "Sean P.",
    "first_name": "Sean",
    "last_name": "P.",
    "title": "Builder",
    "description": "Builder. Coffee.",
    "location": "Columbus, OH",
    "birthday": "1990-01-01",
    "gender": "…",
    "displayed_email": "spannella@example.com",
    "displayed_telephone_number": "+1…",
    "mailing_address": { },
    "languages": [ ],
    "profile_photo_url": "https://.../avatar.jpg",
    "cover_photo_url": "https://.../cover.jpg"
  }
}
```

All `Profile` fields are optional. There is **no** `username`, `bio`,
`avatar_url`, `links`, or `stats` key — see the field-name corrections in §2
FR-2 and §16. The DTO→domain mapping that flattens this wrapper and renames
fields is owned by AND-070.

2) `GET /ui/me` is **not** used for profile rendering. Its schema is `MeResp`
= `{ user_sub, session_id, ip }` (`src/api/types.ts: MeResp`) — identity/
session diagnostics only, no display data. `GET /ui/profile/meta/{identifier}`
is the SEO **meta-tags** endpoint (op `profile_meta_tags_…`), not a profile-
data source, and is not called here.

3) Stats / public counters: if the design requires follower/following/post
counts, they come from `PublicProfileData` via
`GET /ui/profile/public/{identifier}` (`src/api/endpoints/profile.ts:
getPublicProfile`), which is a separate (E10) concern. They are **not**
available from `GET /ui/profile`.

Transport: requests are cookie-authenticated (`credentials: "include"`) and
carry `X-CSRF-Token` copied from the `ui_csrf` cookie on **every** request,
including GETs (the web client is not method-gated — `src/api/client.ts` sets
the header unconditionally when the cookie is present). GET is idempotent:
subject to the client call timeout and bounded backoff retry, plus the
single-shot 401 → `POST /ui/session/refresh` → retry. Verified in
`src/api/client.ts`: on 401, if the user is authenticated, a single shared
`refreshSession()` (`POST /ui/session/refresh`, schema `StatusResp`) runs and
the original request is retried exactly once; a second 401 logs the user out.

Error body follows the FastAPI `detail` convention and is normalized centrally
(`normalizeErrorDetail` handles string | `[{msg}]` | `{code,...}`; `422` uses
schema `HTTPValidationError`). 403 may carry a structured
`{ code: "geo_blocked", message }`; 429 (seen on the cross-user lookup path)
carries `Retry-After` and/or `detail.retry_after_seconds`. This screen only
renders the resulting user-facing message.

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
- `getOwnProfile` issues `GET /ui/profile`, unwraps the `{ profile: … }`
  envelope, maps the DTO, and writes cache (using MockWebServer or the AND-070
  fakes). (**CORRECTED**: single call, not `/ui/me` + `meta/{id}`.)
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

- R1: **RESOLVED in review.** The own profile is a single `GET /ui/profile`
  call returning `{ profile: Profile }`; no identifier and no `me` sentinel are
  involved. The earlier `/ui/me` + `meta/{identifier}` concern is moot (and was
  factually wrong — `meta/{identifier}` is the SEO meta-tags endpoint).
- R2: **PARTIALLY RESOLVED.** The `Profile` DTO (`src/api/types.ts: Profile`)
  has **no** `stats` or `links` fields. Stats live on `PublicProfileData`
  (`GET /ui/profile/public/{identifier}`); there is no links array anywhere on
  `Profile`. Open: whether this ticket must show counts at all and, if so,
  which call AND-070 will expose for the *own* user (public endpoint takes an
  identifier). See §16 Open assumptions.
- R6: The own-profile `Profile` DTO carries no `username`/handle. If the UI
  must show a handle, AND-070 must source it (e.g. from account data), since
  `MeResp` exposes only `user_sub`/`session_id`/`ip`. Open assumption.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Own profile is fetched via `GET /ui/profile` returning `{ profile: Profile }`.**
   VERDICT: Corrected (spec previously said `GET /ui/me` + `GET /ui/profile/meta/{identifier}`).
   SOURCE: `src/api/endpoints/profile.ts: getProfile` (`api.get<{ profile: Profile }>("/ui/profile")`); OpenAPI `GET /ui/profile` (op `ui_get_profile_ui_profile_get`).
2. **`GET /ui/profile/meta/{identifier}` is the SEO meta-tags endpoint, not profile data.**
   VERDICT: Corrected.
   SOURCE: OpenAPI `GET /ui/profile/meta/{identifier}` (op `profile_meta_tags_ui_profile_meta__identifier__get`, params=`identifier` only, no auth params).
3. **`GET /ui/me` returns `{ user_sub, session_id, ip }` (schema `MeResp`), not `{ id, username, display_name, is_authenticated }`, and is not used for profile rendering.**
   VERDICT: Corrected.
   SOURCE: `src/api/types.ts: MeResp`; `src/api/endpoints/auth.ts: getMe` (`api.get<MeResp>("/ui/me")`); OpenAPI `GET /ui/me`.
4. **The `Profile` DTO fields are `display_name, first_name, middle_name, last_name, title, description, birthday, gender, location, displayed_email, displayed_telephone_number, mailing_address, languages, profile_photo_url, cover_photo_url` (all optional).**
   VERDICT: Corrected (spec used `avatar_url`, `bio`, `links`, `stats`).
   SOURCE: `src/api/types.ts: Profile`.
5. **Bio is the `description` field; avatar is `profile_photo_url`.**
   VERDICT: Corrected.
   SOURCE: `src/api/types.ts: Profile`.
6. **Follower/following/post counts are NOT on the own-profile `Profile`; they live on `PublicProfileData` (`follower_count`, `following_count`, `post_count`) via `GET /ui/profile/public/{identifier}`.**
   VERDICT: Corrected.
   SOURCE: `src/api/types.ts: PublicProfileData`; `src/api/endpoints/profile.ts: getPublicProfile`; OpenAPI `GET /ui/profile/public/{identifier}`.
7. **There is no `links` array on any profile DTO; closest fields are `displayed_email`, `displayed_telephone_number`, `languages`.**
   VERDICT: Corrected.
   SOURCE: `src/api/types.ts: Profile` (no `links` member anywhere in the file).
8. **The own-profile `Profile` has no `username`/handle field.**
   VERDICT: Corrected.
   SOURCE: `src/api/types.ts: Profile`.
9. **`X-CSRF-Token` is copied from the `ui_csrf` cookie and sent on every request, including GETs (not method-gated).**
   VERDICT: Verified.
   SOURCE: `src/api/client.ts` (lines ~168-171: `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)` set unconditionally before the fetch).
10. **Cookie-based auth: requests use `credentials: "include"`.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (fetch with `credentials: "include"`).
11. **On 401 (when authenticated) a single shared `POST /ui/session/refresh` runs, then the original request is retried once; a second 401 logs out.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (lines ~194-237, `refreshPromise`/`refreshSession`); `src/api/endpoints/auth.ts: refreshSession` (`api.post<StatusResp>("/ui/session/refresh")`); OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_…`, resp 200).
12. **Error body uses FastAPI `detail` convention; normalized centrally; 422 uses `HTTPValidationError`; 403 may be `{code:"geo_blocked", message}`; 429 carries `Retry-After`/`detail.retry_after_seconds`.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`normalizeErrorDetail`, 403 geo_blocked branch ~245-249); `src/api/endpoints/profile.ts` (429 `retry-after` / `retry_after_seconds` handling); OpenAPI 422 → `HTTPValidationError`.
13. **External links open via `Intent.ACTION_VIEW` with http/https validation; Custom Tabs not required.**
    VERDICT: Unverified-assumption (Android client design choice; no backend/web contract governs it). framework ref: https://developer.android.com/training/basics/intents/sending
14. **Coil `AsyncImage` for circular avatar with placeholder/fallback; Material 3 pull-to-refresh; `collectAsStateWithLifecycle`; Hilt `hiltViewModel()`.**
    VERDICT: Unverified-assumption (Android framework/library choices, consistent with stack in §2). framework ref: https://developer.android.com/develop/ui/compose/state and https://coil-kt.github.io/coil/compose/
15. **`Profile` fields are all optional, so missing-field rendering must be null-safe.**
    VERDICT: Verified.
    SOURCE: `src/api/types.ts: Profile` (every member declared with `?`).

### Corrections made

- §2: Replaced the `GET /ui/me` + `GET /ui/profile/meta/{identifier}` endpoint
  claim with the verified single `GET /ui/profile` (wrapped `{ profile }`);
  clarified `meta/{identifier}` is SEO meta-tags and `/ui/me` returns `MeResp`.
- §2 FR-2 / §5 / §13: Corrected DTO field names — `avatar_url`→`profile_photo_url`,
  `bio`→`description`; removed the non-existent `links` array and `stats` object;
  noted counts live only on `PublicProfileData`; noted there is no `username`/handle.
- §5: Rewrote the API Contract with the real wrapped `Profile` body, real
  `MeResp` shape, verified CSRF-on-all-requests transport, verified 401
  refresh-once-retry, and real error shapes (422/403 geo_blocked/429).
- §4: Corrected repository description (single `GET /ui/profile`, unwrap envelope).
- §11: Corrected the repository test description to the single-call flow.
- §13: Resolved R1, partially resolved R2, added R6 (no handle field).

### Open assumptions

- Whether the own-profile screen must display follower/following/post **counts**
  at all, and if so which endpoint supplies them for the *own* user — the public
  counts endpoint (`GET /ui/profile/public/{identifier}`) takes an identifier and
  is an E10 concern; `GET /ui/profile` provides none. AND-070 must clarify. (Why
  unverifiable: no own-user counts source exists in the current contract.)
- Whether a tappable external-**links** feature is in scope — no `links` field
  exists on any profile DTO; would require a backend/AND-070 addition. (Why:
  feature has no backend contract.)
- Whether a `username`/handle should be shown and from where (not on `Profile`;
  `MeResp` lacks it). (Why: no contract field.)
- All Android client framework choices (Coil, Material 3 pull-to-refresh,
  Intent.ACTION_VIEW, Hilt, lifecycle-aware collection) — client-side, not
  governed by the backend/web contract; cited as framework refs above.

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device);
EMU = headless emulator AVD `test35` (x86_64, API 35) in CI;
DEV = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) on the build
host. The own-profile screen has no camera/biometrics/FCM/WebRTC/Telecom needs,
so most cases run on JVM or EMU; a small e2e/ABI confidence pass uses DEV.

- **TC-AND-071-01** — Happy path: own profile renders from live data.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer returns 200 for `GET /ui/profile` with a full
  `{ "profile": { display_name, description, profile_photo_url, location, … } }`.
  Steps: Repository `getOwnProfile(false)` → ViewModel collected via Turbine.
  Expected: request path is `/ui/profile` (single call, no `/ui/me`, no
  `meta/{identifier}`); envelope unwrapped; emits `Loading → Content`; mapped
  domain fields match (`description`→bio text, `profile_photo_url`→avatar).
  Traces: AC-1, AC-2.
- **TC-AND-071-02** — Compose Content render.
  Type: Compose-UI. Target: EMU.
  Preconditions: ViewModel seeded with `Content` (full profile).
  Steps: set content; assert nodes.
  Expected: display name, description/bio text, location, and any contact rows
  render; avatar slot present. No blank flash. Traces: AC-1.
- **TC-AND-071-03** — Loading skeleton then content; no blank flash.
  Type: Compose-UI. Target: EMU.
  Preconditions: repository delayed success.
  Steps: launch screen; assert skeleton present; advance; assert content.
  Expected: skeleton visible during load, replaced by content, never an empty
  frame. Traces: AC-2.
- **TC-AND-071-04** — First-load failure with no cache → retriable error; Retry recovers.
  Type: unit + contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer 500 (or `IOException`) and empty Room cache;
  then a queued 200 for the retry.
  Steps: load; assert `Error(canRetry=true)`; call `onRetry()` with next 200.
  Expected: `Loading → Error`, then `Loading → Content` after retry. Traces: AC-3.
- **TC-AND-071-05** — Error surface UI invokes retry callback.
  Type: Compose-UI. Target: EMU.
  Preconditions: ViewModel in `Error`.
  Steps: assert message + Retry (≥48dp); click Retry.
  Expected: retry handler invoked; touch target ≥48dp. Traces: AC-3, AC-9.
- **TC-AND-071-06** — Stale: refresh fails with existing content → keep content + stale flag.
  Type: unit (Turbine). Target: JVM.
  Preconditions: prior `Content`; repository returns `Failure`/`Stale` with
  cached data on refresh.
  Steps: `onRefresh()`.
  Expected: content retained, `isStale=true`, `isRefreshing=false`; inline
  "showing saved data" banner state set. Traces: AC-4.
- **TC-AND-071-07** — Flaky dev-host / offline: cache-then-network serves cached data.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: Room has a cached profile; MockWebServer simulates timeout/
  connection drop (mimicking `http://18.222.237.167:8000` flakiness).
  Steps: `getOwnProfile(false)`.
  Expected: cached `Profile` returned as `Stale`; no crash; mapped transient
  error not surfaced as fatal. Traces: AC-4.
- **TC-AND-071-08** — Pull-to-refresh re-fetches and updates.
  Type: Compose-UI. Target: EMU.
  Preconditions: `Content` shown; repository returns updated profile on refresh.
  Steps: trigger Material 3 pull-to-refresh.
  Expected: refresh issued (`forceRefresh=true`), indicator shows, content
  updates to new values. Traces: AC-5.
- **TC-AND-071-09** — Missing optional fields render without crash; empty sections hidden.
  Type: Compose-UI. Target: EMU.
  Preconditions: `Content` with `Profile {}` (no description, no
  profile_photo_url, no contact fields).
  Steps: render.
  Expected: avatar shows neutral fallback; bio/contact/links sections hidden;
  no crash (all fields are nullable per `types.ts: Profile`). Traces: AC-6.
- **TC-AND-071-10** — Edit affordance invokes navigation callback.
  Type: Compose-UI. Target: EMU.
  Preconditions: `Content`.
  Steps: click "Edit profile".
  Expected: `onEditProfile` invoked once (route to AND-072). Traces: AC-7.
- **TC-AND-071-11** — Link/contact open: only http/https launched via ACTION_VIEW; non-http schemes blocked.
  Type: unit (URL-validation) + instrumented. Target: EMU (validation logic);
  DEV for real `ACTION_VIEW` resolution against an installed browser.
  Preconditions: a displayed value `https://example.com` and a malicious
  `javascript:alert(1)` / `intent://` value.
  Steps: invoke open handler for each.
  Expected: https value triggers `Intent.ACTION_VIEW`; non-http(s) schemes are
  rejected (no intent fired). Traces: AC-8.
- **TC-AND-071-12** — Auth/CSRF + 401 refresh-once behavior on `GET /ui/profile`.
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer returns 401 once, expects a
  `POST /ui/session/refresh`, then 200 on the retried `GET /ui/profile`.
  Steps: authenticated `getOwnProfile`.
  Expected: outgoing requests carry `X-CSRF-Token` (from `ui_csrf`) and session
  cookies on the GET; exactly one refresh + one retry; final `Content`. A
  second consecutive 401 surfaces as failure (logout handled by shell).
  Traces: AC-1, AC-3.
- **TC-AND-071-13** — Accessibility semantics.
  Type: Compose-UI (semantics) + manual TalkBack. Target: EMU (assertions);
  DEV for manual TalkBack sweep.
  Preconditions: `Content` with avatar and contact rows.
  Steps: assert avatar `contentDescription` ("Your profile photo"); decorative
  dividers null; touch targets ≥48dp; verify TalkBack announces field + label.
  Expected: semantics present; dynamic-type/dark-theme render intact.
  Traces: AC-6, AC-9.
- **TC-AND-071-14** — End-to-end + ABI/API confidence on physical hardware.
  Type: instrumented/e2e. Target: DEV (MUST run on physical device — arm64-v8a,
  API 34 vs the emulator's x86_64/API 35).
  Preconditions: app built for arm64-v8a, stubbed authenticated session, stable
  test backend or MockWebServer on the host reachable via adb reverse.
  Steps: cold-launch app → Profile tab → observe load → pull-to-refresh → tap a
  link → tap Edit.
  Expected: full flow works on real hardware/ABI; no arm64-specific or
  API-34-specific regressions (Coil decode, Compose pull-to-refresh, ACTION_VIEW
  resolution). Traces: AC-1, AC-5, AC-7, AC-8.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (renders authed profile from live data) | TC-01, TC-02, TC-12, TC-14 |
| AC-2 (loading→content, no blank flash) | TC-01, TC-03 |
| AC-3 (error+Retry recovers) | TC-04, TC-05, TC-12 |
| AC-4 (stale: keep content on failed refresh) | TC-06, TC-07 |
| AC-5 (pull-to-refresh updates) | TC-08, TC-14 |
| AC-6 (missing fields, no crash, hide empties) | TC-09, TC-13 |
| AC-7 (Edit affordance → callback) | TC-10, TC-14 |
| AC-8 (link opens via ACTION_VIEW, http/https) | TC-11, TC-14 |
| AC-9 (unit + Compose UI tests pass in CI) | TC-04, TC-05, TC-13 (and all JVM/EMU cases run in CI) |

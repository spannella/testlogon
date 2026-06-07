---
id: AND-073
title: "Public profile (`/u/:identifier`)"
milestone: M2
epic: E10
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  - **AND-070 — Profile API + DTOs**: provides `ProfileApi`, the `GET /ui/profile/public/{identifier}` endpoint binding (CORRECTED — see §16; the earlier `/ui/profile/meta/{identifier}` is the SEO meta-tags endpoint, not the profile-data read), and the DTO→domain mapping for both own and public payloads. This ticket calls into that API and renders the public domain model.
  - **AND-022 — Navigation host & routes**: provides the single-Activity `NavHost` and typed route registration. This ticket registers its route and deep link into that host.
- **Web reference**: `src/api/endpoints/profile.ts` (`getPublicProfile` / `getProfileByIdentifier`), `src/api/types.ts` (`PublicProfileData` and `CrossUserProfileResp` — note there is NO `PublicProfile` type in the web sources; see §16), `src/pages/profile/PublicUserProfilePage.tsx` (the `/u/:identifier` screen), and `src/api/client.ts` (auth/CSRF/transport). OpenAPI: `GET http://18.222.237.167:8000/openapi.json` (paths `/ui/profile/public/{identifier}`, `/ui/profiles/{identifier}`, `/ui/profile/public/{identifier}/posts`).
- **Stack**: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Coil (avatar), Paging 3 (activity preview, optional), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15. minSdk 24, compileSdk/targetSdk 35.
- **Backend reality**: dev host is **plaintext HTTP**, unreliable. App Links require HTTPS for verification; see §8 for the dev-vs-prod host split.

## 3. Functional Requirements

FR-1 **Route**: The screen is registered as a typed route `ProfileRoute.Public(identifier: String)` rendering at the in-app path `profile/public/{identifier}`.

FR-2 **App Link**: Tapping `https://<verified-host>/u/<identifier>` opens the app directly to this screen with `identifier` extracted from the path. The link must be an **autoVerified** App Link in production. Custom-scheme fallback (`testlogon://u/<identifier>`) is also accepted for share flows.

FR-3 **Load**: On entry, the screen fetches the public profile by `identifier` via `GET /ui/profile/public/{identifier}` (CORRECTED from `/ui/profile/meta/{identifier}`) and shows a skeleton/loading state until the result resolves. The endpoint binding is owned by AND-070.

FR-4 **Loaded state**: Render `display_name` (falling back to `identifier` when blank, per web), `title`, `description`, `location`, avatar (Coil, from `profile_photo_url`; optional `cover_photo_url`), join date (from `created_at`, a **unix epoch seconds** integer — CORRECTED, not an ISO string), and public counters `follower_count`/`following_count`/`post_count`. Null/absent optional fields are omitted, never shown as empty rows. NOTE (CORRECTED): the public DTO has no `handle`, `bio`, `avatar_url`, `joined_at`, or nested `stats{}` object; those names in earlier drafts do not exist in `PublicProfileData` — see §16 for the verified field list.

FR-5 **Not-found state**: HTTP 404 (the backend returns 404 for both genuinely-missing AND suppressed/private profiles — the web `ProfileLookupError` code is `not_found_or_suppressed`) renders a dedicated empty state ("This profile doesn't exist") with a Back action. No retry button (retrying a 404 is pointless).

FR-6 **Private/suppressed state**: There is NO separate "private" signal in the public API (CORRECTED — see §16: `PublicProfileData` has no `is_private` field and the endpoint does not return 403 for private profiles; the web app folds private/suppressed into 404). Treat privacy as a subset of Not-found. The dedicated `Private` UI state is therefore an **Android-only product choice** and currently UNREACHABLE from the verified backend contract; either drop it and route private→NotFound, or keep it behind a defensive `is_private==true`/403 branch flagged as an unverified assumption (R2). The fine-grained audience/member enrichment that the web screen layers on (member email/phone/languages) comes from the SECONDARY `GET /ui/profiles/{identifier}` lookup (`CrossUserProfileResp.audience`), not from the public endpoint.

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

Primary endpoint, owned by AND-070, consumed here. (All shapes below VERIFIED against OpenAPI and `src/api/types.ts: PublicProfileData` — see §16.)

**Request**
```
GET /ui/profile/public/{identifier}      (CORRECTED — was /ui/profile/meta/{identifier})
Headers (all opportunistic; public reads also work fully unauthenticated):
  Authorization: Bearer <accessToken>     (if a session exists)
  X-CSRF-Token: <ui_csrf cookie>           (if the cookie exists)
  X-IMPERSONATION-TOKEN: <token>           (web-only; n/a for the Android client)
```
`{identifier}` is the URL-encoded path segment. OpenAPI description: "Public profile with social metrics and follow status. Auth is optional -- unauthenticated callers get follow fields as False."

**200 — public profile** (`PublicProfileData`; the OpenAPI `200` schema is an empty `{}` so the field list is taken from the verified web DTO):
```json
{
  "user_id": "usr_123",
  "identifier": "ada",
  "canonical_identifier": "ada",
  "display_name": "Ada Lovelace",
  "title": "Mathematician",
  "description": "First programmer.",
  "location": "London",
  "profile_photo_url": "https://cdn.testlogon.dev/a/ada.png",
  "cover_photo_url": null,
  "follower_count": 1280,
  "following_count": 73,
  "post_count": 211,
  "is_following": false,
  "is_followed_by": false,
  "is_mutual": false,
  "has_subscription_plans": true,
  "created_at": 1735992000,
  "discoverability": "public"
}
```
- `created_at` is a **unix epoch seconds** integer (nullable), NOT an ISO-8601 string. Render via `Instant.ofEpochSecond(created_at)`.
- Counts are flat top-level fields (`follower_count`/`following_count`/`post_count`), NOT a nested `stats{}` object.
- Follow fields (`is_following`/`is_followed_by`/`is_mutual`) are `false` for unauthenticated callers; this read-only screen ignores them (follow actions are out of scope) but the DTO carries them.
- `canonical_identifier`: when present and different from the requested `identifier`, the web app **redirects** to `/u/<canonical>` (`navigate(..., { replace: true })`). The Android screen SHOULD mirror this (re-fetch / re-key on the canonical identifier) to keep cache keys and share URLs canonical.

**404 — not found OR suppressed/private** (CORRECTED: there is no 403/`is_private` path):
```json
{ "detail": "Profile not available" }
```
The web maps 404 to `ProfileLookupError("not_found_or_suppressed")` and renders a single "Profile Not Available" page covering both missing and private profiles. Classify 404 → `NotFound`.

**429 — rate limited** (ADDED — present in the web contract, omitted in earlier drafts):
```json
{ "detail": "Too many profile lookups. Please try again shortly." }
```
A `Retry-After` header (seconds, or HTTP-date) and/or `detail.retry_after_seconds` may be present. The web surfaces a dedicated 429 "Too Many Requests" state. Classify 429 → retryable `Error` (ideally honoring `Retry-After` before re-enabling Retry); do NOT hammer.

**FastAPI `detail` mapping** (string | `[{ "msg": ... }]` | `{ "code", ... }`) is normalized by core-network's error mapper. This screen needs the resulting human string for the generic Error state; 404 and 429 are classified by status code before message extraction.

**Secondary (optional) lookup** — `GET /ui/profiles/{identifier}` → `CrossUserProfileResp { identifier, canonical_identifier?, user_sub, audience, profile }`. The web fires this in parallel (ungated; failures are swallowed) to enrich the "About" tab with member-audience fields and to source a canonical redirect. It supports ETag / `If-None-Match` 304 caching. This is OUT of scope for the minimal public screen but documented so AND-070 cache keying matches (R3).

**Activity preview** — `GET /ui/profile/public/{identifier}/posts?limit=&cursor=&filter=` → `ProfilePostsResponse { items[], next_cursor?, total_count }`; `limit` default 12, max 50; `filter ∈ {all,text,image,video,locked}`. Optional/follow-up per §4.

Behaviour: GET is **idempotent** → eligible for the bounded backoff retry on transient failures (timeout/5xx) per the network policy; 404 is **not** retried; 429 is retried only after `Retry-After`.

## 6. Data & State Management

- **Source of truth**: `ProfileRepository` (core-data, AND-070). It performs the network GET, maps DTO→`PublicProfile`, and writes/reads a Room cache keyed by `identifier`. This ticket adds no new persistence.
- **Cache key**: `identifier`. TTL and eviction are AND-070's concern; this ticket relies on `ApiResult.Stale`/cache-hit semantics for FR-7.
- **UI state holder**: `PublicProfileViewModel` exposes `StateFlow<PublicProfileUiState>`, single immutable state. Collected with `collectAsStateWithLifecycle()`.
- **Process death**: `identifier` is recovered from `SavedStateHandle.toRoute()`; the screen re-fetches in `init`. No transient UI fields need saving beyond the route arg.
- **Recomposition**: avatar URL stability ensures Coil does not reload on unrelated recompositions; the `Loaded` data class is value-equal so identical payloads cause no recomposition.

## 7. Error Handling & Resilience

| Condition | Classification | UI |
|---|---|---|
| 404 (`not_found_or_suppressed`; covers missing AND private/suppressed) | terminal | `NotFound`, no retry |
| 403 / `is_private==true` (NOT emitted by the verified backend; defensive only) | terminal | `Private(stub)` if the defensive branch is kept, else `NotFound` — see §16 / R2 |
| 429 rate-limited | transient (rate) | `Error(retryable=true)`; honor `Retry-After`/`detail.retry_after_seconds` before re-enabling Retry |
| Timeout (~20s), 5xx, conn reset | transient | `Error(retryable=true)` with Retry; or `Loaded(stale=true)` if cache hit |
| Offline, no cache | transient | `Error(retryable=true)` |
| Offline, cache present | degraded | `Loaded(stale=true)` + "Showing saved copy" banner |
| Malformed body / parse error | terminal | `Error("Couldn't load profile", retryable=true)` (allow one retry) |

- Honour the **~20s** OkHttp timeout and the **bounded backoff** retry for the idempotent GET (network-layer policy; this screen does not implement its own retry loop beyond the user-driven Retry button).
- On 401, the network layer performs the single `POST /ui/session/refresh` + retry transparently (VERIFIED in `src/api/client.ts`: a 401 on an authenticated request triggers one `POST /ui/session/refresh` then a single retry; failure logs out); this screen never handles 401 directly. For this public, auth-optional read a 401 is unexpected.
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
- Public GET works unauthenticated (VERIFIED: OpenAPI "Auth is optional"); `Authorization: Bearer` and `X-CSRF-Token` (from the `ui_csrf` cookie) are attached opportunistically when a session exists but are not required.
- NOTE (assumption): the `testlogon://u/<id>` custom scheme has no web counterpart (web is route-only, `/u/:identifier`); it is an Android share-flow product choice, not part of the verified backend/web contract — see §16 / Open assumptions.

## 9. Accessibility & i18n

- All strings in `feature-profile/src/main/res/values/strings.xml`; no hardcoded text. Keys: `profile_not_found_title`, `profile_private_title`, `profile_private_body`, `profile_error_retry`, `profile_stale_banner`, `profile_followers`, etc.
- Avatar `AsyncImage` has `contentDescription` = "Avatar of <display name or handle>"; decorative dividers `contentDescription = null`.
- Stats counters use a `pluralResources` `quantityString` (followers/following/posts) and locale-aware number formatting (`NumberFormat.getInstance()`).
- Touch targets (Back, Retry) ≥ 48dp; TalkBack reading order: title → stale banner (if any) → identity → bio → stats. Error/empty states are announced via `liveRegion = Polite`.
- Dynamic type and dark theme via Material 3 tokens from `core-ui`; no fixed font sizes.
- Join date (`created_at`, unix epoch **seconds** — see §5/§16) rendered with `DateTimeFormatter` in the device locale/zone, e.g. `Instant.ofEpochSecond(created_at).atZone(ZoneId.systemDefault())`.

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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer.

1. **Public-profile read endpoint is `GET /ui/profile/public/{identifier}`.** VERDICT: Corrected (earlier draft said `/ui/profile/meta/{identifier}`). SOURCE: OpenAPI `GET /ui/profile/public/{identifier}` (op `get_public_profile_ui_profile_public__identifier__get`); `src/api/endpoints/profile.ts: getPublicProfile`; `src/pages/profile/PublicUserProfilePage.tsx` (`queryFn: () => getPublicProfile(identifier)`).
2. **`/ui/profile/meta/{identifier}` is the SEO meta-tags endpoint, not the profile-data read.** VERDICT: Verified (root cause of the correction in #1). SOURCE: OpenAPI `GET /ui/profile/meta/{identifier}` (op `profile_meta_tags_ui_profile_meta__identifier__get`).
3. **200 response is `PublicProfileData` with fields `user_id, identifier, canonical_identifier?, display_name, title?, description?, location?, profile_photo_url?, cover_photo_url?, follower_count, following_count, post_count, is_following, is_followed_by, is_mutual, has_subscription_plans, created_at?, discoverability?`.** VERDICT: Verified. SOURCE: `src/api/types.ts: PublicProfileData` (lines 503–522). (OpenAPI 200 schema is empty `{}`, so the web DTO is authoritative.)
4. **The public DTO has NO `handle`, `bio`, `avatar_url`, `joined_at`, `is_private`, or nested `stats{}` fields.** VERDICT: Corrected (earlier draft used all of these). SOURCE: `src/api/types.ts: PublicProfileData` (none present); avatar is `profile_photo_url`, bio is `description`, name is `display_name`.
5. **`created_at` is a unix epoch SECONDS integer, not an ISO-8601 string.** VERDICT: Corrected. SOURCE: `src/api/types.ts: PublicProfileData` (`created_at?: number | null`); `src/pages/profile/PublicUserProfilePage.tsx` (`new Date(pub.created_at * 1000)`).
6. **Public counters are flat `follower_count`/`following_count`/`post_count`, not `stats.followers` etc.** VERDICT: Corrected. SOURCE: `src/api/types.ts: PublicProfileData`; `PublicUserProfilePage.tsx` (`pub.follower_count`, `pub.following_count`, `pub.post_count`).
7. **The endpoint is auth-optional; unauthenticated callers get follow fields as `false`.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/profile/public/{identifier}` description ("Auth is optional -- unauthenticated callers get follow fields as False").
8. **Private/suppressed profiles return 404 (no 403, no `is_private`); web maps to `not_found_or_suppressed`.** VERDICT: Corrected (earlier draft asserted a 403 / `is_private==true` Private state). SOURCE: `src/api/endpoints/profile.ts: mapProfileLookupError` (404 → `"not_found_or_suppressed"`, "Profile not available"); `PublicUserProfilePage.tsx` (only 404/429/500 branches; no 403/private branch).
9. **A 429 rate-limited response with `Retry-After`/`detail.retry_after_seconds` exists and is a distinct UI state.** VERDICT: Corrected/Added (omitted in earlier drafts). SOURCE: `src/api/endpoints/profile.ts` (`parseRetryAfterSeconds`, `ProfileLookupError("rate_limited")`); `PublicUserProfilePage.tsx` (status 429 → "Too Many Requests").
10. **Web route is `/u/:identifier`.** VERDICT: Verified. SOURCE: `src/App.tsx` (`<Route path="/u/:identifier" element={<PublicUserProfilePage />}` />).
11. **`identifier` is trimmed but otherwise treated opaque; blank → not-found without a network call.** VERDICT: Verified. SOURCE: `src/api/endpoints/profile.ts: getProfileByIdentifier` (`if (!normalized) throw ProfileLookupError(...404...)`); `PublicUserProfilePage.tsx` (`enabled: Boolean(identifier)`, blank → `ErrorPage status={404}`).
12. **Canonical-identifier redirect: when `canonical_identifier` differs from the requested id, navigate to `/u/<canonical>` (replace).** VERDICT: Verified. SOURCE: `PublicUserProfilePage.tsx` (`navigate(\`/u/${...canonicalIdentifier}\`, { replace: true })`).
13. **Transport: `Authorization: Bearer`, `X-CSRF-Token` from `ui_csrf` cookie, `credentials: include`; on authenticated 401 → single `POST /ui/session/refresh` + one retry.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`refreshSession()` → `POST /ui/session/refresh`; `getCookie("ui_csrf")` → `X-CSRF-Token`; `Authorization: Bearer`; 401 handling lines 194–221).
14. **Secondary enrichment endpoint `GET /ui/profiles/{identifier}` returns `CrossUserProfileResp { identifier, canonical_identifier?, user_sub, audience, profile }`, supports ETag/304, and is fired ungated alongside the public read.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/profiles/{identifier}` (op `ui_get_profile_by_identifier_...`); `src/api/types.ts: CrossUserProfileResp` (lines 493–499); `src/api/endpoints/profile.ts: getProfileByIdentifier` (If-None-Match / 304 logic); `PublicUserProfilePage.tsx` (`detailQ`, ungated, `retry: false`).
15. **Activity/posts endpoint `GET /ui/profile/public/{identifier}/posts` → `ProfilePostsResponse { items[], next_cursor?, total_count }`; `limit` default 12 / max 50; `filter ∈ {all,text,image,video,locked}`.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/profile/public/{identifier}/posts` (limit default 12, max 50; cursor; filter); `src/api/endpoints/profile.ts: getProfilePosts`; `src/api/types.ts: ProfilePostsResponse`.
16. **App Links require HTTPS + Digital Asset Links (`/.well-known/assetlinks.json`) verification; cleartext HTTP host cannot autoVerify.** VERDICT: Verified (framework ref). SOURCE: framework ref — https://developer.android.com/training/app-links/verify-android-applinks.
17. **Type-safe Navigation-Compose deep links via `navDeepLink<T>(basePath = ...)` and `composable<T>(deepLinks = ...)`.** VERDICT: Verified (framework ref). SOURCE: framework ref — https://developer.android.com/guide/navigation/design/deep-link and https://developer.android.com/guide/navigation/design/type-safety.

### Corrections made
- C1: Endpoint path `/ui/profile/meta/{identifier}` → `/ui/profile/public/{identifier}` (claims #1/#2). Fixed in §2, FR-3, §5.
- C2: Response shape rewritten — removed non-existent `handle`/`bio`/`avatar_url`/`joined_at`/`is_private`/`stats{}`; substituted the real `PublicProfileData` fields (claims #3/#4/#6). Fixed in FR-4, §5.
- C3: `created_at` documented as unix epoch SECONDS, not an ISO string (claim #5). Fixed in FR-4, §5, §9.
- C4: Removed the 403/`is_private` "Private" contract; private/suppressed folds into 404 `not_found_or_suppressed` (claim #8). Fixed in FR-6, §5, §7. The `Private` UI state is now flagged as Android-only/unreachable (R2).
- C5: Added the 429 rate-limited path with `Retry-After`/`detail.retry_after_seconds` (claim #9). Fixed in §5, §7.
- C6: Replaced the non-existent web type name `PublicProfile`/`PublicProfileStub` reference with the real `PublicProfileData` / `CrossUserProfileResp` (§2). The Android domain types `PublicProfile`/`PublicProfileStub` are AND-070 abstractions, not web DTOs — left as such but clarified.
- C7: Documented the canonical-identifier redirect, the secondary `/ui/profiles/{identifier}` enrichment lookup, and the posts endpoint that the web screen actually uses (claims #12/#14/#15).

### Open assumptions
- A1 (R1/R3): Production HTTPS App Link host and the `assetlinks.json` publishing owner are unverified — no source in OpenAPI/web; the dev host `18.222.237.167:8000` is cleartext HTTP and cannot autoVerify. Unverifiable from provided sources (release-ops concern).
- A2: The `testlogon://u/<id>` custom scheme has no web counterpart (web is route-only, claim #10); it is an Android-only product choice, not part of the verified backend/web contract.
- A3 (R2): A defensive 403 / `is_private==true` "Private" branch is retained as an unverified assumption only; the verified backend never emits it (claim #8). Recommend routing private→`NotFound` unless backend behavior changes.
- A4: `ApiResult.Stale` / Room cache semantics (FR-7, offline stale banner) belong to AND-070 and are not represented in the web client or OpenAPI; treated as an upstream-owned assumption (the web uses an in-memory ETag map + TanStack Query `staleTime`, not a persistent offline cache).
- A5: `discoverability` field values (e.g. `"public"`) are present in the DTO but their enumeration is not specified in OpenAPI (200 schema is empty `{}`); not consumed by this screen.

## 17. Test Plan

IDs `TC-AND-073-NN`. Targets: JVM = JVM unit/Robolectric (local); MWS = contract via MockWebServer (JVM); EMU = headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). "Traces: AC-#" links to §14.

- **TC-AND-073-01** — Type: unit (JVM). Target: `PublicProfileViewModel` with a fake `ProfileRepository`. Preconditions: repo returns `ApiResult.Success(PublicProfile)` for `identifier="ada"`. Steps: construct VM (init runs `load()`); collect `uiState` via Turbine. Expected: `Loading` → `Loaded(stale=false)` carrying display name, description, counts, `created_at`-derived join date. Traces: AC-2.
- **TC-AND-073-02** — Type: unit (JVM). Target: VM. Preconditions: repo returns `ApiResult.Error` classified 404 (`not_found_or_suppressed`). Steps: init; collect. Expected: `Loading` → `NotFound`; no retryable error; repository called exactly once. Traces: AC-4.
- **TC-AND-073-03** — Type: unit (JVM). Target: VM. Preconditions: `identifier` blank/whitespace. Steps: init; collect; assert repo never invoked. Expected: `NotFound` with zero network/repository calls. Traces: AC-4. (Verifies claim #11.)
- **TC-AND-073-04** — Type: unit (JVM). Target: VM. Preconditions: repo returns transient `Error` (timeout/5xx) then, on `retry()`, `Success`. Steps: collect initial `Error(retryable=true)`; call `retry()`; collect. Expected: `Error(retryable=true)` → `Loading` → `Loaded`. Retry debounced while `Loading`. Traces: AC-5, AC-7.
- **TC-AND-073-05** — Type: unit (JVM). Target: VM. Preconditions: network failure with a Room cache hit (`ApiResult.Stale` or `Success(stale=true)`). Steps: init; collect. Expected: `Loaded(stale=true)`; UI exposes the "Showing saved copy" banner flag. Traces: AC-5.
- **TC-AND-073-06** — Type: contract/MockWebServer (JVM). Target: `ProfileApi`/repository GET against MWS. Preconditions: MWS enqueues `200` with a real `PublicProfileData` body (epoch-seconds `created_at`, flat `*_count`, no `is_private`). Steps: call `getPublicProfile("ada")`; assert request line `GET /ui/profile/public/ada` and parsed domain fields. Expected: path is `/ui/profile/public/{identifier}` (NOT `/meta/`); `created_at` parsed as epoch seconds; counts mapped from flat fields. Traces: AC-2. (Locks corrections C1–C3, C6.)
- **TC-AND-073-07** — Type: contract/MockWebServer (JVM). Target: repository error mapping. Preconditions: MWS enqueues `404 {"detail":"Profile not available"}`, then in a second case `429` with `Retry-After: 30`. Steps: issue GET for each. Expected: 404 → terminal `NotFound` (not retried); 429 → retryable `Error` that honors `Retry-After` (no immediate re-request). Traces: AC-4, AC-5. (Locks corrections C4–C5.)
- **TC-AND-073-08** — Type: contract/MockWebServer (JVM). Target: transport/header attachment. Preconditions: a session cookie jar/token exists. Steps: issue the public GET; inspect the recorded MWS request. Expected: when a session exists, `Authorization: Bearer` and `X-CSRF-Token` (from `ui_csrf`) are present; when no session, the GET still succeeds with neither header (auth-optional). Traces: AC-2. (Verifies claims #7, #13.)
- **TC-AND-073-09** — Type: Compose-UI (EMU; `createAndroidComposeRule`). Target: `PublicProfileScreen` state rendering. Preconditions: VM seeded with each of `Loaded(stale=false)`, `Loaded(stale=true)`, `NotFound`, `Error(retryable=true)`. Steps: assert hallmark nodes. Expected: loaded shows name/description/stats; stale shows "Showing saved copy" banner iff `stale`; not-found shows title + no Retry; error shows Retry; clicking Retry invokes `viewModel.retry()`. Traces: AC-2, AC-4, AC-5.
- **TC-AND-073-10** — Type: Compose-UI / accessibility (EMU). Target: `PublicProfileScreen`. Preconditions: `Loaded` state; TalkBack semantics assertions. Steps: assert avatar `contentDescription` = "Avatar of <name/identifier>"; Back and Retry touch targets ≥ 48dp; error/empty states `liveRegion = Polite`; reading order title → banner → identity → description → stats. Expected: all a11y assertions pass. Traces: AC-2, AC-7. (Manual TalkBack spot-check on DEV recommended for real screen-reader announcement order.)
- **TC-AND-073-11** — Type: instrumented/e2e deep link (EMU). Target: App Link + custom scheme resolution into the NavHost. Preconditions: app installed; `APP_LINK_HOST` set for the build. Steps: `adb shell am start -W -a android.intent.action.VIEW -d "https://<host>/u/ada"` and `-d "testlogon://u/ada"`; also `/u/a%20b`. Expected: `PublicProfileScreen` opens with `identifier=="ada"` (and `"a b"` after one URL-decode); both URI forms resolve the same route. Traces: AC-1. (Custom scheme is the Android-only path — assumption A2.)
- **TC-AND-073-12** — Type: instrumented/e2e (EMU). Target: deep-link cold-start Back behavior. Preconditions: app process not running; launched via the deep link (empty back stack). Steps: press system Back. Expected: navigates to home/start destination, not app exit. Traces: AC-6.
- **TC-AND-073-13** — Type: instrumented/e2e — verified App Link (DEV, MUST run on physical device). Target: real autoVerify + Digital Asset Links handoff. Preconditions: release build signed with the production cert, `assetlinks.json` published, A15 (SM-A156U, API 34) online via adb. Steps: open `https://<verified-host>/u/ada` from a real browser/another app; confirm the app (not Chrome) handles it; check `adb shell pm get-app-links <pkg>` shows `verified`. Expected: link opens `PublicProfileScreen` directly with no disambiguation chooser. Traces: AC-1. (Needs the real device because emulator autoVerify/Asset-Links handoff and the on-device App Links verifier are not reliably reproducible on the headless AVD; also exercises arm64/API-34.)
- **TC-AND-073-14** — Type: integration — offline/flaky-host (DEV preferred; EMU acceptable). Target: full screen against a toggled-connectivity device. Preconditions: profile previously loaded and cached (AND-070 Room); then enable airplane mode. Steps: re-open the screen offline; then with no cache for a fresh identifier offline. Expected: cached identifier → `Loaded(stale=true)` + "Showing saved copy" banner (never serves richer data for a now-private/suppressed profile, per §8); fresh-with-no-cache → `Error(retryable=true)` with working Retry once back online. Traces: AC-5. (Physical-device airplane-mode toggling is more faithful than emulator network shaping.)

### Coverage matrix
| AC | Covered by |
|---|---|
| AC-1 (link opens profile; https verified + custom scheme) | TC-11, TC-13 |
| AC-2 (valid public profile renders name/avatar/description/stats) | TC-01, TC-06, TC-08, TC-09, TC-10 |
| AC-3 (private handled) | TC-02, TC-07 (private folds into 404 `not_found_or_suppressed` — see §16 C4/A3; no separate 403 path) |
| AC-4 (404 → NotFound, no Retry) | TC-02, TC-03, TC-07, TC-09 |
| AC-5 (transient error + Retry; stale cache banner) | TC-04, TC-05, TC-07, TC-09, TC-14 |
| AC-6 (deep-link cold-start Back → home) | TC-12 |
| AC-7 (unit + Compose + deep-link tests green in CI) | TC-01..TC-12 (CI: JVM/MWS local, EMU `test35`; TC-13/TC-14 on DEV) |

---
id: AND-390
title: Public profile polish
milestone: M8
epic: E51
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-073]
blocks: []
---

# AND-390 — Public profile polish

## 1. Overview & Goal

AND-073 delivered the functional public profile screen at the `/u/:identifier`
route together with the baseline Android App Link intent filter, not-found, and
private-profile handling. AND-390 is the *polish* pass over that foundation. Its
single authoritative acceptance criterion is: **a public profile opens
unauthenticated** — i.e. a cold, signed-out app (or an app with no cookie jar
session) that receives a `https://testlogon.com/u/<identifier>` App Link, or an
in-app share-back tap, lands directly on a fully rendered public profile without
being bounced to login.

Concretely this ticket hardens three things on top of AND-073:

1. **Deep-link robustness in the unauthenticated state** — the App Link and the
   internal `nav` route both resolve to the public profile destination *without*
   passing through auth-gated routing (AND-025), even on a cold process start
   from a notification or browser hand-off, including identifier
   normalization, malformed-link rejection, and warm vs. cold start parity.
2. **Share polish** — a correct, branded Android share sheet (`ACTION_SEND`)
   emitting a canonical share URL, plus `ACTION_VIEW` round-trip so a shared
   link re-opens the same profile, and copy-link affordance with feedback.
3. **Unauthenticated presentation polish** — a "Sign in" / "Open app" call to
   action, suppression of auth-only affordances (follow, message, edit),
   stable shimmer/placeholder while the public payload loads, and correct
   back-stack behavior so pressing Back from a deep-linked profile exits to the
   launcher rather than into an empty authed graph.

This is a Feature/P2 ticket; it changes no backend contracts and adds no new
endpoints. It is sized **M** (UI + navigation + intent-filter wiring + tests).

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app in `android/`, branch
  `android-port`.
- **Package base:** `com.testlogon.android` (used for all
  `applicationId`/namespace references below).
- **Owning modules:** `feature-profile` (screen, ViewModel, share logic),
  `core-ui` (state composables AND-021, input/CTA composables AND-020),
  `core-data`/`core-model` (profile DTOs + repository from AND-070), `app`
  (manifest intent filters, nav host AND-022, unauth graph AND-023, auth-gated
  routing AND-025).
- **Upstream dependency — AND-073** (Public profile `/u/:identifier`): owns the
  `PublicProfileScreen`, the `ProfileRepository.publicProfile()` call, and the
  baseline manifest intent filter + not-found/private states. AND-390 extends
  these; it must not re-implement them.
- **Transitive deps (already merged before AND-073):** AND-070 (Profile API +
  DTOs, `ProfileApi.getProfileMeta`), AND-022 (Navigation host + routes),
  AND-023 (unauthenticated nav graph), AND-025 (auth-gated routing), AND-021
  (state composables), AND-029 (`AuthStateStore` for `GET /ui/me` state).
- **Web reference:** `frontend/src/api/endpoints/profile.ts` and shared types in
  `frontend/src/api/types.ts`; the web app's `/u/:identifier` route and its
  share/Open-Graph behavior are the canonical UX reference for the share URL
  shape and the unauthenticated view.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable; ~20s timeouts, bounded backoff for idempotent GETs
  only). Public profile payload served by `GET /ui/profile/public/{identifier}`
  (op `get_public_profile_ui_profile_public__identifier__get`). *(Correction:
  earlier drafts cited `GET /ui/profile/meta/{identifier}`; that endpoint exists
  but returns only "Lightweight meta tag data for SEO" — it is not the profile
  payload the screen renders. The web client's `getPublicProfile()` calls
  `/ui/profile/public/{identifier}`.)* OpenAPI at `/openapi.json`.

## 3. Functional Requirements

FR-1. **Unauthenticated open.** Given a signed-out app, opening
`https://testlogon.com/u/<identifier>` (App Link) or `testlogon://u/<identifier>`
(custom scheme fallback) MUST render the public profile for `<identifier>`
without redirecting to login. No `GET /ui/me` success is required to display a
public profile.

FR-2. **Cold-start parity.** The behavior in FR-1 MUST be identical whether the
process was already running (warm) or launched fresh by the intent (cold). On
cold start the destination MUST be the public profile, not the default
unauthenticated landing screen.

FR-3. **Identifier normalization & validation.** `<identifier>` MUST be
URL-decoded, trimmed, and lower-cased for username-style identifiers (leave
opaque IDs untouched — see Open Question OQ-1). An empty, whitespace-only, or
syntactically invalid identifier MUST route to the not-found state (reusing
AND-073's not-found UI), never crash.

FR-4. **Private/suppressed & missing handling (inherited).** Per the verified
contract there is no distinct `403`: the server returns `404` for both missing
**and** private/suppressed profiles (web error code `not_found_or_suppressed`).
AND-390 renders AND-073's not-found state for `404` and presents the unauth-aware
"Sign in to view" CTA there (signing in may reveal a profile that is suppressed
from anonymous viewers). A `429` shows a rate-limited/retry state. These base
states are defined in AND-073; AND-390 adds the CTA copy and sign-in action.
*(Correction: prior text assumed a `403`/private response that the backend does
not emit for this endpoint.)*

FR-5. **Share action.** A share affordance (overflow menu + visible icon) in the
public profile top bar MUST launch the system share sheet via `ACTION_SEND`
(`text/plain`) carrying the canonical URL
`https://testlogon.com/u/<identifier>` plus a localized title
("<displayName> on TestLogon"). A "Copy link" item MUST copy the same URL to the
clipboard and show a confirmation snackbar.

FR-6. **Share round-trip.** Tapping a URL emitted by FR-5 MUST re-open the same
public profile via the App Link path (FR-1), proving the emitted URL is a valid,
verified App Link target.

FR-7. **Auth-only affordance suppression.** When unauthenticated, follow,
message, report, and edit actions MUST be hidden (not merely disabled). When the
viewer *is* authenticated, those affordances render per their owning tickets;
AND-390 only gates visibility on `AuthStateStore` state.

FR-8. **Sign-in CTA.** Unauthenticated public profile MUST show a non-blocking
"Sign in" CTA that navigates into the auth flow (login route from AND-023/030)
and, on success, returns to the same profile (deep-link preserved as the
post-login destination).

FR-9. **Back-stack correctness.** Pressing Back from a deep-link-launched public
profile (cold start, single destination on the stack) MUST exit the app to the
launcher, not navigate into an empty authenticated graph. Pressing Back from an
in-app navigation to a public profile returns to the previous in-app screen.

FR-10. **Loading polish.** While the public payload loads, a shimmer/placeholder
matching the final layout MUST be shown (no blank screen, no spinner-only).
Offline/stale states reuse AND-021/AND-045 composables.

## 4. Technical Design

### 4.1 Manifest intent filters (`app/src/main/AndroidManifest.xml`)

AND-073 already declares the single-Activity `MainActivity`. AND-390 verifies and
hardens the App Link filter (autoVerify) and adds the custom-scheme fallback:

```xml
<activity
    android:name="com.testlogon.android.MainActivity"
    android:exported="true"
    android:launchMode="singleTask">

  <!-- Verified App Link (HTTPS) -->
  <intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https"
          android:host="testlogon.com"
          android:pathPrefix="/u/" />
  </intent-filter>

  <!-- Custom-scheme fallback (not auto-verified) -->
  <intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="testlogon" android:host="u" />
  </intent-filter>
</activity>
```

`launchMode="singleTask"` ensures a single resolved task; `onNewIntent` is wired
in `MainActivity` to route warm-start intents (FR-2). The
`assetlinks.json` Digital Asset Links file is a backend/web concern; this ticket
assumes it is published for `testlogon.com` and adds a verification check to the
test plan (TC-7) rather than owning the file.

### 4.2 Intent → navigation mapping

`MainActivity` parses the inbound `Uri` and emits a typed nav intent *before*
the auth-gate decides the start destination, so the deep link survives cold
start:

```kotlin
object PublicProfileRoute {
    const val ROUTE = "u/{identifier}"
    const val ARG = "identifier"
    fun build(identifier: String): String = "u/${Uri.encode(identifier)}"

    val deepLinks = listOf(
        navDeepLink { uriPattern = "https://testlogon.com/u/{identifier}" },
        navDeepLink { uriPattern = "testlogon://u/{identifier}" },
    )
}

sealed interface StartDestination {
    data class PublicProfile(val identifier: String) : StartDestination
    data object Default : StartDestination
}

class DeepLinkResolver @Inject constructor() {
    fun resolve(intent: Intent?): StartDestination {
        val uri = intent?.data ?: return StartDestination.Default
        val id = uri.pathSegments
            .takeIf { it.size >= 2 && it[0] == "u" }
            ?.get(1)
            ?.let(Uri::decode)
            ?.let(::normalizeIdentifier)
            ?: return StartDestination.Default
        return if (id.isBlank()) StartDestination.Default
               else StartDestination.PublicProfile(id)
    }

    fun normalizeIdentifier(raw: String): String {
        val t = raw.trim()
        return if (t.matches(USERNAME_RE)) t.lowercase() else t
    }
    companion object { val USERNAME_RE = Regex("^[A-Za-z0-9_.-]{1,64}$") }
}
```

The public profile composable is registered in the **unauthenticated** graph
(AND-023) with the deep links attached, so AND-025's auth gate never wraps it:

```kotlin
composable(
    route = PublicProfileRoute.ROUTE,
    deepLinks = PublicProfileRoute.deepLinks,
    arguments = listOf(navArgument(PublicProfileRoute.ARG) { type = NavType.StringType }),
) { backStackEntry ->
    PublicProfileScreen(
        identifier = backStackEntry.arguments!!.getString(PublicProfileRoute.ARG)!!,
    )
}
```

### 4.3 Auth-gate exemption (AND-025 interaction)

AND-025 gates routes by reading `AuthStateStore`. AND-390 registers
`u/{identifier}` in an **allow-list of unauthenticated-public routes** consumed
by the gate so that the gate short-circuits redirect-to-login for this route:

```kotlin
val PUBLIC_UNAUTH_ROUTES: Set<String> = setOf(PublicProfileRoute.ROUTE)
// AuthGatedNavigator: if destination.route in PUBLIC_UNAUTH_ROUTES -> allow
```

### 4.4 Share & copy (`feature-profile`)

```kotlin
class ProfileShareHelper @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    fun shareUrl(identifier: String): String = "https://testlogon.com/u/$identifier"

    fun buildShareIntent(displayName: String, identifier: String): Intent {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TITLE,
                context.getString(R.string.share_profile_title, displayName))
            putExtra(Intent.EXTRA_TEXT, shareUrl(identifier))
        }
        return Intent.createChooser(send, context.getString(R.string.share_profile_chooser))
    }
}
```

Copy-link uses `ClipboardManager.setPrimaryClip(ClipData.newPlainText(...))`;
the snackbar confirmation is shown via the screen's `SnackbarHostState`. On
Android 13+ the OS shows its own clipboard toast, so the in-app snackbar is
suppressed when `Build.VERSION.SDK_INT >= 33` to avoid duplicate feedback.

### 4.5 Presentation polish

`PublicProfileScreen` reads `isAuthenticated: StateFlow<Boolean>` from
`AuthStateStore` (AND-029) to gate affordances (FR-7) and choose the CTA copy
(FR-8). Loading uses the AND-021 shimmer state matching the avatar/name/bio
layout. No new ViewModel is introduced; `PublicProfileViewModel` from AND-073 is
extended with `onShareClicked`, `onCopyLinkClicked`, and `onSignInClicked`
intents and an injected `ProfileShareHelper`.

## 5. API Contract

AND-390 introduces **no new endpoints** and **no DTO changes**. It consumes the
existing public-profile endpoint owned by AND-070 / AND-073:

`GET /ui/profile/public/{identifier}` — idempotent, cacheable, callable
unauthenticated (OpenAPI: *"Public profile with social metrics and follow
status. Auth is optional -- unauthenticated callers get follow fields as
False."*). Wrapped by `ProfileApi.getPublicProfile(identifier)` returning
`ApiResult<PublicProfileDto>` (typed result per AND-018; web mirror is
`getPublicProfile()` → `PublicProfileData` in `src/api/endpoints/profile.ts`).
Eligible for the bounded-backoff retry policy (AND-016, idempotent GET) and the
~20s OkHttp timeout (AND-009).

**Correction:** earlier drafts used `GET /ui/profile/meta/{identifier}` and a
DTO with `bio`/`avatar_url`/`links`/`is_private`. The authoritative
`PublicProfileData` shape (web `src/api/types.ts`) has none of those fields. The
true success (`200`) shape (verified subset) is:

```json
{
  "user_id": "u_123",
  "identifier": "ada",
  "canonical_identifier": "ada",
  "display_name": "Ada Lovelace",
  "title": "Mathematician",
  "description": "Analytical engine enthusiast.",
  "location": "London",
  "profile_photo_url": "https://.../ada.png",
  "cover_photo_url": "https://.../cover.png",
  "follower_count": 0,
  "following_count": 0,
  "post_count": 0,
  "is_following": false,
  "is_followed_by": false,
  "is_mutual": false,
  "has_subscription_plans": false,
  "created_at": 1700000000,
  "discoverability": "public"
}
```

Notes on the corrected shape: bio → `description`; avatar → `profile_photo_url`;
there is a `cover_photo_url`; no `links` array; **no `is_private` boolean** — the
server folds private/suppressed profiles into the `404` path (see below). Display
name fallback is `identifier` when `display_name` is blank (per the web page).

Failure shapes (verified against OpenAPI + web client error mapping in
`src/api/endpoints/profile.ts` and `src/pages/profile/PublicUserProfilePage.tsx`):

- `404` → not-found **or suppressed/private** state (FR-3/FR-4). The web client
  maps `404` to error code `not_found_or_suppressed` with message "Profile not
  available" — there is **no distinct `403 profile_private` response** in the
  contract. *(Correction: the prior `403 → profile_private` and the literal
  `detail` strings `profile_not_found` / `profile_private` are NOT in the sources;
  privacy is expressed as `404`.)*
- `429` → rate-limited. Web maps this to code `rate_limited` ("Too many profile
  lookups…"); honor `Retry-After`. *(Added: previously omitted; it is a real
  handled case in the web client.)*
- `422` → `HTTPValidationError` (the only non-200 schema declared in OpenAPI for
  this path) for a malformed identifier; treat as not-found (FR-3).
- `401` → MUST NOT occur for this public endpoint; if it does, treat as
  not-found and log a telemetry warning (do **not** trigger the AND-013 refresh
  authenticator — `POST /ui/session/refresh` — for the public read path).

Cookies/CSRF: the public read works with **no** session cookie. The web
transport (`src/api/client.ts`) uses cookie auth (`credentials: include`) plus a
CSRF token read from the `ui_csrf` cookie and sent as the `X-CSRF-Token` header;
neither the persistent cookie jar (AND-011) nor the CSRF header (AND-012) is
required for this GET. If a session exists it may ride along harmlessly.

## 6. Data & State Management

ViewModel exposes `StateFlow<PublicProfileUiState>` (from AND-073, extended):

```kotlin
data class PublicProfileUiState(
    val identifier: String,
    val phase: Phase,                       // Loading | Content | NotFound | RateLimited | Offline
    val profile: PublicProfileUi? = null,
    val isAuthenticated: Boolean = false,   // collected from AuthStateStore
    val shareUrl: String? = null,
    val snackbar: SnackbarEvent? = null,    // one-shot copy/share feedback
)

// Correction: no Private phase — the backend folds private/suppressed into 404
// (NotFound). RateLimited added for the verified 429 case.
enum class Phase { Loading, Content, NotFound, RateLimited, Offline }
```

One-shot effects (share intent launch, copy confirmation, navigate-to-login) are
delivered as a `Channel`/`SharedFlow` of `PublicProfileEffect` consumed in the
composable, not as durable state. Identifier is the screen's only nav argument
(saved in `SavedStateHandle`), so process death restores the same profile.
Offline/stale reads reuse AND-045 baseline (last-good public payload may be
served from the Room cache if AND-070 populated it; otherwise show Offline).

## 7. Error Handling & Resilience

- **Malformed link:** `DeepLinkResolver` returns `Default` or routes to
  not-found (FR-3); never throws. Covered by TC-3.
- **Unreliable dev host:** GET uses AND-016 bounded backoff (idempotent GET
  only) and AND-009 ~20s timeout. On exhausted retries or no connectivity, show
  the Offline state with a Retry button; do not show login.
- **No-session path:** Public read explicitly bypasses the AND-013 401-refresh
  authenticator for `GET /ui/profile/public/**` so an unauthenticated open never
  attempts `POST /ui/session/refresh`.
- **Share with missing data:** If `display_name` is null (still loading), the
  share affordance is disabled until `Content`; the share URL itself only needs
  the identifier, so copy-link may be enabled earlier.
- **Clipboard unavailable:** wrap `setPrimaryClip` in try/catch; on failure show
  an error snackbar rather than crashing.

## 8. Security & Privacy

- Public profile data is, by definition, public; no auth tokens are sent on the
  public read. The session cookie jar is not required and MUST NOT be a
  precondition for rendering (FR-1).
- The share URL contains only the public identifier — no session ids, CSRF
  tokens, or PII beyond what the public profile already exposes.
- Private/suppressed profiles are returned as `404` (no body leakage by design —
  the server reveals nothing beyond "not available"); the ViewModel treats `404`
  as NotFound and renders no profile fields.
- App Link auto-verification (`autoVerify="true"`) prevents arbitrary apps from
  silently claiming `testlogon.com/u/*`; this protects against link hijacking.
  The custom `testlogon://` scheme is unverifiable and is treated as
  lower-trust: it is accepted only for the same read-only public route.
- Dev backend is plaintext HTTP; production uses HTTPS. The hardcoded share URL
  uses `https://testlogon.com` regardless of the dev base URL so shared links
  always point at production web/App Link.

## 9. Accessibility & i18n

- Share and copy-link controls have `contentDescription`s
  (`R.string.cd_share_profile`, `R.string.cd_copy_link`) and a ≥48dp touch
  target.
- Snackbar/CTA text are string resources; copy: `share_profile_title`
  ("%1$s on TestLogon"), `share_profile_chooser`, `link_copied`, `sign_in_cta`,
  `open_app_cta`, `profile_private_body`, `profile_not_found_body`.
- Shimmer placeholders set `Modifier.semantics { contentDescription =
  loadingDesc }` and are excluded from TalkBack reading order once content
  loads.
- Sign-in CTA reachable and operable via TalkBack and keyboard; focus moves to
  the CTA when the private/not-found state renders.
- RTL: layout uses `start`/`end`; the share URL is wrapped with LTR bidi
  isolation when embedded in localized strings.

## 10. Telemetry & Logging

Events (via the app's analytics facade; no PII, identifier hashed if the
facade requires):

- `public_profile_open` — props: `source` (`app_link` | `custom_scheme` |
  `in_app`), `cold_start` (bool), `authenticated` (bool).
- `public_profile_share` — props: `method` (`share_sheet` | `copy_link`).
- `public_profile_result` — props: `phase` (`content`/`not_found`/
  `rate_limited`/`offline`), `latency_ms`.
- `public_profile_signin_cta` — fired on CTA tap.

Logging: deep-link resolution logs at DEBUG (`tag=DeepLink`) the raw vs.
normalized identifier and the resolved `StartDestination`. An unexpected `401`
on the public read logs at WARN. No tokens, cookies, or full URLs with query
strings are logged.

## 11. Testing Strategy

Unit (`feature-profile`, `app`):

- TC-1 `DeepLinkResolver.resolve` maps `https://testlogon.com/u/Ada` →
  `PublicProfile("ada")` (normalization).
- TC-2 maps `testlogon://u/ada` → `PublicProfile("ada")`.
- TC-3 malformed/empty (`https://testlogon.com/u/`,
  `https://testlogon.com/x/y`, whitespace) → `Default`/not-found, no throw.
- TC-4 `ProfileShareHelper.shareUrl` returns
  `https://testlogon.com/u/<id>` even when base URL is the dev host.
- TC-5 ViewModel: `404` → `Phase.NotFound` (covers missing **and**
  private/suppressed); `429` → `Phase.RateLimited`; success → `Phase.Content`
  with affordances gated by `isAuthenticated`.

Repository/contract (MockWebServer, AND-046 harness):

- TC-6 `getPublicProfile` succeeds with **no** cookie jar entry (unauth read);
  asserts no `POST /ui/session/refresh` is issued on the public path.

Instrumentation / Compose UI (AND-048-style):

- TC-7 App Link verification smoke: launch `MainActivity` with an
  `ACTION_VIEW` intent for `https://testlogon.com/u/ada` on a signed-out app →
  `PublicProfileScreen` is displayed (FR-1, FR-2 via fresh activity).
- TC-8 Share: tapping share emits an `ACTION_SEND` intent with `EXTRA_TEXT ==
  https://testlogon.com/u/ada` (Espresso-Intents `intended`).
- TC-9 Copy-link shows snackbar (< API 33) and writes clipboard.
- TC-10 Auth gating: signed-out hides follow/message/edit; signed-in shows them.
- TC-11 Back from cold-start deep link finishes the activity (launcher), not an
  empty authed graph (FR-9).

CI: all of the above run under AND-050 unit-test job; instrumentation tests run
on the existing emulator job.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-073 (public profile screen, baseline App Link,
  not-found/private states) MUST be merged first; AND-390 extends its
  `PublicProfileScreen`/`PublicProfileViewModel`.
- **Transitive (already present):** AND-070 (`ProfileApi`/DTOs), AND-022 (nav
  host), AND-023 (unauth graph), AND-025 (auth-gated routing — needs the
  public-route allow-list hook), AND-029 (`AuthStateStore`), AND-021 (state
  composables), AND-016/AND-009 (retry/timeout), AND-013 (refresh authenticator
  — must exempt the public read path).
- **Blocks:** none recorded. Other share-related M8 polish tickets, if any,
  should reuse `ProfileShareHelper`.
- Coordinate with web/backend to confirm `assetlinks.json` is published for
  `testlogon.com` (precondition for TC-7 verification, not owned here).

## 13. Risks & Open Questions

- **OQ-1 Identifier semantics.** Are `/u/:identifier` values usernames (safe to
  lower-case) or opaque IDs? **Partly resolved:** the web client does NOT
  lower-case client-side — `getProfileByIdentifier` only trims/encodes, and the
  server returns a `canonical_identifier` on `PublicProfileData`; the web page
  then `navigate(...replace)`s to `/u/{canonical_identifier}` when it differs
  (`PublicUserProfilePage.tsx`). **Recommendation/correction:** Android should
  rely on the server's `canonical_identifier` for normalization rather than the
  local `USERNAME_RE.lowercase()` heuristic, which risks mismatching an
  opaque/case-sensitive id. Keep local trim/URL-decode; drop aggressive
  lower-casing. Confirm with backend whether lookups are case-insensitive.
- **OQ-2 Canonical host.** Spec assumes the verified App Link host is
  `testlogon.com`. Confirm the production web host and whether `www.` or other
  subdomains must also be claimed (would require additional `<data>` entries +
  `assetlinks.json` coverage).
- **R-1 App Link verification flakiness** in CI/emulator (no internet asset
  links fetch). Mitigation: TC-7 asserts intent handling via direct
  `ACTION_VIEW` launch, not OS auto-verification; verification itself is a
  manual/device check.
- **R-2 Custom scheme abuse.** `testlogon://u/*` is unverifiable; mitigated by
  restricting it to the read-only public route and never honoring it for
  authed actions.
- **OQ-3 Open Graph / preview cards** for shared links are a web concern; out of
  scope here. Confirm no Android-side preview generation is expected.

## 14. Acceptance Criteria

AC-1 (authoritative). A signed-out app opening
`https://testlogon.com/u/<identifier>` (cold or warm) renders the public profile
for `<identifier>` without redirecting to login. *(FR-1, FR-2; TC-7.)*

AC-2. `testlogon://u/<identifier>` opens the same public profile. *(FR-1; TC-2.)*

AC-3. Malformed/empty identifiers route to the not-found state without crashing.
*(FR-3; TC-3.)*

AC-4. Missing and private/suppressed profiles (both returned as `404`) show the
not-found state with a working "Sign in to view" CTA; a `429` shows a
rate-limited/retry state. *(FR-4; TC-5.)* *(Corrected: the backend does not emit
a distinct `403` for private profiles.)*

AC-5. The share sheet emits `ACTION_SEND` with `EXTRA_TEXT ==
https://testlogon.com/u/<identifier>`; copy-link writes that URL to the
clipboard with confirmation. *(FR-5; TC-8, TC-9.)*

AC-6. A URL emitted by the share action re-opens the same public profile via the
App Link path. *(FR-6; TC-7 + TC-8.)*

AC-7. When unauthenticated, follow/message/report/edit affordances are hidden;
when authenticated, they render. *(FR-7; TC-10.)*

AC-8. Back from a cold-start deep-linked profile exits to the launcher; back
from in-app navigation returns to the previous screen. *(FR-9; TC-11.)*

AC-9. The public read issues no `POST /ui/session/refresh` and requires no
cookie jar session. *(FR-1, §7; TC-6.)*

AC-10. A shimmer placeholder matching the final layout is shown while loading;
no blank screen. *(FR-10.)*

## 15. Definition of Done

- All FRs implemented; all ACs demonstrably met by the listed tests.
- Manifest App Link filter (`autoVerify`) + custom-scheme fallback present and
  resolving to the unauthenticated public route; verified manually on a device
  with published `assetlinks.json`.
- `DeepLinkResolver`, `ProfileShareHelper`, ViewModel extensions, and the
  AND-025 public-route allow-list hook merged with KDoc on public symbols.
- Unit + repository + Compose/Espresso-Intents tests (TC-1…TC-11) green in CI
  (AND-050 unit job + emulator job).
- No new endpoints/DTOs; public read confirmed to bypass refresh authenticator.
- Strings externalized; TalkBack pass on share/CTA/states; RTL spot-checked.
- Telemetry events firing with correct `source`/`cold_start`/`method` props.
- Lint/detekt/ktlint (AND-005) clean; no new warnings in `feature-profile`/`app`.
- OQ-1/OQ-2/OQ-3 resolved or explicitly deferred with an owner noted in the PR.
- PR reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
**OpenAPI index** = `reference/openapi.index.txt`; **OpenAPI spec** =
`reference/openapi.pretty.json`; **FE** = `reference/src/...`.

1. **Public-profile payload endpoint is `GET /ui/profile/public/{identifier}`.**
   VERDICT: Corrected (spec previously said `GET /ui/profile/meta/{identifier}`).
   SOURCE: OpenAPI `GET /ui/profile/public/{identifier}` (op
   `get_public_profile_ui_profile_public__identifier__get`); FE
   `src/api/endpoints/profile.ts: getPublicProfile`.

2. **`GET /ui/profile/meta/{identifier}` is SEO meta tags, not the screen
   payload.** VERDICT: Verified. SOURCE: OpenAPI spec `/ui/profile/meta/{identifier}`
   description "Lightweight meta tag data for SEO. No auth required."

3. **The public read is callable unauthenticated.** VERDICT: Verified. SOURCE:
   OpenAPI spec `/ui/profile/public/{identifier}` description "Auth is optional
   -- unauthenticated callers get follow fields as False."

4. **Success DTO field names (`user_id`, `display_name`, `description`,
   `profile_photo_url`, `cover_photo_url`, counts, follow flags,
   `has_subscription_plans`, `canonical_identifier`, `created_at`,
   `discoverability`).** VERDICT: Corrected (spec used `bio`/`avatar_url`/`links`/
   `is_private`, none of which exist). SOURCE: FE `src/api/types.ts:
   PublicProfileData`.

5. **No distinct `403`/private response; private+missing are both `404`.**
   VERDICT: Corrected. SOURCE: OpenAPI declares only `200` and `422` for the
   path; FE `src/api/endpoints/profile.ts: mapProfileLookupError` maps `404` →
   code `not_found_or_suppressed`; FE `src/pages/profile/PublicUserProfilePage.tsx`
   handles only `404`/`429`/generic, with no private branch.

6. **`429` rate-limited is a real handled case.** VERDICT: Corrected (added;
   previously omitted). SOURCE: FE `mapProfileLookupError` (`429` → `rate_limited`)
   and `PublicUserProfilePage.tsx` (`status === 429` ErrorPage).

7. **`422 HTTPValidationError` is the only declared non-200 schema.** VERDICT:
   Verified. SOURCE: OpenAPI index line for the path
   (`resp=200:;422:HTTPValidationError`).

8. **Normalization should defer to server `canonical_identifier` rather than
   client lower-casing.** VERDICT: Corrected/Recommendation. SOURCE: FE
   `PublicUserProfilePage.tsx` canonical-redirect effect + `getProfileByIdentifier`
   (trim/encode only, no lower-case); `PublicProfileData.canonical_identifier`.

9. **Refresh authenticator endpoint is `POST /ui/session/refresh` and must be
   bypassed for the public read.** VERDICT: Verified. SOURCE: OpenAPI
   `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`);
   FE `src/api/client.ts` refresh call to `/ui/session/refresh`.

10. **Web auth transport is cookie-based with CSRF via `ui_csrf` cookie →
    `X-CSRF-Token` header; not required for this GET.** VERDICT: Verified.
    SOURCE: FE `src/api/client.ts` (`credentials: "include"`, `getCookie("ui_csrf")`,
    `headers.set("X-CSRF-Token", csrf)`).

11. **`GET /ui/me` exists for auth state (AND-029 `AuthStateStore`).** VERDICT:
    Verified. SOURCE: OpenAPI `GET /ui/me` (op `ui_me_ui_me_get`).

12. **Web `/u/:identifier` route renders unauthenticated and gates affordances on
    auth (follow/message/add-contact shown only when authenticated & not own
    profile; "Sign in to view more" shown when signed out).** VERDICT: Verified.
    SOURCE: FE `PublicUserProfilePage.tsx` (`isAuthenticated`, `canUseMemberActions`,
    signed-out "Sign in" button).

13. **Canonical share URL shape `/u/{identifier}`.** VERDICT: Verified (matches
    web canonical). SOURCE: FE `PublicUserProfilePage.tsx` Helmet `og:url` /
    `link rel="canonical"` = `${window.location.origin}/u/${canonicalIdentifier}`.

14. **Native Android share sheet (`ACTION_SEND`) + copy-link are net-new Android
    affordances.** VERDICT: Unverified-assumption (no web equivalent — web relies
    on OG meta tags + browser share). Reasonable Android UX; flagged. SOURCE: FE
    `PublicUserProfilePage.tsx` has no in-app share/copy control.

15. **Android framework choices (App Links `autoVerify`, `singleTask` +
    `onNewIntent`, Navigation Compose `navDeepLink`, `Intent.createChooser`,
    `ClipboardManager`).** VERDICT: Unverified-assumption (framework refs, not in
    repo sources). SOURCE (framework ref):
    https://developer.android.com/training/app-links ,
    https://developer.android.com/guide/navigation/navigation-deep-link ,
    https://developer.android.com/training/sharing/send .

16. **`assetlinks.json` Digital Asset Links published for `testlogon.com`.**
    VERDICT: Unverified-assumption (backend/web concern; not in provided sources).

17. **Production host is `testlogon.com` (App Link host).** VERDICT:
    Unverified-assumption. The web reference uses `window.location.origin`
    (runtime), so the literal host is not pinned in source. SOURCE: FE
    `PublicUserProfilePage.tsx` (`window.location.origin`).

### Corrections made

- Endpoint `GET /ui/profile/meta/{identifier}` → `GET /ui/profile/public/{identifier}`
  (§2, §5, §7); wrapper `getProfileMeta` → `getPublicProfile` (§5, §11 TC-6).
- Success DTO rewritten to the real `PublicProfileData` fields; removed
  `bio`/`avatar_url`/`links`/`is_private` (§5).
- Removed the non-existent `403`/private response; private/suppressed folded into
  `404` (§3 FR-4, §5, §6 `Phase`, §8, §11 TC-5, §14 AC-4, §10 telemetry).
- Added the verified `429` rate-limited case (§5, §6 `Phase`, §11 TC-5, §14 AC-4,
  §10 telemetry).
- Reworked OQ-1 to prefer server `canonical_identifier` over client lower-casing
  (§13).

### Open assumptions

- **Net-new share/copy UI (claim 14):** no web counterpart to verify against;
  taken as an Android-native UX decision.
- **Android framework behaviors (claim 15):** verified only against Android docs,
  not project sources — labeled framework refs.
- **`assetlinks.json` publication & production host = `testlogon.com` (claims 16,
  17):** owned by web/backend; not present in the provided sources. App Link
  auto-verification (and thus TC-AND-390-07's device verification leg) cannot be
  asserted from these sources — confirm with the web/backend team (mirrors OQ-2).
- **FR-7 "report"/"edit" affordances:** the web page exposes follow / message /
  add-contact (no report/edit on this screen). The Android list of suppressed
  affordances is broader than the web reference; their existence is owned by other
  tickets and is unverified here.

## 17. Test Plan

Test targets (per the CI/dev inventory): **JVM** = local JVM/Robolectric, no
device; **emu35** = headless AVD `test35`, x86_64, Android 15 / API 35;
**device** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R),
Android 14 / API 34, arm64-v8a, via adb on the build host. Hardware/OS-edge cases
prefer **device**.

- **TC-AND-390-01** — Type: unit (JVM). Target: JVM. Preconditions:
  `DeepLinkResolver` instance. Steps: resolve an `ACTION_VIEW` intent with data
  `https://testlogon.com/u/Ada`. Expected: returns
  `StartDestination.PublicProfile("ada")` after trim/decode/normalize (or the
  server-canonical value once OQ-1 lands). Traces: AC-1, AC-3.

- **TC-AND-390-02** — Type: unit (JVM). Target: JVM. Preconditions: resolver.
  Steps: resolve `testlogon://u/ada`. Expected:
  `StartDestination.PublicProfile("ada")`. Traces: AC-2.

- **TC-AND-390-03** — Type: unit (JVM). Target: JVM. Preconditions: resolver.
  Steps: resolve each of `https://testlogon.com/u/` (empty),
  `https://testlogon.com/x/y` (wrong prefix), `testlogon://u/%20%20`
  (whitespace), and a malformed URI. Expected: each yields `Default` (→ launch
  default / not-found) and never throws. Traces: AC-3.

- **TC-AND-390-04** — Type: unit (JVM). Target: JVM. Preconditions:
  `ProfileShareHelper` with the Retrofit base URL pointed at the dev host
  `http://18.222.237.167:8000`. Steps: call `shareUrl("ada")`. Expected: returns
  `https://testlogon.com/u/ada` (always production host, never the dev base
  URL). Traces: AC-5.

- **TC-AND-390-05** — Type: unit (JVM/Robolectric). Target: JVM. Preconditions:
  `PublicProfileViewModel` with a fake `ProfileApi`. Steps: feed (a) a `200`
  `PublicProfileData`, (b) a `404`, (c) a `429`, (d) a transport failure.
  Expected: phases `Content` / `NotFound` / `RateLimited` / `Offline`
  respectively; on `Content`, affordances are gated by `isAuthenticated`. Verify
  no `bio`/`avatar_url` mapping — uses `description`/`profile_photo_url`. Traces:
  AC-4, AC-7, AC-10.

- **TC-AND-390-06** — Type: contract/MockWebServer. Target: JVM (AND-046
  harness). Preconditions: empty cookie jar; MockWebServer enqueues a `200`
  `PublicProfileData` for `/ui/profile/public/ada`. Steps: call
  `getPublicProfile("ada")`. Expected: request carries **no** session cookie and
  **no** `X-CSRF-Token`; succeeds; recorder shows **no** `POST /ui/session/refresh`
  was issued. Traces: AC-9.

- **TC-AND-390-07** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  MockWebServer scripted to return `404`, then `429`, then `422`. Steps: call
  `getPublicProfile` for each. Expected: mapped to `NotFound`, `RateLimited`,
  and `NotFound` (malformed) respectively; a `401`, if injected, is mapped to
  NotFound + WARN telemetry and does **not** invoke the refresh authenticator.
  Traces: AC-4, AC-9.

- **TC-AND-390-08** — Type: instrumented/e2e (deep link, cold start). Target:
  emu35 (functional) and **device** (must also pass on API 34/arm64 to cover the
  ABI/API-34-vs-35 difference). Preconditions: signed-out app, process not
  running. Steps: `adb shell am start -a android.intent.action.VIEW -d
  "https://testlogon.com/u/ada"` to a freshly killed app. Expected:
  `PublicProfileScreen` for `ada` renders directly, no login redirect. Traces:
  AC-1.

- **TC-AND-390-09** — Type: Compose-UI/instrumented. Target: emu35.
  Preconditions: signed-out app. Steps: open the public profile; tap Share.
  Expected: Espresso-Intents `intended` captures an `ACTION_SEND` chooser whose
  inner intent has `type=text/plain` and `EXTRA_TEXT ==
  https://testlogon.com/u/ada`. Traces: AC-5, AC-6.

- **TC-AND-390-10** — Type: Compose-UI/instrumented. Target: emu35
  (snackbar path, API 35) **and device** (clipboard-toast suppression on API 34
  is < 33? No — A15 is API 34 ≥ 33, so OS toast shows and in-app snackbar is
  suppressed; the < API 33 snackbar path requires an emu API ≤ 32). Steps: tap
  Copy link. Expected: `ClipboardManager` primary clip == `https://testlogon.com/u/ada`;
  on the < API 33 emulator the in-app confirmation snackbar shows; on API ≥ 33
  (emu35 / device) the in-app snackbar is suppressed (no duplicate feedback) and
  copy still succeeds. Traces: AC-5.

- **TC-AND-390-11** — Type: Compose-UI/instrumented. Target: emu35.
  Preconditions: run twice with `AuthStateStore` signed-out then signed-in.
  Steps: render `PublicProfileScreen`. Expected: signed-out hides
  follow/message/(report/edit) and shows the Sign-in CTA; signed-in shows
  follow/message per their owning tickets. Traces: AC-7.

- **TC-AND-390-12** — Type: instrumented/e2e (back-stack). Target: emu35 and
  **device**. Preconditions: cold-start deep link (single destination on the
  stack). Steps: launch via `ACTION_VIEW` as in TC-08, then press Back. Expected:
  the activity finishes to the launcher (app exits), not into an empty
  authenticated graph; a separate in-app navigation to a profile returns to the
  prior screen on Back. Traces: AC-8.

- **TC-AND-390-13** — Type: manual + instrumented (App Link verification).
  Target: **device** (MUST — real OS Digital Asset Links fetch needs network and
  a published `assetlinks.json`; emulators have no reliable internet asset
  fetch). Preconditions: `assetlinks.json` published for `testlogon.com`; app
  installed. Steps: `adb shell pm get-app-links com.testlogon.android` and tap a
  `https://testlogon.com/u/ada` link from a browser/another app. Expected: domain
  verification state is `verified`; the link opens the app directly without a
  disambiguation chooser. Traces: AC-1, AC-6. (Open assumption: depends on
  `assetlinks.json` / production host — see §16 Open assumptions, OQ-2.)

- **TC-AND-390-14** — Type: instrumented (accessibility). Target: emu35.
  Preconditions: TalkBack enabled (or `AccessibilityChecks` in Espresso).
  Steps: traverse the loading shimmer, then the loaded content, then the
  not-found state. Expected: share/copy controls expose
  `contentDescription` (`cd_share_profile`, `cd_copy_link`) with ≥48dp targets;
  shimmer placeholders are excluded from TalkBack order once content loads; focus
  moves to the Sign-in CTA on the not-found state; layout passes in RTL with the
  share URL LTR-isolated. Traces: AC-4, AC-7, AC-10.

- **TC-AND-390-15** — Type: integration (flaky-host/offline). Target: emu35
  (airplane mode / network shaping) — JVM/MockWebServer covers timeout logic in
  TC-07; this validates real UI. Preconditions: device offline or dev host
  unreachable. Steps: open a public profile. Expected: after bounded backoff
  (AND-016) / ~20s timeout (AND-009) the `Offline` state with a Retry button is
  shown — **never** a login redirect; Retry re-issues the GET. Traces: AC-1,
  AC-10.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1  | TC-AND-390-01, TC-AND-390-08, TC-AND-390-13, TC-AND-390-15 |
| AC-2  | TC-AND-390-02 |
| AC-3  | TC-AND-390-01, TC-AND-390-03 |
| AC-4  | TC-AND-390-05, TC-AND-390-07, TC-AND-390-14 |
| AC-5  | TC-AND-390-04, TC-AND-390-09, TC-AND-390-10 |
| AC-6  | TC-AND-390-09, TC-AND-390-13 |
| AC-7  | TC-AND-390-05, TC-AND-390-11, TC-AND-390-14 |
| AC-8  | TC-AND-390-12 |
| AC-9  | TC-AND-390-06, TC-AND-390-07 |
| AC-10 | TC-AND-390-05, TC-AND-390-14, TC-AND-390-15 |

---
id: AND-390
title: Public profile polish
milestone: M8
epic: E51
priority: P2
size: M
status: draft
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
  only). Public profile metadata served by `GET /ui/profile/meta/{identifier}`.
  OpenAPI at `/openapi.json`.

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

FR-4. **Private & missing handling (inherited).** A `403`/private response shows
the private-profile state and a "Sign in to view" CTA; a `404` shows the
not-found state. These states are defined in AND-073; AND-390 only adds the CTA
copy and the unauth-aware sign-in action.

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
existing public-metadata endpoint owned by AND-070 / AND-073:

`GET /ui/profile/meta/{identifier}` — idempotent, cacheable, callable
unauthenticated. Wrapped by `ProfileApi.getProfileMeta(identifier)` returning
`ApiResult<PublicProfileDto>` (typed result per AND-018). Eligible for the
bounded-backoff retry policy (AND-016, idempotent GET) and the ~20s OkHttp
timeout (AND-009).

Representative success (`200`) shape (subset; canonical definition in AND-070):

```json
{
  "identifier": "ada",
  "display_name": "Ada Lovelace",
  "bio": "Mathematician.",
  "avatar_url": "https://.../ada.png",
  "links": [{ "label": "site", "url": "https://example.com" }],
  "is_private": false
}
```

Failure shapes (FastAPI `detail`, mapped by AND-015 to `ApiError`):

- `404` → `{ "detail": "profile_not_found" }` → not-found state (FR-3/FR-4).
- `403` → `{ "detail": "profile_private" }` → private state + sign-in CTA.
- `401` → MUST NOT occur for this public endpoint; if it does, treat as
  not-found and log a telemetry warning (do **not** trigger the AND-013 refresh
  authenticator for the public read path).

Cookies/CSRF: the public read works with **no** session cookie. The persistent
cookie jar (AND-011) and CSRF header (AND-012) are not required for this call;
if a session exists it may ride along harmlessly.

## 6. Data & State Management

ViewModel exposes `StateFlow<PublicProfileUiState>` (from AND-073, extended):

```kotlin
data class PublicProfileUiState(
    val identifier: String,
    val phase: Phase,                       // Loading | Content | NotFound | Private | Offline
    val profile: PublicProfileUi? = null,
    val isAuthenticated: Boolean = false,   // collected from AuthStateStore
    val shareUrl: String? = null,
    val snackbar: SnackbarEvent? = null,    // one-shot copy/share feedback
)

enum class Phase { Loading, Content, NotFound, Private, Offline }
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
  authenticator for `GET /ui/profile/meta/**` so an unauthenticated open never
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
- Private profiles (`403`) MUST NOT leak any field beyond the private-state
  message; the ViewModel discards the body on `403`.
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
- `public_profile_result` — props: `phase` (`content`/`not_found`/`private`/
  `offline`), `latency_ms`.
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
- TC-5 ViewModel: `403` → `Phase.Private`; `404` → `Phase.NotFound`; success →
  `Phase.Content` with affordances gated by `isAuthenticated`.

Repository/contract (MockWebServer, AND-046 harness):

- TC-6 `getProfileMeta` succeeds with **no** cookie jar entry (unauth read);
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
  lower-case) or opaque IDs? Current design lower-cases only values matching
  `USERNAME_RE` and passes others through. Confirm against `profile.ts` /
  backend routing.
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

AC-4. Private (`403`) and missing (`404`) profiles show their respective states
with a working "Sign in to view" CTA. *(FR-4; TC-5.)*

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

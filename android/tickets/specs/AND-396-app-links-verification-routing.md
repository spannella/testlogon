---
id: AND-396
title: App Links verification + routing
milestone: M8
epic: E51
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-022]
blocks: []
---

# AND-396 — App Links verification + routing

## 1. Overview & Goal

Enable Android **App Links** (HTTP/HTTPS `autoVerify` deep links) so that tapping a TestLogon URL in a browser, email, chat, or notification opens the native app directly — without the Android disambiguation chooser — and lands the user on the correct in-app destination. This ticket delivers two coupled pieces:

1. **Verification plumbing** — the `intent-filter` declarations with `android:autoVerify="true"`, the host/path matrix, and the server-side `/.well-known/assetlinks.json` Digital Asset Links file that proves domain ownership for the app's signing certificates.
2. **A central deep-link router** — a single, testable Kotlin component that parses an inbound `Uri`, maps it to a typed Navigation-Compose route (from AND-022), and either navigates immediately or defers the navigation until the app is authenticated / the back stack is ready.

Goal: a verified App Link to a canonical TestLogon path (e.g. `https://app.testlogon.com/videos/{videoId}` — note the original `/media/{id}` example was not a real route; see FR-2 correction) opens the app directly and navigates to the matching screen, with graceful, deterministic fallbacks for unauthenticated users, unknown paths, and unverified build variants.

This is a **Chore** in backlog terms (no new product surface), but it touches manifest, signing, navigation, and a hosted static asset, so it is sized **M**.

## 2. Context & References

- **Depends on AND-022 (Navigation host & routes):** the central router targets the typed route definitions and the single-Activity `NavHost` created there. This ticket does **not** redefine routes; it maps URIs onto them.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow. minSdk 24, compileSdk/targetSdk 35, AGP 8.7.3, Gradle 8.9.
- **Namespace / applicationId base:** `com.testlogon.android` (used for the verified app statement and the launcher Activity reference).
- **Auth model:** session is established via `POST /ui/session/start` (returns `UiSessionStartResp { auth_required, challenge_id?, required_factors[], session_id? }`) → MFA challenge → `POST /ui/session/finalize` (`UiSessionFinalizeReq { challenge_id, remember_device }`) → `GET /ui/me`. **Correction:** the web client (`src/api/client.ts`) is **not** purely cookie-based — it sends `Authorization: Bearer <accessToken>` from the auth store, a CSRF token from the `ui_csrf` cookie as the `X-CSRF-Token` header, and `credentials: "include"` (so a session cookie travels too); authenticated UI endpoints also accept an `X-SESSION-ID` header (per OpenAPI). Refresh is `POST /ui/session/refresh` on 401. This ticket's router performs **no** auth I/O; it only observes `SessionStateProvider.isAuthenticated`, so the exact transport is informational here. Deep links that resolve to authenticated destinations must defer navigation until a session exists, then resume.
- **Web reference:** the canonical URL shapes mirror the web app under `frontend/`; the router's path table is derived from the web routes so a shared link works on both platforms.
- **Android docs of record:** App Links verification (`autoVerify`), Digital Asset Links `assetlinks.json`, `adb shell pm verify-app-links` / `App Links Assistant`, `Statement List Generator and Tester`.

## 3. Functional Requirements

FR-1. Declare `intent-filter`s with `android:autoVerify="true"` on the single launcher Activity (`com.testlogon.android.MainActivity`) for the production host(s) over `https` (and `http` only where required for fallback; see SEC-2).

FR-2. Support, at minimum, these verified path patterns. **Correction:** the original list (`/media/{id}`, `/library`, `/library/{section}`, `/settings/{section}`, `/auth/*`) does **not** match the actual web routing in `reference/src/App.tsx` — there is **no** `/media/{id}`, `/library`, or `/auth/*` route, and Settings uses fixed sub-paths, not a generic `{section}` param. The list below is derived from the real `react-router` routes (`BrowserRouter`, no `basename`, so paths are root-relative). Public (no-auth) routes are the highest-value deep-link targets:
- `https://{host}/` → Home (`<Route index>` → Dashboard)
- Authenticated content detail (replaces the fictional `/media/{id}`): `https://{host}/videos/{videoId}`, `/gallery/{videoId}`, `/posts/{postId}`, `/clips/{clipId}`, `/shop/{categoryId}/{itemId}`
- Public/unauthenticated, ideal for shared App Links: `https://{host}/u/{identifier}` (public profile), `/share/{linkId}` (download), `/c/{clipId}` (public clip), `/event/{calendarId}/{eventId}`, `/donate/{fundraiserId}`
- Settings: `https://{host}/settings` plus the fixed sub-routes that actually exist (`/settings/privacy`, `/settings/theme`, `/settings/blocked`, `/settings/webhooks`, `/settings/geo`, …) — match these literally, not a wildcard `{section}`
- Auth handoff: top-level `/login`, `/register`, `/password-recovery`, `/magic-link-verify` (there is no `/auth/*` namespace)

The exact subset to ship is confirmed against AND-022's typed routes (see OQ-1); only paths that have a corresponding native `Route` should be verified, the rest fall through to `Unhandled`.

FR-3. A single router parses any inbound `Uri` into a sealed `DeepLink` result and produces either a typed `Route` or a typed failure (`Unhandled`, `RequiresAuth`, `Malformed`).

FR-4. When the app is launched **cold** from a verified link, the router resolves and navigates after the `NavHost` is composed, replacing (not stacking on top of) the default start destination so Back behaves naturally.

FR-5. When the app is **already running** (warm), `onNewIntent` re-runs the router and navigates without recreating the Activity (`launchMode="singleTask"`).

FR-6. Links to authenticated destinations encountered while logged out are **buffered**; after a successful session finalize the buffered link is consumed exactly once and navigation resumes; otherwise the user lands on the auth screen.

FR-7. Unknown / unmapped verified paths route to a safe default (Home) and emit telemetry; they never crash or show a blank screen.

FR-8. The hosted `assetlinks.json` lists SHA-256 cert fingerprints for **debug**, **internal/staging**, and **release/Play App Signing** keys so verification passes across variants.

## 4. Technical Design

### 4.1 Manifest & intent filters
`MainActivity` (created in AND-022) gains a verified intent filter. Host and scheme strings are injected from `build.gradle.kts` `manifestPlaceholders` per flavor so non-prod variants do not hijack prod links.

```xml
<activity
    android:name="com.testlogon.android.MainActivity"
    android:exported="true"
    android:launchMode="singleTask">
  <intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="${appLinkHost}" />
    <data android:scheme="http"  android:host="${appLinkHost}" />
  </intent-filter>
</activity>
```

`manifestPlaceholders["appLinkHost"]` = `app.testlogon.com` (release), `staging.testlogon.com` (internal), etc. Custom-scheme links (`testlogon://`) are **out of scope** here and tracked separately; this ticket is HTTP(S) App Links only.

### 4.2 Router contract (`core-ui` or a new `core-navigation` module)

```kotlin
sealed interface DeepLink {
    data class Resolved(val route: Route, val requiresAuth: Boolean) : DeepLink
    data object RequiresAuth : DeepLink         // resolved but session absent
    data object Unhandled   : DeepLink          // host matched, path unknown
    data object Malformed   : DeepLink          // not parseable / wrong host
}

interface DeepLinkParser {
    /** Pure function: Uri -> DeepLink. No navigation, no I/O. Unit-testable. */
    fun parse(uri: Uri): DeepLink
}

@Singleton
class DeepLinkParserImpl @Inject constructor(
    @AppLinkHosts private val verifiedHosts: Set<String>,
) : DeepLinkParser { /* path table matching, segment extraction */ }
```

```kotlin
@Singleton
class DeepLinkRouter @Inject constructor(
    private val parser: DeepLinkParser,
    private val session: SessionStateProvider,   // from auth module
) {
    private val _pending = MutableStateFlow<DeepLink.Resolved?>(null)
    val pending: StateFlow<DeepLink.Resolved?> = _pending.asStateFlow()

    /** Called from Activity for cold start + onNewIntent. */
    fun onIntent(intent: Intent?)

    /** Called by NavHost host composable once ready; performs navigate or buffers. */
    fun consume(navController: NavController)

    /** Called after successful session finalize to flush a buffered authed link. */
    fun onAuthenticated(navController: NavController)
}
```

### 4.3 Activity integration

```kotlin
@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    @Inject lateinit var router: DeepLinkRouter
    override fun onCreate(b: Bundle?) { super.onCreate(b); router.onIntent(intent); setContent { App(router) } }
    override fun onNewIntent(i: Intent) { super.onNewIntent(i); setIntent(i); router.onIntent(i) }
}
```

Inside the root composable, a `LaunchedEffect(navController)` calls `router.consume(navController)`; an additional effect keyed on `session.isAuthenticated` calls `router.onAuthenticated(...)`. Mapping `Route` → `navController.navigate(...)` reuses the typed route extension functions from AND-022; the router never constructs raw route strings inline.

### 4.4 assetlinks.json (server side, `frontend/public/.well-known/`)

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.testlogon.android",
    "sha256_cert_fingerprints": [
      "AA:BB:...:debug",
      "AA:BB:...:staging",
      "AA:BB:...:play-app-signing"
    ]
  }
}]
```

Served at `https://app.testlogon.com/.well-known/assetlinks.json`, `Content-Type: application/json`, HTTP 200, no redirects, publicly reachable without auth. Fingerprints are pulled via `./gradlew signingReport` (debug/staging) and from the Play Console → App integrity (release upload + Play-managed signing key).

## 5. API Contract

This ticket has **no FastAPI/Retrofit endpoint dependency** for its core behavior. The only HTTP contract is the static Digital Asset Links file:

- `GET https://{host}/.well-known/assetlinks.json` → `200 OK`, body = the JSON array above, served as static content from `frontend/`. No CSRF, no cookies, must not 30x redirect (the Android verifier rejects redirects).

Authenticated **destinations** reached via a deep link consume their own data endpoints, but those contracts are owned by the respective feature tickets, not here. The router only produces the typed route; it performs no network I/O. **Correction:** the original example `GET /ui/media/{id}` does **not** exist in the backend — the only `/ui/media/*` endpoints are `GET`/`PUT /ui/media/preferences`. A video-detail destination would call its own feature endpoint (owned elsewhere); this ticket does not bind any such call.

## 6. Data & State Management

- **Pending-link buffer:** held in `DeepLinkRouter` as `StateFlow<DeepLink.Resolved?>`, process-scoped (`@Singleton`). It is intentionally **not** persisted to DataStore/Room — a deferred deep link should not survive a full process death/relaunch, to avoid surprising navigation later.
- **Consumption is single-shot:** `consume`/`onAuthenticated` set `_pending.value = null` after a successful `navigate`, guarding against double-navigation on recomposition or config change.
- **Session signal:** the router observes `SessionStateProvider.isAuthenticated: StateFlow<Boolean>` (existing auth module) to decide buffer vs. immediate navigation; it does not own session state.
- **Route mapping table** is a pure, immutable `Map`/`when` in `DeepLinkParserImpl` — no mutable shared state, fully reproducible for tests.

## 7. Error Handling & Resilience

- `parse` is total: every `Uri` yields one of the four `DeepLink` variants; no exceptions escape.
- `Malformed` / `Unhandled` → navigate to Home start destination and log; never blank screen, never crash.
- `RequiresAuth` → buffer and route to auth; if the user abandons auth, the buffer is cleared on next cold start.
- Verification independence: even if `assetlinks.json` verification has **not** completed (e.g., DAL file temporarily unreachable, or a non-verified variant), the same `intent-filter` still allows the link to open via the chooser, and the router behaves identically — verification only removes the chooser, it does not change routing logic.
- Network-flakiness (the unreliable dev backend) does not affect routing; the router is offline-safe because it does no I/O. Destination screens own their own ~20s timeout / stale-UI handling.

## 8. Security & Privacy

- SEC-1. Only **explicitly verified hosts** (`verifiedHosts` set) are accepted; any other host → `Malformed`. This prevents an attacker-controlled domain from invoking authenticated routes.
- SEC-2. Prefer `https`; include `http` only if legacy links require it. The dev backend is plaintext HTTP, but **production App Links must be HTTPS** for verification to succeed — `http` is not auto-verifiable.
- SEC-3. Deep-link parameters (`{id}`, `{section}`) are treated as untrusted input: validated/sanitized before being placed on routes; no parameter is used to build file paths, SQL, or raw network URLs.
- SEC-4. `assetlinks.json` pins SHA-256 fingerprints for exactly the intended signing keys; release uses the **Play App Signing** key fingerprint. Compromised/rotated keys require updating the hosted file.
- SEC-5. No PII or tokens are ever encoded in deep-link query params by us; if present in an inbound link, they are dropped, never logged.
- SEC-6. `android:exported="true"` is required for App Links; mitigated by host allowlisting and auth-gating sensitive destinations.

## 9. Accessibility & i18n

Largely **N/A** for this chore — the router renders no UI of its own. Two requirements apply:
- Any fallback/error surface (e.g., a transient "couldn't open this link" toast/snackbar, if shown) uses localized string resources and is announced to TalkBack.
- Deep-linked destinations must arrive with focus on the screen's primary content; the router relies on the destination composables (owned by feature tickets) for correct accessibility focus, and must not steal focus or suppress screen-reader announcements during navigation.

## 10. Telemetry & Logging

Emit structured analytics events (via the app's existing analytics abstraction) — never log full URLs with query strings at info level:
- `deeplink_received` { host, path_template, source: cold|warm }
- `deeplink_resolved` { route_name, required_auth }
- `deeplink_deferred_auth` and `deeplink_resumed_after_auth`
- `deeplink_unhandled` { host, path_template } and `deeplink_malformed`

Path **templates** (e.g. `/media/{id}`) are logged, not raw IDs, to avoid leaking identifiers. App Links verification status is observable out-of-band via `adb shell pm get-app-links com.testlogon.android` and surfaced in CI logs, not in app telemetry.

## 11. Testing Strategy

**Unit (core-testing, JVM):**
- `DeepLinkParserImpl` table tests: each supported path → expected `Route`; unknown path → `Unhandled`; wrong host → `Malformed`; missing/garbage segments → `Malformed`. Use `androidx.core.net.toUri` with Robolectric or a `Uri` shim.
- `DeepLinkRouter` state tests with a fake `SessionStateProvider`: authed link while logged in navigates immediately; authed link while logged out buffers, then flushes on `onAuthenticated`; single-shot consumption (no double navigate).

**Instrumented (androidTest):**
- Espresso/Compose test that fires `Intent(ACTION_VIEW, "https://app.testlogon.com/videos/123".toUri())` at `MainActivity` and asserts the video-detail destination is current via `navController.currentBackStackEntry` (was `/media/123`, which is not a real web route — corrected).
- `onNewIntent` warm-path test (don't recreate Activity).

**Verification / manual + CI:**
- `adb shell pm verify-app-links --re-verify com.testlogon.android` then `pm get-app-links` must report `verified` for the prod host in a release-signed build.
- Google's Statement List Tester against the deployed `assetlinks.json`.
- A CI smoke step curls `https://app.testlogon.com/.well-known/assetlinks.json` and asserts 200 + valid JSON + correct `package_name`.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-022 (Navigation host & routes) — typed `Route` definitions and the single-Activity `NavHost` must exist; the router maps onto them.
- **Soft dependency:** the auth/session module providing `SessionStateProvider` (for the `RequiresAuth` buffering path). If unavailable at implementation time, ship with a stub provider that always reports authenticated and wire the real one in a follow-up.
- **Coordination:** server/web team must deploy `assetlinks.json` to `frontend/public/.well-known/` and provide release fingerprints from Play Console before release-build verification can pass.
- **Sequencing:** land manifest + parser + router + unit tests first (no external blockers); deploy DAL file and run `pm verify-app-links` once a signed build exists.

## 13. Risks & Open Questions

- OQ-1. **Canonical host & exact path table** — confirm production host(s) and the full route list against `frontend/` routing; the FR-2 list is provisional.
- R-1. **Fingerprint drift:** Play App Signing key differs from the local upload key; using the wrong fingerprint silently fails verification. Mitigation: pull from Play Console, include all variant fingerprints.
- R-2. **DAL file redirects/caching:** a CDN redirect or wrong `Content-Type` breaks verification. Mitigation: CI assertion (Section 11).
- R-3. **minSdk 24 verification behavior:** auto-verification UX/strictness changed across OS versions (notably 12+); test on API 24, 31, and 35.
- R-4. **Multiple verified apps / staging hijack:** staging variant verifying the prod host would steal links. Mitigation: per-flavor `manifestPlaceholders` hosts.
- OQ-2. Is a custom scheme (`testlogon://`) needed for any internal flows? Currently out of scope.

## 14. Acceptance Criteria

- AC-1 (backlog): A **verified** App Link to a supported TestLogon path opens the app directly, with no disambiguation chooser, on a release-signed build whose host reports `verified` via `pm get-app-links`.
- AC-2: `https://app.testlogon.com/videos/{videoId}` (a real web route; was `/media/{id}`) cold-launch navigates to the video-detail destination; warm `onNewIntent` does the same without recreating the Activity.
- AC-3: An authenticated-destination link opened while logged out routes to auth, then resumes to the original destination exactly once after session finalize.
- AC-4: Unknown supported-host paths route to Home and emit `deeplink_unhandled`; non-allowlisted hosts are rejected (`Malformed`) and never navigate to authed routes.
- AC-5: `GET /.well-known/assetlinks.json` returns 200, valid JSON, `package_name == com.testlogon.android`, and contains debug/staging/release fingerprints.
- AC-6: `DeepLinkParser` and `DeepLinkRouter` unit tests pass; instrumented intent test asserts the correct current destination.

## 15. Definition of Done

- Manifest intent filters with `android:autoVerify="true"` and per-flavor host placeholders merged; launcher Activity is `singleTask`.
- `DeepLinkParser`, `DeepLinkRouter`, and Hilt bindings implemented under the navigation/core module and wired into `MainActivity` + root composable.
- `assetlinks.json` authored, reviewed, and deployed to the production host; CI smoke check added.
- Unit + instrumented tests green in CI; `pm verify-app-links` confirms `verified` on a release-signed build (evidence attached to the PR).
- Telemetry events emitted with path templates only (no raw IDs/PII); no full-URL logging at info level.
- Open Questions OQ-1/OQ-2 resolved or explicitly deferred with owners; PR references AND-022 and links the deployed DAL URL.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec (`reference/openapi.pretty.json`, `components.schemas.*`), frontend source (`reference/src/**`), or Android framework docs.

1. **Auth flow is `POST /ui/session/start` → MFA → `POST /ui/session/finalize` → `GET /ui/me`.** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/start` (op `ui_session_start_ui_session_start_post`, req `UiSessionStartReq`, resp `200:UiSessionStartResp`), `POST /ui/session/finalize` (req `UiSessionFinalizeReq`), `GET /ui/me` (op `ui_me_ui_me_get`). Schemas at `openapi.pretty.json: components.schemas.UiSessionStartResp { auth_required, challenge_id?, required_factors[], session_id? }` and `UiSessionFinalizeReq { challenge_id, remember_device }`.
2. **Session is "cookie-based".** VERDICT: Corrected. The web client uses `Authorization: Bearer <accessToken>` + `X-CSRF-Token` (from the `ui_csrf` cookie) + `credentials: "include"`, and UI endpoints accept an `X-SESSION-ID` header. SOURCE: `src/api/client.ts` (lines ~157-171 set Bearer + `X-CSRF-Token`; line ~183 `credentials: "include"`); OpenAPI params column shows `X-SESSION-ID` on `/ui/*` endpoints. Refresh path: `POST /ui/session/refresh` (`src/api/client.ts: refreshSession`).
3. **Media detail is reached via `GET /ui/media/{id}`.** VERDICT: Corrected. No such endpoint exists; the only `/ui/media/*` routes are `GET`/`PUT /ui/media/preferences`. SOURCE: OpenAPI `GET /ui/media/preferences` (`MediaPreferencesOut`), `PUT /ui/media/preferences` (`MediaPreferencesIn`); `src/api/endpoints/mediaPreferences.ts`. The router does no I/O, so no endpoint binding is required here.
4. **Web route `/media/{id}` (Media detail).** VERDICT: Corrected — route does not exist. Real content-detail routes: `/videos/:videoId`, `/gallery/:videoId`, `/posts/:postId`, `/clips/:clipId`, `/shop/:categoryId/:itemId`, `/vod/:videoId/free-with-ads`. SOURCE: `src/App.tsx` (lines ~331, 339, 356-360, 365).
5. **Web routes `/library` and `/library/{section}`.** VERDICT: Corrected — no `/library` route exists. The only "library" path is `/licenses/library` (Licensed Library nav, `src/components/layout/MobileNav.tsx:88`). SOURCE: `src/App.tsx` (no `/library` match); `MobileNav.tsx`.
6. **Web route `/settings/{section}` (generic param).** VERDICT: Corrected — Settings uses fixed sub-paths, not a wildcard param: `/settings`, `/settings/privacy`, `/settings/theme`, `/settings/account-deletion`, `/settings/blocked`, `/settings/webhooks`, `/settings/emojis`, `/settings/geo`. SOURCE: `src/App.tsx` (lines ~383-390).
7. **Web route `/auth/*` (auth flow handoff).** VERDICT: Corrected — no `/auth` namespace. Auth pages are top-level: `/login`, `/register`, `/password-recovery`, `/magic-link-verify`. SOURCE: `src/App.tsx` (lines ~275-278).
8. **Web route `/` → Home.** VERDICT: Verified. `<Route index element={<Dashboard />}>` under the protected `AppShell`. SOURCE: `src/App.tsx:290`.
9. **Web app uses root-relative paths (no router basename) so App Link paths map 1:1.** VERDICT: Verified. `BrowserRouter` with no `basename`. SOURCE: `src/main.tsx:16,76` (`<BrowserRouter>` with no props).
10. **Public, shareable deep-link targets exist (high-value App Links).** VERDICT: Verified. `/u/:identifier`, `/share/:linkId`, `/c/:clipId`, `/event/:calendarId/:eventId`, `/donate/:fundraiserId` are rendered outside `ProtectedRoute`. SOURCE: `src/App.tsx` (lines ~279-283).
11. **Validation errors return `HTTPValidationError { detail: ValidationError[] }`.** VERDICT: Verified (relevant for destination screens, not the router). SOURCE: `openapi.pretty.json: components.schemas.HTTPValidationError` / `ValidationError`; all `/ui/*` ops list `422:HTTPValidationError`. Client normalizes via `src/api/client.ts: normalizeErrorDetail`.
12. **`assetlinks.json` schema: `relation: ["delegate_permission/common.handle_all_urls"]`, `target.namespace: "android_app"`, `package_name`, `sha256_cert_fingerprints[]`; must be 200, `application/json`, no redirects.** VERDICT: Verified (framework ref). SOURCE: framework ref — Android Digital Asset Links / App Links verification docs (`developer.android.com/training/app-links/verify-android-applinks`).
13. **`android:autoVerify="true"` on an `ACTION_VIEW` + `BROWSABLE` + `DEFAULT` `https` intent-filter triggers automatic App Links verification.** VERDICT: Verified (framework ref). SOURCE: framework ref — `developer.android.com/training/app-links` (declare-app-links / auto-verify).
14. **`adb shell pm verify-app-links` / `pm get-app-links` report verification status.** VERDICT: Verified (framework ref). SOURCE: framework ref — `developer.android.com/training/app-links/verify-android-applinks#manual-verification`.
15. **`http` scheme is not auto-verifiable; production App Links require `https`.** VERDICT: Verified (framework ref). SOURCE: framework ref — Android App Links verification requires `https` for the Digital Asset Links check.
16. **Production host is `app.testlogon.com` (and `staging.testlogon.com` for internal).** VERDICT: Unverified-assumption. The host is not present in the reference sources (the web app reads `VITE_API_BASE_URL` from env, `src/api/client.ts:7`). Tracked as OQ-1.
17. **`singleTask` launch mode + `onNewIntent` warm-path routing.** VERDICT: Verified (framework ref). SOURCE: framework ref — `developer.android.com/guide/components/activities/tasks-and-back-stack` and `Activity.onNewIntent`.

### Corrections made
- §2 Auth model: changed "cookie-based session" to the actual Bearer-token + `ui_csrf`/`X-CSRF-Token` + `credentials: include` (+ `X-SESSION-ID`) model, with the verified start/finalize/me schema shapes and the `POST /ui/session/refresh` refresh path. (claims 1, 2)
- §3 FR-2 path table: removed the fictional `/media/{id}`, `/library`/`/library/{section}`, `/auth/*`, and generic `/settings/{section}`; replaced with the real `react-router` routes (content-detail, public, fixed settings sub-paths, top-level auth pages). (claims 4-8, 10)
- §1 Overview example: `/media/{id}` → `/videos/{videoId}`. (claim 4)
- §5 API Contract: removed the non-existent `GET /ui/media/{id}` example; noted only `/ui/media/preferences` exists. (claim 3)
- §11 Testing + §14 AC-2: example intent/URL `/media/123` and `/media/{id}` → `/videos/123` and `/videos/{videoId}`. (claim 4)

### Open assumptions
- **Production/staging hostnames** (`app.testlogon.com`, `staging.testlogon.com`): not derivable from the reference sources (web app uses an env-injected API base URL, not a hardcoded host). Must be confirmed with the web/infra team before authoring `assetlinks.json` and `manifestPlaceholders`. (OQ-1)
- **AND-022 typed `Route` names and the typed navigation extension functions**: this spec assumes they exist and will be the mapping target; they are defined in AND-022, not in any reference source here, so the exact `Route` identifiers used in the parser table are assumed.
- **Custom scheme `testlogon://`**: assumed out of scope (OQ-2); no evidence in sources either way.
- **SHA-256 signing fingerprints** (debug/staging/Play App Signing): only obtainable from `./gradlew signingReport` and the Play Console at build/release time; cannot be verified from sources.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **Emulator** = headless AVD `test35` (x86_64, API 35); **Device** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). App Links auto-verification behavior is OS/host dependent, so verification cases note the required target explicitly.

- **TC-AND-396-01 — Parser maps a verified content path to the typed route.** Type: unit (JVM/Robolectric). Target: `DeepLinkParserImpl`. Preconditions: `verifiedHosts = {app.testlogon.com}`; route table loaded. Steps: `parse("https://app.testlogon.com/videos/abc123".toUri())`. Expected: returns `DeepLink.Resolved` with the video-detail `Route` and `requiresAuth = true`; the extracted `videoId == "abc123"`. Traces: AC-2, AC-6.
- **TC-AND-396-02 — Parser maps a public path with no auth.** Type: unit (JVM/Robolectric). Target: `DeepLinkParserImpl`. Preconditions: as 01. Steps: `parse("https://app.testlogon.com/share/lnk_9".toUri())` and `parse(".../u/sean".toUri())`. Expected: `Resolved` with `requiresAuth = false` for both; correct segment extraction (`linkId`, `identifier`). Traces: AC-6.
- **TC-AND-396-03 — Unknown path on a verified host → Unhandled.** Type: unit (JVM/Robolectric). Target: `DeepLinkParserImpl`. Preconditions: as 01. Steps: `parse("https://app.testlogon.com/library".toUri())` (a path that does NOT exist in the web app) and `parse(".../nonsense/x".toUri())`. Expected: both return `DeepLink.Unhandled` (host matched, path unknown). Traces: AC-4, AC-6.
- **TC-AND-396-04 — Non-allowlisted host → Malformed; never an authed route.** Type: unit (JVM/Robolectric). Target: `DeepLinkParserImpl`. Preconditions: as 01. Steps: `parse("https://evil.example.com/videos/abc".toUri())`, `parse("https://app.testlogon.com.evil.com/videos/abc".toUri())`, and `parse("notaurl".toUri())`. Expected: all return `DeepLink.Malformed`; no `Resolved`/route is ever produced for a foreign host (security: prevents an attacker domain invoking authed routes). Traces: AC-4 (SEC-1).
- **TC-AND-396-05 — Router navigates immediately when authenticated.** Type: unit (JVM, fake collaborators). Target: `DeepLinkRouter`. Preconditions: fake `SessionStateProvider.isAuthenticated = true`; fake/relaxed `NavController`. Steps: `onIntent(Intent(VIEW, ".../videos/abc"))` then `consume(navController)`. Expected: navigates to the video-detail route once; `pending` becomes `null`. Traces: AC-2.
- **TC-AND-396-06 — Router buffers an authed link when logged out, then flushes once after auth.** Type: unit (JVM, fake collaborators). Target: `DeepLinkRouter`. Preconditions: `isAuthenticated = false`. Steps: `onIntent(VIEW, ".../videos/abc")`; `consume(nav)` (should route to auth and buffer); flip `isAuthenticated = true`; `onAuthenticated(nav)`; then call `onAuthenticated(nav)` a second time. Expected: original destination is navigated exactly once after auth; second `onAuthenticated` is a no-op (single-shot, `pending == null`). Traces: AC-3.
- **TC-AND-396-07 — Single-shot consumption survives recomposition/config-change.** Type: unit (JVM). Target: `DeepLinkRouter`. Preconditions: authed; one resolved pending link. Steps: call `consume(nav)` twice in a row (simulating recomposition). Expected: navigate invoked exactly once; no double-navigation. Traces: AC-2, AC-6.
- **TC-AND-396-08 — Cold-start intent lands on the correct destination.** Type: instrumented/Compose-UI. Target: `MainActivity` + `NavHost`. Preconditions: app installed; signed-in test session (or stub `SessionStateProvider`=authenticated). Steps (Emulator): launch `MainActivity` with `Intent(ACTION_VIEW, "https://app.testlogon.com/videos/123".toUri())`. Expected: `navController.currentBackStackEntry` is the video-detail route; the default start destination is replaced (Back exits, does not return to a stale Home). Traces: AC-2, AC-6.
- **TC-AND-396-09 — Warm `onNewIntent` re-routes without recreating the Activity.** Type: instrumented. Target: `MainActivity` (`singleTask`). Preconditions: `MainActivity` already resident on Home. Steps (Emulator): deliver a second `ACTION_VIEW` intent for `.../posts/p1` to the running instance. Expected: navigates to post-detail; the Activity instance hash is unchanged (no `onCreate` re-run); back stack is sane. Traces: AC-2.
- **TC-AND-396-10 — Unhandled path routes to Home and emits telemetry; no crash/blank.** Type: instrumented. Target: `MainActivity` + analytics fake. Preconditions: analytics test double installed. Steps (Emulator): fire `ACTION_VIEW` for `https://app.testlogon.com/library` (unknown). Expected: current destination is Home; a `deeplink_unhandled` event with `{host, path_template}` is recorded; no crash, no blank screen. Traces: AC-4, AC-7 (FR-7).
- **TC-AND-396-11 — Router is offline-safe under a flaky/unreachable backend.** Type: integration (Emulator, network disabled or dev host unreachable). Target: `DeepLinkRouter` + `MainActivity`. Preconditions: airplane mode or backend unreachable. Steps: fire `ACTION_VIEW` for a public route `.../c/clip1`. Expected: routing/navigation completes with zero network calls (router does no I/O); only the destination screen shows its own offline/timeout state. Traces: AC-4 (resilience, §7).
- **TC-AND-396-12 — Telemetry never logs raw IDs or full URLs at info level.** Type: unit (JVM). Target: telemetry-emitting code path in router. Preconditions: spy on analytics + a log capture. Steps: drive `deeplink_received`/`deeplink_resolved` for `.../videos/secretId123?token=xyz`. Expected: events carry path **templates** (`/videos/{videoId}`) and never the raw id or query string; no full URL appears in info-level logs; query params (`token`) are dropped, never logged. Traces: AC-4 (SEC-5), §10.
- **TC-AND-396-13 — `assetlinks.json` is served correctly (CI contract).** Type: contract/integration (CI HTTP check; JVM/MockWebServer for the schema assertion). Target: hosted DAL file. Preconditions: file deployed to the prod host. Steps: GET `https://app.testlogon.com/.well-known/assetlinks.json`. Expected: HTTP `200`, `Content-Type: application/json`, **no 3xx redirect**, body is a valid DAL array with `relation` containing `delegate_permission/common.handle_all_urls`, `target.namespace == "android_app"`, `package_name == "com.testlogon.android"`, and `sha256_cert_fingerprints` listing the debug/staging/release fingerprints. Traces: AC-5.
- **TC-AND-396-14 — End-to-end App Links verification removes the chooser (release-signed).** Type: instrumented/e2e + manual. Target: installed release-signed build. **MUST run on the physical Device (SM-A156U)** — real on-device verification against the live DAL file and real browser/chooser behavior, and to cover the API-34 (Device) vs API-35 (Emulator) auto-verify difference (R-3). Preconditions: release-signed build installed; DAL deployed; device online. Steps: `adb shell pm verify-app-links --re-verify com.testlogon.android`; `adb shell pm get-app-links com.testlogon.android`; then tap a `https://app.testlogon.com/videos/123` link from an email/browser. Expected: `get-app-links` reports the prod host as `verified`; tapping the link opens the app directly with **no** disambiguation chooser and lands on video-detail. Traces: AC-1, AC-2.
- **TC-AND-396-15 — Per-flavor host isolation (staging does not hijack prod).** Type: instrumented. Target: manifest `manifestPlaceholders`. Preconditions: build the internal/staging flavor. Steps (Emulator): inspect the merged manifest's `intent-filter` host; fire an `ACTION_VIEW` for the prod host against the staging build's parser. Expected: staging build's verified host is `staging.testlogon.com`, not the prod host; a prod-host link is `Malformed`/not claimed by the staging variant (R-4, SEC-1). Traces: AC-4.
- **TC-AND-396-16 — Accessibility of the fallback surface.** Type: Compose-UI/instrumented (accessibility). Target: the transient "couldn't open this link" snackbar/toast (if shown on `Malformed`). Preconditions: TalkBack assertions enabled (e.g. accessibility checks in the Compose test). Steps (Emulator): trigger a fallback surface and run the accessibility check. Expected: the surface uses a localized string resource and exposes a non-empty content description / live-region announcement to TalkBack; navigation does not steal focus from the destination's primary content. Traces: §9 (a11y), AC-4.

### Coverage matrix
| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (verified link opens app directly, no chooser, `verified` status) | TC-AND-396-14 |
| AC-2 (`/videos/{videoId}` cold + warm `onNewIntent`, no recreate) | TC-AND-396-01, -05, -07, -08, -09, -14 |
| AC-3 (authed link while logged out → auth → resume exactly once) | TC-AND-396-06 |
| AC-4 (unknown path → Home + `deeplink_unhandled`; foreign host rejected, never authed) | TC-AND-396-03, -04, -10, -11, -12, -15, -16 |
| AC-5 (`assetlinks.json` 200 / valid JSON / package_name / fingerprints) | TC-AND-396-13 |
| AC-6 (parser + router unit tests; instrumented current-destination assertion) | TC-AND-396-01, -02, -03, -07, -08 |

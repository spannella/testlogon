---
id: AND-396
title: App Links verification + routing
milestone: M8
epic: E51
priority: P1
size: M
status: draft
depends_on: [AND-022]
blocks: []
---

# AND-396 — App Links verification + routing

## 1. Overview & Goal

Enable Android **App Links** (HTTP/HTTPS `autoVerify` deep links) so that tapping a TestLogon URL in a browser, email, chat, or notification opens the native app directly — without the Android disambiguation chooser — and lands the user on the correct in-app destination. This ticket delivers two coupled pieces:

1. **Verification plumbing** — the `intent-filter` declarations with `android:autoVerify="true"`, the host/path matrix, and the server-side `/.well-known/assetlinks.json` Digital Asset Links file that proves domain ownership for the app's signing certificates.
2. **A central deep-link router** — a single, testable Kotlin component that parses an inbound `Uri`, maps it to a typed Navigation-Compose route (from AND-022), and either navigates immediately or defers the navigation until the app is authenticated / the back stack is ready.

Goal: a verified App Link to a canonical TestLogon path (e.g. `https://app.testlogon.com/media/{id}`) opens the app directly and navigates to the matching screen, with graceful, deterministic fallbacks for unauthenticated users, unknown paths, and unverified build variants.

This is a **Chore** in backlog terms (no new product surface), but it touches manifest, signing, navigation, and a hosted static asset, so it is sized **M**.

## 2. Context & References

- **Depends on AND-022 (Navigation host & routes):** the central router targets the typed route definitions and the single-Activity `NavHost` created there. This ticket does **not** redefine routes; it maps URIs onto them.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow. minSdk 24, compileSdk/targetSdk 35, AGP 8.7.3, Gradle 8.9.
- **Namespace / applicationId base:** `com.testlogon.android` (used for the verified app statement and the launcher Activity reference).
- **Auth model:** cookie-based session (`POST /ui/session/start` → MFA → `/ui/session/finalize` → `GET /ui/me`). Deep links that resolve to authenticated destinations must defer navigation until a session exists, then resume.
- **Web reference:** the canonical URL shapes mirror the web app under `frontend/`; the router's path table is derived from the web routes so a shared link works on both platforms.
- **Android docs of record:** App Links verification (`autoVerify`), Digital Asset Links `assetlinks.json`, `adb shell pm verify-app-links` / `App Links Assistant`, `Statement List Generator and Tester`.

## 3. Functional Requirements

FR-1. Declare `intent-filter`s with `android:autoVerify="true"` on the single launcher Activity (`com.testlogon.android.MainActivity`) for the production host(s) over `https` (and `http` only where required for fallback; see SEC-2).

FR-2. Support, at minimum, these verified path patterns (final list confirmed against `frontend/` routing, see Open Question OQ-1):
- `https://{host}/` → Home
- `https://{host}/media/{id}` → Media detail
- `https://{host}/library` and `/library/{section}` → Library
- `https://{host}/settings/{section}` → Settings
- `https://{host}/auth/*` → Auth flow handoff

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

Authenticated **destinations** reached via a deep link consume their own data endpoints (e.g. media detail calls `GET /ui/media/{id}`), but those contracts are owned by the respective feature tickets, not here. The router only produces the typed route; it performs no network I/O.

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
- Espresso/Compose test that fires `Intent(ACTION_VIEW, "https://app.testlogon.com/media/123".toUri())` at `MainActivity` and asserts the Media detail destination is current via `navController.currentBackStackEntry`.
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
- AC-2: `https://app.testlogon.com/media/{id}` cold-launch navigates to Media detail; warm `onNewIntent` does the same without recreating the Activity.
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

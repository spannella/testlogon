---
id: AND-061
title: Magic-link deep-link verify
milestone: M2
epic: E08
priority: P2
size: M
status: draft
depends_on: [AND-060, AND-022]
blocks: []
---

# AND-061 — Magic-link deep-link verify

## 1. Overview & Goal

Passwordless ("magic-link") authentication lets a user request a one-time login
link by email (AND-060, `POST /ui/passwordless/start`). This ticket implements the
second half: receiving the link when the user taps it in their email client,
opening the TestLogon Android app directly via an **Android App Link**, extracting
the embedded one-time token, calling `POST /ui/passwordless/verify`, and then
**branching** the user to one of two terminal states based on the response:

1. **Authenticated** — verification establishes a full session immediately
   (cookie jar populated, `ui_csrf` cookie present); the app navigates to the
   authenticated home destination.
2. **MFA required** — verification authenticates the first factor but the account
   still requires a second factor; the app hands the returned `challenge_id` and
   `required_factors[]` to the existing MFA challenge flow (E08 / AND-03x) exactly
   as the password-based `/ui/session/start` path does.

The goal is a robust, testable deep-link entry point that works on cold, warm, and
foreground launch, fails gracefully on expired/invalid/used tokens, and never leaves
the user on a blank screen.

**Out of scope:** the "check your email" UI (AND-060), the MFA begin/verify screens
(E08 MFA tickets; this ticket only *routes to* them), and the NavHost scaffolding
(AND-022, a dependency).

## 2. Context & References

- **Repo:** `spannella/testlogon`, branch `android-port`, Android app under `android/`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Module layering:** the verify screen lives in `feature-auth`
  (`com.testlogon.android.feature.auth.magiclink`); networking in `core-network`;
  models in `core-model`; cookie persistence in `core-data`. The single-Activity
  `MainActivity` and `NavHost` live in `app` and consume the deep link (AND-022).
- **Web reference:** `frontend/src/api/endpoints/passwordless.ts`,
  `frontend/src/api/types.ts`, and the web `/magic-link-verify` route component.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable). OpenAPI at `/openapi.json`. Verify endpoint:
  `POST /ui/passwordless/verify`.
- **Auth model:** cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`;
  persistent cookie jar required (shared with AND-022 session bootstrap). A
  successful verify is equivalent to `POST /ui/session/finalize` — it must leave the
  cookie jar authenticated so a subsequent `GET /ui/me` succeeds.
- **Dependencies:** AND-060 (passwordless start; shares the `PasswordlessApi` and the
  email-link format), AND-022 (NavHost & typed routes the deep link resolves to).

## 3. Functional Requirements

FR-1. The app MUST register an **Android App Link** (verified, autoVerify) for the
HTTPS path `/magic-link-verify` on the production web host, and a non-verified deep
link on the dev host, so that tapping the email link opens the app instead of the
browser when the app is installed.

FR-2. The link carries a one-time token as the `token` query parameter, e.g.
`https://<host>/magic-link-verify?token=<opaque-token>`. The app MUST extract
`token` from the `Intent` data `Uri`. If `token` is missing or blank, the screen
MUST render an invalid-link error (no network call).

FR-3. On entry, the screen MUST immediately POST the token to
`/ui/passwordless/verify` and display a determinate "Verifying…" loading state
while the call is in flight.

FR-4. On a response where `auth_required == false` (full session granted), the app
MUST treat the user as authenticated and navigate to the authenticated home
destination (`Route.Home`), clearing the magic-link destination from the back stack
(so Back does not return to the verify screen).

FR-5. On a response where `auth_required == true`, the app MUST navigate to the MFA
challenge entry, passing `challenge_id` and `required_factors[]`, reusing the same
MFA route/contract used by the password login path. The verify destination MUST be
popped from the back stack.

FR-6. The flow MUST work in all three launch modes: cold start (app not running),
warm start (process alive, Activity recreated), and hot/foreground (Activity
already resident — handled via `onNewIntent`). The verify call MUST fire exactly
once per unique token Intent (no double-submit on configuration change /
recomposition).

FR-7. Expired, already-consumed, malformed, and not-found tokens MUST each surface a
clear, user-readable message with a single primary action: **"Request a new link"**,
which navigates back to the passwordless start screen (AND-060). A secondary
**"Use password instead"** action navigates to the standard login screen.

FR-8. A failed network call (timeout/offline) for this **non-idempotent POST** MUST
NOT auto-retry. It MUST show an error with a manual **"Try again"** button that
re-issues the verify with the same token.

## 4. Technical Design

### 4.1 Manifest / App Link registration (`app` module)

```xml
<activity
    android:name=".MainActivity"
    android:exported="true"
    android:launchMode="singleTask">
    <!-- existing launcher intent-filter omitted -->
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https"
              android:host="@string/applink_host"
              android:pathPrefix="/magic-link-verify" />
    </intent-filter>
    <!-- dev host: plain http, not auto-verified, BROWSABLE for tap-through -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="http"
              android:host="18.222.237.167"
              android:pathPrefix="/magic-link-verify" />
    </intent-filter>
</activity>
```

`launchMode="singleTask"` ensures a single Activity instance and that re-taps deliver
via `onNewIntent`. The production host requires a published
`/.well-known/assetlinks.json` with the release signing-cert SHA-256 fingerprint;
publishing that file is a web/ops task (see Risks), the app-side autoVerify is here.

### 4.2 Intent handling → Navigation (`app` module)

`MainActivity` forwards incoming `VIEW` intents into the NavController:

```kotlin
override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    intent.data?.let { navController.handleDeepLink(intent) }
}
```

The verify route is registered in the NavHost (AND-022) with a `navDeepLink`:

```kotlin
composable(
    route = Route.MagicLinkVerify.pattern,            // "magic-link-verify?token={token}"
    arguments = listOf(navArgument("token") {
        type = NavType.StringType; nullable = true; defaultValue = null
    }),
    deepLinks = listOf(
        navDeepLink { uriPattern = "https://{host}/magic-link-verify?token={token}" },
        navDeepLink { uriPattern = "http://18.222.237.167/magic-link-verify?token={token}" },
    ),
) { MagicLinkVerifyScreen(onAuthenticated = ..., onMfaRequired = ..., onRetryLink = ...) }
```

### 4.3 Screen + ViewModel (`feature-auth`)

```kotlin
sealed interface MagicLinkUiState {
    data object Verifying : MagicLinkUiState
    data class Authenticated(val nav: Unit = Unit) : MagicLinkUiState   // emitted as event
    data class MfaRequired(
        val challengeId: String,
        val requiredFactors: List<String>,
    ) : MagicLinkUiState
    data class Error(val kind: MagicLinkError, val message: String) : MagicLinkUiState
}

enum class MagicLinkError { MISSING_TOKEN, EXPIRED, USED, INVALID, NETWORK, SERVER }

@HiltViewModel
class MagicLinkVerifyViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val passwordlessRepository: PasswordlessRepository,
) : ViewModel() {
    private val token: String? = savedStateHandle["token"]
    private val _state = MutableStateFlow<MagicLinkUiState>(MagicLinkUiState.Verifying)
    val state: StateFlow<MagicLinkUiState> = _state.asStateFlow()

    private var verifyJob: Job? = null

    init { verify() }

    fun verify() {
        if (token.isNullOrBlank()) {
            _state.value = MagicLinkUiState.Error(MagicLinkError.MISSING_TOKEN, …); return
        }
        if (verifyJob?.isActive == true) return            // dedupe FR-6
        verifyJob = viewModelScope.launch {
            _state.value = MagicLinkUiState.Verifying
            _state.value = passwordlessRepository.verify(token).toUiState()
        }
    }
}
```

The token is read from `SavedStateHandle`, so the ViewModel survives process death
and config changes. Because `verify()` runs in `init` guarded by `verifyJob`, the
POST fires exactly once per ViewModel instance (FR-6, no double-submit).
`Authenticated`/`MfaRequired` are consumed once via `LaunchedEffect(state)`, then the
verify destination is popped with
`popUpTo(Route.MagicLinkVerify.pattern) { inclusive = true }`.

### 4.4 Repository / API (`core-data` + `core-network`)

The `PasswordlessApi` (introduced in AND-060) gains the verify method:

```kotlin
interface PasswordlessApi {
    @POST("ui/passwordless/start")
    suspend fun start(@Body body: PasswordlessStartRequest): Response<PasswordlessStartResponse>

    @POST("ui/passwordless/verify")
    suspend fun verify(@Body body: PasswordlessVerifyRequest): Response<PasswordlessVerifyResponse>
}

class PasswordlessRepository @Inject constructor(private val api: PasswordlessApi) {
    suspend fun verify(token: String): ApiResult<PasswordlessVerifyResponse> =
        api.verify(PasswordlessVerifyRequest(token)).toApiResult()   // shared mapper
}
```

The verify POST flows through the shared OkHttp stack: the persistent cookie jar
captures the Set-Cookie session + `ui_csrf` on success. The initial verify has no
prior session, so the 401→refresh interceptor is not expected here, and verify is
excluded from the idempotent-GET retry policy.

## 5. API Contract

**`POST /ui/passwordless/verify`** — exchange a one-time email token for a session
or an MFA challenge.

Request body (`PasswordlessVerifyRequest`):
```json
{ "token": "<opaque one-time token from email link>" }
```

Success response (200) — full session granted:
```json
{ "auth_required": false, "challenge_id": null, "required_factors": [] }
```

Success response (200) — second factor still required (mirrors
`/ui/session/start`):
```json
{ "auth_required": true,
  "challenge_id": "chg_8f2…",
  "required_factors": ["totp"] }
```

Kotlin/Moshi models (`core-model`):
```kotlin
@JsonClass(generateAdapter = true)
data class PasswordlessVerifyRequest(val token: String)

@JsonClass(generateAdapter = true)
data class PasswordlessVerifyResponse(
    @Json(name = "auth_required") val authRequired: Boolean,
    @Json(name = "challenge_id") val challengeId: String?,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
)
```

Error responses use the standard FastAPI `detail` shape, mapped by the shared
error mapper (string | `[{msg}]` | `{code,…}`):
- **400/422** — malformed/missing token → `MagicLinkError.INVALID`.
- **401/403** — token expired or already consumed. The discriminator is the
  `detail.code` (e.g. `"token_expired"`, `"token_used"`) when the object form is
  returned; map to `EXPIRED` / `USED`, else fall back to `INVALID`.
- **404** — token not found → `INVALID`.
- **5xx** — `SERVER`.

When `auth_required == false`, the verify screen does **not** call `GET /ui/me`
(the home destination owns its own bootstrap), but the cookie jar MUST be
authenticated after the call.

## 6. Data & State Management

- **UI state:** single `StateFlow<MagicLinkUiState>` per the project convention;
  `Authenticated`/`MfaRequired` are treated as one-shot navigation events consumed in
  `LaunchedEffect` and not re-emitted.
- **Token persistence:** the token lives only in `SavedStateHandle` (the nav
  argument). It is never written to Room or DataStore. After a successful verify the
  destination is popped so the token cannot be replayed from the back stack.
- **Session persistence:** the authenticated cookies and `ui_csrf` are written to the
  shared persistent cookie jar in `core-data` (same store as the password login
  path). No new persistent store is introduced by this ticket.
- **MFA hand-off:** `challenge_id` + `required_factors[]` are passed as typed nav
  arguments to the MFA route — not stored — so they share the lifecycle of the MFA
  destination.

## 7. Error Handling & Resilience

- **No token:** rendered immediately as `MISSING_TOKEN`, no network call.
- **Non-idempotent POST:** verify is **never** auto-retried (project policy:
  bounded backoff applies to idempotent GETs only). Network/timeout failures (~20s
  OkHttp timeout against the unreliable dev host) surface as `NETWORK` with a manual
  **"Try again"** button that calls `viewModel.verify()` again with the same token.
- **Expired/used/invalid:** terminal error states each with copy explaining the
  cause and a primary **"Request a new link"** (→ AND-060 start screen) plus
  secondary **"Use password instead"** (→ login).
- **Process death mid-verify:** on restore, `init` re-runs `verify()` with the
  token from `SavedStateHandle`. Re-verifying a token that the first (now-lost) call
  already consumed yields `USED`, which is handled gracefully — the user is offered a
  fresh link. (Documented trade-off; see Risks.)
- **App-not-installed / verification not provisioned:** the link opens in the browser
  (web `/magic-link-verify` handles it); no app-side regression.

## 8. Security & Privacy

- The one-time token is sensitive. It MUST NOT be logged, included in analytics
  payloads, or written to disk; only the *outcome* (success / error-kind) is logged.
- App Links use `autoVerify` with the release signing cert fingerprint in
  `assetlinks.json` so only the genuine app claims the production URL — this prevents
  link-hijacking by other apps on the device.
- The dev `http://18.222.237.167` filter is **not** auto-verified and is plaintext;
  it is restricted to debug/dev build variants where possible and excluded from
  release builds' cleartext policy where feasible. Production traffic is HTTPS only.
- CSRF: the verify response's `ui_csrf` cookie is captured and echoed as
  `X-CSRF-Token` on subsequent state-changing calls by the shared interceptor.
- The token is single-use server-side; the client additionally pops the destination
  after verify to avoid client-side replay from history/back stack.

## 9. Accessibility & i18n

- All states (Verifying, each error, action buttons) use string resources in
  `feature-auth` `strings.xml`; no hard-coded user-facing text. Keys:
  `magic_link_verifying`, `magic_link_err_expired`, `magic_link_err_used`,
  `magic_link_err_invalid`, `magic_link_err_network`, `magic_link_action_new_link`,
  `magic_link_action_use_password`, `magic_link_action_retry`.
- The "Verifying…" indicator is a Material 3 `CircularProgressIndicator` with a
  `contentDescription`/`liveRegion` announcing progress; on completion the result/error
  is announced via an `assertive` live region so TalkBack users hear the outcome.
- Buttons meet the 48dp minimum touch target; error layout reflows for large font
  scales (no fixed heights, scrollable container).
- RTL-safe (Compose default with start/end paddings).

## 10. Telemetry & Logging

- Emit structured analytics events (token value redacted): `magic_link_verify_start`,
  `magic_link_verify_success` (with `branch = authenticated | mfa`),
  `magic_link_verify_error` (with `kind` = the `MagicLinkError` name and HTTP status).
- Logcat: debug-level logs of state transitions and HTTP status codes only; the OkHttp
  logging interceptor MUST be configured to redact the request body for this endpoint
  (or run at `BASIC`/`HEADERS` level, never `BODY`, for passwordless calls).
- A launch-mode tag (`cold | warm | foreground`) is attached to
  `magic_link_verify_start` to aid debugging the three entry paths.

## 11. Testing Strategy

**Unit (`core-testing` + JUnit/Turbine, ViewModel):**
- `verify()` with null/blank token → emits `Error(MISSING_TOKEN)`, makes no API call.
- `auth_required == false` → state path ends in `Authenticated`.
- `auth_required == true` → `MfaRequired(challengeId, requiredFactors)`.
- 401 `{code:"token_expired"}` → `Error(EXPIRED)`; `token_used` → `USED`;
  422 → `INVALID`; IOException/timeout → `NETWORK`; 5xx → `SERVER`.
- Double invocation of `verify()` while a job is active issues only one API call
  (dedupe).
- "Try again" re-issues the call with the same token.

**Repository / network (MockWebServer):** assert request path `ui/passwordless/verify`,
JSON body `{"token":…}`, and that Set-Cookie on a 200 populates the cookie jar.

**Instrumented / deep-link (`androidTest`, Espresso/Compose):**
- Fire an `ACTION_VIEW` Intent with
  `https://<host>/magic-link-verify?token=valid` against a stubbed backend →
  asserts navigation to Home and verify destination popped (cold + foreground via
  `onNewIntent`).
- Same with an MFA-branch token → asserts navigation to the MFA route with correct
  args.
- Expired-token Intent → asserts error UI and that "Request a new link" navigates to
  the AND-060 start screen.
- `adb shell am start -a android.intent.action.VIEW -d "https://<host>/magic-link-verify?token=…"`
  documented as a manual smoke check; App Links verification checked with
  `adb shell pm get-app-links com.testlogon.android`.

The acceptance test ("tapping the link opens the app and completes/branches auth")
is the instrumented deep-link test above.

## 12. Dependencies & Sequencing

- **AND-060 (Passwordless start):** provides `PasswordlessApi`, the `PasswordlessStartRequest/Response`
  models, the "check your email" screen, and the start destination this ticket's
  error actions navigate back to. Must merge first.
- **AND-022 (Navigation host & routes):** provides the single-Activity `NavHost`,
  typed `Route` definitions, and `navController.handleDeepLink` wiring. The
  `Route.MagicLinkVerify` definition and the `navDeepLink` are added here on top of
  that host.
- **MFA challenge route (E08):** the `MfaRequired` branch navigates to the existing
  MFA entry route (the same one consumed by the password `/ui/session/start` path). If
  that route is not yet merged, this ticket can land behind a temporary placeholder
  destination, but the acceptance MFA-branch test is gated on it.
- **Cookie jar / session (AND-021/AND-022 bootstrap):** the shared persistent cookie
  jar must exist so verify can establish the session.

Sequencing: AND-022 → AND-060 → **AND-061**.

## 13. Risks & Open Questions

- **`assetlinks.json` provisioning:** App Links auto-verification requires the
  production web host to serve `/.well-known/assetlinks.json` with the release cert
  fingerprint. This is a web/ops dependency outside the Android module. *Open
  question:* who owns publishing it for the production host, and is there a staging
  host with a separate fingerprint? Until provisioned, the link opens the browser.
- **Token in URL leakage:** the token travels as a query param; if opened in a
  browser first it may land in history. Mitigated by single-use server semantics.
  *Open question:* does the backend enforce a short TTL and single use? (assumed yes.)
- **Process-death re-verify:** if verify succeeds but the process dies before
  navigation, restore re-POSTs and gets `USED`. Acceptable trade-off; persisting a
  "consumed" flag is rejected to avoid storing token-derived state.
- **Exact error discriminator:** the precise `detail.code` strings for expired vs
  used are assumed from `/openapi.json`; confirm against the live schema. Mapping
  falls back to `INVALID` if codes differ.
- **Dev-host cleartext in release:** ensure the `http://18.222.237.167` intent-filter
  and cleartext permission are stripped from release variants.

## 14. Acceptance Criteria

1. Tapping the magic-link in an email opens the installed app directly at the
   `/magic-link-verify` destination (App Link verified for the production host;
   tap-through deep link working for the dev host). *(tested — instrumented Intent
   test; manual `adb` + `pm get-app-links` smoke check)*
2. A valid token with `auth_required == false` results in an authenticated session
   (cookie jar populated, `ui_csrf` present) and navigation to Home, with the verify
   destination removed from the back stack. *(tested)*
3. A valid token with `auth_required == true` navigates to the MFA challenge route
   carrying the correct `challenge_id` and `required_factors[]`. *(tested)*
4. Missing/blank token shows an invalid-link error with no network call. *(tested)*
5. Expired and already-used tokens each show a distinct, readable error with
   "Request a new link" (→ AND-060) and "Use password instead" (→ login) actions.
   *(tested)*
6. A network/timeout failure shows a manual "Try again" (no auto-retry); retry
   re-issues verify with the same token. *(tested)*
7. The flow works in cold, warm, and foreground (`onNewIntent`) launch modes, and the
   verify POST fires exactly once per token Intent. *(tested)*
8. The token never appears in logs, analytics payloads, or persistent storage.

## 15. Definition of Done

- Manifest intent-filters (HTTPS autoVerify + dev HTTP) and `Route.MagicLinkVerify`
  with `navDeepLink` merged on the `android-port` branch; `app/feature-auth` build
  green under Gradle 8.9 / AGP 8.7.3 / JDK 17.
- `MagicLinkVerifyViewModel`, `MagicLinkVerifyScreen`, and `PasswordlessApi.verify`
  + repository method implemented with the signatures above; `StateFlow<UiState>`
  and `ApiResult<T>` conventions followed; `detail` error mapping wired.
- All unit, MockWebServer, and instrumented deep-link tests in §11 implemented and
  passing in CI; ktlint/detekt clean.
- String resources extracted; TalkBack live-region announcements verified.
- Token redaction verified in the OkHttp logging interceptor and analytics.
- `assetlinks.json` requirement filed/tracked with web/ops; release variant confirmed
  to exclude the dev cleartext filter.
- Code reviewed and merged; AND-061 acceptance ("tapping the link opens the app and
  completes/branches auth") demonstrated on a device/emulator.

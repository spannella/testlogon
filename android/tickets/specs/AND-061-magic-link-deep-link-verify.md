---
id: AND-061
title: Magic-link deep-link verify
milestone: M2
epic: E08
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Auth model:** cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`
  (verified: `src/api/client.ts` reads the `ui_csrf` cookie and sets the
  `X-CSRF-Token` header); persistent cookie jar required (shared with AND-022 session
  bootstrap). A successful verify must leave the cookie jar authenticated so a
  subsequent `GET /ui/me` (verified op `ui_me_ui_me_get`) succeeds.
  *(Note: `POST /ui/passwordless/verify` and `POST /ui/session/finalize` are distinct
  endpoints; the earlier draft's "equivalent to finalize" wording is dropped — verify
  is its own operation that returns its own session, no separate finalize call is
  made. See §16.)*
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

FR-4. On a **full-session** response (`status == "ok"` AND `session_id` present;
`auth_required` is `false`), the app MUST treat the user as authenticated and
navigate to the authenticated home destination (`Route.Home`), clearing the
magic-link destination from the back stack (so Back does not return to the verify
screen).
*(Corrected: the success discriminator is `status == "ok"` + `session_id`, mirroring
the web client — see §16. The earlier draft branched solely on `auth_required ==
false`. The response always includes a required `status` string and an optional
`session_id`; both were absent from the original draft and are now modeled in §5.)*

FR-5. On an **MFA-required** response (`auth_required == true` AND `challenge_id`
present), the app MUST navigate to the MFA challenge entry, passing `challenge_id`
and `required_factors[]`, reusing the same MFA route/contract used by the password
login path. The verify destination MUST be popped from the back stack.

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
            // toUiState() maps: status=="ok" && session_id!=null -> Authenticated;
            // auth_required && challenge_id!=null -> MfaRequired; else INVALID (see §5).
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

> **Verified against `PasswordlessVerifyResp` (OpenAPI) and `src/api/types.ts:
> PasswordlessVerifyResp`.** The response has FIVE fields, not three: `status`
> (string, **required**), `session_id` (string | null), `auth_required` (boolean,
> default `false`), `challenge_id` (string | null), and `required_factors`
> (string[]). The original draft omitted `status` and `session_id`; they are now
> modeled below. (Corrected — see §16.)

Success response (200) — full session granted:
```json
{ "status": "ok",
  "session_id": "sess_…",
  "auth_required": false,
  "challenge_id": null,
  "required_factors": [] }
```

Success response (200) — second factor still required (similar to
`/ui/session/start`, which returns `auth_required` / `challenge_id` /
`required_factors` / `session_id` but **no** `status` field):
```json
{ "status": "mfa_required",
  "session_id": null,
  "auth_required": true,
  "challenge_id": "chg_8f2…",
  "required_factors": ["totp"] }
```
*(Note: the exact non-"ok" `status` value for the MFA branch is not pinned by the
OpenAPI schema — `status` is a free-form string. The branch MUST be discriminated by
`auth_required == true` + `challenge_id` presence, exactly as the web client does
(`src/pages/MagicLinkVerify.tsx`), NOT by the literal `status` string.)*

Kotlin/Moshi models (`core-model`):
```kotlin
@JsonClass(generateAdapter = true)
data class PasswordlessVerifyRequest(val token: String)

@JsonClass(generateAdapter = true)
data class PasswordlessVerifyResponse(
    @Json(name = "status") val status: String,                 // required; "ok" == full session
    @Json(name = "session_id") val sessionId: String?,         // present on full-session success
    @Json(name = "auth_required") val authRequired: Boolean = false,
    @Json(name = "challenge_id") val challengeId: String?,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
)
```

**Branching rule (matches `src/pages/MagicLinkVerify.tsx`):**
- Full session → `status == "ok" && session_id != null` → `Authenticated`.
- MFA → `auth_required == true && challenge_id != null` → `MfaRequired`.
- Otherwise (e.g. `status` not "ok" and not MFA) → treat as `INVALID` error.

Error responses: **Unverified beyond 422.** The OpenAPI index lists only
`resp=200:PasswordlessVerifyResp;422:HTTPValidationError` for this endpoint — i.e.
the only *documented* non-200 status is **422** (`HTTPValidationError`, the standard
FastAPI `detail: [{loc,msg,type}]` array). The web client (`MagicLinkVerify.tsx`)
treats **any** thrown error (and any non-"ok"/non-MFA 200 body) generically as
"link may have expired or already been used" — it does NOT inspect a `detail.code`.
The mapping below is therefore a **best-effort assumption**, not a verified contract:
- **422** — malformed/missing token (validation) → `MagicLinkError.INVALID`. *(verified status code)*
- **400/401/403/404** — expired / already-consumed / not-found token. **Assumed**;
  none of these status codes are declared in the OpenAPI for this op. If present, the
  client SHOULD attempt to read a `detail.code` (e.g. `"token_expired"`,
  `"token_used"`) and map to `EXPIRED` / `USED`, **falling back to `INVALID`** when
  the code is absent or unrecognized (which, per the web client, is the expected
  common case). *(unverified — see §16 Open assumptions.)*
- **5xx** — `SERVER`.

On a full-session success the verify screen does **not** call `GET /ui/me`, the
home destination owns its own bootstrap. *(Divergence from web: the web client
DOES call `getMe()` (`GET /ui/me`) immediately after a successful verify —
`src/pages/MagicLinkVerify.tsx` line 35, `src/api/endpoints/auth.ts: getMe`. This is
an intentional Android design choice, not a contract requirement; see §16.)* The
cookie jar MUST be authenticated after the verify call regardless.

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
- **Exact error discriminator (CONFIRMED GAP):** the OpenAPI schema declares only
  `200` and `422` for `POST /ui/passwordless/verify` — there is **no** documented
  401/403/404 response and **no** `detail.code` enum for expired-vs-used. The web
  client (`src/pages/MagicLinkVerify.tsx`) does not distinguish them; it shows one
  generic "expired or already used" message. The Android `EXPIRED`/`USED` split is
  therefore aspirational and MUST fall back to `INVALID`. *Open question:* does the
  live backend actually emit distinct codes/status for expired vs consumed? Verify
  against a running dev host before relying on the split. (See §16 Open assumptions.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source. Sources are
exact pointers into the OpenAPI index/spec or the frontend reference app.

1. **Endpoint is `POST /ui/passwordless/verify`.** VERIFIED.
   Source: OpenAPI `POST /ui/passwordless/verify` (op
   `passwordless_verify_ui_passwordless_verify_post`); frontend
   `src/api/endpoints/auth.ts: passwordlessVerify` (`api.post("/ui/passwordless/verify", body)`).
2. **Request body is `{ "token": string }` (`PasswordlessVerifyRequest`).** VERIFIED.
   Source: OpenAPI schema `PasswordlessVerifyReq` (single required `token: string`);
   `src/api/types.ts: PasswordlessVerifyReq`.
3. **Companion start endpoint is `POST /ui/passwordless/start` with `{username}`.**
   VERIFIED (context only; owned by AND-060). Source: OpenAPI `POST
   /ui/passwordless/start`, schema `PasswordlessStartReq` (`username` required);
   `src/api/types.ts: PasswordlessStartReq`.
4. **Verify response carries `auth_required` (bool), `challenge_id` (string|null),
   `required_factors` (string[]).** VERIFIED.
   Source: OpenAPI schema `PasswordlessVerifyResp`; `src/api/types.ts:
   PasswordlessVerifyResp`.
5. **Verify response ALSO carries `status` (string, REQUIRED) and `session_id`
   (string|null) — both omitted by the original draft.** CORRECTED.
   Source: OpenAPI schema `PasswordlessVerifyResp` (`required: ["status"]`, plus
   `session_id` anyOf string/null); `src/api/types.ts: PasswordlessVerifyResp`
   (`status: string; session_id?: string`).
6. **Full-session success is discriminated by `status == "ok"` + `session_id`
   present (NOT solely by `auth_required == false`).** CORRECTED.
   Source: `src/pages/MagicLinkVerify.tsx` line 33
   (`if (resp.status === "ok" && resp.session_id)`).
7. **MFA branch is discriminated by `auth_required == true` + `challenge_id`
   present.** VERIFIED. Source: `src/pages/MagicLinkVerify.tsx` line 41
   (`else if (resp.auth_required && resp.challenge_id)`).
8. **The verify response "mirrors `/ui/session/start`".** CORRECTED (partially true).
   `UiSessionStartResp` has `auth_required` (required), `challenge_id`,
   `required_factors`, `session_id` — but **no `status`** field; `PasswordlessVerifyResp`
   adds the required `status`. Source: OpenAPI schemas `UiSessionStartResp` vs
   `PasswordlessVerifyResp`.
9. **Auth model: cookie session + `ui_csrf` cookie echoed as `X-CSRF-Token`.**
   VERIFIED. Source: `src/api/client.ts` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`).
10. **A subsequent `GET /ui/me` is the session-bootstrap endpoint.** VERIFIED.
    Source: OpenAPI `GET /ui/me` (op `ui_me_ui_me_get`); `src/api/endpoints/auth.ts:
    getMe` (`api.get("/ui/me")`), `MeResp { user_sub, session_id }` in
    `src/api/types.ts`.
11. **Web client calls `GET /ui/me` after a successful verify; Android intentionally
    does NOT (home owns bootstrap).** VERIFIED (divergence documented).
    Source: `src/pages/MagicLinkVerify.tsx` line 35 (`const me = await getMe();`).
12. **Original draft claim "successful verify is equivalent to `POST
    /ui/session/finalize`".** CORRECTED. They are distinct ops; verify returns its own
    session and no finalize call is made. Source: OpenAPI `POST /ui/session/finalize`
    (op `ui_session_finalize_...`, req `UiSessionFinalizeReq`) is a separate endpoint;
    `src/pages/MagicLinkVerify.tsx` invokes only `passwordlessVerify` then `getMe`.
13. **Web route is `/magic-link-verify`, reading the `token` query param.** VERIFIED.
    Source: `src/App.tsx` line 278 (`<Route path="/magic-link-verify" .../>`);
    `src/pages/MagicLinkVerify.tsx` line 16 (`searchParams.get("token")`).
14. **Error contract: distinct 401/403/404 + `detail.code` for expired vs used.**
    UNVERIFIED-ASSUMPTION. OpenAPI declares only `200` and `422`
    (`HTTPValidationError`) for this op. The web client handles all errors generically.
    Source: OpenAPI index line for `POST /ui/passwordless/verify`
    (`resp=200:PasswordlessVerifyResp;422:HTTPValidationError`);
    `src/pages/MagicLinkVerify.tsx` `catch` block (generic message).
15. **422 validation error shape is FastAPI `detail: [{loc,msg,type}]`.** VERIFIED.
    Source: OpenAPI `HTTPValidationError` / `ValidationError` schema referenced by the
    `422` response of every `/ui/*` op.
16. **Missing/blank token → no network call.** VERIFIED against web behavior.
    Source: `src/pages/MagicLinkVerify.tsx` lines 19-23 (early `return` when `!token`).
17. **Android App Links / `autoVerify` + `assetlinks.json` + `singleTask` /
    `onNewIntent` deep-link delivery + `navDeepLink`.** UNVERIFIED-ASSUMPTION
    (framework choice, not derivable from backend/web sources). Sources (framework ref):
    https://developer.android.com/training/app-links (App Links & autoVerify),
    https://developer.android.com/training/app-links/verify-android-applinks
    (assetlinks.json Digital Asset Links),
    https://developer.android.com/guide/navigation/navigation-deep-link
    (`navDeepLink` / `handleDeepLink`),
    https://developer.android.com/guide/components/activities/tasks-and-back-stack
    (`singleTask` / `onNewIntent`).
18. **`SavedStateHandle` survives process death / config change for the token nav
    arg.** UNVERIFIED-ASSUMPTION (framework ref):
    https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate
19. **Cleartext dev host (`http://18.222.237.167`) restricted out of release variants.**
    UNVERIFIED-ASSUMPTION (project/ops decision, framework ref):
    https://developer.android.com/privacy-and-security/security-config (cleartext /
    network security config).

### Corrections made

- **§5 / FR-4:** success discriminator changed from `auth_required == false` to
  `status == "ok"` + `session_id` present (matches `src/pages/MagicLinkVerify.tsx`).
- **§5 model:** added the required `status: String` and optional `session_id: String?`
  fields to `PasswordlessVerifyResponse` (and JSON examples), which the draft omitted;
  `authRequired` defaulted to `false` per the schema default.
- **§5 errors:** demoted the 401/403/404 + `detail.code` (`token_expired`/`token_used`)
  mapping to an explicit best-effort assumption; only `200` and `422` are documented.
- **§2:** dropped the "verify is equivalent to `POST /ui/session/finalize`" claim
  (distinct ops); clarified that no finalize call is made; cited the CSRF/cookie and
  `/ui/me` sources.
- **§5:** documented that the web client calls `GET /ui/me` after success while Android
  deliberately defers bootstrap to the home destination.
- **§13:** upgraded the "exact error discriminator" risk to a confirmed schema gap.

### Open assumptions

- **Distinct backend error codes/status for expired vs already-used tokens** cannot be
  confirmed: the OpenAPI declares only `200`/`422` for the verify op and the web client
  collapses all failures into one message. Why unverifiable: no error schema beyond
  `HTTPValidationError` is published and the live dev host is unreliable/plaintext.
  Mitigation: map all non-validation failures to `INVALID` unless a recognized
  `detail.code` is observed at runtime.
- **The literal `status` string for the MFA branch** (e.g. `"mfa_required"`) is not
  pinned — `status` is a free-form string in the schema. Branch only on
  `auth_required` + `challenge_id`. Why unverifiable: schema gives no enum and the web
  client never inspects `status` on the MFA path.
- **App Links auto-verification on the production host** depends on a web/ops-published
  `/.well-known/assetlinks.json` with the release cert fingerprint — outside this
  module and not present in any reviewed source. Why unverifiable: ops artifact, not in
  repo/OpenAPI/frontend.
- **Android framework behaviors** (App Links verification, `onNewIntent` delivery,
  `SavedStateHandle` persistence, cleartext-config stripping) are framework-ref only;
  validated by tests in §17, not by the backend/web contract.

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device); **EMU** =
headless emulator AVD `test35` (x86_64, API 35) on the CI build server; **DEVICE** =
physical Samsung Galaxy A15 5G (SM-A156U, serial `R5CX821TA9R`, Android 14 / API 34,
arm64-v8a) on the build host via adb. Error shapes below use the real contract from
§5/§16 (only `200`/`422` are documented; expired/used are best-effort).

- **TC-AND-061-01** — Type: unit (JVM, Turbine). Target: `MagicLinkVerifyViewModel`.
  Preconditions: repo stub returns `PasswordlessVerifyResponse(status="ok",
  sessionId="sess_1", authRequired=false, challengeId=null, requiredFactors=[])`.
  Steps: construct VM with `SavedStateHandle["token"]="valid"`; collect `state`.
  Expected: `Verifying` → terminal `Authenticated`; exactly one `verify()` API call.
  Traces: AC-2, AC-7.
- **TC-AND-061-02** — Type: unit (JVM, Turbine). Target: `MagicLinkVerifyViewModel`.
  Preconditions: stub returns `status="mfa_required", authRequired=true,
  challengeId="chg_8f2", requiredFactors=["totp"], sessionId=null`.
  Steps: VM with token "valid"; collect state.
  Expected: terminal `MfaRequired(challengeId="chg_8f2", requiredFactors=["totp"])`.
  Traces: AC-3.
- **TC-AND-061-03** — Type: unit (JVM). Target: `MagicLinkVerifyViewModel`.
  Preconditions: `SavedStateHandle["token"]` is null, then blank.
  Steps: construct VM; collect state; assert no repo/API interaction (mock verify).
  Expected: immediate `Error(MISSING_TOKEN)`, zero network calls.
  Traces: AC-4, AC-8.
- **TC-AND-061-04** — Type: unit (JVM). Target: VM + error mapper.
  Preconditions: stub returns 422 `HTTPValidationError`
  (`{"detail":[{"loc":["body","token"],"msg":"...","type":"..."}]}`); then a 200 body
  that is neither "ok"+session_id nor MFA (e.g. `status="failed"`).
  Steps: drive each case.
  Expected: both map to `Error(INVALID)` (fallback per §5).
  Traces: AC-5.
- **TC-AND-061-05** — Type: unit (JVM). Target: VM + error mapper.
  Preconditions: stub throws `IOException`/`SocketTimeoutException`; then a 5xx.
  Steps: drive each.
  Expected: `Error(NETWORK)` for IO/timeout, `Error(SERVER)` for 5xx; **no auto-retry**
  occurs. Traces: AC-6.
- **TC-AND-061-06** — Type: unit (JVM). Target: VM dedupe + retry.
  Preconditions: stub with a suspendable/slow verify.
  Steps: call `verify()` twice while the first job is active; then after it completes,
  invoke retry ("Try again") once.
  Expected: only ONE API call during the active window (dedupe); retry issues exactly
  one further call with the SAME token. Traces: AC-6, AC-7.
- **TC-AND-061-07** — Type: contract/MockWebServer (JVM/Robolectric). Target:
  `PasswordlessApi.verify` + `PasswordlessRepository` over the real OkHttp stack.
  Preconditions: MockWebServer enqueues 200 with body
  `{"status":"ok","session_id":"sess_1","auth_required":false,"challenge_id":null,"required_factors":[]}`
  and a `Set-Cookie: ui_csrf=...; session=...` header.
  Steps: call `repository.verify("valid")`; inspect recorded request and cookie jar.
  Expected: request is `POST /ui/passwordless/verify`, JSON body exactly
  `{"token":"valid"}`, `Content-Type: application/json`; Moshi parses all five fields;
  the persistent cookie jar now holds `ui_csrf` + session cookies. Traces: AC-2.
- **TC-AND-061-08** — Type: contract/MockWebServer (JVM). Target: CSRF echo on the
  shared interceptor. Preconditions: cookie jar pre-seeded with `ui_csrf=abc` from a
  prior verify; enqueue any subsequent state-changing call.
  Steps: issue the follow-up request through the shared client.
  Expected: outgoing request carries header `X-CSRF-Token: abc` (matches
  `src/api/client.ts`). Traces: AC-2, AC-8.
- **TC-AND-061-09** — Type: instrumented/Compose-UI deep link (EMU `test35`). Target:
  `MainActivity` + NavHost + `MagicLinkVerifyScreen` (stubbed backend / MockWebServer).
  Preconditions: app installed, backend stub returns full-session success.
  Steps: launch `ACTION_VIEW` Intent
  `https://<applink_host>/magic-link-verify?token=valid` (cold start), then repeat
  delivering via `onNewIntent` with the Activity already resident (foreground).
  Expected: both paths navigate to `Route.Home`; the verify destination is popped
  (Back does not return to it); verify POST fires exactly once per Intent.
  Traces: AC-1, AC-2, AC-7.
- **TC-AND-061-10** — Type: instrumented deep link (EMU `test35`). Target: NavHost MFA
  hand-off. Preconditions: stub returns MFA-branch body; MFA route registered (or
  placeholder). Steps: fire `ACTION_VIEW` with an MFA-branch token.
  Expected: navigation to the MFA challenge route with nav args
  `challenge_id="chg_8f2"`, `required_factors=["totp"]`; verify destination popped.
  Traces: AC-1, AC-3.
- **TC-AND-061-11** — Type: instrumented deep link (EMU `test35`). Target: error UI +
  recovery navigation. Preconditions: stub returns a verify failure (e.g. 422 / non-ok
  body). Steps: fire the deep-link Intent; on the error screen tap "Request a new
  link", then (separate run) "Use password instead".
  Expected: distinct readable error copy; "Request a new link" navigates to the AND-060
  start screen; "Use password instead" navigates to the login screen.
  Traces: AC-5.
- **TC-AND-061-12** — Type: instrumented offline/flaky-host (DEVICE preferred; EMU
  acceptable). Target: no-auto-retry + manual retry on real radio.
  **MUST run on DEVICE** to exercise real cellular/Wi-Fi loss and timeout against the
  unreliable dev host. Preconditions: app on SM-A156U; toggle airplane mode (or point
  at the flaky dev host `http://18.222.237.167`). Steps: open the magic link while
  offline; observe `NETWORK` error; confirm no automatic re-request fires; restore
  connectivity; tap "Try again".
  Expected: single failed attempt, manual "Try again" re-issues verify with the same
  token, success on restore. Traces: AC-6.
- **TC-AND-061-13** — Type: instrumented security (EMU `test35`). Target: logging +
  persistence redaction. Preconditions: debug build with logging interceptor at
  HEADERS (never BODY) for passwordless; analytics in test sink.
  Steps: run a verify; capture logcat, the analytics sink, and inspect DataStore/Room.
  Expected: the raw token value appears in NONE of logcat, analytics payloads, or
  persistent storage; only outcome/error-kind/HTTP status are recorded. Traces: AC-8.
- **TC-AND-061-14** — Type: manual + instrumented App-Links verification (DEVICE).
  **MUST run on DEVICE** (real installed-app link claiming / email-tap behavior).
  Target: App Link autoVerify + tap-through. Preconditions: release-signed (or
  debug-with-assetlinks) build on SM-A156U. Steps:
  `adb -s R5CX821TA9R shell pm get-app-links com.testlogon.android` (expect
  `verified` for the production host); tap the magic link from a real email client;
  also `adb -s R5CX821TA9R shell am start -a android.intent.action.VIEW -d
  "https://<host>/magic-link-verify?token=..."`. Expected: link opens the app directly
  (production host verified); dev `http` host opens via tap-through chooser; app lands
  on the verify destination. Traces: AC-1.
- **TC-AND-061-15** — Type: Compose-UI accessibility (EMU `test35` with TalkBack, or
  Robolectric semantics). Target: `MagicLinkVerifyScreen` a11y.
  Preconditions: each UI state rendered. Steps: assert semantics for Verifying
  (progress `contentDescription`/live region), each error (assertive live region
  announces outcome), and action buttons. Expected: progress and outcome are announced
  to TalkBack; all touch targets ≥ 48dp; layout reflows/scrolls at large font scale;
  no hard-coded user-facing strings (all from `strings.xml`). Traces: AC-5 (UI), AC-8
  (string-resource hygiene).

### Coverage matrix (§14 Acceptance Criterion → covering TC)

- **AC-1** (link opens app at verify destination; App Link verified prod, tap-through
  dev): TC-09, TC-10, TC-14.
- **AC-2** (valid `status=="ok"` + session → authenticated, cookie jar + `ui_csrf`,
  nav to Home, popped): TC-01, TC-07, TC-08, TC-09.
- **AC-3** (MFA branch carries `challenge_id` + `required_factors`): TC-02, TC-10.
- **AC-4** (missing/blank token → invalid-link error, no network call): TC-03.
- **AC-5** (expired/used/invalid → distinct readable error + "Request a new link" /
  "Use password instead"): TC-04, TC-11, TC-15.
- **AC-6** (network/timeout → manual "Try again", no auto-retry, same token): TC-05,
  TC-06, TC-12.
- **AC-7** (cold/warm/foreground; verify fires exactly once per token Intent): TC-01,
  TC-06, TC-09.
- **AC-8** (token never in logs/analytics/persistent storage): TC-03, TC-08, TC-13,
  TC-15.

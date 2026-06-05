---
id: AND-063
title: SSO / SAML login
milestone: M2
epic: E08
priority: P2
size: M
status: draft
depends_on: [AND-030]
blocks: []
---

# AND-063 — SSO / SAML login

## 1. Overview & Goal

Enable users belonging to an SSO-only (SAML/OIDC) tenant to authenticate from the
native Android client. The TestLogon backend delegates such tenants to an external
Identity Provider (IdP) over a browser-based redirect flow. Because the native HTTP
client cannot (and must not) drive an arbitrary third-party IdP login form, this
ticket implements the *browser-handoff* pattern: the app discovers SSO availability
for the entered identifier, launches the backend's `/sso` (or `/saml/login`)
authorization endpoint in an Android **Custom Tab** (Chrome Custom Tabs / AndroidX
Browser), lets the IdP authenticate the user in a trusted browser context, and
receives the completed, cookie-backed session via an HTTPS **App Link** deep link
back into the app.

The goal is: an SSO-only tenant user can tap "Sign in with SSO", complete IdP login
in the browser tab, and return to the app fully authenticated (`GET /ui/me` succeeds,
session + `ui_csrf` cookies present in the persistent cookie jar) — with no
email/password entry in the native form.

Out of scope: standalone OIDC PKCE without a backend broker (the backend is the
broker), IdP-initiated SSO, SCIM provisioning, and tenant admin configuration of SSO.

## 2. Context & References

- Backlog: AND-063 — Type Feature, Priority **P2**, Deps **AND-030**.
- Depends on **AND-030 — Login screen UI** for the host screen, server-URL entry
  point, identifier field, and error-display affordances. The SSO entry control and
  the redirect-into-Custom-Tab call live in / are triggered from that screen and its
  `LoginViewModel`.
- Cookie/session machinery is shared with the password+MFA flow (project auth context:
  `POST /ui/session/start` → MFA → `POST /ui/session/finalize` → `GET /ui/me`, with the
  `ui_csrf` cookie echoed as `X-CSRF-Token` and single `POST /ui/session/refresh`
  retry on 401). SSO reuses the **same persistent cookie jar**; the IdP round-trip
  results in the backend setting the same session cookies on the redirect response.
- Backend: FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is **plaintext
  HTTP** and unreliable — design for ~20s timeouts and bounded backoff on the
  idempotent `getSsoInfo` GET only.
- OpenAPI: `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`,
  `frontend/src/api/types.ts` — confirm exact `getSsoInfo` field names and the
  `/sso` vs `/saml/login` selection logic against these at implementation time.
- Module layering: `app → feature-auth → core-network/core-data/core-model/core-ui`.
- Canonical namespace / applicationId base: `com.testlogon.android`.

## 3. Functional Requirements

FR-1. The login screen (AND-030) exposes an SSO entry point. After the user enters an
email/identifier (or a tenant/server URL), the app calls `getSsoInfo` to determine
whether SSO is required/available for that identifier or tenant.

FR-2. If `getSsoInfo` reports SSO is enforced (SSO-only tenant), the password fields
are hidden/disabled and a primary "Continue with SSO" button is shown. If SSO is
optional, both the password form and an "Use SSO instead" link are shown. If SSO is
unavailable, behavior is unchanged from AND-030.

FR-3. Tapping the SSO button launches a Custom Tab at the authorization URL. The URL
is either provided directly by `getSsoInfo` (`authorize_url`) or constructed as
`{baseUrl}/sso` / `{baseUrl}/saml/login` with a `return_url` (deep-link) query param
and a client-generated opaque `state` (CSRF/replay guard).

FR-4. After IdP authentication, the backend redirects to the registered deep link
(App Link). The app intercepts it, validates `state`, and finalizes: it calls
`GET /ui/me` (cookies already set by the redirect) to confirm the authenticated
session. On success it navigates to the authenticated graph start destination.

FR-5. The flow handles: user cancels/closes the tab (no session) → return to login,
no error toast; IdP/back-end error redirect (`error` query param) → show mapped error;
state mismatch → reject and show a security error; `GET /ui/me` still 401 → treat as
failed SSO and surface a retryable error.

FR-6. A single in-flight SSO attempt at a time; relaunching cancels/replaces the prior
`state`. Pending state survives process death (app may be killed while the Custom Tab
is foregrounded).

## 4. Technical Design

**Module placement:** all new code in `feature-auth`; networking interface in
`core-network`; models in `core-model`. The deep-link `Activity`/intent filter is
declared in `app`.

**Custom Tabs launcher** (`feature-auth`, wraps AndroidX `androidx.browser:browser`):

```kotlin
interface SsoTabLauncher {
    fun launch(context: Context, authorizeUrl: HttpUrl)
}

class CustomTabsSsoTabLauncher @Inject constructor() : SsoTabLauncher {
    override fun launch(context: Context, authorizeUrl: HttpUrl) {
        val intent = CustomTabsIntent.Builder()
            .setShowTitle(true)
            .setUrlBarHidingEnabled(false)
            .build()
        intent.intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        intent.launchUrl(context, Uri.parse(authorizeUrl.toString()))
        // Fallback if no Custom Tabs provider: ACTION_VIEW to default browser.
    }
}
```

**SSO state machine** (held in `LoginViewModel` from AND-030, extended):

```kotlin
sealed interface SsoUiState {
    data object Idle : SsoUiState
    data object Probing : SsoUiState                       // getSsoInfo in flight
    data class Available(val info: SsoInfo) : SsoUiState   // button shown
    data class AwaitingBrowser(val state: String) : SsoUiState
    data class Finalizing(val state: String) : SsoUiState  // GET /ui/me
    data object Authenticated : SsoUiState
    data class Failed(val message: String, val retryable: Boolean) : SsoUiState
}
```

```kotlin
@HiltViewModel
class LoginViewModel @Inject constructor(
    private val authRepository: AuthRepository,
    private val ssoStateStore: SsoStateStore,         // DataStore-backed pending state
    private val tabLauncher: SsoTabLauncher,
) : ViewModel() {
    val ssoState: StateFlow<SsoUiState>

    fun probeSso(identifier: String)                  // calls getSsoInfo
    fun startSso(context: Context)                     // generates state, launches tab
    fun onSsoRedirect(uri: Uri)                        // from deep link
    fun cancelSso()
}
```

**Deep-link handling.** Register an HTTPS App Link
`https://app.testlogon.com/auth/sso/callback` (verified via assetlinks) AND a custom
scheme fallback `com.testlogon.android://auth/sso/callback` for dev/plaintext hosts
that cannot serve assetlinks. Declared on the single Activity:

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="app.testlogon.com"
          android:pathPrefix="/auth/sso/callback" />
</intent-filter>
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="com.testlogon.android" android:host="auth"
          android:pathPrefix="/sso/callback" />
</intent-filter>
```

The single Activity reads `intent.data` in `onCreate`/`onNewIntent`, routes it to
Navigation-Compose, and the login destination forwards it to
`LoginViewModel.onSsoRedirect(uri)`. The `return_url` sent to the backend matches the
registered deep link (custom scheme for the dev host).

**State store** (`SsoStateStore`, DataStore): persists `pendingState`,
`expiresAtEpochMs`, and `returnScheme`, so a redirect after process death can still be
validated. Cleared on success, cancel, or expiry (TTL 10 min).

## 5. API Contract

**`getSsoInfo`** — discovery (idempotent GET; safe to retry with backoff).
Confirm path/fields against `frontend/src/api/endpoints/*.ts` + `/openapi.json`;
implemented as a Retrofit method:

```kotlin
interface AuthApi {
    @GET("/ui/sso/info")
    suspend fun getSsoInfo(@Query("identifier") identifier: String): SsoInfoDto
}
```

Response shape (Moshi DTO → `core-model` `SsoInfo`):

```json
{
  "sso_enabled": true,
  "sso_enforced": true,
  "tenant": "acme",
  "protocol": "saml",
  "authorize_url": "http://18.222.237.167:8000/saml/login?tenant=acme",
  "display_name": "Acme SSO"
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class SsoInfoDto(
    @Json(name = "sso_enabled") val ssoEnabled: Boolean,
    @Json(name = "sso_enforced") val ssoEnforced: Boolean = false,
    @Json(name = "tenant") val tenant: String? = null,
    @Json(name = "protocol") val protocol: String? = null,   // "saml" | "oidc"
    @Json(name = "authorize_url") val authorizeUrl: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
)
```

**Authorization endpoints (browser, NOT Retrofit):** `GET {baseUrl}/sso` or
`GET {baseUrl}/saml/login`, query params `tenant`, `return_url`,`state`. Opened in the
Custom Tab. Endpoint selection: prefer `authorize_url` from `getSsoInfo`; else choose
`/saml/login` when `protocol == "saml"`, otherwise `/sso`.

**Callback redirect (deep link):** backend redirects to
`{return_url}?state={state}` on success (session + `ui_csrf` cookies set on the
redirect's `Set-Cookie`, captured by the shared persistent cookie jar), or
`{return_url}?error={code}&error_description={msg}&state={state}` on failure.

**Session confirmation:** reuse `GET /ui/me` (returns `200` with the user profile when
authenticated; `401` otherwise). On a single `401`, attempt `POST /ui/session/refresh`
once then retry `GET /ui/me`, consistent with the shared auth client.

`ApiResult<SsoInfo>` and `ApiResult<Me>` wrap results; FastAPI `detail`
(string | `[{msg}]` | `{code,...}`) is normalized by the shared error mapper.

## 6. Data & State Management

- `SsoUiState` (§4) is the single source of truth for the SSO sub-flow, exposed as
  `StateFlow<SsoUiState>` and merged into AND-030's `LoginUiState`.
- Persistent: `SsoStateStore` (DataStore Preferences) holds `pendingState`,
  `expiresAtEpochMs`, `returnUrl`. No SSO data is cached in Room.
- Session cookies (incl. `ui_csrf`) persist in the shared OkHttp persistent cookie
  jar (`core-network`); SSO writes nothing extra — the redirect populates the jar.
- `state` is generated via `SecureRandom` (128-bit, base64url, ~22 chars). It is
  compared in constant time on callback and is single-use (cleared after validation).
- After `Authenticated`, the same post-login navigation/bootstrapping used by the
  password flow runs (fetch `/ui/me`, hydrate session state) — no SSO-specific
  authenticated data model.

## 7. Error Handling & Resilience

- **`getSsoInfo` failures:** ~20s timeout; bounded exponential backoff (e.g. 0.5s,
  1s, 2s; max 3 attempts) since it is an idempotent GET. On exhaustion, fall back to
  the standard password form if available, else show a retryable error. Never block
  the screen indefinitely.
- **No Custom Tabs provider:** fall back to `ACTION_VIEW` (external browser); if no
  browser, show "No browser available to complete sign-in."
- **User cancels / closes tab:** no callback arrives. Detect via Activity resume with
  no redirect intent and `AwaitingBrowser` still pending → return to `Available`
  (silent; no error). Pending `state` retained until TTL or explicit cancel.
- **Error redirect:** parse `error`/`error_description`, map common codes
  (`access_denied`, `tenant_mismatch`, `expired`) to user strings; show `Failed`.
- **State mismatch / missing state:** reject; `Failed("Sign-in could not be verified",
  retryable=true)`; clear pending state.
- **Callback but `GET /ui/me` 401 (after one refresh):** `Failed` retryable; cookies
  cleared to avoid a half-authenticated jar.
- **Process death during browser:** restore `pendingState` from DataStore on
  `onNewIntent`; validate normally. Expired pending state → reject as mismatch.
- **Plaintext dev host:** allow cleartext via network-security-config for the dev IP
  only; custom-scheme callback used since assetlinks cannot be served.

## 8. Security & Privacy

- Use Custom Tabs (shared system browser session/credentials), **never** an embedded
  `WebView`, for IdP login — prevents credential interception and preserves IdP SSO
  cookies.
- `state` parameter is mandatory, `SecureRandom`-generated, single-use,
  constant-time compared, TTL-bounded (10 min) — mitigates CSRF/login-injection and
  replay on the callback.
- App Link with `autoVerify` (assetlinks.json) for production hosts prevents callback
  interception by other apps; custom scheme is dev-only.
- No IdP credentials, SAML assertions, or tokens are stored by the app; only opaque
  session cookies in the encrypted-at-rest persistent jar. `ui_csrf` continues to be
  echoed as `X-CSRF-Token` on subsequent state-changing requests.
- Do not log full `authorize_url`, callback URI, `state`, or cookie values.
- HTTPS enforced for all non-dev hosts; cleartext restricted to the pinned dev IP.

## 9. Accessibility & i18n

- SSO button and "Use SSO instead" link have content descriptions; min 48dp touch
  targets; TalkBack announces state transitions (`Probing` → "Checking sign-in
  options", `Finalizing` → "Completing sign-in").
- Focus returns to the login screen and is moved to the result message on callback.
- All strings (`sso_continue`, `sso_use_instead`, `sso_checking`,
  `sso_failed_generic`, `sso_cancelled`, `sso_no_browser`, IdP error mappings,
  `display_name` fallback) externalized in `strings.xml`; support RTL.
- The IdP UI itself is in the browser and outside app a11y scope; we ensure the
  handoff and return are accessible.

## 10. Telemetry & Logging

Structured analytics events (no PII, no tokens): `sso_probe_started`,
`sso_probe_result{enabled,enforced,protocol}`, `sso_launch{protocol,endpoint}`,
`sso_callback_received{has_error}`, `sso_state_mismatch`, `sso_finalize_result
{success}`, `sso_cancelled`, `sso_no_browser`. Include anonymized tenant where
available. Debug-level logs gated behind `BuildConfig.DEBUG` redact URLs/state.
Latency timers around `getSsoInfo` and around launch→callback for diagnosing the
unreliable dev host.

## 11. Testing Strategy

- **Unit (`core-testing`):** `LoginViewModel` SSO transitions (probe→available→launch
  →callback→authenticated; cancel; error redirect; state mismatch; me-401). Use a fake
  `AuthRepository`, fake `SsoTabLauncher`, in-memory `SsoStateStore`,
  `kotlinx-coroutines-test` + Turbine on `StateFlow`.
- **Endpoint construction tests:** `/sso` vs `/saml/login` selection from `SsoInfo`;
  `return_url`/`state` query encoding; `authorize_url` passthrough.
- **Repository tests:** `getSsoInfo` parsing via MockWebServer (success, `sso_enforced`,
  malformed, timeout→backoff, FastAPI `detail` variants).
- **Deep-link tests:** instrumented test firing `ACTION_VIEW` intents at both
  filters (App Link + custom scheme) → `onSsoRedirect` invoked with parsed params;
  process-death simulation restoring pending state from DataStore.
- **UI (Compose):** SSO-only tenant hides password form and shows the SSO button;
  error/cancel states render correctly (matches web IA per AND-030).
- **Acceptance (manual/E2E):** against a configured SSO-only test tenant, complete the
  full browser round-trip and assert `GET /ui/me` 200 + cookies present.

## 12. Dependencies & Sequencing

- **Depends on AND-030** (login screen host, identifier/server-URL input,
  error-display) — required before this ticket's UI hooks land.
- Reuses the shared cookie jar, `ApiResult`, refresh-on-401 client, and FastAPI error
  mapper from the M1 networking/auth foundation (core-network).
- New library: `androidx.browser:browser` (Custom Tabs). App-module manifest changes
  for deep-link intent filters and `assetlinks.json` hosting (production).
- No downstream ticket is blocked by AND-063 (`blocks: []`); it is an additive auth
  path parallel to password+MFA.

## 13. Risks & Open Questions

- **Q:** Exact `getSsoInfo` path and field names — confirm `/ui/sso/info` vs another
  route and `authorize_url` presence against `/openapi.json` + `frontend/src/api`.
- **Q:** Does the backend accept an app-provided `return_url`, or is the callback host
  fixed/allowlisted server-side? If allowlisted, register the deep-link URL with the
  backend tenant config.
- **Risk:** Dev host is plaintext — assetlinks-verified App Links impossible there;
  mitigated by custom-scheme fallback for dev, App Link for prod.
- **Risk:** Some IdPs block Custom Tabs or force a separate browser; mitigated by
  `ACTION_VIEW` fallback.
- **Risk:** Cookies set on a cross-host redirect may not land in the jar if the
  callback host differs from the API host — verify cookie domain handling end-to-end.
- **Q:** OIDC tenants (`protocol == "oidc"`) — does the same `/sso` broker path cover
  them, or is a distinct endpoint needed?

## 14. Acceptance Criteria

- AC-1 (primary, from backlog): A user on an **SSO-only tenant** can sign in via the
  browser tab and return **authenticated** — `GET /ui/me` returns 200 and session +
  `ui_csrf` cookies are present in the persistent jar; the app navigates to the
  authenticated graph.
- AC-2: For an SSO-only tenant, the password form is hidden/disabled and "Continue
  with SSO" is the primary action after `getSsoInfo` reports `sso_enforced=true`.
- AC-3: The Custom Tab opens the correct endpoint (`/saml/login` for SAML, `/sso`
  otherwise, or `authorize_url` verbatim) with `state` and `return_url` params.
- AC-4: The registered deep link (App Link + dev custom scheme) returns to the app and
  triggers finalization; `state` is validated and single-use.
- AC-5: Cancel/close-tab returns silently to login with pending state retained until
  TTL; error redirect and state-mismatch surface mapped, testable error messages.
- AC-6: `getSsoInfo` uses ~20s timeout with bounded backoff and degrades gracefully
  (fallback to password form or retryable error) on the unreliable dev host.

## 15. Definition of Done

- Code merged to `android-port` in `android/` under `com.testlogon.android`
  (feature-auth + core-network + app manifest changes).
- `getSsoInfo` Retrofit method, `SsoInfo` model, `SsoTabLauncher`, `SsoStateStore`,
  and `LoginViewModel` SSO extensions implemented per §4–§6.
- Deep-link intent filters declared; assetlinks.json hosted for production host; dev
  custom-scheme verified.
- Unit, repository, deep-link, and Compose UI tests (§11) pass in CI; coverage on the
  SSO state machine.
- AC-1…AC-6 verified, including a manual E2E against an SSO-only test tenant.
- No secrets/tokens/state/cookies logged; lint, detekt, and the build (AGP 8.7.3,
  Gradle 8.9, JDK 17) green.
- Strings externalized; TalkBack pass on the login screen SSO controls.
- Spec questions in §13 resolved or filed as follow-up issues referenced in the PR.

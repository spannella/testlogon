---
id: AND-063
title: SSO / SAML login
milestone: M2
epic: E08
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
for the current tenant, launches the backend's SP-initiated **`/saml/login`**
authorization endpoint in an Android **Custom Tab** (Chrome Custom Tabs / AndroidX
Browser), lets the IdP authenticate the user in a trusted browser context, and
receives the completed, cookie-backed session via an HTTPS **App Link** deep link
back into the app.

> CORRECTED (review 2026-06-06): The backend exposes **no `/sso` route**. The only
> SP-initiated authorization endpoint is `GET /saml/login` (the SAML assertion is
> consumed server-side at `POST /saml/acs`). References to `/sso` below are corrected
> to `/saml/login`; see §16. Discovery is `GET /ui/sso/info?tenant=...` and is
> **tenant-scoped**, not identifier-scoped.

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
- OpenAPI: `/openapi.json`. Web reference: `src/api/endpoints/sso.ts`,
  `src/api/types.ts: SsoInfoOut`, `src/pages/Login.tsx`. VERIFIED at review: the only
  SP-initiated route is `/saml/login` (no `/sso`), and `getSsoInfo` returns
  `sso_available`/`sso_only`/`sso_login_url`/`provider_display_name`/`provider_protocol`.
- Module layering: `app → feature-auth → core-network/core-data/core-model/core-ui`.
- Canonical namespace / applicationId base: `com.testlogon.android`.

## 3. Functional Requirements

FR-1. The login screen (AND-030) exposes an SSO entry point. The app calls
`getSsoInfo` for the current **tenant** (`GET /ui/sso/info?tenant=<tenant>`, default
`"default"`) to determine whether SSO is available/enforced. (CORRECTED: discovery is
tenant-scoped — there is no `identifier` query param; the web client calls
`getSsoInfo("default")` on screen mount with `staleTime` 60s. If the app supports a
tenant/server-URL field, pass that value as `tenant`.)

FR-2. If `getSsoInfo` reports `sso_only == true`, the password fields are
hidden/disabled and a primary "Sign in with {provider_display_name}" button is shown.
If `sso_available == true` (and not `sso_only`), the password form is shown alongside a
secondary "Sign in with {provider_display_name}" button. If neither, behavior is
unchanged from AND-030. (CORRECTED field names: `sso_only`/`sso_available`, not
`sso_enforced`/`sso_enabled`; see §5 and §16.)

FR-3. Tapping the SSO button launches a Custom Tab at the authorization URL. The URL
is `sso_login_url` from `getSsoInfo` when present, else `{baseUrl}/saml/login`
(optionally with `?tenant=<tenant>`). (CORRECTED: the backend `/saml/login` accepts
**only** a `tenant` query param. It does **not** accept a client-supplied `return_url`
or `state`; SP-initiated SAML carries replay/CSRF protection in server-side
`RelayState`. The web client navigates straight to `sso_login_url || "/saml/login"`
with no extra params. Any app-generated `state`/`return_url` is therefore a
**local-only** guard, not sent to or honored by the backend — see §8/§16.)

FR-4. After IdP authentication, the backend (`/saml/acs`) sets session + `ui_csrf`
cookies and redirects back to the app's login URL. The app intercepts the deep link,
validates its **local** `state` if one was issued, and finalizes by calling
`GET /ui/me` (cookies already set by the redirect) to confirm the authenticated
session. On success it navigates to the authenticated graph start destination.

FR-5. The flow handles: user cancels/closes the tab (no session) → return to login,
no error toast; backend error redirect (`?error=<code>` query param — real codes:
`sso_validation_failed`, `sso_not_authenticated`, `sso_replay_detected`,
`sso_no_email`, `sso_domain_not_allowed`, `sso_user_not_found`, `account_banned`) →
show mapped error; local `state` mismatch → reject and show a security error;
`GET /ui/me` still 401 → treat as failed SSO and surface a retryable error.
(CORRECTED: error codes are from `src/pages/Login.tsx`; the spec's earlier
`access_denied`/`tenant_mismatch`/`expired` codes were not in the reference app.)

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
`LoginViewModel.onSsoRedirect(uri)`. (CORRECTED: the app does **not** send a
`return_url` to the backend — `/saml/login` does not accept one. The registered deep
link must instead match the backend tenant's configured SAML ACS/return target; see
§13 open item. The custom-scheme fallback is for the dev host only.)

**State store** (`SsoStateStore`, DataStore): persists `pendingState`,
`expiresAtEpochMs`, and `returnScheme`, so a redirect after process death can still be
validated. Cleared on success, cancel, or expiry (TTL 10 min).

## 5. API Contract

**`getSsoInfo`** — discovery (idempotent GET; safe to retry with backoff).
VERIFIED against `src/api/endpoints/sso.ts`, `src/api/types.ts: SsoInfoOut`, and
OpenAPI `GET /ui/sso/info`. The query param is **`tenant`** (default `"default"`),
NOT `identifier`. Implemented as a Retrofit method:

```kotlin
interface AuthApi {
    @GET("/ui/sso/info")
    suspend fun getSsoInfo(
        @Query("tenant") tenant: String = "default",
    ): SsoInfoDto
}
```

Response shape (CORRECTED to match `SsoInfoOut`; Moshi DTO → `core-model` `SsoInfo`):

```json
{
  "sso_available": true,
  "sso_only": true,
  "sso_login_url": "http://18.222.237.167:8000/saml/login?tenant=acme",
  "provider_display_name": "Acme SSO",
  "provider_protocol": "saml"
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class SsoInfoDto(
    @Json(name = "sso_available") val ssoAvailable: Boolean = false,
    @Json(name = "sso_only") val ssoOnly: Boolean = false,
    @Json(name = "sso_login_url") val ssoLoginUrl: String? = null,
    @Json(name = "provider_display_name") val providerDisplayName: String? = null,
    @Json(name = "provider_protocol") val providerProtocol: String? = null,
)
```

> Note: OpenAPI declares the `200` response schema for `/ui/sso/info` as an untyped
> `{}` (empty schema). The field shape above is taken from the frontend `SsoInfoOut`
> TypeScript interface, which is the authoritative client contract. Treat all fields
> as defensively-nullable in Moshi.

**Authorization endpoint (browser, NOT Retrofit):** `GET {baseUrl}/saml/login`,
**only** query param `tenant` (default `"default"`). Opened in the Custom Tab.
Endpoint selection: use `sso_login_url` verbatim when present; else
`{baseUrl}/saml/login?tenant=<tenant>`. (CORRECTED: there is no `/sso` route and the
endpoint does not accept `return_url`/`state` — verified against OpenAPI
`GET /saml/login` params=`tenant` and `src/pages/Login.tsx` which navigates to
`ssoInfo.sso_login_url || "/saml/login"`.)

**Callback redirect (deep link):** the backend `/saml/acs` consumes the IdP assertion,
sets session + `ui_csrf` cookies (`Set-Cookie`, captured by the shared persistent
cookie jar), and redirects back to the login URL. On failure it redirects with
`?error=<code>` (codes enumerated in §3 FR-5 / §7, sourced from `src/pages/Login.tsx`).
There is no `error_description` or echoed `state` param in the reference client.

**Session confirmation:** reuse `GET /ui/me` → `MeResp` (`200` with profile when
authenticated; `401` otherwise). VERIFIED: `getMe()` in `src/api/endpoints/auth.ts`.
NOTE (CORRECTED behavior): the shared client's refresh-on-401 retry
(`POST /ui/session/refresh`) fires **only when the user is already authenticated** in
the auth store (`src/api/client.ts` lines 194–214). The first post-callback
`GET /ui/me` runs while the app is still unauthenticated, so a 401 there propagates
directly and must be treated as failed SSO — do **not** assume an automatic refresh
rescues the initial confirmation call.

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
- **Error redirect:** parse the `?error=<code>` query param and map the real backend
  codes (CORRECTED — verified in `src/pages/Login.tsx`): `sso_validation_failed`,
  `sso_not_authenticated`, `sso_replay_detected`, `sso_no_email`,
  `sso_domain_not_allowed`, `sso_user_not_found`, `account_banned`; unknown codes fall
  back to a generic "SSO error: {code}". There is no `error_description` param. Show
  `Failed`.
- **Local state mismatch / missing state:** reject; `Failed("Sign-in could not be
  verified", retryable=true)`; clear pending state. NOTE: `state` is a client-side-only
  guard (the backend does not echo it); its absence on a legitimate ACS redirect must
  not by itself block finalization — gate on `GET /ui/me` as the source of truth.
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
- `state` parameter (CORRECTED scope): the backend `/saml/login` does **not** accept
  or echo a client `state`; SP-initiated SAML replay/CSRF protection lives server-side
  in `RelayState` and surfaces as the `sso_replay_detected` error. Any app-side `state`
  is therefore a **local-only** defense-in-depth token: `SecureRandom`-generated,
  single-use, constant-time compared, TTL-bounded (10 min), used only to correlate a
  returning deep link with the launch this app initiated. The authoritative session
  check remains `GET /ui/me`. Do not block a valid ACS redirect solely on a missing
  local `state`.
- App Link with `autoVerify` (assetlinks.json) for production hosts prevents callback
  interception by other apps; custom scheme is dev-only.
- No IdP credentials, SAML assertions, or tokens are stored by the app; only opaque
  session cookies in the encrypted-at-rest persistent jar. `ui_csrf` continues to be
  echoed as `X-CSRF-Token` on subsequent state-changing requests.
- Do not log full `sso_login_url`, callback URI, local `state`, or cookie values.
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
`sso_probe_result{available,only,protocol}`, `sso_launch{protocol,endpoint}`,
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
- **Endpoint construction tests:** `sso_login_url` passthrough vs
  `{baseUrl}/saml/login?tenant=<tenant>` fallback; `tenant` query encoding. (No
  `return_url`/`state` are sent to the backend — assert they are NOT appended.)
- **Repository tests:** `getSsoInfo` parsing via MockWebServer (success with
  `sso_only=true`, `sso_available=true`-only, malformed/empty body, timeout→backoff,
  FastAPI `detail` variants on 422).
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

- **RESOLVED (review 2026-06-06):** `getSsoInfo` path is `GET /ui/sso/info?tenant=...`;
  fields are `sso_available`, `sso_only`, `sso_login_url`, `provider_display_name`,
  `provider_protocol` (no `authorize_url`). Source: `SsoInfoOut` in `src/api/types.ts`
  + OpenAPI `GET /ui/sso/info`.
- **RESOLVED:** The backend does **not** accept an app-provided `return_url`. `/saml/login`
  takes only `tenant`; the ACS redirect target is fixed server-side and the failure
  redirect carries `?error=`. The Android deep-link/App-Link registration must match
  whatever the backend's configured SP/ACS return target is — **OPEN**: confirm with
  backend team that the tenant's SAML SP config can be pointed at the app's App Link
  host (`https://app.testlogon.com/auth/sso/callback`) for the native flow, since the
  client cannot supply it per-request.
- **Risk:** Dev host is plaintext — assetlinks-verified App Links impossible there;
  mitigated by custom-scheme fallback for dev, App Link for prod.
- **Risk:** Some IdPs block Custom Tabs or force a separate browser; mitigated by
  `ACTION_VIEW` fallback.
- **Risk:** Cookies set on a cross-host redirect may not land in the jar if the
  callback host differs from the API host — verify cookie domain handling end-to-end.
- **Q:** OIDC tenants (`provider_protocol == "oidc"`) — the reference backend exposes
  only SAML routes (`/saml/login`, `/saml/acs`, `/saml/metadata`, `/saml/slo`); there
  is no generic OIDC broker route. If `provider_protocol` ever reports `oidc`, the
  `sso_login_url` from `getSsoInfo` must be honored verbatim (do not assume `/saml/login`).

## 14. Acceptance Criteria

- AC-1 (primary, from backlog): A user on an **SSO-only tenant** can sign in via the
  browser tab and return **authenticated** — `GET /ui/me` returns 200 and session +
  `ui_csrf` cookies are present in the persistent jar; the app navigates to the
  authenticated graph.
- AC-2: For an SSO-only tenant, the password form is hidden/disabled and "Sign in with
  {provider_display_name}" is the primary action after `getSsoInfo` reports
  `sso_only=true`. (CORRECTED field: `sso_only`, not `sso_enforced`.)
- AC-3: The Custom Tab opens the correct endpoint — `sso_login_url` verbatim when
  present, else `{baseUrl}/saml/login?tenant=<tenant>`. (CORRECTED: there is no `/sso`
  route and `/saml/login` accepts only `tenant`; no `state`/`return_url` are sent to
  the backend.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer (OpenAPI
`METHOD /path` / schema name, frontend path, or framework ref).

1. **Discovery endpoint is `GET /ui/sso/info`.** VERDICT: Verified.
   SOURCE: OpenAPI `GET /ui/sso/info` (op `sso_info_ui_sso_info_get`);
   `src/api/endpoints/sso.ts: getSsoInfo`.
2. **`getSsoInfo` query param is `tenant` (default `"default"`), not `identifier`.**
   VERDICT: Corrected (spec used `@Query("identifier")`).
   SOURCE: OpenAPI `GET /ui/sso/info` params=`tenant`; `src/api/endpoints/sso.ts`
   (`api.get("/ui/sso/info", { tenant })`).
3. **`SsoInfo` fields = `sso_available`, `sso_only`, `sso_login_url`,
   `provider_display_name`, `provider_protocol`.** VERDICT: Corrected (spec claimed
   `sso_enabled`/`sso_enforced`/`tenant`/`protocol`/`authorize_url`/`display_name`).
   SOURCE: `src/api/types.ts: SsoInfoOut`. (OpenAPI 200 schema for `/ui/sso/info` is an
   untyped `{}`, so the TS interface is the authoritative shape.)
4. **SP-initiated authorization endpoint is `GET /saml/login`; there is NO `/sso`
   route.** VERDICT: Corrected (spec offered `/sso` as a primary/alternate path).
   SOURCE: OpenAPI index — `/saml/login`, `/saml/acs`, `/saml/metadata`, `/saml/slo`
   exist; grep for `/sso` path returns no operation; `src/pages/Login.tsx` navigates to
   `ssoInfo.sso_login_url || "/saml/login"`.
5. **`/saml/login` accepts only the `tenant` query param — no `return_url`, no
   `state`.** VERDICT: Corrected (spec constructed `return_url`+`state`).
   SOURCE: OpenAPI `GET /saml/login` params=`tenant`
   (desc: "SP-initiated SSO: build AuthnRequest and redirect to IdP").
6. **Custom Tab opens `sso_login_url` verbatim when present, else
   `{baseUrl}/saml/login`.** VERDICT: Verified.
   SOURCE: `src/pages/Login.tsx` (`window.location.href = ssoInfo.sso_login_url ||
   "/saml/login"`).
7. **SSO-only UI: `sso_only==true` hides password form and makes SSO the primary
   button; `sso_available==true` shows SSO alongside the password form.** VERDICT:
   Corrected (spec keyed off `sso_enforced`).
   SOURCE: `src/pages/Login.tsx` (`ssoInfo?.sso_only ? ... : ...` and
   `ssoInfo?.sso_available && <Button .../>`).
8. **Failure redirect uses `?error=<code>` with codes `sso_validation_failed`,
   `sso_not_authenticated`, `sso_replay_detected`, `sso_no_email`,
   `sso_domain_not_allowed`, `sso_user_not_found`, `account_banned`.** VERDICT:
   Corrected (spec invented `access_denied`/`tenant_mismatch`/`expired`).
   SOURCE: `src/pages/Login.tsx` (`searchParams.get("error")` switch). No
   `error_description` param exists in the reference client.
9. **Session confirmation via `GET /ui/me` (200 profile / 401).** VERDICT: Verified.
   SOURCE: OpenAPI `GET /ui/me` (op `ui_me_ui_me_get`);
   `src/api/endpoints/auth.ts: getMe` → `MeResp`.
10. **`ui_csrf` cookie echoed as `X-CSRF-Token` header; cookie-based session
    (`credentials: include`).** VERDICT: Verified.
    SOURCE: `src/api/client.ts` lines 167–170 (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`), line 124/183 `credentials: "include"`.
11. **Single refresh-on-401 retry via `POST /ui/session/refresh`, but only when already
    authenticated.** VERDICT: Corrected/clarified (spec implied refresh rescues the
    initial post-callback `/ui/me`; it does not while unauthenticated).
    SOURCE: `src/api/client.ts` lines 194–214 (`if (!useAuthStore.getState()
    .isAuthenticated) throw` before refresh); OpenAPI `POST /ui/session/refresh`.
12. **Password+MFA companion flow: `POST /ui/session/start` → MFA →
    `POST /ui/session/finalize`.** VERDICT: Verified.
    SOURCE: OpenAPI `POST /ui/session/start` (req `UiSessionStartReq` →
    `UiSessionStartResp`), `POST /ui/session/finalize` (req `UiSessionFinalizeReq`);
    `src/api/endpoints/auth.ts: sessionStart`/`sessionFinalize`;
    `src/pages/Login.tsx` `handleCredentials`/`handleMfaVerify`.
13. **`/saml/acs` is the assertion-consumer endpoint that sets cookies and redirects.**
    VERDICT: Verified (existence + role).
    SOURCE: OpenAPI `POST /saml/acs` (op `saml_acs_saml_acs_post`); `src/pages/Login.tsx`
    comment "SSO error from URL params (set by ACS redirect)".
14. **Use Custom Tabs (AndroidX `androidx.browser:browser`), never a WebView, for IdP
    login.** VERDICT: Verified (framework ref / best practice).
    SOURCE: framework ref — Android Custom Tabs guide
    (https://developer.android.com/develop/ui/views/layout/webapps/overview-of-android-custom-tabs);
    OAuth-in-app best practice (RFC 8252, native apps SHOULD use the system browser).
15. **HTTPS App Links with `autoVerify` + `assetlinks.json` to claim the callback host.**
    VERDICT: Verified (framework ref).
    SOURCE: framework ref — Android App Links / Digital Asset Links
    (https://developer.android.com/training/app-links/verify-android-applinks).
16. **`SsoStateStore` via Jetpack DataStore (Preferences) for pending-state survival
    across process death.** VERDICT: Verified (framework ref for the mechanism;
    the *need* for it is an app-side design choice, see Open assumptions).
    SOURCE: framework ref — DataStore
    (https://developer.android.com/topic/libraries/architecture/datastore).
17. **Dev host `http://18.222.237.167:8000` is plaintext HTTP; needs cleartext
    network-security-config for that host only.** VERDICT: Verified (matches spec
    context) / framework ref for the mechanism.
    SOURCE: spec §2/§7 context; framework ref — Network security config
    (https://developer.android.com/privacy-and-security/security-config).

### Corrections made

- §1/§3/§5/§14: replaced the non-existent `/sso` route with `/saml/login`
  (claim 4); removed client-supplied `return_url`/`state` query params from the
  authorization request (claim 5).
- §3 FR-1 / §5: `getSsoInfo` query param `identifier` → `tenant` (claim 2).
- §5/§6/§4: `SsoInfoDto` rewritten to `sso_available`/`sso_only`/`sso_login_url`/
  `provider_display_name`/`provider_protocol` (claim 3); telemetry field names in §10
  updated accordingly.
- §3 FR-2 / §14 AC-2: gating field `sso_enforced` → `sso_only`; `sso_enabled` →
  `sso_available` (claim 7).
- §3 FR-5 / §7: SSO error codes replaced with the real `?error=` codes from
  `Login.tsx`; removed the non-existent `error_description` param (claim 8).
- §5/§8: reframed app-side `state` as a local-only correlation guard (backend does not
  accept/echo it); clarified that finalization gates on `GET /ui/me`, not on `state`
  (claims 5, 11).
- §5: documented that the shared refresh-on-401 retry does not fire for the first
  post-callback `/ui/me` because the app is still unauthenticated (claim 11).
- §13: marked the `getSsoInfo` field-names and `return_url` questions RESOLVED; added a
  concrete open item about backend ACS/return-target registration.

### Open assumptions

- **App Link callback host registration.** The backend `/saml/login` does not accept a
  per-request `return_url`, and the OpenAPI/frontend sources do not reveal where the SP
  ACS redirects for a *native* client. Unverifiable from the given sources — requires
  backend tenant SAML SP config. (Why: no source describes native deep-link return.)
- **`state`/`return_url`/custom-scheme handoff design.** The entire app-side
  state-machine, DataStore pending-state, TTL, and custom-scheme fallback are native
  design choices not present in the web reference (web simply does a full-page
  navigation and reads `?error=` on return). Reasonable, but unverified against backend
  behavior on Android. (Why: web reference uses same-origin navigation, not deep links.)
- **`getSsoInfo` 200 response schema.** OpenAPI declares it untyped (`{}`); we rely on
  the `SsoInfoOut` TS interface. Treat fields as nullable; an extra/renamed field on
  the wire would not be caught by the spec. (Why: backend OpenAPI omits the schema.)
- **Cookie domain on cross-host ACS redirect.** Whether session/`ui_csrf` cookies land
  in the OkHttp jar when the App-Link callback host differs from the API host is not
  determinable from the sources; must be validated E2E (see TC-AND-063-08). (Why: no
  source documents cookie `Domain`/`SameSite` for the redirect.)
- **~20s timeout + backoff for the dev host.** A spec design value, not a backend
  contract; carried forward unverified. (Why: not expressible in OpenAPI/frontend.)
- **Provider-protocol `oidc` handling.** Backend exposes only SAML routes; behavior if
  `provider_protocol == "oidc"` is unverified — design defers to `sso_login_url`
  verbatim. (Why: no OIDC broker route in the reference backend.)

## 17. Test Plan

Acceptance-criteria references point at §14 (AC-1…AC-6). Test targets: JVM =
JVM/Robolectric local; Emu = headless AVD `test35` (x86_64, API 35); Phys = physical
Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) on the build host via adb.

- **TC-AND-063-01 — getSsoInfo happy path (sso_only tenant) parses correctly.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues `200` with body
  `{"sso_available":true,"sso_only":true,"sso_login_url":"http://host/saml/login?tenant=acme","provider_display_name":"Acme SSO","provider_protocol":"saml"}`.
  Steps: call `AuthApi.getSsoInfo("acme")`; assert request path `/ui/sso/info` and
  query `tenant=acme` (no `identifier`); map to `SsoInfo`.
  Expected: DTO fields populated; `ssoOnly==true`, `ssoLoginUrl` non-null.
  Traces: AC-2, AC-3.

- **TC-AND-063-02 — SSO-available (not only) parses and exposes optional SSO.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: `200` body with `sso_available:true, sso_only:false, sso_login_url`
  present.
  Steps: call `getSsoInfo`; inspect mapped model.
  Expected: `ssoAvailable==true && ssoOnly==false`; ViewModel will show password form
  plus SSO button.
  Traces: AC-2.

- **TC-AND-063-03 — Authorization URL selection / construction.**
  Type: unit. Target: JVM.
  Preconditions: two `SsoInfo` fixtures — (a) with `ssoLoginUrl` set, (b) with it null
  and `tenant="acme"`.
  Steps: invoke the URL-builder used by `startSso`.
  Expected: (a) returns `ssoLoginUrl` verbatim; (b) returns
  `{baseUrl}/saml/login?tenant=acme`; in BOTH cases the URL contains NO `return_url`
  and NO `state` query param.
  Traces: AC-3.

- **TC-AND-063-04 — LoginViewModel SSO state machine: probe→available→launch→callback→
  authenticated.** Type: unit. Target: JVM (Turbine + coroutines-test).
  Preconditions: fake `AuthRepository` (getSsoInfo→sso_only, getMe→200), fake
  `SsoTabLauncher`, in-memory `SsoStateStore`.
  Steps: `probeSso()` → `startSso()` → feed `onSsoRedirect(callbackUri)` →
  observe `ssoState`.
  Expected: emits `Probing → Available → AwaitingBrowser → Finalizing →
  Authenticated`; `tabLauncher.launch` called once.
  Traces: AC-1, AC-2, AC-4.

- **TC-AND-063-05 — Error redirect maps real backend codes.**
  Type: unit. Target: JVM.
  Preconditions: ViewModel in `AwaitingBrowser`.
  Steps: feed `onSsoRedirect` with `...?error=sso_replay_detected` (and parametrized
  over `sso_validation_failed`, `sso_not_authenticated`, `sso_no_email`,
  `sso_domain_not_allowed`, `sso_user_not_found`, `account_banned`, and an unknown
  code).
  Expected: state → `Failed` with the mapped, externalized string per code; unknown
  code → generic "SSO error: {code}". No crash on missing `error_description`.
  Traces: AC-5.

- **TC-AND-063-06 — Local state mismatch rejected; valid ACS without local state still
  finalizes via /ui/me.** Type: unit. Target: JVM.
  Preconditions: pending local `state="A"`.
  Steps: (a) callback carries `state=B` → expect `Failed(retryable=true)`, pending
  cleared; (b) separately, callback carries NO `state` but `getMe→200` → expect
  `Authenticated` (state is a local-only guard; /ui/me is source of truth).
  Expected: as above; constant-time compare used.
  Traces: AC-4, AC-5.

- **TC-AND-063-07 — Post-callback /ui/me returns 401 → failed, no false refresh.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: app unauthenticated; MockWebServer returns `401` for `GET /ui/me`.
  Steps: drive finalization.
  Expected: `Failed(retryable=true)`; NO automatic `POST /ui/session/refresh` is issued
  for this first unauthenticated call (matches `client.ts` 194–214); cookie jar cleared
  to avoid half-auth state.
  Traces: AC-1, AC-5.

- **TC-AND-063-08 — Full SSO round-trip against SSO-only tenant (E2E, real browser +
  cookies).** Type: instrumented/e2e. Target: **Phys (must)**.
  Why physical: needs the real Chrome Custom Tabs provider, the system browser's IdP
  session/cookies, and real cross-host redirect cookie handling — not reliable on a
  headless emulator without a signed-in browser.
  Preconditions: device provisioned for an SSO-only test tenant; IdP test creds; app
  built with App-Link (or dev custom-scheme) callback registered to match backend ACS.
  Steps: tap "Sign in with SSO"; complete IdP login in the tab; observe deep-link
  return.
  Expected: app finalizes; `GET /ui/me`→200; session + `ui_csrf` cookies present in the
  persistent jar; app navigates to the authenticated graph.
  Traces: AC-1, AC-3, AC-4.

- **TC-AND-063-09 — Cancel / close tab returns silently.**
  Type: instrumented. Target: Emu (or Phys).
  Preconditions: ViewModel in `AwaitingBrowser`; Custom Tab open.
  Steps: dismiss the tab (back/close) without completing IdP; resume the app with no
  redirect intent.
  Expected: state returns to `Available`; no error toast; pending `state` retained
  until TTL.
  Traces: AC-5.

- **TC-AND-063-10 — Deep-link intent filters fire onSsoRedirect (App Link + custom
  scheme).** Type: instrumented. Target: Emu.
  Preconditions: app installed; both intent filters declared.
  Steps: fire `ACTION_VIEW` for
  `https://app.testlogon.com/auth/sso/callback?error=sso_user_not_found` and for
  `com.testlogon.android://auth/sso/callback`.
  Expected: the single Activity routes both to `LoginViewModel.onSsoRedirect(uri)` with
  parsed params.
  Traces: AC-4.

- **TC-AND-063-11 — Pending state survives process death.**
  Type: instrumented. Target: Emu.
  Preconditions: `startSso` issued; `pendingState` + `expiresAtEpochMs` persisted to
  DataStore.
  Steps: simulate process death (kill), relaunch via `onNewIntent` with the callback.
  Expected: pending state restored and validated; finalization proceeds; expired
  pending state (past TTL) → rejected as mismatch.
  Traces: AC-4, AC-5.

- **TC-AND-063-12 — getSsoInfo flaky/offline dev host: timeout, backoff, graceful
  degrade.** Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer with throttled/no response (~exceeds 20s) or
  `SocketPolicy.NO_RESPONSE`, then a 500/timeout sequence.
  Steps: call `getSsoInfo` through the repo.
  Expected: ~20s timeout; bounded exponential backoff (≤3 attempts, 0.5/1/2s); on
  exhaustion either falls back to the password form (if available) or surfaces a
  retryable error; screen never blocks indefinitely.
  Traces: AC-6.

- **TC-AND-063-13 — No-Custom-Tabs / no-browser fallback.**
  Type: instrumented. Target: Emu (uninstall/disable browser to simulate) or Phys.
  Preconditions: (a) no Custom Tabs provider but a browser present; (b) no browser.
  Steps: tap SSO button.
  Expected: (a) falls back to `ACTION_VIEW` external browser; (b) shows
  "No browser available to complete sign-in." (`sso_no_browser`).
  Traces: AC-3, AC-5.

- **TC-AND-063-14 — Compose UI + accessibility for SSO-only and SSO-available states.**
  Type: Compose-UI. Target: Emu (Robolectric/compose-test acceptable).
  Preconditions: `getSsoInfo` stubbed to `sso_only`, then `sso_available`.
  Steps: render the login screen for each; run TalkBack/semantics assertions.
  Expected: `sso_only` → password fields absent, "Sign in with {provider}" primary;
  `sso_available` → password form + SSO button both present; SSO control has a content
  description and ≥48dp touch target; state transitions (`Probing`/`Finalizing`)
  announce via semantics; strings are externalized (no hardcoded literals).
  Traces: AC-2, AC-3.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (SSO-only signs in, /ui/me 200 + cookies) | TC-04, TC-07, TC-08 |
| AC-2 (sso_only hides password, SSO primary) | TC-01, TC-02, TC-04, TC-14 |
| AC-3 (correct endpoint: sso_login_url / /saml/login, no state/return_url) | TC-01, TC-03, TC-08, TC-13, TC-14 |
| AC-4 (deep link returns, state validated single-use) | TC-04, TC-06, TC-08, TC-10, TC-11 |
| AC-5 (cancel silent; error + state-mismatch mapped) | TC-05, TC-06, TC-07, TC-09, TC-11, TC-13 |
| AC-6 (getSsoInfo timeout/backoff/degrade) | TC-12 |

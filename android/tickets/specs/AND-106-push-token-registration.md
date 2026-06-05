---
id: AND-106
title: Push token registration
milestone: M2
epic: E15
priority: P0
size: M
status: draft
depends_on: [AND-105, AND-029]
blocks: []
---

# AND-106 — Push token registration

## 1. Overview & Goal

This ticket delivers the client-side registration of the device's Firebase Cloud
Messaging (FCM) token with the TestLogon backend so the server can target push
notifications at an authenticated user/device pair. AND-105 establishes the FCM
plumbing (Firebase SDK, `google-services.json` per flavor, a
`FirebaseMessagingService` that surfaces token rotations and inbound messages).
AND-029 establishes the authenticated session and the persistent auth-state store
(`authenticated` flag + `user_sub`) backed by DataStore. AND-106 connects the two:
**after a session is finalized and `GET /ui/me` succeeds, the current FCM token is
posted to `POST /ui/push/register`, and the local device→token→user mapping is
persisted so we only re-register when something actually changed.**

The goal is a correct, idempotent, resilient registration path that:

- Registers the token exactly once per `(user_sub, token)` tuple per server-confirmed
  success, and re-registers on token rotation, login by a different user, or app
  upgrade where the contract version changed.
- Treats registration as a best-effort background side effect of login — it must
  never block, degrade, or fail the login flow or the UI.
- Survives the unreliable plaintext dev backend (timeouts, transient 5xx, 401
  session expiry) via bounded retry and deferred re-attempts.

Out of scope: receiving/displaying notifications, notification channels, the
`POST_NOTIFICATIONS` runtime permission UX, and deep-link routing — those belong to
sibling E15 tickets. This ticket only *registers* the token.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp
  4.12 + Moshi 1.15, DataStore (Preferences), WorkManager for deferred retry.
- **Module layering:** `app -> feature-* -> core-*`. This ticket adds a thin
  `feature-push` (registration orchestration + WorkManager worker) on top of
  `core-network` (Retrofit service, cookie/CSRF interceptors from AND-011/AND-028)
  and `core-data` (auth-state DataStore from AND-029). The FCM service from AND-105
  lives in `feature-push` or `app`; this ticket hooks into its `onNewToken`.
- **Auth model:** Cookie-based session. `POST /ui/session/start` →
  MFA → `POST /ui/session/finalize` → `GET /ui/me`. The session rides on the cookie
  jar plus a `ui_csrf` cookie echoed as the `X-CSRF-Token` header. On 401 the
  network layer calls `POST /ui/session/refresh` once and retries. `POST
  /ui/push/register` is an authenticated, state-changing call and therefore requires
  both the session cookies and the CSRF header — both supplied automatically by the
  existing OkHttp interceptors. **No bearer token is involved.**
- **Backend:** FastAPI + DynamoDB at `http://18.222.237.167:8000` (PLAINTEXT, dev,
  unreliable). OpenAPI at `/openapi.json`. FastAPI error `detail` may be a string,
  a `[{msg}]` list, or a `{code,...}` object — reuse the shared `detail` mapper.
- **Web reference:** `frontend/src/api/endpoints/*.ts`, shared types
  `frontend/src/api/types.ts`. Confirm the exact `push/register` request shape
  against `/openapi.json` before freezing the DTO (see §5 Open Question).
- **Namespace:** `com.testlogon.android` everywhere a package appears.

## 3. Functional Requirements

FR-1. On every transition to authenticated state (after `GET /ui/me` succeeds in
AND-029's flow), the app SHALL attempt to obtain the current FCM token and register
it.

FR-2. On `FirebaseMessagingService.onNewToken(token)`, the app SHALL register the
new token **if and only if** the user is currently authenticated; otherwise it SHALL
cache the token locally and register at next login.

FR-3. Registration SHALL be idempotent against local state: the app SHALL NOT call
`POST /ui/push/register` when the persisted last-registered tuple
`(user_sub, fcm_token, contractVersion)` equals the current tuple.

FR-4. On user logout (auth state → unauthenticated, AND-029), the persisted
last-registered tuple SHALL be cleared so the next login re-registers. (Server-side
deregistration on logout is a separate concern and not required here; document as
open question §13.)

FR-5. Registration SHALL run off the main thread, SHALL NOT block the login UI, and
SHALL NOT surface errors into the auth UiState. A failed registration leaves the
user fully logged in.

FR-6. On transient failure (timeout, network, 5xx), registration SHALL be retried
with bounded in-call backoff, and if still failing, deferred to a WorkManager job
(network-constrained) for a later attempt.

FR-7. Acceptance-critical: the token SHALL be registered post-login and SHALL be
verifiable server-side; the request shape and trigger SHALL be testable with
MockWebServer.

## 4. Technical Design

New module `feature-push` under `com.testlogon.android.feature.push`.

**DTOs** (`core-network` or `feature-push` `data` package), Moshi `@JsonClass`:

```kotlin
@JsonClass(generateAdapter = true)
data class PushRegisterRequest(
    @Json(name = "token") val token: String,
    @Json(name = "platform") val platform: String = "android",
    @Json(name = "app_version") val appVersion: String,
    @Json(name = "device_id") val deviceId: String,   // stable per-install UUID
)

@JsonClass(generateAdapter = true)
data class PushRegisterResponse(
    @Json(name = "registered") val registered: Boolean,
    @Json(name = "device_id") val deviceId: String? = null,
)
```

**Retrofit service:**

```kotlin
interface PushApi {
    @POST("ui/push/register")
    suspend fun registerToken(@Body body: PushRegisterRequest): Response<PushRegisterResponse>
}
```

**Repository** wraps the call in the project's typed `ApiResult<T>` (success / error
with mapped `detail` / network failure):

```kotlin
interface PushRepository {
    suspend fun registerCurrentToken(forceToken: String? = null): ApiResult<Unit>
    suspend fun onLogout()
}

class PushRepositoryImpl @Inject constructor(
    private val api: PushApi,
    private val tokenProvider: FcmTokenProvider,   // wraps FirebaseMessaging.token
    private val store: PushRegistrationStore,      // DataStore, §6
    private val authState: AuthStateStore,         // from AND-029
    private val appInfo: AppInfoProvider,          // versionName, install deviceId
) : PushRepository { /* ... */ }
```

`registerCurrentToken` logic:

1. Read `authState.current()`; if not authenticated → cache token (if provided),
   return `ApiResult.Success(Unit)` (no-op).
2. Resolve `token` = `forceToken ?: tokenProvider.currentToken()` (awaits
   `FirebaseMessaging.getInstance().token`); on failure return network error.
3. Build current tuple `(user_sub, token, CONTRACT_VERSION)`; compare to
   `store.lastRegistered()`. If equal → success no-op.
4. Call `api.registerToken(...)`. On success persist the tuple via
   `store.setLastRegistered(...)`; return success. On error map and return.

**Triggering — `FcmTokenRegistrar`** (singleton, Hilt). Two entry points:

- `AuthStateStore.flow` is collected in an application-scoped coroutine; on the
  edge `false→true` it calls `registerCurrentToken()`.
- `FirebaseMessagingService.onNewToken` calls `registrar.onNewToken(token)` which
  delegates to `registerCurrentToken(forceToken = token)`.

`onLogout()` clears `store` (FR-4). The collector is started from a
`@HiltAndroidApp` Application or an `Initializer` (Startup) bound to the
application `CoroutineScope` (SupervisorJob + Dispatchers.IO).

**Deferred retry — WorkManager.** When in-call retries are exhausted,
`registerCurrentToken` enqueues `PushRegisterWorker` (Hilt-injected
`@HiltWorker`) with a unique name `push_register`,
`ExistingWorkPolicy.REPLACE`, `Constraints(NetworkType.CONNECTED)`, and
exponential backoff (30s initial). The worker re-invokes
`pushRepository.registerCurrentToken()`; it returns `Result.success()` on success
or no-op, `Result.retry()` on transient failure, `Result.failure()` on
unauthenticated/permanent error.

`CONTRACT_VERSION` is a const bumped when the request DTO changes, forcing
re-registration across app upgrades.

## 5. API Contract

**Endpoint:** `POST /ui/push/register` (authenticated; requires session cookies +
`X-CSRF-Token`). Base URL `http://18.222.237.167:8000`.

**Request headers (auto-applied by existing interceptors):** `Cookie: <session>;
ui_csrf=<v>`, `X-CSRF-Token: <v>`, `Content-Type: application/json`.

**Request body:**

```json
{
  "token": "fcm-registration-token-string",
  "platform": "android",
  "app_version": "1.0.0",
  "device_id": "9b1c...-stable-install-uuid"
}
```

**Success `200`:**

```json
{ "registered": true, "device_id": "9b1c...-stable-install-uuid" }
```

**Error `401`** → handled by interceptor (`/ui/session/refresh` once + retry). If
refresh fails, repository returns auth error and registration is deferred to the
next authenticated session — not surfaced to the user.

**Error `4xx` (e.g. 422 validation):** FastAPI `detail`:

```json
{ "detail": [ { "loc": ["body", "token"], "msg": "field required", "type": "value_error.missing" } ] }
```

Mapped via the shared `detail` mapper (string | `[{msg}]` | `{code}`); treated as
permanent (no retry).

**Error `5xx` / timeout:** transient → in-call backoff then WorkManager.

> **Open question (verify before freezing DTO):** the exact field names/required
> fields for `/ui/push/register` MUST be confirmed against `/openapi.json` and
> `frontend/src/api/endpoints/`. If the backend keys on `device_id` server-side,
> our stable per-install UUID is the mapping key; otherwise it keys on `token`.

## 6. Data & State Management

**`PushRegistrationStore`** — a dedicated Preferences DataStore
(`push_registration.preferences_pb`), separate from AND-029's auth store:

```kotlin
class PushRegistrationStore @Inject constructor(
    @ApplicationContext context: Context
) {
    suspend fun lastRegistered(): RegisteredTuple?
    suspend fun setLastRegistered(t: RegisteredTuple)
    suspend fun clear()
    suspend fun cachePendingToken(token: String)
    suspend fun pendingToken(): String?
}

data class RegisteredTuple(
    val userSub: String,
    val token: String,
    val contractVersion: Int,
)
```

Keys: `last_user_sub`, `last_token`, `last_contract_version`, `pending_token`.
`device_id` is a stable per-install UUID generated once and stored here (or reused
from a shared install-id provider if one exists). The auth-state inputs
(`authenticated`, `user_sub`) are **read** from AND-029's `AuthStateStore`, not
duplicated.

State flow: `AuthState(false→true)` ⇒ attempt register ⇒ on success write
`RegisteredTuple`. `onNewToken` ⇒ attempt register with forced token. Logout ⇒
`clear()`. Idempotency is enforced purely by tuple comparison; the network is the
source of truth only on first success.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the OkHttp ~20s call timeout configured project-wide for the
  unreliable dev host.
- **In-call retry:** bounded backoff for the idempotent register POST — up to 2
  retries (e.g. 1s, 4s with jitter). `POST /ui/push/register` is idempotent on the
  server by `(user, device_id)`, so retrying the POST is safe (document the
  idempotency assumption in §13).
- **Deferred retry:** on exhaustion, enqueue `PushRegisterWorker` (NetworkType
  CONNECTED, exponential backoff). Unique work `REPLACE` prevents pile-up of stale
  attempts.
- **401:** delegated to the refresh-once interceptor; if still 401, no-op now,
  retry on next authenticated transition.
- **No token available** (Firebase returns failure, e.g. no Play Services): log,
  treat as transient, schedule WorkManager; never crash.
- **Non-blocking guarantee:** all work runs on application scope / IO; the login
  ViewModel never awaits registration. A registration failure NEVER changes auth
  UiState.

## 8. Security & Privacy

- The FCM token is a device routing identifier, not a credential, but it is
  sensitive (allows targeting this device). It is transmitted only over the
  authenticated session and never logged in full (log a short prefix/hash only,
  §10).
- The `device_id` is a random per-install UUID with no PII and is not derived from
  hardware identifiers (no `ANDROID_ID`/IMEI), respecting Play policy.
- Registration is gated on an authenticated session + valid CSRF header, preventing
  unauthenticated or cross-site token registration.
- **Transport caveat:** the dev backend is plaintext HTTP, so the token transits in
  the clear in dev. Production MUST use HTTPS; the cleartext exception is
  flavor/dev-only (network security config from AND-004). Flag in §13.
- On logout the local mapping is cleared; server-side deregistration is tracked as
  an open question (§13).

## 9. Accessibility & i18n

No user-facing UI is introduced by this ticket (registration is a silent background
side effect), so there are no direct a11y or layout concerns. Any user-visible
strings that could arise — e.g. a future non-blocking "notifications may not work"
diagnostic — are out of scope here and owned by the notification-permission/UX
ticket in E15. No hardcoded user-facing strings are added; internal log/telemetry
text is developer-only and not localized.

## 10. Telemetry & Logging

- Structured debug logs (dev builds) at each step: `register_attempt`,
  `register_skip_unauth`, `register_skip_noop`, `register_success`,
  `register_error{httpCode|reason}`, `register_deferred`, `new_token_received`.
- **Never log the full token** — log `token.takeLast(6)` or a SHA-256 prefix and the
  `device_id`.
- Telemetry counters (via the project analytics facade if present, else no-op):
  count of successful registrations, deferred registrations, and permanent failures
  by mapped error code. These feed E15 reliability dashboards.

## 11. Testing Strategy

**Unit / repository (JVM, `core-testing`):**

- `PushRepositoryImpl` registers when authenticated and tuple differs (asserts
  `POST /ui/push/register` issued with correct JSON body).
- No-op when persisted tuple equals current (asserts **no** request).
- No-op + caches pending token when unauthenticated.
- Token rotation (`onNewToken`) forces registration with the new token.
- Logout clears the store; subsequent login re-registers.

**MockWebServer (acceptance-critical, FR-7):**

- Enqueue `200 {"registered":true}`; assert recorded request path
  `/ui/push/register`, method POST, `X-CSRF-Token` header present, and body matches
  `PushRegisterRequest` (token/platform/app_version/device_id).
- Enqueue `503` then `200`; assert in-call retry results in eventual success.
- Enqueue `401` then (refresh `200`) then `200`; assert refresh-and-retry path.
- Enqueue `422 {"detail":[...]}`; assert mapped error, no retry, no tuple persisted.

**WorkManager:** `PushRegisterWorker` returns `retry()` on transient,
`success()` on success/no-op, `failure()` on unauth — tested with
`TestListenableWorkerBuilder`.

**Instrumentation (smoke):** with a fake/authenticated session and a stubbed
`FcmTokenProvider`, verify a register call fires on the auth `false→true` edge.

## 12. Dependencies & Sequencing

- **Depends on AND-105** (FCM integration + Firebase config): provides
  `FirebaseMessagingService`, `onNewToken`, and the token source. MUST land first.
- **Depends on AND-029** (getMe + auth state store): provides the authenticated
  `AuthStateStore` (`authenticated`, `user_sub`) and the post-`/ui/me` success
  signal that triggers registration. MUST land first.
- Transitively relies on AND-011/AND-028 (Retrofit + cookie jar + CSRF + refresh
  interceptor) and AND-004 (Firebase/network-security config).
- **Blocks:** downstream E15 notification-delivery/routing tickets that assume a
  registered device, though they are not listed in this ticket's source bullets.

## 13. Risks & Open Questions

1. **Exact request schema unknown** — must verify `/ui/push/register` body against
   `/openapi.json` + `frontend/`. Field names in §5 are provisional.
2. **Server idempotency** — in-call POST retry assumes the endpoint upserts by
   `(user, device_id)`. If it instead creates duplicates per call, retries must be
   gated to network-level failures only (no response received). Confirm.
3. **Logout deregistration** — should the client call a deregister endpoint on
   logout so the previous user stops receiving pushes on a shared device? Not in
   scope per the bullets; needs a backend endpoint and a follow-up ticket.
4. **Cleartext dev transport** — token sent over HTTP in dev. Acceptable for dev,
   must be HTTPS in prod.
5. **Multi-user on one device** — registering a new `user_sub` with the same token:
   does the server reassign or stack? Affects FR-3 tuple semantics.

## 14. Acceptance Criteria

AC-1. After a successful login (session finalized + `GET /ui/me` success), the app
issues exactly one `POST /ui/push/register` with the current FCM token, and the
registration is verifiable server-side. (Maps directly to the source acceptance
bullet; verified via MockWebServer recorded request and a manual server check.)

AC-2. The request body contains the FCM `token`, `platform="android"`,
`app_version`, and a stable `device_id`, and carries session cookies +
`X-CSRF-Token`.

AC-3. A second login with the same `(user_sub, token)` issues **no** new register
call (idempotent no-op), confirmed by MockWebServer.

AC-4. `onNewToken` while authenticated triggers re-registration with the new token;
while unauthenticated, the token is cached and registered at next login.

AC-5. Transient failures (timeout / 5xx) retry in-call and then defer to
WorkManager; registration never blocks or fails the login flow or alters auth
UiState.

AC-6. Logout clears the local last-registered mapping; the next login re-registers.

AC-7. The full FCM token never appears in logs.

## 15. Definition of Done

- `feature-push` module added under `com.testlogon.android.feature.push` with
  `PushApi`, `PushRepository`/`Impl`, `PushRegistrationStore`, `FcmTokenRegistrar`,
  and `PushRegisterWorker`, wired via Hilt.
- `onNewToken` and the auth `false→true` edge both drive registration.
- DTO confirmed against `/openapi.json`; `ApiResult` + `detail` mapping reused.
- All unit, MockWebServer, and WorkManager tests in §11 pass in CI; coverage
  includes the acceptance-critical post-login registration path.
- No full-token logging; lint/detekt and `./gradlew :feature-push:test` green.
- Manual verification: a real login on the dev backend produces a server-recorded
  registration for the device.
- Code reviewed and merged to `android-port`; open questions in §13 captured as
  follow-up issues.

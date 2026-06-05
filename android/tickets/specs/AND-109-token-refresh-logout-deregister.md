---
id: AND-109
title: Token refresh + logout deregister
milestone: M2
epic: E15
priority: P1
size: M
status: draft
depends_on: [AND-106, AND-032]
blocks: []
---

# AND-109 — Token refresh + logout deregister

## 1. Overview & Goal

This ticket completes the device push lifecycle for the TestLogon native Android
app. AND-106 established the "happy path" — register an FCM token with the backend
after login. AND-109 closes the two remaining lifecycle gaps:

1. **Token rotation (`onNewToken`).** Firebase Cloud Messaging may rotate a
   device's registration token at any time (app reinstall, data clear, restore to
   a new device, periodic security rotation). When this happens the previously
   registered token becomes invalid and the server will silently stop delivering
   to it. The app must detect rotation via `FirebaseMessagingService.onNewToken`,
   persist the new token, and re-register it with the backend so delivery
   continues uninterrupted.

2. **Logout deregister.** On logout the app must affirmatively tell the backend to
   stop delivering push to this device (`DELETE /ui/push/register`) so that a
   signed-out device receives no further notifications, then clear the locally
   cached token/registration state. This is layered into the existing logout flow
   (AND-032), which must call the deregister step *before* the session cookies are
   cleared (deregister is an authenticated, CSRF-protected call).

**Goal:** Token rotation transparently keeps the device deliverable; logout
provably stops delivery to the device.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp
  4.12 + Moshi 1.15, DataStore (prefs), Firebase Cloud Messaging (Media3/Coil/Room
  not relevant here). minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3,
  Gradle 8.9.
- **Module layering:** `app` → `feature-*` → `core-*`. Push registration logic
  lives in `core-data` (`PushRepository`) and `core-network` (`PushApi`); the FCM
  service lives in `app` (it is an Android component declared in the merged
  manifest). Namespace base: `com.testlogon.android`.
- **Auth model:** Cookie-based session with `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header; persistent cookie jar; on 401 the client calls
  `POST /ui/session/refresh` once then retries (owned by core-network auth
  interceptor). Deregister is an authenticated mutating call and therefore
  requires both a live session cookie and the CSRF header.
- **Dependencies:**
  - **AND-106 (Push token registration, P0)** — provides `PushApi.register`,
    `PushRepository`, the `PushPrefs` DataStore, and the registration JSON shape.
    AND-109 reuses and extends these; it does not re-create them.
  - **AND-032 (Logout flow, P0)** — provides `SessionRepository.logout()` which
    clears cookies, auth state, and caches and routes to login. AND-109 inserts a
    deregister step at the front of that flow.
- **Web reference:** `frontend/src/api/endpoints/push.ts` (register/deregister
  calls), `frontend/src/api/types.ts` (request/response types). Backend OpenAPI at
  `http://18.222.237.167:8000/openapi.json` (`/ui/push/*` paths). Dev backend is
  plaintext HTTP and unreliable: design for ~20s timeouts and bounded retry on
  idempotent operations only.

## 3. Functional Requirements

FR-1. When FCM invokes `onNewToken(token)`, the app shall persist the new token to
`PushPrefs` and attempt to register it with the backend, replacing the previously
registered token for this device.

FR-2. Re-registration on rotation shall be idempotent and resilient: a transient
network/server failure shall not lose the new token. The token is persisted first;
a background, retryable work item performs the network registration so it survives
process death and connectivity loss.

FR-3. Re-registration triggered by rotation shall only call the backend when a
valid session exists. If no session is present (user signed out, or rotation
happened while logged out), the new token shall be persisted and marked
"pending" so it is registered the next time the user logs in (AND-106 owns the
post-login registration trigger; AND-109 ensures the latest token is the one it
picks up).

FR-4. On logout, before session cookies are cleared, the app shall call
`DELETE /ui/push/register` for the currently registered token. After the call
(success or definitive failure) the app shall clear the locally cached token,
registration state, and pending flags from `PushPrefs`.

FR-5. Logout shall not be blocked or delayed by deregister failure. The
deregister call is best-effort with a short timeout; if it fails, logout proceeds,
local push state is still cleared, and a deregister-retry work item is enqueued so
the server is eventually told (it will also be invalidated server-side on next
delivery failure as a backstop).

FR-6. After a successful logout + deregister, the device shall receive no further
push messages associated with the prior session for this token.

FR-7. The new/cleared token state shall be observable via a `StateFlow` so a
debug/diagnostics surface (and tests) can assert current registration status.

## 4. Technical Design

### 4.1 FCM service (`app`)

```kotlin
package com.testlogon.android.push

@AndroidEntryPoint
class TlFirebaseMessagingService : FirebaseMessagingService() {

    @Inject lateinit var pushRepository: PushRepository
    @Inject lateinit var workScheduler: PushWorkScheduler

    override fun onNewToken(token: String) {
        // Called on a binder thread; do not block. Persist synchronously-fast,
        // then hand network work to WorkManager.
        pushRepository.onTokenRotated(token)        // persists token + sets pending
        workScheduler.enqueueRegister()             // idempotent unique work
    }

    override fun onMessageReceived(message: RemoteMessage) {
        // Owned by AND-107/AND-108 (display). No-op here beyond delegation.
    }
}
```

Manifest (merged into app): the service is declared with the
`com.google.firebase.MESSAGING_EVENT` intent filter. No new permission beyond
those introduced by AND-105/AND-106.

### 4.2 Repository (`core-data`)

`PushRepository` (introduced in AND-106) gains rotation + deregister:

```kotlin
interface PushRepository {
    val state: StateFlow<PushRegistrationState>

    /** Persist a rotated token and mark it pending registration. Non-suspending,
     *  safe from onNewToken; does no network I/O. */
    fun onTokenRotated(token: String)

    /** Register the currently-persisted token if a session exists.
     *  Idempotent; safe to call repeatedly (WorkManager retry). */
    suspend fun registerCurrentToken(): ApiResult<Unit>

    /** Deregister the currently-registered token for this device. */
    suspend fun deregisterCurrentToken(): ApiResult<Unit>

    /** Clear all local push state (token, pending flag, last-registered). */
    suspend fun clearLocalPushState()
}
```

```kotlin
enum class PushRegStatus { NONE, PENDING, REGISTERED, DEREGISTERED }

data class PushRegistrationState(
    val token: String?,
    val status: PushRegStatus,
    val lastError: String? = null,
)
```

`onTokenRotated` writes `token` and `status = PENDING` to DataStore.
`registerCurrentToken` reads the token + pending flag, calls `PushApi.register`,
and on success sets `status = REGISTERED`. `deregisterCurrentToken` calls
`PushApi.deregister` for the stored token.

### 4.3 Network (`core-network`)

`PushApi` (from AND-106) gains the deregister method:

```kotlin
interface PushApi {
    @POST("ui/push/register")
    suspend fun register(@Body body: PushRegisterRequest): Response<PushRegisterResponse>

    @HTTP(method = "DELETE", path = "ui/push/register", hasBody = true)
    suspend fun deregister(@Body body: PushDeregisterRequest): Response<Unit>
}
```

The shared `AuthInterceptor`/`CsrfInterceptor` (core-network) attach session
cookies + `X-CSRF-Token` and perform the single `session/refresh`-then-retry on
401. Because deregister at logout runs before cookies are cleared, these
interceptors apply normally.

### 4.4 WorkManager (`core-data`)

Two `CoroutineWorker`s with `BackoffPolicy.EXPONENTIAL` and a
`NetworkType.CONNECTED` constraint, scheduled via Hilt-injected
`PushWorkScheduler`:

```kotlin
@HiltWorker
class RegisterPushWorker @AssistedInject constructor(
    @Assisted ctx: Context, @Assisted params: WorkerParameters,
    private val repo: PushRepository,
) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result = when (repo.registerCurrentToken()) {
        is ApiResult.Success -> Result.success()
        is ApiResult.Error.Network, is ApiResult.Error.Server -> Result.retry()
        else -> Result.failure()   // 4xx (e.g. no session) — don't spin
    }
}
```

`DeregisterPushWorker` mirrors this for the retry-after-logout path (FR-5).
`enqueueRegister()` and `enqueueDeregister()` use
`ExistingWorkPolicy.REPLACE` on a unique work name (`"push_register"` /
`"push_deregister"`) so the latest token always wins.

### 4.5 Logout integration (`core-data`, extends AND-032)

```kotlin
suspend fun logout() {
    // 1. Best-effort deregister BEFORE clearing cookies (needs session + CSRF).
    val result = withTimeoutOrNull(DEREGISTER_TIMEOUT_MS) {
        pushRepository.deregisterCurrentToken()
    }
    if (result !is ApiResult.Success) workScheduler.enqueueDeregister()

    // 2. Clear local push state regardless of network outcome.
    pushRepository.clearLocalPushState()

    // 3. Existing AND-032 teardown: clear cookies, auth state, caches, route login.
    sessionTeardown()
}
```

`DEREGISTER_TIMEOUT_MS = 5_000` (shorter than the 20s app default so logout stays
snappy; the enqueued worker covers the slow/offline case).

## 5. API Contract

**Register (reused from AND-106) — `POST /ui/push/register`**

Request:
```json
{ "platform": "android", "token": "<fcm_token>", "app_version": "1.0.0" }
```
Response `200`:
```json
{ "registered": true, "device_id": "dev_9f2c..." }
```

**Deregister — `DELETE /ui/push/register`**

Request body:
```json
{ "platform": "android", "token": "<fcm_token>" }
```
Responses:
- `200 / 204` — deregistered (or already absent; treated as success/idempotent).
- `401` — handled by interceptor (`session/refresh` once then retry); if still
  401, treated as definitive failure → local state cleared, no network retry.
- `404` — token unknown server-side; treated as success (already not deliverable).
- `422` — FastAPI validation; `detail` mapped via the standard
  `string | [{msg}] | {code,...}` mapper into `ApiResult.Error`.

Headers on both calls: session cookies (cookie jar) + `X-CSRF-Token` (from
`ui_csrf` cookie). `Content-Type: application/json`.

## 6. Data & State Management

DataStore `PushPrefs` keys (introduced by AND-106, extended here):

| Key | Type | Meaning |
|-----|------|---------|
| `fcm_token` | String | Current device token (latest from `onNewToken`). |
| `reg_status` | String (enum) | `NONE` / `PENDING` / `REGISTERED` / `DEREGISTERED`. |
| `registered_token` | String | Token last confirmed registered server-side. |
| `device_id` | String | Server-assigned id from register response. |

State transitions: `onTokenRotated` → `PENDING`; worker success → `REGISTERED`
(`registered_token = fcm_token`); `clearLocalPushState` → all cleared, status
`NONE`. `PushRepository.state: StateFlow<PushRegistrationState>` is derived from
DataStore via `prefs.data.map { ... }.stateIn(...)` (FR-7).

DataStore writes from `onTokenRotated` use a fire-and-forget coroutine on an
injected `@ApplicationScope` (binder thread must not block); ordering is preserved
because DataStore serializes writes.

## 7. Error Handling & Resilience

- **Network/5xx during rotation register:** token already persisted (FR-2); worker
  returns `Result.retry()` with exponential backoff (10s → max 5min, capped
  attempts) under a `CONNECTED` constraint.
- **No session during rotation:** `registerCurrentToken` returns
  `ApiResult.Error` (unauthenticated); worker returns `Result.failure()` (no spin).
  Token stays `PENDING`; AND-106's post-login hook registers it later.
- **Deregister timeout/offline at logout:** `withTimeoutOrNull` → enqueue
  `DeregisterPushWorker`; logout never blocks (FR-5).
- **Idempotency:** register and deregister are safe to repeat; `404` on deregister
  and re-register of an already-registered token are both success. Unique work
  names with `REPLACE` prevent stacked/stale work.
- **Dev backend unreliability:** all timeouts honor the ~20s OkHttp ceiling except
  the deliberately shorter 5s logout deregister; retries apply only to these
  idempotent operations.

## 8. Security & Privacy

- The FCM token is a device-routing credential, not a user secret, but is stored
  only in app-private DataStore and transmitted over the existing API client.
  **Note:** the dev backend is plaintext HTTP; the token is exposed on the wire in
  dev. Production must use HTTPS (cross-cutting; tracked in network config ticket,
  not here).
- Deregister requires a valid session + `X-CSRF-Token`; it cannot be issued for
  another user's device. Ordering (deregister before cookie clear) is mandatory so
  the call is authenticated.
- On logout, local token state is cleared so a subsequent different user on the
  same device does not inherit the prior registration.
- No PII is logged; tokens are truncated in logs (see §10).

## 9. Accessibility & i18n

No user-facing UI is introduced by this ticket (the FCM service and workers are
headless; logout UI is owned by AND-032). N/A for screen-reader/touch-target
concerns. Any diagnostic strings surfaced on a debug screen must use string
resources for i18n consistency, but no production-facing copy is added here.

## 10. Telemetry & Logging

- Log (debug build, `Timber`) at each transition: `onNewToken received`,
  `register success/failure (status, attempt)`, `deregister success/failure`,
  `local push state cleared`. Tokens are truncated to first 6 + last 4 chars.
- Counters/events (analytics layer, if present): `push_token_rotated`,
  `push_register_result{outcome}`, `push_deregister_result{outcome}`,
  `push_deregister_enqueued_retry`. These are fire-and-forget and must not affect
  control flow. No raw token in any analytics payload.

## 11. Testing Strategy

Unit (JUnit5 + MockK + Turbine, `core-testing`):
- `onTokenRotated` persists token and sets `PENDING`; `state` emits the new value.
- `registerCurrentToken` maps `200`→`REGISTERED`, network error→`ApiResult.Error`
  (token retained), `401`→error.
- `deregisterCurrentToken`: `200`/`204`/`404`→success; `5xx`→error.
- `clearLocalPushState` resets all keys to `NONE`/null.
- `logout()` ordering: deregister called while cookies still present; on timeout,
  `enqueueDeregister` invoked and local state still cleared; logout completes.

Network (MockWebServer, mirrors AND-106 approach):
- Register request body/headers (`X-CSRF-Token`) correct; deregister issues
  `DELETE /ui/push/register` with correct body.
- 401 → single `session/refresh` then retry, asserted by recorded requests.

Worker (`androidx.work:work-testing` `TestListenableWorkerBuilder`):
- `RegisterPushWorker` returns `retry` on network error, `failure` on no-session,
  `success` on 200.
- `DeregisterPushWorker` retry semantics.

Acceptance/instrumented:
- Token rotation: simulate `onNewToken` with a new token, assert
  `registered_token` updates to the new token after worker runs (MockWebServer).
- Logout-stops-delivery: after `logout()`, assert deregister was sent and local
  state is `NONE`; a subsequent inbound test message handler path is not associated
  with a registered token.

## 12. Dependencies & Sequencing

- **Hard depends on AND-106** for `PushApi`, `PushRepository`, `PushPrefs`, and the
  register request shape. AND-109 must not duplicate these; it extends them.
- **Hard depends on AND-032** for `SessionRepository.logout()` teardown into which
  the deregister step is inserted (deregister must run before cookie clearing).
- Transitively relies on core-network auth/CSRF interceptors (refresh-on-401) and
  the persistent cookie jar already established for the session epic.
- Sequencing: implement repository deregister + rotation methods → wire FCM
  `onNewToken` + workers → integrate into AND-032 logout → tests. Blocks nothing
  currently tracked.

## 13. Risks & Open Questions

- **R1:** `onNewToken` can fire before login on first install; ensured handled by
  persisting + `PENDING` and deferring to AND-106's post-login trigger.
- **R2:** Race between concurrent rotation and logout. Mitigated by unique work
  names with `REPLACE` and by clearing local state last in logout.
- **OQ1:** Does the backend key registrations by `(user, token)` or by `device_id`?
  If `device_id`, deregister should send `device_id` rather than `token`. Confirm
  against `/openapi.json` `DELETE /ui/push/register` schema and
  `frontend/src/api/endpoints/push.ts`. Spec currently assumes token-keyed with
  `404` = idempotent success.
- **OQ2:** Should logout deregister *all* tokens for the device or only the current
  one? Assumed current token; confirm with backend owner.

## 14. Acceptance Criteria

AC-1. When FCM rotates the token (`onNewToken` fires), the new token is persisted
and re-registered with the backend; `registered_token` in `PushPrefs` equals the
new token after the register worker completes (verified with MockWebServer).

AC-2. Token rotation while logged out persists the new token as `PENDING` and does
not call the backend; it is registered on next login.

AC-3. On logout, `DELETE /ui/push/register` is issued for the current token before
session cookies are cleared, with valid session cookie + `X-CSRF-Token`.

AC-4. Logout completes even when deregister times out/fails; local push state is
cleared and a deregister-retry worker is enqueued.

AC-5. After logout, the device has no registered token locally (`status = NONE`)
and receives no further push for the prior session (delivery stops).

AC-6. Register/deregister are idempotent: repeated calls and `404` on deregister
are treated as success; no error surfaced to logout.

## 15. Definition of Done

- All FRs and ACs implemented and green in CI (unit + MockWebServer + work-testing).
- `TlFirebaseMessagingService.onNewToken` wired to persist + enqueue register
  worker; `PushRepository` gains rotation/deregister/clear methods; `PushApi` gains
  `DELETE /ui/push/register`.
- AND-032 logout flow calls deregister before cookie teardown and always clears
  local push state.
- Package `com.testlogon.android.*` throughout; no plaintext token in logs/analytics.
- Code reviewed; KtLint/Detekt clean; merged to `android-port`.
- OQ1/OQ2 resolved against `/openapi.json` and the web reference, with the
  deregister body finalized accordingly.

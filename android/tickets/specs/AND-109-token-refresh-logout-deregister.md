---
id: AND-109
title: Token refresh + logout deregister
milestone: M2
epic: E15
priority: P1
size: M
depends_on: [AND-106, AND-032]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
   stop delivering push to this device (`POST /ui/push/revoke`, body `{device_id}`
   — CORRECTED: there is no `DELETE /ui/push/register`; revoke is a POST keyed by
   the server-assigned `device_id`, per OpenAPI `POST /ui/push/revoke` /
   `PushRevokeReq` and `src/api/endpoints/push.ts: revokePush`) so that a
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
- **Auth model:** Session is cookie-based with `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header (VERIFIED `src/api/client.ts`); persistent cookie jar; on
  401 the client calls `POST /ui/session/refresh` once then retries (VERIFIED
  `src/api/client.ts: refreshSession` + OpenAPI `POST /ui/session/refresh`; owned by
  core-network auth interceptor). CORRECTION/NUANCE: the web client is a *hybrid* —
  in addition to cookies it also sends `Authorization: Bearer <accessToken>` (from
  the auth store) and uses `credentials: "include"`; the OpenAPI further declares
  `X-SESSION-ID`/`user_sub` header/query params on these routes. The Android client
  must mirror whatever AND-106/AND-032 established for transport; this ticket only
  requires that deregister run while the session is still live (cookie + CSRF +
  bearer as applicable). Deregister is an authenticated mutating call and therefore
  requires a live session and the CSRF header.
- **Dependencies:**
  - **AND-106 (Push token registration, P0)** — provides `PushApi.register`,
    `PushRepository`, the `PushPrefs` DataStore, and the registration JSON shape.
    AND-109 reuses and extends these; it does not re-create them.
  - **AND-032 (Logout flow, P0)** — provides `SessionRepository.logout()` which
    clears cookies, auth state, and caches and routes to login. AND-109 inserts a
    deregister step at the front of that flow.
- **Web reference:** `src/api/endpoints/push.ts` (`registerPush` →
  `POST /ui/push/register`; `revokePush` → `POST /ui/push/revoke`),
  `src/api/types.ts` (`PushRegisterReq`, `PushRevokeReq`, `PushDevice`). Backend
  OpenAPI `/ui/push/*` paths (`POST /ui/push/register`, `POST /ui/push/revoke`,
  `GET /ui/push/devices`, `POST /ui/push/test`, `GET /ui/push/vapid-key`). Dev
  backend is plaintext HTTP and unreliable: design for ~20s timeouts and bounded
  retry on idempotent operations only. (NOTE: the web client uses revoke only from
  a manual device-management screen, `src/pages/alerts/PushDevices.tsx`; it does NOT
  call revoke on logout — the logout-deregister behavior is a net-new Android design,
  not a web-verified behavior.)

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
`POST /ui/push/revoke` with the currently registered `device_id` (CORRECTED from
`DELETE /ui/push/register` for the token). After the call
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
and on success sets `status = REGISTERED` **and persists `device_id` from the
`PushDevice` response** (required for later revoke). `deregisterCurrentToken` calls
`PushApi.revoke({device_id})` using the stored `device_id` (CORRECTED: revoke is
keyed by `device_id`, not by token). If no `device_id` is stored (token never
confirmed-registered) there is nothing deliverable server-side, so deregister is a
local-only no-op treated as success.

### 4.3 Network (`core-network`)

`PushApi` (from AND-106) gains the deregister method:

```kotlin
// CORRECTED: deregister is POST /ui/push/revoke with a {device_id} body, not a
// DELETE on /ui/push/register. register returns a PushDevice (carrying device_id),
// which is what revoke must echo back. (OpenAPI POST /ui/push/register →
// PushRegisterReq/PushDevice; POST /ui/push/revoke → PushRevokeReq; web
// src/api/endpoints/push.ts.)
interface PushApi {
    @POST("ui/push/register")
    suspend fun register(@Body body: PushRegisterRequest): Response<PushDevice>

    @POST("ui/push/revoke")
    suspend fun revoke(@Body body: PushRevokeRequest): Response<OkResp>
}

// PushRegisterRequest(token, platform)   // both required; NO app_version
// PushDevice(device_id, platform, created_at, last_seen_at)
// PushRevokeRequest(device_id)           // required
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

**Register (reused from AND-106) — `POST /ui/push/register`** (VERIFIED OpenAPI
`PushRegisterReq` + `src/api/types.ts: PushRegisterReq`)

Request (both fields required; CORRECTED: there is NO `app_version` field):
```json
{ "token": "<fcm_token>", "platform": "android" }
```
Response `200` (CORRECTED: returns a `PushDevice`, not `{registered, device_id}`):
```json
{ "device_id": "dev_9f2c...", "platform": "android",
  "created_at": 1717600000, "last_seen_at": 1717600000 }
```

**Deregister — `POST /ui/push/revoke`** (CORRECTED from `DELETE /ui/push/register`;
VERIFIED OpenAPI `POST /ui/push/revoke` / `PushRevokeReq` +
`src/api/endpoints/push.ts: revokePush` / `src/api/types.ts: PushRevokeReq`)

Request body (CORRECTED: keyed by `device_id`, NOT `token`/`platform`):
```json
{ "device_id": "dev_9f2c..." }
```
Response `200`: `OkResp` (web `revokePush` returns `OkResp`). This resolves OQ1:
registrations are keyed by `device_id`; the client must persist `device_id` from the
register response and send it on revoke.

Responses / error handling:
- `200` — revoked; treated as success/idempotent.
- `401` — handled by interceptor (`POST /ui/session/refresh` once then retry,
  VERIFIED `src/api/client.ts`); if still 401, treated as definitive failure →
  local state cleared, no network retry.
- `422` — FastAPI validation error → `HTTPValidationError`; `detail` mapped via the
  standard `string | [{msg}] | {code,...}` mapper into `ApiResult.Error`. (VERIFIED:
  the only declared error response for these routes is `422:HTTPValidationError`;
  `404`/`204` are NOT documented for revoke — see Open assumptions §16.)
- UNVERIFIED-ASSUMPTION: a missing/already-revoked `device_id` returns a success-ish
  status. The OpenAPI does not document a `404` for revoke; the client treats
  "no stored `device_id`" as a local no-op success and treats any 2xx as success.

Headers on both calls: session cookies (cookie jar) + `X-CSRF-Token` (from
`ui_csrf` cookie, VERIFIED `src/api/client.ts`) + `Authorization: Bearer` if the
transport layer (AND-106/AND-032) attaches it. `Content-Type: application/json`.

## 6. Data & State Management

DataStore `PushPrefs` keys (introduced by AND-106, extended here):

| Key | Type | Meaning |
|-----|------|---------|
| `fcm_token` | String | Current device token (latest from `onNewToken`). |
| `reg_status` | String (enum) | `NONE` / `PENDING` / `REGISTERED` / `DEREGISTERED`. |
| `registered_token` | String | Token last confirmed registered server-side. |
| `device_id` | String | Server-assigned id from the `PushDevice` register response; REQUIRED as the key for `POST /ui/push/revoke` at logout. |

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
- **Idempotency:** register and deregister are safe to repeat; re-register of an
  already-registered token and a revoke for an unknown/already-revoked `device_id`
  are both treated as success. (NOTE: the OpenAPI documents only `200`/`422` for
  these routes, not `404`/`204`; the "unknown id = success" behavior is an
  assumption — see §16 Open assumptions.) Unique work names with `REPLACE` prevent
  stacked/stale work.
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
- `deregisterCurrentToken`: `200`→success; no stored `device_id`→local no-op
  success; `5xx`→error; `422`→error mapped from `HTTPValidationError.detail`.
- `clearLocalPushState` resets all keys to `NONE`/null.
- `logout()` ordering: deregister called while cookies still present; on timeout,
  `enqueueDeregister` invoked and local state still cleared; logout completes.

Network (MockWebServer, mirrors AND-106 approach):
- Register request body (`{token, platform}`, no `app_version`) / headers
  (`X-CSRF-Token`) correct; deregister issues `POST /ui/push/revoke` with body
  `{device_id}`.
- 401 → single `POST /ui/session/refresh` then retry, asserted by recorded requests.

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
- **OQ1 (RESOLVED):** Registrations are keyed by `device_id`, not by token. Deregister
  is `POST /ui/push/revoke` with body `{device_id}` (VERIFIED OpenAPI `PushRevokeReq`
  + `src/api/endpoints/push.ts: revokePush`). The client persists `device_id` from
  the `PushDevice` register response and sends it on revoke. The earlier assumption
  of a token-keyed `DELETE /ui/push/register` was WRONG and has been corrected
  throughout.
- **OQ2 (PARTIALLY RESOLVED):** Revoke is per-`device_id`, so logout deregisters
  exactly this device's registration (one `device_id`). There is no multi-token /
  all-devices semantic in the revoke contract; `POST /ui/sessions/revoke_others`
  exists for sessions but is out of scope. Confirm with backend owner only if a
  "revoke all my devices on logout" product requirement appears (none today).
- **OQ3 (OPEN):** The OpenAPI declares only `200`/`422` for revoke. The exact status
  for an unknown/already-revoked `device_id` (success vs 404) is undocumented; the
  client defensively treats any 2xx and "no stored device_id" as success. Confirm
  with backend owner.

## 14. Acceptance Criteria

AC-1. When FCM rotates the token (`onNewToken` fires), the new token is persisted
and re-registered with the backend; `registered_token` in `PushPrefs` equals the
new token after the register worker completes (verified with MockWebServer).

AC-2. Token rotation while logged out persists the new token as `PENDING` and does
not call the backend; it is registered on next login.

AC-3. On logout, `POST /ui/push/revoke` is issued with the current `device_id`
before session cookies are cleared, with valid session cookie + `X-CSRF-Token`
(CORRECTED from `DELETE /ui/push/register` + token).

AC-4. Logout completes even when deregister times out/fails; local push state is
cleared and a deregister-retry worker is enqueued.

AC-5. After logout, the device has no registered token locally (`status = NONE`)
and receives no further push for the prior session (delivery stops).

AC-6. Register/deregister are idempotent: repeated calls, an unknown/already-revoked
`device_id`, and a logout with no stored `device_id` are all treated as success; no
error is surfaced to logout.

## 15. Definition of Done

- All FRs and ACs implemented and green in CI (unit + MockWebServer + work-testing).
- `TlFirebaseMessagingService.onNewToken` wired to persist + enqueue register
  worker; `PushRepository` gains rotation/deregister/clear methods; `PushApi` gains
  `POST /ui/push/revoke` (body `{device_id}`) — CORRECTED from `DELETE /ui/push/register`.
- AND-032 logout flow calls deregister before cookie teardown and always clears
  local push state.
- Package `com.testlogon.android.*` throughout; no plaintext token in logs/analytics.
- Code reviewed; KtLint/Detekt clean; merged to `android-port`.
- OQ1/OQ2 resolved against the OpenAPI spec and the web reference (deregister body
  finalized as `{device_id}` via `POST /ui/push/revoke`); OQ3 (unknown-id status)
  confirmed with backend owner before relying on a specific non-2xx code.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Register endpoint is `POST /ui/push/register`.** VERIFIED — OpenAPI
   `POST /ui/push/register` (op `ui_register_push_ui_push_register_post`,
   `req=PushRegisterReq`); `src/api/endpoints/push.ts: registerPush`.
2. **Register request shape.** CORRECTED — it is `{token, platform}` (both
   required); there is NO `app_version` field. Source: OpenAPI schema
   `PushRegisterReq` (properties `platform`, `token`; required `[token, platform]`);
   `src/api/types.ts: PushRegisterReq`.
3. **Register response shape.** CORRECTED — returns a `PushDevice`
   `{device_id, platform, created_at, last_seen_at}`, NOT `{registered, device_id}`.
   Source: `src/api/endpoints/push.ts` (`api.post<PushDevice>("/ui/push/register")`);
   `src/api/types.ts: PushDevice`.
4. **Deregister endpoint/method.** CORRECTED — it is `POST /ui/push/revoke`, NOT
   `DELETE /ui/push/register` (no such route exists). Source: OpenAPI
   `POST /ui/push/revoke` (op `ui_revoke_push_ui_push_revoke_post`,
   `req=PushRevokeReq`); `src/api/endpoints/push.ts: revokePush`.
5. **Deregister request shape / keying.** CORRECTED — body is `{device_id}`
   (required); registrations are keyed by `device_id`, not by token. Source:
   OpenAPI schema `PushRevokeReq` (property `device_id`, required `[device_id]`);
   `src/api/types.ts: PushRevokeReq`; usage `src/pages/alerts/PushDevices.tsx`
   (`revokePush({ device_id: deviceId })`).
6. **Deregister response shape.** Corrected/Verified — web `revokePush` returns
   `OkResp`; OpenAPI documents `200` (+ `422`). Source:
   `src/api/endpoints/push.ts` (`api.post<OkResp>("/ui/push/revoke")`); OpenAPI
   index line for `/ui/push/revoke` (`resp=200:;422:HTTPValidationError`).
7. **CSRF model: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** VERIFIED —
   `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
8. **401 handling: single `POST /ui/session/refresh` then retry.** VERIFIED —
   `src/api/client.ts: refreshSession` + the 401 branch (refresh once via a shared
   `refreshPromise`, then retry the original request); OpenAPI
   `POST /ui/session/refresh` (`resp=200:`, no request body).
9. **Auth is purely cookie-based.** CORRECTED/NUANCED — the web client is hybrid:
   it sends `Authorization: Bearer <accessToken>` (from the auth store) AND cookies
   (`credentials: "include"`) AND `X-CSRF-Token`; the OpenAPI additionally declares
   `X-SESSION-ID`/`user_sub` params on `/ui/push/*`. Source: `src/api/client.ts`
   (Authorization + credentials); OpenAPI index `params=user_sub,X-SESSION-ID,...`
   on `/ui/push/register` and `/ui/push/revoke`.
10. **Logout endpoint.** VERIFIED — `POST /ui/session/logout`
    (`src/api/endpoints/auth.ts: logout` → `api.post<StatusResp>("/ui/session/logout")`;
    OpenAPI `POST /ui/session/logout`). The spec's abstract `sessionTeardown()` is the
    AND-032-owned wrapper around this; deregister must precede it.
11. **Web app deregisters on logout.** UNVERIFIED-ASSUMPTION (and in fact NOT a web
    behavior) — `revokePush` is only called from the manual device-management screen
    `src/pages/alerts/PushDevices.tsx`; the web logout (`auth.ts: logout`) does NOT
    call revoke. The logout-deregister flow is a net-new Android design decision.
12. **`onNewToken` runs on a binder thread / must not block; persist then hand to
    WorkManager.** VERIFIED (framework ref) —
    https://firebase.google.com/docs/cloud-messaging/android/client#monitor-token-generation
    and https://developer.android.com/topic/libraries/architecture/workmanager .
13. **WorkManager retry/backoff (`Result.retry()`, `BackoffPolicy.EXPONENTIAL`,
    `NetworkType.CONNECTED`, unique work + `ExistingWorkPolicy.REPLACE`).** VERIFIED
    (framework ref) —
    https://developer.android.com/reference/androidx/work/CoroutineWorker and
    https://developer.android.com/topic/libraries/architecture/workmanager/how-to/define-work .
14. **Unknown/already-revoked `device_id` returns success (404=idempotent).**
    UNVERIFIED-ASSUMPTION — OpenAPI documents only `200`/`422` for revoke; no `404`
    or `204` is declared. Defensive client behavior; flagged as OQ3.
15. **Revoke deregisters exactly one device (this `device_id`); no all-devices
    semantic.** VERIFIED (by absence) — `PushRevokeReq` takes a single `device_id`;
    no array/all-devices field exists in the schema.

### Corrections made

- Deregister endpoint corrected from `DELETE /ui/push/register` to
  `POST /ui/push/revoke` (§1, §2, §4.2, §4.3, §5, §15, FR-4, AC-3, testing notes).
- Deregister body corrected from `{platform, token}` to `{device_id}`; registration
  keying corrected to `device_id`; client now persists `device_id` from the register
  response and uses it for revoke (§4.2, §4.3, §5, §6, §7, OQ1).
- Register request corrected: removed the non-existent `app_version` field (§5).
- Register response corrected from `{registered, device_id}` to the `PushDevice`
  shape `{device_id, platform, created_at, last_seen_at}` (§4.3, §5).
- Auth model corrected/nuanced: hybrid Bearer + cookie + CSRF (and OpenAPI
  `X-SESSION-ID`/`user_sub` params), not pure cookie session (§2).
- `404`/`204`-as-success idempotency claims softened to assumptions (§5, §7, AC-6),
  since only `200`/`422` are documented.
- OQ1 marked RESOLVED (device_id-keyed), OQ2 PARTIALLY RESOLVED, new OQ3 added for
  the undocumented unknown-id status (§13).

### Open assumptions

- **A1 (OQ3):** Server status for revoking an unknown/already-revoked `device_id`
  (200 vs 404 vs 422) is not in the OpenAPI; client treats any 2xx and "no stored
  device_id" as success. Why unverifiable: not documented in the spec and the web
  client never exercises this path.
- **A2:** Exact transport the Android client uses (Bearer vs cookie vs both, and
  whether `X-SESSION-ID`/`user_sub` are required) is owned by AND-106/AND-032; this
  ticket assumes those interceptors are already correct. Why unverifiable here:
  established in upstream tickets, not in the AND-109 sources.
- **A3:** That deregister-before-cookie-clear is acceptable product behavior (web
  does not do this). Why unverifiable: net-new Android design, no web precedent.
- **A4:** `OkResp`/`StatusResp` exact field shapes are treated as opaque success
  envelopes; only HTTP status is consumed by AND-109 logic.

## 17. Test Plan

Acceptance criteria referenced are from §14 (AC-1..AC-6). Test targets: JVM =
JVM/Robolectric local; EMU = headless AVD `test35` (x86_64, API 35); DEVICE =
physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a).

- **TC-AND-109-01** — Type: unit (JVM, MockK + Turbine). Target: JVM.
  Preconditions: `PushRepository` with fake DataStore. Steps: call
  `onTokenRotated("tok_new")`. Expected: DataStore `fcm_token = "tok_new"`,
  `reg_status = PENDING`; `state` StateFlow emits `{token=tok_new, PENDING}`; no
  network I/O performed. Traces: AC-1, AC-2 (FR-1, FR-7).

- **TC-AND-109-02** — Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues `200` `PushDevice` body; valid session +
  `ui_csrf` cookie set. Steps: call `registerCurrentToken()`. Expected: request is
  `POST /ui/push/register`, body exactly `{"token":...,"platform":"android"}` (NO
  `app_version`), header `X-CSRF-Token` present; on success `reg_status=REGISTERED`,
  `registered_token=fcm_token`, `device_id` persisted from response. Traces: AC-1.

- **TC-AND-109-03** — Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues `401` then (after refresh) `200`; another
  `200` for `/ui/session/refresh`. Steps: call `registerCurrentToken()`. Expected:
  recorded requests show register → `POST /ui/session/refresh` (once) → register
  retry; final result success. No second refresh attempted. Traces: AC-1, AC-3
  (shared interceptor behavior).

- **TC-AND-109-04** — Type: unit (JVM). Target: JVM. Preconditions: no session
  (unauthenticated). Steps: `onTokenRotated` then `registerCurrentToken()`.
  Expected: returns `ApiResult.Error` (unauthenticated); token retained with
  `reg_status=PENDING`; no `REGISTERED` transition. Traces: AC-2 (FR-3).

- **TC-AND-109-05** — Type: contract/MockWebServer. Target: JVM.
  Preconditions: `device_id` persisted; MockWebServer enqueues `200` `OkResp`.
  Steps: call `deregisterCurrentToken()`. Expected: request is
  `POST /ui/push/revoke` with body exactly `{"device_id":"dev_..."}` and
  `X-CSRF-Token` header; result success. Traces: AC-3, AC-6.

- **TC-AND-109-06** — Type: unit (JVM). Target: JVM. Preconditions: no stored
  `device_id`. Steps: call `deregisterCurrentToken()`. Expected: local no-op
  treated as `ApiResult.Success`; no network request issued. Traces: AC-6 (FR-4).

- **TC-AND-109-07** — Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues `422` with
  `{"detail":[{"msg":"value is not a valid ..."}]}`. Steps: call
  `deregisterCurrentToken()`. Expected: `ApiResult.Error` carrying the mapped
  `detail` message via the `string | [{msg}] | {code}` mapper. Traces: AC-6
  (error-shape correctness).

- **TC-AND-109-08** — Type: unit (JVM). Target: JVM. Preconditions: fake
  `pushRepository` whose `deregisterCurrentToken()` returns `Success`; spy
  `workScheduler`; cookie jar populated. Steps: invoke `logout()`. Expected:
  deregister is called WHILE cookies/session still present (assert ordering: revoke
  before `sessionTeardown()`); then `clearLocalPushState()` → `reg_status=NONE`;
  `enqueueDeregister()` NOT called on success. Traces: AC-3, AC-5, AC-6.

- **TC-AND-109-09** — Type: unit (JVM). Target: JVM. Preconditions:
  `deregisterCurrentToken()` suspends past `DEREGISTER_TIMEOUT_MS` (or returns
  Error). Steps: invoke `logout()`. Expected: `withTimeoutOrNull` elapses, logout
  is NOT blocked; `enqueueDeregister()` invoked; `clearLocalPushState()` still runs
  (`reg_status=NONE`); logout completes. Traces: AC-4 (FR-5).

- **TC-AND-109-10** — Type: instrumented worker (`work-testing`
  `TestListenableWorkerBuilder`). Target: EMU. Preconditions: repo stub.
  Steps/Expected: `RegisterPushWorker` → `Result.retry()` on network/5xx error,
  `Result.failure()` on no-session 4xx, `Result.success()` on `200`;
  `DeregisterPushWorker` → `retry` on network/5xx, `success` on `200`. Traces:
  AC-1, AC-4 (FR-2, FR-5).

- **TC-AND-109-11** — Type: integration (Robolectric/instrumented + MockWebServer).
  Target: EMU. Preconditions: registered token `tok_old`. Steps: simulate
  `onNewToken("tok_new")`, let `RegisterPushWorker` run against MockWebServer (`200`).
  Expected: a `POST /ui/push/register` with `tok_new`; `registered_token` updates to
  `tok_new`; unique work `"push_register"` used with `REPLACE` (only latest token
  registered). Traces: AC-1.

- **TC-AND-109-12** — Type: instrumented/e2e on real FCM. Target: DEVICE (MUST run
  on physical device — needs real FCM token rotation + push delivery). Preconditions:
  app installed, logged in, registered. Steps: trigger token rotation (clear FCM
  instance ID / reinstall) so `onNewToken` fires; confirm re-registration; then send
  a test push to the OLD token and to the NEW token. Expected: delivery to NEW token
  succeeds; delivery to OLD token stops. Traces: AC-1.

- **TC-AND-109-13** — Type: instrumented/e2e on real FCM. Target: DEVICE (MUST run
  on physical device — real push delivery + notification path). Preconditions:
  logged in and registered. Steps: perform logout (revoke succeeds), then attempt to
  send a push for the prior session/device. Expected: `POST /ui/push/revoke` observed
  before session teardown; local state `NONE`; no further notification delivered for
  the prior session. Traces: AC-3, AC-5.

- **TC-AND-109-14** — Type: integration (offline/flaky-host). Target: EMU (airplane
  mode toggled via emulator), with a confirmatory pass on DEVICE for real radio
  behavior. Preconditions: registered; network disabled at logout time. Steps:
  logout while offline. Expected: deregister times out (5s), logout still completes,
  local state cleared, `DeregisterPushWorker` enqueued under `CONNECTED` constraint;
  on reconnect the worker fires `POST /ui/push/revoke`. Traces: AC-4 (FR-5).

- **TC-AND-109-15** — Type: contract/MockWebServer (security). Target: JVM.
  Preconditions: cookie jar without `ui_csrf`, or session cleared. Steps: attempt
  deregister. Expected: when CSRF/session is absent the call is not silently
  successful — either CSRF header is omitted (server would reject) or the ordering
  guarantee ensures revoke only runs pre-teardown; assert that revoke is NEVER issued
  after `clearLocalPushState()`/cookie clear (no unauthenticated revoke). Traces:
  AC-3 (security/ordering).

(No production UI is added by this ticket, so no Compose-UI/accessibility cases
apply. The only optional UI is a debug diagnostics surface reading
`PushRepository.state`; if implemented, add a Compose-UI case asserting the status
text uses string resources and exposes a content description for TalkBack — tracked
with the debug-screen ticket, not AND-109.)

### Coverage matrix

| AC (§14) | Covered by |
|----------|------------|
| AC-1 (rotation persists + re-registers; `registered_token` = new) | TC-01, TC-02, TC-03, TC-10, TC-11, TC-12 |
| AC-2 (rotation while logged out → PENDING, no backend call) | TC-01, TC-04 |
| AC-3 (logout issues `POST /ui/push/revoke` w/ device_id before cookie clear) | TC-05, TC-08, TC-13, TC-15 |
| AC-4 (logout completes on deregister timeout; retry worker enqueued) | TC-09, TC-10, TC-14 |
| AC-5 (post-logout: status NONE, delivery stops) | TC-08, TC-13 |
| AC-6 (idempotent register/deregister; unknown id / no device_id = success) | TC-05, TC-06, TC-07, TC-08 |

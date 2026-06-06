---
id: AND-106
title: Push token registration
milestone: M2
epic: E15
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Auth model (CORRECTED against `src/api/client.ts`):** `POST /ui/session/start` →
  MFA → `POST /ui/session/finalize` → `GET /ui/me`. `session/start` returns
  `{auth_required, challenge_id?, required_factors[], session_id?}` and
  `session/finalize` returns `{status, session_id?, required_factors[], passed{}}`
  (`src/api/types.ts: SessionStartResp / SessionFinalizeResp`). The web client
  authenticates requests with **three** mechanisms, all applied by the shared `api()`
  wrapper: (1) `Authorization: Bearer <accessToken>` from the auth store
  (`client.ts` lines 157-160 — so a bearer token **IS** involved, contrary to an
  earlier draft of this spec); (2) the `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header (`client.ts` lines 168-171); (3) cookies via
  `credentials: "include"`. The OpenAPI for `POST /ui/push/register` additionally
  declares optional auth-context params `user_sub` (query), `X-SESSION-ID` (header),
  and `X-IMPERSONATION-TOKEN` (header) — all `required: false`. On 401 the client
  calls `POST /ui/session/refresh` once and retries the original request
  (`client.ts` lines 194-237); a second 401 forces logout. `POST /ui/push/register`
  is authenticated and state-changing; the Android port MUST reproduce whichever of
  these mechanisms the backend enforces — minimally the session cookies + CSRF
  header + bearer token — via the existing OkHttp interceptors. **(Unverified which
  subset the server strictly requires; see §16 Open assumptions.)**
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

**CORRECTED to match `components.schemas.PushRegisterReq` and
`src/api/types.ts: PushRegisterReq`.** The request body has **only** `token` and
`platform` (both required); there is **no** `app_version` or `device_id` in the
request — `device_id` is server-generated and returned in the response. The success
response is a `PushDevice` object (`src/api/types.ts: PushDevice`), not a
`{registered, device_id}` envelope.

```kotlin
@JsonClass(generateAdapter = true)
data class PushRegisterRequest(
    @Json(name = "token") val token: String,
    @Json(name = "platform") val platform: String = "android",
)

// Response mirrors PushDevice (created_at/last_seen_at are epoch seconds).
@JsonClass(generateAdapter = true)
data class PushDevice(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "platform") val platform: String,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "last_seen_at") val lastSeenAt: Long,
)
```

> Note: the OpenAPI `200` response schema for this op is declared as an empty
> object (`schema: {}`), so the `PushDevice` shape is taken from the frontend
> contract (`endpoints/push.ts: registerPush` returns `PushDevice`). Parse the
> response defensively (tolerate missing fields). Because `device_id` is now a
> **server-returned** value (not client-sent), the local idempotency tuple keys on
> `(user_sub, token, contractVersion)` only — see §6, corrected below.

**Retrofit service:**

```kotlin
interface PushApi {
    @POST("ui/push/register")
    suspend fun registerToken(@Body body: PushRegisterRequest): Response<PushDevice>
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
ui_csrf=<v>`, `X-CSRF-Token: <v>`, `Authorization: Bearer <accessToken>`,
`Content-Type: application/json`. (The web client sends all of these; OpenAPI also
accepts optional `X-SESSION-ID` header and `user_sub` query param.)

**Request body (CORRECTED — `PushRegisterReq`: only `token` + `platform`, both
required):**

```json
{
  "token": "fcm-registration-token-string",
  "platform": "android"
}
```

**Success `200` (CORRECTED — `PushDevice`; OpenAPI declares the 200 schema as an
empty object, shape taken from the frontend `PushDevice` type):**

```json
{
  "device_id": "9b1c...-server-generated",
  "platform": "android",
  "created_at": 1733443200,
  "last_seen_at": 1733443200
}
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

> **Resolved (verified 2026-06-06):** the request shape is confirmed against
> `components.schemas.PushRegisterReq` and `src/api/types.ts: PushRegisterReq` —
> exactly `{token, platform}`, both required. The server generates and returns
> `device_id`, so the backend keys its device record on the server-side
> `device_id` (returned to us), while the client correlates on `token`. We do not
> send a client `device_id`. **Still unverified:** the precise server upsert key
> (token vs device_id) for idempotency — see §16 Open assumptions.

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

Keys: `last_user_sub`, `last_token`, `last_contract_version`, `pending_token`,
`server_device_id`. **CORRECTION:** the client no longer sends a `device_id` in the
register request (it is not a field of `PushRegisterReq`). The `device_id` is
**returned by the server** in the `PushDevice` response; we may cache it
(`server_device_id`) for diagnostics and for a future `/ui/push/revoke` call (which
*does* take `{device_id}`). The idempotency tuple therefore drops `device_id` and
keys on `(user_sub, token, contractVersion)` only. The auth-state inputs
(`authenticated`, `user_sub`) are **read** from AND-029's `AuthStateStore`, not
duplicated.

State flow: `AuthState(false→true)` ⇒ attempt register ⇒ on success write
`RegisteredTuple`. `onNewToken` ⇒ attempt register with forced token. Logout ⇒
`clear()`. Idempotency is enforced purely by tuple comparison; the network is the
source of truth only on first success.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the OkHttp ~20s call timeout configured project-wide for the
  unreliable dev host.
- **In-call retry:** bounded backoff for the register POST — up to 2 retries
  (e.g. 1s, 4s with jitter). `POST /ui/push/register` is **assumed** idempotent on
  the server by `(user, token)` (the only client-supplied identity in the body is
  `token`; the server mints `device_id`), so retrying the POST is assumed safe.
  This server-side idempotency is **not verifiable** from the OpenAPI/frontend
  sources — see §16 Open assumptions and §13. If it is not idempotent, gate in-call
  retries to network-level failures only (no response received).
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
- The `device_id` is **server-generated** (returned in the `PushDevice` response)
  and is not derived from hardware identifiers (no `ANDROID_ID`/IMEI), respecting
  Play policy. The client does not transmit any device identifier in the request.
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

- Enqueue `200` with a `PushDevice` body
  (`{"device_id":...,"platform":"android","created_at":...,"last_seen_at":...}`);
  assert recorded request path `/ui/push/register`, method POST, `X-CSRF-Token`
  header present, and body matches `PushRegisterRequest` (exactly `token` +
  `platform`, no `app_version`/`device_id`).
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

AC-2. The request body contains exactly the FCM `token` and `platform="android"`
(matching `PushRegisterReq`; no `app_version`/`device_id` in the body), and the
request carries session cookies + `X-CSRF-Token` + `Authorization: Bearer` as the
web client does.

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

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and an exact source pointer.

1. **Endpoint exists at `POST /ui/push/register`.** VERIFIED. OpenAPI
   `POST /ui/push/register` (op=`ui_register_push_ui_push_register_post`); frontend
   `src/api/endpoints/push.ts: registerPush` → `api.post("/ui/push/register", body)`.

2. **Request schema is `{token, platform}`, both required; NO `app_version` or
   `device_id` in the body.** CORRECTED (spec previously listed four fields).
   Source: `components.schemas.PushRegisterReq` (properties: `platform`, `token`;
   required: `[token, platform]`) and `src/api/types.ts: PushRegisterReq`
   (`{ token: string; platform: string }`).

3. **Success response is a `PushDevice` object, not `{registered, device_id}`.**
   CORRECTED. Source: `src/api/endpoints/push.ts: registerPush` returns
   `PushDevice`; `src/api/types.ts: PushDevice` =
   `{device_id, platform, created_at, last_seen_at}`. Note: OpenAPI declares the
   `200` response schema as an empty object (`responses.200.content.
   application/json.schema = {}`), so the field shape is taken from the frontend
   contract — flagged as a parse-defensively item.

4. **`device_id` is server-generated and returned (not client-sent).** CORRECTED
   (spec previously sent a client per-install UUID). Source: absence of `device_id`
   in `PushRegisterReq` + its presence in the `PushDevice` response
   (`src/api/types.ts`). Cross-check: `PushRevokeReq` (`{device_id}`,
   `components.schemas.PushRevokeReq`) consumes the server `device_id`.

5. **Auth/transport: bearer token IS used (web client).** CORRECTED (spec claimed
   "No bearer token is involved"). Source: `src/api/client.ts` lines 157-160 set
   `Authorization: Bearer <accessToken>` from `useAuthStore`; `src/stores/
   authStore.ts` stores `accessToken`; `src/api/types.ts: TokenRefreshResp`
   (`{access_token, id_token?, expires_in?}`).

6. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** VERIFIED. Source:
   `src/api/client.ts` lines 167-171 (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`).

7. **Cookies sent via `credentials: "include"`.** VERIFIED. Source:
   `src/api/client.ts` lines 180-184, 217-221.

8. **OpenAPI also accepts `user_sub` (query), `X-SESSION-ID` (header),
   `X-IMPERSONATION-TOKEN` (header), all optional.** VERIFIED. Source: parameters
   block of `POST /ui/push/register` in `openapi.pretty.json` (each `required:
   false`); also `openapi.index.txt` line `POST /ui/push/register | ... |
   params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`.

9. **On 401, client calls `POST /ui/session/refresh` once and retries; a second
   401 forces logout.** VERIFIED. Source: `src/api/client.ts` lines 194-237
   (`refreshSession()` → `POST /ui/session/refresh`, single in-flight
   `refreshPromise`, retry of original request, `logout("session_expired")` on
   repeat 401). Endpoint confirmed in OpenAPI `POST /ui/session/refresh`.

10. **Login flow `start → finalize → /ui/me`.** VERIFIED. Source:
    `src/api/endpoints/auth.ts: sessionStart / sessionFinalize / getMe`; OpenAPI
    `POST /ui/session/start` (resp `UiSessionStartResp`), `POST
    /ui/session/finalize` (req `UiSessionFinalizeReq`), `GET /ui/me`. Response
    shapes: `src/api/types.ts: SessionStartResp / SessionFinalizeResp / MeResp`.

11. **`user_sub` originates from `/ui/me`.** VERIFIED. Source: `src/api/types.ts:
    MeResp` = `{user_sub, session_id, ip}`.

12. **FastAPI error `detail` may be string | `[{msg}]` | `{code,...}`; reuse shared
    mapper.** VERIFIED. Source: `src/api/client.ts: normalizeErrorDetail` (handles
    string, array-of-`{msg}`, and object-with-`code`/`msg`); 422 uses
    `components.schemas.HTTPValidationError` (`detail: [{loc, msg, type}]`).

13. **Logout/revoke endpoints exist for a future deregistration follow-up.**
    VERIFIED. Source: OpenAPI `POST /ui/session/logout` and `POST /ui/push/revoke`
    (req `PushRevokeReq`); frontend `src/api/endpoints/push.ts: revokePush`,
    `src/api/endpoints/auth.ts: logout`.

14. **Android framework choices** (Hilt `@HiltWorker`, WorkManager constraints +
    exponential backoff, Preferences DataStore, FCM `onNewToken`). UNVERIFIED-
    assumption against backend sources (out of their scope); standard platform
    APIs. framework ref: developer.android.com/topic/libraries/architecture/workmanager,
    developer.android.com/topic/libraries/architecture/datastore,
    firebase.google.com/docs/cloud-messaging/android/client (`onNewToken`).

### Corrections made

- §2 auth model: rewrote the "cookie + CSRF, no bearer token" claim — the web
  client sends `Authorization: Bearer`, `X-CSRF-Token`, AND cookies; documented the
  optional `user_sub`/`X-SESSION-ID`/`X-IMPERSONATION-TOKEN` params (claim #5, #8).
- §4 DTOs: removed `app_version` and `device_id` from `PushRegisterRequest`;
  replaced `PushRegisterResponse{registered,device_id}` with `PushDevice` (claim
  #2, #3, #4); `PushApi.registerToken` now returns `Response<PushDevice>`.
- §5 API Contract: corrected request body to `{token, platform}`, success response
  to `PushDevice`, headers to include bearer; resolved the DTO open question.
- §6 state: dropped client `device_id`; idempotency tuple is now
  `(user_sub, token, contractVersion)`; added `server_device_id` cache for revoke.
- §7 idempotency: re-keyed the idempotency assumption to `(user, token)` and marked
  server idempotency as unverified.
- §8 security: `device_id` re-described as server-generated, not client-sent.
- §11 / §14 AC-2: test/AC body assertions corrected to `token` + `platform` only.

### Open assumptions

- **Server-side idempotency / upsert key** (token vs device_id): not expressible in
  OpenAPI or the frontend; cannot be verified from the provided sources. Treated as
  assumed-idempotent-by-token with a network-only-retry fallback (§7, §13).
- **Which auth mechanism(s) the server strictly enforces** for `/ui/push/register`:
  OpenAPI lists all of cookies/bearer/CSRF/`X-SESSION-ID`/`user_sub` as optional, so
  the hard requirement is undocumented. The port reproduces the full web-client set
  to be safe; needs a manual server probe to confirm the minimum (§2).
- **200 response body shape**: OpenAPI's `200` schema is empty; the `PushDevice`
  shape comes only from the frontend type. Parse defensively (claim #3).
- **Multi-user-on-one-device server behavior** (reassign vs stack on same token):
  unverifiable from sources (§13.5).
- **Cleartext dev transport** (HTTP) is an environment fact, not a contract claim;
  prod MUST be HTTPS (§8, §13.4).

## 17. Test Plan

IDs `TC-AND-106-NN`. "Traces" link to §14 Acceptance Criteria (AC-1..AC-7).

- **TC-AND-106-01 — Happy path: register fires post-login.**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
  Preconditions: MockWebServer enqueues `200` with a `PushDevice` body; fake
  `AuthStateStore` transitions `false→true` with a known `user_sub`; stubbed
  `FcmTokenProvider` returns a known token; empty `PushRegistrationStore`.
  Steps: drive the auth edge `false→true`; await the registrar coroutine.
  Expected: exactly one recorded request, path `/ui/push/register`, method POST,
  JSON body == `{"token":<t>,"platform":"android"}` (no extra fields); response
  parsed into `PushDevice`; tuple `(user_sub, token, contractVersion)` persisted.
  Traces: AC-1, AC-2.

- **TC-AND-106-02 — Required headers present on the request.**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
  Preconditions: interceptors (cookie jar + CSRF + bearer) configured as in prod;
  `ui_csrf` cookie + session cookie + access token seeded; enqueue `200`.
  Steps: trigger registration.
  Expected: recorded request carries `X-CSRF-Token`, `Cookie` (session + ui_csrf),
  and `Authorization: Bearer <token>`. Traces: AC-2.

- **TC-AND-106-03 — Idempotent no-op on second login with same tuple.**
  Type: unit (JVM). Target: JVM unit/Robolectric.
  Preconditions: `PushRegistrationStore` pre-seeded with the current
  `(user_sub, token, contractVersion)`; MockWebServer with NO enqueued response.
  Steps: drive a second `false→true` auth edge with identical token/user.
  Expected: NO request issued (MockWebServer records zero requests); no exception.
  Traces: AC-3.

- **TC-AND-106-04 — `onNewToken` while authenticated re-registers.**
  Type: unit (JVM). Target: JVM unit/Robolectric.
  Preconditions: authenticated; stored tuple has an OLD token; enqueue `200`.
  Steps: call `registrar.onNewToken(newToken)`.
  Expected: one POST with `token == newToken`; stored tuple updated to new token.
  Traces: AC-4.

- **TC-AND-106-05 — `onNewToken` while unauthenticated caches, registers next
  login.** Type: unit (JVM). Target: JVM unit/Robolectric.
  Preconditions: unauthenticated; empty store.
  Steps: call `onNewToken(t)`; assert no request and `pendingToken()==t`; then drive
  `false→true` with `user_sub`; enqueue `200`.
  Expected: no request during step 1; on login, one POST with the cached token;
  tuple persisted. Traces: AC-4.

- **TC-AND-106-06 — Transient 5xx retries in-call then succeeds.**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
  Preconditions: enqueue `503` then `200 PushDevice`.
  Steps: trigger registration; advance virtual time over backoff.
  Expected: two recorded requests; final state success; tuple persisted; auth
  UiState unchanged. Traces: AC-1, AC-5.

- **TC-AND-106-07 — Exhausted transient failure defers to WorkManager.**
  Type: unit (JVM, WorkManager). Target: JVM unit/Robolectric
  (`TestListenableWorkerBuilder`).
  Preconditions: repository forced to keep failing transiently after in-call
  retries.
  Steps: run `registerCurrentToken`; then run `PushRegisterWorker`.
  Expected: a unique-named (`push_register`, REPLACE, `NetworkType.CONNECTED`,
  exp backoff) work request is enqueued; worker returns `Result.retry()` on
  transient failure, `Result.success()` on success/no-op, `Result.failure()` on
  unauthenticated. Login flow never blocked. Traces: AC-5.

- **TC-AND-106-08 — 401 triggers refresh-once then retry succeeds.**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
  Preconditions: enqueue `401` for `/ui/push/register`, then `200` for
  `/ui/session/refresh`, then `200 PushDevice` for the retried register.
  Steps: trigger registration.
  Expected: exactly one `POST /ui/session/refresh`, original register retried once,
  final success; no error surfaced to auth UiState. Traces: AC-1, AC-5.

- **TC-AND-106-09 — 422 validation error is permanent (no retry, no persist).**
  Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
  Preconditions: enqueue `422
  {"detail":[{"loc":["body","token"],"msg":"field required","type":"value_error.missing"}]}`.
  Steps: trigger registration.
  Expected: exactly one request; error mapped via shared `detail` mapper (string |
  `[{msg}]` | `{code}`); NO retry, NO WorkManager enqueue, tuple NOT persisted.
  Traces: AC-5.

- **TC-AND-106-10 — Logout clears mapping; next login re-registers.**
  Type: unit (JVM). Target: JVM unit/Robolectric.
  Preconditions: store seeded with a registered tuple.
  Steps: call `repository.onLogout()`; assert store cleared; drive a new
  `false→true` edge; enqueue `200`.
  Expected: store empty after logout; subsequent login issues one POST and
  re-persists. Traces: AC-6.

- **TC-AND-106-11 — Full FCM token never logged.**
  Type: unit (JVM). Target: JVM unit/Robolectric.
  Preconditions: capture logger/telemetry sink; run a success and an error path.
  Steps: assert emitted log lines.
  Expected: no log line contains the full token; only a short suffix
  (`token.takeLast(6)`) or hash prefix appears. Traces: AC-7.

- **TC-AND-106-12 — Registration is non-blocking and never alters auth UiState.**
  Type: integration (JVM/Robolectric). Target: JVM unit/Robolectric.
  Preconditions: login ViewModel + registrar wired; register call stalled (delayed
  MockWebServer dispatch) and separately forced to fail.
  Steps: complete login while registration is in-flight / failing.
  Expected: auth UiState reaches authenticated immediately regardless of
  registration outcome; no awaiting of registration on the login path.
  Traces: AC-1, AC-5.

- **TC-AND-106-13 — Flaky-dev-host / offline path.**
  Type: instrumented/e2e. Target: PHYSICAL DEVICE (Samsung Galaxy A15 5G, SM-A156U,
  API 34, arm64-v8a) — MUST run on the physical device to exercise real radio
  toggling and real FCM token retrieval. Preconditions: app authenticated against
  the dev backend; toggle airplane mode to simulate offline.
  Steps: register while offline; observe deferral; restore connectivity.
  Expected: no crash, no token available / network failure handled as transient,
  `PushRegisterWorker` enqueued with `NetworkType.CONNECTED`; on reconnect the
  worker runs and registration succeeds (verifiable via dev-host record). Note:
  real FCM token + `NetworkType.CONNECTED` constraint behavior is hardware/
  Play-Services dependent, hence physical device over emulator. Traces: AC-1, AC-5.

- **TC-AND-106-14 — Security: no registration without an authenticated session.**
  Type: integration (JVM/Robolectric). Target: JVM unit/Robolectric.
  Preconditions: unauthenticated state; `onNewToken` and any spurious auth signal.
  Steps: attempt registration paths while unauthenticated.
  Expected: zero `/ui/push/register` requests issued; token cached only; gating on
  authenticated session + CSRF/bearer prevents unauthenticated registration.
  Traces: AC-2, AC-4.

(Accessibility: this ticket introduces no user-facing UI — registration is a silent
background side effect (§9) — so no Compose-UI/a11y case applies. If a future
diagnostic surface is added it is owned by the E15 permission/UX ticket.)

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (one register post-login, server-verifiable) | TC-01, TC-06, TC-08, TC-12, TC-13 |
| AC-2 (body = token+platform; cookies+CSRF+bearer) | TC-01, TC-02, TC-14 |
| AC-3 (idempotent no-op on same tuple) | TC-03 |
| AC-4 (onNewToken auth/unauth handling) | TC-04, TC-05, TC-14 |
| AC-5 (transient retry→defer; never blocks/alters UiState) | TC-06, TC-07, TC-08, TC-09, TC-12, TC-13 |
| AC-6 (logout clears mapping; next login re-registers) | TC-10 |
| AC-7 (full token never logged) | TC-11 |

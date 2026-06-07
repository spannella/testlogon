---
id: AND-052
title: Auth telemetry/logging (redacted)
milestone: M1
epic: E07
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-031, AND-040]
blocks: []
---

# AND-052 — Auth telemetry/logging (redacted)

## 1. Overview & Goal

The authentication flow (cookie session start → MFA challenge → finalize → `/ui/me`) runs against a known-unreliable plaintext dev backend (`http://18.222.237.167:8000`). When login or MFA fails, the only signal today is a generic error surfaced in `LoginUiState`/`MfaUiState`. Engineers cannot tell whether a failure was a credential rejection, an MFA mismatch, a CSRF/cookie problem, a timeout, a DNS/connect failure, or a 5xx from the flaky host.

This ticket delivers a **structured, redacted telemetry and logging layer for the auth flow**. It defines a small set of typed auth events (login attempt/success/failure, MFA begin/verify/success/failure, session refresh, finalize) plus **network diagnostics** (timing, retry count, response code, exception class, host reachability) emitted at well-defined points in `LoginViewModel` (AND-031), `MfaViewModel` (AND-040), and the network layer. All output is mandatorily redacted: no password, OTP/SMS/email code, cookie value, CSRF token, `challenge_id`, or PII (username) is ever written.

Goal: when an auth failure occurs on the dev host, an engineer reading Logcat (debug) or the in-memory diagnostics buffer can triage the root cause in under a minute, with zero risk of leaking a secret.

Non-goals: shipping logs to a remote analytics backend, crash reporting (Crashlytics/Sentry), and user-facing diagnostics UI. This ticket is local logging + an in-memory ring buffer only; a remote sink is explicitly deferred.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15. minSdk 24, JDK 17.
- **Module placement:** the telemetry contract and redaction live in `core-data` (so both feature modules and `core-network` can depend on it without cycles). Package root `com.testlogon.android.core.data.telemetry`. The OkHttp interceptor lives in `core-network` (`com.testlogon.android.core.network.diag`).
- **Auth flow (authoritative, verified against OpenAPI + `src/api/endpoints/auth.ts`):** `POST /ui/session/start` with body `{ "challenge_context": { ... } }` (`UiSessionStartReq.challenge_context` is a free-form `object`; the web client carries the username/password inside it) → response `UiSessionStartResp` `{ auth_required, challenge_id?, required_factors[], session_id? }` → MFA: `POST /ui/mfa/{sms|email}/begin` (body = `{ challenge_id }` only — **no code**) then `POST /ui/mfa/{totp|sms|email}/verify` (body carries `challenge_id` + the factor code: `totp_code` for TOTP, `code` for SMS/email) → `POST /ui/session/finalize` (`UiSessionFinalizeReq` `{ challenge_id, remember_device? }`) → `GET /ui/me`. NOTE: there is **no** `/ui/mfa/totp/begin` endpoint — TOTP has verify only. Cookie-based session + `ui_csrf` cookie echoed as the `X-CSRF-Token` header (verified `src/api/client.ts`). On a 401 the web client refreshes-then-retries **only when the user was already authenticated**; an *unauthenticated* 401 (e.g. wrong password at login) propagates directly with **no** refresh attempt (verified `src/api/client.ts` 401 handling). This distinction drives `SESSION_EXPIRED` vs `INVALID_CREDENTIALS` reason mapping (§4).
- **Upstream dependencies:**
  - AND-031 `LoginViewModel` — emits login attempt/result events.
  - AND-040 `MfaViewModel` — emits MFA begin/verify/result events.
  - Network diagnostics hook into the OkHttp client established by core-network (the same client that owns the persistent cookie jar and CSRF/refresh interceptors).
- **Web reference:** `frontend/src/api/endpoints/*.ts` (endpoint paths), `frontend/src/api/types.ts` (factor/challenge shapes). The web app has no equivalent redaction layer; this is Android-specific.

## 3. Functional Requirements

FR-1. Define a typed, sealed `AuthEvent` hierarchy covering the auth lifecycle: login attempt/success/failure, MFA challenge presented, MFA begin requested, MFA verify attempt/success/failure, session finalize success/failure, session refresh attempt/success/failure.

FR-2. Provide an `AuthTelemetry` interface with a single `log(event: AuthEvent)` entry point, injected via Hilt as a singleton.

FR-3. Every event carries: monotonic timestamp, a coarse `AuthStage` enum, an `AuthOutcome` (`ATTEMPT|SUCCESS|FAILURE`), and a redacted, bounded key/value attribute map.

FR-4. Failure events carry a typed `AuthFailureReason` derived from the network/HTTP outcome (`INVALID_CREDENTIALS`, `MFA_REJECTED`, `CSRF_MISSING`, `SESSION_EXPIRED`, `TIMEOUT`, `CONNECT_FAILED`, `DNS_FAILED`, `SERVER_5XX`, `MALFORMED_RESPONSE`, `UNKNOWN`).

FR-5. Network diagnostics: for every auth-path request, capture method, redacted path (path only, never query), HTTP status, wall-clock duration (ms), retry attempt index, and on failure the throwable class name + first line of message (redaction-scanned).

FR-6. **Redaction is mandatory and central.** A single `Redactor` sanitizes all attribute values and free-text before emission. Forbidden tokens (password, otp/code, cookie values, `X-CSRF-Token`, `challenge_id`, raw username) must never appear. `challenge_id` is replaced by a stable salted short hash for correlation; username is replaced by `userPresent=true/false` (never the value).

FR-7. Maintain an in-memory **ring buffer** (last N=200 events) exposed as a read-only snapshot for debug triage and for assertion in instrumentation tests.

FR-8. Logcat output is gated on `BuildConfig.DEBUG`. In release builds events still flow to the ring buffer and to the (no-op for now) remote sink seam, but nothing is written to Logcat.

FR-9. Event emission must be non-blocking and must never throw into the caller. A failure inside the telemetry layer is swallowed (and itself logged once at debug).

## 4. Technical Design

New module-local package `com.testlogon.android.core.data.telemetry`.

```kotlin
enum class AuthStage { LOGIN, MFA_BEGIN, MFA_VERIFY, FINALIZE, REFRESH, ME }
enum class AuthOutcome { ATTEMPT, SUCCESS, FAILURE }
enum class AuthFactor { TOTP, SMS, EMAIL }

enum class AuthFailureReason {
    INVALID_CREDENTIALS, MFA_REJECTED, CSRF_MISSING, SESSION_EXPIRED,
    TIMEOUT, CONNECT_FAILED, DNS_FAILED, SERVER_5XX, MALFORMED_RESPONSE, UNKNOWN
}

sealed interface AuthEvent {
    val stage: AuthStage
    val outcome: AuthOutcome
    val elapsedMs: Long?
    val attrs: Map<String, String>   // already redacted by construction

    data class LoginAttempt(val userPresent: Boolean) : AuthEvent { /* stage=LOGIN, outcome=ATTEMPT */ }
    data class LoginSuccess(val requiredFactors: List<AuthFactor>, override val elapsedMs: Long?) : AuthEvent
    data class LoginFailure(val reason: AuthFailureReason, val httpStatus: Int?, override val elapsedMs: Long?) : AuthEvent
    data class MfaBegin(val factor: AuthFactor, val challengeRef: String) : AuthEvent
    data class MfaVerifyAttempt(val factor: AuthFactor, val challengeRef: String) : AuthEvent
    data class MfaSuccess(val factor: AuthFactor, val challengeRef: String, override val elapsedMs: Long?) : AuthEvent
    data class MfaFailure(val factor: AuthFactor, val reason: AuthFailureReason, val remainingFactors: Int, override val elapsedMs: Long?) : AuthEvent
    data class FinalizeResult(override val outcome: AuthOutcome, val reason: AuthFailureReason?, override val elapsedMs: Long?) : AuthEvent
    data class RefreshResult(override val outcome: AuthOutcome, override val elapsedMs: Long?) : AuthEvent
}
```

`challengeRef` is `Redactor.shortHash(challengeId)` (see §8), never the raw id.

```kotlin
interface AuthTelemetry {
    fun log(event: AuthEvent)
    fun snapshot(): List<TelemetryRecord>   // newest-last copy of ring buffer
}

data class TelemetryRecord(
    val tMillis: Long,
    val stage: AuthStage,
    val outcome: AuthOutcome,
    val reason: AuthFailureReason?,
    val line: String,          // fully redacted, structured "k=v" line
)
```

Default implementation:

```kotlin
@Singleton
class DefaultAuthTelemetry @Inject constructor(
    private val redactor: Redactor,
    @Named("io") private val scope: CoroutineScope,    // SupervisorJob + Dispatchers.IO
    private val clock: () -> Long = { SystemClock.elapsedRealtime() },
) : AuthTelemetry {

    private val ring = ArrayDeque<TelemetryRecord>(RING_CAPACITY)
    private val lock = Any()

    override fun log(event: AuthEvent) {
        runCatching {
            val rec = event.toRecord(clock(), redactor)
            synchronized(lock) {
                if (ring.size >= RING_CAPACITY) ring.removeFirst()
                ring.addLast(rec)
            }
            if (BuildConfig.DEBUG) Log.println(rec.logLevel(), TAG, rec.line)
            // remote sink seam: no-op in M1 (see AND backlog future ticket)
        }.onFailure { if (BuildConfig.DEBUG) Log.d(TAG, "telemetry self-error") }
    }

    override fun snapshot(): List<TelemetryRecord> = synchronized(lock) { ring.toList() }

    companion object { const val RING_CAPACITY = 200; const val TAG = "AuthTelemetry" }
}
```

The structured line format is deterministic and parseable:
`stage=MFA_VERIFY outcome=FAILURE reason=MFA_REJECTED factor=TOTP cref=a91f remaining=1 http=401 t=842ms`.

**Network diagnostics** are produced by an OkHttp `Interceptor` scoped to auth-path requests (path prefix `/ui/`), inserted as an application interceptor *after* the retry/refresh interceptor so it observes the final outcome and attempt count.

```kotlin
class AuthDiagInterceptor @Inject constructor(
    private val telemetry: AuthTelemetry,
    private val redactor: Redactor,
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val req = chain.request()
        if (!req.url.encodedPath.startsWith("/ui/")) return chain.proceed(req)
        val start = SystemClock.elapsedRealtime()
        val attempt = req.tag(AttemptTag::class.java)?.index ?: 0
        return try {
            chain.proceed(req).also {
                telemetry.log(networkEvent(req, status = it.code, attempt, start, err = null))
            }
        } catch (e: IOException) {
            telemetry.log(networkEvent(req, status = null, attempt, start, err = e)); throw e
        }
    }
}
```

`networkEvent(...)` maps the `(status, throwable)` pair to an `AuthFailureReason` and to the appropriate `AuthEvent` subtype based on the request path: `SocketTimeoutException → TIMEOUT`, `UnknownHostException → DNS_FAILED`, `ConnectException → CONNECT_FAILED`, 5xx → `SERVER_5XX`, JSON parse failure surfaced by callers → `MALFORMED_RESPONSE`. The 401 mapping is **path- and auth-state-dependent** (mirrors the verified web client): a 401 on `POST /ui/session/start` (login, unauthenticated) → `INVALID_CREDENTIALS` and propagates with **no** refresh/retry; a 401 on a post-login authenticated request (`/ui/me`, finalize, etc.) → `SESSION_EXPIRED` and triggers the single refresh-then-retry. The interceptor only records the *transport* signal; semantic failures (e.g. MFA rejected vs malformed) are refined by the ViewModels using the typed `ApiResult`.

**ViewModel integration.** `LoginViewModel` (AND-031) and `MfaViewModel` (AND-040) take an injected `AuthTelemetry` and emit `LoginAttempt`/`LoginSuccess`/`LoginFailure` and the MFA events at the same points where they transition `UiState`. Mapping from the repository's `ApiResult<T>` (and the FastAPI `detail` mapping) to `AuthFailureReason` is done by a shared extension:

```kotlin
fun ApiResult.Failure.toAuthReason(stage: AuthStage): AuthFailureReason
```

No raw `detail` strings are placed in `attrs`; only the derived enum + numeric http status.

## 5. API Contract

This ticket consumes existing auth endpoints but defines **no new server endpoints**. It observes:

- `POST /ui/session/start` → `UiSessionStartResp` `{ "auth_required": bool, "challenge_id": "<redacted>", "required_factors": ["totp","sms"], "session_id": "<redacted>" }` — only `required_factors` (mapped to `AuthFactor`) and a hash of `challenge_id` are logged; `session_id` is never logged.
- `POST /ui/mfa/{sms|email}/begin` (body = `{ challenge_id }` only — **no code**) and `POST /ui/mfa/{totp|sms|email}/verify` (verify body = `{ challenge_id, totp_code }` for TOTP or `{ challenge_id, code }` for SMS/email) — request bodies are **never** logged; only path, status, factor, `cref` (hashed challenge id). NOTE: TOTP has **no** begin endpoint; the verify code field is `totp_code` (not `code`), so the redaction denylist must cover `totp_code` as well as `code`.
- `POST /ui/session/finalize`, `POST /ui/session/refresh`, `GET /ui/me` — status + timing only.

Telemetry emits no network payload. The local `snapshot()` contract returns `List<TelemetryRecord>` as defined in §4; this is an internal API, not a wire contract.

Remote ingestion contract is **out of scope / N/A** for AND-052; the `remote sink seam` is a no-op and any future remote telemetry endpoint is owned by a later M2 observability ticket (not yet ticketed in this backlog slice).

## 6. Data & State Management

- **In-memory only.** No Room table and no DataStore key — telemetry must not persist secrets-adjacent data to disk, and persistence is not required for dev-host triage. The ring buffer (capacity 200) lives in the `DefaultAuthTelemetry` singleton and is cleared on process death.
- The redaction salt used for `challengeRef` hashing is a per-process random value held in memory (so hashes are stable within a session for correlation but not reversible/persisted across runs).
- ViewModels do not store telemetry in their `StateFlow<UiState>`; telemetry is a side channel. `UiState` continues to carry only user-facing error text (owned by AND-031/AND-040).
- `snapshot()` returns an immutable copy; callers never get a live reference to the buffer.

## 7. Error Handling & Resilience

- **Self-isolation:** `log()` wraps all work in `runCatching`; a telemetry failure can never propagate into the auth flow or alter `UiState`.
- **Flaky-host diagnostics (core value of this ticket):** the diag interceptor distinguishes `TIMEOUT` (20s ceiling reached), `CONNECT_FAILED`, and `DNS_FAILED`, and records the retry `attempt` index so an engineer can see "GET /ui/me failed 3x: TIMEOUT, TIMEOUT, CONNECT_FAILED" — directly attributing the failure to the unreliable dev host vs an app bug.
- Retry telemetry mirrors core-network policy: bounded backoff retries apply only to idempotent GETs; each retry produces a distinct attempt-indexed event so retry storms are visible.
- Backpressure: emission is O(1) under a short `synchronized` block; no unbounded queues. If the ring is full the oldest record is evicted.
- Thread-safety: ring access is guarded; `clock` and `redactor` are pure/stateless.

## 8. Security & Privacy

This is the highest-stakes section for AND-052 (acceptance criterion: "No secrets logged").

- **Central Redactor** is the only path values reach a sink:

```kotlin
class Redactor @Inject constructor(@Named("redactSalt") private val salt: ByteArray) {
    fun shortHash(value: String): String =                 // 4-hex correlation token
        HMAC_SHA256(salt, value.toByteArray()).toHexString().take(8).take(4)
    fun scrub(text: String): String                        // masks token patterns + denylist keys
}
```

- **Hard denylist** (never logged in any form): `password`, `pwd`, `code`, `totp_code`, `otp`, `token`, `csrf`, `cookie`, `set-cookie`, `authorization`. Matching is substring/case-insensitive on the key (so `totp_code` is also caught by the `code` substring, but it is listed explicitly for clarity since the wire field name is `totp_code` per `TotpVerifyReq`). Any attribute whose key matches the denylist is dropped; any value matching secret-shaped regexes (e.g. 6-digit codes `\b\d{6}\b`, JWT-like, long hex/base64) is replaced with `***`.
- **Username** is never logged — only `userPresent=true/false`.
- **`challenge_id`** → `cref=<4 hex>` via salted HMAC; not reversible.
- **No request/response bodies, no headers** (especially `Cookie`/`Set-Cookie`/`X-CSRF-Token`) are ever passed to telemetry. The diag interceptor reads only method, `encodedPath` (query stripped), and status.
- **Release builds:** Logcat output disabled (`BuildConfig.DEBUG` gate), so even the redacted lines do not reach device logs in production.
- A unit-test "canary" feeds known secrets (a password, a 6-digit code, a fake cookie, a JWT) through every event constructor and asserts none appear in `TelemetryRecord.line`.

## 9. Accessibility & i18n

N/A for user-facing UI — this ticket produces developer-facing logs only, with no Compose surface and no user-visible strings. Telemetry log lines are intentionally English, machine-parseable, and **not** localized (they must never be translated, to keep grep/triage stable). The user-facing error strings that correspond to these failures are owned and localized by AND-031 (`LoginUiState`) and AND-040 (`MfaUiState`); this ticket does not add or alter any `strings.xml` entry.

## 10. Telemetry & Logging

This ticket *is* the telemetry layer; the design is specified in §3–§4. Summary of emission points:

- `LoginViewModel.submit()` → `LoginAttempt` then `LoginSuccess`/`LoginFailure`.
- `MfaViewModel` state machine transitions → `MfaBegin`, `MfaVerifyAttempt`, `MfaSuccess`/`MfaFailure`, `FinalizeResult`.
- Refresh interceptor / session layer → `RefreshResult`.
- `AuthDiagInterceptor` → transport-level network records for all `/ui/` requests.

Log tag `AuthTelemetry`, level mapping: `ATTEMPT`/`SUCCESS` → `INFO`, `FAILURE` → `WARN` (or `ERROR` for `SERVER_5XX`/`MALFORMED_RESPONSE`). The remote-sink seam (`interface RemoteTelemetrySink` with a `NoopRemoteTelemetrySink` Hilt binding) is wired but inert; swapping in a real sink later requires no call-site changes.

## 11. Testing Strategy

Unit tests (`core-testing` helpers), JUnit5 + Turbine + MockWebServer where applicable:

- **RedactorTest:** denylist keys dropped; 6-digit codes, JWT, long hex/base64 masked to `***`; `shortHash` deterministic within a salt and ≠ raw input; different salts → different hashes.
- **SecretsCanaryTest:** construct every `AuthEvent` subtype with planted secrets (password, OTP `123456`, cookie string, `X-CSRF-Token` value, raw `challenge_id`, username) → assert `snapshot()` lines contain none of them, and contain `cref=` and `userPresent=`.
- **DefaultAuthTelemetryTest:** ring buffer caps at 200 (oldest evicted); `log()` never throws even when `redactor` throws; `snapshot()` returns an immutable copy; level mapping correct.
- **AuthDiagInterceptorTest (MockWebServer):** simulate timeout, `UnknownHostException`, 500, 401, 200 → assert correct `AuthFailureReason` and that path query strings/headers are absent from emitted lines; assert `attempt` index increments across retried GETs.
- **ApiResultMappingTest:** `ApiResult.Failure` (each FastAPI `detail` shape) → expected `AuthFailureReason`; raw `detail` text never reaches `attrs`.
- **ViewModel integration:** with a fake `AuthTelemetry`, assert `LoginViewModel`/`MfaViewModel` emit the expected event sequence for success and each failure path, in order, aligned with `UiState` transitions (depends on AND-031/AND-040 fakes).

Coverage gate: Redactor + canary tests are required-passing; CI fails the build if `SecretsCanaryTest` fails.

## 12. Dependencies & Sequencing

- **Depends on AND-031 (LoginViewModel)** — provides the login state transitions and `ApiResult` mapping points where login events are emitted.
- **Depends on AND-040 (MfaViewModel)** — provides the MFA challenge state machine emission points and `remainingFactors`.
- Soft dependency on core-network's existing OkHttp client / retry+refresh interceptor (cookie jar, CSRF) so `AuthDiagInterceptor` can be ordered after them; if that interceptor chain changes ordering, re-verify attempt-index accuracy.
- **Blocks:** nothing in this backlog slice. A future remote-observability ticket would build on the `RemoteTelemetrySink` seam.
- Sequencing: implement `Redactor` + `AuthEvent` + `DefaultAuthTelemetry` (no upstream deps) first; wire `AuthDiagInterceptor` once core-network is stable; wire ViewModel emission last (needs AND-031/AND-040 merged).

## 13. Risks & Open Questions

- **R1 — Redaction completeness.** Regex-based secret masking can miss novel formats. Mitigation: denylist-by-key is primary; regex is defense-in-depth; canary test is mandatory CI gate. Open: should we add a build-time lint that flags any `Log.*` call inside auth packages not routed through `AuthTelemetry`? (Recommend yes, follow-up.)
- **R2 — Interceptor ordering.** If `AuthDiagInterceptor` runs before the refresh/retry interceptor it will misreport attempt counts and double-count. Must be ordered last among application interceptors; covered by interceptor-order test.
- **R3 — Plaintext HTTP host.** Diagnostics describe an inherently insecure channel; this ticket does not change transport security. Open question: is `usesCleartextTraffic` already scoped to the dev host elsewhere? (Owned by network-config ticket, not here.)
- **R4 — `challenge_id` correlation.** 4-hex `cref` has collision potential across many sessions but is adequate for single-session triage; acceptable given non-persistence.
- **Open:** N=200 ring size — confirm sufficient for a full retry-storm trace (a single flaky login can produce ~10–15 events; 200 covers a deep session). Tunable constant.

## 14. Acceptance Criteria

1. **No secrets logged.** `SecretsCanaryTest` proves password, OTP/SMS/email codes, cookie values, `X-CSRF-Token`, raw `challenge_id`, and raw username never appear in any `TelemetryRecord.line` or Logcat output; CI fails if violated.
2. Every auth-flow step emits a typed `AuthEvent` (login attempt/success/failure, MFA begin/verify/success/failure, finalize, refresh) with correct `AuthStage`/`AuthOutcome`/`AuthFailureReason`, verified by ViewModel integration tests.
3. **Diagnostics help triage dev-host issues:** for timeout, connect-refused, DNS-failure, 5xx, and 401 against the dev host, the emitted record carries the correct `AuthFailureReason`, HTTP status (or throwable class), elapsed ms, and retry attempt index — demonstrated via MockWebServer tests.
4. Telemetry never throws into or alters the auth flow / `UiState` (proven by a redactor-throws test).
5. Logcat output is suppressed in release builds; ring buffer + no-op remote seam still function.
6. In-memory ring buffer caps at 200 with oldest-eviction; `snapshot()` returns an immutable copy.
7. No new server endpoints, no persisted telemetry, no localized strings introduced.

## 15. Definition of Done

- `Redactor`, `AuthEvent`, `AuthTelemetry`/`DefaultAuthTelemetry`, `AuthDiagInterceptor`, `RemoteTelemetrySink` (+ no-op binding), and `ApiResult.Failure.toAuthReason` implemented under `com.testlogon.android.core.data.telemetry` / `com.testlogon.android.core.network.diag`, with Hilt bindings (singleton).
- `LoginViewModel` (AND-031) and `MfaViewModel` (AND-040) wired to emit events at all transitions.
- All §11 tests written and green; `SecretsCanaryTest` enforced as a required CI check.
- Detekt/ktlint clean; no `Log.*` secret leaks introduced; PR includes a sample redacted trace of a failed dev-host login in the description.
- Code reviewed and merged to branch `android-port` in `spannella/testlogon`; `core-data`/`core-network` modules build with KSP under Gradle 8.9 / AGP 8.7.3 / JDK 17.
- Documented constants (`RING_CAPACITY`, denylist) and a one-paragraph note in the module README on how to read a telemetry trace.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **`POST /ui/session/start` exists; request `UiSessionStartReq`, response `UiSessionStartResp`.** VERIFIED. OpenAPI `POST /ui/session/start | op=ui_session_start_ui_session_start_post | req=UiSessionStartReq | resp=200:UiSessionStartResp`; `src/api/endpoints/auth.ts: sessionStart`.
2. **`UiSessionStartResp` fields = `auth_required` (required), `challenge_id?`, `required_factors[]`, `session_id?`.** VERIFIED. `components.schemas.UiSessionStartResp` (openapi.pretty.json); `src/api/types.ts: SessionStartResp`. (Spec previously omitted `session_id`; added and explicitly excluded from logging.)
3. **`UiSessionStartReq.challenge_context` is a free-form object carrying username/password.** VERIFIED (shape) / Unverified (contents). Schema `UiSessionStartReq` has only `challenge_context: object (additionalProperties:true)`; `src/api/types.ts: SessionStartReq { challenge_context?: Record<string, unknown> }`. The exact keys (`username`,`password`) inside are not pinned by the schema — treated as the web convention.
4. **MFA begin endpoints take `{ challenge_id }` only (no code).** CORRECTED (spec §5 previously said "begin … body includes `challenge_id` + code"). OpenAPI `POST /ui/mfa/sms/begin | req=SmsBeginReq`, `POST /ui/mfa/email/begin | req=EmailBeginReq`; schemas `SmsBeginReq`/`EmailBeginReq` = `{ challenge_id }` only; `src/api/types.ts: SmsBeginReq`/`EmailBeginReq`.
5. **No `/ui/mfa/totp/begin` endpoint (TOTP is verify-only).** CORRECTED. openapi.index.txt has `POST /ui/mfa/totp/verify` but no `/ui/mfa/totp/begin` (only `totp/devices/*` management endpoints). `src/api/endpoints/auth.ts` exposes `verifyTotp` but no `beginTotp`.
6. **MFA verify code field names: `totp_code` (TOTP), `code` (SMS/email).** CORRECTED/clarified. Schemas `TotpVerifyReq { challenge_id, totp_code }`, `SmsVerifyReq { challenge_id, code }`, `EmailVerifyReq { challenge_id, code }`; `src/api/types.ts: TotpVerifyReq`/`SmsVerifyReq`/`EmailVerifyReq`. Denylist updated to include `totp_code` (§8).
7. **`POST /ui/session/finalize` body `UiSessionFinalizeReq { challenge_id, remember_device? }`.** VERIFIED. `components.schemas.UiSessionFinalizeReq`; `src/api/endpoints/auth.ts: sessionFinalize`; `src/api/types.ts: SessionFinalizeReq`.
8. **`POST /ui/session/refresh` exists, no request body.** VERIFIED. OpenAPI `POST /ui/session/refresh | req= | resp=200:`; `src/api/endpoints/auth.ts: refreshSession` (POST, no body); `src/api/client.ts: refreshSession()`.
9. **`GET /ui/me` exists.** VERIFIED. OpenAPI `GET /ui/me | op=ui_me_ui_me_get`; `src/api/endpoints/auth.ts: getMe`.
10. **CSRF: `ui_csrf` cookie value sent as `X-CSRF-Token` header.** VERIFIED. `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
11. **401 handling: refresh-then-retry only when already authenticated; unauthenticated 401 propagates with no refresh.** CORRECTED (spec previously stated a blanket "On 401 … refresh once then retries"). `src/api/client.ts` 401 branch: `if (!useAuthStore.getState().isAuthenticated) { … throw ApiError(401,…) }` before any refresh; refresh+single retry only otherwise.
12. **Offline/DNS/connect failures surface as a status-0 error in the web client.** VERIFIED (web behavior basis for `CONNECT_FAILED`/`DNS_FAILED`/network mapping). `src/api/client.ts` catch around `fetch` → `throw new ApiError(0, "Network error", err)`.
13. **Validation errors (422) shape = `HTTPValidationError { detail: ValidationError[] }` with `{loc,msg,type}`; auth errors (401/403) use string- or object-`detail`.** VERIFIED. `components.schemas.HTTPValidationError` → array of `ValidationError`; `src/api/client.ts: normalizeErrorDetail` handles string, array-of-`{msg}`, and object-with-`code`. Telemetry must map the derived enum only — never the raw `detail`/`msg` text.
14. **No new server endpoints / no remote sink in M1.** VERIFIED (by absence). No telemetry/ingest endpoint matches in openapi.index.txt; consistent with §5.
15. **Framework choices: OkHttp `Interceptor` ordering (application interceptor after retry/refresh), `Log.println`, `SystemClock.elapsedRealtime()`, `BuildConfig.DEBUG` gate.** Unverified-assumption (framework, not sourced from this repo's contracts). framework ref: OkHttp interceptors https://square.github.io/okhttp/features/interceptors/ ; Android `SystemClock` https://developer.android.com/reference/android/os/SystemClock ; `Log` https://developer.android.com/reference/android/util/Log . Reasonable standard choices; not contradicted by any source.

### Corrections made

- §2 / §4 / §5: MFA **begin** bodies carry `{ challenge_id }` only — not "challenge_id + code". Code is present only on **verify**. (Claims 4.)
- §2 / §5: Removed the implied `/ui/mfa/totp/begin`; TOTP is verify-only. (Claim 5.)
- §5 / §8: MFA verify code field is `totp_code` for TOTP (and `code` for SMS/email); denylist extended to include `totp_code`. (Claims 6.)
- §2 / §4: The 401 refresh-then-retry is conditional on prior authentication; an unauthenticated login 401 → `INVALID_CREDENTIALS` and propagates without refresh; an authenticated 401 → `SESSION_EXPIRED` + single refresh/retry. Removed the blanket "On 401 … refresh once then retries". (Claim 11.)
- §5: Added `session_id` to the documented `UiSessionStartResp` and stated it is never logged. (Claim 2.)

### Open assumptions

- **Username/password live inside `challenge_context`** (Claim 3): the OpenAPI schema is a free-form object, so the exact key names are not pinned. Web convention assumed; confirm against AND-031's actual request builder when it lands.
- **Interceptor attempt-index source** (`req.tag(AttemptTag::class.java)`): depends on core-network's retry/refresh interceptor tagging requests with an attempt counter — that internal contract is not in the OpenAPI/web sources and must be confirmed against AND-031/core-network (already flagged R2/§12).
- **Framework-level choices** (Claim 15): standard Android/OkHttp APIs, validated against vendor docs, not against this repo.
- **`ApiResult` / `ApiResult.Failure.toAuthReason` types**: Android-internal abstractions owned by AND-031; no source in the reference web app (the web client uses a single `ApiError` class instead). Mapping fidelity is asserted by tests, not by an external contract.

## 17. Test Plan

Acceptance criteria referenced are from §14 (AC-1 … AC-7). Test target legend per the CI/dev inventory: JVM = JVM/Robolectric local; Emu = headless AVD `test35` (x86_64, API 35); Phys = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This ticket is a developer-facing logging layer with **no Compose surface**, so most coverage is JVM unit + MockWebServer contract; a small instrumented slice validates the ring buffer and Logcat gating on real Android.

- **TC-AND-052-01** — Type: unit (JVM). Target: JVM. Test target: `Redactor`.
  - Preconditions: `Redactor` constructed with a fixed test salt.
  - Steps: feed denylisted keys (`password`, `pwd`, `code`, `totp_code`, `otp`, `token`, `csrf`, `cookie`, `set-cookie`, `authorization`) and secret-shaped values (6-digit `123456`, a JWT-like string, a 40-char hex, a base64 blob) through `scrub`/attribute construction.
  - Expected: denylisted keys dropped entirely; secret-shaped values replaced with `***`; non-secret values pass through unchanged.
  - Traces: AC-1.

- **TC-AND-052-02** — Type: unit (JVM). Target: JVM. Test target: `Redactor.shortHash`.
  - Preconditions: two `Redactor` instances with salt A and salt B.
  - Steps: hash the same `challenge_id` twice within salt A, once with salt B.
  - Expected: 4-hex `cref`; deterministic within a salt; `cref` ≠ raw input; salt A `cref` ≠ salt B `cref`; output reveals nothing reversible.
  - Traces: AC-1.

- **TC-AND-052-03** — Type: unit (JVM, "secrets canary"). Target: JVM. Test target: every `AuthEvent` subtype + `DefaultAuthTelemetry`.
  - Preconditions: real `DefaultAuthTelemetry` + real `Redactor`.
  - Steps: construct/log each `AuthEvent` subtype with planted secrets — password, OTP `123456`, a cookie string, an `X-CSRF-Token` value, a raw `challenge_id`, `totp_code`, and a raw username; read `snapshot()`.
  - Expected: no planted secret appears in any `TelemetryRecord.line`; lines contain `cref=` and `userPresent=true|false` but never the username. CI fails the build if this test fails.
  - Traces: AC-1, AC-2, AC-7.

- **TC-AND-052-04** — Type: unit (JVM). Target: JVM. Test target: `DefaultAuthTelemetry` ring buffer.
  - Preconditions: telemetry singleton, `RING_CAPACITY=200`.
  - Steps: log 250 events; call `snapshot()`; mutate the returned list / log more.
  - Expected: snapshot size capped at 200, oldest 50 evicted (FIFO, newest-last); returned list is an immutable copy (mutating it or logging more does not alter a prior snapshot).
  - Traces: AC-6.

- **TC-AND-052-05** — Type: unit (JVM). Target: JVM. Test target: `DefaultAuthTelemetry.log` self-isolation + level mapping.
  - Preconditions: a `Redactor` stub that throws on `scrub`.
  - Steps: call `log()` with the throwing redactor; also log normal `ATTEMPT`/`SUCCESS`/`FAILURE`/`SERVER_5XX` events.
  - Expected: `log()` never throws to the caller; failing event is swallowed (optionally one debug self-log); level mapping `ATTEMPT|SUCCESS→INFO`, `FAILURE→WARN`, `SERVER_5XX|MALFORMED_RESPONSE→ERROR`.
  - Traces: AC-4.

- **TC-AND-052-06** — Type: contract/MockWebServer. Target: JVM. Test target: `AuthDiagInterceptor` happy path.
  - Preconditions: OkHttp client with `AuthDiagInterceptor`; MockWebServer enqueues `200` for `POST /ui/session/start`.
  - Steps: execute the request (with a query string and `Cookie`/`X-CSRF-Token` headers attached).
  - Expected: one network record with `stage` for the start path, `outcome=SUCCESS`, `http=200`, an `elapsedMs`, `attempt=0`; the emitted line contains the path but **no query string** and **no header values** (no cookie/CSRF leakage).
  - Traces: AC-3, AC-1.

- **TC-AND-052-07** — Type: contract/MockWebServer. Target: JVM. Test target: `AuthDiagInterceptor` error-reason mapping.
  - Preconditions: MockWebServer scenarios — socket timeout (no response / `SocketPolicy.NO_RESPONSE_AFTER_REQUEST`), `UnknownHostException` (bad host), connection refused, `500`, and `401` on `POST /ui/session/start`.
  - Steps: drive each scenario through the auth path.
  - Expected: reasons map to `TIMEOUT`, `DNS_FAILED`, `CONNECT_FAILED`, `SERVER_5XX`, and (unauthenticated start) `INVALID_CREDENTIALS` respectively; failure records carry the throwable class name (first line only, redaction-scanned) or `http` status; no secrets in any line.
  - Traces: AC-3.

- **TC-AND-052-08** — Type: contract/MockWebServer. Target: JVM. Test target: retry/attempt-index accuracy (flaky-host trace).
  - Preconditions: interceptor ordered **after** the retry/refresh interceptor; MockWebServer returns timeout, timeout, then connection-refused for a retried idempotent `GET /ui/me`.
  - Steps: issue the GET; let core-network retry per policy.
  - Expected: three distinct attempt-indexed records (`attempt=0,1,2`) with reasons `TIMEOUT, TIMEOUT, CONNECT_FAILED`, reproducing the "GET /ui/me failed 3x" triage narrative; no double-counting.
  - Traces: AC-3, AC-6.

- **TC-AND-052-09** — Type: contract/MockWebServer. Target: JVM. Test target: 401 refresh-vs-propagate semantics.
  - Preconditions: two cases — (a) unauthenticated login (`POST /ui/session/start` → 401); (b) authenticated request (`GET /ui/me` → 401, then `POST /ui/session/refresh` → 200, then retry → 200).
  - Steps: run both.
  - Expected: (a) no `/ui/session/refresh` call is made, `LoginFailure`/network reason = `INVALID_CREDENTIALS`; (b) exactly one refresh then a retry, with a `RefreshResult(SUCCESS)` event and `SESSION_EXPIRED`-classified original 401. Mirrors verified web client behavior.
  - Traces: AC-2, AC-3.

- **TC-AND-052-10** — Type: unit (JVM). Target: JVM. Test target: `ApiResult.Failure.toAuthReason` + `detail`-shape mapping.
  - Preconditions: fabricate `ApiResult.Failure` for each shape: 422 `HTTPValidationError { detail: [{loc,msg,type}] }`, 401 string `detail`, 403 object `detail { code }`, malformed JSON, 5xx.
  - Steps: map each to `AuthFailureReason`.
  - Expected: correct enum per stage (`MALFORMED_RESPONSE` for parse failure, `SERVER_5XX` for 5xx, etc.); raw `detail`/`msg` text never written into `attrs` or `line` (only the enum + numeric status).
  - Traces: AC-1, AC-2.

- **TC-AND-052-11** — Type: integration (fake telemetry). Target: JVM/Robolectric. Test target: `LoginViewModel` (AND-031) + `MfaViewModel` (AND-040) emission sequence.
  - Preconditions: ViewModels wired to a fake `AuthTelemetry`; fake repo returns scripted success and failure `ApiResult`s.
  - Steps: drive happy path (login→MFA begin→verify→finalize→me) and each failure path; capture event order with Turbine.
  - Expected: emitted `AuthEvent` sequence matches `UiState` transitions in order (e.g. `LoginAttempt`→`LoginSuccess`→`MfaBegin`→`MfaVerifyAttempt`→`MfaSuccess`/`MfaFailure`→`FinalizeResult`), with correct `stage/outcome/reason` and `remainingFactors` from `MfaVerifyResp.remaining_factors`.
  - Traces: AC-2.

- **TC-AND-052-12** — Type: instrumented/e2e. Target: Phys (Samsung Galaxy A15 5G, API 34, arm64-v8a). Test target: `DefaultAuthTelemetry` ring buffer + `BuildConfig.DEBUG` Logcat gate on real hardware.
  - Preconditions: debug build installed on the physical device; logcat capture via adb.
  - Steps: exercise a scripted auth failure sequence; read `snapshot()` and dump logcat for tag `AuthTelemetry`.
  - Expected: ring buffer populated identically to JVM tests; redacted lines visible in logcat under tag `AuthTelemetry`. MUST run on the physical device to confirm real arm64/API-34 `Log`/`SystemClock` behavior differs from the x86_64/API-35 emulator (ABI/API-level check per the inventory). A parallel run on Emu `test35` confirms parity.
  - Traces: AC-5, AC-6.

- **TC-AND-052-13** — Type: instrumented (release variant). Target: Emu `test35`. Test target: release Logcat suppression.
  - Preconditions: a release-type build (or `BuildConfig.DEBUG=false`) installed.
  - Steps: trigger auth failures; capture logcat; read `snapshot()`.
  - Expected: **zero** `AuthTelemetry` lines in logcat; ring buffer still populated and the no-op `RemoteTelemetrySink` still invoked (verifiable via a test sink). Confirms no redacted lines reach device logs in production.
  - Traces: AC-5, AC-7.

- **TC-AND-052-14** — Type: manual / static check (security). Target: JVM (Detekt/ktlint + review). Test target: auth packages + diag interceptor.
  - Preconditions: full build with lint/Detekt.
  - Steps: scan auth packages for `Log.*` calls not routed through `AuthTelemetry`; confirm the diag interceptor reads only method, `encodedPath` (query stripped), and status (never headers/bodies); confirm no `strings.xml` entry, Room table, or DataStore key added.
  - Expected: no stray `Log.*` leaks; no headers/bodies/query reach telemetry; no persisted telemetry and no localized strings introduced (AC-7). (Promote to a CI lint rule per R1 follow-up.)
  - Traces: AC-1, AC-7.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
|---|---|
| AC-1 No secrets logged | TC-01, TC-02, TC-03, TC-06, TC-07, TC-10, TC-14 |
| AC-2 Every step emits a typed `AuthEvent` (correct stage/outcome/reason) | TC-03, TC-09, TC-10, TC-11 |
| AC-3 Diagnostics triage dev-host (timeout/connect/DNS/5xx/401, status/throwable/elapsed/attempt) | TC-06, TC-07, TC-08, TC-09 |
| AC-4 Telemetry never throws into / alters the auth flow | TC-05 |
| AC-5 Logcat suppressed in release; ring + no-op seam still function | TC-12, TC-13 |
| AC-6 Ring buffer caps at 200, oldest-eviction, immutable snapshot | TC-04, TC-08, TC-12 |
| AC-7 No new endpoints, no persisted telemetry, no localized strings | TC-03, TC-13, TC-14 |

---
id: AND-052
title: Auth telemetry/logging (redacted)
milestone: M1
epic: E07
priority: P2
size: M
status: draft
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
- **Auth flow (authoritative):** `POST /ui/session/start` `{challenge_context:{username,password}}` → `{auth_required, challenge_id, required_factors[]}` → `/ui/mfa/{totp|sms|email}/begin|verify` (with `challenge_id`) → `POST /ui/session/finalize` → `GET /ui/me`. Cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`. On 401 the client calls `POST /ui/session/refresh` once then retries.
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

`networkEvent(...)` maps the `(status, throwable)` pair to an `AuthFailureReason` and to the appropriate `AuthEvent` subtype based on the request path: `SocketTimeoutException → TIMEOUT`, `UnknownHostException → DNS_FAILED`, `ConnectException → CONNECT_FAILED`, status 401 → `SESSION_EXPIRED`/`INVALID_CREDENTIALS` (path-dependent), 5xx → `SERVER_5XX`, JSON parse failure surfaced by callers → `MALFORMED_RESPONSE`. The interceptor only records the *transport* signal; semantic failures (e.g. MFA rejected vs malformed) are refined by the ViewModels using the typed `ApiResult`.

**ViewModel integration.** `LoginViewModel` (AND-031) and `MfaViewModel` (AND-040) take an injected `AuthTelemetry` and emit `LoginAttempt`/`LoginSuccess`/`LoginFailure` and the MFA events at the same points where they transition `UiState`. Mapping from the repository's `ApiResult<T>` (and the FastAPI `detail` mapping) to `AuthFailureReason` is done by a shared extension:

```kotlin
fun ApiResult.Failure.toAuthReason(stage: AuthStage): AuthFailureReason
```

No raw `detail` strings are placed in `attrs`; only the derived enum + numeric http status.

## 5. API Contract

This ticket consumes existing auth endpoints but defines **no new server endpoints**. It observes:

- `POST /ui/session/start` → `{ "auth_required": true, "challenge_id": "<redacted>", "required_factors": ["totp","sms"] }` — only `required_factors` (mapped to `AuthFactor`) and a hash of `challenge_id` are logged.
- `POST /ui/mfa/{totp|sms|email}/begin` and `/verify` (body includes `challenge_id` + code) — request bodies are **never** logged; only path, status, factor, `cref` (hashed challenge id).
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

- **Hard denylist** (never logged in any form): `password`, `pwd`, `code`, `otp`, `token`, `csrf`, `cookie`, `set-cookie`, `authorization`. Any attribute whose key matches the denylist is dropped; any value matching secret-shaped regexes (e.g. 6-digit codes `\b\d{6}\b`, JWT-like, long hex/base64) is replaced with `***`.
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

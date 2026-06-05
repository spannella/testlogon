---
id: AND-033
title: MFA API + DTOs
milestone: M1
epic: E05
priority: P0
size: M
status: draft
depends_on: [AND-026, AND-027]
blocks: [AND-034, AND-035, AND-036, AND-037, AND-064]
---

# AND-033 — MFA API + DTOs

## 1. Overview & Goal

This ticket delivers the network-layer surface for multi-factor authentication (MFA): the Retrofit `MfaApi` interface, its associated Moshi DTOs, and the `ApiResult<T>`-returning call wrappers that higher-level feature tickets consume. After the user submits credentials via `POST /ui/session/start` (AND-027), the backend may respond with `auth_required = true` plus a `challenge_id` and a `required_factors` list. The work of stepping through each factor — TOTP verification, SMS/email code begin+verify, and recovery-code redemption — is performed against the `/ui/mfa/**` endpoints. AND-033 is the foundation for all of that: it defines the exact request/response shapes, wires them into the existing `core-network` Retrofit/OkHttp/Moshi stack (cookie jar + CSRF interceptor from AND-010/AND-021), and proves every endpoint is callable and contract-correct under MockWebServer.

The goal is a thin, fully-typed, unit-tested API boundary in `com.testlogon.android.core.network.auth`. This ticket explicitly does **not** implement repository orchestration, factor sequencing logic, or any UI — those belong to AND-034 (TOTP), AND-035 (SMS), AND-036 (email), AND-037 (recovery), and AND-064. AND-033 owns only the `MfaApi` interface, the `Mfa*` DTOs, and their (de)serialization correctness. Success is measured by: every documented MFA endpoint reachable through `MfaApi`; request bodies, paths, verbs, and headers matching the FastAPI contract; and Moshi round-tripping the captured JSON samples exactly.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, branch `android-port`, Android app under `android/`. Code lands in `:core-network` (`android/core-network/src/main/kotlin/com/testlogon/android/core/network/auth/`).
- **Stack:** Kotlin 2.0.21, Retrofit 2.11, OkHttp 4.12, Moshi 1.15 (codegen via KSP), Coroutines/Flow, Hilt. minSdk 24, compileSdk/targetSdk 35, JDK 17.
- **Upstream dependencies:**
  - **AND-026** — Auth DTOs + adapters. Provides shared types (`SessionStartResp`, `RequiredFactor`, `SessionInfo`, error envelope adapters, and the `Mfa*` DTO families per Appendix A). AND-033 reuses these where they exist and adds MFA-specific request/response DTOs not already created.
  - **AND-027** — `AuthApi` (session endpoints). Establishes the Retrofit interface pattern, the `ApiResult<T>` call-wrapper convention, and the MockWebServer test harness reused here.
- **Cross-cutting infra (already built):** persistent cookie jar (`PersistentCookieJar`), `CsrfInterceptor` that echoes the `ui_csrf` cookie as `X-CSRF-Token`, `~20s` OkHttp timeouts, and the single-`401`→`POST /ui/session/refresh`→retry `Authenticator`.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext, unreliable). Contract source of truth: `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts`.
- **Downstream consumers (blocked by this ticket):** AND-034, AND-035, AND-036, AND-037, AND-064.

## 3. Functional Requirements

FR-1. Provide a Retrofit interface `MfaApi` exposing one suspend function per MFA endpoint, each returning a typed `ApiResult<T>` (via the AND-027 wrapper pattern).

FR-2. Cover all factor operations named in scope:
- TOTP: `verifyTotp` → `POST /ui/mfa/totp/verify`.
- SMS: `beginSms` → `POST /ui/mfa/sms/begin`; `verifySms` → `POST /ui/mfa/sms/verify`.
- Email: `beginEmail` → `POST /ui/mfa/email/begin`; `verifyEmail` → `POST /ui/mfa/email/verify`.
- Recovery: `useRecovery` → `POST /ui/mfa/recovery/{factor}` (path-templated factor selector).

FR-3. Every request carries the active `challenge_id` (from `SessionStartResp`) in its JSON body. No factor call is valid without it.

FR-4. All calls automatically include cookies and the `X-CSRF-Token` header via the existing OkHttp interceptor chain; `MfaApi` declares no manual header parameters for these.

FR-5. Provide Moshi `@JsonClass(generateAdapter = true)` DTOs for every request and response, with `@Json(name = ...)` annotations mapping snake_case wire fields to Kotlin camelCase properties.

FR-6. `begin` responses surface a masked destination (`sent_to`, e.g. `+1•••••1234` / `j•••@example.com`) plus a cooldown hint for resend. `verify` responses surface the post-verification state: remaining factors and whether the challenge is now satisfied.

FR-7. DTOs and the interface must (de)serialize the captured JSON samples byte-for-shape, validated by unit tests. Unknown JSON keys must not crash deserialization (forward-compat tolerance).

FR-8. Expose an enum/sealed type for the recovery `{factor}` path segment so callers cannot pass arbitrary strings.

## 4. Technical Design

All code lives in `com.testlogon.android.core.network.auth`. DTOs go in a `dto/` sub-package; the interface and call wrappers at package root.

```kotlin
package com.testlogon.android.core.network.auth

import com.testlogon.android.core.network.ApiResult
import com.testlogon.android.core.network.auth.dto.*
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.POST
import retrofit2.http.Path

/** Retrofit interface for /ui/mfa/** factor challenge endpoints. */
interface MfaApi {

    @POST("ui/mfa/totp/verify")
    suspend fun verifyTotp(@Body body: MfaVerifyReq): Response<MfaVerifyResp>

    @POST("ui/mfa/sms/begin")
    suspend fun beginSms(@Body body: MfaBeginReq): Response<MfaBeginResp>

    @POST("ui/mfa/sms/verify")
    suspend fun verifySms(@Body body: MfaVerifyReq): Response<MfaVerifyResp>

    @POST("ui/mfa/email/begin")
    suspend fun beginEmail(@Body body: MfaBeginReq): Response<MfaBeginResp>

    @POST("ui/mfa/email/verify")
    suspend fun verifyEmail(@Body body: MfaVerifyReq): Response<MfaVerifyResp>

    @POST("ui/mfa/recovery/{factor}")
    suspend fun useRecovery(
        @Path("factor") factor: String,
        @Body body: MfaVerifyReq,
    ): Response<MfaVerifyResp>
}
```

Functions return raw `Response<T>` so the shared `safeApiCall { }` wrapper (AND-027) can map HTTP status, FastAPI `detail`, and IO failures into `ApiResult<T>`. A thin client `MfaApiClient` provides the typed, `ApiResult`-returning façade consumed downstream:

```kotlin
package com.testlogon.android.core.network.auth

import javax.inject.Inject
import javax.inject.Singleton

enum class RecoveryFactor(val wire: String) { TOTP("totp"), SMS("sms"), EMAIL("email") }

@Singleton
class MfaApiClient @Inject constructor(
    private val api: MfaApi,
    private val errorMapper: ApiErrorMapper, // from AND-026/027
) {
    suspend fun verifyTotp(challengeId: String, code: String): ApiResult<MfaVerifyResp> =
        safeApiCall(errorMapper) { api.verifyTotp(MfaVerifyReq(challengeId, code)) }

    suspend fun beginSms(challengeId: String): ApiResult<MfaBeginResp> =
        safeApiCall(errorMapper) { api.beginSms(MfaBeginReq(challengeId)) }

    suspend fun verifySms(challengeId: String, code: String): ApiResult<MfaVerifyResp> =
        safeApiCall(errorMapper) { api.verifySms(MfaVerifyReq(challengeId, code)) }

    suspend fun beginEmail(challengeId: String): ApiResult<MfaBeginResp> =
        safeApiCall(errorMapper) { api.beginEmail(MfaBeginReq(challengeId)) }

    suspend fun verifyEmail(challengeId: String, code: String): ApiResult<MfaVerifyResp> =
        safeApiCall(errorMapper) { api.verifyEmail(MfaVerifyReq(challengeId, code)) }

    suspend fun useRecovery(factor: RecoveryFactor, challengeId: String, code: String): ApiResult<MfaVerifyResp> =
        safeApiCall(errorMapper) { api.useRecovery(factor.wire, MfaVerifyReq(challengeId, code)) }
}
```

Hilt wiring extends the existing auth network module:

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object MfaNetworkModule {
    @Provides @Singleton
    fun provideMfaApi(retrofit: Retrofit): MfaApi = retrofit.create(MfaApi::class.java)
}
```

The `Retrofit` instance, base URL (`http://18.222.237.167:8000/`), Moshi converter, cookie jar, CSRF interceptor, `Authenticator`, and timeouts are all provided by the shared `core-network` `NetworkModule` (AND-010/AND-021); this ticket adds no new OkHttp configuration.

## 5. API Contract

Base URL `http://18.222.237.167:8000/`. All endpoints are `POST`, `Content-Type: application/json`, require the session + `ui_csrf` cookies and the `X-CSRF-Token` header (supplied automatically). The `{factor}` path values are `totp` | `sms` | `email`.

**Begin (SMS / email)** — `POST /ui/mfa/{sms|email}/begin`
Request:
```json
{ "challenge_id": "chl_7af3c2e1" }
```
Response `200`:
```json
{ "sent_to": "+1•••••1234", "expires_in": 300, "resend_available_in": 30, "challenge_id": "chl_7af3c2e1" }
```

**Verify (TOTP / SMS / email)** — `POST /ui/mfa/{totp|sms|email}/verify`
Request:
```json
{ "challenge_id": "chl_7af3c2e1", "code": "482915" }
```
Response `200` (factor accepted, more factors pending):
```json
{ "verified": true, "challenge_id": "chl_7af3c2e1", "remaining_factors": ["sms"], "auth_complete": false }
```
Response `200` (last factor; ready for finalize):
```json
{ "verified": true, "challenge_id": "chl_7af3c2e1", "remaining_factors": [], "auth_complete": true }
```

**Recovery** — `POST /ui/mfa/recovery/{factor}`
Request:
```json
{ "challenge_id": "chl_7af3c2e1", "code": "ab12-cd34-ef56" }
```
Response: same shape as verify (`MfaVerifyResp`).

**Error responses** map the FastAPI `detail` polymorph (string | `[{msg}]` | `{code,...}`), handled by `ApiErrorMapper`:
- `400` invalid/expired code → `{ "detail": { "code": "mfa_invalid_code", "attempts_remaining": 2 } }`
- `422` validation → `{ "detail": [{ "loc": ["body","code"], "msg": "field required", "type": "value_error.missing" }] }`
- `401` session expired → triggers the single refresh-and-retry `Authenticator`.
- `429` resend throttled → `{ "detail": { "code": "mfa_resend_throttled", "retry_after": 22 } }`

Owner of the contract for finalize (`POST /ui/session/finalize`) is AND-027, not this ticket.

## 6. Data & State Management

This is a stateless API/DTO ticket: no Room tables, no DataStore keys, no `StateFlow`/`UiState` are introduced here (those are owned by AND-034/035/036/037). The only persisted state touched is the OkHttp cookie jar and `ui_csrf` cookie, owned by AND-010/AND-021 and merely relied upon.

DTOs (`dto/MfaDtos.kt`), all Moshi-generated:

```kotlin
@JsonClass(generateAdapter = true)
data class MfaBeginReq(@Json(name = "challenge_id") val challengeId: String)

@JsonClass(generateAdapter = true)
data class MfaBeginResp(
    @Json(name = "sent_to") val sentTo: String,
    @Json(name = "expires_in") val expiresIn: Int,
    @Json(name = "resend_available_in") val resendAvailableIn: Int = 0,
    @Json(name = "challenge_id") val challengeId: String,
)

@JsonClass(generateAdapter = true)
data class MfaVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "code") val code: String,
)

@JsonClass(generateAdapter = true)
data class MfaVerifyResp(
    @Json(name = "verified") val verified: Boolean,
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "remaining_factors") val remainingFactors: List<String> = emptyList(),
    @Json(name = "auth_complete") val authComplete: Boolean,
)
```

Notes: nullable/defaulted fields (`resendAvailableIn`, `remainingFactors`) tolerate absent keys. `remaining_factors` strings should align with the `RequiredFactor` codes defined in AND-026; mapping the raw strings to a typed enum is deferred to AND-026/the repository layer to avoid hard-failing on a server-introduced factor. The recovery `{factor}` is constrained at the client boundary by the `RecoveryFactor` enum.

## 7. Error Handling & Resilience

- **Wrapper:** every `MfaApiClient` call funnels through `safeApiCall`, producing `ApiResult.Success`, `ApiResult.HttpError(status, ApiError)`, or `ApiResult.NetworkError(throwable)`. No exceptions escape to callers.
- **FastAPI `detail` mapping:** `ApiErrorMapper` (AND-026) normalizes the three `detail` shapes into a single `ApiError(code, message, fieldErrors, retryAfter, attemptsRemaining)`. MFA-specific codes (`mfa_invalid_code`, `mfa_resend_throttled`, `mfa_challenge_expired`) are surfaced as-is for downstream UI.
- **401 refresh:** handled by the shared `Authenticator` — one `POST /ui/session/refresh` then a single retry. If refresh fails, the original `401` propagates as an `HttpError`. No MFA-specific 401 logic here.
- **Retries / idempotency:** `begin` and all `verify`/`recovery` calls are **non-idempotent** state-mutating `POST`s — they MUST NOT participate in the GET backoff-retry policy. `MfaApiClient` issues exactly one network attempt per call.
- **Timeouts:** inherited ~20s connect/read/write from the shared OkHttp client; surface as `NetworkError`.
- **Throttling:** `429` with `retry_after` is mapped but not auto-retried; the resend cooldown is a UI concern (AND-035/036).

## 8. Security & Privacy

- MFA codes (TOTP/SMS/email OTP, recovery codes) are secrets: never log request bodies. The OkHttp `HttpLoggingInterceptor` for these paths must be capped at `Level.BASIC` (method + URL + status) or use a redacting interceptor; `Level.BODY` is prohibited for `/ui/mfa/**` in all build types.
- `challenge_id` is sensitive session material — redact in any telemetry (Section 10).
- The dev backend is plaintext HTTP, so codes traverse the wire unencrypted **in dev only**. Production must enforce HTTPS; document this constraint and ensure release builds reject cleartext (`usesCleartextTraffic=false` outside the dev flavor / network-security-config). This is flagged here but the build-config enforcement is owned by the manifest/build tickets.
- DTOs hold codes transiently; no persistence of codes to Room/DataStore. The cookie jar persists session cookies, not codes.
- CSRF protection is mandatory — the `X-CSRF-Token` header derived from the `ui_csrf` cookie must be present on every MFA `POST` (verified in tests, Section 11).

## 9. Accessibility & i18n

N/A for this layer — no UI is produced. Accessibility (TalkBack labels, code-entry fields, error announcements) and user-facing string localization are owned by the factor-flow UI tickets AND-034, AND-035, AND-036, AND-037. One i18n-adjacent constraint applies: masked destinations (`sent_to`) and error `message` strings are server-provided and must be passed through verbatim to the UI layer without client-side reformatting, so localization/masking remains a server + UI concern.

## 10. Telemetry & Logging

- Emit structured analytics events at the client boundary via the shared analytics façade (no PII, no codes): `mfa_factor_begin { factor }`, `mfa_factor_verify_attempt { factor }`, `mfa_factor_verify_result { factor, verified, auth_complete }`, `mfa_factor_error { factor, code }`. `challenge_id` and any `sent_to`/`code` value MUST be excluded or hashed.
- Logging: BASIC-level OkHttp logging only for `/ui/mfa/**` (see Section 8). On error, log the mapped `ApiError.code` (a non-secret enum) and HTTP status, never the body.
- These events feed the auth-funnel dashboards owned by the telemetry ticket; AND-033 only emits them.

## 11. Testing Strategy

All tests are JVM unit tests in `core-network` using MockWebServer + Moshi, reusing the AND-027 harness. `core-testing` provides JSON fixtures.

1. **DTO (de)serialization (FR-7):** for each DTO, parse a captured fixture (`testlogon/.../fixtures/mfa/*.json`) and assert field-by-field; re-serialize a constructed instance and assert the emitted JSON object matches the wire shape (snake_case keys). Include the "unknown key" fixture to prove forward-compat tolerance.
2. **Path/verb/body correctness (Acceptance):** enqueue a `200` MockWebServer response, invoke each `MfaApi`/`MfaApiClient` method, then assert `RecordedRequest.path` (e.g. `/ui/mfa/sms/begin`), `method == POST`, and the request body JSON contains exactly the expected keys/values (`challenge_id`, `code`).
3. **Recovery path templating:** assert `useRecovery(RecoveryFactor.SMS, …)` hits `/ui/mfa/recovery/sms`.
4. **CSRF/cookie propagation:** with the CSRF interceptor installed, assert `RecordedRequest` carries the `X-CSRF-Token` header and `Cookie`.
5. **Error mapping:** enqueue `400`/`422`/`429` bodies and assert `safeApiCall` yields `ApiResult.HttpError` with the correct `ApiError.code`, `attemptsRemaining`, and `retryAfter`.
6. **No-retry guarantee:** enqueue a `429` then a `200`; assert exactly one request is recorded (POSTs are not retried).
7. **Coverage:** ≥90% line coverage on `MfaApi`, `MfaApiClient`, and the `dto/` package.

## 12. Dependencies & Sequencing

- **Blocked by:** AND-026 (shared `Mfa*`/error DTOs + `ApiErrorMapper`) and AND-027 (`safeApiCall`/`ApiResult`, Retrofit + MockWebServer harness). Both must merge first; AND-033 reuses, not duplicates, their types.
- **Blocks:** AND-034 (TOTP flow), AND-035 (SMS flow), AND-036 (email flow), AND-037 (recovery flow), and AND-064. These consume `MfaApiClient` exclusively and must not call Retrofit directly.
- **Sequencing:** AND-010/AND-021 (network module, cookie jar, CSRF interceptor) are assumed merged. Recommended order: AND-026 → AND-027 → **AND-033** → AND-034/035/036/037 in parallel.
- **No external/3rd-party additions** — all libraries (Retrofit, Moshi, OkHttp, Hilt) are already on the classpath.

## 13. Risks & Open Questions

- **R1 — Exact wire shapes:** the JSON above is reconstructed from the web reference and contract description. Before merge, capture live samples from `/openapi.json` and the running dev host to confirm field names (`sent_to` vs `destination`, `auth_complete` vs `complete`, `remaining_factors` ordering). Adjust `@Json(name=...)` accordingly.
- **R2 — Recovery body shape:** open question whether recovery uses `{code}` or a dedicated `{recovery_code}` field, and whether `{factor}` is a path segment vs a body field. Confirm against `frontend/src/api/endpoints`. Current design assumes path segment + `code`.
- **R3 — Factor enum drift:** server may add factors (e.g., `webauthn`). Keeping `remaining_factors` as `List<String>` (not enum) at this layer mitigates hard-fail; typed mapping is deferred to AND-026.
- **R4 — Resend metadata:** `resend_available_in`/`retry_after` presence is not guaranteed across factors; defaulted to `0` to avoid deserialization failure — verify with fixtures.
- **R5 — Dev host instability:** flaky `5xx`/timeouts during contract validation; rely on MockWebServer for deterministic CI and treat live calls as smoke-only.

## 14. Acceptance Criteria

AC-1. `MfaApi` exposes callable methods for `totp/verify`, `sms/begin`, `sms/verify`, `email/begin`, `email/verify`, and `recovery/{factor}`, each returning a typed response and routed through `ApiResult<T>` via `MfaApiClient`. (Maps to source AC: "All MFA endpoints callable and contract-correct (tested).")

AC-2. Under MockWebServer, every endpoint's path, `POST` verb, and JSON request body (keys `challenge_id`, `code`) match the contract; recovery resolves `{factor}` to `totp|sms|email`.

AC-3. All `Mfa*` DTOs (de)serialize the captured JSON fixtures exactly (snake_case ↔ camelCase), tolerate unknown keys, and round-trip without loss.

AC-4. `X-CSRF-Token` header and session cookies are present on every MFA request (asserted via `RecordedRequest`).

AC-5. `400`/`422`/`429` responses map to `ApiResult.HttpError` with correct `ApiError.code`/`attemptsRemaining`/`retryAfter`; non-idempotent POSTs are never auto-retried.

AC-6. No MFA code or `challenge_id` appears in logs or analytics payloads; OkHttp body logging is disabled for `/ui/mfa/**`.

## 15. Definition of Done

- `MfaApi`, `MfaApiClient`, `RecoveryFactor`, and `dto/MfaDtos.kt` implemented under `com.testlogon.android.core.network.auth` and provided via `MfaNetworkModule` (Hilt).
- Live wire shapes verified against `/openapi.json` (R1/R2 resolved); `@Json` names finalized.
- Unit tests (Section 11) pass with ≥90% coverage on the new code; CI green.
- Redaction/logging constraints (Section 8/10) implemented and asserted by test.
- No new dependencies introduced; module layering (`core-network` only) preserved — no `feature-*`/UI code added.
- Code reviewed and merged to `android-port`; downstream tickets AND-034/035/036/037/064 can compile against `MfaApiClient` with no further network changes.
- KDoc on `MfaApi` and `MfaApiClient` documenting each endpoint and the no-retry/secret-handling contract.

---
id: AND-033
title: MFA API + DTOs
milestone: M1
epic: E05
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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

FR-6. `begin` responses (`ChallengeResp`) surface `challenge_id` plus an OPTIONAL masked destination list `sent_to` (an array of strings — CORRECTED from a single string; e.g. `["+1•••••1234"]`). There is **no** `expires_in` or `resend_available_in` field in the documented contract (see §16). `verify`/`recovery` responses (`MfaVerifyResp`) surface the post-verification state: `status`, optional `session_id`, `required_factors`, a `passed` map (factor → bool), and `remaining_factors`. The challenge is satisfied when `remaining_factors` is empty (there is **no** `auth_complete`/`verified` boolean — CORRECTED).

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

/**
 * Retrofit interface for /ui/mfa/** factor challenge endpoints.
 *
 * CORRECTION (review 2026-06-06): the backend does NOT use a single unified
 * MfaVerifyReq/MfaBeginReq. Each factor has its own request schema and the
 * verify code field name differs per factor:
 *   - TOTP verify  → TotpVerifyReq  { challenge_id, totp_code }
 *   - SMS  begin   → SmsBeginReq    { challenge_id }
 *   - SMS  verify  → SmsVerifyReq   { challenge_id, code }
 *   - Email begin  → EmailBeginReq  { challenge_id }
 *   - Email verify → EmailVerifyReq { challenge_id, code }
 *   - Recovery     → RecoveryReq    { challenge_id, recovery_code, factor? }
 * begin endpoints return ChallengeResp (NOT MfaBeginResp); all verify/recovery
 * endpoints return MfaVerifyResp. See §5 and §16 for the verified field shapes.
 */
interface MfaApi {

    @POST("ui/mfa/totp/verify")
    suspend fun verifyTotp(@Body body: TotpVerifyReq): Response<MfaVerifyResp>

    @POST("ui/mfa/sms/begin")
    suspend fun beginSms(@Body body: SmsBeginReq): Response<ChallengeResp>

    @POST("ui/mfa/sms/verify")
    suspend fun verifySms(@Body body: SmsVerifyReq): Response<MfaVerifyResp>

    @POST("ui/mfa/email/begin")
    suspend fun beginEmail(@Body body: EmailBeginReq): Response<ChallengeResp>

    @POST("ui/mfa/email/verify")
    suspend fun verifyEmail(@Body body: EmailVerifyReq): Response<MfaVerifyResp>

    @POST("ui/mfa/recovery/{factor}")
    suspend fun useRecovery(
        @Path("factor") factor: String,
        @Body body: RecoveryReq,
    ): Response<MfaVerifyResp>
}
```

Functions return raw `Response<T>` so the shared `safeApiCall { }` wrapper (AND-027) can map HTTP status, FastAPI `detail`, and IO failures into `ApiResult<T>`. A thin client `MfaApiClient` provides the typed, `ApiResult`-returning façade consumed downstream:

```kotlin
package com.testlogon.android.core.network.auth

import javax.inject.Inject
import javax.inject.Singleton

// CORRECTION (review 2026-06-06): the recovery {factor} path segment mirrors the
// web client's active MFA method, which is one of totp|sms|email|recovery
// (Login.tsx line 41 + useRecoveryCode(activeMfa, …)). The enum therefore
// includes RECOVERY as well. The recovery request body also carries an OPTIONAL
// `factor` field (server default "totp"); the web client omits it, so the client
// below also omits it and relies on the path segment.
enum class RecoveryFactor(val wire: String) {
    TOTP("totp"), SMS("sms"), EMAIL("email"), RECOVERY("recovery")
}

@Singleton
class MfaApiClient @Inject constructor(
    private val api: MfaApi,
    private val errorMapper: ApiErrorMapper, // from AND-026/027
) {
    suspend fun verifyTotp(challengeId: String, totpCode: String): ApiResult<MfaVerifyResp> =
        safeApiCall(errorMapper) { api.verifyTotp(TotpVerifyReq(challengeId, totpCode)) }

    suspend fun beginSms(challengeId: String): ApiResult<ChallengeResp> =
        safeApiCall(errorMapper) { api.beginSms(SmsBeginReq(challengeId)) }

    suspend fun verifySms(challengeId: String, code: String): ApiResult<MfaVerifyResp> =
        safeApiCall(errorMapper) { api.verifySms(SmsVerifyReq(challengeId, code)) }

    suspend fun beginEmail(challengeId: String): ApiResult<ChallengeResp> =
        safeApiCall(errorMapper) { api.beginEmail(EmailBeginReq(challengeId)) }

    suspend fun verifyEmail(challengeId: String, code: String): ApiResult<MfaVerifyResp> =
        safeApiCall(errorMapper) { api.verifyEmail(EmailVerifyReq(challengeId, code)) }

    suspend fun useRecovery(factor: RecoveryFactor, challengeId: String, recoveryCode: String): ApiResult<MfaVerifyResp> =
        safeApiCall(errorMapper) { api.useRecovery(factor.wire, RecoveryReq(challengeId, recoveryCode)) }
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

Base URL `http://18.222.237.167:8000/`. All endpoints are `POST`, `Content-Type: application/json`, require the session + `ui_csrf` cookies and the `X-CSRF-Token` header (supplied automatically). The `{factor}` path values used by the web client are `totp` | `sms` | `email` | `recovery` (Login.tsx passes the active MFA method; CORRECTED — `recovery` is a valid path value).

> Review note (2026-06-06): the JSON below is now reconciled with the OpenAPI schemas and `frontend/src/api/types.ts`. The original draft used a unified `code` field and `MfaBeginResp`/`auth_complete`/`verified` fields that do **not** exist in the contract. See §16 for the exact source pointers. The OpenAPI documents only `200` (untyped body) and `422` (`HTTPValidationError`) for these paths; the verify/begin response shapes below come from the frontend DTOs.

**Begin (SMS / email)** — `POST /ui/mfa/{sms|email}/begin`
Request (`SmsBeginReq` / `EmailBeginReq`):
```json
{ "challenge_id": "chl_7af3c2e1" }
```
Response `200` (`ChallengeResp`):
```json
{ "challenge_id": "chl_7af3c2e1", "sent_to": ["+1•••••1234"] }
```
`sent_to` is an OPTIONAL **array** of masked destination strings. There is no `expires_in`/`resend_available_in` in the contract.

**Verify — TOTP** — `POST /ui/mfa/totp/verify`
Request (`TotpVerifyReq`, note `totp_code`, NOT `code`):
```json
{ "challenge_id": "chl_7af3c2e1", "totp_code": "482915" }
```

**Verify — SMS / email** — `POST /ui/mfa/{sms|email}/verify`
Request (`SmsVerifyReq` / `EmailVerifyReq`):
```json
{ "challenge_id": "chl_7af3c2e1", "code": "482915" }
```

**Verify response `200` (`MfaVerifyResp`)** — same shape for TOTP/SMS/email/recovery:
```json
{
  "status": "mfa_required",
  "session_id": null,
  "required_factors": ["totp", "sms"],
  "passed": { "totp": true, "sms": false },
  "remaining_factors": ["sms"]
}
```
When the last factor passes, `remaining_factors` is `[]`; the client then calls `POST /ui/session/finalize` (owned by AND-027) to obtain the session. There is **no** `verified` or `auth_complete` field — completion is `remaining_factors.length == 0`.

**Recovery** — `POST /ui/mfa/recovery/{factor}`
Request (`RecoveryReq`, note `recovery_code`, NOT `code`; `factor` is an optional body field, server default `"totp"`, omitted by the web client):
```json
{ "challenge_id": "chl_7af3c2e1", "recovery_code": "ab12-cd34-ef56" }
```
Response: same shape as verify (`MfaVerifyResp`).

**Error responses:**
- `422` validation (VERIFIED — `HTTPValidationError`): `detail` is an **array** of `ValidationError { loc, msg, type }`:
  ```json
  { "detail": [{ "loc": ["body", "totp_code"], "msg": "Field required", "type": "missing" }] }
  ```
- `400`/`429` custom MFA error envelopes (`{ "detail": { "code": "mfa_invalid_code", "attempts_remaining": 2 } }`, `{ "detail": { "code": "mfa_resend_throttled", "retry_after": 22 } }`) are **UNVERIFIED ASSUMPTIONS** — the OpenAPI only documents `200`/`422` for these paths. `ApiErrorMapper` (AND-026) handles the polymorphic `detail` (string | array | object) defensively, but the exact `400`/`429` codes/fields must be confirmed against the running backend before relying on them (see §16, Open assumptions).
- `401` session expired → assumed to trigger the single refresh-and-retry `Authenticator` (AND-021). `/ui/session/refresh` (POST, no body) is VERIFIED to exist; the `401`-on-MFA behavior itself is not documented in the contract and is an infra assumption.

Owner of the contract for finalize (`POST /ui/session/finalize`, VERIFIED to exist) is AND-027, not this ticket.

## 6. Data & State Management

This is a stateless API/DTO ticket: no Room tables, no DataStore keys, no `StateFlow`/`UiState` are introduced here (those are owned by AND-034/035/036/037). The only persisted state touched is the OkHttp cookie jar and `ui_csrf` cookie, owned by AND-010/AND-021 and merely relied upon.

DTOs (`dto/MfaDtos.kt`), all Moshi-generated:

CORRECTED DTOs (review 2026-06-06) — per-factor request types, with the verify
code field differing by factor, and the verified response shapes:

```kotlin
// ── Begin requests (SMS / email) ──
@JsonClass(generateAdapter = true)
data class SmsBeginReq(@Json(name = "challenge_id") val challengeId: String)

@JsonClass(generateAdapter = true)
data class EmailBeginReq(@Json(name = "challenge_id") val challengeId: String)

// ── Begin response (shared) ──
// sent_to is an OPTIONAL ARRAY of masked-destination strings; no expires_in / resend_available_in.
@JsonClass(generateAdapter = true)
data class ChallengeResp(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "sent_to") val sentTo: List<String>? = null,
)

// ── Verify requests (note the per-factor code field name) ──
@JsonClass(generateAdapter = true)
data class TotpVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "totp_code") val totpCode: String,   // NOT "code"
)

@JsonClass(generateAdapter = true)
data class SmsVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "code") val code: String,
)

@JsonClass(generateAdapter = true)
data class EmailVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "code") val code: String,
)

// ── Recovery request ──
// recovery_code (NOT "code"); factor is an optional body field (server default "totp"),
// omitted here to match the web client which relies on the {factor} path segment.
@JsonClass(generateAdapter = true)
data class RecoveryReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "recovery_code") val recoveryCode: String,
    @Json(name = "factor") val factor: String? = null,
)

// ── Verify / recovery response (shared) ──
@JsonClass(generateAdapter = true)
data class MfaVerifyResp(
    @Json(name = "status") val status: String,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
    @Json(name = "passed") val passed: Map<String, Boolean> = emptyMap(),
    @Json(name = "remaining_factors") val remainingFactors: List<String> = emptyList(),
)
```

Notes: nullable/defaulted fields (`sentTo`, `sessionId`, `passed`, `remainingFactors`) tolerate absent keys. `required_factors`/`remaining_factors` strings should align with the `RequiredFactor` codes defined in AND-026; mapping the raw strings to a typed enum is deferred to AND-026/the repository layer to avoid hard-failing on a server-introduced factor. The recovery `{factor}` is constrained at the client boundary by the `RecoveryFactor` enum (`totp|sms|email|recovery`). Auth completion is derived from `remainingFactors.isEmpty()` (there is no `auth_complete` boolean).

## 7. Error Handling & Resilience

- **Wrapper:** every `MfaApiClient` call funnels through `safeApiCall`, producing `ApiResult.Success`, `ApiResult.HttpError(status, ApiError)`, or `ApiResult.NetworkError(throwable)`. No exceptions escape to callers.
- **FastAPI `detail` mapping:** `ApiErrorMapper` (AND-026) normalizes the polymorphic `detail` (string | array-of-`ValidationError` | object) into a single `ApiError(code, message, fieldErrors, retryAfter, attemptsRemaining)`. The array shape is VERIFIED (`HTTPValidationError` → `ValidationError{loc,msg,type}`). MFA-specific object codes (`mfa_invalid_code`, `mfa_resend_throttled`, `mfa_challenge_expired`) are **assumed** (the contract documents only 200/422 for these paths — see §16) and surfaced as-is for downstream UI when present; the mapper must not crash if they are absent or differently shaped.
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

- Emit structured analytics events at the client boundary via the shared analytics façade (no PII, no codes): `mfa_factor_begin { factor }`, `mfa_factor_verify_attempt { factor }`, `mfa_factor_verify_result { factor, status, remaining_count }` (derived from `MfaVerifyResp.status` and `remaining_factors.size`; CORRECTED — there is no `verified`/`auth_complete` field), `mfa_factor_error { factor, code }`. `challenge_id` and any `sent_to`/`code` value MUST be excluded or hashed.
- Logging: BASIC-level OkHttp logging only for `/ui/mfa/**` (see Section 8). On error, log the mapped `ApiError.code` (a non-secret enum) and HTTP status, never the body.
- These events feed the auth-funnel dashboards owned by the telemetry ticket; AND-033 only emits them.

## 11. Testing Strategy

All tests are JVM unit tests in `core-network` using MockWebServer + Moshi, reusing the AND-027 harness. `core-testing` provides JSON fixtures.

1. **DTO (de)serialization (FR-7):** for each DTO, parse a captured fixture (`testlogon/.../fixtures/mfa/*.json`) and assert field-by-field; re-serialize a constructed instance and assert the emitted JSON object matches the wire shape (snake_case keys). Include the "unknown key" fixture to prove forward-compat tolerance.
2. **Path/verb/body correctness (Acceptance):** enqueue a `200` MockWebServer response, invoke each `MfaApi`/`MfaApiClient` method, then assert `RecordedRequest.path` (e.g. `/ui/mfa/sms/begin`), `method == POST`, and the request body JSON contains exactly the expected keys/values — note the per-factor code field: `totp_code` for TOTP, `code` for SMS/email, `recovery_code` for recovery (plus `challenge_id` everywhere).
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

- **R1 — Exact wire shapes (RESOLVED in review 2026-06-06):** field names are now reconciled with the OpenAPI schemas and `frontend/src/api/types.ts`. Confirmed: per-factor verify code fields (`totp_code`/`code`), begin response is `ChallengeResp{challenge_id, sent_to?: string[]}` (no `expires_in`/`resend_available_in`), verify response is `MfaVerifyResp{status, session_id?, required_factors, passed, remaining_factors}` (no `verified`/`auth_complete`). Remaining live-host smoke check is only to confirm runtime values, not field names.
- **R2 — Recovery body shape (RESOLVED in review 2026-06-06):** recovery uses `recovery_code` (not `code`), `{factor}` is a path segment, and `factor` is ALSO an optional body field (server default `"totp"`) which the web client omits. Design updated accordingly.
- **R3 — Factor enum drift:** server may add factors (e.g., `webauthn`). Keeping `remaining_factors` as `List<String>` (not enum) at this layer mitigates hard-fail; typed mapping is deferred to AND-026.
- **R4 — Resend / throttle metadata (UPDATED):** `expires_in`/`resend_available_in` are NOT in the documented `ChallengeResp` (removed from the DTOs). Any `retry_after` on a `429` lives in the (unverified) error envelope, not the success body. If resend-cooldown UI (AND-035/036) needs server-driven timing, the contract must be extended; for now treat cooldown as a client-side UI concern.
- **R5 — Dev host instability:** flaky `5xx`/timeouts during contract validation; rely on MockWebServer for deterministic CI and treat live calls as smoke-only.

## 14. Acceptance Criteria

AC-1. `MfaApi` exposes callable methods for `totp/verify`, `sms/begin`, `sms/verify`, `email/begin`, `email/verify`, and `recovery/{factor}`, each returning a typed response and routed through `ApiResult<T>` via `MfaApiClient`. (Maps to source AC: "All MFA endpoints callable and contract-correct (tested).")

AC-2. Under MockWebServer, every endpoint's path, `POST` verb, and JSON request body match the contract — with the correct per-factor code field (`totp_code` for TOTP, `code` for SMS/email, `recovery_code` for recovery; `challenge_id` on all); recovery resolves `{factor}` to `totp|sms|email|recovery`.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **`POST /ui/mfa/totp/verify` exists and is POST.** VERIFIED. OpenAPI `POST /ui/mfa/totp/verify` (op `ui_totp_verify_ui_mfa_totp_verify_post`, req `TotpVerifyReq`); frontend `src/api/endpoints/auth.ts: verifyTotp`.
2. **`POST /ui/mfa/sms/begin` and `/sms/verify` exist and are POST.** VERIFIED. OpenAPI `POST /ui/mfa/sms/begin` (req `SmsBeginReq`), `POST /ui/mfa/sms/verify` (req `SmsVerifyReq`); frontend `src/api/endpoints/auth.ts: beginSms, verifySms`.
3. **`POST /ui/mfa/email/begin` and `/email/verify` exist and are POST.** VERIFIED. OpenAPI `POST /ui/mfa/email/begin` (req `EmailBeginReq`), `POST /ui/mfa/email/verify` (req `EmailVerifyReq`); frontend `src/api/endpoints/auth.ts: beginEmail, verifyEmail`.
4. **`POST /ui/mfa/recovery/{factor}` exists with `factor` as a path param.** VERIFIED. OpenAPI `POST /ui/mfa/recovery/{factor}` (op `ui_recovery_factor_…`, req `RecoveryReq`, `params=factor`); frontend `src/api/endpoints/auth.ts: useRecoveryCode(factor, body)`.
5. **TOTP verify request field is `totp_code` (NOT `code`).** CORRECTED. OpenAPI `components.schemas.TotpVerifyReq` = `{challenge_id, totp_code}` (both required); frontend `src/api/types.ts: TotpVerifyReq`.
6. **SMS/email verify request field is `code`.** VERIFIED. OpenAPI `SmsVerifyReq` / `EmailVerifyReq` = `{challenge_id, code}`; `src/api/types.ts: SmsVerifyReq, EmailVerifyReq`.
7. **SMS/email begin request is `{challenge_id}` only.** VERIFIED. OpenAPI `SmsBeginReq` / `EmailBeginReq`; `src/api/types.ts: SmsBeginReq, EmailBeginReq`.
8. **Recovery request field is `recovery_code` (NOT `code`) plus optional `factor` body field (default `"totp"`).** CORRECTED. OpenAPI `components.schemas.RecoveryReq` = `{challenge_id (req), recovery_code (req), factor (default "totp")}`; `src/api/types.ts: RecoveryReq { challenge_id, recovery_code, factor? }`. Web client omits `factor` in body (`src/pages/Login.tsx: useRecoveryCode(activeMfa, {challenge_id, recovery_code})`).
9. **Begin response is `ChallengeResp {challenge_id, sent_to?: string[]}` (NOT a `MfaBeginResp` with `expires_in`/`resend_available_in`, and `sent_to` is an ARRAY not a string).** CORRECTED. Frontend `src/api/endpoints/auth.ts: beginSms/beginEmail → api.post<ChallengeResp>`; `src/api/types.ts: ChallengeResp { challenge_id, sent_to?: string[] }`. (OpenAPI index lists `resp=200:` untyped for these paths, so the frontend DTO is the source of truth.)
10. **Verify/recovery response is `MfaVerifyResp {status, session_id?, required_factors, passed, remaining_factors}` (NOT `{verified, challenge_id, remaining_factors, auth_complete}`).** CORRECTED. Frontend `src/api/endpoints/auth.ts: verify* / useRecoveryCode → api.post<MfaVerifyResp>`; `src/api/types.ts: MfaVerifyResp`.
11. **Auth completion is `remaining_factors.length == 0`, then call `POST /ui/session/finalize` — there is no `auth_complete` boolean.** CORRECTED/VERIFIED. `src/pages/Login.tsx` (checks `resp.remaining_factors.length === 0` then `sessionFinalize`, then `finalResp.status === "ok"`). `POST /ui/session/finalize` exists: OpenAPI `POST /ui/session/finalize` (req `UiSessionFinalizeReq`).
12. **Recovery `{factor}` path value may be `totp|sms|email|recovery`.** CORRECTED. `src/pages/Login.tsx:41` `type MfaMethod = "totp" | "sms" | "email" | "recovery"` and `useRecoveryCode(activeMfa, …)` passes the active method (which can be `recovery`). Original spec restricted the enum to `totp|sms|email`.
13. **Session start signals MFA via `auth_required` + `challenge_id` + `required_factors`.** VERIFIED. OpenAPI `components.schemas.UiSessionStartResp` = `{auth_required (req), challenge_id?, required_factors: string[], session_id?}`; `src/pages/Login.tsx` reads `resp.auth_required`, `resp.challenge_id`, `resp.required_factors`, `resp.session_id`.
14. **CSRF: `X-CSRF-Token` header is derived from the `ui_csrf` cookie on every request.** VERIFIED. Frontend `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`). Android side relies on the AND-021 `CsrfInterceptor` (infra, not re-verified here).
15. **422 validation error shape is `{detail: [{loc, msg, type}]}`.** VERIFIED. OpenAPI `components.schemas.HTTPValidationError` (`detail: ValidationError[]`) and `ValidationError = {loc, msg, type}` (all required). OpenAPI index lists `422:HTTPValidationError` for every MFA path.
16. **`400` invalid-code envelope `{detail:{code:"mfa_invalid_code", attempts_remaining}}` and `429` `{detail:{code:"mfa_resend_throttled", retry_after}}`.** UNVERIFIED-ASSUMPTION. The OpenAPI documents only `200` and `422` for all `/ui/mfa/**` paths; no `400`/`429` schema exists in the contract and the frontend types do not model these envelopes. Field names/codes are invented by the spec author.
17. **`401` on an MFA call triggers the single `POST /ui/session/refresh` retry (Authenticator).** UNVERIFIED-ASSUMPTION (infra). `POST /ui/session/refresh` exists (OpenAPI `POST /ui/session/refresh`, no req body) but no `401` response is documented for MFA paths; the refresh-and-retry behavior is an AND-021 infra assumption, not a contract guarantee.
18. **Cookies + CSRF are applied automatically by the shared OkHttp chain (no manual `@Header` params).** UNVERIFIED-ASSUMPTION (cross-ticket). Owned by AND-010/AND-021; not present in these sources and not independently verifiable here.
19. **Android framework/stack choices (Retrofit 2.11, Moshi codegen via KSP, Hilt, `@Path` templating, `@JsonClass(generateAdapter=true)`).** VERIFIED as standard usage. framework ref: Retrofit https://square.github.io/retrofit/ ; Moshi codegen https://github.com/square/moshi#codegen .

### Corrections made

- C1. Replaced the single unified `MfaVerifyReq`/`MfaBeginReq` with the real per-factor request DTOs: `TotpVerifyReq`, `SmsBeginReq`, `SmsVerifyReq`, `EmailBeginReq`, `EmailVerifyReq`, `RecoveryReq` (§4, §6).
- C2. TOTP verify code field corrected from `code` to `totp_code` (§4, §5, §6, §11, AC-2).
- C3. Recovery code field corrected from `code` to `recovery_code`; added the optional body `factor` field (default `"totp"`) and noted the web client omits it (§4, §5, §6).
- C4. Begin response corrected from `MfaBeginResp{sent_to:String, expires_in, resend_available_in, challenge_id}` to `ChallengeResp{challenge_id, sent_to?: List<String>}`; removed the non-existent `expires_in`/`resend_available_in` (§4, §5, §6, FR-6, R4).
- C5. Verify response corrected from `{verified, challenge_id, remaining_factors, auth_complete}` to `MfaVerifyResp{status, session_id?, required_factors, passed: Map, remaining_factors}`; completion is `remaining_factors.isEmpty()` (§4, §5, §6, FR-6, §10, AC).
- C6. `RecoveryFactor` enum extended to include `RECOVERY` (`totp|sms|email|recovery`) to match `Login.tsx` (§4, §5, AC-2).
- C7. Flagged the `400`/`429` MFA error envelopes and the MFA `401`-refresh behavior as unverified assumptions (only `200`/`422` are in the contract) (§5, §7).
- C8. Telemetry event fields `verified`/`auth_complete` replaced with `status`/`remaining_count` (§10).
- C9. R1/R2 marked RESOLVED with the verified shapes (§13).

### Open assumptions

- OA1. The exact `400`/`429` MFA error body codes and fields (`mfa_invalid_code`, `attempts_remaining`, `mfa_resend_throttled`, `retry_after`, `mfa_challenge_expired`) — NOT in the OpenAPI (only 200/422 documented) nor in the frontend types. Must be captured from the running dev host before `ApiErrorMapper` can depend on them.
- OA2. `401`-on-MFA + refresh-and-retry behavior — assumed from AND-021 infra; not documented per-endpoint.
- OA3. The `200` success bodies for the MFA paths are untyped in the OpenAPI index (`resp=200:` with no schema); `ChallengeResp`/`MfaVerifyResp` shapes are taken from the frontend DTOs and should be confirmed with a live sample (R1 smoke check).
- OA4. The runtime value set of `MfaVerifyResp.status` (e.g. `"mfa_required"` vs `"ok"`) is inferred from `Login.tsx` comparisons (`finalResp.status === "ok"`); the full enumeration is not in the sources.
- OA5. Cookie jar / `CsrfInterceptor` / `Authenticator` / timeouts are owned by AND-010/AND-021 and are assumed present and correct; not verifiable from the provided sources.

## 17. Test Plan

All test-target choices below use: **JVM/Robolectric** (local, no device) for the DTO/Retrofit/MockWebServer suite — this is a network/DTO ticket with no UI, so the bulk runs on the JVM. The **emulator `test35`** (API 35) and **physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a, serial R5CX821TA9R)** are used only for the few instrumented checks (cleartext policy, ABI/API parity) where device/runtime behavior matters; the physical device is REQUIRED where API-34-vs-35 or arm64-vs-x86 behavior is in scope.

- **TC-AND-033-01** — Type: contract/MockWebServer. Target: JVM/Robolectric. Preconditions: MockWebServer up; `MfaApiClient` wired with test Retrofit/Moshi. Steps: enqueue `200` `MfaVerifyResp`; call `verifyTotp("chl_x","482915")`; capture `RecordedRequest`. Expected: path `/ui/mfa/totp/verify`, method `POST`, body JSON has exactly `{challenge_id:"chl_x", totp_code:"482915"}` (key is `totp_code`, NOT `code`); result is `ApiResult.Success<MfaVerifyResp>`. Traces: AC-1, AC-2.
- **TC-AND-033-02** — Type: contract/MockWebServer. Target: JVM/Robolectric. Preconditions: as above. Steps: enqueue `200` `ChallengeResp`; call `beginSms("chl_x")`; then `verifySms("chl_x","482915")`. Expected: paths `/ui/mfa/sms/begin` then `/ui/mfa/sms/verify`, both `POST`; begin body `{challenge_id}`, verify body `{challenge_id, code}`; begin result deserializes `ChallengeResp{challengeId, sentTo:List<String>?}`. Traces: AC-1, AC-2, AC-3.
- **TC-AND-033-03** — Type: contract/MockWebServer. Target: JVM/Robolectric. Steps: enqueue `200`; call `beginEmail` then `verifyEmail`. Expected: paths `/ui/mfa/email/begin` and `/ui/mfa/email/verify`, `POST`; verify body `{challenge_id, code}`. Traces: AC-1, AC-2.
- **TC-AND-033-04** — Type: contract/MockWebServer. Target: JVM/Robolectric. Steps: enqueue `200`; call `useRecovery(RecoveryFactor.SMS, "chl_x", "ab12-cd34-ef56")`. Expected: path `/ui/mfa/recovery/sms`, `POST`; body has `recovery_code` (NOT `code`) and `challenge_id`, and omits `factor`; also assert `RecoveryFactor.RECOVERY.wire == "recovery"` resolves to `/ui/mfa/recovery/recovery`. Traces: AC-1, AC-2.
- **TC-AND-033-05** — Type: unit (Moshi). Target: JVM. Preconditions: Moshi instance with generated adapters; fixtures in `core-testing`. Steps: parse `mfa_verify_resp.json` (`{status, session_id, required_factors, passed, remaining_factors}`) and assert field-by-field; re-serialize and assert snake_case keys; repeat for `ChallengeResp` (incl. `sent_to` as an array and a fixture with `sent_to` absent → null). Expected: exact round-trip; `auth_complete`/`verified` keys never appear. Traces: AC-3.
- **TC-AND-033-06** — Type: unit (Moshi). Target: JVM. Steps: parse an `MfaVerifyResp` fixture containing an unknown key (e.g. `"server_note":"x"`) and a `RecoveryReq`/`TotpVerifyReq` round-trip; assert deserialization succeeds (forward-compat) and constructed requests emit exactly the required keys (`totp_code` for TOTP, `recovery_code` for recovery). Expected: no exception; unknown key ignored. Traces: AC-3.
- **TC-AND-033-07** — Type: contract/MockWebServer. Target: JVM/Robolectric. Preconditions: CSRF interceptor + cookie jar installed; `ui_csrf` cookie seeded. Steps: call any verify endpoint; inspect `RecordedRequest`. Expected: header `X-CSRF-Token` equals the `ui_csrf` cookie value and a `Cookie` header is present. Traces: AC-4.
- **TC-AND-033-08** — Type: contract/MockWebServer. Target: JVM/Robolectric. Steps: enqueue `422` `{detail:[{loc:["body","totp_code"],msg:"Field required",type:"missing"}]}`; call `verifyTotp`. Expected: `ApiResult.HttpError(422, ApiError)` with `fieldErrors` populated from `detail[]`; no crash. Traces: AC-5.
- **TC-AND-033-09** — Type: contract/MockWebServer. Target: JVM/Robolectric. Steps: enqueue `400` `{detail:{code:"mfa_invalid_code", attempts_remaining:2}}`; call `verifySms`. Expected: `ApiResult.HttpError(400, ApiError)`; if the object envelope is present, `ApiError.code=="mfa_invalid_code"` and `attemptsRemaining==2`; the mapper MUST NOT crash if `detail` is a bare string or missing fields (covers OA1). Traces: AC-5.
- **TC-AND-033-10** — Type: contract/MockWebServer. Target: JVM/Robolectric. Steps: enqueue `429` then `200`; call `beginSms`. Expected: exactly ONE `RecordedRequest` (non-idempotent POST is not auto-retried); first result is `ApiResult.HttpError(429, …)` with `retryAfter` mapped if present. Traces: AC-5.
- **TC-AND-033-11** — Type: contract/MockWebServer (offline/flaky-host path). Target: JVM/Robolectric. Preconditions: simulate the unreliable dev host. Steps: (a) `mockWebServer.shutdown()` before the call, and (b) enqueue `SocketPolicy.NO_RESPONSE` to force a read timeout; call `verifyTotp`. Expected: each yields `ApiResult.NetworkError(throwable)` (no exception escapes), single attempt, completes within the ~20s timeout. Traces: AC-5.
- **TC-AND-033-12** — Type: unit + log assertion (security). Target: JVM/Robolectric. Preconditions: OkHttp client configured per §8 for `/ui/mfa/**`; capture log output. Steps: perform a verify call against MockWebServer with logging enabled. Expected: logs contain method+URL+status only; the request body (the `totp_code`/`code`/`recovery_code` and `challenge_id`) NEVER appears in any log line; emitted analytics payload excludes `challenge_id`, `sent_to`, and any code. Traces: AC-6.
- **TC-AND-033-13** — Type: instrumented/e2e (cleartext policy, security). Target: PHYSICAL DEVICE (Samsung Galaxy A15, API 34) AND emulator `test35` (API 35). MUST run on the physical device because cleartext-traffic enforcement is an OS/runtime behavior and we must confirm API-34 vs API-35 parity. Preconditions: release-flavor network-security-config with `usesCleartextTraffic=false`. Steps: attempt a plaintext `http://` MFA call from a release build; then repeat from the dev flavor. Expected: release build BLOCKS cleartext (IO/network failure surfaced as `ApiResult.NetworkError`); dev flavor permits it. Identical outcome on both API 34 and API 35. Traces: AC-6 (security/transport), supports DoD cleartext constraint.
- **TC-AND-033-14** — Type: instrumented (ABI/API parity, smoke). Target: PHYSICAL DEVICE (arm64-v8a, API 34) vs emulator `test35` (x86_64, API 35). MUST include the physical device for the arm64 path. Preconditions: app installed on both. Steps: run the MockWebServer-backed `MfaApiClient` happy-path suite (TC-01..04) as instrumented tests on each target. Expected: Moshi codegen adapters and Retrofit `@Path` templating behave identically across arm64-v8a/API-34 and x86_64/API-35 (no ABI- or API-level deserialization differences). Traces: AC-1, AC-2, AC-3.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (endpoints callable via `MfaApiClient`/`ApiResult`) | TC-01, TC-02, TC-03, TC-04, TC-14 |
| AC-2 (path/verb/body correct; recovery `{factor}` incl. `recovery`) | TC-01, TC-02, TC-03, TC-04, TC-14 |
| AC-3 (DTO round-trip, snake↔camel, unknown-key tolerance) | TC-02, TC-05, TC-06, TC-14 |
| AC-4 (`X-CSRF-Token` + cookies on every request) | TC-07 |
| AC-5 (400/422/429 → `HttpError`; no auto-retry; network errors) | TC-08, TC-09, TC-10, TC-11 |
| AC-6 (no codes/`challenge_id` in logs/analytics; body logging off; transport security) | TC-12, TC-13 |

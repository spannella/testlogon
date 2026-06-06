---
id: AND-026
title: Auth DTOs + adapters
milestone: M1
epic: E04
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-010]
blocks: [AND-027]
---

# AND-026 — Auth DTOs + adapters

## 1. Overview & Goal

This ticket delivers the typed, Moshi-backed data-transfer objects (DTOs) and
custom adapters that model the wire format of the TestLogon cookie-based
authentication surface. It produces no UI, no networking calls, and no business
logic. The deliverable is a set of immutable Kotlin `data class` DTOs plus the
Moshi `JsonAdapter` wiring required so that the request/response payloads of the
session-management and MFA endpoints `(de)serialize the documented JSON exactly`.

The session flow these DTOs describe is:
`POST /ui/session/start` → (challenge + `required_factors`) → MFA
begin/verify (`/ui/mfa/{totp|sms|email}/begin|verify`) →
`POST /ui/session/finalize` → `GET /ui/me`, with `POST /ui/session/refresh`
on 401 and `POST /ui/session/logout` to tear down. AND-026 owns *only* the
serialization contract for the bodies and responses of those calls. The
Retrofit `AuthApi` interface that actually invokes them is AND-027; the cookie
jar, CSRF header injection, and 401-refresh interceptor are separate
core-network tickets. This ticket is the single source of truth for the JSON
shapes so that downstream API, repository, and ViewModel work compiles against
stable types.

Goal: ship `core-model` (DTO definitions) + the `core-network` Moshi adapter
registration such that every documented auth payload survives a
serialize→deserialize→serialize round-trip byte-for-byte against captured
backend samples, validated by unit tests.

## 2. Context & References

- **Module placement.** DTOs live in `core-model` under package
  `com.testlogon.android.core.model.auth`. Any custom Moshi adapters and the
  `AuthMoshiModule` Hilt contribution live in `core-network` under
  `com.testlogon.android.core.network.auth`. This keeps `core-model` free of a
  Moshi *runtime* dependency where possible (codegen annotations only) and
  concentrates adapter registration in `core-network`.
- **Stack.** Kotlin 2.0.21, Moshi 1.15 with `moshi-kotlin-codegen` via KSP,
  Retrofit 2.11 Moshi converter. minSdk 24 / compileSdk 35, JDK 17.
- **Dependency (AND-010).** Retrofit + Moshi are configured; a shared
  `Moshi` instance is provided by Hilt and a sample endpoint round-trips JSON.
  AND-026 extends that `Moshi` with auth adapters.
- **Downstream (AND-027).** `AuthApi` Retrofit interface consumes these DTOs.
- **Backend.** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). OpenAPI at `/openapi.json`. Web reference for exact
  field names: `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts`
  (mirror these names; do not invent camelCase variants — backend is snake_case).
- **Appendix A** of the project plan is the authoritative field list; this spec
  encodes it. Where Appendix A and `/openapi.json` disagree, `/openapi.json` of
  the running dev host wins and the captured sample is updated.

## 3. Functional Requirements

FR-1. Define request DTOs: `SessionStartReq`, `SessionFinalizeReq`, and the
per-factor MFA request bodies. (CORRECTED) There is no generic `MfaBeginReq`/
`MfaVerifyReq`: begin bodies are `SmsBeginReq`/`EmailBeginReq` (TOTP has no begin),
and verify bodies are `TotpVerifyReq` (`totp_code`), `SmsVerifyReq` (`code`), and
`EmailVerifyReq` (`code`). `RecoveryReq` is modeled for the recovery-code path.

FR-2. Define response DTOs: `SessionStartResp`, `SessionFinalizeResp`, `MeResp`,
`SessionInfo`, `SessionsResp` (the `{sessions:[...]}` wrapper for `GET /ui/sessions`),
`ChallengeResp` (begin response), `MfaVerifyResp`, plus the generic envelopes
`OkResp` and `StatusResp`. (CORRECTED) There is no `MfaBeginResp` and no standalone
`Challenge` model in the verified contract.

FR-3. (CORRECTED) Model `challenge_context` for `/ui/session/start` as a free-form
`Map<String, Any?>` (backend `additionalProperties: true`, field optional) — NOT a
typed `{username, password}` object. Model the `required_factors` list returned in
the start/finalize/verify responses.

FR-4. Every DTO field maps to the backend's snake_case name via `@Json(name=…)`
when the Kotlin property uses camelCase. Unknown/extra JSON keys must be tolerated
(deserialization must not throw on additive backend fields).

FR-5. Nullable vs. required fields must match the contract: optional fields are
Kotlin nullable with a default of `null`; required fields are non-null and absence
must surface as a deserialization error (so callers fail fast, not silently).

FR-6. A polymorphic/sealed representation of the MFA factor type
(`totp | sms | email`) must (de)serialize from/to its lowercase string token.

FR-7. All DTOs are immutable `data class`es; no mutable collections are exposed
(use `List<T>`).

FR-8. Provide captured JSON sample fixtures under `core-model` test resources for
each payload, used by round-trip unit tests.

## 4. Technical Design

All DTOs are `@JsonClass(generateAdapter = true)` data classes so Moshi codegen
(KSP) emits adapters at build time — no reflection adapter is added for these
types.

```kotlin
package com.testlogon.android.core.model.auth

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

// CORRECTED: backend `UiSessionStartReq.challenge_context` is a free-form object
// (`additionalProperties: true`, and the field itself is OPTIONAL). It is NOT a
// typed {username, password}. The web type is `challenge_context?: Record<string,
// unknown>` (src/api/types.ts: SessionStartReq). We therefore model it as an
// open string-keyed map rather than a typed ChallengeContext. (The {username,
// password} shape was an unverified assumption — see §16.)
@JsonClass(generateAdapter = true)
data class SessionStartReq(
    @Json(name = "challenge_context") val challengeContext: Map<String, Any?>? = null,
)

// CORRECTED: added `session_id` (nullable) — present in both UiSessionStartResp
// and the web SessionStartResp. Per OpenAPI only `auth_required` is `required`;
// `required_factors` is non-required in the schema but always present in the web
// type, so we keep a non-null default of emptyList().
@JsonClass(generateAdapter = true)
data class SessionStartResp(
    @Json(name = "auth_required") val authRequired: Boolean,
    @Json(name = "challenge_id") val challengeId: String? = null,  // null when no auth needed
    @Json(name = "required_factors") val requiredFactors: List<MfaFactor> = emptyList(),
    @Json(name = "session_id") val sessionId: String? = null,
)

// CORRECTED: added `remember_device` (boolean, backend default false).
@JsonClass(generateAdapter = true)
data class SessionFinalizeReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "remember_device") val rememberDevice: Boolean = false,
)

// CORRECTED: backend/web shape is {status, session_id?, required_factors, passed},
// NOT {ok, user_id?}. `status` is "ok" | "pending"; `passed` maps factor token →
// bool. (src/api/types.ts: SessionFinalizeResp)
@JsonClass(generateAdapter = true)
data class SessionFinalizeResp(
    val status: String,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<MfaFactor> = emptyList(),
    val passed: Map<String, Boolean> = emptyMap(),
)

// CORRECTED: `GET /ui/me` returns {user_sub, session_id, ip} — NOT username/email/
// display_name/mfa_enabled (those fields do not exist in MeResp).
// (src/api/types.ts: MeResp)
@JsonClass(generateAdapter = true)
data class MeResp(
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "session_id") val sessionId: String,
    val ip: String,
)

// CORRECTED: timestamps are epoch numbers (Long), not ISO-8601 strings; field is
// `is_current` not `current`; added required `revoked`/`user_agent` and optional
// `revoked_at`. (src/api/types.ts: SessionInfo)
@JsonClass(generateAdapter = true)
data class SessionInfo(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "is_current") val isCurrent: Boolean,
    @Json(name = "created_at") val createdAt: Long,          // epoch seconds
    @Json(name = "last_seen_at") val lastSeenAt: Long,       // epoch seconds
    val ip: String,
    @Json(name = "user_agent") val userAgent: String,
    val revoked: Boolean,
    @Json(name = "revoked_at") val revokedAt: Long? = null,
)

// CORRECTED: there is no generic MfaBeginReq/MfaBeginResp and no TOTP begin
// endpoint. SMS/email begin take {challenge_id} (SmsBeginReq / EmailBeginReq)
// and return ChallengeResp {challenge_id, sent_to?}. (openapi: SmsBeginReq,
// EmailBeginReq; src/api/types.ts: ChallengeResp)
@JsonClass(generateAdapter = true)
data class SmsBeginReq(
    @Json(name = "challenge_id") val challengeId: String,
)

@JsonClass(generateAdapter = true)
data class EmailBeginReq(
    @Json(name = "challenge_id") val challengeId: String,
)

@JsonClass(generateAdapter = true)
data class ChallengeResp(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "sent_to") val sentTo: List<String>? = null,
)

// CORRECTED: verify bodies differ per factor. TOTP uses `totp_code`; SMS and
// email use `code`. A single MfaVerifyReq(challenge_id, code) is WRONG for TOTP.
// (openapi: TotpVerifyReq, SmsVerifyReq, EmailVerifyReq)
@JsonClass(generateAdapter = true)
data class TotpVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "totp_code") val totpCode: String,
)

@JsonClass(generateAdapter = true)
data class SmsVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    val code: String,
)

@JsonClass(generateAdapter = true)
data class EmailVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    val code: String,
)

// CORRECTED: shape is {status, session_id?, required_factors, passed,
// remaining_factors}. There is no `ok` / `satisfied_factors`; success is signalled
// by `status` and the `passed` map. (src/api/types.ts: MfaVerifyResp)
@JsonClass(generateAdapter = true)
data class MfaVerifyResp(
    val status: String,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<MfaFactor> = emptyList(),
    val passed: Map<String, Boolean> = emptyMap(),
    @Json(name = "remaining_factors") val remainingFactors: List<MfaFactor> = emptyList(),
)

// Recovery (login flow) — modeled for completeness; backend RecoveryReq.
@JsonClass(generateAdapter = true)
data class RecoveryReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "recovery_code") val recoveryCode: String,
    val factor: String? = null,
)

@JsonClass(generateAdapter = true)
data class OkResp(val ok: Boolean)

// CORRECTED: StatusResp has ONLY `status`; there is no `detail` field.
// logout / refresh / revoke / revoke_others all return StatusResp.
// (src/api/types.ts: StatusResp)
@JsonClass(generateAdapter = true)
data class StatusResp(
    val status: String,
)

// `GET /ui/sessions` returns a WRAPPER object {sessions: [...]}, not a bare list.
// (src/api/endpoints/auth.ts: getSessions → {sessions: SessionInfo[]})
@JsonClass(generateAdapter = true)
data class SessionsResp(
    val sessions: List<SessionInfo> = emptyList(),
)
```

The MFA factor token is modeled as an enum with an explicit unknown fallback so a
new backend factor does not crash deserialization:

```kotlin
enum class MfaFactor(val token: String) {
    TOTP("totp"),
    SMS("sms"),
    EMAIL("email"),
    UNKNOWN("unknown");

    companion object { fun fromToken(t: String): MfaFactor =
        entries.firstOrNull { it.token == t } ?: UNKNOWN }
}
```

Custom adapter (lives in `core-network`) so the enum round-trips lowercase tokens
and degrades gracefully:

```kotlin
package com.testlogon.android.core.network.auth

import com.squareup.moshi.FromJson
import com.squareup.moshi.ToJson
import com.testlogon.android.core.model.auth.MfaFactor

object MfaFactorAdapter {
    @FromJson fun fromJson(value: String): MfaFactor = MfaFactor.fromToken(value)
    @ToJson fun toJson(factor: MfaFactor): String = factor.token
}
```

Hilt registration extends the AND-010 `Moshi` provider. To keep one shared
instance, AND-010's `@Provides Moshi` is updated to consume contributed adapters,
or this module provides the auth adapters into the builder:

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object AuthMoshiModule {
    @Provides @IntoSet @AppMoshiAdapter
    fun mfaFactorAdapter(): Any = MfaFactorAdapter
}
```

(If AND-010 did not expose an adapter set, this ticket adds the `@AppMoshiAdapter`
qualifier + set-multibinding and folds it into the `Moshi.Builder().add(...)`
loop; that is the only edit permitted to AND-010 code and must keep its sample
test green.)

Toleration of unknown keys is the Moshi default for codegen adapters (extra keys
are skipped). No `failOnUnknown()` is set on the shared `Moshi`.

## 5. API Contract

This ticket does not perform network I/O; it freezes the JSON bodies the AND-027
`AuthApi` will exchange. Endpoint invocation is owned by AND-027. The exact
shapes:

All shapes below are CORRECTED against `openapi.pretty.json` and the web client
(`src/api/types.ts`, `src/api/endpoints/auth.ts`).

`POST /ui/session/start` request (`UiSessionStartReq`; `challenge_context` is a
free-form, optional object — credential keys are backend-defined, not part of the
typed contract):
```json
{ "challenge_context": { "username": "alice", "password": "s3cret" } }
```
response (`UiSessionStartResp`, auth required):
```json
{ "auth_required": true, "challenge_id": "chl_abc123",
  "required_factors": ["totp"], "session_id": null }
```

`POST /ui/mfa/totp/verify` request (`TotpVerifyReq` — note `totp_code`, not `code`)
/ response (`MfaVerifyResp`):
```json
{ "challenge_id": "chl_abc123", "totp_code": "123456" }
```
```json
{ "status": "ok", "session_id": "sess_99", "required_factors": ["totp"],
  "passed": { "totp": true }, "remaining_factors": [] }
```

`POST /ui/mfa/sms/verify` / `POST /ui/mfa/email/verify` request (`code`, not
`totp_code`):
```json
{ "challenge_id": "chl_abc123", "code": "123456" }
```

`POST /ui/mfa/sms/begin` request (`SmsBeginReq`) / response (`ChallengeResp`):
```json
{ "challenge_id": "chl_abc123" }
```
```json
{ "challenge_id": "chl_abc123", "sent_to": ["+1•••••1234"] }
```

`POST /ui/session/finalize` request (`UiSessionFinalizeReq`) / response
(`SessionFinalizeResp`):
```json
{ "challenge_id": "chl_abc123", "remember_device": false }
```
```json
{ "status": "ok", "session_id": "sess_99", "required_factors": ["totp"],
  "passed": { "totp": true } }
```

`GET /ui/me` response (`MeResp`):
```json
{ "user_sub": "usr_42", "session_id": "sess_99", "ip": "203.0.113.7" }
```

`GET /ui/sessions` returns a WRAPPER `{ "sessions": [SessionInfo, ...] }` (not a
bare list), e.g.:
```json
{ "sessions": [ { "session_id": "sess_99", "is_current": true,
  "created_at": 1749081600, "last_seen_at": 1749085200, "ip": "203.0.113.7",
  "user_agent": "okhttp/4.12", "revoked": false } ] }
```

`POST /ui/session/refresh`, `POST /ui/session/logout`, `POST /ui/sessions/revoke`
(body `{ "session_id": "..." }`) and `POST /ui/sessions/revoke_others` all return
`StatusResp` (`{"status": "ok"}`), NOT `OkResp`. The `ui_csrf` cookie and
`X-CSRF-Token` header are transport concerns (verified in `src/api/client.ts`),
not DTO fields, and are out of scope here. (Validation failures on any of these
endpoints return HTTP 422 `HTTPValidationError` `{ "detail": [ {loc, msg, type} ] }`
— modeled by the core-network error ticket, not these success DTOs.)

## 6. Data & State Management

No persistent or in-memory app state is introduced. DTOs are transient wire types.
They must **not** be stored directly in Room or DataStore; mapping to domain
models and persistence is the responsibility of core-data / repository tickets.
DTOs carry no Compose `@Stable`/`@Immutable` annotations because they never enter
composition directly. ISO-8601 timestamps remain `String` at this layer; parsing
to `Instant` is deferred to the domain-mapping ticket to avoid coupling DTOs to a
time library. The `MfaFactor.UNKNOWN` fallback is the only stateful behavioral
choice and exists purely to keep deserialization total.

## 7. Error Handling & Resilience

Deserialization-level robustness only (no network resilience here — timeouts,
20s budgets, bounded GET retry, and offline/stale UI belong to core-network and
feature-auth tickets):

- Missing required field → Moshi `JsonDataException`; this is desired
  fail-fast behavior and is asserted in tests.
- Unknown/extra JSON keys → skipped silently (additive backend evolution safe).
- Unknown MFA token → mapped to `MfaFactor.UNKNOWN`, never throws.
- `null` for a nullable field → tolerated; `null` for a non-null field →
  `JsonDataException`.
- FastAPI error envelopes (`detail: string | [{msg}] | {code,...}`) are **not**
  modeled by these success DTOs; error mapping is owned by the core-network
  `ApiResult`/error-adapter ticket. `StatusResp.detail` here is only the
  documented success/status payload, not the error `detail` union.

## 8. Security & Privacy

- DTOs may carry credentials (whatever the caller puts in
  `SessionStartReq.challengeContext`, e.g. a password) and MFA secrets
  (`TotpVerifyReq.totpCode`, `SmsVerifyReq.code`, `EmailVerifyReq.code`,
  `RecoveryReq.recoveryCode`). These classes must **not** be logged. (CORRECTED:
  there is no `ChallengeContext`/`MfaVerifyReq` class anymore — redaction applies
  to `SessionStartReq` and each per-factor verify/recovery DTO.) Override
  `toString()` to redact sensitive fields, e.g.:
  ```kotlin
  override fun toString() = "SessionStartReq(challengeContext=***)"
  // and e.g. "TotpVerifyReq(challengeId=$challengeId, totpCode=***)"
  ```
- No credential is persisted; DTOs are constructed, serialized, and discarded.
- No tokens are stored in DTO fields. (CLARIFIED: the web client transports auth
  via BOTH session cookies — `credentials: "include"` — and an `Authorization:
  Bearer <accessToken>` header sourced from its auth store, per
  `src/api/client.ts`. Neither mechanism appears in these DTOs; both are
  transport concerns owned by core-network. The Android port must decide whether
  it mirrors the Bearer-token path or relies on the cookie jar alone — flagged as
  an open assumption in §16.)
- Test fixtures must use synthetic credentials/codes only (no real secrets in
  committed JSON samples).

## 9. Accessibility & i18n

Not applicable — this ticket has no UI surface. No user-facing strings are
introduced. Masked delivery hints (`delivery_hint`) are passed through verbatim
as supplied by the backend; any localization of MFA prompts is owned by the
feature-auth UI ticket (AND-028+). No `strings.xml` entries are added.

## 10. Telemetry & Logging

No analytics events are emitted by DTOs. Logging is prohibited at this layer; in
particular, no `@JvmStatic` logging in adapters and no full-body request logging
for auth endpoints (the OkHttp logging interceptor configured in core-network
must redact the `/ui/session/start` and `/ui/mfa/*/verify` bodies — that
redaction rule is documented here as a constraint for the core-network ticket but
implemented there). The only diagnostic surface this ticket adds is the redacted
`toString()` overrides above.

## 11. Testing Strategy

All tests are JVM unit tests in `core-model` (and the adapter test in
`core-network`); no Android instrumentation required. Use the shared `Moshi`
instance from the Hilt graph or an equivalently-built test `Moshi` that includes
`MfaFactorAdapter`.

- **Round-trip fixtures.** For each DTO, a captured JSON sample lives at
  `core-model/src/test/resources/auth/<name>.json`. Test asserts
  `moshi.adapter(T::class.java).fromJson(sample)` is non-null, deserializes to
  the expected object, and re-serializing produces JSON whose parsed tree equals
  the original parsed tree (compare via `JSONObject`/Moshi `Map` to ignore key
  ordering and whitespace).
- **Field-name mapping.** Assert snake_case keys appear in serialized output
  (e.g., serialized `SessionStartReq` contains `"challenge_context"`, never
  `"challengeContext"`).
- **Required-field failure.** Removing `auth_required` from the
  `SessionStartResp` sample causes `fromJson` to throw `JsonDataException`
  (`auth_required` is the one `required` field in `UiSessionStartResp`).
- **Unknown-key tolerance.** A sample with an extra `"server_time"` key
  deserializes without error.
- **MFA enum.** `"totp"/"sms"/"email"` map to the correct enum; `"webauthn"`
  maps to `UNKNOWN`; serialization emits lowercase tokens.
- **Redaction.** `SessionStartReq(...).toString()` and each per-factor verify
  DTO's `toString()` (`TotpVerifyReq`/`SmsVerifyReq`/`EmailVerifyReq`/`RecoveryReq`)
  must not contain the password / code / recovery-code value.
- **Coverage target.** Every DTO declared in Section 4 has at least one
  round-trip test and a committed fixture. Test class:
  `com.testlogon.android.core.model.auth.AuthDtoRoundTripTest`.

## 12. Dependencies & Sequencing

- **Depends on AND-010** (Retrofit + Moshi setup): requires the shared `Moshi`
  instance and the KSP `moshi-kotlin-codegen` toolchain. If AND-010's `Moshi`
  provider does not expose an extensible adapter set, this ticket adds the
  multibinding hook (only permitted edit to AND-010 code; AND-010's sample
  round-trip test must stay green).
- **Blocks AND-027** (AuthApi session endpoints): the Retrofit `AuthApi`
  interface references these DTOs as request/response types; it cannot compile
  without them.
- Indirectly enables the auth repository, cookie-jar/CSRF interceptor, and
  feature-auth UI tickets that follow AND-027.

## 13. Risks & Open Questions

- **R1 — Field-name drift.** Appendix A lagged the live contract and was the
  source of several errors now corrected (see §16): `SessionFinalizeResp` is
  `{status, session_id?, required_factors, passed}` (no `user_id`/`ok`); there is
  no `MfaBeginResp` (`sent`/`delivery_hint` were invented) — begin returns
  `ChallengeResp {challenge_id, sent_to?}`. *Resolved* against `openapi.pretty.json`
  and `src/api/types.ts`. Mitigation going forward: capture fixtures directly from
  the dev host and treat the live contract as authoritative.
- **R2 — Nullable ambiguity.** *Resolved:* `MeResp` is `{user_sub, session_id, ip}`
  — all three present (the previously-assumed `email`/`display_name`/`mfa_enabled`
  fields do not exist). Confirmed against `src/api/types.ts: MeResp`.
- **R3 — `required_factors` ordering.** Backend `required_factors` is a plain
  `array` of strings; OpenAPI says nothing about ordering significance. Modeled as
  ordered `List` to preserve whatever order the server sends. *Open:* whether order
  is semantically significant is still unverified (no schema/source statement).
- **R4 — Unknown MFA factor.** `UNKNOWN` fallback prevents crashes but a UI
  rendering only known factors could silently skip a required one. Downstream UI
  must surface unknown-required-factor as a hard error (noted for AND-028).
- **R5 — Adapter-set coupling to AND-010.** If AND-010 shipped a closed `Moshi`
  provider, the required edit could conflict with in-flight AND-010 work;
  sequence AND-026 after AND-010 merges.

## 14. Acceptance Criteria

1. All DTOs in Section 4 exist in
   `com.testlogon.android.core.model.auth` as immutable `@JsonClass(generateAdapter=true)`
   data classes, and `MfaFactorAdapter` is registered on the shared `Moshi`.
2. Every documented auth payload (Sections 4–5) **(de)serializes the documented
   JSON exactly**, proven by `AuthDtoRoundTripTest` against committed captured
   samples (parsed-tree equality, snake_case keys verified).
3. Required-field absence throws `JsonDataException`; unknown JSON keys are
   tolerated; unknown MFA tokens map to `MfaFactor.UNKNOWN`.
4. `SessionStartReq.toString()` and every per-factor verify/recovery DTO's
   `toString()` (`TotpVerifyReq`/`SmsVerifyReq`/`EmailVerifyReq`/`RecoveryReq`)
   redact password/code/recovery-code; no committed fixture contains a real secret.
5. The module compiles with KSP codegen (no reflective Moshi adapter added for
   these types) and AND-010's existing sample round-trip test still passes.
6. AND-027's `AuthApi` can reference all request/response types and compile.

## 15. Definition of Done

- Code merged to `android-port` under `core-model` (DTOs) and `core-network`
  (`MfaFactorAdapter`, `AuthMoshiModule`), package base
  `com.testlogon.android`.
- `AuthDtoRoundTripTest` and the adapter test pass in CI; captured JSON fixtures
  committed under `core-model/src/test/resources/auth/`.
- No new lint/detekt violations; `./gradlew :core-model:test :core-network:test`
  green on JDK 17.
- Sensitive `toString()` redaction verified by test.
- Open questions R1/R2/R3 resolved against `/openapi.json` (or explicitly
  ticketed for follow-up) before AND-027 starts consuming the DTOs.
- Spec reviewed; no UI, persistence, or network-call code introduced (those are
  downstream tickets).

## 16. Citations & Assumption Audit

Each numbered item: the claim → VERDICT → SOURCE (exact pointer).

1. `POST /ui/session/start` exists, req `UiSessionStartReq`, resp 200
   `UiSessionStartResp`. → **Verified** → OpenAPI `POST /ui/session/start`
   (op `ui_session_start_ui_session_start_post`).
2. `SessionStartReq.challenge_context` is a typed `{username, password}` object. →
   **Corrected** → OpenAPI `UiSessionStartReq.challenge_context` is
   `type: object, additionalProperties: true` and the field is NOT in `required`;
   web type is `challenge_context?: Record<string, unknown>`
   (`src/api/types.ts: SessionStartReq`). Now modeled as optional
   `Map<String, Any?>`.
3. `SessionStartResp` = `{auth_required, challenge_id?, required_factors}`. →
   **Corrected** (incomplete) → OpenAPI `UiSessionStartResp` also has
   `session_id` (nullable); only `auth_required` is `required`. Added `session_id`.
   (`src/api/types.ts: SessionStartResp`.)
4. `SessionFinalizeReq` = `{challenge_id}`. → **Corrected** (incomplete) → OpenAPI
   `UiSessionFinalizeReq` adds `remember_device` (boolean, default false).
   (`src/api/types.ts: SessionFinalizeReq`.) Added field.
5. `SessionFinalizeResp` = `{ok, user_id?}`. → **Corrected** (wrong shape) →
   actual `{status: "ok"|"pending", session_id?, required_factors, passed:
   Record<string, boolean>}` (`src/api/types.ts: SessionFinalizeResp`). Backend
   resp body has no published schema, so the web type is authoritative.
6. `GET /ui/me` returns `{user_id, username, email?, display_name?, mfa_enabled}`. →
   **Corrected** (wrong shape) → actual `{user_sub, session_id, ip}`
   (`src/api/types.ts: MeResp`; OpenAPI `GET /ui/me` resp has no schema body, web
   type authoritative). Note: `/ui/me` declares query/header params
   `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN` (OpenAPI index) — transport
   concerns, not DTO fields.
7. `SessionInfo` timestamps are ISO-8601 `String`; field `current`. → **Corrected**
   → actual `created_at`/`last_seen_at` are epoch `number`, field is `is_current`,
   plus required `user_agent`/`revoked` and optional `revoked_at`
   (`src/api/types.ts: SessionInfo`).
8. `GET /ui/sessions` returns `List<SessionInfo>`. → **Corrected** → returns a
   wrapper `{sessions: SessionInfo[]}` (`src/api/endpoints/auth.ts: getSessions`).
   Added `SessionsResp`.
9. MFA verify uses a single `MfaVerifyReq(challenge_id, code)`. → **Corrected** →
   TOTP body is `TotpVerifyReq {challenge_id, totp_code}` (field `totp_code`, not
   `code`); SMS/email are `SmsVerifyReq`/`EmailVerifyReq {challenge_id, code}`.
   (OpenAPI `TotpVerifyReq`, `SmsVerifyReq`, `EmailVerifyReq`;
   `src/api/types.ts`.)
10. MFA begin uses `MfaBeginReq` and returns `MfaBeginResp {sent, delivery_hint,
    expires_at}`. → **Corrected** → no such schemas. Begin endpoints are
    `POST /ui/mfa/sms/begin` (`SmsBeginReq {challenge_id}`) and
    `/ui/mfa/email/begin` (`EmailBeginReq {challenge_id}`); both return
    `ChallengeResp {challenge_id, sent_to?}`. TOTP has NO begin endpoint.
    (OpenAPI `POST /ui/mfa/sms/begin`, `POST /ui/mfa/email/begin`, schemas
    `SmsBeginReq`/`EmailBeginReq`; `src/api/endpoints/auth.ts: beginSms/beginEmail`,
    `src/api/types.ts: ChallengeResp`.)
11. `MfaVerifyResp` = `{ok, satisfied_factors, remaining_factors}`. →
    **Corrected** → actual `{status, session_id?, required_factors, passed:
    Record<string, boolean>, remaining_factors}`; no `ok`/`satisfied_factors`.
    (`src/api/types.ts: MfaVerifyResp`.)
12. Standalone `Challenge {challenge_id, required_factors, satisfied_factors}`
    model. → **Corrected/Removed** → no such schema in OpenAPI or web types; the
    begin response is `ChallengeResp {challenge_id, sent_to?}`. Dropped the
    invented `Challenge` model.
13. `OkResp = {ok}`. → **Verified** → `src/api/types.ts: OkResp`. (Used by
    `/ui/password-recovery/confirm` per `src/api/endpoints/auth.ts`.)
14. `StatusResp = {status, detail?}`. → **Corrected** → actual `{status}` only;
    no `detail` field (`src/api/types.ts: StatusResp`). Removed `detail`.
15. `logout`/`refresh`/revoke endpoints return `OkResp`. → **Corrected** →
    `logout`, `refreshSession`, `revokeSession`, `revokeOtherSessions` all return
    `StatusResp` (`src/api/endpoints/auth.ts`). Logout/refresh are
    `POST /ui/session/logout` and `POST /ui/session/refresh`; revoke is
    `POST /ui/sessions/revoke` with body `{session_id}` and
    `POST /ui/sessions/revoke_others` (OpenAPI index).
16. CSRF: `ui_csrf` cookie sent as `X-CSRF-Token` header. → **Verified** →
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", …)`).
17. 401 handling refreshes via `POST /ui/session/refresh` then retries once. →
    **Verified** → `src/api/client.ts` `refreshSession()` + retry block.
18. "Auth rides on cookies (HttpOnly) only." → **Corrected/Clarified** → web
    client also sends `Authorization: Bearer <accessToken>` from its auth store in
    addition to `credentials: "include"` cookies (`src/api/client.ts`). Neither is
    a DTO field; transport choice for Android is an open assumption (below).
19. Validation errors are HTTP 422 `HTTPValidationError {detail: [{loc, msg,
    type}]}`. → **Verified** → OpenAPI `responses.422` on every auth path;
    schemas `HTTPValidationError`, `ValidationError`. Web normalizes `detail`
    (string | array-of-{msg} | object) in `src/api/client.ts: normalizeErrorDetail`.
20. Moshi 1.15 + `moshi-kotlin-codegen` (KSP) skips unknown keys by default and
    throws `JsonDataException` on missing non-null fields. → **Verified (framework
    ref)** → Moshi docs/behavior:
    https://github.com/square/moshi (codegen adapters skip unknown names; absent
    required values raise `JsonDataException`). Specific Kotlin 2.0.21 / Retrofit
    2.11 / minSdk 24 / JDK 17 version pins are inherited from AND-010 and are
    **Unverified-assumption** at this layer (no source in this repo set).
21. `MfaFactor` enum with `UNKNOWN` fallback for unknown tokens. → **Unverified-
    assumption (design choice)** → backend `required_factors`/`passed` use plain
    lowercase strings (`totp`/`sms`/`email`) but the enum closed set and the
    `UNKNOWN` sentinel are this spec's modeling decision; `recovery` is also a
    real factor path (`/ui/mfa/recovery/{factor}`) not in the enum — callers must
    handle it. Note `passed` is keyed by factor token (`Map<String,Boolean>`) and
    is intentionally NOT typed by the enum to stay total.

### Corrections made
- `challenge_context` retyped from `{username,password}` to optional free-form
  `Map<String, Any?>`; removed the `ChallengeContext` class (items 2).
- `SessionStartResp` gained `session_id` (item 3).
- `SessionFinalizeReq` gained `remember_device` (item 4).
- `SessionFinalizeResp` rewritten to `{status, session_id?, required_factors,
  passed}` (item 5).
- `MeResp` rewritten to `{user_sub, session_id, ip}` (item 6).
- `SessionInfo` rewritten: epoch-`Long` timestamps, `is_current`, `user_agent`,
  `revoked`, `revoked_at?` (item 7).
- Added `SessionsResp` wrapper for `GET /ui/sessions` (item 8).
- Split MFA verify into `TotpVerifyReq` (`totp_code`), `SmsVerifyReq`,
  `EmailVerifyReq` (`code`); added `RecoveryReq` (items 9, 21).
- Removed `MfaBeginReq`/`MfaBeginResp`; added `SmsBeginReq`/`EmailBeginReq` +
  `ChallengeResp`; documented TOTP has no begin (item 10).
- `MfaVerifyResp` rewritten to `{status, session_id?, required_factors, passed,
  remaining_factors}` (item 11).
- Removed invented `Challenge` model (item 12).
- `StatusResp` reduced to `{status}` (item 14).
- Documented `logout`/`refresh`/revoke return `StatusResp` (item 15).
- Updated FR-1/FR-2/FR-3, §5 JSON samples, §8 redaction targets, §11 tests,
  §13 R1/R2/R3, and §14 AC-4 to match the corrected DTO set.

### Open assumptions
- **Backend response bodies for `/ui/me`, `/ui/session/finalize`, `/ui/mfa/*/verify`,
  `/ui/sessions`, `StatusResp`, `OkResp`, `ChallengeResp` have NO published OpenAPI
  schema** (the index shows `resp=200:` with an empty schema). Their shapes are
  taken from the web client's TypeScript types, which is the next-best contract but
  is not the running backend. *Why unverifiable:* the OpenAPI spec omits these
  response models; the live dev host (`http://18.222.237.167:8000`) is plaintext/
  unreliable and was not reachable from this review.
- **Android auth transport (Bearer vs cookie-only).** The web client sends both a
  Bearer token and session cookies; whether the Android port mirrors the Bearer
  path is a core-network decision not settled by these sources.
- **`required_factors` ordering significance** — not stated in any source (R3).
- **Toolchain version pins** (Kotlin 2.0.21, Moshi 1.15, Retrofit 2.11, minSdk 24,
  compileSdk 35, JDK 17) are inherited from AND-010 and not independently verifiable
  from the reference set.
- **`MfaFactor` enum membership** — `recovery` is a real factor route but is not in
  the enum; treated as a design choice with `UNKNOWN` fallback.

## 17. Test Plan

All cases are JVM unit / contract tests in `core-model` (DTOs) and `core-network`
(adapter), unless noted. "Contract" cases assert (de)serialization against captured
fixtures or literal JSON; MockWebServer is referenced where a future AND-027
integration test would exercise the same shape, but no live network is used here.

- **TC-AND-026-01** — Type: contract. Pre: `MeResp` fixture
  `{"user_sub","session_id","ip"}`. Steps: `adapter.fromJson(sample)`; assert all
  three fields; re-serialize and compare parsed trees. Expected: round-trips
  byte-equivalent; serialized keys are exactly `user_sub`/`session_id`/`ip` (no
  `user_id`/`email`). Traces: AC-1, AC-2.
- **TC-AND-026-02** — Type: contract. Pre: `SessionStartResp` fixture with
  `auth_required`, `challenge_id`, `required_factors:["totp"]`, `session_id:null`.
  Steps: deserialize; assert `requiredFactors == [TOTP]`, `sessionId == null`;
  re-serialize. Expected: parsed-tree equality; snake_case keys present. Traces:
  AC-1, AC-2.
- **TC-AND-026-03** — Type: unit (validation/error). Pre: `SessionStartResp`
  sample with `auth_required` removed. Steps: `fromJson`. Expected: throws
  `JsonDataException` (required field absent). Traces: AC-3.
- **TC-AND-026-04** — Type: unit. Pre: `SessionStartResp` sample with extra key
  `"server_time": 1749081600`. Steps: `fromJson`. Expected: succeeds, extra key
  skipped (no throw). Traces: AC-3.
- **TC-AND-026-05** — Type: contract. Pre: `TotpVerifyReq("chl","123456")`.
  Steps: `toJson`. Expected: output contains `"totp_code":"123456"` and
  `"challenge_id"`, and does NOT contain `"code"`. Traces: AC-2, AC-6.
- **TC-AND-026-06** — Type: contract. Pre: `SmsVerifyReq`/`EmailVerifyReq` samples.
  Steps: round-trip. Expected: key is `"code"` (not `totp_code`); deserializes to
  correct DTO. Traces: AC-2, AC-6.
- **TC-AND-026-07** — Type: contract. Pre: `MfaVerifyResp` fixture
  `{"status":"ok","session_id":"s","required_factors":["totp"],"passed":{"totp":
  true},"remaining_factors":[]}`. Steps: round-trip. Expected: `passed` maps to
  `{"totp": true}`; no `ok`/`satisfied_factors` key emitted on re-serialize.
  Traces: AC-2.
- **TC-AND-026-08** — Type: contract. Pre: `SessionFinalizeReq("chl", true)`.
  Steps: `toJson`. Expected: contains `"challenge_id"` and `"remember_device":true`.
  And `SessionFinalizeResp` fixture `{"status","session_id","required_factors",
  "passed"}` round-trips. Traces: AC-2.
- **TC-AND-026-09** — Type: contract. Pre: `SessionsResp` fixture
  `{"sessions":[{...is_current,created_at:1749081600,...revoked:false}]}`. Steps:
  round-trip. Expected: parses wrapper; `createdAt`/`lastSeenAt` are `Long`;
  `isCurrent` mapped from `is_current`; re-serialize equal. Traces: AC-1, AC-2.
- **TC-AND-026-10** — Type: unit (MFA enum + adapter, `core-network`). Pre: built
  test `Moshi` with `MfaFactorAdapter`. Steps: deserialize
  `["totp","sms","email","webauthn"]`. Expected: maps to
  `[TOTP,SMS,EMAIL,UNKNOWN]`; serializing `[TOTP]` emits lowercase `["totp"]`;
  unknown token never throws. Traces: AC-3.
- **TC-AND-026-11** — Type: unit (security/redaction). Pre: `SessionStartReq` with
  a credential map; `TotpVerifyReq`/`SmsVerifyReq`/`EmailVerifyReq`/`RecoveryReq`
  with secrets. Steps: call `toString()`. Expected: none of the password / code /
  recovery-code values appear; `challengeId` may appear. Traces: AC-4.
- **TC-AND-026-12** — Type: unit (security). Pre: committed fixtures under
  `core-model/src/test/resources/auth/`. Steps: scan fixture contents in a test.
  Expected: no real secret patterns; only synthetic values (`123456`, `s3cret`).
  Traces: AC-4.
- **TC-AND-026-13** — Type: contract (error shape, forward-compat). Pre: literal
  422 body `{"detail":[{"loc":["body","challenge_id"],"msg":"field required",
  "type":"missing"}]}`. Steps: confirm the success DTOs do NOT silently parse it
  (e.g. `SessionFinalizeResp.fromJson` yields `status == null`-driven
  `JsonDataException` since `status` is required), documenting that error mapping is
  owned elsewhere. Expected: success adapter rejects the error envelope. Traces:
  AC-3.
- **TC-AND-026-14** — Type: integration (build/codegen) + MockWebServer hook for
  AND-027. Pre: `:core-model` and `:core-network` modules. Steps: `./gradlew
  :core-model:test :core-network:test`; assert KSP generated `*JsonAdapter` classes
  exist for every §4 DTO and that AND-010's sample round-trip test still passes;
  smoke a MockWebServer-served `MeResp`/`StatusResp` body through the shared
  `Moshi` (proves AND-027 can consume the types). Expected: green; no reflective
  Moshi adapter registered for these types. Traces: AC-1, AC-5, AC-6.

Note on offline/flaky-dev-host path: this ticket performs no network I/O, so the
unreliable dev host and offline behavior are out of scope at the DTO layer (owned
by core-network). TC-AND-026-14's MockWebServer hook is the seam where AND-027 will
add timeout/offline coverage; no accessibility cases apply (no UI surface, §9).

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (DTOs exist, adapter registered) | TC-01, TC-02, TC-09, TC-14 |
| AC-2 (documented JSON (de)serializes exactly, snake_case) | TC-01, TC-02, TC-05, TC-06, TC-07, TC-08, TC-09 |
| AC-3 (required-absent throws; unknown keys tolerated; unknown MFA→UNKNOWN) | TC-03, TC-04, TC-10, TC-13 |
| AC-4 (toString redaction; no real secrets in fixtures) | TC-11, TC-12 |
| AC-5 (KSP codegen; AND-010 sample test stays green) | TC-14 |
| AC-6 (AND-027 AuthApi can reference/compile all types) | TC-05, TC-06, TC-14 |

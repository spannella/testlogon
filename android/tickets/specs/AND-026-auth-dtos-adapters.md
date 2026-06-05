---
id: AND-026
title: Auth DTOs + adapters
milestone: M1
epic: E04
priority: P0
size: M
status: draft
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

FR-1. Define request DTOs: `SessionStartReq`, `SessionFinalizeReq`, and the MFA
begin/verify request bodies (`MfaBeginReq`, `MfaVerifyReq`).

FR-2. Define response DTOs: `SessionStartResp`, `SessionFinalizeResp`, `MeResp`,
`SessionInfo`, `MfaBeginResp`, `MfaVerifyResp`, plus the generic envelopes
`OkResp`, `StatusResp`, and the `Challenge` model.

FR-3. Model the `challenge_context` nested object for `/ui/session/start`
(`{username, password}`), and the `required_factors` list returned in the
challenge response.

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

@JsonClass(generateAdapter = true)
data class ChallengeContext(
    val username: String,
    val password: String,
)

@JsonClass(generateAdapter = true)
data class SessionStartReq(
    @Json(name = "challenge_context") val challengeContext: ChallengeContext,
)

@JsonClass(generateAdapter = true)
data class SessionStartResp(
    @Json(name = "auth_required") val authRequired: Boolean,
    @Json(name = "challenge_id") val challengeId: String?,      // null when no auth needed
    @Json(name = "required_factors") val requiredFactors: List<MfaFactor> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class Challenge(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "required_factors") val requiredFactors: List<MfaFactor>,
    @Json(name = "satisfied_factors") val satisfiedFactors: List<MfaFactor> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SessionFinalizeReq(
    @Json(name = "challenge_id") val challengeId: String,
)

@JsonClass(generateAdapter = true)
data class SessionFinalizeResp(
    val ok: Boolean,
    @Json(name = "user_id") val userId: String? = null,
)

@JsonClass(generateAdapter = true)
data class MeResp(
    @Json(name = "user_id") val userId: String,
    val username: String,
    val email: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "mfa_enabled") val mfaEnabled: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class SessionInfo(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "created_at") val createdAt: String,        // ISO-8601, kept as String
    @Json(name = "last_seen_at") val lastSeenAt: String? = null,
    @Json(name = "user_agent") val userAgent: String? = null,
    val ip: String? = null,
    val current: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class MfaBeginReq(
    @Json(name = "challenge_id") val challengeId: String,
)

@JsonClass(generateAdapter = true)
data class MfaBeginResp(
    val sent: Boolean = false,                                // sms/email transports
    @Json(name = "delivery_hint") val deliveryHint: String? = null, // masked target
    @Json(name = "expires_at") val expiresAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class MfaVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    val code: String,
)

@JsonClass(generateAdapter = true)
data class MfaVerifyResp(
    val ok: Boolean,
    @Json(name = "satisfied_factors") val satisfiedFactors: List<MfaFactor> = emptyList(),
    @Json(name = "remaining_factors") val remainingFactors: List<MfaFactor> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class OkResp(val ok: Boolean)

@JsonClass(generateAdapter = true)
data class StatusResp(
    val status: String,
    val detail: String? = null,
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

`POST /ui/session/start` request:
```json
{ "challenge_context": { "username": "alice", "password": "s3cret" } }
```
response (auth required):
```json
{ "auth_required": true, "challenge_id": "chl_abc123",
  "required_factors": ["totp"] }
```

`POST /ui/mfa/totp/verify` request / response:
```json
{ "challenge_id": "chl_abc123", "code": "123456" }
```
```json
{ "ok": true, "satisfied_factors": ["totp"], "remaining_factors": [] }
```

`POST /ui/mfa/sms/begin` response:
```json
{ "sent": true, "delivery_hint": "+1•••••1234", "expires_at": "2026-06-05T12:05:00Z" }
```

`POST /ui/session/finalize` request / response:
```json
{ "challenge_id": "chl_abc123" }
```
```json
{ "ok": true, "user_id": "usr_42" }
```

`GET /ui/me` response:
```json
{ "user_id": "usr_42", "username": "alice", "email": "alice@example.com",
  "display_name": "Alice A.", "mfa_enabled": true }
```

`GET /ui/sessions` returns `List<SessionInfo>`; `POST /ui/session/refresh` and
`POST /ui/session/logout` return `OkResp` (`{"ok": true}`). The `ui_csrf` cookie
and `X-CSRF-Token` header are transport concerns, not DTO fields, and are out of
scope here.

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

- DTOs carry credentials (`ChallengeContext.password`) and MFA `code`. These
  classes must **not** be logged. `ChallengeContext` and `MfaVerifyReq` override
  `toString()` to redact sensitive fields:
  ```kotlin
  override fun toString() = "ChallengeContext(username=$username, password=***)"
  ```
- No credential is persisted; DTOs are constructed, serialized, and discarded.
- No tokens are stored in DTO fields — auth rides on cookies (HttpOnly), which are
  invisible to this layer by design.
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
  `SessionStartResp` sample causes `fromJson` to throw `JsonDataException`.
- **Unknown-key tolerance.** A sample with an extra `"server_time"` key
  deserializes without error.
- **MFA enum.** `"totp"/"sms"/"email"` map to the correct enum; `"webauthn"`
  maps to `UNKNOWN`; serialization emits lowercase tokens.
- **Redaction.** `SessionStartReq(...).toString()` and
  `MfaVerifyReq(...).toString()` must not contain the password / code value.
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

- **R1 — Field-name drift.** Appendix A may lag the live `/openapi.json`.
  Mitigation: capture fixtures directly from the dev host (or `/openapi.json`
  schemas) and treat the live contract as authoritative. *Open:* confirm exact
  key names for `SessionFinalizeResp` (`user_id` presence) and `MfaBeginResp`
  (`sent` vs `delivery_hint`) against the running backend.
- **R2 — Nullable ambiguity.** Which `MeResp` fields are guaranteed non-null is
  inferred. *Open:* confirm `email`/`display_name` nullability from
  `/openapi.json` `required` arrays before finalizing.
- **R3 — `required_factors` ordering.** If the backend implies a preferred MFA
  order, preserving list order matters for the UI. Modeled as ordered `List`;
  *open:* confirm whether order is significant.
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
4. `ChallengeContext.toString()` and `MfaVerifyReq.toString()` redact
   password/code; no committed fixture contains a real secret.
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

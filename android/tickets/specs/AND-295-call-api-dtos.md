---
id: AND-295
title: Call API + DTOs
milestone: M7
epic: E40
priority: P0
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-289, AND-290, AND-291, AND-292]
---

# AND-295 — Call API + DTOs

## 1. Overview & Goal

This ticket delivers the Retrofit service interface and the Moshi data-transfer
objects (DTOs) for the one-to-one call control plane exposed under
`/messaging/messages/calls/*`. It is the network-contract foundation for the
native Android WebRTC calling stack: invite, accept, decline, end, timeout,
heartbeat (billing/keepalive), out-of-band signaling relay, and TURN/STUN
credential acquisition.

The deliverable is **wire-level only**: a `CallApi` Retrofit interface plus a
set of `@JsonClass(generateAdapter = true)` request/response DTOs in
`core-network` / `core-model`, with round-trip serialization tests against
fixtures captured from the backend OpenAPI schema. No UI, no ViewModel, no
WebRTC `PeerConnection` wiring, no SSE consumption, and no repository orchestration
is in scope — those are owned by AND-289 (PeerConnection wrapper), AND-290
(signaling transport / SSE), AND-291 (TURN config), and AND-292 (media capture).

Goal: every call-control payload in the contract can be serialized and
deserialized losslessly by the app, callable through `CallApi`, and verified by
MockWebServer-backed tests so that downstream WebRTC tickets build on a frozen,
tested surface.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace/applicationId base `com.testlogon.android`.
- **Module layering:** `CallApi` lives in `core-network`
  (`com.testlogon.android.core.network.api`); DTOs live in `core-network`'s
  `dto` package (`com.testlogon.android.core.network.dto.call`). Domain mapping
  to `core-model` is **out of scope** here and is handled in the WebRTC feature
  module (AND-289+) / the messaging mappers ticket AND-126.
- **Depends on AND-027 (AuthApi / session endpoints):** establishes the shared
  Retrofit instance, the cookie-based session (persistent cookie jar AND-011),
  the `X-CSRF-Token` interceptor (AND-012), the 401→`/ui/session/refresh`
  authenticator (AND-013), Moshi setup (AND-010), and the `ApiResult<T>`
  wrapper (AND-018). `CallApi` is registered on that same Retrofit builder.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json` is authoritative; the
  schemas in §5 were extracted directly from it.
- **Web reference:** API layer under `frontend/src/api/endpoints/*.ts` and shared
  types in `frontend/src/api/types.ts` (call types mirror these DTOs).
- **Sibling DTO tickets for style precedent:** AND-026 (auth DTOs/adapters),
  AND-120 (messaging API + DTOs). Follow the same naming, nullability, and
  adapter conventions.
- **Note on auth params:** the OpenAPI lists `authorization`/`X-SESSION-ID`
  headers on these operations. On Android, session identity rides on the cookie
  jar + CSRF header injected by the shared OkHttp interceptors; these header
  parameters are therefore **not** modeled as `@Header` arguments in `CallApi`
  (matching how AND-027 handled the same headers). The `user_sub` /
  `X-IMPERSONATION-TOKEN` parameters on `billing`/`heartbeat` are likewise
  server-derived for first-party use and are not surfaced on the interface.

## 3. Functional Requirements

FR-1. Provide a Retrofit `CallApi` interface covering exactly the nine
call-control operations in §5: `invite`, `accept`, `decline`, `end`, `timeout`,
`heartbeat`, `signal`, `turn-credentials`, `billing`.

FR-2. Each operation returns `ApiResult<T>` (AND-018) where `T` is the typed
success DTO, so callers get uniform success/error handling. Suspend functions.

FR-3. Provide Moshi DTOs for every request and response body in the contract,
with `@Json(name = …)` for every snake_case field and Kotlin-idiomatic
property names.

FR-4. Default values present in the OpenAPI schema (e.g. `initial_mode="audio"`,
`paid=false`, `reason="declined"`, `reason="ended"`, `reason="no_answer"`,
`action="ok"`) must be honored as Kotlin default arguments so callers may omit
them and the emitted JSON matches the server's expectations.

FR-5. Nullable fields in the schema (e.g. `idempotency_key`, `rate_cents_per_min`,
`from_state`, `reason`, `client_ts`) must be modeled as nullable Kotlin types
(`String?`, `Int?`, `Long?`). Required fields are non-null.

FR-6. The `signal` and `turn-credentials` operations return typed error bodies
(`CallSignalingErrorOut`, `TurnCredentialErrorOut`) on 4xx/503; the contract must
make those parseable (see §7). The generic FastAPI 422 `HTTPValidationError`
maps through the existing AND-015 error model.

FR-7. `CallSignalingIn.payload` is a free-form JSON object (SDP offer/answer or
ICE candidate envelope). It must be modeled as `Map<String, Any?>` so arbitrary
WebRTC payloads pass through untouched; the DTO layer must not impose SDP/ICE
structure (that is AND-289/290's concern).

FR-8. Path templating: operations except `invite` take a `call_id` path segment;
`invite` posts to a fixed path. All paths are relative to the configured base URL
(AND-006 / AND-014 host selection).

FR-9. Provide an `IdempotencyKey` helper (UUIDv4 string) usable by callers for
the idempotent-bodied operations (`accept`, `end`, `timeout`, `invite`). The DTOs
accept a caller-supplied key; generation policy is the caller's (downstream).

## 4. Technical Design

Package: `com.testlogon.android.core.network` (interface) and
`com.testlogon.android.core.network.dto.call` (DTOs).

```kotlin
// core-network/api/CallApi.kt
interface CallApi {

    @POST("messaging/messages/calls/invite")
    suspend fun invite(@Body body: CallInviteIn): ApiResult<CallInviteOut>

    @POST("messaging/messages/calls/{callId}/accept")
    suspend fun accept(
        @Path("callId") callId: String,
        @Body body: CallAcceptIn = CallAcceptIn(),
    ): ApiResult<CallActionOut>

    @POST("messaging/messages/calls/{callId}/decline")
    suspend fun decline(
        @Path("callId") callId: String,
        @Body body: CallDeclineIn = CallDeclineIn(),
    ): ApiResult<CallActionOut>

    @POST("messaging/messages/calls/{callId}/end")
    suspend fun end(
        @Path("callId") callId: String,
        @Body body: CallEndIn = CallEndIn(),
    ): ApiResult<CallActionOut>

    @POST("messaging/messages/calls/{callId}/timeout")
    suspend fun timeout(
        @Path("callId") callId: String,
        @Body body: CallTimeoutIn = CallTimeoutIn(),
    ): ApiResult<CallActionOut>

    @PATCH("messaging/messages/calls/{callId}/heartbeat")
    suspend fun heartbeat(
        @Path("callId") callId: String,
        @Body body: HeartbeatIn = HeartbeatIn(),
    ): ApiResult<HeartbeatOut>

    @POST("messaging/messages/calls/{callId}/signal")
    suspend fun signal(
        @Path("callId") callId: String,
        @Body body: CallSignalingIn,
    ): ApiResult<CallSignalingOut>

    @POST("messaging/messages/calls/{callId}/turn-credentials")
    suspend fun turnCredentials(
        @Path("callId") callId: String,
    ): ApiResult<TurnCredentialsOut>

    @GET("messaging/messages/calls/{callId}/billing")
    suspend fun billing(
        @Path("callId") callId: String,
    ): ApiResult<CallBillingStatusOut>
}
```

`ApiResult<T>` is the AND-018 sealed type; the existing `CallAdapter.Factory`
registered on the shared Retrofit (AND-010/AND-018) decodes success bodies and
routes error bodies through the AND-015 mapper. `CallApi` is provided by Hilt:

```kotlin
// core-network/di/CallApiModule.kt
@Module
@InstallIn(SingletonComponent::class)
object CallApiModule {
    @Provides @Singleton
    fun provideCallApi(retrofit: Retrofit): CallApi = retrofit.create(CallApi::class.java)
}
```

DTOs are plain Moshi data classes (KSP `MoshiCodegen`). Example shape:

```kotlin
@JsonClass(generateAdapter = true)
data class CallInviteIn(
    @Json(name = "call_id") val callId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "callee_user_id") val calleeUserId: String,
    @Json(name = "initial_mode") val initialMode: String = "audio",
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
    @Json(name = "paid") val paid: Boolean = false,
    @Json(name = "rate_cents_per_min") val rateCentsPerMin: Int? = null,
)
```

The `payload` field on `CallSignalingIn` uses Moshi's built-in
`Map<String, Any?>` adapter (already available via the standard `Moshi` from
AND-010; if a Kotlin `Any` adapter is needed it is registered there, not in this
ticket). A small enum-like `object CallSignalType` of `String` constants
(`"offer"`, `"answer"`, `"ice"`, `"bye"`) is provided for caller convenience but
the wire field stays a raw `String` to remain forward-compatible.

```kotlin
object CallSignalType { const val OFFER="offer"; const val ANSWER="answer"
    const val ICE="ice"; const val BYE="bye" }

object IdempotencyKey { fun new(): String = UUID.randomUUID().toString() }
```

## 5. API Contract

All paths relative to base URL. Headers `Cookie` + `X-CSRF-Token` are added by
shared interceptors (AND-011/012); not modeled per-call.

**POST `messaging/messages/calls/invite`** → `200 CallInviteOut` | `422`
```jsonc
// CallInviteIn
{ "call_id":"c_01H...", "conversation_id":"conv_123", "callee_user_id":"u_456",
  "initial_mode":"audio", "idempotency_key":null, "paid":false,
  "rate_cents_per_min":null }
// CallInviteOut
{ "call_id":"c_01H...", "conversation_id":"conv_123", "caller_user_id":"u_001",
  "callee_user_id":"u_456", "state":"ringing", "initial_mode":"audio",
  "start_ts":1733400000, "paid":false, "rate_cents_per_minute":null }
```

**POST `…/{call_id}/accept`** → `200 CallActionOut` | `422`
`CallAcceptIn = { "idempotency_key": null }`

**POST `…/{call_id}/decline`** → `200 CallActionOut` | `422`
`CallDeclineIn = { "reason": "declined" }`

**POST `…/{call_id}/end`** → `200 CallActionOut` | `422`
`CallEndIn = { "reason": "ended", "idempotency_key": null }`

**POST `…/{call_id}/timeout`** → `200 CallActionOut` | `422`
`CallTimeoutIn = { "reason": "no_answer", "idempotency_key": null }`

```jsonc
// CallActionOut (shared by accept/decline/end/timeout)
{ "call_id":"c_01H...", "conversation_id":"conv_123", "state":"ended",
  "from_state":"connected", "reason":"ended", "event_ts":1733400123,
  "voicemail_eligible":false }
```

**PATCH `…/{call_id}/heartbeat`** → `200 HeartbeatOut` | `422`
```jsonc
// HeartbeatIn
{ "client_ts": 1733400100 }            // nullable
// HeartbeatOut
{ "call_id":"c_01H...", "elapsed_seconds":42, "total_cost_cents":0,
  "balance_remaining_cents":0, "rate_cents_per_minute":0,
  "next_bill_in_seconds":18, "warn_low_balance":false, "minutes_remaining":0.0,
  "max_duration_warning":false, "action":"ok" }
```

**POST `…/{call_id}/signal`** → `200 CallSignalingOut` | `400/403/404/409/429/503
CallSignalingErrorOut` | `422`
```jsonc
// CallSignalingIn
{ "type":"offer", "event_id":"evt_01H...", "conversation_id":"conv_123",
  "recipient_user_id":"u_456", "nonce":"n_abc", "sent_at":1733400000,
  "payload": { "sdp":"v=0...", "sdpMLineIndex":0 } }
// CallSignalingOut
{ "event_id":"evt_01H...", "call_id":"c_01H...", "conversation_id":"conv_123",
  "event_type":"offer", "delivered_to":"u_456", "status":"delivered" }
// CallSignalingErrorOut
{ "code":"rate_limited", "message":"too many signals" }
```

**POST `…/{call_id}/turn-credentials`** → `200 TurnCredentialsOut` |
`400/403/404/409/503 TurnCredentialErrorOut` | `422`
```jsonc
// TurnCredentialsOut
{ "ttl_seconds":86400, "expires_at":1733486400,
  "ice_servers":[ { "urls":["turn:turn.example:3478"], "username":"u",
                    "credential":"c" } ] }
// TurnCredentialErrorOut
{ "detail": { "code":"call_not_active", "message":"no active call" } }
```

**GET `…/{call_id}/billing`** → `200 CallBillingStatusOut` | `422`
```jsonc
{ "call_id":"c_01H...", "paid":true, "rate_cents_per_minute":50,
  "total_cost_cents":150, "total_billed_seconds":180, "billing_cycle_count":3,
  "caller_balance_remaining_cents":850, "platform_fee_bps":2000,
  "max_duration_seconds":3600, "elapsed_seconds":182, "billing_status":"active" }
```

Nested DTOs: `TurnIceServerOut { urls:List<String>, username:String,
credential:String }`, `TurnCredentialErrorDetailOut { code:String,
message:String }`.

## 6. Data & State Management

This ticket introduces **no persisted state** — no Room entities, no DataStore
keys, no in-memory caches. It is a stateless network contract. Call/session
state (current call, billing ticker, ICE server cache with `expires_at` TTL) is
owned by the WebRTC feature module (AND-289+) and is explicitly out of scope.

The only stateful concern this ticket exposes is the `expires_at` / `ttl_seconds`
fields on `TurnCredentialsOut`, which downstream AND-291 will use to decide when
to re-fetch; this ticket just guarantees those fields round-trip as `Long`
(epoch seconds) and `Int` respectively. `start_ts`, `event_ts`, `sent_at`,
`client_ts` are likewise epoch-second `Long`s.

DTO immutability: all DTOs are immutable `data class`es; no mutable collections
are exposed (`payload` is a read `Map`, `ice_servers`/`urls` are `List`).

## 7. Error Handling & Resilience

- All operations return `ApiResult<T>` (AND-018). Transport/HTTP failures are
  mapped by the shared `ApiResult` call adapter; FastAPI `detail` shapes
  (string | `[{msg}]` | `{code,…}`) are normalized by AND-015's error mapper.
- **Typed signaling errors:** for `signal`, the non-422 4xx/503 bodies are
  `CallSignalingErrorOut {code,message}`. The error branch of `ApiResult` must
  surface `code`/`message`; provide a parser so callers can switch on `code`
  (e.g. `rate_limited`, `not_found`, `conflict`). Implementation: register a
  best-effort error-body decode in the shared error mapper keyed on the presence
  of top-level `code`+`message`. No retry is performed for `signal` (POST, not
  idempotent at the transport layer; ordering matters).
- **Typed TURN errors:** `turn-credentials` returns
  `TurnCredentialErrorOut {detail:{code,message}}` (note the `detail` nesting,
  distinct from the signaling shape). Both must be parseable.
- **Retry policy:** Per project policy, bounded backoff retry is for **idempotent
  GETs only** (AND-016). Of these operations only `billing` (GET) is eligible for
  the AND-016 retry interceptor; all POST/PATCH operations are **excluded** from
  automatic retry. Caller-driven retries of `accept`/`end`/`timeout`/`invite`
  rely on the `idempotency_key` field for server-side dedup.
- **Timeouts:** inherit the ~20s OkHttp timeouts from AND-009 (unreliable dev
  host). `turn-credentials` and `signal` failures must not crash; they return a
  failed `ApiResult` for the caller to handle.
- **401 handling:** the AND-013 authenticator transparently calls
  `/ui/session/refresh` once and retries; no per-call logic needed.

## 8. Security & Privacy

- Session is cookie-based over the shared jar (AND-011); no tokens are passed in
  DTOs. The `authorization`/`X-SESSION-ID`/`X-IMPERSONATION-TOKEN` parameters in
  OpenAPI are intentionally **not** modeled to avoid leaking/duplicating session
  material into request bodies.
- **TURN credentials are short-lived secrets.** `TurnCredentialsOut.username`
  and `.credential` must never be logged, persisted to disk in this ticket, or
  included in crash/telemetry payloads. The DTO is held in memory only; redaction
  is enforced in §10.
- `CallSignalingIn.payload` carries SDP, which can include IP candidates and
  fingerprints; treat as sensitive — never log payload contents.
- Dev backend is plaintext HTTP; this is a known dev-only condition. No
  credentials beyond session cookies traverse the wire from this layer.
- No PII is stored. User IDs (`callee_user_id`, `recipient_user_id`, etc.) are
  opaque identifiers handled in-memory only.

## 9. Accessibility & i18n

N/A for this ticket — it contains no UI, strings, or user-facing surfaces.
Server-supplied `reason`/`code`/`billing_status`/`action`/`state` values are
machine tokens, not display strings; their localization to user-facing copy is
owned by the call UI tickets in epic E39 (AND-289+) and string plumbing
(AND-111). DTOs preserve the raw tokens so the UI layer can map them.

## 10. Telemetry & Logging

- Reuse the redacting OkHttp logging interceptor configured in AND-009/AND-052.
  Extend its redaction allow/deny rules so that request/response bodies for
  `…/turn-credentials` and `…/signal` are **redacted** (bodies replaced with
  `<redacted>`), protecting TURN secrets and SDP.
- Emit a structured debug log (no body) per call op: `op` name, `call_id`
  (truncated/hashed if telemetry is remote), HTTP status, latency ms. No PII,
  no credentials, no SDP.
- A lightweight `CallApiTelemetry` tag/constant is added for filtering; actual
  analytics events for call lifecycle are owned by AND-285/AND-171-style
  heartbeat analytics and the WebRTC feature, not here.
- `heartbeat`/`billing` numeric fields may be logged at debug for diagnostics but
  must not be sent to remote analytics from this layer.

## 11. Testing Strategy

Unit tests in `core-network` using the AND-046 MockWebServer harness +
`core-testing` fixtures. Coverage:

1. **Round-trip serialization** for every DTO: build the Kotlin object →
   serialize with the project `Moshi` → assert JSON equals the captured fixture;
   then deserialize the fixture → assert field-by-field equality. One fixture
   file per response DTO under `core-network/src/test/resources/fixtures/call/`.
2. **Default-value emission:** assert `CallInviteIn()` with defaults emits
   `"initial_mode":"audio"`, `"paid":false`; `CallDeclineIn()` emits
   `"reason":"declined"`; `end`/`timeout` defaults likewise.
3. **Nullability:** assert `idempotency_key:null`, `rate_cents_per_min:null`,
   `from_state:null`, `client_ts:null` deserialize to Kotlin `null` and that
   absent keys also yield `null` (no exception).
4. **Endpoint correctness (MockWebServer):** for each `CallApi` method assert the
   recorded request method (POST/PATCH/GET), path (including `call_id`
   substitution), `Content-Type: application/json`, and that the `X-CSRF-Token`
   header is present (interceptor integration).
5. **Free-form payload:** `CallSignalingIn.payload` with a nested SDP map
   round-trips byte-for-byte (key order tolerant) without structural loss.
6. **Typed error bodies:** enqueue a 429 with `CallSignalingErrorOut` and a 404
   with `TurnCredentialErrorOut`; assert the `ApiResult` error branch parses
   `code`/`message` (and the nested `detail` for TURN).
7. **422 mapping:** enqueue `HTTPValidationError` and assert it flows through the
   AND-015 mapper.

Fixtures are derived from `/openapi.json` example shapes (see §5). Target ≥90%
line coverage on the DTO + API package. Acceptance ("Call payloads map
(tested)") is satisfied by tests 1–3 and 5–6 passing in CI (AND-050).

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session endpoints) — supplies the shared
  Retrofit, cookie jar, CSRF + 401-refresh interceptors, Moshi, and
  `ApiResult`. Transitively depends on AND-010, AND-011, AND-012, AND-013,
  AND-015, AND-016, AND-018.
- **Blocks / enables:** AND-289 (PeerConnection wrapper) consumes these DTOs;
  AND-290 (signaling transport over `/signal` + SSE) calls `signal` and consumes
  `CallSignalingIn/Out`; AND-291 (TURN/STUN config) calls `turn-credentials`;
  AND-292 (media capture) is downstream of the same call lifecycle. The call UI
  and ViewModels in epic E39 build on top.
- Sequencing: implement DTOs first, then `CallApi`, then Hilt module, then tests.
  No backend changes required (contract already deployed).

## 13. Risks & Open Questions

- **R1 — `signal` payload schema is opaque (`object`).** Mitigation: model as
  `Map<String,Any?>`; freeze SDP/ICE envelope shape in AND-290. Risk that the
  server expects a specific envelope key set; verify against a staged exchange.
- **R2 — Header auth divergence.** OpenAPI declares `authorization`/`X-SESSION-ID`
  headers; we rely on cookies. If the dev backend rejects cookie-only auth for
  these routes, we may need to thread `X-SESSION-ID` explicitly. **Open
  question:** confirm cookie-only acceptance against `18.222.237.167:8000`.
- **R3 — Two distinct error shapes** (`{code,message}` for signal vs
  `{detail:{code,message}}` for TURN) plus the generic FastAPI `detail`. Mapping
  must distinguish all three; covered by tests 6–7.
- **R4 — `minutes_remaining` is a JSON number (float).** Model as `Double` (not
  `Int`) to avoid truncation; verify Moshi handles integer-valued floats.
- **R5 — Group-call endpoints** (`/ui/calls/group/*`) exist in the API but are
  **out of scope** for AND-295 (1:1 only). Open question: which milestone owns
  group calls? Not blocking.
- **R6 — `idempotency_key` server semantics** (dedup window, scope) are
  undocumented; downstream retry logic (AND-289) must validate.

## 14. Acceptance Criteria

1. `CallApi` interface exists in `core-network` with all nine operations,
   correct HTTP verbs/paths per §5, returning `ApiResult<T>` suspend functions,
   and is provided via Hilt.
2. All request DTOs (`CallInviteIn`, `CallAcceptIn`, `CallDeclineIn`,
   `CallEndIn`, `CallTimeoutIn`, `HeartbeatIn`, `CallSignalingIn`) and response
   DTOs (`CallInviteOut`, `CallActionOut`, `HeartbeatOut`, `CallSignalingOut`,
   `CallSignalingErrorOut`, `TurnCredentialsOut`, `TurnIceServerOut`,
   `TurnCredentialErrorOut`, `TurnCredentialErrorDetailOut`,
   `CallBillingStatusOut`) exist with `@Json` names and correct nullability.
3. **Call payloads map (tested):** round-trip serialization tests pass for every
   DTO against fixtures; default values and nullable fields verified.
4. MockWebServer tests confirm each method's verb, path (`call_id` substituted),
   and JSON content type; CSRF header present.
5. Typed signaling and TURN error bodies parse into their DTOs via the
   `ApiResult` error branch.
6. TURN credential and signaling bodies are redacted in logs.
7. `billing` is the only operation eligible for AND-016 GET retry; POST/PATCH
   are excluded.
8. All new tests pass in CI (AND-050); ktlint/detekt (AND-005) clean.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.core.network`
  (interface + DTOs + Hilt module).
- All acceptance criteria in §14 met; unit + MockWebServer tests green in CI;
  ≥90% coverage on the new package.
- ktlint/detekt pass; no new lint baseline suppressions.
- Log redaction rules for `turn-credentials`/`signal` verified by a test or
  manual interceptor check.
- No persisted state, UI, or WebRTC wiring introduced (scope respected).
- Public DTO/API surface reviewed by a messaging/WebRTC owner so AND-289/290/291
  can build against a frozen contract; KDoc on `CallApi` notes the cookie-auth
  decision and the out-of-scope group-call endpoints.
- Spec linked from the PR; downstream tickets (AND-289–292) updated to reference
  the concrete DTO names.

---
id: AND-324
title: Liveness call
milestone: M7
epic: E42
priority: P2
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-290, AND-323]
blocks: []
---

# AND-324 — Liveness call

> **REVIEW NOTE (2026-06-06, AND-324 amend):** This spec was drafted around a
> self-service in-app WebRTC negotiation model (offer/answer/ICE, signaling
> control prompts, in-app verdict). **That model is contradicted by the
> authoritative backend OpenAPI and the web reference app.** The real
> `kycLivenessCall` feature is a **scheduled appointment**: the owner books a
> live video verification call against an existing KYC `case_id`, and a human
> verifier later conducts it and records pass/fail. The call media itself is
> reached via an opaque `join_url` (an external/hosted video link), not via an
> in-app `RtcPeerConnection`. There is **no** `/signal` SDP/ICE exchange, no
> `peer_id`/`signal_room`, no `ice_servers`, and no automated prompt script in
> the contract. Sections below are corrected inline; the now-unsupported WebRTC
> design is flagged where it appears. Full audit in §16.

## 1. Overview & Goal

This ticket delivers `kycLivenessCall`: a **scheduled liveness verification
call** in which the user books a live video verification appointment against an
existing KYC `case_id`, and a human verifier later joins and confirms the person
is a live human (anti-spoof) rather than a replayed photo or video. It
complements the still-image **facial comparison** flow (AND-323).

[CORRECTED] The deliverable is a `feature-kyc` sub-flow comprising a scheduling
+ status screen (`LivenessCallScreen`, Compose: schedule form + list of the
user's calls with status/result + a "Join call" action that opens `join_url`),
a `LivenessCallViewModel` exposing `StateFlow<LivenessUiState>`, and a
`LivenessCoordinator`/repository in `core-data` over **one HTTP surface only**:
the `/ui/kyc/liveness-call` family on `KycApi` (AND-319), used to schedule,
list, fetch status, and cancel calls. **No WebRTC, signaling (`SignalingClient`,
AND-290), or `RtcPeerConnection` (AND-289) is involved** — the actual video
session happens outside the app at `join_url`. The earlier dependence on AND-289/
AND-290 is therefore **not required by the verified contract** (see §2, §16);
the app launches `join_url` via an `Intent`/Custom Tab rather than negotiating
media itself.

**Definition of success (source acceptance — "Liveness session connects +
completes"):** from the KYC case/requirements screen the user schedules a
liveness call, the call appears with `status == "scheduled"` and a `join_url`,
the user can join it, and the backend later reflects a terminal
`status`/`result` (`passed` / `failed`, or `cancelled` / `expired`) that is
surfaced to the user. [CORRECTED] The contract has **no** `review` verdict and
**no** `RtcSessionState.Connected` milestone owned by this app.

## 2. Context & References

- **Module / location:** `feature-kyc` (UI + ViewModel) under
  `com.testlogon.android.feature.kyc.liveness`; orchestration in `core-data`
  under `com.testlogon.android.core.data.kyc`. Layering respected: `app ->
  feature-kyc -> core-* (core-data, core-network, core-webrtc, core-signaling,
  core-model, core-ui)`. No `feature-*` symbol leaks into `core-*`.
- **AND-323 (Facial comparison, dep):** sibling KYC requirement. AND-324 reuses
  AND-323's shared `KycRepository`/case entry point and status-refresh path.
  [CORRECTED] AND-324 does **not** need AND-323's `CameraPermissionGate` or
  front-camera preview plumbing: the verified flow captures no media in-app (the
  call runs at `join_url`). Camera/mic permission is therefore **not** a
  requirement of this ticket. [UNVERIFIED] The exact requirement key/`type` that
  surfaces the scheduling entry point (e.g. `liveness_call`) is not visible in
  the liveness-call schemas; the verified linkage is the KYC **`case_id`** that
  the schedule request requires (`KycLivenessCallScheduleRequest.case_id`). See
  §16 open assumptions.
- **AND-290 (Signaling transport):** [CORRECTED] **Not used by the verified
  contract.** There is no `/signal` exchange in the liveness-call API; the call
  is reached via `join_url`. Drop AND-290 as a dependency for this ticket
  (retained only if a future in-app media model is adopted — not in scope).
- **AND-289 (PeerConnection wrapper):** [CORRECTED] **Not used.** No
  `RtcPeerConnection`/Offerer/SDP/ICE work is part of AND-324 per the OpenAPI +
  web reference. The app does not carry liveness media.
- **AND-319 (KYC API + DTOs, transitive):** `KycApi`, KYC DTO/enum conventions,
  and the authenticated Retrofit pipeline. [CORRECTED] AND-324 adds the
  liveness-call sub-endpoints under **`/ui/kyc/liveness-call*`** (NOT
  `/v1/kyc/liveness/*`) to that same authenticated Retrofit. Auth on this seam
  (verified from `src/api/client.ts`) is `Authorization: Bearer <accessToken>`
  **plus** the `ui_csrf` cookie echoed as `X-CSRF-Token`, sent with cookies
  (`credentials: include`); optional `X-SESSION-ID` and `X-IMPERSONATION-TOKEN`
  headers and an optional `user_sub` query param exist on these routes. 401 →
  one `POST /ui/session/refresh` then retry (client.ts), else logout.
- **AND-291 (TURN/STUN credentials):** [CORRECTED] Irrelevant — no NAT traversal
  is performed in-app; remove as a dependency. No `ice_servers` field exists in
  any liveness-call schema.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; ~20s timeouts, bounded backoff for idempotent
  GETs only). OpenAPI at `/openapi.json`. [CORRECTED] Verified web reference is
  `src/api/endpoints/kycLivenessCall.ts`, `src/api/types.ts`, and
  `src/pages/kyc/KycLivenessCallSchedulePage.tsx` (owner flow) /
  `KycLivenessCallVerifierPage.tsx` (verifier flow). Endpoints reconciled in §5
  and §16 (OQ-1 resolved).
- **Stack pins:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP),
  Coroutines/Flow, Media3 not used here (WebRTC owns its own surface), webrtc-
  android (via AND-288/289), minSdk 24 / compileSdk/targetSdk 35, JDK 17,
  AGP 8.7.3 / Gradle 8.9.

## 3. Functional Requirements

> [CORRECTED] The original FR-1..FR-8 assumed an in-app WebRTC negotiation. They
> are rewritten below to the verified scheduling model. The signaling/PeerConnection
> wording is removed; verdict authority is the call's `status`/`result` fetched
> over HTTP.

FR-1 **Entry & gating.** The liveness flow is reachable from a KYC case context.
The schedule action requires a valid `case_id` (verified required field). No
camera/mic permission is requested by this app. [UNVERIFIED] Whether a specific
`KycRequirement.key`/`type` gates visibility is not expressed in the liveness-call
schemas — see §16.

FR-2 **Schedule call.** [CORRECTED] `POST /ui/kyc/liveness-call` with body
`{ case_id, scheduled_at (unix int, required), duration_minutes (5..60, default
15), note?, verifier_sub? }` returns **`201`** with a `KycLivenessCallOut`
(`call_id`, `case_id`, `status`, `scheduled_at`, `duration_minutes`, optional
`join_url`, `result`, etc.). The ViewModel moves `Idle → Scheduling → Scheduled`.

FR-3 **List & view calls.** [CORRECTED] `GET /ui/kyc/liveness-call` returns
`{ calls: KycLivenessCallOut[] }` (the user's calls). `GET /ui/kyc/liveness-call/
{callId}` returns a single `KycLivenessCallOut`. `GET /ui/kyc/liveness-call/case/
{caseId}` returns `{ verification_call: KycLivenessCallStatusOut | null }` (owner
view, no verifier identity). Each call renders its `status` badge, scheduled time
(`scheduled_at * 1000`), duration, and `result` if present. **No in-app media,
prompts, or PiP surface.**

FR-4 **Join the call.** [CORRECTED] There are **no automated prompts** in the
contract. When a call has a non-null `join_url`, the app exposes a "Join call"
action that opens `join_url` externally (Custom Tab / `ACTION_VIEW` intent),
exactly as the web app renders `<a href={join_url}>` (verified
`KycLivenessCallSchedulePage.tsx`). The verifier (a human) conducts the call and
records the outcome out-of-band via the admin endpoints (`/admin/{call_id}/
conduct`, `/admin/{call_id}/result`) — **not part of this owner-facing ticket**.

FR-5 **Completion & result.** [CORRECTED] The session has no in-app verdict
channel. The app learns the outcome by re-fetching the call (`GET
.../liveness-call/{callId}` or `.../case/{caseId}`) until `status` is terminal
(`passed`/`failed`/`cancelled`/`expired`) and reading `result`
(`passed`/`failed`/`null`). There is **no** `review` value. The list/status view
is refreshed (web invalidates the `["kyc","liveness-call","mine"]` query).

FR-6 **Result reflection.** [CORRECTED] On `passed` the KYC status/case is
refreshed (shared `KycRepository` refresh) so the case reflects the satisfied
requirement. `failed`/`expired`/`cancelled` let the user schedule a new call.
[UNVERIFIED] `max_attempts`/cooldown does not exist in any liveness-call schema —
remove that concept (see §16).

FR-7 **Cancel.** [CORRECTED] The owner cancels a `scheduled` or `in_progress`
call via `POST /ui/kyc/liveness-call/{callId}/cancel` → returns the updated
`KycLivenessCallOut` with `status:"cancelled"` (verified: web enables Cancel only
for `scheduled`/`in_progress`). There is **no** signaling `BYE` / `close()`
teardown because there is no in-app peer connection.

FR-8 **Multiple calls.** [CORRECTED] The API/web place **no single-active-session
constraint** on the client; `listMyKycLivenessCalls` returns a list and the web
imposes no client-side guard. Do not invent an in-flight latch beyond ordinary
double-submit debouncing of the schedule button (web disables the button while
`scheduleMutation.isPending`).

## 4. Technical Design

> [CORRECTED] The technical design is realigned to the scheduling model. The UI
> state, ViewModel, and coordinator no longer model permission/connection/prompt
> phases. §4.4 (signaling↔peer bridge) and §4.5 (offerer negotiation) describe a
> non-existent transport and are **struck out** below — kept only as a record of
> the original (incorrect) design.

### 4.1 UI state

```kotlin
package com.testlogon.android.feature.kyc.liveness

// [CORRECTED] No permission / Connecting / InCall / prompt states — there is no
// in-app media. The screen is a scheduler + list of the user's calls.
sealed interface LivenessUiState {
    data object Loading : LivenessUiState                         // initial list fetch
    data class  Ready(
        val calls: List<LivenessCallUi>,                         // user's calls
        val scheduling: Boolean = false,                          // schedule POST in flight
        val formError: String? = null,                            // 422 / validation message
    ) : LivenessUiState
    data class  Error(val error: KycError, val recoverable: Boolean) : LivenessUiState
}

data class LivenessCallUi(
    val callId: String,
    val caseId: String,
    val status: LivenessCallStatus,        // scheduled|in_progress|passed|failed|cancelled|expired
    val scheduledAtEpochSec: Long,
    val durationMinutes: Int,
    val result: LivenessResult?,           // PASSED | FAILED | null
    val joinUrl: String?,                  // present → "Join call" action
    val cancellable: Boolean,              // status in {scheduled, in_progress}
)

// [CORRECTED] enums match the verified contract exactly (UNKNOWN fallback per AND-319).
enum class LivenessCallStatus { SCHEDULED, IN_PROGRESS, PASSED, FAILED, CANCELLED, EXPIRED, UNKNOWN }
enum class LivenessResult { PASSED, FAILED, UNKNOWN }
```

### 4.2 ViewModel

```kotlin
@HiltViewModel
class LivenessCallViewModel @Inject constructor(
    private val coordinator: LivenessCoordinator,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    val uiState: StateFlow<LivenessUiState>      // backed by repository list/state

    // [CORRECTED] scheduler/list actions — no permissions, no connect, no mic, no prompts.
    fun refresh()                                 // GET /ui/kyc/liveness-call
    fun schedule(caseId: String, scheduledAtEpochSec: Long, durationMinutes: Int, note: String?)
    fun cancel(callId: String)                    // POST .../{callId}/cancel
    fun onJoinClicked(callId: String): String?    // returns join_url to open externally
    override fun onCleared()
}
```

[CORRECTED] The ViewModel touches no libwebrtc/signaling (none exists here); it
drives the `LivenessCoordinator`/repository and maps `KycLivenessCallOut` →
`LivenessCallUi`.

### 4.3 Coordinator (orchestration, `core-data`)

```kotlin
package com.testlogon.android.core.data.kyc

interface LivenessCoordinator {
    val state: StateFlow<LivenessListState>
    suspend fun refresh(): ApiResult<Unit>                              // GET list
    suspend fun schedule(req: LivenessScheduleParams): ApiResult<LivenessCallUi>  // POST schedule (201)
    suspend fun cancel(callId: String): ApiResult<LivenessCallUi>       // POST .../cancel
    suspend fun statusForCase(caseId: String): ApiResult<LivenessCallUi?>
}

// [CORRECTED] No signaling/RTC factories injected — they are not used.
class DefaultLivenessCoordinator @Inject constructor(
    private val kycApi: KycApi,                                 // AND-319 (+ liveness-call methods)
    private val kycRepository: KycRepository,                    // case/status refresh on terminal
    @Dispatcher(IO) private val io: CoroutineDispatcher,
    private val clock: Clock,
    private val metrics: KycMetrics,
) : LivenessCoordinator
```

[CORRECTED] `LivenessListState` carries the user's calls; there is no
`RtcSessionState`/`SignalingState` to surface (no in-app media).

### 4.4 Signaling ↔ PeerConnection bridge — ~~STRUCK OUT (does not exist)~~

> [CORRECTED] The verified contract has **no `/signal` channel, no SDP/ICE, no
> `RtcPeerConnection`, and no in-call `control`/prompt messages**. The original
> `LivenessSignalingBridge` / `SignalType.CONTROL` design below is retained only
> as a record of the superseded approach and **must not be implemented**.

~~AND-324 implements `SignalingPort` by serializing SDP/ICE into `SignalingEnvelope`s
and feeding remote envelopes back into the `RtcPeerConnection`; liveness prompts
and verdicts travel as a `SignalType.CONTROL` message parsed by the coordinator.~~

### 4.5 Join flow (replaces "Negotiation flow (Offerer)")

[CORRECTED] There is no offer/answer negotiation. The owner flow is:

1. `kycApi.scheduleLiveness(case_id, scheduled_at, duration_minutes, note?)` →
   `201 KycLivenessCallOut`.
2. The call is listed; when `join_url` is non-null the user taps "Join call",
   which opens `join_url` externally (Custom Tab / `ACTION_VIEW`).
3. The human verifier conducts the call out-of-band and records pass/fail.
4. The app refreshes the call (`GET .../{callId}` or `.../case/{caseId}`) to read
   terminal `status`/`result`; on `passed`, `kycRepository.refresh()` updates the
   case. No teardown/close step exists (no in-app connection).

### 4.6 Hilt wiring

```kotlin
@Module @InstallIn(SingletonComponent::class)
abstract class LivenessModule {
    @Binds abstract fun bindCoordinator(impl: DefaultLivenessCoordinator): LivenessCoordinator
}
```

`feature-kyc` declares `implementation(project(":core-data"))`,
`":core-signaling"`, `":core-webrtc"`, `":core-network"`, `":core-model"`,
`":core-ui"`. No new third-party dependency is introduced (WebRTC artifact comes
from AND-288).

## 5. API Contract

> [CORRECTED] Reconciled against `/openapi.json` (paths `ui/kyc/liveness-call*`,
> tag `kyc-liveness-call`) and the web reference
> `src/api/endpoints/kycLivenessCall.ts` + `src/api/types.ts`. **The previously
> specified `/v1/kyc/liveness/start|{id}|cancel` surface, the start/SDP/ICE/
> prompts/verdict shapes, and the signaling control messages do not exist.** The
> verified surface and exact field shapes are below. Methods are added to
> `KycApi` (AND-319), reusing its authenticated transport (`Authorization:
> Bearer`, `X-CSRF-Token` from the `ui_csrf` cookie, cookies via the cookie jar;
> optional `X-SESSION-ID` / `X-IMPERSONATION-TOKEN`). Paths use the `/ui` prefix.

```kotlin
// added to KycApi (AND-319), package com.testlogon.android.core.network.kyc

// Owner endpoints
@Headers("Content-Type: application/json")
@POST("ui/kyc/liveness-call")                                    // returns 201
suspend fun scheduleLiveness(@Body body: LivenessScheduleReq): LivenessCallOut

@GET("ui/kyc/liveness-call")
suspend fun listMyLivenessCalls(): LivenessCallListResp           // idempotent

@GET("ui/kyc/liveness-call/{callId}")
suspend fun getLivenessCall(@Path("callId") callId: String): LivenessCallOut  // idempotent

@GET("ui/kyc/liveness-call/case/{caseId}")
suspend fun getLivenessCallForCase(@Path("caseId") caseId: String): LivenessCallStatusResp  // idempotent

@POST("ui/kyc/liveness-call/{callId}/cancel")                     // no body
suspend fun cancelLivenessCall(@Path("callId") callId: String): LivenessCallOut
```

**POST `ui/kyc/liveness-call`** (`schedule_liveness_call_…`) — auth as above.
Request body (`KycLivenessCallScheduleRequest`):
```json
{
  "case_id": "kyc_...",          // required, 1..128 chars
  "scheduled_at": 1749120600,    // required, unix timestamp (int) of call start
  "duration_minutes": 15,        // optional, default 15, 5..60
  "note": "anything for the verifier",   // optional, ≤500 chars, nullable
  "verifier_sub": null           // optional, ≤256 chars, nullable
}
```
Optional `user_sub` query param exists on this route. Response **`201`**
(`KycLivenessCallOut`):
```json
{
  "call_id": "lc_9f1c",
  "case_id": "kyc_...",
  "user_sub": null,
  "status": "scheduled",
  "scheduled_at": 1749120600,
  "duration_minutes": 15,
  "note": null,
  "verifier_sub": null,
  "result": null,
  "result_notes": null,
  "result_set_at": null,
  "recording_ref": null,
  "started_at": null,
  "join_url": null,
  "created_at": 1749100000,
  "updated_at": 1749100000
}
```
`status ∈ {scheduled, in_progress, passed, failed, cancelled, expired}` (required);
`result ∈ {passed, failed, null}`. Required fields per schema: `call_id`,
`case_id`, `status`. **OpenAPI documents only `201` and `422` (validation)** for
this route — `409`/`503` are NOT documented (treat any non-2xx generically; see
§7). `401`/`403` are handled by the shared transport (client.ts: 401 → one
`POST /ui/session/refresh` + retry).

**GET `ui/kyc/liveness-call`** (`list_my_liveness_calls_…`) → `200`
`KycLivenessCallListResponse`:
```json
{ "calls": [ { /* KycLivenessCallOut */ } ] }
```

**GET `ui/kyc/liveness-call/{callId}`** → `200` `KycLivenessCallOut`.

**GET `ui/kyc/liveness-call/case/{caseId}`** (`get_liveness_call_status_for_case…`)
→ `200` `KycLivenessCallStatusResponse` (owner view, no verifier identity):
```json
{ "verification_call": {
    "call_id": "lc_9f1c", "case_id": "kyc_...", "status": "passed",
    "scheduled_at": 1749120600, "duration_minutes": 15,
    "result": "passed", "join_url": null,
    "created_at": 1749100000, "updated_at": 1749121000 } }
```
`verification_call` may be `null` (no call for the case).

**POST `ui/kyc/liveness-call/{callId}/cancel`** (`cancel_my_liveness_call_…`,
no request body) → `200` `KycLivenessCallOut` with `status:"cancelled"`.

**Verifier/admin endpoints (NOT in this owner ticket, for reference):**
`GET .../admin/by-status?status=&limit=`, `GET .../admin/{call_id}`,
`POST .../admin/{call_id}/conduct`, `POST .../admin/{call_id}/result`
(`KycLivenessCallResultRequest`: `result` passed|failed, `notes` 1..2000 req,
`recording_linked` default true), `POST .../admin/{call_id}/cancel`. These power
the human verifier; the owner app does not call them.

**No in-call control/prompt/SDP/ICE messages exist** — that section is removed.

**DTOs** (`core-model/.../kyc`, `@JsonClass(generateAdapter = true)`, snake_case
via `@Json(name=)`, enums with `UNKNOWN` fallback like AND-319):
`LivenessScheduleReq` (← `KycLivenessCallScheduleRequest`),
`LivenessCallOut` (← `KycLivenessCallOut`),
`LivenessCallStatusOut` (← `KycLivenessCallStatusOut`),
`LivenessCallListResp` (← `KycLivenessCallListResponse`),
`LivenessCallStatusResp` (← `KycLivenessCallStatusResponse`).
FastAPI `detail` union (string | `{msg}` | array of `{msg}`; see client.ts
`normalizeErrorDetail`) mapped by AND-015 → `KycError`. No `ice_servers`/prompt/
score DTOs (they do not exist).

## 6. Data & State Management

- **No Room persistence.** [CORRECTED] A liveness *call* is server-side state;
  the app holds the fetched list/status in memory only. There is no `expires_at`
  field (the status enum has an `expired` value instead); there are no signaling
  envelopes/SDP/ICE to hold. The only persisted artifact is the cookie jar
  (AND-011), reused so the KYC HTTP calls share the authenticated session.
- **Source of truth:** [CORRECTED] the **server** is authoritative. The
  coordinator's `state` is just the last-fetched `calls` list / per-call
  `KycLivenessCallOut`; there is no `RtcPeerConnection.state`/`SignalingClient.state`
  to `combine` (they are not used). The ViewModel maps to `LivenessUiState`.
- **`SavedStateHandle`:** [CORRECTED] no in-flight call to re-attach. At most
  persist transient form input (case id / scheduled time / duration / note)
  across rotation; on relaunch simply re-`GET` the list. No `peer_id`/`session_id`.
- **Verdict reconciliation:** [CORRECTED] not applicable — there is no in-call
  control channel to reconcile against. The terminal `status`/`result` from the
  authenticated GET is the single source of truth (so §8's "authority" point is
  trivially satisfied: HTTP is the only channel).
- **KYC status refresh:** on terminal `passed`, refresh the KYC case via the
  shared `KycRepository` so the case/requirement reflects the result. [UNVERIFIED]
  The exact refresh method name (`refreshMe()`/`KycMeResp`) is owned by AND-319 and
  not confirmed in these sources — see §16.

## 7. Error Handling & Resilience

> [CORRECTED] Removed negotiation-timeout / ICE-loss / signaling-degrade /
> attempts-exhausted handling — none of those code paths exist (no media, no
> signaling, no `max_attempts` field). Error handling is ordinary REST.

- **Timeouts:** ~20s connect/read on all liveness HTTP calls (AND-009). Refresh
  of the list/status is an idempotent GET and may use bounded exponential backoff
  (full jitter, `BASE=1s`, `MAX=8s`, AND-016). `scheduleLiveness` /
  `cancelLivenessCall` (POST, non-idempotent) are **not** auto-retried;
  connection-level failures surface `Error(recoverable = true)` for a user retry.
- **422 validation:** [CORRECTED] the only documented error for schedule besides
  auth. Map the FastAPI `detail` (string | `{msg}` | array of `{msg}`, per
  client.ts `normalizeErrorDetail`) to `Ready(formError=…)` shown inline next to
  the schedule form (mirrors web `setError`).
- **401:** handled once by the shared transport (client.ts → one
  `POST /ui/session/refresh` then retry); a second 401 → `Error(AuthExpired)` and
  route to login (AND-025).
- **403:** permission/geo-blocked; map `detail.code` (e.g. `role_required*`,
  `geo_blocked`) to a clear message (web `mapAuthorizationError`). Non-recoverable.
- **404:** unknown/foreign `call_id`/`case_id` → `Error(Transport(404))`, refresh
  the list.
- **`expired`/`cancelled` status:** terminal, non-error states shown as a badge;
  the user may schedule a new call (no `max_attempts` gate exists).
- **Join failure:** if `join_url` is null/unopenable, disable/hide "Join call"
  (web only renders the link when `join_url` is present).
- **Idempotent cancel:** cancelling a call already terminal is harmless; reflect
  the server's returned status.

```kotlin
sealed interface KycError {                       // shared with AND-323 where overlapping
    data object AuthExpired : KycError            // double 401
    data object PermissionDenied : KycError       // 403 (role/geo)
    data class  Validation(val message: String) : KycError  // 422 schedule
    data class  Transport(val httpCode: Int?) : KycError    // 404 / other non-2xx / network
    data class  Unknown(val message: String?) : KycError
}
// [CORRECTED] removed MediaTimeout, VerifierUnavailable(503), AttemptsExhausted(409):
// none are produced by the verified contract.
```

## 8. Security & Privacy

- **Biometric sensitivity.** [CORRECTED] The actual video/biometric capture
  happens **outside this app** at `join_url` (an external/hosted session), so the
  app holds no live face/voice media. There is therefore **no in-app recording,
  frame capture, or media surface** to protect. `FLAG_SECURE` on a liveness
  *capture* surface is moot here; consider it only if `join_url` is ever rendered
  in an embedded WebView (not the current design — the web app uses a plain
  anchor link). The app must not log `join_url`, `recording_ref`, or `result_notes`.
- **Media encryption.** [CORRECTED] No in-app WebRTC/DTLS-SRTP path exists. The
  security of the call media is the responsibility of the hosted `join_url`
  endpoint, not this client. Removed the libwebrtc/SDP/ICE cleartext discussion.
  HTTP API security still applies: production HTTPS-only; dev plaintext host gated
  by the scoped `network_security_config.xml` cleartext entry (AND-006).
- **Server-side authority.** [CORRECTED] The terminal `status`/`result` come only
  from the authenticated GET — there is no client-trusted control channel to
  spoof. The server scopes calls to the authenticated principal (optional
  `user_sub` query / `X-SESSION-ID`); the owner endpoints return owner-safe views
  (`KycLivenessCallStatusOut` omits `verifier_sub`).
- **Auth.** [CORRECTED] All `/ui/kyc/liveness-call*` calls carry the authenticated
  transport: `Authorization: Bearer <accessToken>` **and** the `ui_csrf`-derived
  `X-CSRF-Token`, plus session cookies (verified `src/api/client.ts`). The earlier
  "no bearer tokens" claim was wrong. No `ice_servers`/TURN credentials exist.
- **Permissions.** [CORRECTED] **No `CAMERA`/`RECORD_AUDIO` permission is required
  by this app** (no in-app capture). Opening `join_url` uses an external Custom
  Tab/browser; only `INTERNET` is needed. If a future embedded-WebView approach is
  adopted, camera/mic permission would re-enter scope (out of scope now).
- **Redaction.** Exclude `join_url`, `recording_ref`, `result_notes`,
  `verifier_sub`, and tokens from logs (§10).

## 9. Accessibility & i18n

> [CORRECTED] No prompts/timers/call surface exist; a11y applies to the schedule
> form and the call list.

- **Form a11y.** The schedule form fields (KYC case id, scheduled date/time
  picker, duration selector, optional note) each have associated labels/content
  descriptions; the date/time uses an accessible picker. Validation errors (422)
  are announced via a live region (`Modifier.semantics { liveRegion =
  LiveRegionMode.Assertive }`) and associated with the offending field.
- **List a11y.** Each call row exposes a single semantic description combining
  case, scheduled time, duration, status, and result (not color/badge alone);
  status is conveyed as text, not just badge color.
- **Localization.** [CORRECTED] Map the verified `status`/`result` enums →
  localized `R.string.liveness_status_*` / `R.string.liveness_result_*`; all UI
  chrome ("Schedule call", "Join call", "Cancel", "No verification calls yet",
  error copy) are string resources — no hard-coded English. Scheduled times use
  locale-aware date/time formatting (web uses `toLocaleString` on
  `scheduled_at * 1000`); durations use locale-aware number formatting; layout is
  RTL-safe. Backend-supplied `note` is rendered verbatim.
- **Touch targets / focus:** "Schedule call", "Join call", and "Cancel" buttons
  ≥48dp with content descriptions; "Join call" announces that it opens an external
  browser.

## 10. Telemetry & Logging

- **Events** (shared analytics seam / `KycMetrics`, no new SDK): [CORRECTED] to
  the scheduling model —
  `liveness_schedule{durationMinutes, hasNote, result: ok|validation|error}`,
  `liveness_list_view{count}`,
  `liveness_join_clicked{callId}` (join_url opened externally),
  `liveness_cancel{callId, result: ok|error}`,
  `liveness_outcome{status, result}` (terminal observed via GET),
  `liveness_error{code, httpCode}`.
- **Redaction (strict):** [CORRECTED] never log `join_url`, `recording_ref`,
  `result_notes`, `verifier_sub`, or auth tokens. Log `call_id`/`case_id` as short
  ids; `status`/`result` as enums. (No media/SDP/ICE/score exist to redact.)
- **Levels:** list/state changes at `DEBUG`; validation/cancel at `INFO`; auth/
  permission failures at `ERROR`.

## 11. Testing Strategy

> [CORRECTED] The original T-1..T-10/E-1 tested a WebRTC negotiation that does
> not exist (fake signaling, fake peer, offer/answer, prompts, verdict
> reconciliation, media timeout, attempts-exhausted). They are replaced by the
> scheduling-model tests below; the **authoritative, traced test plan is §17**.

**Unit (JVM, `core-testing` fakes):**
- Coordinator happy path: `schedule()` issues the POST, returns `201` mapped to a
  `LivenessCallUi(status=SCHEDULED)`; `refresh()` maps the list; on a fetched
  terminal `passed`, `KycRepository` refresh is invoked.
- `cancel()` issues `POST .../{callId}/cancel`, maps returned `status=cancelled`.
- 422 schedule → `Ready(formError=…)` (FastAPI `detail` mapping).
- 401 path: first 401 → refresh → retry once; second 401 → `Error(AuthExpired)`.
- enum `UNKNOWN` fallback for unexpected `status`/`result` values.

**MockWebServer (`core-network`):**
- `scheduleLiveness` issues `POST /ui/kyc/liveness-call` with JSON body + Bearer +
  `X-CSRF-Token`, decodes `201 KycLivenessCallOut`. `listMyLivenessCalls` →
  `GET /ui/kyc/liveness-call`. `getLivenessCallForCase` → `GET .../case/{caseId}`
  (`verification_call` may be null). `cancelLivenessCall` → `POST .../{callId}/cancel`.
  Snake_case + enum-`UNKNOWN` fallback (committed fixtures under
  `core-model/src/test/resources/kyc/liveness/`).

**Compose UI (`feature-kyc` androidTest):**
- `LivenessCallScreen` renders the schedule form, validation error, the call list
  with status/result badges, an enabled "Join call" when `join_url` present, and a
  Cancel action only for `scheduled`/`in_progress`; TalkBack announces validation
  errors; "Join call" fires an `ACTION_VIEW` intent for `join_url`.

**Instrumented / staged (acceptance):**
- E-1 Against a staged backend, schedule a call, see it appear as `scheduled` with
  a `join_url`, then observe a verifier-recorded terminal `status`/`result`
  surfaced after refresh — the source acceptance "Liveness session connects +
  completes". Flaky dev host mitigated by treating E-1 as confirmatory with the
  unit/MockWebServer tests as the gate.

Coverage gate: ≥80% line coverage on `DefaultLivenessCoordinator` and the
ViewModel mapping (non-DI, non-UI-surface code).

## 12. Dependencies & Sequencing

> [CORRECTED] AND-290 (signaling), AND-289 (PeerConnection), AND-288 (WebRTC),
> and AND-291 (TURN/STUN) are **NOT dependencies** of the verified scheduling
> model. The frontmatter `depends_on: [AND-290, AND-323]` should be revised to
> drop AND-290 (kept in frontmatter to avoid silent scope changes — flag in PR).

- **AND-323 (Facial comparison) — hard dep.** [CORRECTED] Provides the shared KYC
  case/`KycRepository` entry point and status-refresh path AND-324 reuses. The
  camera-gate/front-camera plumbing is **not** reused (no in-app capture).
- **AND-319 — hard dep.** `KycApi` + KYC DTO/enum conventions and the
  authenticated transport (Bearer + CSRF + cookies, 401-refresh). AND-324 *adds*
  the five `/ui/kyc/liveness-call*` owner methods + DTOs to it.
- **Transitive/support:** AND-015/016/018 (error map, backoff, `ApiResult`),
  AND-025 (auth-gated routing), AND-022 (nav host), AND-011 (cookie jar).
- **Removed deps:** AND-290, AND-289, AND-288, AND-291 (no signaling/WebRTC/TURN).
- **Sequencing within the ticket:** (1) endpoints already confirmed against
  `/openapi.json` + `src/api/endpoints/kycLivenessCall.ts` (§5, OQ-1 resolved);
  (2) add liveness-call DTOs/methods to `KycApi` + MockWebServer round-trip tests;
  (3) build `DefaultLivenessCoordinator`/repository against fakes;
  (4) `LivenessCallViewModel` + `LivenessCallScreen` (scheduler + list);
  (5) staged E-1.
- **Blocks:** none in the source backlog (leaf of the KYC liveness sub-flow).

## 13. Risks & Open Questions

- **OQ-1 — RESOLVED.** [CORRECTED] The endpoints are `/ui/kyc/liveness-call*`
  (NOT `/v1/kyc/liveness/*`) and the model is a **scheduled appointment + human
  verifier**, not an in-app WebRTC/prompt session. Verified against `/openapi.json`
  (tag `kyc-liveness-call`) and `src/api/endpoints/kycLivenessCall.ts`. There is
  no automated-prompt mode and no `agent`/`automated` mode field.
- **OQ-2 — RESOLVED (moot).** [CORRECTED] No `/signal` control channel exists;
  prompts/verdict are not delivered in-app. Outcome (`status`/`result`) is read
  only via the authenticated GET. No dead-code branch to avoid.
- **OQ-3 — RESOLVED (moot).** [CORRECTED] No `ice_servers` field exists in any
  liveness-call schema; AND-291 is not a dependency.
- **OQ-4 — RESOLVED (moot).** [CORRECTED] No `max_attempts`/cooldown field exists;
  a `failed`/`expired` call simply lets the user schedule another (no client gate).
- **OQ-5 (new, open):** How is the scheduling entry point gated from the KYC case
  UI (which requirement key/`type`)? Not expressed in the liveness-call schemas —
  needs the KYC case/requirements contract (AND-319). See §16.
- **OQ-6 (new, open):** What is `join_url` (hosted vendor link? in-app deep link?)
  and is it safe to open in an external Custom Tab vs. an embedded WebView? The
  web app uses a plain external anchor; confirm the production URL scheme/host.
- **R-1:** Unreliable plaintext dev host makes E-1 flaky; mitigated by unit +
  MockWebServer tests as the gate and E-1 as confirmatory.
- **R-2:** [CORRECTED] No WebRTC/emulator-media instability risk (no in-app
  media). Emulator is sufficient for all UI/contract tests.
- **R-3:** [CORRECTED] Biometric media is handled by the external `join_url`
  session, not this app; the residual app risk is logging sensitive fields
  (`join_url`, `recording_ref`, `result_notes`) — mitigated by §10 redaction.
- **R-4:** [CORRECTED] No control-channel verdict spoofing risk (no such channel);
  outcome authority is the authenticated GET.

## 14. Acceptance Criteria

> [CORRECTED] Re-stated to the verified scheduling model. Trace tags point to §17.

- **AC-1 (source acceptance).** From the KYC case context the user schedules a
  liveness call (`POST /ui/kyc/liveness-call` → `201`, `status:"scheduled"`), can
  reach the call via its `join_url`, and the app surfaces the terminal
  `status`/`result` after the verifier completes it — "Liveness session connects +
  completes" (TC-AND-324-01, TC-AND-324-10).
- **AC-2.** `LivenessCallViewModel.uiState` traverses `Loading → Ready(calls,
  scheduling) → Ready(updated)`, and `Error` on failure, observable as a
  `StateFlow` (TC-AND-324-01, TC-AND-324-09).
- **AC-3.** `scheduleLiveness` posts to `POST /ui/kyc/liveness-call` with
  `Authorization: Bearer` + `X-CSRF-Token` + cookies and decodes `201`;
  `listMyLivenessCalls`/`getLivenessCall`/`getLivenessCallForCase` are the
  idempotent GETs; `cancelLivenessCall` POSTs `.../{callId}/cancel`; all DTOs
  (de)serialize the §5 JSON exactly with snake_case keys and `UNKNOWN` enum
  fallback (TC-AND-324-02, TC-AND-324-03, TC-AND-324-04).
- **AC-4.** When a call has a non-null `join_url`, the app opens it externally
  (`ACTION_VIEW`/Custom Tab); no in-app WebRTC/signaling is performed
  (TC-AND-324-06).
- **AC-5.** Terminal `status`/`result` is read only from the authenticated GET;
  on `passed` the shared `KycRepository` case refresh is invoked so the case
  reflects the result (TC-AND-324-05, TC-AND-324-10).
- **AC-6.** `422` validation, `403`, `404`, and double-401 each map to the correct
  `KycError`/`formError`; no crash (TC-AND-324-07, TC-AND-324-08, TC-AND-324-11).
- **AC-7.** Cancel of a `scheduled`/`in_progress` call calls
  `POST .../{callId}/cancel` and reflects `status:"cancelled"`; no sensitive field
  (`join_url`/`recording_ref`/`result_notes`/tokens) is logged (TC-AND-324-04,
  TC-AND-324-12).
- **AC-8.** Schedule-form validation errors are announced to TalkBack; status/
  result are localized via enums → string resources; all UI chrome is
  string-resourced and RTL-safe (TC-AND-324-09, TC-AND-324-13).

## 15. Definition of Done

- `LivenessCallScreen` (scheduler + call list), `LivenessCallViewModel`,
  `LivenessUiState`, and `DefaultLivenessCoordinator` implemented under
  `com.testlogon.android.feature.kyc.liveness` / `core.data.kyc`, building on
  Kotlin 2.0.21 / AGP 8.7.3 / Gradle 8.9 / JDK 17 with Hilt+KSP, layering
  respected (`feature-kyc -> core-data/-network/-model/-ui`). [CORRECTED] No
  dependency on `core-webrtc`/`core-signaling`.
- [CORRECTED] The **five** `/ui/kyc/liveness-call*` owner methods + DTOs are added
  to `KycApi`/`core-model` (AND-319 conventions), reconciled with `/openapi.json`
  (OQ-1..OQ-4 resolved, recorded in the PR; OQ-5/OQ-6 tracked).
- All §11/§17 unit + MockWebServer + Compose tests green; ≥80% coverage on the
  coordinator/ViewModel; staged E-1 demonstrated and captured (log linked in PR).
- [CORRECTED] No WebRTC/signaling code (none used); KYC case refresh shared with
  AND-323; `join_url` opened via external Custom Tab/`ACTION_VIEW`.
- [CORRECTED] No `FLAG_SECURE`/recording path needed (no in-app media); telemetry
  emitted with strict redaction (no `join_url`/`recording_ref`/`result_notes`/
  tokens); cleartext scoped to the dev host only.
- All UI strings localized + a11y-announced (form errors via live region); no
  hard-coded English.
- Code review approved on `android-port`; no new lint/Detekt errors; public
  coordinator/ViewModel API KDoc'd.

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer.

1. **Endpoints are `/ui/kyc/liveness-call*`, NOT `/v1/kyc/liveness/start|{id}|cancel`.**
   VERDICT: Corrected. SOURCE: OpenAPI `POST /ui/kyc/liveness-call`,
   `GET /ui/kyc/liveness-call`, `GET /ui/kyc/liveness-call/{call_id}`,
   `GET /ui/kyc/liveness-call/case/{case_id}`,
   `POST /ui/kyc/liveness-call/{call_id}/cancel`;
   `src/api/endpoints/kycLivenessCall.ts`.
2. **The feature is a scheduled appointment with a human verifier, not in-app
   WebRTC.** VERDICT: Corrected. SOURCE: schema `KycLivenessCallScheduleRequest`
   (`case_id`, `scheduled_at`, `duration_minutes`), admin ops
   `POST /ui/kyc/liveness-call/admin/{call_id}/conduct` and `.../result`;
   `src/pages/kyc/KycLivenessCallSchedulePage.tsx` (schedule form + call list).
3. **Schedule request body = `{case_id (req,1..128), scheduled_at (req, unix int),
   duration_minutes (5..60, default 15), note? (≤500), verifier_sub? (≤256)}`.**
   VERDICT: Verified. SOURCE: schema `KycLivenessCallScheduleRequest`;
   `src/api/types.ts: KycLivenessCallScheduleRequest`.
4. **Schedule responds `201` with `KycLivenessCallOut`; OpenAPI documents only
   `201` and `422`.** VERDICT: Corrected (was `200`; was claimed `409`/`503`).
   SOURCE: OpenAPI `POST /ui/kyc/liveness-call` responses (`201`,`422`);
   index line `resp=201:KycLivenessCallOut;422:HTTPValidationError`.
5. **`KycLivenessCallOut` fields and required set (`call_id`,`case_id`,`status`).**
   VERDICT: Verified. SOURCE: schema `KycLivenessCallOut`;
   `src/api/types.ts: KycLivenessCallOut`.
6. **`status` enum = `{scheduled,in_progress,passed,failed,cancelled,expired}`.**
   VERDICT: Corrected (was `{pending,in_progress,completed,failed,expired,cancelled}`).
   SOURCE: schema `KycLivenessCallOut.status`; `src/api/types.ts: KycLivenessCallStatus`.
7. **`result` enum = `{passed,failed,null}`; there is NO `review` verdict and NO
   separate `verdict` field.** VERDICT: Corrected. SOURCE: schema
   `KycLivenessCallOut.result`; `src/api/types.ts: KycLivenessCallOut.result`.
8. **Owner case-status route returns `{verification_call: KycLivenessCallStatusOut
   | null}` (no verifier identity).** VERDICT: Verified. SOURCE: schema
   `KycLivenessCallStatusResponse` / `KycLivenessCallStatusOut`;
   `src/api/endpoints/kycLivenessCall.ts: getKycLivenessCallStatusForCase`.
9. **Cancel = `POST .../{call_id}/cancel` (no body) → `KycLivenessCallOut`;
   enabled only for `scheduled`/`in_progress`.** VERDICT: Verified. SOURCE:
   OpenAPI `POST /ui/kyc/liveness-call/{call_id}/cancel`;
   `src/pages/kyc/KycLivenessCallSchedulePage.tsx` (`cancellable = status ===
   "scheduled" || status === "in_progress"`).
10. **The call is joined via an opaque `join_url` opened externally (anchor link),
    not an in-app PeerConnection.** VERDICT: Corrected. SOURCE:
    `KycLivenessCallOut.join_url`; `KycLivenessCallSchedulePage.tsx`
    (`<a href={call.join_url}>Join call</a>`).
11. **No `peer_id`, `signal_room`, `ice_servers`, `mode (automated|agent)`,
    `prompts`, `require_audio`, `max_attempts`, `expires_at`, `score`, or
    in-call control/SDP/ICE messages exist.** VERDICT: Corrected (all were
    fabricated). SOURCE: absence across schemas `KycLivenessCall*` in
    `openapi.pretty.json` and `src/api/types.ts` (grep returned no such fields).
12. **Auth on the seam = `Authorization: Bearer <accessToken>` + `X-CSRF-Token`
    (from `ui_csrf` cookie) + cookies (`credentials: include`); optional
    `X-SESSION-ID`, `X-IMPERSONATION-TOKEN` headers, optional `user_sub` query.**
    VERDICT: Corrected (spec claimed "no bearer tokens"). SOURCE:
    `src/api/client.ts` (sets `Authorization`, `X-CSRF-Token`, `credentials`);
    OpenAPI params on `POST /ui/kyc/liveness-call` (`user_sub`, `X-SESSION-ID`,
    `X-IMPERSONATION-TOKEN`).
13. **401 handling = one `POST /ui/session/refresh` then retry, else logout.**
    VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` + 401 branch.
14. **FastAPI error `detail` shape (string | `{msg}` | array of `{msg}` | coded
    object) drives user-facing messages.** VERDICT: Verified. SOURCE:
    `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`;
    schema `HTTPValidationError`.
15. **Verifier `result` request = `{result: passed|failed, notes (1..2000, req),
    recording_linked (default true)}` (admin-only, out of owner scope).**
    VERDICT: Verified. SOURCE: schema `KycLivenessCallResultRequest`;
    `src/api/endpoints/kycLivenessCall.ts: recordKycLivenessCallResult`.
16. **Web schedule form: case id, datetime-local, duration in {5,10,15,30,60},
    optional note; submit disabled while pending; times shown as
    `scheduled_at*1000` via `toLocaleString`.** VERDICT: Verified. SOURCE:
    `src/pages/kyc/KycLivenessCallSchedulePage.tsx`.
17. **Open `join_url` via Android external Custom Tabs / `Intent.ACTION_VIEW`.**
    VERDICT: Unverified-assumption (framework ref). SOURCE: framework ref —
    https://developer.android.com/develop/ui/views/layout/webapps/customtabs ;
    https://developer.android.com/reference/android/content/Intent#ACTION_VIEW .
    Chosen to mirror the web app's external anchor; the production `join_url`
    scheme/host is unconfirmed (OQ-6).
18. **Stack pins (Kotlin 2.0.21, Compose/M3, Hilt+KSP, minSdk 24, compile/target
    35, JDK 17, AGP 8.7.3/Gradle 8.9).** VERDICT: Unverified-assumption (carried
    from sibling tickets; not in these sources). SOURCE: spec §2; not checkable
    against OpenAPI/frontend.

### Corrections made

- Replaced the entire `/v1/kyc/liveness/*` start/poll/cancel surface with the real
  `/ui/kyc/liveness-call*` family (#1, #4, #9).
- Reframed the feature from in-app WebRTC negotiation (offer/answer/ICE,
  signaling, PiP, prompts) to a scheduled appointment + external `join_url` +
  human verifier (#2, #10, #11). Struck §4.4/§4.5 bridge/negotiation; rewrote
  §1, §3 (FR-1..FR-8), §4.1-4.3/4.5, §5, §6, §7, §8, §9, §10, §11.
- Corrected response code `200`→`201` and removed fabricated `409`/`503` errors
  (#4); corrected `status`/`result` enums and removed `verdict`/`review` (#6, #7).
- Removed fabricated fields `peer_id`/`signal_room`/`ice_servers`/`mode`/`prompts`/
  `require_audio`/`max_attempts`/`expires_at`/`score` and all control messages (#11).
- Corrected auth: added `Authorization: Bearer` (#12); removed "no bearer tokens".
- Dropped AND-289/AND-290/AND-288/AND-291 as dependencies; removed camera/mic
  permission, `FLAG_SECURE`/recording, DTLS-SRTP, and TURN claims (#2, #10, #11).
- Rewrote `KycError`, telemetry events, a11y (prompts→form/list), AC-1..AC-8, DoD,
  and resolved OQ-1..OQ-4 (added OQ-5/OQ-6).

### Open assumptions

- **OQ-5 — KYC entry-point gating.** Which `KycRequirement.key`/`type` surfaces
  the scheduler is not in the liveness-call schemas; only the required `case_id`
  link is verified. Needs the AND-319 KYC case/requirements contract.
- **OQ-6 — `join_url` nature.** Hosted vendor link vs. in-app deep link, and
  Custom Tab vs. embedded WebView, are unconfirmed; the web app uses a plain
  external anchor. If an embedded WebView is mandated, camera/mic permission and
  `FLAG_SECURE` re-enter scope (#17).
- **Refresh method name** (`KycRepository.refreshMe()`/`KycMeResp`) is owned by
  AND-319 and not in these sources (§6).
- **Stack pins** (#18) are carried from sibling tickets, not verifiable here.
- **Telemetry/`KycMetrics` seam** is an internal convention, not in these sources.

## 17. Test Plan

IDs `TC-AND-324-NN`. Targets: JVM = JVM/Robolectric unit (local); MWS =
MockWebServer (`core-network`, local); Compose-UI / instrumented = emulator
**AVD `test35`** (API 35) unless a case needs the **physical Samsung Galaxy A15
5G (SM-A156U, API 34)**, called out explicitly. No case requires in-app camera/
mic/WebRTC (the feature has none), so the physical device is needed only for the
real-browser `join_url` handoff and the API-34-vs-35 launch check.

- **TC-AND-324-01 — Schedule happy path (coordinator).**
  Type: unit (JVM). Target: `DefaultLivenessCoordinator` with a fake `KycApi`.
  Preconditions: fake returns `201 KycLivenessCallOut{status:"scheduled",
  join_url:null}`. Steps: call `schedule(caseId, scheduledAt, 15, note)`; then
  `refresh()` returns a list containing it. Expected: `ApiResult` success;
  `uiState` = `Ready(calls=[..SCHEDULED..])`. Traces: AC-1, AC-2.

- **TC-AND-324-02 — Schedule wire contract (MockWebServer).**
  Type: contract/MockWebServer. Target: `KycApi.scheduleLiveness`.
  Preconditions: MWS enqueues `201` with the §5 JSON. Steps: call
  `scheduleLiveness(req)`. Expected: request is `POST /ui/kyc/liveness-call`,
  body has snake_case `case_id`/`scheduled_at`/`duration_minutes`/`note`, headers
  include `Authorization: Bearer …` and `X-CSRF-Token`; response decodes to
  `LivenessCallOut` (snake_case mapped, `status=SCHEDULED`). Traces: AC-3.

- **TC-AND-324-03 — GET list / case-status / single-call decode (MockWebServer).**
  Type: contract/MockWebServer. Target: `listMyLivenessCalls`,
  `getLivenessCall`, `getLivenessCallForCase`. Preconditions: MWS returns
  `{calls:[…]}`, a single `KycLivenessCallOut`, and `{verification_call:null}`.
  Steps: invoke each. Expected: paths `GET /ui/kyc/liveness-call`,
  `.../{callId}`, `.../case/{caseId}`; null `verification_call` maps to no call;
  unknown `status`/`result` strings map to `UNKNOWN`. Traces: AC-3.

- **TC-AND-324-04 — Cancel (MockWebServer + coordinator).**
  Type: contract/MockWebServer. Target: `cancelLivenessCall`.
  Preconditions: MWS returns `KycLivenessCallOut{status:"cancelled"}`. Steps:
  call `cancel(callId)`. Expected: request is `POST /ui/kyc/liveness-call/
  {callId}/cancel` with no body; mapped call shows `CANCELLED`; list refreshed.
  Traces: AC-3, AC-7.

- **TC-AND-324-05 — Terminal `passed` triggers case refresh.**
  Type: unit (JVM). Target: coordinator + fake `KycRepository`. Preconditions:
  `getLivenessCall` returns `status:"passed", result:"passed"`. Steps: refresh a
  known call. Expected: `KycRepository` case refresh invoked exactly once;
  `uiState` reflects PASSED. Traces: AC-5.

- **TC-AND-324-06 — Join opens `join_url` externally.**
  Type: Compose-UI (emulator `test35`). Target: `LivenessCallScreen`.
  Preconditions: a call with non-null `join_url`. Steps: tap "Join call".
  Expected: an `ACTION_VIEW` intent for `join_url` is fired (assert via Espresso
  `Intents`); no in-app WebView/media surface is created. "Join call" is absent
  when `join_url` is null. Traces: AC-4.

- **TC-AND-324-07 — 422 validation maps to inline form error.**
  Type: contract/MockWebServer. Target: `scheduleLiveness` + ViewModel.
  Preconditions: MWS returns `422 {detail:[{msg:"scheduled_at is required"}]}`.
  Steps: schedule with a bad payload. Expected: `uiState` =
  `Ready(formError="scheduled_at is required")`; no crash; no retry. Traces: AC-6.

- **TC-AND-324-08 — 403 / 404 mapping.**
  Type: contract/MockWebServer. Target: coordinator. Preconditions: MWS returns
  `403 {detail:{code:"role_required"}}` then `404`. Steps: schedule (403); GET an
  unknown `callId` (404). Expected: 403 → `KycError.PermissionDenied` with the
  mapped message; 404 → `KycError.Transport(404)`; both non-crashing. Traces: AC-6.

- **TC-AND-324-09 — UI state traversal + a11y form error (Compose).**
  Type: Compose-UI (emulator `test35`). Target: `LivenessCallScreen`.
  Preconditions: fake VM emits `Loading → Ready(scheduling=true) →
  Ready(formError=…)`. Steps: render each. Expected: spinner, disabled submit
  while scheduling, error text associated to the field and announced via the
  assertive live region; accessibility checks (labels present, touch targets
  ≥48dp) pass. Traces: AC-2, AC-8.

- **TC-AND-324-10 — Staged end-to-end acceptance.**
  Type: instrumented/e2e (emulator `test35` against staged backend). Target: full
  flow. Preconditions: authenticated session; a valid KYC `case_id`. Steps:
  schedule a call; confirm it lists as `scheduled` with a `join_url`; have a
  staged verifier mark it `passed`; refresh. Expected: terminal `status:"passed"`/
  `result:"passed"` surfaced and case refreshed — "Liveness session connects +
  completes". Traces: AC-1, AC-5.

- **TC-AND-324-11 — Double-401 ends in AuthExpired (offline/flaky-host adjacent).**
  Type: contract/MockWebServer. Target: transport + coordinator. Preconditions:
  MWS returns `401`, refresh `POST /ui/session/refresh` `200`, then `401` again.
  Steps: call any liveness endpoint. Expected: one refresh + one retry; second
  `401` → `KycError.AuthExpired` and route-to-login signal; on raw network
  failure (simulated offline) → `KycError.Transport(null)` recoverable, no crash.
  Traces: AC-6.

- **TC-AND-324-12 — Redaction / no sensitive logging (security).**
  Type: unit (JVM, log-capture). Target: coordinator + `KycMetrics`.
  Preconditions: a call with `join_url`, `recording_ref`, `result_notes`,
  `verifier_sub` and an auth token in flight. Steps: run schedule/list/cancel
  with a capturing logger. Expected: no log/metric contains `join_url`,
  `recording_ref`, `result_notes`, `verifier_sub`, or the token; only short
  `call_id`/`case_id` and enum `status`/`result`. Traces: AC-7.

- **TC-AND-324-13 — Localization / RTL audit.**
  Type: manual + Compose-UI. Target: `LivenessCallScreen`. Preconditions: device
  locale set to a RTL locale (e.g. ar) and a non-English LTR locale. Steps:
  render scheduler + list with each `status`/`result`. Expected: no hard-coded
  English; `status`/`result` resolve via string resources; dates/durations are
  locale-formatted; layout mirrors correctly in RTL. Traces: AC-8.

- **TC-AND-324-14 — Real-browser join + ABI/API-34 launch (physical device).**
  Type: instrumented/e2e. Target: app on the **physical Samsung Galaxy A15 5G
  (SM-A156U, API 34, arm64-v8a)** — MUST run here, not the x86_64/API-35 emulator,
  to validate the real Chrome Custom Tab/browser handoff for `join_url` and the
  arm64/API-34 app launch. Preconditions: app installed via adb on serial
  `R5CX821TA9R`; a scheduled call with a real `join_url`. Steps: tap "Join call".
  Expected: the system browser/Custom Tab opens `join_url`; returning to the app
  preserves the list; no crash on arm64/API-34. Traces: AC-1, AC-4.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 | TC-AND-324-01, TC-AND-324-10, TC-AND-324-14 |
| AC-2 | TC-AND-324-01, TC-AND-324-09 |
| AC-3 | TC-AND-324-02, TC-AND-324-03, TC-AND-324-04 |
| AC-4 | TC-AND-324-06, TC-AND-324-14 |
| AC-5 | TC-AND-324-05, TC-AND-324-10 |
| AC-6 | TC-AND-324-07, TC-AND-324-08, TC-AND-324-11 |
| AC-7 | TC-AND-324-04, TC-AND-324-12 |
| AC-8 | TC-AND-324-09, TC-AND-324-13 |

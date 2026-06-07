---
id: AND-379
title: Agent availability / online state
milestone: M8
epic: E49
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-145]
blocks: [AND-162]
---

# AND-379 — Agent availability / online state

## 1. Overview & Goal

Helpdesk/support agents in TestLogon claim queued conversations from a shared
queue (`GET /messaging/helpdesk/queue` →
`POST /messaging/helpdesk/conversations/{conversation_id}/claim`). Agents need an
explicit **availability toggle** ("Online / Available" vs. "Away") that controls
whether they are eligible to claim work. When an agent is Away, the claim
affordances in the helpdesk UI must be disabled and a guard must block claim
attempts; when Online, claiming proceeds normally.

The toggle is surfaced as agent-visible online state. There is no dedicated
`agent/availability` write endpoint in the dev backend OpenAPI; availability is
expressed through the presence subsystem delivered by **AND-145** — specifically
the `status` field of `PresenceHeartbeatIn` (`"available"` | `"away"`) carried by
the foreground heartbeat — combined with a client-side **claim-eligibility gate**.
This ticket owns: (a) the availability toggle UI and its persisted state, (b)
wiring availability into the presence heartbeat `status` field, and (c) gating
the helpdesk claim flow on local availability so that an Away agent cannot claim.

Goal: a durable, foreground-aware availability toggle whose value (1) is reflected
in the agent's outgoing presence heartbeats and (2) deterministically gates the
ability to claim helpdesk conversations on-device.

## 2. Context & References

- **Project stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, DataStore (prefs), Room 2.6 (cache). minSdk 24 / target 35, JDK 17.
- **Namespace:** `com.testlogon.android` (applicationId base and package root).
- **Module layering:** `app → feature-* → core-*`. This ticket lives in
  `feature-helpdesk` (UI/VM) and reuses `core-data` presence repository from
  AND-145, `core-network` for the helpdesk API, and `core-ui` state composables.
- **Dependency AND-145 (Presence + heartbeat, M3/E20):** provides
  `PresenceRepository`, the foreground heartbeat loop (`POST
  /messaging/presence/heartbeat`), and online indicators. AND-379 extends the
  heartbeat payload with the availability `status` and adds the claim gate.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (helpdesk + presence API
  layer), `frontend/src/api/types.ts` (shared DTOs).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable; ~20s timeouts, bounded retry for idempotent GETs only).
  OpenAPI at `/openapi.json`. Cookie-based session with `X-CSRF-Token` echo and
  one-shot `POST /ui/session/refresh` on 401.
- **Relevant endpoints (verified in `/openapi.json`):**
  `GET /messaging/helpdesk/queue`,
  `POST /messaging/helpdesk/conversations/{conversation_id}/claim`,
  `POST /messaging/presence/heartbeat`, `GET /messaging/presence`.

## 3. Functional Requirements

1. **Availability toggle.** An agent-facing toggle with two states: `ONLINE`
   (a.k.a. Available) and `AWAY`. Rendered in the helpdesk queue screen header and
   mirrored in the helpdesk section of settings. Default on first run: `AWAY`
   (fail-safe — agents must opt in to receiving claims).
2. **Persistence.** Availability survives process death and app restart. It is
   stored in DataStore and restored before the queue screen renders.
3. **Heartbeat reflection.** While the app is foregrounded and the agent is signed
   in, each presence heartbeat (AND-145 loop) must carry `status = "available"`
   when `ONLINE` and `status = "away"` when `AWAY`. Changing the toggle triggers an
   **immediate** out-of-band heartbeat so the backend/peers observe the change
   without waiting for the next interval tick.
4. **Claim gating.** When availability is `AWAY`:
   - Every "Claim" button/affordance in the queue and conversation detail is
     disabled (visually and for input), with an inline explanation.
   - Any programmatic claim attempt (e.g. from a queued tap that raced the toggle)
     is short-circuited by `HelpdeskClaimGate` and surfaces a "You're Away — go
     Online to claim" message instead of calling the network.
5. **Claim when Online.** When `ONLINE`, claim proceeds via
   `POST /messaging/helpdesk/conversations/{id}/claim`; success updates the queue
   item to assigned. Server-side conflicts (already claimed by another agent) are
   handled per §7 and are distinct from the availability gate.
6. **Foreground awareness.** Availability is an explicit user setting and is **not**
   auto-cleared on backgrounding; however, the heartbeat carrying it only runs in
   foreground (AND-145). On returning to foreground, the persisted availability is
   re-asserted via an immediate heartbeat.
7. **Single source of truth.** All claim affordances and the heartbeat read the same
   `StateFlow<Availability>`; there must be no path where the UI shows Online while
   heartbeats send `away` (or vice versa).

## 4. Technical Design

### Module placement
- `core-model`: `Availability` enum + `AgentAvailabilityState`.
- `core-data`: `AvailabilityRepository` (DataStore-backed) and the heartbeat
  `status` integration point on the existing `PresenceRepository` (AND-145).
- `feature-helpdesk`: `AvailabilityToggle` composable, `HelpdeskClaimGate`,
  `HelpdeskQueueViewModel` claim wiring.

### Domain model (`core-model`)
```kotlin
enum class Availability { ONLINE, AWAY }

fun Availability.heartbeatStatus(): String = when (this) {
    Availability.ONLINE -> "available"
    Availability.AWAY   -> "away"
}

data class AgentAvailabilityState(
    val availability: Availability = Availability.AWAY,
    val lastChangedAt: Long = 0L,      // epoch millis, for telemetry/diagnostics
    val pushPending: Boolean = false,  // true while an immediate heartbeat is in flight
)
```

### Repository (`core-data`)
```kotlin
interface AvailabilityRepository {
    val availability: StateFlow<Availability>
    suspend fun set(value: Availability)   // persists + triggers immediate heartbeat
    suspend fun current(): Availability     // synchronous-ish read for gating
}

@Singleton
class AvailabilityRepositoryImpl @Inject constructor(
    @AvailabilityPrefs private val dataStore: DataStore<Preferences>,
    private val presenceRepository: PresenceRepository,   // from AND-145
    @ApplicationScope private val scope: CoroutineScope,
) : AvailabilityRepository {

    private companion object { val KEY = stringPreferencesKey("agent_availability") }

    override val availability: StateFlow<Availability> =
        dataStore.data
            .map { it[KEY]?.let(::runCatching)?.getOrNull()
                ?.let { v -> Availability.valueOf(v) } ?: Availability.AWAY }
            .stateIn(scope, SharingStarted.Eagerly, Availability.AWAY)

    override suspend fun set(value: Availability) {
        dataStore.edit { it[KEY] = value.name }
        presenceRepository.sendHeartbeatNow(status = value.heartbeatStatus())  // immediate
    }

    override suspend fun current(): Availability = availability.value
}
```

`PresenceRepository` (AND-145) is extended so the periodic heartbeat reads the
current availability and `sendHeartbeatNow(status)` exists for the out-of-band push:
```kotlin
// core-data (AND-145, amended by AND-379)
suspend fun sendHeartbeatNow(status: String): ApiResult<Unit>
// periodic loop body now: api.heartbeat(PresenceHeartbeatDto(
//     device = deviceLabel, status = availabilityRepository.current().heartbeatStatus()))
```
To avoid a DI cycle (`PresenceRepository` ↔ `AvailabilityRepository`), the periodic
loop reads availability via an injected `Provider<AvailabilityRepository>` /
`StateFlow` rather than holding a hard reference, and `AvailabilityRepository`
depends on `PresenceRepository`.

### Claim gate (`feature-helpdesk`)
```kotlin
sealed interface ClaimGateResult {
    data object Allowed : ClaimGateResult
    data object BlockedAway : ClaimGateResult
}

class HelpdeskClaimGate @Inject constructor(
    private val availabilityRepository: AvailabilityRepository,
) {
    suspend fun check(): ClaimGateResult =
        if (availabilityRepository.current() == Availability.ONLINE)
            ClaimGateResult.Allowed else ClaimGateResult.BlockedAway
}
```

### ViewModel wiring
```kotlin
@HiltViewModel
class HelpdeskQueueViewModel @Inject constructor(
    private val helpdeskRepository: HelpdeskRepository,
    private val availabilityRepository: AvailabilityRepository,
    private val claimGate: HelpdeskClaimGate,
) : ViewModel() {

    val availability: StateFlow<Availability> = availabilityRepository.availability

    private val _uiState = MutableStateFlow<HelpdeskQueueUiState>(HelpdeskQueueUiState.Loading)
    val uiState: StateFlow<HelpdeskQueueUiState> = _uiState.asStateFlow()

    fun setAvailability(value: Availability) = viewModelScope.launch {
        availabilityRepository.set(value)
    }

    fun claim(conversationId: String) = viewModelScope.launch {
        when (claimGate.check()) {
            ClaimGateResult.BlockedAway ->
                _uiState.update { it.withTransientMessage(R.string.helpdesk_claim_blocked_away) }
            ClaimGateResult.Allowed -> when (val r = helpdeskRepository.claim(conversationId)) {
                is ApiResult.Success -> applyClaim(r.data)
                is ApiResult.Failure -> _uiState.update { it.withClaimError(r.error) }
            }
        }
    }
}
```

### UI (`feature-helpdesk`)
```kotlin
@Composable
fun AvailabilityToggle(
    value: Availability,
    onChange: (Availability) -> Unit,
    modifier: Modifier = Modifier,
)
```
A Material 3 `Switch` + label ("Online" / "Away") with a status dot
(`core-ui` presence indicator from AND-145). Queue list items pass
`enabled = (availability == ONLINE)` to their `ClaimButton`; when disabled they
show a caption: "Go Online to claim".

## 5. API Contract

This ticket introduces **no new endpoints**. It composes two existing ones.

### Presence heartbeat (status carrier) — `POST /messaging/presence/heartbeat`
Request body (`PresenceHeartbeatIn`; both fields nullable on the server, AND-379
always sends `status`):
```json
{ "device": "android", "status": "available" }   // or "away"
```
Response: `200`. **Correction:** the OpenAPI types the 200 body as an open `{}`
schema (any JSON), and the web reference parses a JSON object
`{ ok: boolean, user_id: string, online: boolean, last_seen_at: number }`
(`frontend/src/api/endpoints/messaging.ts: sendHeartbeat`) — it is **not** an
empty body. AND-379 may ignore the body, but the network layer must tolerate a
present JSON object (do not assert empty). Note the web client sends only
`{ device }` and never `status`; the `status` field is an AND-379 addition that
the schema permits (`PresenceHeartbeatIn.status` = `anyOf string|null`) but no
web caller exercises (see §16, unverified vocabulary). Headers: cookie session +
`X-CSRF-Token`. This is
a **non-idempotent POST** — do not auto-retry on transient failure beyond the
single 401-refresh-retry; an immediate-push failure is non-fatal (the next periodic
heartbeat will carry the correct status).

### Helpdesk claim (gated action) — `POST /messaging/helpdesk/conversations/{conversation_id}/claim`
Path param: `conversation_id` (string). No request body. Response `200`
(`HelpdeskClaimOut`):
```json
{
  "ok": true,
  "conversation_id": "conv_123",
  "state": "assigned",
  "assigned_agent_user_id": "u_self",
  "assignment_version": 4,
  "idempotent": false
}
```
- `idempotent: true` + `assigned_agent_user_id == self` → already claimed by us; treat
  as success (no error toast).
- `assigned_agent_user_id != self` → claimed by another agent (conflict, §7).
- `422` → `HTTPValidationError` (mapped per AND-015).
- **Correction:** the OpenAPI defines **only** `200` and `422` for this operation —
  there is **no 409** status. Conflict ("claimed by another agent") is signalled
  *in the 200 body* via `assigned_agent_user_id`/`idempotent`, not by an HTTP error
  code. Earlier text referencing "backend 409" is an unverified assumption (§16).
  All response fields are `required` except `idempotent` (defaults `false`).

### Queue read — `GET /messaging/helpdesk/queue`
Returns `ConversationOut[]` (an array; the OpenAPI 200 schema is
`array<ConversationOut>`). **Correction:** this GET takes a **required** query
param `group_id` (string, maxLength 128) plus optional `state` (string) and
`limit` (integer, default 50, max 200) — the earlier text omitted these. The web
reference calls it with `group_id` (+ optional `state`) and treats `403` as an
expected non-error for non-agents (`silent403`, see §8). Relevant
`ConversationOut` fields for claim state (all `anyOf <type>|null`):
`active_agent_user_id`, `active_agent_claimed_at`, `assignment_version`,
`routing_state`. This is an **idempotent GET** → eligible for bounded backoff retry
(AND-016) and stale display (AND-045).

The availability `status` string vocabulary (`"available"` / `"away"`) is the
contract AND-379 commits to; if the backend later adds a dedicated availability
endpoint, that is a follow-up ticket and not owned here.

## 6. Data & State Management

- **Persisted (DataStore, `@AvailabilityPrefs`):** single string key
  `agent_availability` ∈ {`ONLINE`,`AWAY`}. Default `AWAY` (fail-safe).
- **In-memory:** `AvailabilityRepository.availability: StateFlow<Availability>`,
  hot, `SharingStarted.Eagerly`, sourced from DataStore so it is correct before
  first UI composition. This is the **single source of truth** read by both the
  toggle UI and the heartbeat loop.
- **No Room.** Availability is device-local agent preference, not cached server
  data; it does not belong in the SWR cache (AND-116). The helpdesk **queue** is
  cached/staled separately by the existing helpdesk read layer.
- **State propagation:** `set()` writes DataStore (DataStore emits → StateFlow
  updates → all collectors recompose) and then fires the immediate heartbeat. UI
  never mutates availability directly; it calls `viewModel.setAvailability(...)`.
- **Lifecycle:** on `ON_START` of the helpdesk graph (and on cold start) the
  persisted value is already loaded; AND-145's foreground heartbeat resumes and
  reads the current availability on its next tick, plus AND-379 issues one
  immediate heartbeat to re-assert on resume.

## 7. Error Handling & Resilience

- **Toggle set failure (DataStore write):** extremely rare; surface a transient
  error and revert the in-memory optimistic value to the last persisted value.
- **Immediate-heartbeat push failure:** non-fatal and silent to the user. The
  persisted toggle value is authoritative; the next periodic heartbeat carries it.
  `set()` returns after DataStore commit regardless of heartbeat outcome.
- **Claim blocked by Away (gate):** not an error — a deterministic UX state.
  Show `helpdesk_claim_blocked_away` ("You're Away — go Online to claim"). No
  network call is made.
- **Claim conflict (server):** detected via the **200 body** —
  `HelpdeskClaimOut.assigned_agent_user_id != self` → message "Already claimed by
  another agent", refresh the queue item from the latest
  `GET /messaging/helpdesk/queue?group_id=…`. **Correction:** the OpenAPI exposes no
  `409` for this operation, so conflict handling must not depend on an HTTP 409
  (earlier "backend 409 mapped via AND-015" is unverified — see §16).
- **403 on queue read (non-agent):** the web reference treats `403` from the queue
  as expected (the caller is not a helpdesk agent) and suppresses the error toast
  (`silent403`). AND-379 should likewise treat queue `403` as a "not an agent / no
  access" empty state rather than a hard error.
- **Claim network/timeout failure:** map via `ApiResult.Failure` + FastAPI `detail`
  mapping (string | `[{msg}]` | `{code,...}`). Claim POST is **not** auto-retried
  (non-idempotent); offer manual retry. Honor ~20s timeout against the unreliable
  dev host.
- **401 during heartbeat or claim:** standard one-shot `POST /ui/session/refresh`
  then retry once (AND-013). If refresh fails, route to re-auth; availability
  persists across re-auth.
- **Offline:** toggle remains operable and persists locally; claim affordances are
  additionally disabled while offline (connectivity probe, AND-017) with an
  "Offline" caption that takes precedence over the Away caption.

## 8. Security & Privacy

- Availability is agent-scoped state tied to the authenticated cookie session; it
  is never sent or read on behalf of another user. The heartbeat and claim calls
  carry only the session cookie + `X-CSRF-Token` — no credentials in payloads.
- `status` values are non-PII enums (`available`/`away`); no free-text, no
  location. Presence `last_seen_at` exposure is governed by AND-145, unchanged here.
- DataStore file holds only the enum name; no encryption required (non-sensitive),
  and it is cleared on full sign-out alongside other agent prefs.
- Claim gating is a **UX/affordance** control, not a security boundary — the
  backend remains the authority on who may claim. The gate prevents accidental
  claims while Away; it must never be relied upon for authorization.

## 9. Accessibility & i18n

- `AvailabilityToggle` exposes a `Switch` with `Modifier.semantics` `role = Switch`,
  `stateDescription` = "Online"/"Away", and an `contentDescription` of
  "Agent availability". The status dot is decorative
  (`contentDescription = null`); state is conveyed by the text label, not color
  alone (WCAG 1.4.1).
- Disabled claim buttons set `stateDescription`/`onClick` semantics so TalkBack
  announces "disabled — go Online to claim".
- Touch target ≥ 48dp; toggle reachable and operable without the queue list.
- All strings via `core-ui` i18n plumbing (AND-111): `helpdesk_availability_online`,
  `helpdesk_availability_away`, `helpdesk_availability_label`,
  `helpdesk_claim_blocked_away`, `helpdesk_claim_disabled_offline`,
  `helpdesk_claim_conflict`. RTL-safe (no hardcoded start/end). No string
  concatenation; use plurals/placeholders where needed.

## 10. Telemetry & Logging

Structured events via the app telemetry facade (redacted, no PII):
- `helpdesk_availability_changed` — props: `from`, `to`, `source`
  (`queue_header` | `settings`), `ts`.
- `helpdesk_availability_heartbeat_push` — props: `status`, `result`
  (`ok`|`failure`), `latency_ms`.
- `helpdesk_claim_blocked` — props: `reason` (`away`|`offline`), `conversation_id`
  (hashed/opaque id, allowed — server-side id, not PII).
- `helpdesk_claim_result` — props: `result` (`success`|`conflict`|`error`),
  `assignment_version`.

Logging: debug-level only; redact cookies/CSRF (OkHttp logging level NONE in
release per AND-009). Never log the heartbeat body beyond the `status` enum.

## 11. Testing Strategy

**Unit (`core-data` / `core-model`, JVM):**
- `Availability.heartbeatStatus()` maps ONLINE→"available", AWAY→"away".
- `AvailabilityRepositoryImpl`: default is `AWAY` when key absent; `set()` persists
  and invokes `presenceRepository.sendHeartbeatNow("available"/"away")` (verify with
  a fake `PresenceRepository`); StateFlow emits new value after `set()`.
- `HelpdeskClaimGate.check()` returns `Allowed` iff ONLINE else `BlockedAway`.

**ViewModel (coroutines test, Turbine):**
- `claim()` while AWAY → no `helpdeskRepository.claim` call, transient
  `helpdesk_claim_blocked_away` message emitted.
- `claim()` while ONLINE → calls repository; success applies assignment; conflict
  (`assigned_agent_user_id != self`) emits conflict message and triggers queue refresh.
- `setAvailability()` flips the exposed `availability` StateFlow.

**Repository contract (MockWebServer, AND-046):**
- Heartbeat POST body contains `"status":"available"` after `set(ONLINE)`.
- Claim POST returns `HelpdeskClaimOut`; `idempotent:true & self` treated as success.
- 401 on claim → one refresh + retry; second 401 → failure surfaced.

**Compose UI (instrumented, AND-051):**
- Toggle renders Online/Away; tapping calls `onChange`.
- When AWAY, all `ClaimButton`s are disabled and show the "Go Online" caption;
  tapping does nothing.
- When ONLINE, claim button enabled and triggers claim.
- Accessibility assertions: switch `stateDescription`, disabled-button semantics.

**Persistence:** restart-survival test — `set(ONLINE)`, recreate repository from
same DataStore, assert `availability.value == ONLINE`.

## 12. Dependencies & Sequencing

- **Depends on AND-145 (Presence + heartbeat):** required — provides
  `PresenceRepository`, the foreground heartbeat loop, `PresenceHeartbeatIn.status`
  wiring point, and the `core-ui` online indicator dot. AND-379 amends the loop to
  read availability and adds `sendHeartbeatNow(status)`.
- **Soft dependency on the helpdesk claim/reply feature (AND-162):** AND-379 gates
  the claim action that AND-162 implements end-to-end. If AND-379 lands first, the
  gate wraps the existing `HelpdeskRepository.claim`; AND-379 therefore **blocks**
  AND-162's "claim while Away" acceptance. Sequence: AND-145 → AND-379 → AND-162
  final claim UX (or co-develop the claim button `enabled` contract).
- Reuses cross-cutting infra already present: `ApiResult` (AND-018), error/detail
  mapping (AND-015), DataStore prefs, connectivity probe (AND-017), i18n (AND-111),
  telemetry (AND-052 patterns).

## 13. Risks & Open Questions

1. **No dedicated availability endpoint.** The dev OpenAPI has presence heartbeat
   (`status`) and helpdesk claim but no `agent/availability` write. AND-379 models
   availability via the heartbeat `status` string + client gate. **Risk:** backend
   may not consume `status` for routing today, so gating is client-authoritative
   until then. **Q:** does the backend route/skip Away agents based on heartbeat
   `status`, or is a separate availability resource planned? (Owner: backend.)
2. **DI cycle** between `PresenceRepository` and `AvailabilityRepository` — mitigated
   via `Provider`/StateFlow indirection (§4); needs review at integration with AND-145.
3. **Foreground-only heartbeat** means an Away→Online flip made just before
   backgrounding may not be observed server-side until next foreground. Accepted:
   immediate push on `set()` + re-assert on resume mitigate the common case.
4. **Status vocabulary drift.** `"available"`/`"away"` are unconstrained strings on
   the server (`anyOf string|null`). **Q:** confirm canonical values; align with web
   reference (`frontend/src/api/types.ts`) to avoid a third spelling (e.g. "online").
5. **Default = AWAY** may surprise agents expecting to be auto-online on launch.
   Chosen for fail-safe (no surprise claims); revisit if product disagrees.

## 14. Acceptance Criteria

1. **Availability toggle affects claim eligibility** (source acceptance): with the
   toggle set to **Away**, the agent cannot claim — all claim buttons are disabled
   and any claim attempt is blocked client-side with no `POST .../claim` call; with
   the toggle set to **Online**, claim is enabled and performs the claim request.
   (Verifiable by MockWebServer: zero claim requests while Away, one while Online.)
2. Toggling availability sends an **immediate** presence heartbeat whose body
   `status` equals `"available"` (Online) or `"away"` (Away), and subsequent
   periodic heartbeats carry the same value.
3. Availability **persists** across process death/app restart; the restored value
   gates the UI before the queue renders. Default on first launch is `AWAY`.
4. The toggle UI and the heartbeat read the **same** `StateFlow` — no state where UI
   shows Online while heartbeats send `away` (covered by a single-source test).
5. Claim **conflicts** (claimed by another agent) and the Away **gate** produce
   distinct, correctly-localized messages; gate produces no network call.
6. Offline disables claim with a precedence-correct caption and the toggle still
   persists locally.
7. Accessibility: toggle and disabled claim buttons expose correct TalkBack
   state/role semantics; state not conveyed by color alone.

## 15. Definition of Done

- `Availability` model, `AvailabilityRepository` (+impl), `HelpdeskClaimGate`,
  `AvailabilityToggle`, and `HelpdeskQueueViewModel` claim/availability wiring are
  implemented under `com.testlogon.android` in `core-model`/`core-data`/
  `feature-helpdesk`, with Hilt bindings.
- `PresenceRepository` (AND-145) is amended to read availability for periodic
  heartbeats and to expose `sendHeartbeatNow(status)`, without a DI cycle.
- All §11 unit, ViewModel, repository-contract, Compose-UI, and persistence tests
  are written and green in CI (AND-050/AND-051).
- All strings localized via i18n plumbing; no hardcoded user-facing text; RTL-safe.
- Telemetry events from §10 emitted with redaction verified; release OkHttp logging
  remains NONE.
- `detekt`/lint/format clean (AND-005); module layering (`app→feature→core`) not
  violated; no new lint baselines.
- Manually verified against dev backend `http://18.222.237.167:8000`: heartbeat
  `status` flips with the toggle, claim succeeds only while Online, behavior is
  graceful under ~20s timeouts and offline.
- Spec acceptance criteria §14 all demonstrably met; PR references AND-379 and notes
  the AND-145 amendment and AND-162 claim-UX hand-off.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index/spec (`reference/openapi.index.txt`, `reference/openapi.pretty.json`,
schemas under `components.schemas.*`) and frontend (`reference/src/...`).

1. **Claim:** `POST /messaging/presence/heartbeat` is the heartbeat endpoint.
   **Verified.** Source: OpenAPI `POST /messaging/presence/heartbeat`
   (op `presence_heartbeat_messaging_presence_heartbeat_post`); frontend
   `src/api/endpoints/messaging.ts: sendHeartbeat`.
2. **Claim:** Heartbeat request body is `PresenceHeartbeatIn` with `device` and
   `status`, both nullable. **Verified.** Source: `components.schemas.PresenceHeartbeatIn`
   (`device`, `status` each `anyOf: [string, null]`, object has no `required`).
3. **Claim:** Heartbeat `status` carries `"available"`/`"away"`. **Unverified-assumption.**
   The schema permits any string (`status: anyOf string|null`), but no web caller
   sends `status` at all (`sendHeartbeat` posts only `{ device }`) and
   `PresenceStatus` (`src/api/types.ts: PresenceStatus`) exposes only
   `user_id/online/last_seen_at` — no `status`/availability field. The
   `"available"`/`"away"` vocabulary is an AND-379 convention with no source
   precedent. Source: `src/api/endpoints/messaging.ts: sendHeartbeat`,
   `src/api/types.ts: PresenceStatus`, `components.schemas.PresenceHeartbeatIn`.
4. **Claim (corrected):** Heartbeat 200 response is "empty body". **Corrected.**
   OpenAPI types the 200 as an open `{}` schema (any JSON); the web client parses
   `{ ok, user_id, online, last_seen_at }`. Network layer must tolerate a JSON
   object, not assert empty. Source: OpenAPI
   `paths./messaging/presence/heartbeat.post.responses.200` (schema `{}`);
   `src/api/endpoints/messaging.ts: sendHeartbeat` (typed return
   `{ ok: boolean; user_id: string; online: boolean; last_seen_at: number }`).
5. **Claim:** Claim endpoint is `POST /messaging/helpdesk/conversations/{conversation_id}/claim`,
   path param `conversation_id` (string), no request body. **Verified.** Source:
   OpenAPI `POST /messaging/helpdesk/conversations/{conversation_id}/claim`
   (params `conversation_id` path string; no `requestBody`); frontend
   `src/api/endpoints/messaging.ts: claimHelpdeskConversation` posts `{}`.
6. **Claim:** Claim 200 = `HelpdeskClaimOut` with `ok, conversation_id, state,
   assigned_agent_user_id, assignment_version, idempotent`. **Verified.** Source:
   `components.schemas.HelpdeskClaimOut` (`idempotent` defaults `false`; others in
   `required`); `src/api/types.ts: HelpdeskClaimOut`.
7. **Claim (corrected):** Claim conflict surfaces as backend `409`. **Corrected.**
   The operation defines only `200` and `422`; there is no `409`. Conflict must be
   read from the 200 body (`assigned_agent_user_id != self`), not an HTTP code.
   Source: OpenAPI claim op `responses` = `{200, 422}` only.
8. **Claim:** Claim validation error is `422 → HTTPValidationError`. **Verified.**
   Source: OpenAPI claim op `responses.422` → `HTTPValidationError`.
9. **Claim (corrected):** Queue read `GET /messaging/helpdesk/queue` returns
   `ConversationOut[]`. **Verified for the array shape; corrected for params.** The
   200 schema is `array<ConversationOut>`, BUT the GET requires query param
   `group_id` (string, maxLength 128) and accepts optional `state` (string) and
   `limit` (int, default 50, max 200) — the spec originally omitted these.
   Source: OpenAPI `GET /messaging/helpdesk/queue` (params + array response);
   `src/api/endpoints/messaging.ts: getHelpdeskQueue`.
10. **Claim:** `ConversationOut` claim-state fields `active_agent_user_id`,
    `active_agent_claimed_at`, `assignment_version`, `routing_state` exist.
    **Verified.** Source: `components.schemas.ConversationOut` (each
    `anyOf <type>|null`).
11. **Claim:** Auth is cookie session + `X-CSRF-Token` echo. **Verified.** Source:
    `src/api/client.ts` — reads `ui_csrf` cookie → sets `X-CSRF-Token`; all calls
    `credentials: "include"`.
12. **Claim:** On 401, one-shot `POST /ui/session/refresh` then retry once.
    **Verified.** Source: `src/api/client.ts: refreshSession` and the 401 branch
    (single shared `refreshPromise`, one retry; second 401 → logout).
13. **Claim:** FastAPI `detail` mapping handles string | array-of-`{msg}` | object.
    **Verified.** Source: `src/api/client.ts: normalizeErrorDetail` usage in 401/403
    error construction; OpenAPI `HTTPValidationError`/`ValidationError` shapes.
14. **Claim:** Non-agents get `403` from the queue and it is treated as expected.
    **Verified.** Source: `src/api/endpoints/messaging.ts: getHelpdeskQueue`
    (`silent403: true`); `src/api/client.ts` 403 handling branch.
15. **Claim:** `GET /messaging/presence` exists for online indicators (AND-145).
    **Verified.** Source: OpenAPI `GET /messaging/presence` (params `user_ids`);
    `src/api/endpoints/messaging.ts: getPresence` → `PresenceStatus[]`.
16. **Claim:** No dedicated `agent/availability` write endpoint exists.
    **Verified (absence).** Source: `reference/openapi.index.txt` — grep for
    helpdesk/presence yields only the four endpoints above; no `availability` path.
17. **Claim:** DataStore (prefs) for local persistence; Compose/Hilt/Retrofit stack.
    **Unverified-assumption (framework choice).** Not derivable from backend/frontend
    sources; standard Android choices. framework ref:
    https://developer.android.com/topic/libraries/architecture/datastore and
    https://developer.android.com/jetpack/compose .
18. **Claim:** Backend routes/skips Away agents based on heartbeat `status`.
    **Unverified-assumption.** No endpoint or schema documents routing behavior on
    `status`; gating is therefore client-authoritative (matches §13 Risk #1).

### Corrections made
- §5 heartbeat response: "empty body" → returns a JSON object
  `{ ok, user_id, online, last_seen_at }` (OpenAPI schema is open `{}`); tolerate,
  do not assert empty. (Audit #4)
- §5 + §7 claim conflict: removed reliance on a non-existent HTTP `409`; conflict is
  determined from the 200 `HelpdeskClaimOut.assigned_agent_user_id`. The operation
  exposes only `200`/`422`. (Audit #7)
- §5 queue read: added the **required** `group_id` query param (+ optional `state`,
  `limit` default 50/max 200) that was previously omitted. (Audit #9)
- §7: added explicit `403` (non-agent) queue handling consistent with the web
  `silent403` behavior. (Audit #14)

### Open assumptions
- **`status` vocabulary `"available"`/`"away"`** — no source uses/validates it; the
  server accepts any string and the web client never sends `status`. Confirm the
  canonical spelling with backend/web before shipping (else risk a third spelling).
- **Backend consumption of `status` for routing** — unverified; gating is
  client-only until backend confirms it honors `status` in routing/claim eligibility.
- **Android stack choices (DataStore/Compose/Hilt/Retrofit)** — engineering
  decisions, not contract-derived; cited as framework refs, not source-verified.
- **Telemetry facade / string keys / i18n plumbing (§9, §10)** — internal app
  conventions referenced from sibling tickets (AND-052/AND-111), not verifiable from
  the provided backend/frontend sources.

## 17. Test Plan

Targets: **JVM** = local JVM/Robolectric (no device); **emu35** = headless AVD
`test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API
34, arm64-v8a) on the build host. Most cases here are non-hardware and run on JVM or
emu35; the API-34-vs-35 / arm64-vs-x86 case MUST run on A15.

- **TC-AND-379-01** — Type: unit (JVM). Target: JVM. Precond: `core-model` built.
  Steps: call `Availability.ONLINE.heartbeatStatus()` and
  `Availability.AWAY.heartbeatStatus()`. Expected: returns `"available"` and
  `"away"` respectively (exact strings, lowercase). Traces: AC-2.
- **TC-AND-379-02** — Type: unit (JVM). Target: JVM. Precond: empty fake DataStore.
  Steps: construct `AvailabilityRepositoryImpl` with no persisted key; read
  `availability.value`. Expected: defaults to `AWAY` (fail-safe). Traces: AC-3.
- **TC-AND-379-03** — Type: unit (JVM). Target: JVM. Precond: fake
  `PresenceRepository` recording `sendHeartbeatNow(status)`. Steps: call
  `set(ONLINE)`. Expected: DataStore persists `ONLINE`, `availability` StateFlow
  emits `ONLINE`, and `sendHeartbeatNow("available")` invoked exactly once.
  Traces: AC-2, AC-4.
- **TC-AND-379-04** — Type: unit (JVM). Target: JVM. Precond: fake repo at AWAY then
  ONLINE. Steps: call `HelpdeskClaimGate.check()` in each state. Expected:
  `BlockedAway` when AWAY, `Allowed` when ONLINE. Traces: AC-1.
- **TC-AND-379-05** — Type: integration (JVM, persistence). Target: JVM. Precond:
  temp DataStore file. Steps: `set(ONLINE)`; dispose repo; recreate repo from the
  same DataStore. Expected: `availability.value == ONLINE` after restart (survives
  process death). Traces: AC-3.
- **TC-AND-379-06** — Type: unit/ViewModel (JVM, Turbine). Target: JVM. Precond:
  VM with availability=AWAY, MockK helpdesk repo. Steps: call
  `claim("conv_1")`. Expected: `helpdeskRepository.claim` is **never** called; a
  transient `helpdesk_claim_blocked_away` message is emitted on `uiState`.
  Traces: AC-1, AC-5.
- **TC-AND-379-07** — Type: unit/ViewModel (JVM, Turbine). Target: JVM. Precond:
  VM with availability=ONLINE; repo returns `HelpdeskClaimOut(ok=true,
  state="assigned", assigned_agent_user_id=self, assignment_version=4,
  idempotent=false)`. Steps: call `claim("conv_1")`. Expected: repo `claim` called
  once; queue item becomes assigned to self; no error/conflict message.
  Traces: AC-1.
- **TC-AND-379-08** — Type: unit/ViewModel (JVM, Turbine). Target: JVM. Precond:
  VM ONLINE; repo returns `HelpdeskClaimOut` with
  `assigned_agent_user_id != self`. Steps: call `claim("conv_1")`. Expected:
  localized conflict message (`helpdesk_claim_conflict`, "Already claimed by
  another agent") distinct from the Away message; triggers queue refresh; no crash.
  Traces: AC-5.
- **TC-AND-379-09** — Type: contract/MockWebServer (JVM). Target: JVM. Precond:
  MockWebServer enqueues `200` for heartbeat. Steps: `set(ONLINE)` then inspect the
  recorded heartbeat request. Expected: `POST /messaging/presence/heartbeat` with
  body containing `"status":"available"`; on `set(AWAY)` a request with
  `"status":"away"`. Confirms immediate out-of-band push and the single-source
  contract (UI value == sent status). Traces: AC-2, AC-4.
- **TC-AND-379-10** — Type: contract/MockWebServer (JVM). Target: JVM. Precond:
  MWS enqueues `200 HelpdeskClaimOut {idempotent:true, assigned_agent_user_id:self}`.
  Steps: ONLINE, call claim. Expected: treated as success (already-claimed-by-us),
  no error toast; response parsed into `HelpdeskClaimOut`. Then enqueue a
  `422 HTTPValidationError` and assert it maps to a failure via `detail`
  (string|array|object) handling — no crash. Traces: AC-1, AC-5.
- **TC-AND-379-11** — Type: contract/MockWebServer (JVM). Target: JVM. Precond: MWS
  enqueues `401`, then a `200` for `POST /ui/session/refresh`, then a `200
  HelpdeskClaimOut`. Steps: ONLINE, call claim. Expected: one refresh + one retry;
  claim ultimately succeeds. Enqueue a second `401` after refresh → assert single
  retry only, failure surfaced (no infinite loop), CSRF `X-CSRF-Token` header
  present on requests. Traces: AC-1.
- **TC-AND-379-12** — Type: Compose-UI (instrumented). Target: emu35 (also smoke on
  A15). Precond: queue screen rendered, availability=AWAY. Steps: observe all
  `ClaimButton`s; tap one. Expected: every Claim affordance is disabled, shows the
  "Go Online to claim" caption, and tapping performs **no** network call / no state
  change. Toggling to ONLINE enables them. Traces: AC-1.
- **TC-AND-379-13** — Type: Compose-UI accessibility (instrumented). Target: emu35.
  Precond: queue header with `AvailabilityToggle`; TalkBack semantics asserted via
  Compose test API. Steps: inspect switch and a disabled claim button. Expected:
  switch exposes `role = Switch` + `stateDescription` "Online"/"Away" +
  contentDescription "Agent availability"; disabled button announces "disabled — go
  Online to claim"; status conveyed by text label, not color alone; touch target
  ≥ 48dp. Traces: AC-7.
- **TC-AND-379-14** — Type: instrumented (offline/flaky-host). Target: A15 (toggle
  airplane mode for real radio behavior; emu35 acceptable via network shaping).
  Precond: ONLINE, device offline (connectivity probe AND-017 reports offline).
  Steps: observe claim affordances and caption precedence; flip toggle while
  offline; restore network. Expected: claim disabled with "Offline" caption taking
  precedence over the Away caption; toggle still operable and persists locally; on
  reconnect an immediate heartbeat re-asserts the persisted status; a heartbeat-push
  failure while offline is silent/non-fatal. Traces: AC-6, AC-2.
- **TC-AND-379-15** — Type: instrumented/e2e (security boundary). Target: A15.
  Precond: signed in as a **non-agent** user against dev backend (or MWS `403` for
  queue). Steps: open helpdesk queue; attempt to set ONLINE and claim. Expected:
  queue `403` is handled as an expected empty/no-access state (no error toast,
  `silent403`); the client gate is UX-only — even if forced ONLINE, the backend
  remains authoritative and the non-agent cannot claim. Confirms gate is not a
  security control. Traces: AC-1.
- **TC-AND-379-16** — Type: instrumented (ABI / API-level differences). Target:
  **A15 (MUST)** — arm64-v8a, API 34. Precond: release-config build installed on
  A15. Steps: exercise toggle → heartbeat → claim happy path on the physical device;
  compare against the same suite on emu35 (x86_64/API 35). Expected: identical
  behavior across arm64/API-34 vs x86_64/API-35 (DataStore persistence, StateFlow
  emission timing, immediate heartbeat); no ABI- or API-specific regressions.
  Traces: AC-1, AC-2, AC-3, AC-4.

### Coverage matrix
- **AC-1** (Away blocks claim / Online performs claim; zero vs one claim request):
  TC-04, TC-06, TC-07, TC-10, TC-11, TC-12, TC-15, TC-16.
- **AC-2** (immediate + periodic heartbeat carries correct `status`):
  TC-01, TC-03, TC-09, TC-14, TC-16.
- **AC-3** (persistence across restart; default AWAY): TC-02, TC-05, TC-16.
- **AC-4** (single StateFlow source for UI and heartbeat): TC-03, TC-09, TC-16.
- **AC-5** (conflict vs gate produce distinct localized messages; gate = no network):
  TC-06, TC-08, TC-10.
- **AC-6** (offline disables claim with precedence-correct caption; toggle persists):
  TC-14.
- **AC-7** (accessibility: TalkBack state/role; not color-only): TC-13.

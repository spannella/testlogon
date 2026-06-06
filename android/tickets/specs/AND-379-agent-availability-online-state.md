---
id: AND-379
title: Agent availability / online state
milestone: M8
epic: E49
priority: P2
size: M
status: draft
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
Response: `200` with empty body. Headers: cookie session + `X-CSRF-Token`. This is
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

### Queue read — `GET /messaging/helpdesk/queue`
Returns `ConversationOut[]`; relevant fields for claim state:
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
- **Claim conflict (server):** `HelpdeskClaimOut.assigned_agent_user_id != self`
  (or backend 409 mapped via AND-015) → message "Already claimed by another agent",
  refresh the queue item from the latest `GET /messaging/helpdesk/queue`.
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

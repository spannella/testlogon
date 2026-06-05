---
id: AND-127
title: DM find-or-create
milestone: M3
epic: E18
priority: P1
size: M
status: draft
depends_on: [AND-120]
blocks: [AND-123]
---

# AND-127 — DM find-or-create

## 1. Overview & Goal

This ticket implements **direct-message find-or-create**: the ability to start a
1:1 conversation with another user from a profile screen or contact entry,
landing the caller in an existing DM thread if one already exists or in a freshly
created one if it does not. The single backend operation is
`POST /messaging/conversations/dm/find-or-create`, which is **idempotent by
participant pair** — calling it twice for the same peer must return the same
conversation id.

Scope, verbatim from the backlog: *`POST /conversations/dm/find-or-create`; start
DM from profile/contact.* Acceptance: *Starting a DM opens/creates the
conversation.*

The deliverable is the typed API method, a repository operation that wraps it in
`ApiResult<Conversation>`, a `StartDmViewModel` exposing a one-shot
navigation effect, and the entry-point wiring (a "Message" affordance on the
profile/contact surface) that navigates into the thread route owned by AND-123.
This ticket owns the *find-or-create transition*: from a peer user id to a
resolved conversation id and a navigation into the thread. It does **not** own the
thread screen itself (AND-123), the conversation list (AND-121/122), message
sending (AND-124), or the conversation/message DTOs and `MessagingApi` skeleton
(AND-120, which this ticket extends).

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. The API method extends `MessagingApi` in module
  **`core-network`** (package `com.testlogon.android.core.network.messaging`); the
  repository operation lands in **`core-data`**
  (`com.testlogon.android.core.data.messaging`); the ViewModel and the entry-point
  composable land in **`feature-messaging`**
  (`com.testlogon.android.feature.messaging.dm`).
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit 2.11.0, OkHttp 4.12.0,
  Moshi 1.15.x (KSP codegen), Hilt (KSP), Coroutines/Flow, Navigation-Compose,
  Compose + Material 3, JDK 17, minSdk 24 / compileSdk 35.
- **Module layering:** `app -> feature-* -> core-*`. `feature-messaging` depends on
  `core-data`, which depends on `core-network` and `core-model`. No `feature-*`
  symbols leak downward.
- **Upstream dependency — AND-120 (Messaging API + DTOs):** supplies the
  `MessagingApi` interface, the shared Retrofit, and the `ConversationDto` /
  domain `Conversation` mappers reused here. This ticket adds one method to that
  interface and reuses its response mapping; it must not redefine the
  conversation DTO or its mapper.
- **Cross-cutting infra (transitive, no work here):** AND-011 persistent cookie
  jar, AND-012 `X-CSRF-Token` interceptor (POST is a state-changing request and
  therefore carries the CSRF header), AND-013 401-refresh `Authenticator`,
  AND-015 FastAPI `detail` error mapping, AND-018 `ApiResult<T>`. These attach to
  the shared `OkHttpClient`/Retrofit and apply to this call without changes.
- **Downstream consumers:** AND-123 (thread screen) is the navigation target;
  AND-121 (conversation list) may also surface a "new DM" entry that reuses this
  ViewModel.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` is
  plaintext HTTP and unreliable (~20s timeouts). Because find-or-create is a
  **POST** it is *not* eligible for the AND-016 idempotent-GET retry policy even
  though it is semantically idempotent; see Section 7. OpenAPI at `/openapi.json`.
  Web reference for shapes: `frontend/src/api/endpoints/messaging.ts`, shared
  types `frontend/src/api/types.ts`.

## 3. Functional Requirements

FR-1. A user viewing another user's profile or a contact-list row sees a
**"Message"** affordance (icon button + label). Tapping it triggers DM
find-or-create for that peer's user id.

FR-2. The action calls `POST /messaging/conversations/dm/find-or-create` with the
peer user id and resolves to a single conversation id, whether the conversation
pre-existed or was newly created. The two outcomes are indistinguishable to the
user except for the resulting thread being empty vs. populated.

FR-3. On success the app **navigates into the thread route** (owned by AND-123)
keyed by the resolved conversation id, replacing nothing on the back stack so the
user can back out to the originating profile/contact surface.

FR-4. While the call is in flight the affordance shows a busy state (disabled +
inline progress) and is **debounced**: rapid repeat taps do not fire concurrent
requests and do not create duplicate navigation.

FR-5. A user **cannot start a DM with themselves**. If the peer id equals the
current principal id (from the AND-029 auth state store), the affordance is hidden
(preferred) or, if the id is only known late, the call is short-circuited with a
local validation error and no network request.

FR-6. On failure the user sees an inline, retryable error (snackbar or inline
message) and remains on the originating surface; no navigation occurs.

FR-7. The navigation effect is a **one-shot** event (consumed once), not derived
from durable state, so process death / recomposition does not re-navigate.

## 4. Technical Design

### 4.1 API method (core-network, extends AND-120 `MessagingApi`)

```kotlin
// com.testlogon.android.core.network.messaging.MessagingApi (added method)
interface MessagingApi {
    // ...existing AND-120 methods...

    @POST("messaging/conversations/dm/find-or-create")
    suspend fun findOrCreateDm(
        @Body body: FindOrCreateDmRequest,
    ): ConversationDto
}
```

```kotlin
// com.testlogon.android.core.model.messaging (Moshi DTO; mapper reused from AND-120)
@JsonClass(generateAdapter = true)
data class FindOrCreateDmRequest(
    @Json(name = "user_id") val userId: String,
)
```

Path is declared without a leading slash (AND-010 convention) so it appends to the
normalized base URL. `ConversationDto` and its `toDomain()` mapper come from
AND-120 and are reused unchanged.

### 4.2 Repository operation (core-data)

```kotlin
// com.testlogon.android.core.data.messaging.MessagingRepository
interface MessagingRepository {
    // ...existing...
    suspend fun findOrCreateDm(peerUserId: String): ApiResult<Conversation>
}

@Singleton
class DefaultMessagingRepository @Inject constructor(
    private val api: MessagingApi,
    private val authState: AuthStateStore,            // AND-029, for self-DM guard
    @IoDispatcher private val io: CoroutineDispatcher,
) : MessagingRepository {

    override suspend fun findOrCreateDm(peerUserId: String): ApiResult<Conversation> =
        withContext(io) {
            val me = authState.currentUserIdOrNull()
            if (me != null && me == peerUserId) {
                return@withContext ApiResult.Failure.Validation("Cannot message yourself")
            }
            apiCall { api.findOrCreateDm(FindOrCreateDmRequest(peerUserId)).toDomain() }
        }
}
```

`apiCall { }` is the shared AND-018 wrapper that catches `HttpException`/`IOException`,
applies AND-015 `detail` mapping, and yields `ApiResult.Success/Failure`.

### 4.3 ViewModel (feature-messaging)

```kotlin
// com.testlogon.android.feature.messaging.dm.StartDmViewModel
data class StartDmUiState(
    val inFlight: Boolean = false,
    val error: UiText? = null,
)

sealed interface StartDmEffect {
    data class OpenThread(val conversationId: String) : StartDmEffect
}

@HiltViewModel
class StartDmViewModel @Inject constructor(
    private val repo: MessagingRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(StartDmUiState())
    val state: StateFlow<StartDmUiState> = _state.asStateFlow()

    private val _effects = Channel<StartDmEffect>(Channel.BUFFERED)
    val effects: Flow<StartDmEffect> = _effects.receiveAsFlow()

    fun startDm(peerUserId: String) {
        if (_state.value.inFlight) return                 // FR-4 debounce
        _state.update { it.copy(inFlight = true, error = null) }
        viewModelScope.launch {
            when (val r = repo.findOrCreateDm(peerUserId)) {
                is ApiResult.Success ->
                    _effects.send(StartDmEffect.OpenThread(r.value.id))
                is ApiResult.Failure ->
                    _state.update { it.copy(error = r.toUiText()) }
            }
            _state.update { it.copy(inFlight = false) }
        }
    }

    fun consumeError() = _state.update { it.copy(error = null) }
}
```

The `Channel` + `receiveAsFlow()` pattern gives a one-shot effect (FR-7): the
event is delivered exactly once to the collecting composable and is not replayed
after navigation/recomposition.

### 4.4 Entry-point composable

```kotlin
@Composable
fun MessagePeerButton(
    peerUserId: String,
    onOpenThread: (conversationId: String) -> Unit,
    vm: StartDmViewModel = hiltViewModel(),
) {
    val state by vm.state.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) {
        vm.effects.collect { eff ->
            when (eff) { is StartDmEffect.OpenThread -> onOpenThread(eff.conversationId) }
        }
    }
    Button(enabled = !state.inFlight, onClick = { vm.startDm(peerUserId) }) {
        if (state.inFlight) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
        else Text(stringResource(R.string.dm_message))
    }
    state.error?.let { /* host snackbar; call vm.consumeError() after shown */ }
}
```

`onOpenThread` is provided by the nav graph and routes to the AND-022/AND-123
thread destination, e.g. `navController.navigate(ThreadRoute(conversationId))`.

## 5. API Contract

**Request** — `POST /messaging/conversations/dm/find-or-create`
Headers: cookie session (auto), `X-CSRF-Token: <ui_csrf>` (AND-012),
`Content-Type: application/json`.

```json
{ "user_id": "usr_8c1f..." }
```

**Response 200/201** — the resolved (existing or new) conversation. Shape matches
AND-120 `ConversationDto` (subset shown):

```json
{
  "id": "conv_4a90...",
  "type": "dm",
  "participants": [
    { "user_id": "usr_self...", "display_name": "You" },
    { "user_id": "usr_8c1f...", "display_name": "Ada L." }
  ],
  "last_message": null,
  "unread_count": 0,
  "created_at": "2026-06-05T12:00:00Z",
  "updated_at": "2026-06-05T12:00:00Z"
}
```

A pre-existing DM returns `200` with a populated `last_message`; a newly created
one typically returns `201` with `last_message: null`. Both decode through the
same `ConversationDto.toDomain()`; the client treats them identically (FR-2). The
**exact** field names are verified against `/openapi.json` and
`frontend/src/api/endpoints/messaging.ts` during AND-120 fixture capture and
reused here.

**Errors** (FastAPI `detail`, mapped by AND-015):
- `401` — session expired → AND-013 refresh-once-then-retry; if still 401, surfaced
  as auth failure.
- `403` — CSRF/permission (e.g. peer blocked) → inline error.
- `404` — peer `user_id` unknown → `detail` string mapped to inline error.
- `422` — validation (`detail: [{msg, loc, type}]`) → first `msg` shown.

`detail` may be `string | [{msg}] | {code,...}`; AND-015 normalizes all three.

## 6. Data & State Management

- **No Room persistence in this ticket.** Find-or-create is a transient action;
  the resolved `Conversation` is handed to the thread screen via navigation
  argument (conversation id) and re-fetched/observed there per AND-123. Optionally
  the returned `Conversation` is upserted into the AND-120/AND-118 conversation
  cache so the list (AND-121) reflects the new DM immediately, but this is a
  non-blocking side effect, not a requirement of acceptance.
- **UI state** is the small `StartDmUiState` (`inFlight`, `error`) held in
  `StartDmViewModel` as `StateFlow`. **Navigation** is modeled as a one-shot
  `StartDmEffect` over a `Channel`, deliberately *not* in `StateFlow`, to avoid
  re-navigation on config change / process recreation (FR-7).
- **Self id** comes from the AND-029 `AuthStateStore` (`currentUserIdOrNull()`),
  not duplicated here.
- **No DataStore** writes. The persistent cookie jar (AND-011) carries session +
  `ui_csrf` automatically.

## 7. Error Handling & Resilience

- **Timeouts:** inherits the shared OkHttp ~20s timeouts (AND-009). On timeout the
  call returns `ApiResult.Failure.Network`; the affordance re-enables and shows a
  retryable error.
- **No automatic retry/backoff.** This is a **POST**; AND-016 backoff applies only
  to idempotent GETs. Even though find-or-create is server-side idempotent, the
  client does not auto-retry — duplicate POSTs are safe but we keep one
  in-flight request and let the user retry manually to avoid surprising bursts.
- **Debounce / single-flight:** `startDm` is a no-op while `inFlight` (FR-4),
  preventing concurrent requests and duplicate navigation from double taps.
- **401:** handled transparently by the AND-013 `Authenticator` (refresh once,
  retry once). A persistent 401 surfaces as an auth failure and the auth-gated
  router (AND-025) may redirect to login.
- **Offline:** if the connectivity probe (AND-017) reports offline, the affordance
  may pre-empt with an offline message; otherwise the network failure path handles
  it. No optimistic local DM creation — we never fabricate a conversation id.
- **Self-DM guard:** short-circuited locally as `ApiResult.Failure.Validation`
  with no network call (FR-5).

## 8. Security & Privacy

- All requests ride the **cookie-based session** (AND-011) with the
  `X-CSRF-Token` header injected by AND-012; the POST is rejected (`403`) without
  a valid CSRF token, which is the intended protection against cross-site DM
  creation.
- No credentials, tokens, or peer PII are logged. The peer `user_id` is an opaque
  identifier; do not log `display_name` (Section 10).
- Authorization (whether the caller may DM the peer — blocks, privacy settings) is
  enforced **server-side**; the client honors `403`/`404` without leaking whether
  a conversation already existed.
- Dev backend is plaintext HTTP (cleartext permitted only for the dev flavor per
  AND-006); release builds disallow cleartext.

## 9. Accessibility & i18n

- The "Message" affordance has a `contentDescription` (e.g.
  `R.string.dm_message_cd`) and a visible label; both are externalized strings, no
  hardcoded text.
- Busy state announces progress via the standard `CircularProgressIndicator`
  semantics; the button reports `disabled` while in flight so TalkBack does not
  invite a tap.
- Touch target ≥ 48dp. Error messages are surfaced via the host snackbar (live
  region) so they are announced.
- All user-facing strings (`dm_message`, `dm_message_cd`, error fallbacks) live in
  `feature-messaging/src/main/res/values/strings.xml`. RTL handled by Compose
  defaults.

## 10. Telemetry & Logging

- Emit a structured event `dm_find_or_create` with attributes: `outcome`
  (`opened_existing` | `created` | `error`), `error_kind` (network/http/validation,
  on failure), and `latency_ms`. Do **not** include `user_id`, `conversation_id`,
  or any display name in analytics payloads.
- Debug-build OkHttp logging (AND-009) logs the request line and status but body
  logging is restricted in release. Repository logs failures at `WARN` with
  error kind only, never peer identity.

## 11. Testing Strategy

**Unit — repository (`core-data`, MockWebServer via AND-046 harness):**
- `findOrCreateDm` posts to `messaging/conversations/dm/find-or-create` with body
  `{"user_id": "<peer>"}` and request carries `X-CSRF-Token` (assert recorded
  request path, method `POST`, JSON body).
- `200` existing-DM fixture and `201` new-DM fixture both map to
  `ApiResult.Success<Conversation>` with the expected id.
- Self-DM (peer id == stored self id) returns `ApiResult.Failure.Validation` with
  **no** recorded request.
- `404`/`422` fixtures map to `ApiResult.Failure` with the `detail`-derived message
  (verifies AND-015 integration).

**Unit — ViewModel (Turbine over `state` and `effects`):**
- Success emits exactly one `StartDmEffect.OpenThread(id)` and leaves
  `inFlight=false`, `error=null`.
- Failure emits no effect and sets `error`; `consumeError()` clears it.
- Calling `startDm` twice while in flight fires the repository **once** (debounce).

**Compose UI test (`feature-messaging`, AND-046 fixtures):**
- Tapping "Message" with a stubbed success navigates to the thread route with the
  resolved conversation id (assert nav arg).
- Tapping with a stubbed failure shows the error and stays on the surface.
- Button is disabled while in flight.

All tests run under AND-050 CI and must be deterministic against the flaky-host
simulation.

## 12. Dependencies & Sequencing

- **Depends on AND-120** (Messaging API + DTOs): provides `MessagingApi`, the
  shared Retrofit, `ConversationDto`, and its `toDomain()` mapper. This ticket adds
  one method and one request DTO; it cannot land before AND-120.
- **Soft dependency — AND-029** (auth state store) for the self-DM guard; if not
  yet available, the guard can read the principal id from the existing
  `/ui/me`-backed store, but AND-029 is the canonical source.
- **Blocks AND-123** (thread screen) only at the *navigation/UX* level: this ticket
  routes into the thread destination, so the thread route id/argument contract
  (AND-022/AND-123) must be agreed. Functionally the two can be developed in
  parallel against a stub route.
- Infra (AND-009/011/012/013/015/018) is assumed already merged.

## 13. Risks & Open Questions

- **R1 — Exact endpoint path.** Backlog writes `POST /conversations/dm/find-or-create`
  but the AND-120 base is `/messaging/conversations`. This spec assumes
  `messaging/conversations/dm/find-or-create`. **Action:** confirm against
  `/openapi.json` during AND-120 fixture capture; adjust the single `@POST` path if
  the backend omits the `messaging` prefix.
- **R2 — Request body key.** Assumed `{"user_id": "..."}`. The web reference may use
  `participant_id` / `recipient_id`. Confirm against
  `frontend/src/api/endpoints/messaging.ts`.
- **R3 — Status code semantics.** Whether new vs. existing returns `201` vs `200` is
  assumed but not load-bearing; the client treats both identically. Confirm only if
  product wants a "new conversation" UX distinction.
- **R4 — Group DM future.** This ticket is strictly 1:1. A future multi-participant
  create would need a different endpoint/body and is out of scope.
- **R5 — Self-DM allowed?** Some products permit "note to self" DMs. We assume
  **not**; if the backend supports it, drop the FR-5 guard.

## 14. Acceptance Criteria

AC-1. Tapping "Message" on a profile/contact for peer P issues exactly one
`POST messaging/conversations/dm/find-or-create` with body `{"user_id": "P"}`,
carrying the session cookie and `X-CSRF-Token`. (MockWebServer test.)

AC-2. When a DM with P already exists, the response is mapped and the user is
navigated into **that** conversation's thread. When none exists, the newly created
conversation is opened. Both paths land in the thread route keyed by the resolved
id. (UI + repository tests.) — satisfies backlog acceptance *"Starting a DM
opens/creates the conversation."*

AC-3. Repeated/double taps while a request is in flight do not produce duplicate
requests or duplicate navigation. (ViewModel test.)

AC-4. A failure (network/`404`/`422`/`403`) shows a retryable inline error and does
**not** navigate; the affordance re-enables. (UI + repository tests.)

AC-5. Attempting to DM oneself produces no network request and a local validation
error (or the affordance is hidden). (Repository test.)

AC-6. Navigation fires exactly once per success and does not re-fire on
recomposition/config change. (ViewModel effect test.)

## 15. Definition of Done

- `MessagingApi.findOrCreateDm` and `FindOrCreateDmRequest` merged in
  `core-network`/`core-model`; `MessagingRepository.findOrCreateDm` merged in
  `core-data`; `StartDmViewModel` + `MessagePeerButton` merged in
  `feature-messaging`, all under `com.testlogon.android.*`.
- The "Message" affordance is wired on the profile/contact surface and navigates
  into the AND-123 thread route (against a stub route if AND-123 is not yet
  merged).
- All Section 11 unit and Compose tests pass deterministically in AND-050 CI;
  ktlint/detekt (AND-005) clean.
- No PII (`user_id`, names) in logs/analytics; CSRF header present on the POST.
- Endpoint path and request-body key reconciled with `/openapi.json` (R1/R2
  resolved) or the deviation documented in the PR.
- Strings externalized; affordance has content description and ≥48dp target.
- PR description links AND-120 (upstream) and AND-123 (nav target) and notes any
  unresolved open questions from Section 13.

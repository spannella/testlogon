---
id: AND-127
title: DM find-or-create
milestone: M3
epic: E18
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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

**Request** — `POST /messaging/conversations/dm/find-or-create` (path **verified**
in OpenAPI index, op `find_or_create_dm_...`; `messaging` prefix confirmed present).
Headers: cookie session (auto, `credentials: "include"`), `X-CSRF-Token: <ui_csrf>`
(AND-012; web client reads the `ui_csrf` cookie and sets this header —
`client.ts`), `Content-Type: application/json`. Note: the web client **also** sends
`Authorization: Bearer <accessToken>` when an access token is present in the auth
store (`client.ts`), so the backend accepts both cookie-session and bearer auth;
the Android client uses the cookie-session path (AND-011).

```json
{ "user_id": "usr_8c1f..." }
```

**Response 200** — the resolved (existing or new) conversation. The backend schema
is `ConversationOut` (verified in `/openapi.json`); the AND-120 `ConversationDto`
mirrors it and `toDomain()` maps `conversation_id` → domain `Conversation.id`.
**Corrected** subset (real field names/types):

```json
{
  "conversation_id": "conv_4a90...",
  "type": "dm",
  "status": "active",
  "participant_count": 2,
  "participants": [
    { "user_id": "usr_self...", "display_name": "You", "status": "active", "role": "member" },
    { "user_id": "usr_8c1f...", "display_name": "Ada L.", "status": "active", "role": "member" }
  ],
  "last_message": null,
  "last_message_at": null,
  "last_message_preview": null,
  "unread_count": 0,
  "created_at": 1749124800,
  "created_by": "usr_self..."
}
```

Corrections vs. the prior draft (verified against `components.schemas.ConversationOut`):
the id field is **`conversation_id`** (not `id`); timestamps are **integer epoch
seconds** (`created_at`), not ISO strings; there is **no `updated_at`** field — the
nearest analogue is the nullable `last_message_at`; `type`, `status`,
`participant_count`, `created_at`, `created_by` are **required**. `participants`
items are `app__routers__messaging__ParticipantOut` whose required fields are
`user_id`, `status`, `role` (with nullable `display_name`, `profile_photo_url`).

The OpenAPI declares a single success code **`200:ConversationOut`** for this
operation (no documented `201`). The web client (`messaging.ts: findOrCreateDm`)
treats existing vs. new identically — a populated `last_message` distinguishes an
existing thread; both decode through `ConversationDto.toDomain()` (FR-2). A `201`
for new conversations is an **unverified assumption** and is non-load-bearing.

**Errors** (FastAPI `detail`, mapped by AND-015):
- `422` — validation (`detail: [{loc, msg, type}]`) → first `msg` shown. This is the
  **only** error code documented for this op in `/openapi.json` (resp=`422:HTTPValidationError`).
- `401` — session expired / invalid token → AND-013 refresh-once-then-retry; if
  still 401, surfaced as auth failure. (Handled by shared auth infra, not declared
  per-op in OpenAPI.)
- `403` — CSRF/permission (e.g. peer blocked) → inline error. **Plausible but not
  declared** in OpenAPI for this op; the web client has generic 403 handling
  (`client.ts: mapAuthorizationError`). Treated as an unverified assumption.
- `404` — peer `user_id` unknown → `detail` mapped to inline error. **Not declared**
  in OpenAPI for this op (unverified assumption); client still handles it generically.

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
  `X-CSRF-Token` header injected by AND-012 (verified: the web client sets
  `X-CSRF-Token` from the `ui_csrf` cookie in `client.ts`). The POST is expected to
  be rejected without a valid CSRF token, the intended protection against cross-site
  DM creation. (The web client additionally attaches `Authorization: Bearer` when an
  access token exists; the Android client relies on the cookie session per AND-011.)
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

- **R1 — Exact endpoint path. RESOLVED (verified).** OpenAPI index line 314 declares
  `POST /messaging/conversations/dm/find-or-create`; the `messaging` prefix IS
  present, matching this spec. No change needed.
- **R2 — Request body key. RESOLVED (verified).** Schema `FindOrCreateDmIn` has a
  single required property `user_id: string`; the web client sends `{ user_id }`
  (`messaging.ts: findOrCreateDm`). The assumed key is correct.
- **R3 — Status code semantics. RESOLVED (corrected).** OpenAPI declares only
  `200:ConversationOut` for this op (no `201`). New vs. existing is not signalled by
  status code; the client distinguishes by `last_message`/`last_message_at` and
  treats both identically. The earlier `201` claim was an unverified assumption.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Endpoint path is `POST /messaging/conversations/dm/find-or-create`.**
   VERDICT: Verified. SOURCE: OpenAPI index `POST /messaging/conversations/dm/find-or-create`
   (op `find_or_create_dm_messaging_conversations_dm_find_or_create_post`);
   frontend `src/api/endpoints/messaging.ts: findOrCreateDm`.
2. **HTTP method is POST.** VERDICT: Verified. SOURCE: same OpenAPI line (METHOD=POST);
   `src/api/endpoints/messaging.ts: findOrCreateDm` (`api.post`).
3. **Request body is `{ "user_id": "<peer>" }` (single required string).**
   VERDICT: Verified. SOURCE: `components.schemas.FindOrCreateDmIn` (property `user_id`,
   required); `src/api/endpoints/messaging.ts: findOrCreateDm` sends `{ user_id: userId }`.
4. **Response schema is `ConversationOut` with success code 200.** VERDICT: Verified
   (and Corrected re: the prior `200/201` claim). SOURCE: OpenAPI index `resp=200:ConversationOut;422:HTTPValidationError`.
5. **Response id field is `conversation_id` (not `id`).** VERDICT: Corrected. SOURCE:
   `components.schemas.ConversationOut` (required `conversation_id`);
   `src/api/endpoints/messagingAdapter.ts: adaptConversation` reads `raw.conversation_id`.
   The domain `Conversation.id` is the AND-120 mapping of `conversation_id`.
6. **Timestamps are integer epoch seconds; no `updated_at` field.** VERDICT: Corrected.
   SOURCE: `components.schemas.ConversationOut` (`created_at: integer`,
   `last_message_at: integer|null`; no `updated_at`); `messagingAdapter.ts` wraps
   `created_at`/`last_message_at` in `toNum(...)`.
7. **Participants expose `user_id` and `display_name`.** VERDICT: Verified. SOURCE:
   `components.schemas.app__routers__messaging__ParticipantOut` (required `user_id`,
   `status`, `role`; nullable `display_name`).
8. **`unread_count` defaults to 0 and `last_message` is nullable.** VERDICT: Verified.
   SOURCE: `components.schemas.ConversationOut` (`unread_count` default 0;
   `last_message` anyOf MessageOut|null).
9. **CSRF: POST carries `X-CSRF-Token` from the `ui_csrf` cookie.** VERDICT: Verified.
   SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
10. **Session is cookie-based (`credentials: "include"`).** VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`credentials: "include"` on the fetch).
11. **Web client also sends `Authorization: Bearer <accessToken>`.** VERDICT: Verified
    (refines the spec's "cookie-only" framing). SOURCE: `src/api/client.ts`
    (`headers.set("Authorization", \`Bearer ${accessToken}\`)`).
12. **401 → refresh-once-then-retry.** VERDICT: Verified (transport behavior).
    SOURCE: `src/api/client.ts` (automatic token refresh on 401); Android side AND-013
    `Authenticator` (framework ref:
    https://square.github.io/okhttp/recipes/#handling-authentication-kt-java).
13. **422 error shape is `detail: [{ loc, msg, type }]`.** VERDICT: Verified. SOURCE:
    `components.schemas.HTTPValidationError` → `ValidationError` (required `loc`, `msg`, `type`).
14. **403 (CSRF/block) and 404 (unknown peer) are returnable.** VERDICT:
    Unverified-assumption. SOURCE: not declared for this op in OpenAPI (only `200`/`422`);
    generic handling exists in `src/api/client.ts: mapAuthorizationError`.
15. **New-vs-existing distinguished by `201` vs `200`.** VERDICT: Unverified-assumption
    (kept as non-load-bearing). SOURCE: OpenAPI declares only `200`; client treats both
    paths identically (`messaging.ts: findOrCreateDm`).
16. **POST is excluded from AND-016 idempotent-GET retry policy.** VERDICT:
    Unverified-assumption (internal Android policy, not in external sources). SOURCE: this
    spec / AND-016; consistent with REST idempotency conventions (framework ref:
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/POST).
17. **One-shot navigation via Channel + receiveAsFlow (no re-navigation on
    recomposition/config change).** VERDICT: Verified (framework choice). SOURCE: Android
    guidance on events vs. state (framework ref:
    https://developer.android.com/topic/architecture/ui-layer/events).
18. **Self-DM guard is a local pre-check.** VERDICT: Unverified-assumption (product/
    backend may allow note-to-self). SOURCE: no backend constraint found in OpenAPI; see R5.

### Corrections made

- Response id field corrected from `id` to **`conversation_id`** (§5 example + audit).
- Timestamps corrected from ISO-8601 strings to **integer epoch seconds**, and the
  nonexistent **`updated_at`** removed (replaced with `last_message_at`) (§5).
- Success codes corrected from "200/201" to **200 only**; `201` reclassified as an
  unverified, non-load-bearing assumption (§5, §13 R3).
- §5 example expanded with the actually-required fields (`status`, `participant_count`,
  `created_by`) and correct participant fields (`status`, `role`).
- Error table: `403`/`404` downgraded to **plausible/unverified** (only `422` is
  declared for this op); `422` `detail` tuple order normalized to `[{loc, msg, type}]`.
- Auth framing refined: cookie session + `X-CSRF-Token` **plus** an `Authorization:
  Bearer` header from the web auth store (§5, §8).
- §13 R1 and R2 marked **RESOLVED/verified**; R3 marked **RESOLVED/corrected**.

### Open assumptions

- **403/404 for blocked/unknown peers** — not declared in OpenAPI for this op; only
  `200`/`422` are. The client must still handle them defensively. (Why: backend may
  return generic auth/not-found responses not enumerated per-op.)
- **`201` for newly-created conversations** — never observed in OpenAPI; client treats
  both outcomes identically, so this is non-load-bearing. (Why: status semantics not
  documented; could only be confirmed by a live capture against the dev host.)
- **Self-DM is disallowed (FR-5 guard)** — no backend rule found in the sources. (Why:
  the OpenAPI does not express same-participant constraints; product decision in R5.)
- **AND-016 retry exclusion for POST** — an internal Android transport policy not
  expressible from the backend/frontend sources. (Why: client-side concern.)
- **The AND-120 `ConversationDto`/`toDomain()` exact Kotlin shape** — defined in a
  sibling ticket, not in these sources. (Why: out of this repo's reference set.)

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device); **MWS** =
contract test over MockWebServer (JVM); **EMU** = headless emulator AVD `test35`
(x86_64, API 35); **DEVICE** = physical Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R, API 34, arm64-v8a). This ticket is pure networking + ViewModel +
a small Compose affordance with no camera/biometrics/WebRTC/push, so the emulator is
sufficient for all instrumented/Compose cases; a single ABI smoke is pinned to the
physical device to cover arm64-v8a / API-34.

**TC-AND-127-01 — Happy path: request line + body + CSRF**
Type: contract/MockWebServer. Target: MWS (`DefaultMessagingRepository`).
Preconditions: AuthStateStore self id `usr_self`; `ui_csrf` cookie present; MWS enqueues
`200` with a `ConversationOut` fixture (`conversation_id: conv_1`).
Steps: call `findOrCreateDm("usr_peer")`; inspect the `RecordedRequest`.
Expected: method `POST`, path `/messaging/conversations/dm/find-or-create`, JSON body
exactly `{"user_id":"usr_peer"}`, header `X-CSRF-Token` present; result
`ApiResult.Success` with `conversation.id == "conv_1"`.
Traces: AC-1.

**TC-AND-127-02 — Existing DM maps and opens that thread**
Type: integration (repo+VM with MWS). Target: MWS + JVM.
Preconditions: MWS `200` fixture with populated `last_message`/`last_message_at`,
`conversation_id: conv_existing`.
Steps: `StartDmViewModel.startDm("usr_peer")`; collect `effects` via Turbine.
Expected: exactly one `OpenThread("conv_existing")`; `state.inFlight` returns to false;
no error. Traces: AC-2.

**TC-AND-127-03 — Newly created DM maps and opens (empty thread)**
Type: integration. Target: MWS + JVM.
Preconditions: MWS `200` fixture with `last_message: null`, `last_message_at: null`,
`unread_count: 0`, `conversation_id: conv_new`.
Steps: `startDm("usr_peer")`; collect effects.
Expected: one `OpenThread("conv_new")`; client behaves identically to TC-02 (no 201
dependence). Traces: AC-2.

**TC-AND-127-04 — Field-shape contract (correct names/types decode)**
Type: contract/MockWebServer. Target: MWS.
Preconditions: fixture uses real `ConversationOut` shape — `conversation_id`,
integer `created_at`, `participants[].{user_id,display_name,status,role}`, no `updated_at`.
Steps: decode via the AND-120 `ConversationDto` adapter + `toDomain()`.
Expected: decode succeeds; domain `id == conversation_id`; integer `created_at` parsed
as epoch (not a string); absence of `updated_at` causes no failure. Traces: AC-1, AC-2.

**TC-AND-127-05 — Debounce / single-flight on rapid taps**
Type: unit (ViewModel). Target: JVM (Turbine + fake repo with a suspended deferred).
Preconditions: repo `findOrCreateDm` suspends until released; spy counts invocations.
Steps: call `startDm("usr_peer")` twice before the first completes; release.
Expected: repository invoked exactly **once**; exactly one `OpenThread` effect emitted.
Traces: AC-3.

**TC-AND-127-06 — Self-DM short-circuit, no network**
Type: unit (repository). Target: MWS (assert no recorded request).
Preconditions: AuthStateStore self id `usr_self`.
Steps: call `findOrCreateDm("usr_self")`.
Expected: `ApiResult.Failure.Validation("Cannot message yourself")`; MWS records
**zero** requests. Traces: AC-5.

**TC-AND-127-07 — 422 validation error maps to inline message**
Type: contract/MockWebServer. Target: MWS.
Preconditions: MWS `422` body `{"detail":[{"loc":["body","user_id"],"msg":"field required","type":"missing"}]}`.
Steps: call `findOrCreateDm("usr_peer")`.
Expected: `ApiResult.Failure` whose message derives from the first `detail[].msg`
("field required") per AND-015; no `Conversation` produced. Traces: AC-4.

**TC-AND-127-08 — 404/403 generic-failure path (defensive, unverified codes)**
Type: contract/MockWebServer. Target: MWS.
Preconditions: parametrized MWS responses `404` and `403` with `{"detail":"..."}`.
Steps: call `findOrCreateDm("usr_peer")` for each.
Expected: `ApiResult.Failure` with the `detail` string surfaced; ViewModel sets `error`
and emits **no** `OpenThread`. (Documents that these codes are not OpenAPI-declared but
must be handled.) Traces: AC-4.

**TC-AND-127-09 — Timeout/offline failure re-enables affordance**
Type: integration (flaky-host simulation). Target: MWS (`SocketPolicy.NO_RESPONSE` /
throttled body to mimic the ~20s dev-host stall).
Preconditions: MWS configured to stall past the OkHttp timeout (AND-009).
Steps: `startDm("usr_peer")`; await completion.
Expected: `ApiResult.Failure.Network`; `state.inFlight` false; `state.error` set;
no navigation. Traces: AC-4.

**TC-AND-127-10 — One-shot navigation survives recomposition/config change**
Type: Compose-UI. Target: EMU.
Preconditions: `MessagePeerButton` hosted in a test composable with a stubbed
success VM; nav callback records conversation ids.
Steps: tap "Message"; observe one navigation; trigger recomposition/config change
(rotate/`StateRestorationTester`); confirm no re-navigation.
Expected: `onOpenThread` invoked **exactly once** for the success; not re-fired after
recomposition. Traces: AC-6.

**TC-AND-127-11 — Compose: failure shows error and does not navigate; busy disables**
Type: Compose-UI. Target: EMU.
Preconditions: stubbed VM returns failure for one tap, then a slow success for another.
Steps: tap with failure → assert error surfaced and no nav; tap with in-flight success →
assert button reports `disabled`/progress while in flight.
Expected: error visible, no navigation on failure; button non-clickable while
`inFlight`. Traces: AC-3, AC-4.

**TC-AND-127-12 — Accessibility of the "Message" affordance**
Type: Compose-UI (a11y assertions). Target: EMU.
Preconditions: `MessagePeerButton` rendered.
Steps: assert non-empty `contentDescription` from `R.string.dm_message_cd`; touch
target ≥ 48dp; in-flight state exposes `disabled` semantics so TalkBack does not invite
a tap; error is delivered to a live-region snackbar host.
Expected: all a11y assertions pass. Traces: AC-3, AC-4.

**TC-AND-127-13 — ABI/API smoke on physical hardware (arm64-v8a / API 34)**
Type: instrumented/e2e. Target: **DEVICE (must run on the physical device)**.
Preconditions: app installed on SM-A156U; stub/local server returns a `200`
`ConversationOut`.
Steps: from a profile surface tap "Message"; observe navigation into the thread route
keyed by the resolved `conversation_id`.
Expected: find-or-create succeeds and navigates on arm64-v8a/API-34; no
ABI/JSON-codec divergence from the x86_64/API-35 emulator runs. (Pinned to the device
to catch arm64-vs-x86 and API-34-vs-35 differences.) Traces: AC-2.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (one POST, correct body, cookie + CSRF) | TC-01, TC-04 |
| AC-2 (existing/new both open the thread route) | TC-02, TC-03, TC-04, TC-13 |
| AC-3 (debounce: no duplicate request/navigation) | TC-05, TC-11, TC-12 |
| AC-4 (failure → retryable inline error, no nav) | TC-07, TC-08, TC-09, TC-11, TC-12 |
| AC-5 (self-DM → no request, local validation error) | TC-06 |
| AC-6 (navigation fires once, no re-fire) | TC-10 |

---
id: AND-146
title: Typing indicators
milestone: M3
epic: E20
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-144, AND-143, AND-009]
blocks: []
---

# AND-146 — Typing indicators

## 1. Overview & Goal

This ticket adds real-time **typing indicators** to the conversation (direct-message
and group-thread) experience of the native Android TestLogon client. When a participant
in a conversation is composing a message, every other foregrounded participant viewing
that conversation sees a transient "X is typing…" affordance; when the composer stops
typing, sends the message, or leaves the screen, the indicator clears.

The feature has two halves: **Send** — the composer emits a debounced typing signal to
`POST /messaging/conversations/{conversation_id}/typing` with body `{"is_typing": true}`
while text is entered, and `{"is_typing": false}` when input idles, is cleared, or the message
is sent. **Receive** — inbound `typing:update` events arrive over the already-established SSE
messaging stream (AND-144 on the SSE core in AND-143), with a `GET .../typing` poll as a
fallback; the conversation ViewModel folds these into UI state with per-user expiry so stale
indicators self-clear even if an `is_typing:false` event is dropped.

> **Corrected during review (2026-06-06):** the endpoint is namespaced under `/messaging/...`,
> the request body uses a boolean `is_typing` field (schema `TypingIn`, not a `state`
> start/stop string), and the SSE event is named `typing:update` carrying
> `{conversation_id, user_id, is_typing, updated_at}` — there is no `display_name` or
> `state` field. See §16 for the full audit.

The backlog success condition is precise and testable: **typing shows and clears correctly**.
The design therefore prioritizes deterministic clearing (expiry timers, lifecycle teardown)
over visual polish, because the dev host (`http://18.222.237.167:8000`, plaintext HTTP,
unreliable) will drop and reorder events. Out of scope: presence dots (AND-145), read receipts
(AND-147), and message-list rendering (AND-144 / epic E19).

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Feature module:** `feature-messaging` (consumes `core-network`, `core-model`,
  `core-ui`, `core-data`). This ticket lives in `feature-messaging`; it does **not** create
  a new module.
- **Upstream dependencies:**
  - **AND-143 (SSE client core)** — `OkHttp EventSource` wrapper exposing a
    `Flow<SseEvent>`, lifecycle-aware, auth-cookie aware, with reconnect/backoff.
  - **AND-144 (Messaging events stream)** — subscribes `/messaging/events/stream`, decodes
    the event envelope, and dispatches `new-message`/`edit`/`delete`. This ticket extends that
    dispatcher with a `typing` event branch rather than opening a second stream.
  - **AND-009 (OkHttp client)** — shared `OkHttpClient` (≈20s timeouts, redacting logging
    interceptor) used by the Retrofit service that issues the typing POST.
- **Web reference (verified):** typing behavior lives in
  `src/api/endpoints/messaging.ts` (`sendTyping`/`getTyping`),
  `src/hooks/useMessagingStream.ts` (the `typing:update` SSE branch), and
  `src/pages/messages/TypingIndicator.tsx` (the component + `useTypingSignal` hook); DTO
  shapes are in `src/api/types.ts` (`TypingUser`). Field names were confirmed against
  `reference/openapi.pretty.json` (`TypingIn`, `TypingUser`) — see §16. Note the web
  client labels typers by `user_id` (the typing payload carries **no** display name).
- **Auth:** cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`; persistent
  cookie jar. The typing POST is a state-changing request and therefore **must** carry the
  CSRF header (handled by the shared CSRF interceptor from the network layer).

## 3. Functional Requirements

FR-1 **Emit start:** When the user types in the conversation composer and the field is
non-empty, the client sends a typing-start signal to the backend, debounced so at most one
request fires per `TYPING_THROTTLE` window (default **3s**) while typing continues.

FR-2 **Heartbeat while typing:** If the user keeps typing past the throttle window, a
refresh start signal is re-sent every `TYPING_THROTTLE` so the receiver's expiry timer is
kept alive.

FR-3 **Emit stop:** A typing-stop signal is sent when any of: (a) the composer goes idle for
`TYPING_IDLE` (default **5s**) after the last keystroke; (b) the field is cleared to empty;
(c) the message is sent; (d) the user navigates away / the screen stops (lifecycle
`ON_STOP`).

FR-4 **Receive & display:** Inbound `typing:update` events (`is_typing: true`) for the
currently open conversation update a set of "who is typing" users (excluding the local user).
The composer area shows: `"<name> is typing…"` for one user, `"<name> and <name> are
typing…"` for two, `"Several people are typing…"` for three or more. **Display-name caveat:**
the typing payload carries only `user_id` (no display name — confirmed against schema
`TypingUser` and the web `TypingIndicator.tsx`, which renders the raw `user_id`). The Android
client must resolve `user_id → displayName` from the already-loaded conversation participant
roster (AND-144 message authors); when the id is unknown it falls back to `"Someone"`.

FR-5 **Self-clearing:** Each remote typing entry carries an expiry. If no refresh
`typing:update`/`is_typing:true` event arrives within `TYPING_TTL` (default **6s**, > sender
throttle), the entry is removed even without an `is_typing:false` event. An explicit
`is_typing:false` event removes it immediately. (The web reference uses a 5s client TTL +
a 2s cleanup sweep, and the POST response returns a server `ttl` field — see §16.)

FR-6 **Scope correctness:** Only typing events whose `conversation_id` matches the open
conversation affect the visible indicator. Events for other conversations are ignored by
this screen (the conversation **list** badge is out of scope here).

FR-7 **No self-echo:** The backend may echo the sender's own typing event back over the
stream; the client filters events where `user_id == me.id`.

FR-8 **Resilience:** Send failures (timeout / 5xx / offline) are swallowed silently — typing
is best-effort and must never surface an error toast or block the composer.

## 4. Technical Design

All new code lives in `feature-messaging`. Package root:
`com.testlogon.android.feature.messaging`.

### 4.1 Domain model (`core-model`)

```kotlin
// core-model
data class TypingUser(
    val userId: String,
    val displayName: String,
    val conversationId: String,
    val expiresAtMillis: Long, // wall-clock expiry for self-clearing (FR-5)
)
```

### 4.2 Inbound event type (extends AND-144 envelope)

AND-144 decodes a sealed `MessagingEvent`. This ticket adds one variant; no new stream.

```kotlin
sealed interface MessagingEvent {
    // ... NewMessage, EditMessage, DeleteMessage from AND-144 ...
    data class Typing(
        val conversationId: String,   // data.conversation_id
        val userId: String,           // data.user_id
        val isTyping: Boolean,        // data.is_typing
        val updatedAtSeconds: Long,   // data.updated_at (epoch seconds)
    ) : MessagingEvent
}
```

> **Corrected during review:** the SSE event is named `typing:update` (not `typing`), and its
> `data` payload is `{conversation_id, user_id, is_typing, updated_at}`. There is no
> `display_name` and no `state` enum — start/stop is the boolean `is_typing`. The
> `displayName` is resolved client-side from the participant roster (FR-4), not from this
> event. The Moshi adapter in `feature-messaging` maps the SSE `event: typing:update` /
> `data:` payload (§5) into `MessagingEvent.Typing`. A missing/unparseable `is_typing`
> defaults to `true` (fail-open toward showing, since expiry will clear it anyway); a missing
> `updated_at` defaults to the device's current epoch-seconds.

### 4.3 Send path — `TypingSignalController`

A per-screen helper that converts composer text changes into debounced network calls. It is
created in the ViewModel and driven by a `MutableSharedFlow<TypingInput>`.

```kotlin
sealed interface TypingInput { object Keystroke : TypingInput; object Cleared : TypingInput
    object Sent : TypingInput; object Left : TypingInput }

class TypingSignalController @AssistedInject constructor(
    @Assisted private val conversationId: String,
    private val repo: TypingRepository,
    @Dispatcher(IO) private val io: CoroutineDispatcher,
) {
    private val input = MutableSharedFlow<TypingInput>(extraBufferCapacity = 16)
    fun onInput(i: TypingInput) { input.tryEmit(i) }

    /** Collect within viewModelScope; auto-stops via finally on scope cancel. */
    suspend fun run() {
        var lastStart = 0L
        var typing = false
        try {
            input
                // idle timeout produces a synthetic Cleared after TYPING_IDLE of silence
                .debounceOrTimeout(TYPING_IDLE)
                .collect { event ->
                    when (event) {
                        is TypingInput.Keystroke -> {
                            val now = SystemClock.elapsedRealtime()
                            if (!typing || now - lastStart >= TYPING_THROTTLE) {
                                lastStart = now; typing = true
                                runCatching { repo.start(conversationId) } // FR-8 swallow
                            }
                        }
                        else -> if (typing) { typing = false
                            runCatching { repo.stop(conversationId) } }
                    }
                }
        } finally {
            if (typing) withContext(NonCancellable + io) {
                runCatching { repo.stop(conversationId) } // FR-3(d) lifecycle teardown
            }
        }
    }
    @AssistedFactory interface Factory { fun create(conversationId: String): TypingSignalController }
}
```

`Keystroke` is mapped from `onValueChange` only when the resulting text is non-empty; an
empty result maps to `Cleared`. `Sent`/`Left` are emitted by the ViewModel on those events.

### 4.4 Receive path — folding into UI state

The conversation ViewModel already collects `MessagingEvent` from AND-144. This ticket adds
a `typingUsers: StateFlow<List<TypingUser>>` derived stream plus a ticking expiry sweep.

```kotlin
@HiltViewModel
class ConversationViewModel @Inject constructor(
    private val events: MessagingEventBus,          // AND-144
    private val typingControllerFactory: TypingSignalController.Factory,
    private val session: SessionStore,              // current user id
    savedState: SavedStateHandle,
) : ViewModel() {
    private val conversationId: String = checkNotNull(savedState["conversationId"])
    private val typing = MutableStateFlow<Map<String, TypingUser>>(emptyMap())

    val typingUsers: StateFlow<List<TypingUser>> = typing
        .map { it.values.sortedBy(TypingUser::displayName) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val controller = typingControllerFactory.create(conversationId)

    init {
        viewModelScope.launch { controller.run() }
        viewModelScope.launch {                       // ingest events
            events.stream
                .filterIsInstance<MessagingEvent.Typing>()
                .filter { it.conversationId == conversationId }
                .filter { it.userId != session.userId }      // FR-7
                .collect { applyTyping(it) }
        }
        viewModelScope.launch { while (isActive) { sweepExpired(); delay(1_000) } } // FR-5
    }

    fun onComposerChanged(text: String) =
        controller.onInput(if (text.isBlank()) TypingInput.Cleared else TypingInput.Keystroke)
    fun onMessageSent() = controller.onInput(TypingInput.Sent)

    private fun applyTyping(e: MessagingEvent.Typing) = typing.update { m ->
        if (!e.isTyping) {
            m - e.userId                                  // is_typing:false removes immediately
        } else {
            m + (e.userId to TypingUser(
                e.userId, resolveName(e.userId) ?: "Someone", e.conversationId,
                System.currentTimeMillis() + TYPING_TTL_MS))  // displayName from roster, FR-4
        }
    }
    private fun sweepExpired() = typing.update { m ->
        val now = System.currentTimeMillis(); m.filterValues { it.expiresAtMillis > now }
    }
}
```

### 4.5 UI — `TypingIndicator` composable (`core-ui` or `feature-messaging`)

```kotlin
@Composable
fun TypingIndicator(users: List<TypingUser>, modifier: Modifier = Modifier) {
    AnimatedVisibility(visible = users.isNotEmpty(), modifier = modifier,
        enter = fadeIn(), exit = fadeOut()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AnimatedTypingDots()              // three bouncing dots
            Spacer(Modifier.width(8.dp))
            Text(text = typingLabel(users), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
```

`typingLabel` implements FR-4 pluralization via `pluralStringResource`. Placed directly above
the composer in `ConversationScreen`, it does not push the message list (overlay/insets so the
list scroll position is stable when the indicator appears/disappears).

### 4.6 Lifecycle

The composing screen ties `TypingSignalController` teardown to `Lifecycle.State.STARTED`: a
`LifecycleEventObserver` (or `repeatOnLifecycle`) emits `TypingInput.Left` on `ON_STOP`, which
the controller turns into a final `stop` (FR-3d). The `finally`/`NonCancellable` block in
`run()` is the backstop if the scope is cancelled abruptly.

## 5. API Contract

### Send (typing on/off) — **VERIFIED & CORRECTED**

```
POST /messaging/conversations/{conversation_id}/typing
Headers: Cookie: <session>; X-CSRF-Token: <ui_csrf>; X-SESSION-ID: <session id>
Content-Type: application/json
Body:   { "is_typing": true }      // or { "is_typing": false }; field defaults to true
```

Request schema is `TypingIn { is_typing: boolean (default true) }`. OpenAPI declares the
success response as `200` with an empty schema; the web client types the body as
`{ ok: boolean; is_typing: boolean; ttl: number }` (`src/api/endpoints/messaging.ts:sendTyping`).
The Android client treats any 2xx as success and **does not** depend on the response body
(best-effort, FR-8); it MAY read the `ttl` field if present to align `TYPING_TTL` with the
server, but must not fail if it is absent.

> **Corrections vs. the original draft:** path is `/messaging/conversations/{id}/typing` (was
> `/conversations/{id}/typing`); body is `{"is_typing": bool}` (was `{"state":"start|stop"}`);
> it is a single endpoint, not split start/stop. Verified against
> `POST /messaging/conversations/{conversation_id}/typing` (op
> `set_typing_messaging_conversations__conversation_id__typing_post`, req schema `TypingIn`).

Retrofit service:

```kotlin
interface TypingApi {
    @POST("messaging/conversations/{id}/typing")
    suspend fun setTyping(
        @Path("id") conversationId: String,
        @Body body: TypingRequest,
    ): Response<Unit>            // 2xx treated as success; body ignored

    // Fallback poll (see Receive). Returns the current typers for the conversation.
    @GET("messaging/conversations/{id}/typing")
    suspend fun getTyping(@Path("id") conversationId: String): Response<List<TypingUserDto>>
}
data class TypingRequest(@Json(name = "is_typing") val isTyping: Boolean)
// schema TypingUser: { user_id: String, updated_at: Long (epoch seconds) }
data class TypingUserDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "updated_at") val updatedAt: Long,
)
```

Repository wraps it in the typed `ApiResult<T>` convention but the controller discards the
result (best-effort, FR-8):

```kotlin
class TypingRepository @Inject constructor(private val api: TypingApi) {
    suspend fun start(id: String) = runCatching { api.setTyping(id, TypingRequest(true)) }
    suspend fun stop(id: String)  = runCatching { api.setTyping(id, TypingRequest(false)) }
    suspend fun poll(id: String)  = runCatching { api.getTyping(id) } // fallback path
}
```

### Receive (over AND-144 SSE stream) — **VERIFIED & CORRECTED**

Same `GET /messaging/events/stream` connection opened by AND-144 (verified:
`GET /messaging/events/stream`, op `events_stream_...`). Typing frames:

```
event: typing:update
data: {"conversation_id":"c_123","user_id":"u_456","is_typing":true,"updated_at":1717632000}
```

> **Corrections vs. the original draft:** event name is `typing:update` (was `typing`); the
> payload carries `is_typing` (boolean) and `updated_at` (epoch **seconds**), **not** a
> `state` string; there is **no** `display_name` field. Verified against
> `src/hooks/useMessagingStream.ts` (the `eventType === "typing:update"` branch reads
> `data.user_id`, `data.is_typing`, `data.updated_at`) and the named-listener registration
> list (`"typing:update"`).

`is_typing` carries on/off; `display_name` is **not** sent and is resolved client-side from
the participant roster (FR-4, fallback "Someone"). The AND-144 envelope decoder routes
`event: typing:update` to `MessagingEvent.Typing`.

**Fallback poll:** the web client also calls `GET /messaging/conversations/{id}/typing` on a
~30s interval (`TypingIndicator.tsx`) as a backstop when SSE frames are missed. The Android
client SHOULD do the same low-frequency poll while the conversation is foregrounded so the
indicator recovers after stream gaps on the flaky dev host. (See §16 open assumptions.)

FastAPI `detail` error mapping is **not** exercised on the happy path here — typing send
errors are swallowed, and stream errors are owned by AND-143/AND-144. The only declared error
response on these endpoints is `422 HTTPValidationError`
(`{ "detail": [ { loc, msg, type } ] }`); a malformed `is_typing` body would produce it, but
the client never surfaces it (FR-8).

## 6. Data & State Management

- **No Room persistence.** Typing state is ephemeral and presence-like; persisting it would be
  incorrect after process death. It lives only in the in-memory `MutableStateFlow<Map<String,
  TypingUser>>` inside `ConversationViewModel`.
- **No DataStore.** The only tunables (throttle/idle/ttl) are compile-time constants in a
  `TypingConfig` object; they are not user-configurable.
- **Source of truth for "me":** `SessionStore.userId` (from the cookie session established via
  `/ui/session/start` → `/ui/session/finalize` → `/ui/me`) is used for self-filtering (FR-7).
- **Constants:**

```kotlin
object TypingConfig {
    val TYPING_THROTTLE = 3.seconds   // min interval between start sends (FR-1/FR-2)
    val TYPING_IDLE     = 5.seconds   // composer silence -> stop (FR-3a)
    const val TYPING_TTL_MS = 6_000L  // remote entry self-expiry (FR-5), > sender throttle
}
```

State transitions are unidirectional: composer/event inputs → ViewModel reducers
(`applyTyping`, `sweepExpired`) → `StateFlow` → Compose. `SharingStarted.WhileSubscribed(5s)`
ensures collection (and the expiry sweep's observable surface) stops shortly after the screen
leaves composition.

## 7. Error Handling & Resilience

- **Send is best-effort (FR-8):** every `setTyping` call is wrapped in `runCatching`; failures
  (20s timeout against the unreliable dev host, 5xx, `IOException` offline) are logged at
  `DEBUG` and dropped. No retry — typing-start is not idempotent-meaningful enough to justify
  the backoff retry budget reserved for GETs, and a stale start auto-expires anyway.
- **Dropped `stop` events:** the `TYPING_TTL` expiry sweep (FR-5) guarantees the indicator
  clears within ~6–7s even if the `stop` frame never arrives — the primary defense against the
  flaky stream.
- **Reordering:** because `START` carries a fresh expiry and `STOP` removes the key, a `STOP`
  that arrives after a later `START` for the same user is benign — the next refresh `START`
  re-adds the user; worst case the indicator flickers for <3s.
- **Stream reconnect:** handled by AND-143/144. On reconnect the typing map may briefly hold
  stale entries; the sweep clears them. No special replay needed.
- **CSRF / 401:** the shared network layer performs the single `POST /ui/session/refresh` +
  retry on 401; a failed refresh just yields a swallowed send error.

## 8. Security & Privacy

- Typing events expose only that a user is composing in a conversation they already share — no
  message content is transmitted in the start/stop body.
- The send POST is state-changing and **requires** the `X-CSRF-Token` header sourced from the
  `ui_csrf` cookie via the shared CSRF interceptor (verified pattern in
  `src/api/client.ts`: `getCookie("ui_csrf")` → `X-CSRF-Token`). A missing/invalid token is
  expected to be rejected by the backend CSRF middleware; the exact status (403) is **not**
  declared on this path in the OpenAPI spec (only `200`/`422` are) and is treated as an
  unverified assumption (§16). Whatever the status, this feature treats it as a (swallowed)
  send failure.
- Session cookies ride the persistent cookie jar; no credentials are added or stored by this
  feature.
- Logging redacts auth/cookie headers (AND-009 interceptor). Typing logs at `DEBUG` only and
  must not log raw cookie or CSRF values.
- The dev backend is plaintext HTTP; typing metadata travels in the clear, acceptable for the
  dev host only. Production cleartext is gated by the network-security config from the network
  epic (not weakened here).

## 9. Accessibility & i18n

- The indicator text is a real `Text` node with `contentDescription`/`liveRegion` so TalkBack
  announces appearance/clearing politely: `Modifier.semantics { liveRegion =
  LiveRegionMode.Polite }`. Use `Polite` (not `Assertive`) to avoid interrupting message reads.
- The animated dots are purely decorative: `Modifier.clearAndSetSemantics {}`.
- All strings via `strings.xml` with plurals:
  `R.plurals.typing_indicator` (one / two / other), e.g. `"%1$s is typing…"`,
  `"%1$s and %2$s are typing…"`, `"Several people are typing…"`. Use
  `pluralStringResource`/`stringResource` — no concatenation.
- Respect reduced-motion: when `Settings.Global.ANIMATOR_DURATION_SCALE == 0`, render static
  dots instead of the bounce animation.
- Color contrast: indicator uses `onSurfaceVariant` on `surface` (≥4.5:1 in both M3 themes).

## 10. Telemetry & Logging

- **Logging:** `Timber`-style `DEBUG` logs in `feature-messaging`:
  `typing.send state=start conv=<id> ok=<bool>` and
  `typing.recv user=<id> state=<start|stop>`. No PII beyond opaque ids; no cookies.
- **Metrics (optional, behind existing analytics facade if present):**
  `typing_send_failed` counter, `typing_indicator_shown` (count of distinct show events). If
  no analytics module exists yet, this is **N/A** and deferred to the telemetry epic — do not
  introduce a new dependency for it.
- No crash-prone paths introduced; the sweep coroutine and controller are scoped to
  `viewModelScope` and cannot leak.

## 11. Testing Strategy

**Unit (core-testing, JUnit + Turbine + coroutines-test):**

- `TypingSignalControllerTest`
  - rapid keystrokes within `TYPING_THROTTLE` → exactly **one** `start` send.
  - sustained typing past throttle → repeated `start` at throttle cadence (FR-2).
  - `Cleared` / `Sent` / idle timeout → exactly one `stop` (FR-3a/b/c).
  - scope cancellation → final `stop` via `NonCancellable` (FR-3d).
  - `repo.start` throwing → no crash, no propagated exception (FR-8).
- `ConversationViewModelTypingTest` (virtual time)
  - inbound `START` for other user → `typingUsers` contains them; matching `STOP` removes
    them (FR-4/FR-5).
  - no refresh within `TYPING_TTL` → entry auto-removed by sweep (FR-5).
  - `START` with `userId == me` → ignored (FR-7).
  - `START` for a different `conversationId` → ignored (FR-6).
  - label/pluralization: 1, 2, 3+ users produce correct strings (FR-4).

**Network (MockWebServer):**

- `TypingApiTest` — `start(id)` issues `POST /messaging/conversations/{id}/typing` with body
  `{"is_typing":true}` and the `X-CSRF-Token` header present; `stop(id)` sends
  `{"is_typing":false}`; 200 → success; 503/timeout → `Result.failure` without throwing to
  caller.

**Compose UI (createComposeRule):**

- `TypingIndicatorTest` — empty list → indicator not displayed; non-empty → text node with
  expected `contentDescription`; transition uses `AnimatedVisibility` (assert via test tag).

**Acceptance harness ("shows/clears correctly"):** an integration test wiring a fake
`MessagingEventBus` proves the end-to-end show-then-clear for both explicit `STOP` and
TTL-expiry paths. All tests run **headlessly** in CI (Robolectric for the Compose/VM tests).

## 12. Dependencies & Sequencing

- **Hard deps:**
  - **AND-144** (messaging events stream) — must land first; this ticket adds the `Typing`
    branch to its `MessagingEvent` sealed type and event dispatcher.
  - **AND-143** (SSE client core) — transitively required by AND-144 for the receive path.
  - **AND-009** (OkHttp client) — provides the configured client/timeouts/logging for the
    Retrofit `TypingApi`.
- **Sibling, non-blocking:** AND-145 (presence) and AND-147 (read receipts) are peers in epic
  E20 that share the same SSE stream; they must not regress each other's event branches.
  Coordinate the shared `MessagingEvent` sealed hierarchy to avoid merge conflicts (add the
  `Typing` variant additively).
- **Blocks:** nothing in the current backlog depends on AND-146.
- **Suggested order within the dev's PR:** model + Moshi adapter → `TypingApi`/repo → send
  controller → ViewModel fold + sweep → composable → tests.

## 13. Risks & Open Questions

- **R1 — Exact endpoint shape: RESOLVED (2026-06-06 review).** It is a single POST
  `/messaging/conversations/{id}/typing` with body `{"is_typing": bool}` (schema `TypingIn`),
  not split start/stop and not a `state` string. Receive rides the AND-144 stream under the
  frame name `typing:update`, with `GET .../typing` as a fallback poll. The design isolates
  this in `TypingApi` + the Moshi adapter so any future change is one file each.
- **R2 — Field names: RESOLVED (2026-06-06 review).** Confirmed snake_case
  `conversation_id` / `user_id` / `is_typing` / `updated_at` against `openapi.pretty.json`
  (`TypingIn`, `TypingUser`) and `src/api/types.ts`. There is **no** `display_name` field on
  the typing payload; the name is resolved client-side (FR-4).
- **R3 — Unreliable host event loss:** mitigated by TTL self-expiry; residual flicker risk is
  accepted.
- **R4 — Group conversations with many typers:** the "Several people are typing…" collapse at
  3+ bounds UI growth; no virtualization needed.
- **R5 — Throttle vs TTL coupling:** if backend sender semantics differ (e.g., it expects only
  a single start with server-side expiry), `TYPING_THROTTLE`/`TYPING_TTL` may need retuning;
  they are centralized in `TypingConfig`.

## 14. Acceptance Criteria

AC-1 Typing in the composer triggers at most one
`POST /messaging/conversations/{id}/typing` `{"is_typing":true}` per 3s window, with the
`X-CSRF-Token` header set (verified via MockWebServer). *(FR-1, FR-2)*

AC-2 Clearing the field, sending the message, going idle for 5s, or leaving the screen each
results in exactly one `{"is_typing":false}` send. *(FR-3)*

AC-3 An inbound `typing:update` event with `is_typing:true` for another user in the open
conversation displays `"<name> is typing…"`; a subsequent `is_typing:false` for that user
removes it immediately. *(FR-4)*

AC-4 If no refresh event arrives within ~6s, the indicator clears automatically even with no
`stop` event received. *(FR-5)*

AC-5 Typing events for other conversations and self-echoed events never alter the visible
indicator. *(FR-6, FR-7)*

AC-6 Send failures (timeout/5xx/offline) never surface an error to the user and never block the
composer. *(FR-8)*

AC-7 Pluralization renders correctly for 1, 2, and 3+ concurrent typers; TalkBack announces the
indicator politely. *(§9)*

AC-8 All unit, network, Compose, and the show/clear integration tests pass headlessly in CI —
satisfying the backlog acceptance "Typing shows/clears correctly."

## 15. Definition of Done

- Code merged to `android-port` under `feature-messaging`
  (`com.testlogon.android.feature.messaging`), additively extending the AND-144 event model.
- `TypingApi`, `TypingRepository`, `TypingSignalController`, `MessagingEvent.Typing` +
  Moshi adapter, `ConversationViewModel` typing fold/sweep, and `TypingIndicator` composable
  implemented as specified.
- All §11 tests written and green headlessly; CI lint/detekt/ktlint clean.
- Strings externalized with plurals; reduced-motion and TalkBack behavior verified.
- Endpoint/field assumptions in §13 confirmed against `/openapi.json` (or the spec/adapters
  updated accordingly) and noted in the PR description.
- Manual smoke against the dev host (`http://18.222.237.167:8000`) with two sessions: typing in
  one shows then clears in the other via both explicit stop and TTL expiry.
- No new module, no new persisted state, no regressions to AND-144/145/147 event branches.
- PR reviewed and approved; spec status flipped from `draft` on merge.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Typing send endpoint is `POST /messaging/conversations/{conversation_id}/typing`.**
   VERDICT: Corrected (draft said `POST /conversations/{id}/typing`).
   SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/typing`
   (op `set_typing_messaging_conversations__conversation_id__typing_post`);
   `src/api/endpoints/messaging.ts: sendTyping`.

2. **Send request body is `{ "is_typing": boolean }` (schema `TypingIn`, default true), not a
   `state` start/stop string, and it is a single endpoint (not split start/stop).**
   VERDICT: Corrected.
   SOURCE: OpenAPI schema `components.schemas.TypingIn` (`is_typing: boolean, default true`);
   `src/api/endpoints/messaging.ts: sendTyping` posts `{ is_typing: isTyping }`.

3. **Send success is HTTP 200; OpenAPI declares an empty success schema, while the web client
   types the body as `{ ok, is_typing, ttl }`. Client ignores the body (best-effort).**
   VERDICT: Verified (with nuance — see open assumptions on `ttl`).
   SOURCE: OpenAPI `POST .../typing` responses `200: {}` ; `422: HTTPValidationError`;
   `src/api/endpoints/messaging.ts: sendTyping` return type.

4. **Receive SSE event name is `typing:update` (not `typing`), carried on the shared
   `GET /messaging/events/stream` connection.**
   VERDICT: Corrected (event name) / Verified (stream URL).
   SOURCE: `src/hooks/useMessagingStream.ts` (`eventType === "typing:update"` branch; named
   listener list includes `"typing:update"`; `MESSAGING_STREAM_URL = "/messaging/events/stream"`);
   OpenAPI `GET /messaging/events/stream` (op `events_stream_messaging_events_stream_get`).

5. **Typing SSE payload fields are `conversation_id`, `user_id`, `is_typing` (boolean),
   `updated_at` (epoch seconds). There is no `display_name` and no `state` field.**
   VERDICT: Corrected.
   SOURCE: `src/hooks/useMessagingStream.ts` (reads `data.user_id`, `data.is_typing`,
   `data.updated_at`); schema `components.schemas.TypingUser` (`user_id: string`,
   `updated_at: integer`).

6. **A fallback `GET /messaging/conversations/{conversation_id}/typing` returns
   `TypingUser[]` (`{ user_id, updated_at }`), polled ~30s by the web client.**
   VERDICT: Verified (added to spec).
   SOURCE: OpenAPI `GET /messaging/conversations/{conversation_id}/typing` (resp `200`);
   `src/api/endpoints/messaging.ts: getTyping`; `src/pages/messages/TypingIndicator.tsx`
   (`refetchInterval: TYPING_FALLBACK_POLL_MS = 30_000`); `src/api/types.ts: TypingUser`.

7. **The typing payload has no display name; the web UI labels typers by `user_id`.**
   VERDICT: Corrected (draft used `display_name` from the event).
   SOURCE: `src/pages/messages/TypingIndicator.tsx` (`${others[0].user_id} is typing`);
   schema `TypingUser` has no name field.

8. **Self-filtering uses the current user id (`user_id != me`).**
   VERDICT: Verified.
   SOURCE: `src/pages/messages/TypingIndicator.tsx` (`.filter((t) => t.user_id !== userId)`).

9. **State-changing POSTs carry `X-CSRF-Token` sourced from the `ui_csrf` cookie via the
   shared transport.**
   VERDICT: Verified.
   SOURCE: `src/api/client.ts` (`const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`,
   `credentials: "include"`).

10. **On 401 the transport performs a single `POST /ui/session/refresh` + retry.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts: refreshSession` (`POST /ui/session/refresh`); OpenAPI
    `POST /ui/session/refresh` (op `ui_session_refresh_...`).

11. **"Me" is established via `/ui/session/start` → `/ui/session/finalize` → `/ui/me`.**
    VERDICT: Verified.
    SOURCE: OpenAPI `POST /ui/session/start` (resp `UiSessionStartResp`),
    `POST /ui/session/finalize` (req `UiSessionFinalizeReq`), `GET /ui/me`.

12. **Web client throttle/TTL values: 2s send debounce, 5s client TTL, 2s cleanup sweep.**
    VERDICT: Verified (Android uses its own 3s/5s/6s values, deliberately conservative for the
    flaky dev host — a design choice, not a contract).
    SOURCE: `src/pages/messages/TypingIndicator.tsx` (`TYPING_DEBOUNCE_MS = 2_000`,
    `TYPING_CLIENT_TTL_MS = 5_000`, `TYPING_CLEANUP_INTERVAL_MS = 2_000`).

13. **Only declared error response on the typing endpoints is `422 HTTPValidationError`
    (`{ detail: [ { loc, msg, type } ] }`).**
    VERDICT: Verified.
    SOURCE: OpenAPI `POST`/`GET .../typing` responses; schemas
    `components.schemas.HTTPValidationError`, `components.schemas.ValidationError`.

14. **Framework choices — Compose `AnimatedVisibility`, `pluralStringResource`,
    `semantics { liveRegion = Polite }`, lifecycle `repeatOnLifecycle`.**
    VERDICT: Verified (framework ref).
    SOURCE (framework ref):
    `https://developer.android.com/develop/ui/compose/animation/composables-modifiers#animatedvisibility`;
    `https://developer.android.com/jetpack/compose/text/resources` (plurals);
    `https://developer.android.com/develop/ui/compose/accessibility#live-regions`;
    `https://developer.android.com/topic/libraries/architecture/coroutines#lifecycle-aware`.

### Corrections made

- Endpoint path corrected to `/messaging/conversations/{id}/typing` everywhere (§1, §5, §14,
  §11, §13).
- Send body corrected from `{"state":"start|stop"}` to `{"is_typing": boolean}` (schema
  `TypingIn`); collapsed the imagined two-endpoint variant into the real single endpoint.
- SSE event renamed `typing` → `typing:update`; payload corrected to
  `{conversation_id, user_id, is_typing, updated_at}` (removed nonexistent `display_name`/
  `state`). `MessagingEvent.Typing` and `applyTyping` rewritten to use the boolean `isTyping`
  and an `updatedAtSeconds` field; dropped `TypingState` enum.
- Added the `GET .../typing` fallback poll (Retrofit `getTyping` + `TypingUserDto`) and a §5
  note matching the web client's 30s backstop.
- FR-4 reworked: display name is resolved from the participant roster (not the event), with a
  `"Someone"` fallback.
- §8 CSRF: kept the `X-CSRF-Token` requirement (verified) but downgraded the specific "403"
  status to an unverified assumption (not declared in OpenAPI).
- §13 R1/R2 marked RESOLVED with the confirmed shapes.

### Open assumptions

- **Server `ttl` in the POST response.** The web client's `sendTyping` return type includes
  `ttl`, but OpenAPI declares the `200` body as an empty schema, so the field is not
  contractually guaranteed. Android treats it as optional; `TYPING_TTL = 6s` is a local
  default. (Unverifiable from the contract.)
- **CSRF-failure status code.** Assumed 403 by middleware; only `200`/`422` are declared on
  the path. Behavior is swallowed regardless, so the exact code is non-blocking.
- **`X-SESSION-ID` header.** The OpenAPI `params` list both `authorization` and `X-SESSION-ID`
  for the typing endpoints; the web `client.ts` sets `Authorization: Bearer` + cookies and
  relies on cookie credentials. Whether the Android client must also send an explicit
  `X-SESSION-ID` header (vs. it being derived server-side from the session cookie) is not
  determinable from the sources and is delegated to the AND-009/AND-143 network layer.
- **Self-echo over SSE.** FR-7 assumes the backend may echo the sender's own `typing:update`;
  the web stream handler does not special-case self (it relies on the `getTyping`/render-time
  `user_id !== me` filter). Android keeps the defensive self-filter; whether the server
  actually echoes is unverified but harmless either way.
- **Group-conversation participant roster availability.** FR-4's `user_id → displayName`
  resolution assumes AND-144 exposes participant identities to this screen; if it does not,
  the indicator falls back to `"Someone"`. Cross-ticket dependency, not contract-verifiable
  here.

## 17. Test Plan

Test IDs `TC-AND-146-NN`. Targets: JVM = JVM/Robolectric unit (local, no device);
EMU = headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). Hardware-independent UI/instrumented cases run on EMU; cases
needing real-device behavior note DEV explicitly.

**TC-AND-146-01 — Throttled start send (happy path).**
Type: unit (JVM). Target: `TypingSignalControllerTest`.
Preconditions: fake `TypingRepository` recording calls; virtual time.
Steps: emit 10 `Keystroke` inputs within a 3s window.
Expected: exactly one `repo.start` invoked; no `stop`.
Traces: AC-1.

**TC-AND-146-02 — Heartbeat re-send past throttle.**
Type: unit (JVM). Target: `TypingSignalControllerTest`.
Preconditions: virtual time, fake repo.
Steps: emit `Keystroke` continuously for ~9s (advance virtual clock across 3 throttle windows).
Expected: `repo.start` invoked ~3 times (once per `TYPING_THROTTLE`); no premature `stop`.
Traces: AC-1.

**TC-AND-146-03 — Stop on clear / send / idle / leave.**
Type: unit (JVM). Target: `TypingSignalControllerTest` (parameterized).
Preconditions: controller `typing=true` after a start; virtual time.
Steps: drive each terminator independently — (a) `Cleared`; (b) `Sent`; (c) 5s idle
(`TYPING_IDLE`); (d) scope cancellation triggering the `finally`/`NonCancellable` block.
Expected: each yields exactly one `repo.stop`; case (d) still sends stop despite cancellation.
Traces: AC-2.

**TC-AND-146-04 — Send is best-effort (failures swallowed).**
Type: unit (JVM). Target: `TypingSignalControllerTest`.
Preconditions: fake `repo.start`/`repo.stop` throw `IOException` / return 5xx.
Steps: drive a start then a stop while the repo throws.
Expected: no exception propagates out of `run()`; no crash; controller remains usable.
Traces: AC-6.

**TC-AND-146-05 — Contract: POST shape, body, headers.**
Type: contract/MockWebServer (JVM). Target: `TypingApiTest` + CSRF interceptor.
Preconditions: MockWebServer enqueues `200 {}`; `ui_csrf` cookie present in jar.
Steps: call `repo.start(id)` then `repo.stop(id)`.
Expected: requests are `POST /messaging/conversations/{id}/typing`; bodies
`{"is_typing":true}` then `{"is_typing":false}`; `X-CSRF-Token` header equals the `ui_csrf`
value; `Content-Type: application/json`. 200 → `Result.success`.
Traces: AC-1, AC-2.

**TC-AND-146-06 — Contract: error/offline responses do not throw.**
Type: contract/MockWebServer (JVM). Target: `TypingApiTest`.
Preconditions: enqueue `503`, then a socket disconnect (simulated offline), then a `422`
`{"detail":[{"loc":["body","is_typing"],"msg":"...","type":"..."}]}`.
Steps: call `repo.start(id)` against each.
Expected: each returns `Result.failure` (or a non-2xx `Response`) without throwing to the
caller; no error surfaced to UI.
Traces: AC-6.

**TC-AND-146-07 — Receive: show then explicit clear.**
Type: integration (JVM/Robolectric). Target: `ConversationViewModelTypingTest` with fake
`MessagingEventBus`.
Preconditions: VM open on conversation `c1`; `me = u_self`.
Steps: emit `typing:update {c1, u_other, is_typing:true}`; assert `typingUsers` contains
`u_other`; emit `typing:update {c1, u_other, is_typing:false}`.
Expected: indicator user added then removed immediately on the false event.
Traces: AC-3.

**TC-AND-146-08 — Receive: TTL self-clear with no false event (flaky-stream path).**
Type: integration (JVM/Robolectric, virtual time). Target: `ConversationViewModelTypingTest`.
Preconditions: VM open; sweep coroutine running on virtual clock.
Steps: emit a single `is_typing:true`; advance time past `TYPING_TTL` (6s) with no further
events.
Expected: entry removed by the expiry sweep within ~6–7s even though no `is_typing:false`
arrived.
Traces: AC-4.

**TC-AND-146-09 — Scope/self filters.**
Type: unit (JVM). Target: `ConversationViewModelTypingTest`.
Preconditions: VM open on `c1`; `me = u_self`.
Steps: emit `is_typing:true` for (a) `{c2, u_other}` (other conversation) and (b)
`{c1, u_self}` (self-echo).
Expected: neither alters `typingUsers`.
Traces: AC-5.

**TC-AND-146-10 — Pluralization labels.**
Type: unit (JVM/Robolectric for resources). Target: `typingLabel` / plurals.
Preconditions: roster resolves names A, B, C.
Steps: render label for 1, 2, and 3 typers.
Expected: `"A is typing…"`, `"A and B are typing…"`, `"Several people are typing…"`.
Traces: AC-7.

**TC-AND-146-11 — Compose UI visibility + accessibility.**
Type: Compose-UI (EMU, createComposeRule). Target: `TypingIndicatorTest`.
Preconditions: composable hosted with controllable `users` state.
Steps: start empty → assert indicator not displayed; set one user → assert text node shown
with the expected `contentDescription`; assert the row carries `liveRegion = Polite` and the
animated dots are `clearAndSetSemantics {}` (not announced); set empty again → hidden.
Expected: visibility toggles via `AnimatedVisibility`; TalkBack semantics as specified.
Traces: AC-3, AC-7.

**TC-AND-146-12 — Reduced-motion fallback.**
Type: instrumented (EMU). Target: `TypingIndicator` reduced-motion branch.
Preconditions: `Settings.Global.ANIMATOR_DURATION_SCALE = 0`.
Steps: show the indicator with one typer.
Expected: static dots rendered (no bounce animation); text still shown.
Traces: AC-7.

**TC-AND-146-13 — Lifecycle teardown sends final stop.**
Type: instrumented (EMU). Target: `ConversationScreen` + controller.
Preconditions: MockWebServer backing the typing API; screen typing (`typing=true`).
Steps: drive the host lifecycle to `ON_STOP` (background the screen).
Expected: exactly one `{"is_typing":false}` POST observed at teardown (FR-3d).
Traces: AC-2.

**TC-AND-146-14 — Real-device end-to-end show/clear over live SSE on the flaky dev host.**
Type: instrumented/e2e (DEV — physical SM-A156U). Rationale: exercises real-network SSE
delivery, reconnect, and event loss against `http://18.222.237.167:8000` on real hardware
(arm64/API 34), which the emulator cannot faithfully reproduce.
Preconditions: two authenticated sessions in the same conversation (device + a second client);
network-security config permits cleartext to the dev host.
Steps: type in the second client; observe the device shows `"<name> is typing…"`; stop typing
and let the `is_typing:false`/TTL path fire; repeat while toggling connectivity to force a
dropped frame.
Expected: indicator appears, then clears via both explicit `is_typing:false` and TTL expiry;
the ~30s fallback poll recovers state after a forced stream gap; no error toast ever appears.
Traces: AC-3, AC-4, AC-6, AC-8.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (throttled start, CSRF header) | TC-01, TC-02, TC-05 |
| AC-2 (single stop on clear/send/idle/leave) | TC-03, TC-05, TC-13 |
| AC-3 (show on `is_typing:true`, clear on false) | TC-07, TC-11, TC-14 |
| AC-4 (TTL self-clear, no false event) | TC-08, TC-14 |
| AC-5 (other-conversation + self-echo ignored) | TC-09 |
| AC-6 (send failures swallowed, never blocks) | TC-04, TC-06, TC-14 |
| AC-7 (pluralization + TalkBack/a11y) | TC-10, TC-11, TC-12 |
| AC-8 (suite green headlessly; show/clear e2e) | TC-01–TC-13 (CI headless), TC-14 (device e2e) |

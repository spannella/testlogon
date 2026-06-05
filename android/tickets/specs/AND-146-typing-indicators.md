---
id: AND-146
title: Typing indicators
milestone: M3
epic: E20
priority: P1
size: M
status: draft
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
`POST /conversations/{id}/typing` while text is entered, and a stop signal when input idles,
is cleared, or the message is sent. **Receive** — inbound `typing` events arrive over the
already-established SSE messaging stream (AND-144 on the SSE core in AND-143); the conversation
ViewModel folds these into UI state with per-user expiry so stale indicators self-clear even if
a `stop` event is dropped.

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
- **Web reference:** typing behavior in `frontend/src/api/endpoints/*.ts` (conversation
  endpoints) and event/type shapes in `frontend/src/api/types.ts`. Confirm exact field
  names against `/openapi.json` on the dev host before locking the Moshi adapters
  (see Open Questions §13).
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

FR-4 **Receive & display:** Inbound `typing` events for the currently open conversation
update a set of "who is typing" users (excluding the local user). The composer area shows:
`"<name> is typing…"` for one user, `"<name> and <name> are typing…"` for two,
`"Several people are typing…"` for three or more.

FR-5 **Self-clearing:** Each remote typing entry carries an expiry. If no refresh `typing`
event arrives within `TYPING_TTL` (default **6s**, > sender throttle), the entry is removed
even without a `stop` event. An explicit `stop` event removes it immediately.

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
        val conversationId: String,
        val userId: String,
        val displayName: String?,
        val state: TypingState, // START or STOP
    ) : MessagingEvent
}

enum class TypingState { START, STOP }
```

The Moshi adapter in `feature-messaging` maps the SSE `event:`/`data:` payload (§5) into
`MessagingEvent.Typing`. Unknown `state` values default to `START` (fail-open toward showing,
since expiry will clear them anyway).

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
        when (e.state) {
            TypingState.STOP -> m - e.userId
            TypingState.START -> m + (e.userId to TypingUser(
                e.userId, e.displayName ?: "Someone", e.conversationId,
                System.currentTimeMillis() + TYPING_TTL_MS))
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

### Send (typing start/stop)

```
POST /conversations/{id}/typing
Headers: Cookie: <session>; X-CSRF-Token: <ui_csrf>
Content-Type: application/json
Body:   { "state": "start" }      // or { "state": "stop" }
```

Expected `200`/`204` with an empty or trivial body. The client treats any 2xx as success and
**does not** parse the response. (If the backend instead distinguishes endpoints —
`/typing/start` and `/typing/stop` — adapt the Retrofit methods; verify via `/openapi.json`,
Open Question §13.)

Retrofit service:

```kotlin
interface TypingApi {
    @POST("conversations/{id}/typing")
    suspend fun setTyping(
        @Path("id") conversationId: String,
        @Body body: TypingRequest,
    ): Response<Unit>
}
data class TypingRequest(@Json(name = "state") val state: String) // "start" | "stop"
```

Repository wraps it in the typed `ApiResult<T>` convention but the controller discards the
result (best-effort, FR-8):

```kotlin
class TypingRepository @Inject constructor(private val api: TypingApi) {
    suspend fun start(id: String) = runCatching { api.setTyping(id, TypingRequest("start")) }
    suspend fun stop(id: String)  = runCatching { api.setTyping(id, TypingRequest("stop")) }
}
```

### Receive (over AND-144 SSE stream)

Same `GET /messaging/events/stream` connection opened by AND-144. Typing frames:

```
event: typing
data: {"conversation_id":"c_123","user_id":"u_456","display_name":"Ada","state":"start"}
```

The `state` field carries `start`/`stop`. `display_name` may be absent (fallback "Someone").
The AND-144 envelope decoder routes `event: typing` to `MessagingEvent.Typing`. FastAPI
`detail` error mapping is **not** exercised here — typing send errors are swallowed, and stream
errors are owned by AND-143/AND-144.

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
  `ui_csrf` cookie via the shared CSRF interceptor; without it the backend returns 403, which
  this feature treats as a (swallowed) send failure.
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

- `TypingApiTest` — `setTyping("start")` issues `POST /conversations/{id}/typing` with body
  `{"state":"start"}` and the `X-CSRF-Token` header present; 204 → success; 503/timeout →
  `Result.failure` without throwing to caller.

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

- **R1 — Exact endpoint shape:** the backlog says `/conversations/{id}/typing` send + receive.
  It is unconfirmed whether start/stop is one POST with a `state` body (assumed here) or two
  endpoints, and whether receive truly rides the AND-144 stream vs. a dedicated frame name.
  **Action:** verify against `/openapi.json` and `frontend/src/api/endpoints/*.ts` before
  finalizing adapters; the design isolates this in `TypingApi` + the Moshi adapter so the blast
  radius of a change is one file each.
- **R2 — Field names:** `conversation_id` / `user_id` / `display_name` / `state` are assumed
  snake_case per FastAPI convention; confirm casing in `frontend/src/api/types.ts`.
- **R3 — Unreliable host event loss:** mitigated by TTL self-expiry; residual flicker risk is
  accepted.
- **R4 — Group conversations with many typers:** the "Several people are typing…" collapse at
  3+ bounds UI growth; no virtualization needed.
- **R5 — Throttle vs TTL coupling:** if backend sender semantics differ (e.g., it expects only
  a single start with server-side expiry), `TYPING_THROTTLE`/`TYPING_TTL` may need retuning;
  they are centralized in `TypingConfig`.

## 14. Acceptance Criteria

AC-1 Typing in the composer triggers at most one `POST /conversations/{id}/typing`
`{"state":"start"}` per 3s window, with the `X-CSRF-Token` header set (verified via
MockWebServer). *(FR-1, FR-2)*

AC-2 Clearing the field, sending the message, going idle for 5s, or leaving the screen each
results in exactly one `{"state":"stop"}` send. *(FR-3)*

AC-3 An inbound `typing`/`start` event for another user in the open conversation displays
`"<name> is typing…"`; an inbound `stop` for that user removes it immediately. *(FR-4)*

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

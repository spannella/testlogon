---
id: AND-137
title: Countdown messages
milestone: M3
epic: E19
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-124]
blocks: []
---

# AND-137 — Countdown messages

## 1. Overview & Goal

Add support for **countdown messages** to the messaging feature: a message type whose body is a future target instant plus a title, which renders in the thread as a live, self-updating countdown (days/hours/minutes/seconds remaining) that ticks down to zero and then flips to an "event reached" state. This ticket delivers both the **send** path (a composer entry point that posts `POST /messaging/conversations/{conversation_id}/messages/countdown`) and the **render** path (a Compose bubble that derives remaining time from the device clock once per second).

Countdown is one of the sealed message kinds enumerated by AND-126 (`text/image/video/file/voice/gif/sticker/poll/countdown/calendar/system`). AND-126 defines the domain model and the DTO→domain mapper for the read side; this ticket owns the **write side** (request DTO, repository send method, ViewModel action, picker UI) and the **live-rendering** Composable for the `countdown` kind. It reuses the optimistic-send + outbox + reconciliation machinery established by AND-124 — countdown is just another payload sent through that pipeline, not a new send architecture.

Goal restated as a testable outcome: a user can open a countdown picker, choose a title and a future date/time, send it, see it appear optimistically in the thread, reconcile on server ack, and watch the rendered bubble tick second-by-second toward the target; when the target passes, the bubble shows the completed state without a reload.

## 2. Context & References

- **Module:** `feature-messaging` (Gradle module `:feature:messaging`), package `com.testlogon.android.feature.messaging`. The countdown picker and bubble live under `…feature.messaging.countdown`.
- **Layering:** `feature-messaging` → `core-network` (Retrofit service + `ApiResult<T>`), `core-model` (DTO ↔ domain), `core-data` (repository, Room cache, outbox), `core-ui` (Compose components, theme). No backward dependencies.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. The countdown endpoint description is `Send a countdown message to a conversation (MSG-010)` (OpenAPI summary `Create Countdown Message`). Auth (per `src/api/client.ts`): session cookies (`credentials: "include"`) **plus** an `Authorization: Bearer <accessToken>` header from the auth store **plus** `ui_csrf` cookie echoed as `X-CSRF-Token`; on `401` the web client calls `POST /ui/session/refresh` once and retries (the OkHttp authenticator mirrors this). The OpenAPI parameters for this endpoint list optional `authorization` and `X-SESSION-ID` headers. Persistent cookie jar required (core-network tickets). *(Correction: original draft said "Cookie-based auth" only and omitted the Bearer token.)*
- **Web reference:** `src/api/endpoints/messaging.ts` (`sendCountdownMessage`), `src/pages/messages/CountdownComposerDialog.tsx` + `CountdownCard.tsx` (composer + render behavior), and `src/api/types.ts` (`Message` countdown fields). The Android DTO must mirror `SendCountdownMessageIn` and the `MessageOut` countdown projection. *(Correction: original draft pointed at `endpoints/conversations.ts`; the actual countdown call lives in `endpoints/messaging.ts`.)*
- **Dependency AND-124** supplies: `MessageComposer`, `ComposerState`, the outbox (`OutboxMessageEntity`/`OutboxDao`), `MessageRepository.sendMessage(...)` as the optimistic-send template, the `SendStatus` enum (`SENDING/SENT/FAILED`), and the merge/dedup-by-`clientId` flow. AND-126 supplies the sealed `Message`/`MessageContent` domain model and the read-side mapper that produces a `Countdown` content variant.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, Paging 3. minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

FR-1. The composer (AND-124) gains an **attachment/extra-content menu** entry "Countdown" that opens a `CountdownPickerSheet` (Material 3 `ModalBottomSheet`).

FR-2. The picker collects: a **title** (1–200 chars, required) and a **target date+time** (required, must be strictly in the future at send time). Date/time selection uses Material 3 `DatePicker` + `TimePicker`. The target is captured in the device time zone and converted to a **UTC Unix timestamp in seconds** for the request.

FR-3. The "Send countdown" action is enabled only when title is non-blank (≤200 chars) and the chosen instant is `> now`. A past/now selection is blocked with an inline error ("Pick a future time").

FR-4. On send, a countdown message is enqueued through the **same optimistic pipeline as AND-124**: an outbox row with `status = SENDING` and a client-generated `clientId` appears immediately in the thread rendered as a countdown bubble; the network POST fires in the background; on ack the row reconciles in place to the server message (`SENT`, server `id`, server `created_at`); on failure it shows `FAILED` + Retry preserving the entered title/target.

FR-5. The countdown bubble renders, for a `Message` of kind `countdown`: the **title**, the **target date/time** (locale-formatted, in device zone), and a **live remaining-time** display updating once per second — broken into days, hours, minutes, seconds as appropriate (e.g. `2d 04:12:09`, or `04:12:09` when < 1 day).

FR-6. When the target instant is reached or passed, the bubble switches to a **completed** state (e.g. "Event reached" / elapsed time), stops counting down, and no longer schedules further ticks.

FR-7. Optionally surfaced (read-only, from server): `associated_event_type` (`broadcast|call|calendar|custom`) and `associated_event_id`. In this ticket these are **display/pass-through only** — the picker defaults `associated_event_type = "custom"` and does not set an `associated_event_id`; deep-linking into the associated broadcast/call/calendar item is out of scope and owned by AND-138 (calendar) and the broadcast/calls epics.

FR-8. Ticking must be **lifecycle-aware**: timers run only while the thread screen is in `STARTED`/`RESUMED` and only for countdown bubbles currently composed/visible; they stop on stop/dispose and re-sync to wall-clock on resume (no drift, no leaked coroutines).

FR-9. Sending preserves scroll-to-bottom and composer insets behavior inherited from AND-124. Multiple countdowns may be in flight independently.

## 4. Technical Design

### 4.1 Domain (consumed from AND-126, extended for outbox)

AND-126 defines the sealed content model; the relevant variant:

```kotlin
sealed interface MessageContent {
    data class Countdown(
        val title: String,
        val targetEpochSeconds: Long,                 // UTC
        val associatedEventType: AssociatedEventType, // BROADCAST|CALL|CALENDAR|CUSTOM
        val associatedEventId: String? = null,
    ) : MessageContent
    /* … other kinds … */
}

enum class AssociatedEventType { BROADCAST, CALL, CALENDAR, CUSTOM, UNKNOWN }
```

The outbox (AND-124) is generalized so a pending row carries a typed payload rather than only a text body:

```kotlin
@Entity(tableName = "outbox_messages")
data class OutboxMessageEntity(
    @PrimaryKey val clientId: String,
    val conversationId: String,
    val kind: String,            // "text" | "countdown" | …
    val payloadJson: String,     // Moshi-encoded kind-specific payload
    val createdAt: Long,         // epoch millis (local placeholder)
    val status: String,          // SENDING | FAILED
    val attemptCount: Int = 0,
)
```

`payloadJson` for a countdown encodes `{title, target_datetime, associated_event_type}` so the optimistic bubble renders identically to the eventual server row and a retry re-sends the exact request.

### 4.2 Live-ticking design

A single ticker drives all visible countdown bubbles to avoid one coroutine per bubble. The current wall-clock instant is exposed as a Flow that emits once per second while collected:

```kotlin
fun tickerFlow(period: Duration = 1.seconds): Flow<Instant> = flow {
    while (true) { emit(Clock.System.now()); delay(period) }
}.conflate()
```

In the countdown Composable, remaining time is derived (never stored as a mutable counter, so it self-corrects against the system clock and survives backgrounding):

```kotlin
@Composable
fun rememberRemaining(targetEpochSeconds: Long): State<Duration> {
    val now by tickerFlow()
        .map { Instant.fromEpochSeconds(targetEpochSeconds) - it }
        .collectAsStateWithLifecycle(initialValue = Duration.ZERO)
    return remember { derivedStateOf { now.coerceAtLeast(Duration.ZERO) } }
}
```

`collectAsStateWithLifecycle` (lifecycle-runtime-compose) guarantees collection stops below `STARTED` (FR-8). When `remaining == ZERO` the Composable renders the completed state and the upstream `map` keeps clamping to zero (cheap; or the bubble can pass a `done` flag to short-circuit further formatting).

### 4.3 Formatting

```kotlin
object CountdownFormatter {
    fun format(remaining: Duration): String  // "2d 04:12:09" | "04:12:09" | "00:00:09"
    fun isDone(remaining: Duration): Boolean = remaining <= Duration.ZERO
}
```
Pure function → directly unit-testable with fixed `Duration` inputs (no clock).

### 4.4 ViewModel action

Extends `MessagingViewModel` (AND-124/AND-123):

```kotlin
data class CountdownDraft(
    val title: String = "",
    val targetEpochSeconds: Long? = null,
)

fun onCountdownPickerOpen()
fun onCountdownDraftChange(draft: CountdownDraft)
fun onSendCountdown()           // validates, enqueues outbox, fires send
fun onRetry(clientId: String)   // inherited; re-fires by re-decoding payloadJson
```

`onSendCountdown`:
1. Validate: `title` 1–200 chars; `target != null && target > now`. Else set inline error, return.
2. `val clientId = UUID.randomUUID().toString()`.
3. `outboxDao.upsert(SENDING, kind="countdown", payloadJson=…)` → close sheet → scroll to bottom.
4. `viewModelScope.launch { repo.sendCountdown(conversationId, clientId, draft) }` then reconcile (`Success` → `messageDao.upsert` + `outboxDao.delete`; `Error` → `outboxDao.upsert(FAILED, attemptCount+1)`), identical to AND-124.

### 4.5 Repository

```kotlin
interface MessageRepository {           // method added in this ticket
    suspend fun sendCountdown(
        conversationId: String,
        clientId: String,
        draft: CountdownDraft,
    ): ApiResult<Message>
}
```
Implementation maps `CountdownDraft` → `SendCountdownMessageIn` → `MessagingApi.sendCountdown(...)` → `MessageOut.toDomain()` (AND-126 mapper, yielding `MessageContent.Countdown`), all wrapped by the shared `apiCall { }` helper that converts non-2xx/exceptions to `ApiResult.Error` and decodes the FastAPI `detail` shape (AND-015).

### 4.6 Composables

```kotlin
@Composable fun CountdownPickerSheet(
    draft: CountdownDraft,
    onChange: (CountdownDraft) -> Unit,
    onSend: () -> Unit,
    onDismiss: () -> Unit,
    error: UiError? = null,
)

@Composable fun CountdownBubble(
    content: MessageContent.Countdown,
    sendStatus: SendStatus,
    modifier: Modifier = Modifier,
)
```
`CountdownBubble` is the branch added to the AND-123 message-item Composable for `kind == countdown`. It shows title, formatted target, the live remaining string, and (when `SENDING`/`FAILED`) the optimistic/failed affordances inherited from AND-124.

## 5. API Contract

**Endpoint:** `POST /messaging/conversations/{conversation_id}/messages/countdown` (operationId `create_countdown_message_messaging_conversations__conversation_id__messages_countdown_post`, summary "Create Countdown Message", description "Send a countdown message to a conversation (MSG-010)"). *Verified against `openapi.index.txt` line 336.*

**Request headers:** session cookies (cookie jar) + `Authorization: Bearer <accessToken>` + `X-CSRF-Token: <ui_csrf>` (CSRF interceptor) + `Content-Type: application/json`. *(The OpenAPI declares optional `authorization` and `X-SESSION-ID` headers for this op; the web client sends the Bearer token and the `ui_csrf`-derived CSRF header on every call — see `src/api/client.ts`.)*

**Request body** — schema `SendCountdownMessageIn`:
```json
{
  "title": "Launch",
  "target_datetime": 1780000000,
  "associated_event_type": "custom",
  "associated_event_id": null,
  "reply_to_message_id": null
}
```
- `title`: string, **required**, minLength 1, maxLength 200.
- `target_datetime`: integer, **required**, UTC Unix timestamp (seconds) of the target event.
- `associated_event_type`: string, default `"custom"`, pattern `^(broadcast|call|calendar|custom)$`.
- `associated_event_id`: string ≤128 chars or null.
- `reply_to_message_id`: string or null (not used by this ticket; send null).

**Success `201`** — schema `MessageOut` (countdown projection); relevant fields:
```json
{
  "message_id": "msg_01H...",
  "conversation_id": "conv_01H...",
  "sender_id": "usr_01H...",
  "kind": "countdown",
  "countdown_title": "Launch",
  "target_datetime": 1780000000,
  "associated_event_type": "custom",
  "associated_event_id": null,
  "created_at": 1780000000
}
```
*(Corrections vs original draft: the identifier field is `message_id`, NOT `id`; `created_at` is an **integer Unix epoch** (`MessageOut.created_at: type integer`), NOT an ISO-8601 string. The author field is `sender_id`. There is **no** `client_id`/idempotency field on `MessageOut`. Verified against `components.schemas.MessageOut` and `src/api/endpoints/messagingAdapter.ts: adaptMessage` which reads `message_id` and `toNum(created_at)`. The `kind` enum value `"countdown"` is one of the `MessageOut.kind` enum members.)*

**Moshi DTOs + Retrofit:**
```kotlin
@JsonClass(generateAdapter = true)
data class SendCountdownMessageIn(
    @Json(name = "title") val title: String,
    @Json(name = "target_datetime") val targetDatetime: Long,
    @Json(name = "associated_event_type") val associatedEventType: String = "custom",
    @Json(name = "associated_event_id") val associatedEventId: String? = null,
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
)

interface MessagingApi {                                   // extends AND-120
    @POST("messaging/conversations/{conversation_id}/messages/countdown")
    suspend fun sendCountdown(
        @Path("conversation_id") conversationId: String,
        @Body body: SendCountdownMessageIn,
    ): Response<MessageOut>
}
```
The `MessageOut` DTO (countdown fields `kind`, `countdown_title`, `target_datetime`, `associated_event_type`, `associated_event_id`) is owned by AND-120/AND-126; this ticket only ensures those fields are present in the shared DTO and mapped.

**Error responses** — FastAPI `detail` mapped by the AND-015 decoder into `UiError`:
- `401` → authenticator refreshes once then retries; second `401` → `Unauthorized`, send `FAILED`, surface re-auth.
- `403` → CSRF/permission; `FAILED`, non-retryable hint.
- `404` → conversation gone; `FAILED`, "conversation unavailable".
- `422` → `HTTPValidationError` = `{ detail: ValidationError[] }`, where each `ValidationError` is `{ loc: (string|int)[], msg: string, type: string }` (all three required) — e.g. title length, missing `target_datetime`; `FAILED`, show first `msg`; validate client-side to avoid most cases. *(Correction: original draft listed only `{msg, loc}`; `type` is also present and required. Verified against `components.schemas.ValidationError`. Note: per `openapi.index.txt`, the only declared error response for this op is `422`; `401/403/404/5xx` below are framework-level/transport behaviors, not enumerated response schemas for this endpoint — treated as unverified-for-this-op assumptions, consistent with the shared client in `src/api/client.ts`.)*
- `5xx`/timeout/`IOException` → `FAILED`, retryable.

## 6. Data & State Management

- **Confirmed countdowns:** persisted as `MessageEntity` (Room, AND-123) with the kind-specific countdown fields stored in the entity's payload column; source of truth for thread history + dedup against poll/refresh by `clientId`/`id`.
- **Pending/failed countdowns:** `OutboxMessageEntity` with `kind="countdown"` and `payloadJson` (this ticket's generalization). Survives process death so a `FAILED` countdown and its title/target are recoverable and retryable.
- **Picker draft:** held in the ViewModel (and mirrored to `SavedStateHandle` key `countdown_draft_<conversationId>`) so rotation while the sheet is open does not lose the title/target.
- **Merge/dedup:** render list = `history ∪ outbox` deduped by `clientId` (history wins); on a matching confirmed row the outbox entry is deleted — unchanged from AND-124.
- **Live remaining time is NOT persisted or stored as mutable state.** It is always *derived* from `targetEpochSeconds` and the current clock at render time, so it is correct after backgrounding, rotation, and process recreation with zero reconciliation logic.
- **Ordering / threading:** rows ordered by `createdAt`; optimistic rows use local time and re-sort on ack; all DB writes on `Dispatchers.IO`; state exposed as `StateFlow<MessagingUiState>` via `stateIn`.

## 7. Error Handling & Resilience

- **Send is POST (non-idempotent at HTTP).** No auto-retry — retry is user-initiated (inherits AND-124 FR-7). If `MessageOut` echoes/derives a `client_id` for dedupe, a manual retry reconciles safely; this is recorded as **OQ-1**.
- **Timeouts:** OkHttp call timeout ~20s (dev-host policy). A send exceeding it becomes `FAILED`, never hangs the UI.
- **Offline:** with no connectivity the optimistic countdown goes straight to `FAILED` with "No connection — Retry"; nothing is dropped, and the bubble still ticks locally from its stored target.
- **Clock skew:** remaining time uses the **device** clock; a wrong device clock yields a wrong countdown. Acceptable for this ticket; if the server provided a reference `now`, an offset correction could be applied later (noted in Risks). The server-supplied `target_datetime` is authoritative for the target itself.
- **Refresh-on-401:** centralized in the OkHttp authenticator; the send coroutine sees only the post-refresh outcome; double-401 → `FAILED`.
- **Process death mid-send:** `SENDING` outbox row older than the timeout window is normalized to `FAILED` on next thread load (AND-124 rule); retry re-encodes from `payloadJson`.
- **Ticker resilience:** lifecycle-scoped collection (`collectAsStateWithLifecycle`) prevents leaked coroutines and background battery drain; on resume the derived value snaps to the correct wall-clock remaining (no accumulated drift).

## 8. Security & Privacy

- Auth/CSRF/cookie-jar are transport concerns owned by core-network; this ticket adds no auth code and must not bypass the `X-CSRF-Token` interceptor or cookie jar.
- Countdown `title` is user content: never written to logcat or telemetry payloads (see §10). The outbox stores the title only in the app-private Room DB.
- The dev backend is plaintext HTTP (known dev-only). Release builds use HTTPS and the network-security-config forbids cleartext for production hosts (inherited from network/build tickets).
- `title` is sent verbatim as JSON via Moshi (no string interpolation → no injection surface) and rendered via Compose `Text` (no HTML → no XSS). Validate `target_datetime` is a plausible integer to avoid sending malformed payloads.

## 9. Accessibility & i18n

- Picker controls labeled: title `TextField` ("Countdown title"), date/time pickers expose their Material 3 semantics; "Send countdown" button has `contentDescription` and announces disabled state with the reason.
- The countdown bubble exposes a **single coherent `contentDescription`** (e.g. "Countdown: Launch, 2 days 4 hours remaining") rather than reading four separate numeric fields; it updates at a coarse cadence (e.g. on minute change) to avoid spamming TalkBack every second. The completed state announces "Event reached".
- Live ticking conveys state via text, not color only; reduced-motion users are unaffected (text update, no animation required).
- All strings in `strings.xml`; remaining-time and target formatting are **locale- and time-zone-aware** (`java.time` / kotlinx-datetime with the device zone for display, UTC for transport). RTL-safe (start/end, no hardcoded LTR layout). Touch targets ≥ 48dp.

## 10. Telemetry & Logging

- Events (analytics facade from core-data; no PII, **no title**):
  - `countdown_send_attempt` { conversationId (hashed), leadTimeBucket } — `leadTimeBucket` = coarse bucket of (target − now), not the exact instant.
  - `countdown_send_success` { latencyMs }
  - `countdown_send_failed` { errorClass, httpStatus }
  - `countdown_send_retry` { attemptCount }
- Logging: `Timber.d`/`w` for send lifecycle keyed by `clientId` only — never the title, target, or cookies. Network logging interceptor stays at `BASIC` for release.

## 11. Testing Strategy

- **Unit — `CountdownFormatter` (pure, deterministic):** formats `2d 04:12:09`, `04:12:09`, `00:00:09`, `00:00:00`; `isDone` true at/under zero; boundary at exactly 24h.
- **Unit — remaining-time derivation:** feed a fake/`TestScope` ticker emitting controlled instants; assert the derived `Duration` decreases each tick and clamps to zero past the target (no negative). Uses an injected `Clock`/ticker (no real `delay`).
- **Unit — ViewModel (`MainDispatcherRule`, Turbine):**
  - Valid draft → optimistic countdown row inserted (`SENDING`), sheet closed, draft cleared. *(covers "Countdown message sends")*
  - `ApiResult.Success` → row reconciles to `SENT` with server `id`/`created_at`, outbox deleted, no duplicate.
  - `ApiResult.Error` → `FAILED`, title/target preserved, retry re-fires same payload → `SENDING`.
  - Validation: blank/over-200-char title, null target, and past/now target all block send with the right inline error.
  - Time-zone correctness: a local date/time selection maps to the expected UTC `target_datetime` (seconds).
- **Repository / MockWebServer:** assert request JSON (`title`, `target_datetime`, `associated_event_type`) and `X-CSRF-Token` header; map `201`→`MessageContent.Countdown`; map `422`/`500`/timeout → correct `ApiResult.Error`.
- **Compose UI:** open picker → pick future time → Send shows a ticking bubble; bubble's displayed remaining text decreases over advanced test time and flips to completed at/after target *(covers "and ticks")*; accessibility assertions on the bubble's `contentDescription`; ticker stops when the screen leaves `STARTED` (no recomposition storm).
- No live dev-host calls in CI; all timing tests use injected dispatchers/clock — never real wall-clock waits.

## 12. Dependencies & Sequencing

- **Depends on AND-124** (Send text message): provides the optimistic-send pipeline, outbox, `MessageRepository` send template, `SendStatus`, and merge/dedup-by-`clientId` flow that this ticket reuses. Must merge after AND-124.
- **Transitive (must exist):** AND-126 (sealed message model + countdown mapper, `MessageContent.Countdown`), AND-120 (`MessagingApi` + `MessageOut` DTO incl. countdown fields), AND-123 (thread screen + message-item Composable to add the countdown branch), and the core-network auth/CSRF/cookie-jar/`ApiResult`/`detail`-decoder tickets.
- **Library:** add `androidx.lifecycle:lifecycle-runtime-compose` (for `collectAsStateWithLifecycle`) and `kotlinx-datetime` if not already present (managed in the version catalog by the build tickets).
- **Blocks:** none recorded in the source bullets. (AND-138 calendar messages may later deep-link from a countdown's `associated_event_*`, but that linkage is owned there, not here.)

## 13. Risks & Open Questions

- **OQ-1 (RESOLVED — no idempotency key):** Confirmed that **neither** `SendCountdownMessageIn` (request) **nor** `MessageOut` (response) carries a `client_id`/idempotency field — verified against `components.schemas.SendCountdownMessageIn`, `components.schemas.MessageOut`, and `src/api/endpoints/messaging.ts: sendCountdownMessage` (the web client posts only `{title, target_datetime, associated_event_type?, associated_event_id?, reply_to_message_id?}`). Therefore a manual retry after an uncertain failure **can** create a duplicate countdown. Mitigation as drafted: client-side reconcile by `(sender_id, title, target_datetime, createdAt≈)` heuristic (note: author field is `sender_id`, not `authorId`) and gate retry behind explicit user confirmation.
- **OQ-2 (RESOLVED):** Schema confirms `associated_event_type` defaults to `"custom"` and `associated_event_id` is `string ≤128 | null`. The web composer (`CountdownComposerDialog.tsx`) treats `associated_event_id` as **required when `associated_event_type != "custom"`** and not required for `custom` — so defaulting to `custom`/null (this ticket's behavior) is safe and contract-correct.
- **OQ-3 (RESOLVED):** Success is **`201` only** for this op (no `200` declared in OpenAPI responses); still handle via `Response.isSuccessful` for robustness. `created_at` is an **integer Unix epoch** (`MessageOut.created_at: type integer`), so **do NOT use an ISO-8601 adapter** — decode as `Long` epoch (web `adaptMessage` does `toNum(created_at)`). *(Correction: original draft assumed a 200/201 ambiguity and an ISO-8601 timestamp.)*
- **Risk — device clock skew:** remaining time depends on the device clock; a wrong clock shows a wrong countdown. Mitigation: documented limitation; optional future server-`now` offset correction (out of scope).
- **Risk — battery/recomposition:** a naive per-bubble 1s timer could thrash. Mitigation: single conflated ticker + `derivedStateOf` + lifecycle-scoped collection; covered by the "ticker stops below STARTED" UI test.
- **Risk — far-future targets:** large `target − now` must format without overflow; `Duration`/`Long` seconds are safe within documented ranges; tested at multi-year lead time.

## 14. Acceptance Criteria

AC-1. From the composer, a user can open the countdown picker, enter a title (1–200 chars) and a **future** date/time, and send; the message appears in the thread optimistically as a countdown bubble (`SENDING`). *(source: "Countdown message sends")*

AC-2. The request posts to `POST /messaging/conversations/{conversation_id}/messages/countdown` with `title` and a UTC-seconds `target_datetime` (and `associated_event_type="custom"`), carrying session cookies + `X-CSRF-Token`; on `201` the row reconciles to a confirmed `SENT` message with no duplicate. *(verified by automated test)*

AC-3. The rendered countdown bubble shows the title, the locale/zone-formatted target, and a remaining-time value that **decreases once per second** (days/hours/minutes/seconds), and flips to a completed "event reached" state at/after the target without a reload. *(source: "and ticks")*

AC-4. A past/now target or a blank/over-200-char title is blocked client-side with an inline error and cannot be sent.

AC-5. On send failure the bubble shows `FAILED` + Retry, preserving the entered title/target; retry re-sends the same payload and returns to `SENDING`; a pending/failed countdown survives process death (outbox).

AC-6. Time zone is handled correctly: a selected local date/time maps to the correct UTC `target_datetime`, and the displayed target/remaining values are computed in the device zone. *(verified by automated test)*

AC-7. Ticking is lifecycle-aware: timers stop when the thread leaves the foreground and re-sync (no drift, no leaked coroutines, no per-bubble timer storm). *(verified by automated test)*

## 15. Definition of Done

- `SendCountdownMessageIn` DTO + `MessagingApi.sendCountdown` in `:core:network`/`:core:model`; `MessageContent.Countdown` mapping confirmed (AND-126); `MessageRepository.sendCountdown` in `:core:data`; `CountdownDraft`, `onSendCountdown`/validation in `MessagingViewModel`; `CountdownPickerSheet`, `CountdownBubble`, `CountdownFormatter`, and the lifecycle-aware ticker in `:feature:messaging` under `com.testlogon.android.feature.messaging`.
- Optimistic send + ack reconciliation + manual retry functional against MockWebServer and manually verified against the dev host; live ticking and completion verified.
- All §11 unit, repository, DAO/outbox, and Compose UI tests pass in CI; no live-host calls in CI; timing tests use injected clock/dispatcher.
- No title in logs or telemetry; `X-CSRF-Token` and cookie-jar paths verified; Detekt/ktlint clean; KSP builds.
- Strings externalized; bubble exposes a coherent throttled accessibility description; locale/RTL/time-zone-correct formatting; touch targets ≥ 48dp.
- All ACs in §14 demonstrably met; OQ-1 (idempotency/dedupe) confirmed and reflected in code before merge.
- PR targets the `android-port` branch and references AND-137 and AND-124 (and AND-126/AND-123 as consumed).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI pointers reference `reference/openapi.index.txt` (line 336 for this op) and `reference/openapi.pretty.json` (`components.schemas.<Name>`). Frontend pointers are paths under `reference/src/`.

1. **Endpoint is `POST /messaging/conversations/{conversation_id}/messages/countdown`.** — **Verified.** Source: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/countdown` (index line 336); `src/api/endpoints/messaging.ts: sendCountdownMessage`.
2. **operationId / summary / description.** operationId `create_countdown_message_messaging_conversations__conversation_id__messages_countdown_post`; summary "Create Countdown Message"; description "Send a countdown message to a conversation (MSG-010)". — **Verified.** Source: OpenAPI path object for the op (`openapi.pretty.json`).
3. **Request schema `SendCountdownMessageIn`:** `title` (string, required, minLength 1, maxLength 200), `target_datetime` (integer, required, "UTC Unix timestamp of the target event"), `associated_event_type` (string, default `"custom"`, pattern `^(broadcast|call|calendar|custom)$`), `associated_event_id` (string ≤128 | null), `reply_to_message_id` (string | null); required = `[title, target_datetime]`. — **Verified.** Source: `components.schemas.SendCountdownMessageIn`.
4. **Success status is `201` with body `MessageOut`; only `422` is the declared error response.** — **Verified.** Source: OpenAPI op `responses` (`201: MessageOut`, `422: HTTPValidationError`); index line 336 `resp=201:MessageOut;422:HTTPValidationError`.
5. **Response identifier field is `message_id` (NOT `id`).** — **Corrected** (draft said `id`). Source: `components.schemas.MessageOut` (`message_id` property); `src/api/endpoints/messagingAdapter.ts: adaptMessage` (`message_id: String(raw.message_id ?? "")`).
6. **`MessageOut.created_at` is an integer Unix epoch (NOT ISO-8601 string).** — **Corrected** (draft example used an ISO string; OQ-3 assumed an ISO-8601 adapter). Source: `components.schemas.MessageOut.created_at: {type: integer}`; `adaptMessage` uses `created_at: toNum(raw.created_at)`.
7. **Countdown projection fields on `MessageOut`: `countdown_title`, `target_datetime`, `associated_event_type`, `associated_event_id`, `kind`.** — **Verified.** Source: `components.schemas.MessageOut` (those properties exist); `src/api/types.ts` (`countdown_title?`, `target_datetime?`, `associated_event_type?: "broadcast"|"call"|"calendar"|"custom"|null`, `associated_event_id?`).
8. **`MessageOut.kind` enum includes `"countdown"`.** — **Verified.** Source: `components.schemas.MessageOut.kind.enum` = `[text,image,file,audio,video,gallery,file_share,calendar_share,calendar_event,meeting_poll,video_share,voice_message,voicemail,countdown,gif,sticker,find_datetime]`. (Note: this server enum differs from the AND-126 domain enumeration cited in §1, e.g. server has `voice_message`/`gif`/`sticker` but no `poll`/`system`; the `countdown` member — all this ticket needs — is present.)
9. **No client idempotency key (`client_id`) on request or response.** — **Verified (OQ-1 resolved).** Source: `components.schemas.SendCountdownMessageIn` (no such field), `components.schemas.MessageOut` (no such field), `src/api/endpoints/messaging.ts: sendCountdownMessage` (posts no client key).
10. **`422` validation shape is `HTTPValidationError = {detail: ValidationError[]}` with `ValidationError = {loc, msg, type}` (all required).** — **Corrected** (draft listed only `{msg, loc}`). Source: `components.schemas.HTTPValidationError`, `components.schemas.ValidationError`.
11. **Auth: session cookies + `Authorization: Bearer <accessToken>` + `ui_csrf` cookie echoed as `X-CSRF-Token`.** — **Corrected** (draft said "Cookie-based auth" only, omitting the Bearer token). Source: `src/api/client.ts` (`headers.set("Authorization", \`Bearer ${accessToken}\`)`, `getCookie("ui_csrf")` → `X-CSRF-Token`, `credentials: "include"`). OpenAPI op also declares optional `authorization` and `X-SESSION-ID` headers (`openapi.pretty.json` op `parameters`).
12. **On `401`, refresh once via `POST /ui/session/refresh` then retry; second failure logs out.** — **Verified.** Source: `src/api/client.ts: refreshSession()` (POST `/ui/session/refresh`) and the 401 retry block (single in-flight `refreshPromise`, retry, logout on repeat 401).
13. **`403` handling carries structured `detail.code` (e.g. `geo_blocked`, `role_required*`, `helpdesk_*`).** — **Verified.** Source: `src/api/client.ts: mapAuthorizationError` + the 403 branch handling `code === "geo_blocked"`.
14. **Web validation: title non-blank & ≤200 chars, target strictly future; target seconds = `floor(localDate.getTime()/1000)`.** — **Verified.** Source: `src/pages/messages/CountdownComposerDialog.tsx` (`canSubmit`, `targetTs = Math.floor(new Date(localDatetime).getTime()/1000)`, `isFuture = targetTs > nowTs`).
15. **`custom` requires no `associated_event_id`; non-custom requires one (web).** — **Verified (OQ-2 resolved).** Source: `CountdownComposerDialog.tsx` (`eventIdRequired = eventType !== "custom"`; `canSubmit` includes `(!eventIdRequired || eventId.trim().length > 0)`). Schema permits `associated_event_id: null` (`SendCountdownMessageIn`).
16. **Web render ticks once per second from wall-clock and stops at zero; format `{d}d HH:MM:SS` / `HH:MM:SS`.** — **Verified.** Source: `src/pages/messages/CountdownCard.tsx` (`setInterval(...,1000)`, `calculateRemaining` recomputed from `Date.now()`, `clearInterval` when `total <= 0`; days shown only when `> 0`).
17. **Web completed-state copy is "Time's up!" (custom) / "Event started!" (non-custom), with deep-link CTAs for broadcast/call/calendar when an event id is present.** — **Verified.** Source: `CountdownCard.tsx`. The Android spec's "Event reached" string (§1/§6/§9) is an **app-level copy choice**, not a server contract — acceptable divergence.
18. **`collectAsStateWithLifecycle` stops collection below `STARTED` (lifecycle-aware ticking, FR-8).** — **Verified (framework ref).** Source: framework ref — Android Developers, `lifecycle-runtime-compose` / `collectAsStateWithLifecycle` (https://developer.android.com/reference/kotlin/androidx/lifecycle/compose/package-summary#(kotlinx.coroutines.flow.StateFlow).collectAsStateWithLifecycle(androidx.lifecycle.Lifecycle.State,kotlin.coroutines.CoroutineContext)).
19. **Material 3 `ModalBottomSheet` / `DatePicker` / `TimePicker` exist for the picker (FR-1/FR-2).** — **Unverified-assumption (framework ref).** Source: framework ref — Material 3 Compose APIs (https://developer.android.com/jetpack/compose/components/datepickers). Not checkable from backend/frontend sources; standard M3 components.

### Corrections made

- **§2 & §5:** auth description expanded to include `Authorization: Bearer <accessToken>` (web client sends it); previously stated "Cookie-based auth" only. (Audit #11)
- **§2 & §13:** web-reference path corrected from `frontend/src/api/endpoints/conversations.ts` to `src/api/endpoints/messaging.ts` (`sendCountdownMessage`); added the actual composer/render files. (Audit #1)
- **§5 success example:** `"id"` → `"message_id"`; `created_at` ISO-8601 string → integer epoch; added `sender_id`; noted absence of `client_id`. (Audit #5, #6, #9)
- **§5 error responses:** `422` shape corrected to include the required `type` field; clarified that only `422` is an OpenAPI-declared error for this op. (Audit #10)
- **§13 OQ-1/OQ-2/OQ-3:** marked resolved with verified findings (no idempotency key; `custom` needs no event id; success is `201`-only and `created_at` is an integer epoch, so no ISO-8601 adapter). The reconcile heuristic field corrected from `authorId` to `sender_id`. (Audit #9, #15, #6)

### Open assumptions

- **AND-126 domain `kind` enumeration vs server enum (§1).** The §1 list (`…poll/countdown/calendar/system`) does not match the server `MessageOut.kind` enum (audit #8). This is owned by AND-126, not verifiable as "correct" here; only `countdown` (this ticket's concern) is confirmed present server-side. **Why open:** cross-ticket domain mapping is out of this ticket's authority.
- **`401/403/404/5xx` mapping for this specific op (§5).** OpenAPI declares only `422` for this operation; the other statuses are framework/transport behaviors inferred from the shared `src/api/client.ts`. Treated as reasonable assumptions, not endpoint-declared contracts. **Why open:** not enumerated in the OpenAPI responses for this path.
- **`X-SESSION-ID` header usage from Android (§2/§5).** The op declares an optional `X-SESSION-ID` header, but `src/api/client.ts` does not set it (it uses cookies + Bearer + CSRF). **Why open:** no source shows a client populating it; assume Android does not send it unless a core-network ticket dictates otherwise.
- **Material 3 picker components and exact M3 string/copy choices (§9, FR-1/2).** Framework-level; no authoritative project source. **Why open:** UI-framework choice, not a backend/web contract.
- **Device-clock-based remaining time (no server `now` reference).** Confirmed the server provides no reference clock in `MessageOut`; clock-skew remains an accepted limitation. **Why open:** server contract offers nothing to correct against.

## 17. Test Plan

Test targets: **JVM/Robolectric** (local, no device), **emulator AVD `test35`** (x86_64, API 35), **physical device** Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Pure-logic, contract, and ViewModel suites run on JVM/Robolectric. Compose-UI/instrumented suites run on the emulator by default; the physical device is only required where real hardware/ABI/API-34 behavior matters (none of this ticket's core logic is hardware-dependent — see TC-AND-137-12). All timing tests use an injected clock/ticker and a `TestScope`/virtual time — never real wall-clock waits.

- **TC-AND-137-01 — Formatter happy path (pure).** Type: unit (JVM). Target: `CountdownFormatter`. Preconditions: none. Steps: call `format()` with `Duration`s for `2d 04:12:09`, `04:12:09`, `00:00:09`, and `00:00:00`; call `isDone()` at `0s` and `-5s`. Expected: exact strings as listed; `isDone` true at `≤ 0`, false above; days shown only when `≥ 1d` (matches web `CountdownCard`). Traces: AC-3.

- **TC-AND-137-02 — Remaining-time derivation decreases and clamps (pure).** Type: unit (JVM, `TestScope`). Target: `rememberRemaining`/derivation using a fake ticker emitting controlled `Instant`s. Preconditions: injected clock/ticker. Steps: set target = now+10s; advance ticker 1s at a time past the target. Expected: derived `Duration` strictly decreases each tick, never negative, equals `ZERO` at/after target; no real `delay` used. Traces: AC-3, AC-7.

- **TC-AND-137-03 — Request contract & headers (contract/MockWebServer).** Type: contract (JVM, MockWebServer). Target: `MessageRepository.sendCountdown` → `MessagingApi`. Preconditions: enqueue `201` with a valid `MessageOut` countdown body. Steps: call `sendCountdown(conversationId, clientId, draft)` with title="Launch", a future target. Expected: request is `POST /messaging/conversations/{conversation_id}/messages/countdown`; JSON body has `title`, integer `target_datetime`, `associated_event_type="custom"`, `associated_event_id` and `reply_to_message_id` null/omitted; headers include `X-CSRF-Token` and `Authorization: Bearer …` and `Content-Type: application/json`. Traces: AC-2.

- **TC-AND-137-04 — Response mapping `201` → domain (contract/MockWebServer).** Type: contract (JVM). Target: `MessageOut.toDomain()` via repository. Preconditions: enqueue `201` body with `message_id`, integer `created_at`, `kind:"countdown"`, `countdown_title`, `target_datetime`, `associated_event_type:"custom"`, `associated_event_id:null`. Steps: send; inspect `ApiResult.Success`. Expected: `ApiResult.Success<Message>` whose content is `MessageContent.Countdown(title, targetEpochSeconds, CUSTOM, null)`, server `id` taken from **`message_id`**, `createdAt` parsed as a **Long epoch** (not ISO-8601). Traces: AC-2, AC-6.

- **TC-AND-137-05 — `422` validation error mapping (contract/MockWebServer).** Type: contract (JVM). Target: `apiCall`/`detail` decoder. Preconditions: enqueue `422` with `{"detail":[{"loc":["body","title"],"msg":"String should have at most 200 characters","type":"string_too_long"}]}`. Steps: send; inspect result. Expected: `ApiResult.Error` surfacing the first `msg`; decoder tolerates the `type` field; status classified non-retryable-validation. Traces: AC-4, AC-5.

- **TC-AND-137-06 — Server/transport error mapping (contract/MockWebServer).** Type: contract (JVM). Target: `apiCall`. Preconditions: enqueue `500`, then a socket timeout, then a dropped connection in separate runs. Steps: send each. Expected: each → `ApiResult.Error` classified retryable; OkHttp call timeout (~20s) bounds the hang; UI never blocks. Traces: AC-5.

- **TC-AND-137-07 — Optimistic send + reconcile (unit ViewModel).** Type: unit (JVM, `MainDispatcherRule` + Turbine). Target: `MessagingViewModel.onSendCountdown`. Preconditions: valid draft; repo stubbed `Success`. Steps: open picker, set valid draft, send. Expected: an outbox row `SENDING` with `kind="countdown"` and a `clientId` appears immediately, sheet closes, draft cleared, scroll-to-bottom requested; on `Success` the row reconciles to `SENT` with server `message_id`/`created_at`, outbox deleted, no duplicate (dedup by `clientId`). Traces: AC-1, AC-2.

- **TC-AND-137-08 — Send failure + retry preserves payload (unit ViewModel).** Type: unit (JVM, Turbine). Target: `onSendCountdown` + `onRetry`. Preconditions: repo stubbed `Error` first, then `Success`. Steps: send valid draft → observe `FAILED`; invoke `onRetry(clientId)`. Expected: row goes `FAILED` (title/target preserved via `payloadJson`), retry re-decodes the exact payload and re-fires → `SENDING` → `SENT`; `attemptCount` increments. Traces: AC-5.

- **TC-AND-137-09 — Client-side validation blocks send (unit ViewModel).** Type: unit (JVM). Target: `onSendCountdown` validation. Preconditions: none. Steps: attempt send with (a) blank title, (b) 201-char title, (c) null target, (d) past/now target. Expected: each blocked with the appropriate inline error ("Pick a future time" for past/now; length/required for title), no outbox row, no network call. Traces: AC-4.

- **TC-AND-137-10 — Time-zone correctness (unit).** Type: unit (JVM, fixed zone + fixed clock). Target: draft→`target_datetime` conversion. Preconditions: set device zone (e.g. `America/Chicago`) and a fixed clock. Steps: select a local date/time; compute the request timestamp; also format the target back for display. Expected: `target_datetime` equals the correct UTC seconds (`floor(localInstant/1000)`, matching web `CountdownComposerDialog`); displayed target is rendered in the device zone. Traces: AC-6.

- **TC-AND-137-11 — Bubble ticks and flips to completed (Compose-UI).** Type: Compose-UI (emulator `test35`). Target: `CountdownBubble` + ticker. Preconditions: composed with target = now+3s using an injected/advanceable clock. Steps: assert displayed remaining text; advance test clock 1s at a time; advance past target. Expected: remaining text decreases each second; at/after target the bubble shows the completed ("Event reached") state, stops scheduling ticks (no recomposition storm), without a reload. Traces: AC-3.

- **TC-AND-137-12 — Lifecycle-aware ticker stops below STARTED (instrumented).** Type: instrumented (emulator `test35`; physical device only if verifying API-34 lifecycle parity). Target: ticker collection via `collectAsStateWithLifecycle`. Preconditions: thread screen visible with a countdown bubble. Steps: move the host lifecycle to `STOPPED` (background), wait, then return to `RESUMED`. Expected: no ticks/recompositions while below `STARTED` (no leaked coroutine, no battery drain); on resume the derived remaining snaps to correct wall-clock value with no accumulated drift. Traces: AC-7.

- **TC-AND-137-13 — Offline / flaky dev-host path (contract + Compose-UI).** Type: contract/MockWebServer + Compose-UI (emulator). Target: send pipeline under no connectivity / dev-host failure. Preconditions: simulate offline (no route) or MockWebServer dropping the connection. Steps: send a valid countdown. Expected: optimistic bubble appears then goes `FAILED` with "No connection — Retry"; nothing dropped; the bubble still ticks locally from its stored target; a subsequent successful retry reconciles to `SENT`. Traces: AC-5, AC-3.

- **TC-AND-137-14 — Auth: CSRF/Bearer present; 401→refresh→retry (contract/MockWebServer).** Type: contract (JVM/instrumented). Target: transport (cookie jar + CSRF interceptor + authenticator). Preconditions: MockWebServer returns `401` once then `201` on retry; cookie jar seeded; `ui_csrf` set. Steps: send. Expected: first request carries `X-CSRF-Token` + `Authorization: Bearer` + cookies; on `401` a single `POST /ui/session/refresh` fires, then the original request retries and succeeds; a second consecutive `401` → `FAILED`/re-auth, no infinite loop. Traces: AC-2, AC-5.

- **TC-AND-137-15 — Accessibility of picker and bubble (Compose-UI).** Type: Compose-UI (emulator). Target: `CountdownPickerSheet`, `CountdownBubble`. Preconditions: bubble composed mid-countdown. Steps: assert semantics. Expected: title field labeled "Countdown title"; "Send countdown" button has a content description and announces its disabled reason; the bubble exposes a single coherent `contentDescription` (e.g. "Countdown: Launch, 2 days 4 hours remaining") updated at a coarse (≈minute) cadence, not every second; completed state announces "Event reached"; state conveyed by text not color-only; touch targets ≥ 48dp. Traces: AC-3, AC-4.

- **TC-AND-137-16 — Security: title not logged; no auth bypass (unit + manual).** Type: unit (JVM) + manual. Target: logging/telemetry facade + transport. Preconditions: send a countdown with a recognizable title. Steps: capture Timber/logcat and analytics payloads during send/retry; inspect outgoing request. Expected: no title/target/cookies in logs or analytics (only `clientId`, hashed conversationId, buckets); request always carries the CSRF + cookie/Bearer (interceptor not bypassable); release network log interceptor at `BASIC`. Traces: AC-2, AC-5.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (open picker, enter title+future, optimistic bubble) | TC-AND-137-07, TC-AND-137-15 |
| AC-2 (POST contract, cookies+CSRF, 201 reconcile, no dup) | TC-AND-137-03, TC-AND-137-04, TC-AND-137-07, TC-AND-137-14, TC-AND-137-16 |
| AC-3 (bubble shows title/target, ticks/sec, flips completed) | TC-AND-137-01, TC-AND-137-02, TC-AND-137-11, TC-AND-137-13, TC-AND-137-15 |
| AC-4 (past/now or bad title blocked client-side) | TC-AND-137-05, TC-AND-137-09, TC-AND-137-15 |
| AC-5 (FAILED+Retry preserves payload, survives process death) | TC-AND-137-05, TC-AND-137-06, TC-AND-137-08, TC-AND-137-13, TC-AND-137-14, TC-AND-137-16 |
| AC-6 (time-zone correctness, UTC target_datetime) | TC-AND-137-04, TC-AND-137-10 |
| AC-7 (lifecycle-aware ticking, no drift/leak/storm) | TC-AND-137-02, TC-AND-137-11, TC-AND-137-12 |

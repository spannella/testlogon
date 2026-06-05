---
id: AND-138
title: Calendar event / share messages
milestone: M3
epic: E19
priority: P2
size: M
status: draft
depends_on: [AND-124, AND-037]
blocks: []
---

# AND-138 — Calendar event / share messages

> Note on dependencies: the backlog cites `AND-037(M6 cal)` — the calendar-domain
> ticket that owns the canonical calendar model and the M6 calendar feature
> screens. Where this spec needs calendar primitives that AND-037 owns, it
> defines a minimal local fallback and flags the hand-off explicitly. `AND-124`
> (Send text message) is the message-pipeline dependency that establishes the
> conversation/message rendering substrate this ticket extends.

## 1. Overview & Goal

Add first-class rendering and detail navigation for two structured message
payload types inside a conversation thread: **calendar event** messages
(`/messages/calendar-event`) and **calendar share** messages
(`/messages/calendar-share`). A calendar-event message carries an inline event
(title, start/end, location, RSVP state); a calendar-share message carries a
reference to a shared calendar (calendar id, name, owner, permission level).

Today the thread (AND-123) and composer (AND-124) only render plain text. When
the backend delivers a message whose `type` is `calendar_event` or
`calendar_share`, the current client renders it as an empty or raw-JSON bubble.

Goal: render both message types as rich, accessible cells inside the existing
`LazyColumn` thread, and make each cell tappable to open a read-only detail
screen. The detail screen surfaces the full payload and, for calendar-event
messages, an "Add to calendar" affordance that hands off to the system calendar
via an `ACTION_INSERT` intent (no in-app calendar write in M3 — that lands in M6
under AND-037).

This ticket is **render + open detail** only. Authoring/sending these message
types, RSVP mutation, and accepting a calendar share are explicitly out of scope
and tracked downstream (see §12).

## 2. Context & References

- Thread/message substrate: AND-123 (`thread-message-list-screen`), AND-124
  (`send-text-message`). This ticket plugs into the existing
  `feature-messages` module and its `MessageCell` dispatch.
- Sibling structured-message ticket: AND-137 (`countdown-messages`) follows the
  identical "new `MessageType` + cell renderer + dispatch" pattern; keep the
  `MessageContent` sealed hierarchy and Moshi polymorphic adapter consistent
  with it.
- Calendar domain owner: AND-037 (M6 calendar). Reuse its `CalendarRef` /
  `CalendarEvent` core-model types if merged; otherwise define the minimal DTOs
  here and migrate.
- Web reference: `frontend/src/api/endpoints/messages.ts` and
  `frontend/src/api/types.ts` (`MessageType`, `CalendarEventPayload`,
  `CalendarSharePayload`). OpenAPI: `GET /openapi.json` (dev backend
  `http://18.222.237.167:8000`, plaintext HTTP, ~20s timeouts, unreliable).
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single
  Activity), Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi
  1.15, Paging 3, Coil. Package base `com.testlogon.android`. minSdk 24,
  compile/target 35, JDK 17.

## 3. Functional Requirements

FR-1. The thread list MUST render a message whose `type == "calendar_event"`
using `CalendarEventCell`, showing event title, formatted start–end time
(localized, timezone-aware), location (if present), and RSVP status chip
(`yes`/`no`/`maybe`/`pending`).

FR-2. The thread list MUST render a message whose `type == "calendar_share"`
using `CalendarShareCell`, showing calendar name, owner display name, and a
permission badge (`viewer`/`editor`).

FR-3. Both cells MUST honor sender alignment (incoming/outgoing), date
separators, and sender grouping established by AND-123 — they are a payload
swap inside the existing message-row chrome, not a new row layout.

FR-4. Tapping either cell MUST navigate to a read-only detail route
(`message/{conversationId}/{messageId}/calendar-event` or
`.../calendar-share`) rendered by `CalendarMessageDetailScreen`.

FR-5. The calendar-event detail MUST expose an "Add to calendar" button that
launches an `Intent(Intent.ACTION_INSERT)` against
`CalendarContract.Events.CONTENT_URI` prefilled from the payload. If no calendar
app resolves the intent, show a non-blocking snackbar ("No calendar app
available") and do not crash.

FR-6. The calendar-share detail MUST display calendar metadata and a disabled,
labeled "Accept share (coming soon)" affordance pointing at the downstream
ticket; it MUST NOT perform any mutation.

FR-7. Unknown/malformed structured payloads MUST degrade to a generic
"Unsupported message" fallback cell (never an empty bubble, never a crash) and
remain tappable to a fallback detail showing raw fields.

FR-8. All times MUST render in the device locale and the device timezone, with
all-day events rendered without a clock component.

## 4. Technical Design

Module: `feature-messages` (UI + ViewModels), models in `core-model`,
serialization in `core-network`.

### 4.1 Model (core-model)

Extend the existing message content sealed type (introduced by AND-124, extended
by AND-137):

```kotlin
sealed interface MessageContent {
    data class Text(val body: String) : MessageContent
    // AND-137:
    data class Countdown(val targetAt: Instant, val label: String?) : MessageContent
    // AND-138:
    data class CalendarEventContent(val event: CalendarEventPayload) : MessageContent
    data class CalendarShareContent(val share: CalendarSharePayload) : MessageContent
    data class Unsupported(val rawType: String, val raw: Map<String, Any?>) : MessageContent
}

data class CalendarEventPayload(
    val eventId: String,
    val title: String,
    val startAt: Instant,
    val endAt: Instant?,
    val allDay: Boolean,
    val timezone: String?,        // IANA tz, e.g. "America/New_York"
    val location: String?,
    val description: String?,
    val rsvp: RsvpStatus,         // server-reported viewer RSVP
)

enum class RsvpStatus { YES, NO, MAYBE, PENDING, UNKNOWN }

data class CalendarSharePayload(
    val calendarId: String,
    val calendarName: String,
    val ownerDisplayName: String,
    val permission: SharePermission, // VIEWER | EDITOR | UNKNOWN
    val color: String?,              // hex, optional
)

enum class SharePermission { VIEWER, EDITOR, UNKNOWN }
```

`Instant` from `java.time` (desugaring already enabled for minSdk 24 per
AND-001/AND-002; confirm `coreLibraryDesugaringEnabled = true`).

### 4.2 Serialization (core-network)

Moshi polymorphic adapter keyed on the wire `type` discriminator. Register in
the network module; defaults to `Unsupported`:

```kotlin
val messageContentAdapter: PolymorphicJsonAdapterFactory<MessageContentDto> =
    PolymorphicJsonAdapterFactory.of(MessageContentDto::class.java, "type")
        .withSubtype(TextDto::class.java, "text")
        .withSubtype(CountdownDto::class.java, "countdown")
        .withSubtype(CalendarEventDto::class.java, "calendar_event")
        .withSubtype(CalendarShareDto::class.java, "calendar_share")
        .withDefaultValue(MessageContentDto.Unsupported)
```

DTO→domain mapping lives in `MessageMappers.kt`. `Instant` parsed from RFC-3339
strings via a shared `InstantJsonAdapter` (define once if AND-137 has not).
Enums map unknown strings to `UNKNOWN`/`PENDING` rather than throwing.

### 4.3 Cell dispatch (feature-messages)

```kotlin
@Composable
fun MessageCell(
    message: UiMessage,
    onOpenDetail: (MessageRef) -> Unit,
    modifier: Modifier = Modifier,
) {
    when (val c = message.content) {
        is MessageContent.Text -> TextCell(c, modifier)
        is MessageContent.Countdown -> CountdownCell(c, modifier)
        is MessageContent.CalendarEventContent ->
            CalendarEventCell(c.event, onClick = { onOpenDetail(message.ref) }, modifier)
        is MessageContent.CalendarShareContent ->
            CalendarShareCell(c.share, onClick = { onOpenDetail(message.ref) }, modifier)
        is MessageContent.Unsupported ->
            UnsupportedCell(c, onClick = { onOpenDetail(message.ref) }, modifier)
    }
}

data class MessageRef(val conversationId: String, val messageId: String, val kind: String)
```

Cells are stateless `@Composable` functions using Material 3 `Card`/`Surface`
with `onClickLabel` set for talkback. Date/time formatting via a shared
`rememberEventTimeFormatter()` that wraps `DateTimeFormatter.ofLocalizedDateTime`
in device locale + `ZoneId.systemDefault()`.

### 4.4 Detail navigation (feature-messages)

Add routes to the messages nav graph (within the authenticated graph,
AND-024/AND-025):

```kotlin
const val ROUTE_CAL_EVENT_DETAIL =
    "message/{conversationId}/{messageId}/calendar-event"
const val ROUTE_CAL_SHARE_DETAIL =
    "message/{conversationId}/{messageId}/calendar-share"
```

`CalendarMessageDetailScreen` is driven by `CalendarMessageDetailViewModel`
(Hilt `@HiltViewModel`, args via `SavedStateHandle`), exposing
`StateFlow<CalendarDetailUiState>`. It reads the already-cached message from the
thread repository (no new network call required for render; see §5/§6).

### 4.5 "Add to calendar" hand-off

```kotlin
fun buildInsertEventIntent(p: CalendarEventPayload): Intent =
    Intent(Intent.ACTION_INSERT).apply {
        data = CalendarContract.Events.CONTENT_URI
        putExtra(CalendarContract.Events.TITLE, p.title)
        p.location?.let { putExtra(CalendarContract.Events.EVENT_LOCATION, it) }
        p.description?.let { putExtra(CalendarContract.Events.DESCRIPTION, it) }
        putExtra(CalendarContract.EXTRA_EVENT_ALL_DAY, p.allDay)
        putExtra(CalendarContract.EXTRA_EVENT_BEGIN_TIME, p.startAt.toEpochMilli())
        (p.endAt ?: p.startAt).let {
            putExtra(CalendarContract.EXTRA_EVENT_END_TIME, it.toEpochMilli())
        }
    }
```

Launched via `rememberLauncherForActivityResult` /
`context.startActivity` guarded by `intent.resolveActivity(packageManager)`.
No `READ/WRITE_CALENDAR` permission is requested — `ACTION_INSERT` opens the
calendar app's own UI and requires no manifest permission.

## 5. API Contract

This ticket adds **no new endpoints**. Calendar-event and calendar-share
payloads arrive inline on the existing message objects returned by the
thread-history endpoint owned by AND-123:

`GET /conversations/{id}/messages` (paged, reverse-chronological).

Each message item carries a polymorphic `content` (or top-level `type` +
payload, matching the web `MessageType` union in `frontend/src/api/types.ts`).
Representative item shapes:

```json
{
  "id": "msg_01HZX...",
  "conversation_id": "conv_7Q...",
  "sender_id": "usr_42",
  "created_at": "2026-06-05T14:30:00Z",
  "type": "calendar_event",
  "calendar_event": {
    "event_id": "evt_91",
    "title": "Sprint review",
    "start_at": "2026-06-10T17:00:00Z",
    "end_at": "2026-06-10T18:00:00Z",
    "all_day": false,
    "timezone": "America/New_York",
    "location": "Room 4B / Meet link",
    "description": "Demo + retro",
    "rsvp": "pending"
  }
}
```

```json
{
  "id": "msg_01HZY...",
  "type": "calendar_share",
  "created_at": "2026-06-05T15:00:00Z",
  "calendar_share": {
    "calendar_id": "cal_55",
    "calendar_name": "Team On-call",
    "owner_display_name": "Dana Ruiz",
    "permission": "viewer",
    "color": "#2E7D32"
  }
}
```

If the precise field names differ from `/openapi.json`, the OpenAPI/web-types
shape is authoritative and the DTOs above MUST be reconciled before merge
(verify against the live schema, do not assume). The detail screen MAY issue an
idempotent `GET` refresh of the single message if a per-message endpoint exists;
if so it uses the bounded-backoff GET retry policy from AND-016 and a ~20s
timeout. Error `detail` is mapped per AND-015 (`string | [{msg}] | {code,...}`).

All requests ride the cookie session + `X-CSRF-Token` header; a 401 triggers
the single `POST /ui/session/refresh` + retry via the AND-013 authenticator.

## 6. Data & State Management

- Source of truth for render is the **Room-cached message** populated by the
  thread repository (AND-123/core-data). This ticket adds two columns or a JSON
  `content` blob column already present from AND-137; reuse it. No separate
  calendar table is introduced here (calendar persistence is AND-037/M6).
- ViewModel state:

```kotlin
sealed interface CalendarDetailUiState {
    data object Loading : CalendarDetailUiState
    data class EventReady(val event: CalendarEventPayload, val sender: SenderInfo) :
        CalendarDetailUiState
    data class ShareReady(val share: CalendarSharePayload, val sender: SenderInfo) :
        CalendarDetailUiState
    data class Unsupported(val rawType: String) : CalendarDetailUiState
    data class Error(val message: UiText, val retryable: Boolean) : CalendarDetailUiState
}
```

- The ViewModel resolves the message from cache by `messageId` first; only if
  absent (deep-link cold start) does it hit the network read. Stale-cache reads
  render immediately with an "offline/stale" indicator per AND-021/AND-045.
- Paging 3 thread flow is unchanged; new cells are pure functions of the already
  mapped `UiMessage`, so no paging invalidation is required.

## 7. Error Handling & Resilience

- **Malformed payload**: Moshi default → `MessageContent.Unsupported`; renders
  `UnsupportedCell`, never crashes (FR-7).
- **Missing optional fields** (`end_at`, `location`, `timezone`, `color`): omit
  the corresponding UI element; never render "null".
- **Unknown enum values**: map to `UNKNOWN`/`PENDING`; chip shows neutral state.
- **Network read for cold deep-link**: 20s timeout, bounded backoff for the
  idempotent GET only (AND-016); on failure show `Error(retryable = true)` with
  a Retry button; on offline show stale cache if present else offline state.
- **No calendar app** for `ACTION_INSERT`: snackbar, no crash (FR-5).
- **Timezone math**: all conversions go through `java.time` with explicit
  `ZoneId`; never use `Date`/`Calendar` arithmetic. All-day events use
  `LocalDate` rendering to avoid off-by-one across DST.

## 8. Security & Privacy

- No new credentials or PII storage; calendar payloads persist only in the
  existing encrypted-at-rest-by-OS Room cache already used for messages.
- The `ACTION_INSERT` intent shares event title/location/description with the
  user-selected calendar app — this is an explicit, user-initiated export; log
  no payload contents (see §10). No `READ_CALENDAR`/`WRITE_CALENDAR` permissions
  are added, minimizing surface.
- Detail screen is read-only; no mutations, no CSRF-bearing writes from this
  ticket. Session/CSRF handling is inherited unchanged from core-network.
- Do not place message ids or calendar ids in any analytics payload beyond
  hashed/anonymized form (§10).

## 9. Accessibility & i18n

- Each cell sets a single merged `contentDescription` summarizing the event,
  e.g. "Calendar event, Sprint review, June 10 5 to 6 PM, RSVP pending. Double
  tap to open." Permission/RSVP chips include text, not color alone.
- Minimum touch target 48dp for the whole cell and all detail buttons.
- All strings in `strings.xml` (no hardcoded literals); date/time via localized
  `DateTimeFormatter` honoring device locale, 12/24h setting, and timezone.
  Use `<plurals>` where counts appear. Layouts are RTL-safe (use start/end
  paddings). Support Dynamic Type / font scaling without truncation of title.
- The "coming soon" accept-share control is announced as disabled.

## 10. Telemetry & Logging

- Events (via the app analytics wrapper, redacted): `calendar_msg_rendered`
  `{kind: event|share, hasLocation, allDay}`; `calendar_msg_detail_opened`
  `{kind}`; `calendar_add_to_calendar_clicked` `{resolved: bool}`;
  `calendar_msg_unsupported_rendered` `{rawType}`.
- NO event title, location, description, names, calendar ids, or message ids in
  telemetry — only enums/booleans. Follow the redaction policy from AND-052.
- Logcat: `Timber.d` only at debug for dispatch decisions; no payload bodies in
  release builds.

## 11. Testing Strategy

Unit (core-network / core-model):
- Moshi: parse `calendar_event` and `calendar_share` JSON → correct domain;
  unknown `type` → `Unsupported`; missing `end_at`/`timezone` handled; bad enum
  → `UNKNOWN`/`PENDING`; RFC-3339 → `Instant` round-trip.
- `buildInsertEventIntent` populates extras correctly, including all-day flag and
  `endAt ?: startAt` fallback.

ViewModel (core-testing + coroutines test):
- `CalendarMessageDetailViewModel` emits `EventReady`/`ShareReady` from cache;
  `Error(retryable=true)` on cold-deep-link network failure; `Unsupported` path.

Compose UI tests (AND-048/AND-049 harness, instrumented):
- `CalendarEventCell` shows title + formatted time + RSVP chip; tapping invokes
  `onOpenDetail`. `CalendarShareCell` shows name/owner/permission badge.
- Thread renders mixed text + calendar cells in order (MockWebServer fixtures
  per AND-046).
- Detail "Add to calendar" launches an `ACTION_INSERT` intent (Espresso-Intents
  `intended(hasAction(ACTION_INSERT))`); no-resolver path shows snackbar.

This directly satisfies the backlog acceptance ("Calendar message renders +
opens detail") with automated coverage.

## 12. Dependencies & Sequencing

- **Depends on**: AND-124 (message pipeline, `MessageContent` sealed type,
  composer/thread cell dispatch) and AND-037 (M6 calendar domain — canonical
  `CalendarEventPayload`/`CalendarRef` if available). Also implicitly builds on
  AND-123 (thread list chrome) and AND-015/AND-016/AND-013 (error/retry/auth).
- **Pattern-aligned with**: AND-137 (countdown) — land after or alongside it to
  share the polymorphic adapter and `MessageContent.Unsupported` default.
- **Blocks**: none recorded. Downstream (NOT in this ticket): authoring calendar
  messages, RSVP mutation, and accept-share are owned by the M6 calendar epic
  (AND-037 family); wire the disabled "Accept share" control to that ticket when
  it lands.

## 13. Risks & Open Questions

- R1 (schema): exact wire field names/discriminator (`type` vs nested) must be
  confirmed against `/openapi.json` and `frontend/src/api/types.ts`; DTOs here
  are provisional. Owner: implementer, before merge.
- R2 (model ownership): if AND-037 has not merged its `CalendarEventPayload`,
  this ticket defines a local copy and must migrate later — risk of type
  duplication. Mitigation: keep types in `core-model` so AND-037 can adopt them.
- R3 (timezone): server may send naive timestamps + separate `timezone`;
  rendering must use that tz, not device tz, when present. Open question:
  confirm whether `start_at` is always UTC.
- R4 (RSVP semantics): is `rsvp` the viewer's status or aggregate? Affects chip
  copy. Defer mutation regardless (out of scope).
- R5 (all-day off-by-one): DST/locale edge cases for `ACTION_INSERT` all-day
  extras; covered by unit tests but verify on a physical device.

## 14. Acceptance Criteria

AC-1. A message with `type == "calendar_event"` renders a `CalendarEventCell`
showing title, localized start–end time (or all-day), location (if present), and
RSVP chip — verified by Compose UI test.
AC-2. A message with `type == "calendar_share"` renders a `CalendarShareCell`
showing calendar name, owner, and permission badge — verified by Compose UI test.
AC-3. Tapping either cell navigates to `CalendarMessageDetailScreen` showing the
full payload (verified via Espresso navigation assertion).
AC-4. Calendar-event detail "Add to calendar" launches an `ACTION_INSERT` intent
prefilled from the payload; no-resolver case shows a snackbar without crashing.
AC-5. Unknown/malformed structured payload renders `UnsupportedCell` (no crash,
no empty bubble) and opens a fallback detail.
AC-6. Times render in device locale/timezone; all-day events render without a
clock component.
AC-7. No new permissions added; no event payload content appears in telemetry or
release logs.

## 15. Definition of Done

- [ ] `CalendarEventContent`/`CalendarShareContent`/`Unsupported` added to
  `MessageContent`; DTOs + Moshi polymorphic adapter registered; mappers cover
  missing/unknown fields.
- [ ] `CalendarEventCell`, `CalendarShareCell`, `UnsupportedCell` implemented and
  wired into `MessageCell` dispatch in `feature-messages`.
- [ ] Detail routes + `CalendarMessageDetailScreen` +
  `CalendarMessageDetailViewModel` (StateFlow UiState) added to the
  authenticated nav graph; reads from cache, falls back to idempotent GET.
- [ ] `ACTION_INSERT` hand-off with resolver guard + snackbar fallback.
- [ ] All user-facing strings in `strings.xml`; cells/buttons meet 48dp + have
  contentDescriptions; RTL + font-scaling verified.
- [ ] Telemetry events emitted with redacted payloads (AND-052 policy).
- [ ] Unit, ViewModel, and Compose/Espresso-Intents tests pass in CI
  (AND-050/AND-051); ktlint/detekt clean (AND-005).
- [ ] DTO field names reconciled against `/openapi.json` and web types; PR
  description notes any deviation and the AND-037 migration follow-up.
- [ ] Code reviewed and merged to `android-port`.

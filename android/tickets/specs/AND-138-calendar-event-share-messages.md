---
id: AND-138
title: Calendar event / share messages
milestone: M3
epic: E19
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
the backend delivers a message whose `kind` is `calendar_event` or
`calendar_share`, the current client renders it as an empty or raw-JSON bubble.

> CORRECTION (review 2026-06-06): the wire discriminator is the top-level
> `kind` enum on `MessageOut`, NOT a `type` field, and the payload is a flat
> sibling object (`calendar_event` / `calendar_share`), NOT a Moshi-polymorphic
> `content` union. See §5 and §16. References to `type ==` below are corrected
> to `kind ==`.

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

FR-1. The thread list MUST render a message whose `kind == "calendar_event"`
using `CalendarEventCell`, showing the event `name`, formatted start–end time
(localized, timezone-aware) derived from `start_utc`/`end_utc`, and the event
`description` (if present).

> CORRECTION (review 2026-06-06): the `calendar_event` attachment
> (`CalendarEventAttachment` in `src/api/types.ts`) carries `event_id`,
> `calendar_id`, `name`, `start_utc?`, `end_utc?`, `all_day`, `all_day_date?`,
> `timezone`, `description?`, `owner`. There is NO `title`, NO `location`, and
> NO `rsvp` field. The original "title", "location", and "RSVP chip" claims are
> removed: the web client renders none of them. Use `name` (not `title`); drop
> the RSVP chip from required scope (no source for RSVP state on this payload).

FR-2. The thread list MUST render a message whose `kind == "calendar_share"`
using `CalendarShareCell`, showing the calendar `name` and a permission badge
(`read`/`write`, surfaced as "View only" / "View + Edit" per the web client).

> CORRECTION (review 2026-06-06): the `calendar_share` attachment
> (`CalendarShareAttachment`) carries `calendar_id`, `name`, `owner`,
> `permission: "read" | "write"`, `booking_link_id?`, `booking_public_url?`.
> Permission values are `read`/`write` (NOT `viewer`/`editor`); the web card
> labels them "View only"/"View + Edit". There is NO `color` field. The `owner`
> field exists but the web card does not display it; showing it is OPTIONAL and
> not a verified requirement.

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

// CORRECTED 2026-06-06 to match CalendarEventAttachment (src/api/types.ts).
// start_utc/end_utc are RFC-3339 strings and OPTIONAL on the wire; all_day_date
// is a separate date-only string used for all-day events. No title/location/rsvp.
data class CalendarEventPayload(
    val eventId: String,            // event_id
    val calendarId: String,         // calendar_id (needed for detail/ical links)
    val name: String,               // name (NOT "title")
    val startUtc: Instant?,         // start_utc (optional)
    val endUtc: Instant?,           // end_utc (optional)
    val allDay: Boolean,            // all_day
    val allDayDate: LocalDate?,     // all_day_date (date-only, for all-day events)
    val timezone: String,           // timezone (IANA tz; required on the wire)
    val description: String?,       // description (optional)
    val owner: String,              // owner
)

// CORRECTED 2026-06-06 to match CalendarShareAttachment (src/api/types.ts).
data class CalendarSharePayload(
    val calendarId: String,            // calendar_id
    val name: String,                  // name (NOT "calendar_name")
    val owner: String,                 // owner (web card omits it; OPTIONAL to show)
    val permission: SharePermission,   // READ | WRITE | UNKNOWN
    val bookingLinkId: String?,        // booking_link_id (optional)
    val bookingPublicUrl: String?,     // booking_public_url (optional)
)

// CORRECTED 2026-06-06: wire enum is "read" | "write" (NOT viewer/editor).
enum class SharePermission { READ, WRITE, UNKNOWN }
```

> CORRECTION (review 2026-06-06): removed `RsvpStatus`/`rsvp` (no source field),
> removed `location` and `color` (no source fields), renamed `title`→`name`,
> `calendar_name`→`name`, `ownerDisplayName`→`owner`, `startAt`→`startUtc` /
> `endAt`→`endUtc` (wire is `start_utc`/`end_utc`, both optional), made
> `timezone` non-null (required on the wire), and added `all_day_date`,
> `calendar_id` (event), `owner`, `booking_link_id`, `booking_public_url`.

`Instant` from `java.time` (desugaring already enabled for minSdk 24 per
AND-001/AND-002; confirm `coreLibraryDesugaringEnabled = true`).

### 4.2 Serialization (core-network)

> CORRECTION (review 2026-06-06): the wire is NOT a discriminated polymorphic
> `content` object. `MessageOut` is a FLAT object with a top-level `kind` enum
> and per-kind sibling fields (`text`, `calendar_event`, `calendar_share`,
> `countdown_title`/`target_datetime`, …), each optional. The clean Android
> approach is therefore a single `MessageDto` with all optional payload fields
> plus `kind`, and a mapper that switches on `kind` to build the `MessageContent`
> sealed type (the `PolymorphicJsonAdapterFactory` snippet below does NOT apply
> to this backend and should be treated as illustrative only — map by `kind` in
> `MessageMappers.kt` instead). The sealed `MessageContent` domain type is still
> the right model; only the deserialization mechanism changes. Defaults to
> `Unsupported` for unrecognized `kind` values.

Original (illustrative, superseded) polymorphic-adapter sketch keyed on a wire
discriminator:

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
// CORRECTED 2026-06-06: use p.name (no title), no location extra (no source
// field), use startUtc/endUtc (both nullable). For all-day events derive the
// begin time from all_day_date at local midnight.
fun buildInsertEventIntent(p: CalendarEventPayload): Intent =
    Intent(Intent.ACTION_INSERT).apply {
        data = CalendarContract.Events.CONTENT_URI
        putExtra(CalendarContract.Events.TITLE, p.name)
        p.description?.let { putExtra(CalendarContract.Events.DESCRIPTION, it) }
        putExtra(CalendarContract.EXTRA_EVENT_ALL_DAY, p.allDay)
        val begin: Long? = when {
            p.allDay && p.allDayDate != null ->
                p.allDayDate.atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli()
            else -> p.startUtc?.toEpochMilli()
        }
        begin?.let { putExtra(CalendarContract.EXTRA_EVENT_BEGIN_TIME, it) }
        val end: Long? = (p.endUtc ?: p.startUtc)?.toEpochMilli()
        end?.let { putExtra(CalendarContract.EXTRA_EVENT_END_TIME, it) }
    }
```

Launched via `rememberLauncherForActivityResult` /
`context.startActivity` guarded by `intent.resolveActivity(packageManager)`.
No `READ/WRITE_CALENDAR` permission is requested — `ACTION_INSERT` opens the
calendar app's own UI and requires no manifest permission.

## 5. API Contract

This ticket adds **no new endpoints**. Calendar-event and calendar-share
payloads arrive inline (as flat sibling objects on each message) from the
existing thread-history endpoint owned by AND-123:

`GET /messaging/conversations/{conversation_id}/messages`
(query params: `limit`, `before`; auth: `authorization` Bearer + `X-SESSION-ID`
+ `X-API-Key`; resp 200, plus 400/401/403/422/429).

> CORRECTION (review 2026-06-06): the path is
> `/messaging/conversations/{conversation_id}/messages` — NOT
> `/conversations/{id}/messages`. Verified at OpenAPI
> `GET /messaging/conversations/{conversation_id}/messages`
> (op=list_messages…). The web client (`src/api/endpoints/messaging.ts:
> getMessages`) calls this same path with a `cursor` query param and tolerates
> BOTH response envelopes: a bare `Message[]` array OR
> `{ messages: Message[], next_cursor?: string }` (see `adaptMessage` /
> `messagingAdapter.ts`). OpenAPI advertises a `before` param; the web uses
> `cursor`. Android paging MUST handle both response envelopes; treat the
> pagination param as an open assumption (§16) and confirm `before` vs `cursor`
> against the live backend.

Each `MessageOut` is a FLAT object with a top-level `kind` discriminator and
per-kind sibling payload objects. Required fields: `conversation_id`,
`message_id`, `sender_id`, `created_at`, `kind`. Note `created_at` (and other
timestamps) are **integer epoch** values, not RFC-3339 strings. Representative
item shapes (field names per `CalendarEventAttachment` /
`CalendarShareAttachment` in `src/api/types.ts`):

```json
{
  "message_id": "msg_01HZX...",
  "conversation_id": "conv_7Q...",
  "sender_id": "usr_42",
  "created_at": 1749134400,
  "kind": "calendar_event",
  "text": "see you there",
  "calendar_event": {
    "event_id": "evt_91",
    "calendar_id": "cal_55",
    "name": "Sprint review",
    "start_utc": "2026-06-10T17:00:00Z",
    "end_utc": "2026-06-10T18:00:00Z",
    "all_day": false,
    "all_day_date": null,
    "timezone": "America/New_York",
    "description": "Demo + retro",
    "owner": "usr_42"
  }
}
```

```json
{
  "message_id": "msg_01HZY...",
  "conversation_id": "conv_7Q...",
  "sender_id": "usr_42",
  "created_at": 1749136200,
  "kind": "calendar_share",
  "calendar_share": {
    "calendar_id": "cal_55",
    "name": "Team On-call",
    "owner": "Dana Ruiz",
    "permission": "read",
    "booking_link_id": null,
    "booking_public_url": null
  }
}
```

> CORRECTION (review 2026-06-06): the OpenAPI `MessageOut` schema declares
> `calendar_event` and `calendar_share` as free-form objects
> (`additionalProperties: true`) — their internal field names are NOT formalized
> in OpenAPI, so the field names above are taken from the FRONTEND contract
> (`src/api/types.ts`), which is authoritative for the wire shape and matches
> what `MessageBubble.tsx` reads (`ev.name`, `ev.start_utc`, `ev.all_day`,
> `ev.all_day_date`, `share.name`, `share.permission`, `share.booking_public_url`).
> The composer (`CreateCalendarEventMessageIn` / `CreateCalendarShareMessageIn`)
> sends only references (`calendar_id` + `event_id` for events; `calendar_id` +
> `permission` for shares); the server hydrates the attachment fields above.

There is **NO per-message GET endpoint** (`GET .../messages/{message_id}`
returning a `MessageOut` does not exist — verified against the OpenAPI index).
For a cold deep-link the detail screen therefore CANNOT "refresh a single
message"; the only options are (a) re-page the thread list to locate the message,
or (b) for calendar-event details, fetch the canonical event via the public
event endpoint `GET /calendar/public/event/{calendar_id}/{event_id}` (and its
`/ical` sibling for download). Either GET is idempotent and uses the
bounded-backoff retry policy from AND-016 with a ~20s timeout. Error `detail` is
mapped per AND-015 (`string | [{msg}] | {code,...}`) — verified against
`src/api/client.ts: normalizeErrorDetail`.

All requests ride the authenticated transport: cookie session
(`credentials: include`) + `Authorization: Bearer` + `X-CSRF-Token` (from the
`ui_csrf` cookie) — verified in `src/api/client.ts`. A 401 triggers a single
`POST /ui/session/refresh` + retry via the AND-013 authenticator. (Native
Android equivalents of `X-SESSION-ID`/`X-API-Key` are inherited from
core-network and out of this ticket's scope.)

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
  absent (deep-link cold start) does it fall back to the network. Because there
  is no per-message GET (see §5 CORRECTION), the cold-deep-link fallback must
  re-page the thread list to locate the message (or, for calendar-event detail,
  fetch the canonical event via `GET /calendar/public/event/{calendar_id}/{event_id}`).
  Stale-cache reads render immediately with an "offline/stale" indicator per
  AND-021/AND-045.
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
  e.g. "Calendar event, Sprint review, June 10 5 to 6 PM. Double tap to open."
  (No RSVP — not in the payload.) The share permission badge includes text, not
  color alone.
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
- Moshi/mapper: parse a `MessageOut` with `kind == "calendar_event"` and
  `kind == "calendar_share"` JSON → correct domain; unknown `kind` →
  `Unsupported`; missing `start_utc`/`end_utc` and all-day (`all_day_date`)
  handled; bad `permission` enum → `UNKNOWN`; `created_at` integer epoch and
  `start_utc`/`end_utc` RFC-3339 → `Instant` parsing.
- `buildInsertEventIntent` populates extras correctly, including all-day flag
  (begin from `all_day_date` at local midnight) and `endUtc ?: startUtc`
  fallback; no location extra is set.

ViewModel (core-testing + coroutines test):
- `CalendarMessageDetailViewModel` emits `EventReady`/`ShareReady` from cache;
  `Error(retryable=true)` on cold-deep-link network failure; `Unsupported` path.

Compose UI tests (AND-048/AND-049 harness, instrumented):
- `CalendarEventCell` shows `name` + formatted time (no RSVP chip — not in the
  payload); tapping invokes `onOpenDetail`. `CalendarShareCell` shows `name` +
  permission badge ("View only"/"View + Edit").
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
- R4 (RSVP semantics): RESOLVED by review — there is no `rsvp` field on the
  `calendar_event` attachment (verified `src/api/types.ts`). RSVP rendering is
  dropped from scope; if RSVP is added server-side later it is a follow-up.
- R5 (all-day off-by-one): DST/locale edge cases for `ACTION_INSERT` all-day
  extras; covered by unit tests but verify on a physical device.

## 14. Acceptance Criteria

AC-1. A message with `kind == "calendar_event"` renders a `CalendarEventCell`
showing `name`, localized start–end time (or all-day from `all_day_date`), and
`description` (if present) — verified by Compose UI test. (CORRECTED: was
"title/location/RSVP chip"; those fields do not exist on the payload.)
AC-2. A message with `kind == "calendar_share"` renders a `CalendarShareCell`
showing calendar `name` and the permission badge ("View only"/"View + Edit" for
`read`/`write`) — verified by Compose UI test. (CORRECTED: permission is
`read`/`write`, not viewer/editor; owner display is optional.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Thread-history endpoint is `GET /messaging/conversations/{conversation_id}/messages`.**
   VERDICT: Corrected (spec originally said `GET /conversations/{id}/messages`).
   SOURCE: OpenAPI `GET /messaging/conversations/{conversation_id}/messages`
   (op=list_messages…; params=conversation_id,limit,before,authorization,X-SESSION-ID,X-API-Key);
   `src/api/endpoints/messaging.ts: getMessages`.

2. **Message discriminator field is top-level `kind` (enum), not `type`.**
   VERDICT: Corrected. SOURCE: OpenAPI schema `MessageOut.kind`
   (enum includes `calendar_event`, `calendar_share`); `src/api/types.ts: Message.kind`.

3. **`MessageOut` is a flat object with optional per-kind sibling payloads, NOT a
   polymorphic `content` union.** VERDICT: Corrected. SOURCE: OpenAPI
   `components.schemas.MessageOut` (flat properties incl. `calendar_event`,
   `calendar_share`, `text`, …; required=[conversation_id,message_id,sender_id,created_at,kind]);
   `src/api/types.ts: Message`.

4. **`created_at` (and message timestamps) are integer epoch, not RFC-3339 strings.**
   VERDICT: Corrected. SOURCE: OpenAPI `MessageOut.created_at` `type: integer`;
   `src/api/types.ts: Message.created_at: number`.

5. **`calendar_event` attachment fields: `event_id`, `calendar_id`, `name`,
   `start_utc?`, `end_utc?`, `all_day`, `all_day_date?`, `timezone`, `description?`,
   `owner`. No `title`, `location`, or `rsvp`.** VERDICT: Corrected (spec invented
   `title`, `location`, `rsvp`/`RsvpStatus`, and made `timezone` optional).
   SOURCE: `src/api/types.ts: CalendarEventAttachment`; rendering in
   `src/pages/messages/MessageBubble.tsx` (uses `ev.name`, `ev.start_utc`,
   `ev.all_day`, `ev.all_day_date`). NOTE: OpenAPI types this object as
   `additionalProperties: true` (free-form), so the frontend type is the
   authoritative field source.

6. **`calendar_share` attachment fields: `calendar_id`, `name`, `owner`,
   `permission` (`read`|`write`), `booking_link_id?`, `booking_public_url?`.
   No `calendar_name`, `owner_display_name`, or `color`.** VERDICT: Corrected
   (spec used `calendar_name`/`owner_display_name`/`color` and viewer/editor).
   SOURCE: `src/api/types.ts: CalendarShareAttachment`;
   `src/pages/messages/MessageBubble.tsx` (calendar-share card).

7. **Share `permission` enum is `read`/`write`, surfaced as "View only" /
   "View + Edit" — NOT viewer/editor.** VERDICT: Corrected. SOURCE:
   `CreateCalendarShareMessageIn.permission` enum `["read","write"]` (OpenAPI);
   `src/api/types.ts: CalendarShareAttachment.permission`;
   `MessageBubble.tsx` ("View + Edit"/"View only" labels).

8. **Composer create endpoints exist and send references only:**
   `POST .../messages/calendar-event` (`CreateCalendarEventMessageIn`:
   `calendar_id`,`event_id`,`send_at?`,`text?`) and `.../messages/calendar-share`
   (`CreateCalendarShareMessageIn`: `calendar_id`,`permission` default `read`,
   `include_booking_link` default false,`send_at?`,`text?`). VERDICT: Verified
   (informational — authoring is out of scope). SOURCE: OpenAPI ops
   create_calendar_event_message / create_calendar_share_message; schemas
   `CreateCalendarEventMessageIn`, `CreateCalendarShareMessageIn`;
   `src/api/endpoints/messaging.ts: sendCalendarEventMessage / sendCalendarShareMessage`.

9. **There is NO per-message GET endpoint returning a `MessageOut`.** VERDICT:
   Corrected (spec assumed an "idempotent GET refresh of the single message").
   SOURCE: OpenAPI index — only sub-resource GETs exist under
   `.../messages/{message_id}/` (attachment, edits, reactions/details, views);
   no bare `GET .../messages/{message_id}`.

10. **Per-event detail/iCal endpoints exist:**
    `GET /calendar/public/event/{calendar_id}/{event_id}` and
    `GET /calendar/public/event/{calendar_id}/{event_id}/ical`. VERDICT: Verified.
    SOURCE: OpenAPI ops get_public_event / download_public_ical; the web event
    card links to `/event/{calendar_id}/{event_id}` and the `.../ical` download
    (`MessageBubble.tsx`).

11. **List response envelope is polymorphic: bare `Message[]` OR
    `{messages, next_cursor}`; web uses `cursor` param while OpenAPI advertises
    `before`.** VERDICT: Verified (web) / Unverified-assumption (which param the
    backend honors). SOURCE: `src/api/endpoints/messaging.ts: getMessages`
    (handles both shapes, sends `cursor`); OpenAPI index params `limit,before`.

12. **Auth transport: cookie session + `Authorization: Bearer` + `X-CSRF-Token`
    (from `ui_csrf` cookie); single `POST /ui/session/refresh` retry on 401.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (`credentials: "include"`,
    `Authorization: Bearer`, `X-CSRF-Token` from `getCookie("ui_csrf")`, 401 →
    `/ui/session/refresh` once).

13. **Error `detail` shape is `string | [{msg}] | {code,...}`.** VERDICT: Verified.
    SOURCE: `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError`;
    OpenAPI `HTTPValidationError` (422) for the array-of-`{msg}` form.

14. **`ACTION_INSERT` against `CalendarContract.Events.CONTENT_URI` needs no
    READ/WRITE_CALENDAR permission.** VERDICT: Verified (framework ref).
    SOURCE: Android docs — CalendarContract "Inserting an event using an intent"
    (`https://developer.android.com/guide/topics/providers/calendar-provider#intent-insert`):
    `ACTION_INSERT` launches the calendar app's own UI and requires no permission.

15. **`EXTRA_EVENT_ALL_DAY` / `EXTRA_EVENT_BEGIN_TIME` / `EXTRA_EVENT_END_TIME`
    extras for the insert intent.** VERDICT: Verified (framework ref). SOURCE:
    Android `CalendarContract` reference
    (`https://developer.android.com/reference/android/provider/CalendarContract`).

16. **`java.time` (`Instant`/`LocalDate`/`ZoneId`) usable on minSdk 24 via core
    library desugaring.** VERDICT: Verified (framework ref). SOURCE: Android
    desugaring docs
    (`https://developer.android.com/studio/write/java8-support-table`).

17. **Compose/Espresso-Intents (`intended(hasAction(...))`) for intent
    verification; Espresso for navigation assertions.** VERDICT: Verified
    (framework ref). SOURCE: AndroidX Espresso-Intents docs
    (`https://developer.android.com/training/testing/espresso/intents`).

### Corrections made

- Endpoint path corrected to `/messaging/conversations/{conversation_id}/messages`
  (§5).
- Discriminator corrected from `type` to top-level `kind`; payload model
  corrected from a polymorphic `content` union to flat sibling objects (§1, §4.2,
  §5).
- `calendar_event` payload corrected: `name` (not `title`); `start_utc`/`end_utc`
  (not `start_at`/`end_at`, both optional); `timezone` required; added
  `all_day_date`, `calendar_id`, `owner`; removed `location` and `rsvp`/`RsvpStatus`
  (§3 FR-1, §4.1, §4.5, §9, §11, AC-1).
- `calendar_share` payload corrected: `name` (not `calendar_name`), `owner` (not
  `owner_display_name`); permission enum `read`/`write` (not viewer/editor) shown
  as "View only"/"View + Edit"; removed `color`; added `booking_link_id` /
  `booking_public_url` (§3 FR-2, §4.1, AC-2).
- `created_at` documented as integer epoch (§5).
- "Idempotent GET refresh of the single message" removed — no per-message GET
  exists; cold-deep-link fallback re-pages the thread or uses the public event
  endpoint (§5, §6).
- `buildInsertEventIntent` updated to `name`, drop location extra, all-day begin
  from `all_day_date`, `endUtc ?: startUtc` (§4.5).
- R4 (RSVP) marked RESOLVED — no RSVP field exists (§13).

### Open assumptions

- **Pagination parameter (`before` vs `cursor`).** OpenAPI lists `limit`/`before`;
  the web client sends `cursor` and reads `next_cursor`. Which the live backend
  honors is unconfirmed from static sources; Android must verify against the dev
  backend and handle both. (Why unverifiable: index/web disagree, no runtime
  access here.)
- **List response envelope.** The web tolerates both a bare array and
  `{messages,next_cursor}`; the OpenAPI 200 response body is untyped (empty
  `resp=200:`), so the canonical envelope is unconfirmed. Android must tolerate
  both.
- **Exact internal field names of `calendar_event`/`calendar_share` per OpenAPI.**
  Typed only as `additionalProperties: true`; field names are taken from the
  frontend contract and MUST be re-confirmed against a live payload before merge.
- **`X-SESSION-ID` / `X-API-Key` native handling.** Present as OpenAPI params but
  managed by core-network (AND-013); their exact Android wiring is out of this
  ticket's scope and inherited.
- **All-day timezone semantics for `ACTION_INSERT`.** Whether `all_day_date`
  should anchor at device-local midnight vs the event `timezone` for the insert
  begin-time extra is a known DST/off-by-one edge (R5); verify on a physical
  device (TC-AND-138-12).

## 17. Test Plan

Acceptance criteria referenced are §14 AC-1..AC-7. Targets: JVM = local
JVM/Robolectric unit; Emu = headless AVD `test35` (x86_64, API 35); Device =
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). MockWebServer is
used for contract tests; Espresso-Intents for intent assertions.

- **TC-AND-138-01** — Parse calendar_event MessageOut (happy path).
  Type: unit (JVM). Target: `MessageMappers` / Moshi in core-network.
  Preconditions: fixture JSON with `kind:"calendar_event"` and a full
  `calendar_event` object (name, start_utc, end_utc, all_day:false, timezone,
  description, owner, calendar_id, event_id). Steps: deserialize to `MessageOut`
  DTO, map to `MessageContent.CalendarEventContent`. Expected: all fields mapped;
  `startUtc`/`endUtc` parsed to `Instant`; `name` (not title) populated; no
  location/rsvp fields. Traces: AC-1.

- **TC-AND-138-02** — Parse calendar_share MessageOut (happy path + permission
  mapping). Type: unit (JVM). Target: `MessageMappers`. Preconditions: fixture
  with `kind:"calendar_share"`, `permission:"write"`, booking_public_url set.
  Steps: deserialize → map. Expected: `SharePermission.WRITE`; `name`/`owner`
  populated; bookingPublicUrl preserved. Traces: AC-2.

- **TC-AND-138-03** — Unknown `kind` and malformed payload degrade to Unsupported.
  Type: unit (JVM). Target: `MessageMappers`. Preconditions: (a) fixture with
  `kind:"hologram"`; (b) `kind:"calendar_event"` but `calendar_event` missing/null.
  Steps: map each. Expected: both yield `MessageContent.Unsupported(rawType=…)`;
  no exception thrown. Traces: AC-5.

- **TC-AND-138-04** — Optional/edge fields: missing end_utc, all-day event, bad
  permission enum. Type: unit (JVM). Target: `MessageMappers`. Preconditions:
  fixtures: (a) event with `start_utc` only, no `end_utc`; (b) `all_day:true` with
  `all_day_date` and null start/end; (c) share with `permission:"owner"`. Steps:
  map. Expected: (a) endUtc null; (b) allDay true, allDayDate parsed; (c)
  `SharePermission.UNKNOWN`. Traces: AC-1, AC-2, AC-6.

- **TC-AND-138-05** — `buildInsertEventIntent` extras. Type: unit (JVM/Robolectric).
  Target: `buildInsertEventIntent`. Preconditions: timed event payload and an
  all-day payload. Steps: build intent for each. Expected: action ACTION_INSERT,
  data = Events.CONTENT_URI, TITLE = `name`, DESCRIPTION set when present, NO
  EVENT_LOCATION extra; timed: BEGIN = startUtc epoch, END = endUtc epoch; all-day:
  EXTRA_EVENT_ALL_DAY true and BEGIN derived from `all_day_date` at local midnight;
  `endUtc ?: startUtc` fallback when end absent. Traces: AC-4, AC-6.

- **TC-AND-138-06** — Contract: list endpoint path, kind dispatch, both envelopes.
  Type: contract/MockWebServer (JVM/Robolectric). Target: messages repository /
  Retrofit service. Preconditions: MockWebServer enqueues (a)
  `{messages:[...],next_cursor:"c2"}` and (b) a bare `[...]` array, each mixing
  text + calendar_event + calendar_share + unknown kind. Steps: call repository
  `getMessages`. Expected: request path is
  `/messaging/conversations/{id}/messages`; both envelopes parse; messages map to
  the correct `MessageContent` subtypes in order. Traces: AC-1, AC-2, AC-5.

- **TC-AND-138-07** — Contract: error `detail` shapes + 401 refresh. Type:
  contract/MockWebServer (JVM/Robolectric). Target: network error mapping +
  authenticator. Preconditions: MockWebServer returns (a) 422 with
  `{detail:[{msg:"bad"}]}`, (b) 400 with `{detail:"nope"}`, (c) 401 then (after
  `/ui/session/refresh`) 200. Steps: invoke `getMessages`/detail fetch. Expected:
  (a)/(b) mapped to readable error per AND-015; (c) exactly one refresh + retry
  succeeds. Traces: AC-1, AC-2 (resilience), AC-7 (no payload leaked on error).

- **TC-AND-138-08** — ViewModel emits Ready/Unsupported/Error states. Type: unit
  (JVM, coroutines-test). Target: `CalendarMessageDetailViewModel`. Preconditions:
  fake repo returning cached event, cached share, unsupported, and (cold deep-link)
  a network failure. Steps: construct VM with each SavedStateHandle arg set.
  Expected: `EventReady` / `ShareReady` / `Unsupported` / `Error(retryable=true)`
  respectively. Traces: AC-3, AC-5.

- **TC-AND-138-09** — Compose-UI: cells render correct fields and are tappable.
  Type: Compose-UI (instrumented, Emu test35). Target: `CalendarEventCell`,
  `CalendarShareCell`. Preconditions: supply event payload (name+time+description)
  and share payload (name + permission write). Steps: render; assert text; perform
  click. Expected: event cell shows `name`, formatted start–end, description, NO
  RSVP chip; share cell shows `name` + "View + Edit"; click invokes `onOpenDetail`.
  Traces: AC-1, AC-2, AC-3.

- **TC-AND-138-10** — Compose-UI: thread renders mixed message kinds in order;
  unknown kind shows UnsupportedCell (no empty bubble). Type: Compose-UI +
  MockWebServer (instrumented, Emu test35). Target: thread `LazyColumn` /
  `MessageCell`. Preconditions: MockWebServer fixture mixing text, calendar_event,
  calendar_share, and an unknown kind. Steps: load thread. Expected: each row
  renders its correct cell in order; unknown kind renders `UnsupportedCell`, never
  empty, no crash. Traces: AC-1, AC-2, AC-5.

- **TC-AND-138-11** — Espresso-Intents: "Add to calendar" launches ACTION_INSERT;
  no-resolver path shows snackbar. Type: instrumented/e2e (Emu test35). Target:
  `CalendarMessageDetailScreen` add-to-calendar action. Preconditions: (a) stub a
  resolver for ACTION_INSERT via `intending`; (b) no-resolver variant.
  Steps: open event detail, tap "Add to calendar". Expected: (a)
  `intended(allOf(hasAction(ACTION_INSERT), hasData(Events.CONTENT_URI)))`; (b)
  snackbar "No calendar app available", no crash. Traces: AC-4.

- **TC-AND-138-12** — Physical-device: real "Add to calendar" hand-off + all-day
  DST correctness. Type: instrumented/e2e (Device — MUST run on physical A15).
  Target: ACTION_INSERT hand-off to a real installed calendar app. Preconditions:
  Samsung/Google Calendar installed; (a) timed event near a DST boundary; (b)
  all-day event. Steps: tap "Add to calendar"; in the opened calendar app inspect
  prefilled date/time. Expected: real calendar app opens with correct title and
  date/time; all-day event shows the correct single day with no clock and no
  off-by-one across DST (R5); arm64/API-34 path verified vs emulator. MUST be
  device because it exercises a real third-party calendar app + device locale/tz.
  Traces: AC-4, AC-6.

- **TC-AND-138-13** — Cold deep-link detail with no per-message GET (offline /
  flaky host). Type: integration + MockWebServer (instrumented, Emu test35).
  Target: `CalendarMessageDetailViewModel` cold-start fallback. Preconditions:
  empty cache; MockWebServer (a) serves the thread page containing the target
  message after retry delay (flaky-host), (b) returns errors → offline. Steps:
  deep-link into detail by messageId. Expected: (a) message located by re-paging
  (NOT by a `messages/{id}` GET — assert no such request is made) and rendered;
  (b) offline state shown, Retry works. Traces: AC-3, AC-5.

- **TC-AND-138-14** — Security/telemetry: no payload content in logs/analytics; no
  new permissions. Type: unit + manual (JVM for telemetry, manual manifest review).
  Target: telemetry wrapper + AndroidManifest. Preconditions: render + open detail
  + tap add-to-calendar with a fake analytics sink. Steps: capture emitted events;
  inspect merged manifest. Expected: events carry only enums/booleans
  (`kind`,`hasLocation` etc.) — no `name`/description/ids; no
  READ_CALENDAR/WRITE_CALENDAR (or any new) permission in the merged manifest.
  Traces: AC-7.

- **TC-AND-138-15** — Accessibility: contentDescription, 48dp targets, font
  scaling, RTL. Type: Compose-UI/instrumented (Emu test35). Target: cells +
  detail buttons. Preconditions: enable large font scale and RTL pseudo-locale.
  Steps: render cells/detail; assert semantics and touch-target size. Expected:
  each cell exposes a single merged contentDescription (no RSVP text); permission
  badge announced by text not color; all interactive targets ≥ 48dp; title not
  truncated at large font scale; layout mirrors correctly in RTL. Traces: AC-1,
  AC-2, AC-3, AC-4.

### Coverage matrix

| AC | Covered by |
|----|-----------|
| AC-1 (event cell renders correct fields) | TC-01, TC-04, TC-06, TC-09, TC-10, TC-15 |
| AC-2 (share cell renders name + permission) | TC-02, TC-04, TC-06, TC-09, TC-10, TC-15 |
| AC-3 (tap → detail screen) | TC-08, TC-09, TC-13, TC-15 |
| AC-4 (Add to calendar ACTION_INSERT + snackbar) | TC-05, TC-11, TC-12, TC-15 |
| AC-5 (unknown/malformed → UnsupportedCell) | TC-03, TC-06, TC-08, TC-10, TC-13 |
| AC-6 (locale/timezone; all-day no clock) | TC-04, TC-05, TC-12 |
| AC-7 (no new permissions; no payload in telemetry/logs) | TC-07, TC-14 |

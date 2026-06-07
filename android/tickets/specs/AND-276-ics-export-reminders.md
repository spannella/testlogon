---
id: AND-276
title: ICS export / reminders
milestone: M6
epic: E37
priority: P2
size: M
depends_on: [AND-272]
blocks: [AND-277]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-276 — ICS export / reminders

## 1. Overview & Goal

Add two complementary, on-device capabilities to the calendar feature module of
the TestLogon native Android app: (1) **ICS export** — generate an RFC 5545
`text/calendar` document for one or more calendar events and hand it to the OS via
a standard share/save sheet; and (2) **local reminders** — schedule a device-local
notification ahead of an event's start so the user is alerted even when the app is
backgrounded or closed.

Both features operate primarily on data already loaded by the Event Detail screen
(AND-272). ICS export is a pure client-side serialization of event fields — it does
not require any new backend endpoint. Reminders are scheduled with `AlarmManager`
(exact, allow-while-idle) and surfaced through a `NotificationChannel`; they survive
process death and device reboot. Neither feature touches authentication beyond the
event read that already happened upstream.

Success means: a user on an event detail screen can tap "Add reminder", pick a lead
time, and reliably receive a notification at the computed trigger time; and can tap
"Export .ics" to produce a valid calendar file that imports cleanly into Google
Calendar, Apple Calendar, and Outlook.

## 2. Context & References

- **Upstream data source:** AND-272 (Event detail (+ public event)) supplies the
  loaded `Event` domain model and the screen that hosts the two new actions.
  AND-270 (Calendar API + DTOs) and AND-271 (Calendar views) define event/recurrence
  DTOs and timezone handling that this ticket reuses verbatim — we do not redefine
  event parsing here.
- **Module placement:** `feature-calendar` (UI + ViewModel actions, reminder
  scheduling glue) and `core-data` (ICS serializer, reminder persistence). No new
  module.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Room 2.6 (reminder records), DataStore (default lead-time pref). minSdk 24,
  targetSdk 35, JDK 17.
- **Web reference:** `frontend/src/api/endpoints/calendar.ts` and
  `frontend/src/api/types.ts` for the canonical event field set; the web app's ICS
  export (if present) is reference-only — Android uses a Kotlin serializer.
- **Platform docs:** RFC 5545 (iCalendar), Android exact-alarm and notification
  runtime-permission models (`SCHEDULE_EXACT_ALARM` / `USE_EXACT_ALARM`,
  `POST_NOTIFICATIONS` on API 33+).
- **Package base:** `com.testlogon.android` everywhere.

## 3. Functional Requirements

FR-1. From the Event Detail screen (AND-272), the user can trigger **Export .ics**
for the currently displayed event. The app builds a VCALENDAR/VEVENT document and
launches `ACTION_SEND` (share) with MIME `text/calendar`, plus an explicit "Save to
files" affordance via `ACTION_CREATE_DOCUMENT`.

FR-2. The exported VEVENT includes, at minimum: `UID`, `DTSTAMP`, `DTSTART`,
`DTEND` (or `DURATION`), `SUMMARY`, `DESCRIPTION`, `URL` (the public
event App Link from AND-272), and `STATUS`. All-day events emit `DTSTART;VALUE=DATE`.
Recurring events emit an `RRULE` derived from the event's recurrence DTO.

> CORRECTION (review): `SUMMARY` is sourced from `CalendarEvent.name` (not a
> `summary`/`title` field — see `src/api/types.ts: CalendarEvent`). `LOCATION` was
> removed from the required set: neither `CalendarEvent` nor `CalendarEventAttachment`
> exposes a location field in the verified DTOs, so `LOCATION` MUST NOT be emitted
> from event data. If a location is ever added upstream, emit it then; until then it
> is omitted (not emitted empty). `STATUS` maps from `CalendarEvent.status` (a free
> string in the DTO; the serializer normalizes to `CONFIRMED`/`TENTATIVE`/`CANCELLED`).

FR-3. ICS text values are escaped per RFC 5545 (`\` `;` `,` `\n` rules) and lines
are folded at 75 octets. Timestamps are emitted in UTC (`...Z`) unless the event is
all-day or carries an explicit IANA `TZID`, in which case a matching `VTIMEZONE`
block is emitted.

FR-4. From Event Detail, the user can **Add reminder** by selecting a lead time
(presets: at start, 5m, 15m, 30m, 1h, 1 day; plus a custom picker). The default
preset is read from DataStore and persists across sessions.

FR-5. A scheduled reminder fires a notification at `event.start − leadTime`. The
notification shows the event title, formatted start time, and a deep-link
`PendingIntent` opening Event Detail for that event. Tapping it navigates to the
event.

FR-6. The user can **view and cancel** an existing reminder from Event Detail; an
event may have at most one active reminder (re-adding replaces it). Reminders for
events whose start is already in the past are not scheduled (the action is disabled
with an explanatory caption).

FR-7. Reminders survive app process death and device reboot: on `BOOT_COMPLETED`
the app re-arms all future reminders from the Room store.

FR-8. On API 33+, adding a reminder requests `POST_NOTIFICATIONS` if not granted;
on API 31+ exact alarms degrade gracefully to an inexact window if the user has not
granted exact-alarm permission (see §7).

## 4. Technical Design

### 4.1 ICS serialization (core-data)

```kotlin
package com.testlogon.android.core.data.ics

data class IcsEvent(
    val uid: String,
    val summary: String,
    val description: String?,
    val location: String?,
    val url: String?,                 // public App Link from AND-272
    val start: Instant,
    val end: Instant?,
    val allDay: Boolean,
    val timeZone: ZoneId?,            // null => emit UTC
    val rrule: String?,               // RRULE line value built by the mapper, e.g. "FREQ=WEEKLY;BYDAY=MO"
    val exdatesUtc: List<Instant> = emptyList(), // from CalendarEvent.exdates_utc -> EXDATE
    val status: IcsStatus = IcsStatus.CONFIRMED,
)

enum class IcsStatus { CONFIRMED, TENTATIVE, CANCELLED }

interface IcsSerializer {
    /** Returns a complete RFC 5545 VCALENDAR document (CRLF line endings). */
    fun serialize(events: List<IcsEvent>): String
}

@Singleton
class Rfc5545IcsSerializer @Inject constructor(
    @Named("appVersion") private val prodId: String,
) : IcsSerializer {
    override fun serialize(events: List<IcsEvent>): String { /* fold + escape */ }
}
```

A mapper `EventDetail.toIcsEvent(publicUrl: String): IcsEvent` lives in
`feature-calendar` and adapts the AND-272 domain model. NOTE (review): the upstream
`CalendarEvent` DTO does NOT carry a pre-built RRULE string — it exposes a structured
`recurrence_rule: RecurrenceRule { freq: DAILY|WEEKLY|MONTHLY, interval?, until_utc?,
count?, byday?, bymonthday?, bysetpos? }` plus `exdates_utc: string[]`. The mapper is
responsible for serializing that structure into an RFC 5545 `RRULE` value and the
`exdates_utc` list into one or more `EXDATE` lines (see `src/api/types.ts:
RecurrenceRule`). `start`/`end` map from `start_utc`/`end_utc` (ISO-8601);
`allDay`/all-day date map from `all_day`/`all_day_date`; `timeZone` from `timezone`.
The serializer emits CRLF
(`\r\n`), `PRODID:-//com.testlogon.android//TestLogon//EN`, `VERSION:2.0`,
`CALSCALE:GREGORIAN`, and one `VEVENT` per input. Line folding inserts CRLF + a
single space when a content line exceeds 75 octets (UTF-8 aware).

### 4.2 Export delivery (feature-calendar)

The ViewModel writes the document to app cache and exposes a sharable URI through a
`FileProvider` (`${applicationId}.fileprovider`, authority declared in the manifest;
`filepaths.xml` maps `cache/ics`). The UI launches the share sheet:

```kotlin
class IcsExporter @Inject constructor(@ApplicationContext private val ctx: Context) {
    fun writeToCache(fileName: String, ics: String): Uri
    fun shareIntent(uri: Uri): Intent           // ACTION_SEND, type text/calendar, grant read
}
```

`ACTION_CREATE_DOCUMENT` is driven from Compose via
`rememberLauncherForActivityResult(CreateDocument("text/calendar"))`; the resulting
`Uri` is written through `ContentResolver.openOutputStream`.

### 4.3 Reminder scheduling (core-data + feature-calendar)

```kotlin
package com.testlogon.android.core.data.reminder

@Entity(tableName = "event_reminders")
data class ReminderEntity(
    @PrimaryKey val eventId: String,
    val calendarId: String,
    val title: String,
    val eventStartEpochMs: Long,
    val leadMillis: Long,
    val triggerEpochMs: Long,         // eventStart - lead
    val createdEpochMs: Long,
)

interface ReminderRepository {
    suspend fun upsert(reminder: ReminderEntity)
    suspend fun cancel(eventId: String)
    fun observe(eventId: String): Flow<ReminderEntity?>
    suspend fun allFuture(now: Long): List<ReminderEntity>
}

class ReminderScheduler @Inject constructor(
    @ApplicationContext private val ctx: Context,
    private val alarmManager: AlarmManager,
) {
    fun schedule(reminder: ReminderEntity)      // setExactAndAllowWhileIdle or windowed fallback
    fun cancel(eventId: String)                 // cancels matching PendingIntent
}
```

The `PendingIntent` targets a `ReminderReceiver : BroadcastReceiver` (exported=false)
carrying `eventId`/`calendarId`/`title`/`triggerEpochMs` as extras; request code =
stable hash of `eventId` so re-scheduling replaces the prior alarm. On receipt the
receiver builds the notification on channel `reminders` and posts via
`NotificationManagerCompat`. The notification's content `PendingIntent` deep-links
to `testlogon://event/{calendarId}/{eventId}` handled by the single Activity / nav
host (consistent with the App Link route from AND-272).

A `BootReceiver : BroadcastReceiver` listening for `ACTION_BOOT_COMPLETED` and
`ACTION_MY_PACKAGE_REPLACED` enqueues a Hilt-injected coroutine that calls
`allFuture(now)` and re-arms each reminder.

### 4.4 ViewModel surface

```kotlin
data class ExportReminderUiState(
    val reminder: ReminderEntity? = null,
    val canSchedule: Boolean = true,        // false if event start in past
    val defaultLead: Duration = Duration.ofMinutes(30),
    val exportInProgress: Boolean = false,
    val message: UiMessage? = null,         // permission rationale / success / error
)

sealed interface ExportReminderEvent {
    data class Export(val mode: ExportMode) : ExportReminderEvent   // SHARE | SAVE
    data class AddReminder(val lead: Duration) : ExportReminderEvent
    data object CancelReminder : ExportReminderEvent
    data object PermissionDenied : ExportReminderEvent
}
```

Exposed as `StateFlow<ExportReminderUiState>` from a Hilt `@HiltViewModel` that is
either part of the existing Event Detail ViewModel or a sibling collaborator, keeping
the AND-272 screen the single host.

## 5. API Contract

No new backend HTTP endpoint. Both features are fully on-device:

- **ICS export** serializes data already fetched by AND-272 (which calls the calendar
  read endpoints owned by AND-270, e.g. `GET /ui/calendars/{calendar_id}/events/{event_id}`
  — note plural `calendars`; the web client's `getEvent` uses this path, returning
  `CalendarEvent`). This ticket performs no network I/O.
- **Server-side iCal already exists** (context only; this ticket deliberately serializes
  client-side for offline/share fidelity): `GET /ui/calendars/{calendar_id}/events/{event_id}/ical`
  (authenticated) and `GET /calendar/public/event/{calendar_id}/{event_id}/ical` (public).
  These return a server-rendered `.ics`; the Android serializer is intentionally
  independent so export works on already-loaded data without a network round-trip.
- **Reminders** use `AlarmManager` / `NotificationManager`; no server-side reminder
  state. (If server-synced reminders are ever required, that is a separate future
  ticket and out of scope here.)

The only "contract" is the **ICS document shape** produced. Representative output:

```
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//com.testlogon.android//TestLogon//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
UID:evt_8f12@testlogon.android
DTSTAMP:20260605T120000Z
DTSTART:20260610T150000Z
DTEND:20260610T160000Z
SUMMARY:Q3 Content Review
DESCRIPTION:Agenda\, notes and links
URL:http://18.222.237.167:8000/event/cal_1/evt_8f12
STATUS:CONFIRMED
END:VEVENT
END:VCALENDAR
```

All-day variant: `DTSTART;VALUE=DATE:20260610` / `DTEND;VALUE=DATE:20260611`.
Recurring variant adds e.g. `RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=8`. The `URL` value
reuses the public event App Link format established by AND-272 — verified against the
web router route `/event/:calendarId/:eventId` (see `src/App.tsx`), confirming the
`http://<host>/event/{calendarId}/{eventId}` shape used above. `SUMMARY` is the
event's `name` field (verified: `src/api/types.ts: CalendarEvent.name`); the example
omits `LOCATION` because no location field exists in the verified event DTOs.

## 6. Data & State Management

- **Room (`core-data`):** single table `event_reminders` (schema in §4.3). DAO
  methods: `upsert`, `deleteByEventId`, `observeByEventId`, `selectFutureTriggers`.
  Exposed only through `ReminderRepository`. Bump Room schema version; provide a
  migration (additive, new table → version N).
- **DataStore (Preferences):** key `calendar_default_reminder_lead_ms: Long`
  (default 1,800,000 = 30m). Read into `ExportReminderUiState.defaultLead`; updated
  when the user changes the preset.
- **ViewModel state:** `StateFlow<ExportReminderUiState>` derived by combining the
  reminder `Flow`, the loaded event (start-in-past check), and the DataStore pref.
- **No cache for ICS:** generated documents are written to `cacheDir/ics` and are
  disposable; the system may clear them. Saved-to-files documents leave the app
  sandbox via SAF and are the user's responsibility.
- **Transient files** are namespaced `event-{eventId}.ics` and overwritten on
  re-export.

## 7. Error Handling & Resilience

- **POST_NOTIFICATIONS (API 33+):** request at the moment of first "Add reminder".
  If denied, the reminder record is still saved and the alarm armed, but the UI
  surfaces `UiMessage` explaining the OS will suppress the notification until the
  permission is granted in Settings; provide a deep link to app notification settings.
- **Exact alarms (API 31+):** prefer `setExactAndAllowWhileIdle`. If
  `AlarmManager.canScheduleExactAlarms()` is false, fall back to
  `setWindow`/`setAndAllowWhileIdle` (inexact) and show a caption that the reminder
  may be delayed; offer an action launching `ACTION_REQUEST_SCHEDULE_EXACT_ALARM`.
  Manifest declares `USE_EXACT_ALARM` only if policy-eligible; otherwise
  `SCHEDULE_EXACT_ALARM` (user-grantable).
- **Past events:** `canSchedule=false` disables the action; if `event.start` passes
  while the screen is open, recompute and disable.
- **ICS serialization failures** (null required field) are guarded by builder
  validation; the export action shows a non-fatal error and logs the cause. Missing
  optional fields are simply omitted, never emitted empty.
- **FileProvider / SAF failures** (no output stream, revoked grant) surface a
  retryable error message; no crash.
- **Doze / battery optimization:** `allowWhileIdle` variants are used so reminders
  fire in Doze maintenance windows; we accept OEM-imposed delays for inexact mode
  and document them. No network, so backend timeout/backoff (the unreliable dev
  host) is not applicable to this ticket.

## 8. Security & Privacy

- All processing is local; no event content is transmitted by this feature. The
  upstream event fetch (AND-272) already enforces cookie + `X-CSRF-Token` auth.
- `FileProvider` grants are per-URI, read-only, and time-bound to the share intent;
  no broad external-storage permission is requested.
- `ReminderReceiver` and `BootReceiver` are `exported=false` (except `BootReceiver`
  which must be exported to receive `BOOT_COMPLETED` but is guarded by the
  `RECEIVE_BOOT_COMPLETED` permission and ignores unexpected actions).
- Notification content shows the event title only; sensitive descriptions are not
  placed in the notification body. Channel visibility defaults to private.
- ICS `UID` uses an opaque event id, not user PII. No credentials, cookies, or CSRF
  tokens are ever written to the ICS file or notification extras.

## 9. Accessibility & i18n

- Export and reminder buttons have `contentDescription`s ("Export event as .ics
  file", "Add reminder", "Cancel reminder"); state changes announced via
  `Modifier.semantics { liveRegion = Polite }`.
- Lead-time presets are exposed as a labelled radio/segmented control reachable by
  TalkBack; custom picker uses the platform time picker (already accessible).
- All user-facing strings (presets, rationale, errors, notification title/body
  template) live in `strings.xml`; reminder lead labels use plurals (`%d minutes`,
  `%d hours`, `%d days`).
- Timestamps in UI and notifications are formatted with the device locale and
  timezone via `java.time` + `DateTimeFormatter.ofLocalizedDateTime`. ICS itself is
  locale-independent (UTC or explicit TZID), satisfying interop regardless of device
  locale.
- Touch targets ≥ 48dp; presets meet Material 3 contrast.

## 10. Telemetry & Logging

- Structured debug logs (no PII) via the app's logger: `ics_export_started`,
  `ics_export_completed{events,bytes,mode}`, `ics_export_failed{reason}`,
  `reminder_scheduled{leadMs,exact}`, `reminder_fired{eventId}`,
  `reminder_cancelled`, `reminder_rearmed_on_boot{count}`,
  `notif_permission_result{granted}`, `exact_alarm_fallback`.
- Event ids may be logged only at debug level and hashed in any release-eligible
  log. No event titles/descriptions in logs.
- Counters useful for QA: number of reminders re-armed on boot, exact-vs-inexact
  scheduling ratio. No third-party analytics added by this ticket.

## 11. Testing Strategy

- **Unit (core-data):** `Rfc5545IcsSerializerTest` — golden-file assertions for
  timed, all-day, recurring, and special-character (escaping/folding) events;
  verify CRLF, 75-octet folding, UTC `Z` output, and `VTIMEZONE` emission for TZID
  events. Parse output back with `ical4j` (test-only dependency) to assert validity.
- **Unit (scheduler):** `ReminderSchedulerTest` using Robolectric +
  `ShadowAlarmManager` to assert an alarm is set at `start − lead`, replaced on
  re-add, and removed on cancel; verify exact vs windowed branch by toggling
  `canScheduleExactAlarms`.
- **Repository:** `ReminderRepositoryTest` with in-memory Room — upsert/cancel/
  observe and `allFuture(now)` filtering.
- **Receiver:** `BootReceiverTest` re-arms only future reminders;
  `ReminderReceiverTest` posts to channel `reminders` (Robolectric
  `NotificationManager` shadow) and builds the correct deep-link `PendingIntent`.
- **Compose UI (feature-calendar):** add-reminder flow toggles state and disables
  for past events; permission-denied path shows rationale; export buttons launch
  the expected intents (verified with `Intents`/Espresso-Intents in instrumented
  test).
- **Coverage gate** belongs to AND-277 (Calendar tests), which this ticket feeds;
  this ticket ships its own unit/UI tests green in CI (AND-050 pipeline).

## 12. Dependencies & Sequencing

- **Depends on AND-272** (Event detail (+ public event)) — provides the event
  domain model, the host screen, and the public App Link used for the ICS `URL`.
  Transitively relies on AND-270 (DTOs/recurrence) and AND-271 (timezone handling).
- **Feeds AND-277** (Calendar tests) — shared repo/UI test scope for
  timezone/recurrence will exercise the serializer and scheduler.
- **Reuses** AND-021 state composables (error/empty messaging) and the single-
  Activity nav host (AND-022) for the reminder deep link.
- **New test-only dependency:** `ical4j` (validation in unit tests only; not shipped).
- **Sequencing:** implement serializer + repository + scheduler in `core-data`
  first (independently testable), then wire ViewModel actions and Compose UI into
  the AND-272 screen, then manifest receivers/permissions and FileProvider.

## 13. Risks & Open Questions

- **OEM Doze/battery killers** may delay inexact alarms beyond the lead time on
  some devices. Mitigation: `allowWhileIdle` + exact-alarm path; document expected
  behavior. Open: do we proactively prompt for exact-alarm grant or only on
  fallback? (Default: only on fallback to avoid permission fatigue.)
- **Recurrence → RRULE fidelity:** the verified DTO surface is
  `RecurrenceRule { freq: DAILY|WEEKLY|MONTHLY, interval?, until_utc?, count?, byday?,
  bymonthday?, bysetpos? }` plus `exdates_utc: string[]` (`src/api/types.ts`). This maps
  cleanly to `FREQ`/`INTERVAL`/`UNTIL`/`COUNT`/`BYDAY`/`BYMONTHDAY`/`BYSETPOS` and an
  `EXDATE` list — so a basic EXDATE list IS supported (earlier "complex EXDATE
  unmappable" concern is resolved for the simple list case). `freq` is restricted to
  DAILY/WEEKLY/MONTHLY (no YEARLY/HOURLY/etc.), so no exotic FREQ values need handling.
  Residual open: `until_utc` vs `count` precedence and `bysetpos` edge cases; for any
  truly unrepresentable pattern, export the single occurrence with a `COMMENT` noting
  truncation rather than emit an invalid RRULE.
- **All-day timezone semantics:** confirm whether AND-271 treats all-day events as
  floating dates; export must match to avoid off-by-one-day in importers.
- **Multiple reminders per event:** current scope is one active reminder per event.
  Open question whether QA wants multiple lead times — deferred unless requested.
- **Exact-alarm policy eligibility:** whether the app qualifies for `USE_EXACT_ALARM`
  (calendar/alarm category) vs must use the grantable `SCHEDULE_EXACT_ALARM`.

## 14. Acceptance Criteria

AC-1. From Event Detail, tapping **Export .ics** produces a `text/calendar`
document and launches a share sheet; "Save to files" writes the same document via
SAF. (Backlog: "ICS exports.")

AC-2. The exported document is valid RFC 5545: opens without error in Google
Calendar, and `ical4j` parses it in tests; contains `UID`, `DTSTAMP`, `DTSTART`,
`DTEND`/`DURATION`, `SUMMARY`, and `URL` (public App Link). Special characters are
escaped and lines folded at 75 octets.

AC-3. All-day events export with `VALUE=DATE`; recurring events export a valid
`RRULE`; TZID events emit a matching `VTIMEZONE`.

AC-4. From Event Detail, adding a reminder with a chosen lead time schedules an
alarm at `start − lead`, persists it in Room, and reflects it in the UI; re-adding
replaces it; cancelling removes both alarm and record.

AC-5. The reminder **fires** a notification at the trigger time (verified in
instrumented/Robolectric test and on a real device); tapping it deep-links to the
correct event. (Backlog: "Reminder fires.")

AC-6. After device reboot, future reminders are re-armed and still fire; past
reminders are not re-scheduled.

AC-7. On API 33+ without `POST_NOTIFICATIONS`, the user is prompted; on denial the
app explains the consequence without crashing. On API 31+ without exact-alarm
permission, scheduling falls back to inexact with a visible caption.

AC-8. Adding a reminder is disabled for events whose start is in the past.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android` with serializer +
  reminder repository/scheduler in `core-data` and UI/ViewModel wiring in
  `feature-calendar`.
- Manifest declares `FileProvider`, `reminders` `NotificationChannel`,
  `ReminderReceiver` (not exported), `BootReceiver` (boot-guarded), and the
  notification/exact-alarm permissions; `filepaths.xml` added.
- All §11 unit and UI tests pass in CI (AND-050 pipeline); ktlint/detekt clean
  (AND-005); no new lint Errors.
- ICS golden files committed; `ical4j` confined to `testImplementation`.
- Manual verification on a physical device: reminder fires while app is killed and
  again after reboot; .ics imports cleanly into at least two third-party calendar
  apps.
- All user-facing strings localized; accessibility labels present and TalkBack-
  verified.
- Spec acceptance criteria §14 each demonstrably met; open questions in §13 either
  resolved or explicitly deferred with a follow-up note. Hand-off to AND-277 for
  consolidated calendar test coverage.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Event read endpoint used upstream (AND-272) is `GET /ui/calendars/{calendar_id}/events/{event_id}` returning `CalendarEvent`.** — VERDICT: Corrected (spec said `/ui/calendar/...`, singular). SOURCE: `src/api/endpoints/calendar.ts: getEvent` (`api.get<CalendarEvent>(\`/ui/calendars/${calendarId}/events/${eventId}\`)`). NOTE: this exact single-GET path is not in the OpenAPI index (the index lists `GET/POST /ui/calendars/{calendar_id}/events`, `PATCH/DELETE .../events/{event_id}`, and `.../events/{event_id}/ical`); the web client nonetheless calls it, so it is treated as a live route. The plural `calendars` is authoritative.

2. **No new backend HTTP endpoint is required; both features are on-device.** — VERDICT: Verified. SOURCE: feature is client serialization + `AlarmManager`/`NotificationManager`; no matching new op in OpenAPI index, and no frontend network call for client-side ICS/reminders. (Reasonable, consistent with sources.)

3. **A server-side iCal endpoint already exists.** — VERDICT: Verified (added as context). SOURCE: OpenAPI `GET /ui/calendars/{calendar_id}/events/{event_id}/ical` and `GET /calendar/public/event/{calendar_id}/{event_id}/ical`; frontend `src/api/endpoints/calendar.ts: downloadIcalUrl` and `getPublicIcalUrl`. The ticket deliberately serializes client-side instead.

4. **Public event web route / ICS `URL` format is `/event/{calendarId}/{eventId}`.** — VERDICT: Verified. SOURCE: `src/App.tsx` route `<Route path="/event/:calendarId/:eventId" element={<PublicEventPage />} />`; frontend `src/api/endpoints/calendar.ts: getPublicEvent` → `GET /calendar/public/event/{calendarId}/{eventId}` (OpenAPI confirms). The example host `18.222.237.167:8000` is the dev host and is environment-specific.

5. **Event title for `SUMMARY` is the `name` field.** — VERDICT: Corrected (spec implied a `summary`/`title` field). SOURCE: `src/api/types.ts: CalendarEvent.name` (and `CalendarEventAttachment.name`). OpenAPI `EventOut`/`EventCreateIn` use `name` as well.

6. **`LOCATION` is available from event data.** — VERDICT: Corrected (removed). SOURCE: `src/api/types.ts: CalendarEvent` and `CalendarEventAttachment` — neither has a `location` field. `EventCreateIn` also has none. `LOCATION` must not be emitted from event data until upstream adds it.

7. **Timestamps come from `start_utc`/`end_utc`; all-day from `all_day` + `all_day_date`; timezone from `timezone`.** — VERDICT: Verified. SOURCE: `src/api/types.ts: CalendarEvent` (`start_utc?`, `end_utc?`, `all_day`, `all_day_date?`, `timezone`).

8. **Recurrence is a structured DTO, not a pre-built RRULE string; EXDATE list is available.** — VERDICT: Corrected (spec's `rrule: String` field was described as a "pre-built RRULE line value"; the mapper must build it). SOURCE: `src/api/types.ts: RecurrenceRule { freq: "DAILY"|"WEEKLY"|"MONTHLY", interval?, until_utc?, count?, byday?, bymonthday?, bysetpos? }` and `CalendarEvent.exdates_utc?: string[]` / `EventCreateIn.exdates_utc`.

9. **`STATUS` source is `CalendarEvent.status`.** — VERDICT: Verified (with caveat). SOURCE: `src/api/types.ts: CalendarEvent.status: string` — it is a free-form string in the DTO (not the constrained enum the spec's `IcsStatus` uses); the serializer must normalize to `CONFIRMED`/`TENTATIVE`/`CANCELLED` (`CalendarEventAttachment`-adjacent types use `"open"|"confirmed"|"cancelled"`, so a normalization map is required).

10. **Upstream event fetch enforces cookie + `X-CSRF-Token` auth.** — VERDICT: Verified. SOURCE: `src/api/client.ts` — `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, with `credentials: "include"`. (This ticket itself does no network I/O, so it inherits but does not exercise this.)

11. **`POST_NOTIFICATIONS` runtime permission on API 33+ and exact-alarm models (`SCHEDULE_EXACT_ALARM`/`USE_EXACT_ALARM`, `setExactAndAllowWhileIdle`, `canScheduleExactAlarms`, `ACTION_REQUEST_SCHEDULE_EXACT_ALARM`).** — VERDICT: Verified (framework ref). SOURCE: Android docs — POST_NOTIFICATIONS (developer.android.com/develop/ui/views/notifications/notification-permission); exact alarms (developer.android.com/develop/background-work/services/alarms/schedule#exact-permission-check). Not derivable from backend/frontend; correct per platform behavior.

12. **RFC 5545 serialization rules: CRLF, 75-octet line folding, UTC `Z`, escaping of `\ ; , \n`, `VALUE=DATE`, `RRULE`, `VTIMEZONE`.** — VERDICT: Verified (framework ref). SOURCE: RFC 5545 §3.1 (content line folding, 75 octets), §3.3.5 (date-time/UTC), §3.3.11 (TEXT escaping). Independent of project sources.

13. **`FileProvider` per-URI grant + `ACTION_SEND`/`ACTION_CREATE_DOCUMENT` (SAF) for share/save.** — VERDICT: Verified (framework ref). SOURCE: Android docs — FileProvider (developer.android.com/reference/androidx/core/content/FileProvider), Storage Access Framework / `CreateDocument` ActivityResultContract.

14. **`BOOT_COMPLETED` re-arm requires `RECEIVE_BOOT_COMPLETED` and an exported receiver; `setExactAndAllowWhileIdle` fires in Doze maintenance windows.** — VERDICT: Verified (framework ref). SOURCE: Android docs — `ACTION_BOOT_COMPLETED` / `RECEIVE_BOOT_COMPLETED`; Doze restrictions (developer.android.com/training/monitoring-device-state/doze-standby).

15. **Deep-link `testlogon://event/{calendarId}/{eventId}` mirrors the public event route.** — VERDICT: Unverified-assumption (Android-internal scheme). SOURCE: shape mirrors verified web route `/event/:calendarId/:eventId` (`src/App.tsx`), but the custom scheme `testlogon://` and the single-Activity nav route are defined by AND-022/AND-272, not the backend/frontend reference here.

### Corrections made

- §5 endpoint path `GET /ui/calendar/{calendarId}/events/{eventId}` → `GET /ui/calendars/{calendar_id}/events/{event_id}` (plural `calendars`), per `getEvent` in `calendar.ts`.
- §FR-2, §5 example, §4.1: removed `LOCATION` from the required/example VEVENT fields — no location field exists in the verified event DTOs; documented that it must not be emitted from event data.
- §FR-2 / §5 / §4.1: clarified `SUMMARY` derives from `CalendarEvent.name` (no `summary`/`title` field exists).
- §4.1: `rrule` field re-described as built by the mapper from the structured `RecurrenceRule`; added `exdatesUtc` → `EXDATE`; documented `start_utc`/`end_utc`/`all_day`/`all_day_date`/`timezone` mapping.
- §13: replaced the speculative "complex EXDATE" concern with the verified `RecurrenceRule` shape and `exdates_utc`; noted simple EXDATE list IS supported and `freq` is restricted to DAILY/WEEKLY/MONTHLY.
- Added §5 context note that server-side iCal endpoints already exist.
- §9 `STATUS` normalization: noted `CalendarEvent.status` is a free string requiring mapping to the `IcsStatus` enum.

### Open assumptions

- **Deep-link scheme `testlogon://event/...`** — cannot be verified from backend/frontend sources (Android-app-internal, owned by AND-022/AND-272). Shape is consistent with the verified web route but the scheme/registration is assumed.
- **`USE_EXACT_ALARM` policy eligibility** — whether TestLogon qualifies for the non-grantable `USE_EXACT_ALARM` (calendar/alarm app category) vs must use grantable `SCHEDULE_EXACT_ALARM` is a Play policy determination, not derivable from these sources. Default to `SCHEDULE_EXACT_ALARM` until confirmed.
- **`appVersion`/`PRODID` value** — `@Named("appVersion")` injection point is assumed to exist from app build config; not verifiable here.
- **Single-event GET route presence** — `GET /ui/calendars/{calendar_id}/events/{event_id}` is used by the web client but absent from the OpenAPI index; assumed live (AND-272's concern, not this ticket's). This ticket does no network I/O so it is unaffected either way.
- **`event.status` exact value domain** — the DTO types it as a bare `string`; the precise set of server values (beyond `open/confirmed/cancelled` seen on adjacent attachment types) is not enumerated in the sources, so the normalization map is a best-effort assumption.

## 17. Test Plan

Test IDs `TC-AND-276-NN`. "Traces" link to §14 acceptance criteria (AC-1..AC-8).
Targets: JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or the
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a, serial R5CX821TA9R).

**TC-AND-276-01 — ICS serializer golden output (timed event).**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: `Rfc5545IcsSerializer` with a fixed `PRODID`; `IcsEvent` mapped from a `CalendarEvent` with `name`, `description`, `start_utc`, `end_utc`, `status=confirmed`, public `URL`.
- Steps: serialize a single timed event; compare to a committed golden `.ics`; re-parse output with `ical4j`.
- Expected: output begins `BEGIN:VCALENDAR`/`VERSION:2.0`/`PRODID:-//com.testlogon.android//TestLogon//EN`/`CALSCALE:GREGORIAN`; one `VEVENT` with `UID`,`DTSTAMP`,`DTSTART`,`DTEND`,`SUMMARY` (from `name`),`DESCRIPTION`,`URL`,`STATUS`; CRLF line endings; UTC `...Z` timestamps; NO `LOCATION` line; `ical4j` parses without error.
- Traces: AC-2.

**TC-AND-276-02 — Escaping and 75-octet line folding.**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: event whose `description` contains `;`, `,`, `\`, newline, and a >75-octet multibyte (UTF-8) string.
- Steps: serialize; inspect raw bytes.
- Expected: `;`→`\;`, `,`→`\,`, `\`→`\\`, newline→`\n`; long content lines folded with CRLF + single leading space; folding never splits a UTF-8 multibyte sequence; `ical4j` re-parse round-trips the original text.
- Traces: AC-2.

**TC-AND-276-03 — All-day event serialization.**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: `CalendarEvent` with `all_day=true`, `all_day_date` set.
- Steps: serialize.
- Expected: `DTSTART;VALUE=DATE:YYYYMMDD` and `DTEND;VALUE=DATE:` (next day); no `Z`/time component; no off-by-one day; `ical4j` parses as a date-valued all-day event.
- Traces: AC-3.

**TC-AND-276-04 — Recurrence + EXDATE + TZID serialization.**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: event with `recurrence_rule { freq:WEEKLY, byday:[MO], count:8 }`, two `exdates_utc`, and an explicit IANA `timezone` (e.g. `America/New_York`).
- Steps: serialize.
- Expected: `RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=8`; one `EXDATE` line (or lines) for the excluded occurrences; a matching `VTIMEZONE` block; `DTSTART;TZID=America/New_York:`; `ical4j` parses RRULE/EXDATE/VTIMEZONE without error.
- Traces: AC-3.

**TC-AND-276-05 — STATUS normalization and missing-optional omission.**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: events with `status` values `"confirmed"`, `"cancelled"`, an unknown string, and an event with null `description`.
- Steps: serialize each.
- Expected: status maps to `CONFIRMED`/`CANCELLED`/(default `CONFIRMED` or `TENTATIVE` per mapping spec); null `description` omits the `DESCRIPTION` line entirely (never `DESCRIPTION:`); builder validation rejects a null required field (e.g. missing `start`) with a guarded error, not a crash.
- Traces: AC-2.

**TC-AND-276-06 — Reminder scheduler: exact vs windowed branch.**
- Type: unit (Robolectric, `ShadowAlarmManager`). Target: JVM/Robolectric (local).
- Preconditions: `ReminderScheduler`; toggleable `canScheduleExactAlarms()`.
- Steps: with exact-alarm allowed, schedule reminder for `start−lead`; assert `setExactAndAllowWhileIdle` at the correct trigger ms. Flip `canScheduleExactAlarms()=false`; re-schedule; re-add same event; cancel.
- Expected: exact path sets one alarm at `eventStart−lead`; fallback uses `setWindow`/`setAndAllowWhileIdle` (inexact); re-add replaces the prior `PendingIntent` (stable request code = hash of `eventId`); cancel removes the alarm.
- Traces: AC-4, AC-7.

**TC-AND-276-07 — Reminder repository (Room) upsert/cancel/observe/allFuture.**
- Type: unit (Robolectric, in-memory Room). Target: JVM/Robolectric (local).
- Preconditions: in-memory `event_reminders` DB.
- Steps: upsert a reminder; observe by eventId; upsert again (replace); cancel; insert one past + one future trigger and call `allFuture(now)`.
- Expected: at most one row per `eventId` (PK = eventId); `observe` emits updates; `cancel` deletes; `allFuture(now)` returns only `triggerEpochMs > now`.
- Traces: AC-4, AC-6.

**TC-AND-276-08 — BootReceiver re-arms only future reminders.**
- Type: unit (Robolectric). Target: JVM/Robolectric (local).
- Preconditions: Room seeded with past and future reminders; `ShadowAlarmManager`.
- Steps: dispatch `ACTION_BOOT_COMPLETED` (and `ACTION_MY_PACKAGE_REPLACED`) to `BootReceiver`; let the injected coroutine run.
- Expected: alarms re-armed for every future reminder; none for past; `BootReceiver` ignores unexpected actions; emits `reminder_rearmed_on_boot{count}`.
- Traces: AC-6.

**TC-AND-276-09 — ReminderReceiver posts notification with correct deep-link.**
- Type: unit (Robolectric notification shadow). Target: JVM/Robolectric (local).
- Preconditions: `ReminderReceiver`; channel `reminders` created.
- Steps: deliver the broadcast with `eventId`/`calendarId`/`title`/`triggerEpochMs` extras.
- Expected: a notification posted on channel `reminders`; title = event title, body = formatted start time (locale/timezone formatted); content `PendingIntent` targets `testlogon://event/{calendarId}/{eventId}`; no event `description` in the notification body.
- Traces: AC-5, and security (no sensitive body).

**TC-AND-276-10 — Compose UI: add/cancel reminder, disabled for past events.**
- Type: Compose-UI (instrumented). Target: emulator AVD `test35` (API 35).
- Preconditions: Event Detail host with a future event and (separately) a past event.
- Steps: open reminder presets, choose a lead, confirm; verify UI reflects scheduled state; cancel; for the past event, observe the action.
- Expected: choosing a lead schedules + shows the reminder; cancel clears it; for past event the action is disabled with the explanatory caption (`canSchedule=false`); state changes announced via `liveRegion=Polite`.
- Traces: AC-4, AC-8.

**TC-AND-276-11 — Export intents launched (share + Save to files).**
- Type: instrumented (Espresso-Intents). Target: emulator AVD `test35` (API 35).
- Preconditions: Event Detail with a loaded event; `FileProvider` authority `${applicationId}.fileprovider` declared; `filepaths.xml` maps `cache/ics`.
- Steps: tap Export .ics → choose Share; then tap Save to files.
- Expected: `ACTION_SEND` with type `text/calendar` and a `content://${applicationId}.fileprovider/...` URI carrying `FLAG_GRANT_READ_URI_PERMISSION`; Save path launches `ACTION_CREATE_DOCUMENT` with `text/calendar`; resulting URI written via `ContentResolver.openOutputStream`. No crash if launcher returns cancelled/null.
- Traces: AC-1.

**TC-AND-276-12 — POST_NOTIFICATIONS denial and exact-alarm fallback (API behavior).**
- Type: instrumented / manual. Target: physical device (SM-A156U, API 34) for the real OS permission dialogs and OEM exact-alarm behavior; emulator `test35` can cover the API-35 dialog variant.
- Preconditions: notifications permission revoked; exact-alarm permission not granted.
- Steps: add a reminder; deny `POST_NOTIFICATIONS`; observe UI; then attempt scheduling without exact-alarm grant; use the offered action to open `ACTION_REQUEST_SCHEDULE_EXACT_ALARM`.
- Expected: on denial the reminder record is still saved and an alarm armed; `UiMessage` explains OS will suppress notifications and offers a deep link to notification settings; no crash. Without exact-alarm grant, scheduling falls back to inexact with a visible caption and an action to request exact alarms; `exact_alarm_fallback` logged. MUST run on the physical device for true OEM (Samsung) Doze/exact-alarm behavior; emulator covers the dialog/permission flow only.
- Traces: AC-7.

**TC-AND-276-13 — End-to-end reminder fires while app killed, then after reboot.**
- Type: instrumented/e2e + manual. Target: physical device (SM-A156U, API 34) — REQUIRED.
- Preconditions: reminder scheduled for a near-future trigger; app then swiped away (process killed); separately, a future reminder scheduled before a device reboot.
- Steps: kill app, wait for trigger time, observe notification; tap it. Then reboot the device, wait for the second trigger, observe notification.
- Expected: notification fires at trigger time with app killed (Doze maintenance window tolerance noted for inexact); tap deep-links to the correct Event Detail; after reboot the future reminder is re-armed and fires; a past reminder is not re-scheduled. MUST be on the physical device — real FCM-independent AlarmManager + reboot + OEM battery behavior cannot be trusted on the emulator.
- Traces: AC-5, AC-6.

**TC-AND-276-14 — Cross-app ICS import + accessibility sweep.**
- Type: manual + Compose-UI accessibility. Target: physical device (SM-A156U) for import into real calendar apps; emulator `test35` acceptable for TalkBack/contrast checks.
- Preconditions: an exported `.ics` for timed, all-day, and recurring events.
- Steps: import each `.ics` into at least two third-party calendar apps (e.g., Google Calendar, Outlook); separately run TalkBack over the export/reminder controls.
- Expected: events import cleanly with correct date/time, recurrence, and URL; no off-by-one for all-day. Export/reminder buttons expose `contentDescription`s ("Export event as .ics file", "Add reminder", "Cancel reminder"); presets are a labelled, TalkBack-reachable control; touch targets ≥48dp; strings localized (plurals for lead labels). Import into real apps MUST use the physical device.
- Traces: AC-1, AC-2, AC-3 (interop) and accessibility (§9).

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (export produces text/calendar + SAF save) | TC-11, TC-14 |
| AC-2 (valid RFC 5545: required fields, escape/fold, ical4j) | TC-01, TC-02, TC-05, TC-14 |
| AC-3 (all-day VALUE=DATE, RRULE, VTIMEZONE) | TC-03, TC-04, TC-14 |
| AC-4 (schedule at start−lead, persist, replace, cancel) | TC-06, TC-07, TC-10 |
| AC-5 (reminder fires; tap deep-links) | TC-09, TC-13 |
| AC-6 (re-arm future on reboot; skip past) | TC-07, TC-08, TC-13 |
| AC-7 (POST_NOTIFICATIONS prompt/denial; exact-alarm fallback) | TC-06, TC-12 |
| AC-8 (add disabled for past events) | TC-10 |

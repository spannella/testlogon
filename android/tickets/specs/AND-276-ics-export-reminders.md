---
id: AND-276
title: ICS export / reminders
milestone: M6
epic: E37
priority: P2
size: M
status: draft
depends_on: [AND-272]
blocks: [AND-277]
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
`DTEND` (or `DURATION`), `SUMMARY`, `DESCRIPTION`, `LOCATION`, `URL` (the public
event App Link from AND-272), and `STATUS`. All-day events emit `DTSTART;VALUE=DATE`.
Recurring events emit an `RRULE` derived from the event's recurrence DTO.

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
    val rrule: String?,               // pre-built RRULE line value, e.g. "FREQ=WEEKLY;BYDAY=MO"
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
`feature-calendar` and adapts the AND-272 domain model. The serializer emits CRLF
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
  read endpoints owned by AND-270, e.g. `GET /ui/calendar/{calendarId}/events/{eventId}`).
  This ticket performs no network I/O.
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
LOCATION:Remote
URL:http://18.222.237.167:8000/event/cal_1/evt_8f12
STATUS:CONFIRMED
END:VEVENT
END:VCALENDAR
```

All-day variant: `DTSTART;VALUE=DATE:20260610` / `DTEND;VALUE=DATE:20260611`.
Recurring variant adds e.g. `RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=8`. The `URL` value
reuses the public event App Link format established by AND-272.

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
- **Recurrence → RRULE fidelity:** AND-270's recurrence DTO may not map 1:1 to all
  RFC 5545 RRULE constructs (e.g., complex EXDATE). Open: confirm the DTO surface;
  for unsupported patterns, export the single occurrence with a `COMMENT` noting
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

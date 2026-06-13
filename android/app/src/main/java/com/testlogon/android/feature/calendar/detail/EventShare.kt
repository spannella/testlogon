package com.testlogon.android.feature.calendar.detail

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.provider.CalendarContract
import com.testlogon.android.R
import java.net.URLEncoder
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-272 — builds the canonical, auth-free public share URL for an event, mirroring the verified web
 * route `/event/:calendarId/:eventId` (reference src/App.tsx). Pure / JVM-unit-testable.
 *
 * The host is the published App Link host (the prod/staging web host) — NEVER the plaintext dev host
 * (18.222.237.167:8000), so a shared link is always https on a real host.
 */
object EventShareUrl {

    /** Builds `https://<host>/event/<calendarId>/<eventId>`. */
    fun build(host: String, calendarId: String, eventId: String): String =
        "https://$host/event/${enc(calendarId)}/${enc(eventId)}"

    /**
     * AND-391 — builds the canonical PUBLIC iCal download URL
     * `https://<host>/event/<calendarId>/<eventId>/ical`, mirroring the verified web
     * `calendar.ts:getPublicIcalUrl` and the backend op
     * `GET /calendar/public/event/{calendar_id}/{event_id}/ical`. The host is the published App Link
     * host (prod/staging), NEVER the plaintext dev host, so the link is always https on a real host.
     * Opened via [EventIntents.openUrl] (ACTION_VIEW) — no vendor/native SDK; the download is a public,
     * unauthenticated GET handled by the browser/system download manager.
     */
    fun publicIcalUrl(host: String, calendarId: String, eventId: String): String =
        "https://$host/event/${enc(calendarId)}/${enc(eventId)}/ical"

    // Pure path-segment encoder (encodeURIComponent-equivalent) — no android.net.Uri, JVM-testable.
    private fun enc(segment: String): String =
        URLEncoder.encode(segment, "UTF-8").replace("+", "%20")
}

/** The text payload handed to the share sheet for an event. */
data class EventShareContent(val url: String, val subject: String?)

/** Add-to-device-calendar fields, prefilled into an ACTION_INSERT intent. */
data class EventCalendarInsert(
    val title: String,
    val description: String?,
    val beginMillis: Long?,
    val endMillis: Long?,
    val allDay: Boolean,
    /**
     * AND-276 — optional device-calendar reminder lead in minutes. When non-null, the inserted event is
     * prefilled with a CalendarContract reminder this many minutes before start (0 = at start).
     */
    val reminderMinutes: Int? = null,
)

/**
 * AND-272 — side-effecting platform intents for the event detail screen, behind an injectable seam so
 * they are testable and never invoked directly from a composable body. Each returns false when no app
 * can handle the intent so the caller can show a Snackbar instead of crashing.
 */
@Singleton
class EventIntents @Inject constructor() {

    /** Shares the canonical public event URL via the system chooser (ACTION_SEND, text/plain). */
    fun share(context: Context, content: EventShareContent): Boolean {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, content.url)
            content.subject?.let { putExtra(Intent.EXTRA_SUBJECT, it) }
        }
        val chooser = Intent.createChooser(send, context.getString(R.string.calendar_share_chooser_title))
            .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
        return launch(context, chooser)
    }

    /** Opens the device calendar's insert UI prefilled with the event (ACTION_INSERT). */
    fun addToCalendar(context: Context, insert: EventCalendarInsert): Boolean {
        val intent = Intent(Intent.ACTION_INSERT).apply {
            data = CalendarContract.Events.CONTENT_URI
            putExtra(CalendarContract.Events.TITLE, insert.title)
            insert.description?.let { putExtra(CalendarContract.Events.DESCRIPTION, it) }
            insert.beginMillis?.let {
                putExtra(CalendarContract.EXTRA_EVENT_BEGIN_TIME, it)
            }
            insert.endMillis?.let {
                putExtra(CalendarContract.EXTRA_EVENT_END_TIME, it)
            }
            if (insert.allDay) putExtra(CalendarContract.EXTRA_EVENT_ALL_DAY, true)
            // AND-276: prefill a device-calendar reminder (minutes before start; 0 = at start).
            insert.reminderMinutes?.let {
                putExtra(CalendarContract.Reminders.MINUTES, it)
                putExtra(CalendarContract.Reminders.METHOD, CalendarContract.Reminders.METHOD_ALERT)
            }
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return launch(context, intent)
    }

    /**
     * AND-276 — shares an exported `.ics` document (a FileProvider content URI) via the system chooser
     * (ACTION_SEND, MIME text/calendar) with a transient read grant. Returns false when no app can
     * handle it so the caller can show a Snackbar instead of crashing.
     */
    fun shareIcs(context: Context, uri: android.net.Uri, subject: String?): Boolean {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/calendar"
            putExtra(Intent.EXTRA_STREAM, uri)
            subject?.let { putExtra(Intent.EXTRA_SUBJECT, it) }
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(send, context.getString(R.string.calendar_share_chooser_title))
            .apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
        return launch(context, chooser)
    }

    /**
     * AND-391 — opens an https URL via ACTION_VIEW (the public iCal download URL). The system browser /
     * download manager handles the unauthenticated GET and the `.ics` MIME, so the file is offered for
     * download or opened in a calendar app — no vendor SDK and no in-app file write needed. Returns
     * false when no app can handle it so the caller can show a Snackbar instead of crashing.
     */
    fun openUrl(context: Context, url: String): Boolean {
        val view = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return launch(context, view)
    }

    private fun launch(context: Context, intent: Intent): Boolean = try {
        context.startActivity(intent)
        true
    } catch (_: ActivityNotFoundException) {
        false
    }
}

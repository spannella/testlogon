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
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return launch(context, intent)
    }

    private fun launch(context: Context, intent: Intent): Boolean = try {
        context.startActivity(intent)
        true
    } catch (_: ActivityNotFoundException) {
        false
    }
}

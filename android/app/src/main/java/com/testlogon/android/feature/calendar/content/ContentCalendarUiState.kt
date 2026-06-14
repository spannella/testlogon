package com.testlogon.android.feature.calendar.content

import com.testlogon.android.data.contentcalendar.ScheduledContent

/**
 * AND-274 — UI state for the content-calendar (schedule/agenda) screen.
 *
 * The visible period is a month identified by the epoch day of its first day ([focusEpochDay]) in the
 * display zone; the screen shows the period label resolved from it. Items are grouped into [ContentDay]
 * buckets keyed by local epoch day (bucketing reuses the pure CalendarMath in the ViewModel).
 */
sealed interface ContentCalendarUiState {
    val focusEpochDay: Long

    data class Loading(override val focusEpochDay: Long) : ContentCalendarUiState

    data class Empty(override val focusEpochDay: Long) : ContentCalendarUiState

    data class Error(
        override val focusEpochDay: Long,
        val message: String,
        val isOffline: Boolean,
    ) : ContentCalendarUiState

    data class Content(
        override val focusEpochDay: Long,
        val days: List<ContentDay>,
        val isStale: Boolean = false,
    ) : ContentCalendarUiState
}

/** One day's bucket of scheduled content, ordered by scheduled time. [epochDay] is a local epoch day. */
data class ContentDay(
    val epochDay: Long,
    val items: List<ScheduledContent>,
)

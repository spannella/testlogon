package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * Discovery DTOs for the in-app composers that must pick a real calendar / event / file:
 *  - GET ui/calendars                          -> bare array of CalendarAccessOut
 *  - GET ui/calendars/{id}/events?limit=&...    -> EventsPageOut {events:[EventOut], next_cursor}
 *  - GET v1/fs/list?path=/&limit=                -> {path, items:[FsItemOut], cursor}
 *
 * Verified against app/routers/calendar.py (CalendarAccessOut models.py:954, EventOut models.py:1183,
 * EventsPageOut models.py:1249) and app/routers/filemanager.py (GET /v1/fs/list returns
 * {path, items:[{path,type,name,size,updated_at,content_type}], cursor}).
 */

/** CalendarAccessOut. permission ∈ owner|read|write. */
@JsonClass(generateAdapter = true)
data class CalendarAccessDto(
    @Json(name = "calendar_id") val calendarId: String,
    val name: String = "",
    val timezone: String = "UTC",
    @Json(name = "owner_user_id") val ownerUserId: String = "",
    val permission: String = "read",
)

/** EventOut (subset used by the composer; the wire object carries far more). */
@JsonClass(generateAdapter = true)
data class CalendarEventDto(
    @Json(name = "event_id") val eventId: String,
    @Json(name = "calendar_id") val calendarId: String = "",
    val name: String = "",
    @Json(name = "start_utc") val startUtc: String? = null,
    @Json(name = "end_utc") val endUtc: String? = null,
    @Json(name = "all_day") val allDay: Boolean = false,
    @Json(name = "all_day_date") val allDayDate: String? = null,
)

/** EventsPageOut. */
@JsonClass(generateAdapter = true)
data class CalendarEventsPageDto(
    val events: List<CalendarEventDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/** GET /v1/fs/list response envelope. */
@JsonClass(generateAdapter = true)
data class FsListRespDto(
    val path: String = "/",
    val items: List<FsItemDto> = emptyList(),
    val cursor: String? = null,
)

/** One file/folder node. [path] is the absolute VFS path (starts with /), used for file-share. */
@JsonClass(generateAdapter = true)
data class FsItemDto(
    val path: String = "",
    val type: String = "file",
    val name: String = "",
    val size: Long? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
    @Json(name = "content_type") val contentType: String? = null,
)

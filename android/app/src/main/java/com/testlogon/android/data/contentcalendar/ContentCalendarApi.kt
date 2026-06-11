package com.testlogon.android.data.contentcalendar

import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-274 — Retrofit interface for the content-calendar read.
 *
 * Verified against reference openapi.index.txt (GET /ui/content-calendar, params from_ts,to_ts,types)
 * and src/api/endpoints/content-calendar.ts: getContentCalendar. Path is relative (no leading slash) so
 * it resolves against the shared Retrofit base; cookies / CSRF / auth are attached by the shared
 * interceptor chain. `from_ts`/`to_ts` are Unix epoch SECONDS (both required); `types` is an optional
 * comma-separated CSV of post,broadcast,vod. There is NO channel/status/page param and NO paging cursor.
 */
interface ContentCalendarApi {

    @GET("ui/content-calendar")
    suspend fun listScheduledContent(
        @Query("from_ts") fromTs: Long,
        @Query("to_ts") toTs: Long,
        @Query("types") types: String? = null,
    ): ContentCalendarRespDto
}

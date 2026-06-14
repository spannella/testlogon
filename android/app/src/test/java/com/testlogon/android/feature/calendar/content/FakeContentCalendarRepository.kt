package com.testlogon.android.feature.calendar.content

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.contentcalendar.ContentDateRange
import com.testlogon.android.data.contentcalendar.ContentFilter
import com.testlogon.android.data.contentcalendar.ContentCalendarRepository
import com.testlogon.android.data.contentcalendar.ContentItemType
import com.testlogon.android.data.contentcalendar.ScheduledContent
import com.testlogon.android.data.contentcalendar.ScheduledStatus
import java.time.Instant

/** AND-274 — pure-JVM fake [ContentCalendarRepository] for ViewModel tests. */
class FakeContentCalendarRepository : ContentCalendarRepository {

    var result: ApiResult<List<ScheduledContent>> = ApiResult.Success(emptyList())
    var lastRange: ContentDateRange? = null
    var calls = 0

    override suspend fun scheduledContent(
        range: ContentDateRange,
        filter: ContentFilter,
    ): ApiResult<List<ScheduledContent>> {
        calls++
        lastRange = range
        return result
    }

    companion object {
        fun sample(id: String, epochSeconds: Long, type: ContentItemType = ContentItemType.POST) =
            ScheduledContent(
                id = id,
                type = type,
                title = "Title $id",
                status = ScheduledStatus.SCHEDULED,
                scheduledAt = Instant.ofEpochSecond(epochSeconds),
                timezone = "UTC",
                localTime = null,
                color = null,
                icon = null,
            )
    }
}

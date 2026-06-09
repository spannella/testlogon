package com.testlogon.android.feature.activity

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.activity.ActivityEvent
import com.testlogon.android.data.activity.ActivityEventType
import com.testlogon.android.data.activity.ActivityPage
import com.testlogon.android.data.activity.ActivityRepository

/** AND-096 — in-memory [ActivityRepository] fake for paging + ViewModel unit tests. */
class FakeActivityRepository(
    /** Sequential pages keyed by cursor; cursor=null returns pagesByCursor[null]. */
    private val pagesByCursor: Map<String?, ActivityPage> = emptyMap(),
) : ActivityRepository {

    var feedResult: ApiResult<ActivityPage>? = null
    var feedCalls = 0

    override suspend fun feed(cursor: String?, limit: Int?): ApiResult<ActivityPage> {
        feedCalls++
        feedResult?.let { return it }
        val page = pagesByCursor[cursor] ?: ActivityPage(emptyList(), null, 0)
        return ApiResult.Success(page)
    }

    companion object {
        fun event(id: String, read: Boolean = false) = ActivityEvent(
            id = id,
            type = ActivityEventType.LOGIN_SUCCESS,
            rawType = "login_success",
            actorId = "usr_1",
            createdAtEpochSeconds = 1_749_132_202L,
            targetType = null,
            targetId = null,
            read = read,
            detail = null,
        )

        fun page(items: List<ActivityEvent>, nextCursor: String?) =
            ActivityPage(items, nextCursor, 0)

        fun failure(status: Int = 500) = ApiResult.Failure(ApiError(status = status, message = "boom"))
    }
}

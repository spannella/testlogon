package com.testlogon.android.feature.notifications

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.notifications.Notification
import com.testlogon.android.data.notifications.NotificationPage
import com.testlogon.android.data.notifications.NotificationRepository
import com.testlogon.android.data.notifications.NotificationType
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** AND-090 — in-memory [NotificationRepository] fake for ViewModel + paging unit tests. */
class FakeNotificationRepository(
    initialUnread: Int = 0,
    /** Sequential pages keyed by cursor; cursor=null returns pages[0]. */
    private val pagesByCursor: Map<String?, NotificationPage> = emptyMap(),
) : NotificationRepository {

    private val _unread = MutableStateFlow(initialUnread)
    override val unreadCount: StateFlow<Int> = _unread

    var listResult: ApiResult<NotificationPage>? = null
    var markReadResult: ApiResult<Int> = ApiResult.Success(1)
    var markAllResult: ApiResult<Int> = ApiResult.Success(1)
    var unreadResult: ApiResult<Int>? = null

    val markReadCalls = mutableListOf<List<String>>()
    var markAllCalls = 0
    var listCalls = 0

    override suspend fun list(cursor: String?, limit: Int?): ApiResult<NotificationPage> {
        listCalls++
        listResult?.let { return it }
        val page = pagesByCursor[cursor] ?: NotificationPage(emptyList(), null)
        return ApiResult.Success(page)
    }

    override suspend fun markRead(ids: List<String>): ApiResult<Int> {
        markReadCalls += ids
        if (markReadResult is ApiResult.Success) {
            _unread.value = (_unread.value - ids.size).coerceAtLeast(0)
        }
        return markReadResult
    }

    override suspend fun markAllRead(): ApiResult<Int> {
        markAllCalls++
        if (markAllResult is ApiResult.Success) _unread.value = 0
        return markAllResult
    }

    override suspend fun refreshUnreadCount(): ApiResult<Int> {
        val r = unreadResult ?: ApiResult.Success(_unread.value)
        if (r is ApiResult.Success) _unread.value = r.data
        return r
    }

    companion object {
        fun notification(id: String, read: Boolean = false, type: NotificationType = NotificationType.SYSTEM) =
            Notification(
                id = id,
                type = type,
                title = "Title $id",
                body = "Body $id",
                read = read,
                createdAtEpochSeconds = 1_749_124_800L,
                batchKey = null,
                batchCount = 1,
                batchActors = emptyList(),
                data = emptyMap(),
            )

        fun failure(status: Int = 500) = ApiResult.Failure(ApiError(status = status, message = "boom"))
    }
}

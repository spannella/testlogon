package com.testlogon.android.data.notifications

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-084 — notification data layer over [NotificationsApi].
 *
 * Wraps list / mark-read / mark-all-read / unread-count in [ApiResult], mapping wire DTOs to the
 * domain [Notification]. Holds the single source of truth for the unread badge as an observable
 * [unreadCount] StateFlow: it is refreshed from the list response (unread_count) and the dedicated
 * unread-count endpoint (count), and zeroed optimistically on mark-all-read. mark-read carries no
 * count, so it does not update the StateFlow (the badge is re-read via [unreadCount] / next list()).
 *
 * Network-only (no Room cache in scope); failures fold into ApiResult.Error / NetworkError and the
 * repository never throws to callers (CancellationException is re-thrown).
 */
interface NotificationRepository {

    /** Observable unread badge count (single source of truth for downstream badge composables). */
    val unreadCount: StateFlow<Int>

    suspend fun list(cursor: String? = null, limit: Int? = null): ApiResult<NotificationPage>

    /** Mark the given ids read; returns marked_count. */
    suspend fun markRead(ids: List<String>): ApiResult<Int>

    /** Convenience single-id wrapper (wire endpoint is the bulk array form). */
    suspend fun markRead(id: String): ApiResult<Int> = markRead(listOf(id))

    /** Mark everything read; returns marked_count and zeroes the badge optimistically. */
    suspend fun markAllRead(): ApiResult<Int>

    /** Fetch the authoritative unread count; also refreshes [unreadCount]. */
    suspend fun refreshUnreadCount(): ApiResult<Int>
}

@Singleton
class NotificationRepositoryImpl @Inject constructor(
    private val api: NotificationsApi,
    private val errorParser: ApiErrorParser,
) : NotificationRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    private val _unreadCount = MutableStateFlow(0)
    override val unreadCount: StateFlow<Int> = _unreadCount.asStateFlow()

    override suspend fun list(cursor: String?, limit: Int?): ApiResult<NotificationPage> =
        withContext(io) {
            apiCall { api.list(cursor, limit) }.map { dto ->
                _unreadCount.value = dto.unreadCount
                NotificationPage(dto.items.map { it.toDomain() }, dto.nextCursor)
            }
        }

    override suspend fun markRead(ids: List<String>): ApiResult<Int> = withContext(io) {
        apiCall { api.markRead(MarkNotificationsReadReq(ids)) }.map { it.markedCount }
    }

    override suspend fun markAllRead(): ApiResult<Int> = withContext(io) {
        apiCall { api.markAllRead() }.map { resp ->
            _unreadCount.value = 0
            resp.markedCount
        }
    }

    override suspend fun refreshUnreadCount(): ApiResult<Int> = withContext(io) {
        apiCall { api.unreadCount() }.map { resp ->
            _unreadCount.value = resp.count
            resp.count
        }
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

package com.testlogon.android.data.activity

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-091 — activity data layer over [ActivityApi].
 *
 * Wraps the cursor-paged `GET ui/activity/feed` in [ApiResult], mapping wire DTOs to the domain
 * [ActivityEvent]. Network-only (no Room cache in scope for this surface); failures fold into
 * ApiResult.Failure / NetworkError and the repository never throws to callers
 * (CancellationException is re-thrown so structured concurrency / Paging cancellation works).
 */
interface ActivityRepository {

    /** One page of activity events keyed by the opaque [cursor] (null = head). */
    suspend fun feed(cursor: String? = null, limit: Int? = null): ApiResult<ActivityPage>
}

@Singleton
class ActivityRepositoryImpl @Inject constructor(
    private val api: ActivityApi,
    private val errorParser: ApiErrorParser,
) : ActivityRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun feed(cursor: String?, limit: Int?): ApiResult<ActivityPage> =
        withContext(io) {
            apiCall { api.getActivity(cursor, limit) }.map { dto ->
                ActivityPage(
                    items = dto.items.map { it.toDomain() },
                    nextCursor = dto.nextCursor,
                    totalUnread = dto.totalUnread,
                )
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

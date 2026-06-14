package com.testlogon.android.data.earnings

import androidx.paging.Pager
import androidx.paging.PagingConfig
import com.testlogon.android.feature.earnings.percontent.ContentRevenuePagingSource
import com.testlogon.android.core.model.ApiResult
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
 * AND-253 — per-content revenue data layer over [ContentRevenueApi].
 *
 * Exposes a Paging 3 [Pager] for the cursor-paged list (header summary is surfaced via [onHeader] on
 * the first page) and a one-shot [detail] read wrapped in [ApiResult]. Idempotent GETs; the repository
 * never throws to callers (CancellationException is re-thrown so Paging cancellation works).
 */
interface ContentRevenueRepository {

    /**
     * Builds a [Pager] for [query]; [onHeader] is invoked once with the first page's header summary
     * (totals + currency) so the screen can render the aggregate row.
     */
    fun pager(
        query: ContentRevenueQuery,
        onHeader: (ContentRevenuePage) -> Unit,
    ): Pager<String, ContentRevenue>

    /** Per-content detail (used by the optional per-item view). */
    suspend fun detail(contentId: String, fromDate: String?, toDate: String?): ApiResult<ContentRevenueDetail>
}

@Singleton
class ContentRevenueRepositoryImpl @Inject constructor(
    private val api: ContentRevenueApi,
    private val errorParser: ApiErrorParser,
) : ContentRevenueRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun pager(
        query: ContentRevenueQuery,
        onHeader: (ContentRevenuePage) -> Unit,
    ): Pager<String, ContentRevenue> = Pager(
        config = PagingConfig(
            pageSize = ContentRevenueApi.DEFAULT_LIMIT,
            prefetchDistance = PREFETCH_DISTANCE,
            initialLoadSize = ContentRevenueApi.DEFAULT_LIMIT,
            enablePlaceholders = false,
        ),
        pagingSourceFactory = {
            ContentRevenuePagingSource(
                load = { cursor, limit -> loadPage(query, cursor, limit) },
                onHeader = onHeader,
            )
        },
    )

    override suspend fun detail(
        contentId: String,
        fromDate: String?,
        toDate: String?,
    ): ApiResult<ContentRevenueDetail> = withContext(io) {
        call { api.detail(contentId, fromDate, toDate) }.let { result ->
            when (result) {
                is ApiResult.Success -> ApiResult.Success(result.data.toDomain())
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }
    }

    /** One page of mapped content-revenue rows for the paging source. */
    private suspend fun loadPage(
        query: ContentRevenueQuery,
        cursor: String?,
        limit: Int,
    ): ApiResult<ContentRevenuePage> = withContext(io) {
        call {
            api.list(
                fromDate = query.fromDate,
                toDate = query.toDate,
                sortBy = query.sortBy.apiValue,
                sortOrder = query.sortOrder.apiValue,
                contentType = query.contentType,
                limit = limit.coerceIn(1, ContentRevenueApi.MAX_LIMIT),
                cursor = cursor,
            )
        }.let { result ->
            when (result) {
                is ApiResult.Success -> ApiResult.Success(result.data.toDomain())
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val PREFETCH_DISTANCE = 10
    }
}

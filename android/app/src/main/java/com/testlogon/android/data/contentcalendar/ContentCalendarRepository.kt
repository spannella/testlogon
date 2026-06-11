package com.testlogon.android.data.contentcalendar

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
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
 * AND-274 — data layer over [ContentCalendarApi].
 *
 * Wraps the read in [ApiResult] (Failure for HTTP errors via [ApiErrorParser], NetworkError for
 * transport failures, Failure(parse) for malformed JSON). Maps DTOs to domain and sorts items ascending
 * by scheduled time. The GET is idempotent; no Room cache in this slice. CancellationException is
 * re-thrown.
 */
interface ContentCalendarRepository {

    suspend fun scheduledContent(
        range: ContentDateRange,
        filter: ContentFilter = ContentFilter(),
    ): ApiResult<List<ScheduledContent>>
}

@Singleton
class ContentCalendarRepositoryImpl @Inject constructor(
    private val api: ContentCalendarApi,
    private val errorParser: ApiErrorParser,
) : ContentCalendarRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun scheduledContent(
        range: ContentDateRange,
        filter: ContentFilter,
    ): ApiResult<List<ScheduledContent>> = withContext(io) {
        val typesCsv = filter.types
            .mapNotNull { it.wire() }
            .takeIf { it.isNotEmpty() }
            ?.joinToString(",")
        call {
            api.listScheduledContent(
                fromTs = range.from.epochSecond,
                toTs = range.to.epochSecond,
                types = typesCsv,
            )
        }.map { resp ->
            resp.items.map { it.toDomain() }.sortedBy { it.scheduledAt }
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

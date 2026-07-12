package com.testlogon.android.data.marketing

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
 * Marketing content data layer over [MarketingApi].
 *
 * loadContent(type) issues the idempotent GET (first page, filtered by content type); lifecycle
 * mutations (approve/publish/archive/schedule/delete/create/update) map 1:1. Calendar + engagement are
 * read-only GETs. Every call wrapped in [ApiResult]; a last-known-good content page cached in-memory for
 * stale fallback.
 */
interface MarketingRepository {
    suspend fun loadContent(type: String?): ApiResult<MarketingContentPage>
    suspend fun getContent(contentId: String): ApiResult<MarketingContent>
    suspend fun createContent(contentType: String, title: String, body: String): ApiResult<Unit>
    suspend fun updateContent(
        contentId: String,
        title: String,
        body: String,
        summary: String?,
        tags: List<String>,
        seoTitle: String?,
        seoDescription: String?,
    ): ApiResult<Unit>
    suspend fun approve(contentId: String): ApiResult<Unit>
    suspend fun publish(contentId: String): ApiResult<Unit>
    suspend fun archive(contentId: String): ApiResult<Unit>
    suspend fun schedule(contentId: String, publishAtSeconds: Long): ApiResult<Unit>
    suspend fun delete(contentId: String): ApiResult<Unit>
    suspend fun loadCalendar(month: String): ApiResult<List<CalendarEntry>>
    suspend fun loadEngagement(days: Int): ApiResult<EngagementSummary>
    fun cachedContent(): MarketingContentPage?
    fun clear()
}

@Singleton
class MarketingRepositoryImpl @Inject constructor(
    private val api: MarketingApi,
    private val errorParser: ApiErrorParser,
) : MarketingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var contentSnapshot: MarketingContentPage? = null

    override suspend fun loadContent(type: String?): ApiResult<MarketingContentPage> = withContext(io) {
        call { api.listContent(type = type, limit = PAGE_SIZE).toDomain() }
            .also { if (it is ApiResult.Success) contentSnapshot = it.data }
    }

    override suspend fun getContent(contentId: String): ApiResult<MarketingContent> = withContext(io) {
        call { api.getContent(contentId).toDomain() }
    }

    override suspend fun createContent(
        contentType: String,
        title: String,
        body: String,
    ): ApiResult<Unit> = withContext(io) {
        call {
            api.createContent(
                CreateMarketingContentReqDto(
                    contentType = contentType,
                    title = title.trim(),
                    body = body.trim(),
                ),
            )
            Unit
        }
    }

    override suspend fun updateContent(
        contentId: String,
        title: String,
        body: String,
        summary: String?,
        tags: List<String>,
        seoTitle: String?,
        seoDescription: String?,
    ): ApiResult<Unit> = withContext(io) {
        val seo: Map<String, Any?>? = if (seoTitle.isNullOrBlank() && seoDescription.isNullOrBlank()) {
            null
        } else {
            mapOf("title" to seoTitle.orEmpty(), "description" to seoDescription.orEmpty())
        }
        call {
            api.updateContent(
                contentId,
                UpdateMarketingContentReqDto(
                    title = title.trim(),
                    body = body.trim(),
                    summary = summary?.trim()?.takeIf { it.isNotEmpty() },
                    tags = tags.takeIf { it.isNotEmpty() },
                    seoMeta = seo,
                ),
            )
            Unit
        }
    }

    override suspend fun approve(contentId: String): ApiResult<Unit> = mutate { api.approveContent(contentId) }
    override suspend fun publish(contentId: String): ApiResult<Unit> = mutate { api.publishContent(contentId) }
    override suspend fun archive(contentId: String): ApiResult<Unit> = mutate { api.archiveContent(contentId) }
    override suspend fun delete(contentId: String): ApiResult<Unit> = mutate { api.deleteContent(contentId) }

    override suspend fun schedule(contentId: String, publishAtSeconds: Long): ApiResult<Unit> =
        mutate { api.scheduleContent(contentId, ScheduleReqDto(publishAt = publishAtSeconds)) }

    override suspend fun loadCalendar(month: String): ApiResult<List<CalendarEntry>> = withContext(io) {
        call { api.getCalendar(month).map { it.toDomain() } }
    }

    override suspend fun loadEngagement(days: Int): ApiResult<EngagementSummary> = withContext(io) {
        call { api.getEngagementSummary(days).toDomain() }
    }

    override fun cachedContent(): MarketingContentPage? = contentSnapshot

    override fun clear() {
        contentSnapshot = null
    }

    private suspend fun mutate(block: suspend () -> Any?): ApiResult<Unit> = withContext(io) {
        call {
            block()
            Unit
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        private const val PAGE_SIZE = 50
    }
}

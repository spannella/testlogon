package com.testlogon.android.data.discover

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
 * AND-183 — tag-page data layer over [DiscoverApi.getPostsByTag].
 *
 * Wraps the cursor-paged `GET /ui/discover/tags/{tag}` in [ApiResult], mapping the wire DTO to the
 * redaction-safe [TagPostPage] domain (reusing the AND-097 FeedPost mapper). Network-only; failures
 * fold into Failure / NetworkError and the repository never throws (CancellationException re-thrown so
 * Paging cancellation works).
 */
interface TagRepository {

    /** One page of posts for [tag], keyed by the opaque [cursor] (null = first page). */
    suspend fun getTagPage(
        tag: String,
        cursor: String? = null,
        limit: Int = DiscoverApi.TAG_PAGE_SIZE,
    ): ApiResult<TagPostPage>
}

@Singleton
class TagRepositoryImpl @Inject constructor(
    private val api: DiscoverApi,
    private val errorParser: ApiErrorParser,
) : TagRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getTagPage(tag: String, cursor: String?, limit: Int): ApiResult<TagPostPage> =
        withContext(io) {
            call { api.getPostsByTag(tag = tag, limit = limit, cursor = cursor) }.map { it.toDomain() }
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
}

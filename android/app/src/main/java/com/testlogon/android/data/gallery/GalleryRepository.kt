package com.testlogon.android.data.gallery

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
 * AND-201 — gallery data layer over [GalleryApi].
 *
 * Wraps the cursor-paged browse/search GETs and the categories GET in [ApiResult], mapping wire DTOs to
 * the [GalleryPage] domain (dropping items missing required fields). Network-only; failures fold into
 * Failure / NetworkError and the repository never throws (CancellationException re-thrown so Paging
 * cancellation works). The [GalleryPagingSource] follows [GalleryPage.cursor] for the next key.
 */
interface GalleryRepository {

    /** One page of browse results for the optional [category], keyed by [cursor] (null = first page). */
    suspend fun browse(category: String?, cursor: String?, limit: Int = GalleryApi.PAGE_SIZE): ApiResult<GalleryPage>

    /** One page of search results for [query], keyed by [cursor] (null = first page). */
    suspend fun search(query: String, cursor: String?, limit: Int = GalleryApi.PAGE_SIZE): ApiResult<GalleryPage>

    /** The standalone category list. */
    suspend fun categories(): ApiResult<List<GalleryCategory>>
}

@Singleton
class GalleryRepositoryImpl @Inject constructor(
    private val api: GalleryApi,
    private val errorParser: ApiErrorParser,
) : GalleryRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun browse(category: String?, cursor: String?, limit: Int): ApiResult<GalleryPage> =
        withContext(io) {
            call { api.browseGallery(category = category, cursor = cursor, limit = limit) }.map { it.toDomain() }
        }

    override suspend fun search(query: String, cursor: String?, limit: Int): ApiResult<GalleryPage> =
        withContext(io) {
            call { api.searchGallery(query = query, cursor = cursor, limit = limit) }.map { it.toDomain() }
        }

    override suspend fun categories(): ApiResult<List<GalleryCategory>> =
        withContext(io) {
            call { api.categories() }.map { dto -> dto.categories.map { it.toDomain() } }
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

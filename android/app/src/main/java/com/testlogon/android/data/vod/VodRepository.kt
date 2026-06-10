package com.testlogon.android.data.vod

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
 * AND-191 — VOD catalog data layer over [VodApi].
 *
 * One [catalogPage] entry point selects the right backend endpoint by filter: a free-text [query] hits
 * the gallery search, a [category] hits the gallery browse, and no filter hits the public catalog.
 * Each call is wrapped in [ApiResult]; CancellationException is re-thrown so Paging cancellation works.
 */
interface VodRepository {

    /**
     * One cursor-paged catalog page. With [query] -> gallery search; with [category] -> gallery
     * browse; otherwise -> public catalog. All collapse to [VodPage].
     */
    suspend fun catalogPage(
        cursor: String?,
        limit: Int = VodApi.CATALOG_PAGE_SIZE,
        category: String? = null,
        query: String? = null,
    ): ApiResult<VodPage>

    /** Browsable categories for the catalog filter chips (GET ui/videos/gallery/categories). */
    suspend fun categories(): ApiResult<List<VodCategory>>
}

@Singleton
class VodRepositoryImpl @Inject constructor(
    private val api: VodApi,
    private val errorParser: ApiErrorParser,
) : VodRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun catalogPage(
        cursor: String?,
        limit: Int,
        category: String?,
        query: String?,
    ): ApiResult<VodPage> = withContext(io) {
        when {
            !query.isNullOrBlank() ->
                call { api.searchGallery(query = query, cursor = cursor, limit = limit) }.map { it.toDomain() }
            !category.isNullOrBlank() ->
                call { api.browseGallery(category = category, cursor = cursor, limit = limit) }.map { it.toDomain() }
            else ->
                call { api.getPublicCatalog(cursor = cursor, limit = limit) }.map { it.toDomain() }
        }
    }

    override suspend fun categories(): ApiResult<List<VodCategory>> = withContext(io) {
        call { api.getCategories() }.map { resp -> resp.categories.map { it.toDomain() } }
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

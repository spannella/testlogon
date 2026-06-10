package com.testlogon.android.data.catalog

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
 * AND-204 / AND-205 — storefront catalog data layer over [CatalogApi].
 *
 * Wraps the token-paged categories / category-items / search GETs in [ApiResult], mapping wire DTOs to
 * the catalog domain. Network-only; failures fold into Failure / NetworkError and the repository never
 * throws (CancellationException re-thrown so Paging cancellation works). The paging source follows
 * [CatalogItemPage.nextToken] for the next key.
 */
interface CatalogRepository {

    /** First (or [nextToken]-keyed) page of all categories. */
    suspend fun categories(
        nextToken: String? = null,
        pageSize: Int = CatalogApi.PAGE_SIZE,
    ): ApiResult<CatalogCategoryPage>

    /** One page of items in [categoryId], keyed by [cursor] (null = first page). */
    suspend fun categoryItems(
        categoryId: String,
        cursor: String?,
        limit: Int = CatalogApi.PAGE_SIZE,
    ): ApiResult<CatalogItemPage>

    /** One page of search results for [query], keyed by [cursor] (null = first page). */
    suspend fun search(
        query: String,
        cursor: String?,
        limit: Int = CatalogApi.PAGE_SIZE,
    ): ApiResult<CatalogItemPage>
}

@Singleton
class CatalogRepositoryImpl @Inject constructor(
    private val api: CatalogApi,
    private val errorParser: ApiErrorParser,
) : CatalogRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun categories(nextToken: String?, pageSize: Int): ApiResult<CatalogCategoryPage> =
        withContext(io) {
            call { api.listCategories(pageSize = pageSize, nextToken = nextToken) }.map { it.toDomain() }
        }

    override suspend fun categoryItems(categoryId: String, cursor: String?, limit: Int): ApiResult<CatalogItemPage> =
        withContext(io) {
            call { api.listItems(categoryId = categoryId, pageSize = limit, nextToken = cursor) }.map { it.toDomain() }
        }

    override suspend fun search(query: String, cursor: String?, limit: Int): ApiResult<CatalogItemPage> =
        withContext(io) {
            call { api.searchCatalog(query = query, pageSize = limit, nextToken = cursor) }.map { it.toDomain() }
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

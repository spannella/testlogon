package com.testlogon.android.data.catalog

import com.testlogon.android.core.model.ApiError
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

    /**
     * AND-206 — resolves a single item by id. There is NO single-item GET; the item is fetched from the
     * category-items list and selected by [itemId] (web parity, list-then-find). When the list resolves
     * but holds no matching id, returns a [ApiResult.Failure] flagged [STATUS_ITEM_NOT_FOUND] (a
     * client-side not-found, never an HTTP 404). Transport / HTTP failures pass through unchanged. The
     * list is paged through (bounded by [NOT_FOUND_MAX_PAGES]) so an id beyond the first page resolves.
     */
    suspend fun getItem(categoryId: String, itemId: String): ApiResult<CatalogItem>

    companion object {
        /** Synthetic status flagging a client-side "id absent from the category list" (no HTTP 404). */
        const val STATUS_ITEM_NOT_FOUND = 404

        /** Page-walk bound when resolving an item by id so a huge category cannot loop unboundedly. */
        const val NOT_FOUND_MAX_PAGES = 20
    }
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

    override suspend fun getItem(categoryId: String, itemId: String): ApiResult<CatalogItem> =
        withContext(io) {
            var cursor: String? = null
            var page = 0
            // No single-item GET: walk the category-items pages and select by id.
            while (page < CatalogRepository.NOT_FOUND_MAX_PAGES) {
                when (val r = categoryItems(categoryId, cursor = cursor)) {
                    is ApiResult.Success -> {
                        val match = r.data.items.firstOrNull { it.itemId == itemId }
                        if (match != null) return@withContext ApiResult.Success(match)
                        cursor = r.data.nextToken
                        if (cursor == null) {
                            // List fully resolved with no match -> client-side not-found.
                            return@withContext ApiResult.Failure(
                                ApiError(status = CatalogRepository.STATUS_ITEM_NOT_FOUND, message = "Item not found"),
                            )
                        }
                    }
                    is ApiResult.Failure -> return@withContext r
                    is ApiResult.NetworkError -> return@withContext r
                }
                page++
            }
            ApiResult.Failure(
                ApiError(status = CatalogRepository.STATUS_ITEM_NOT_FOUND, message = "Item not found"),
            )
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

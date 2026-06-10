package com.testlogon.android.data.discover

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
 * AND-185 — global multi-entity search data layer over [SearchApi].
 *
 * Wraps `GET /ui/search` in [ApiResult], maps via [SearchMapper], and clamps `limit` to the backend
 * max (20). A small in-memory LRU (size 16) holds the last successful results per query so the
 * ViewModel can serve a stale snapshot when a re-query fails offline (spec §6); [clearCache] is wired
 * to logout. This is independent of the AND-152 message search.
 */
interface SearchRepository {

    /**
     * [filters] supplies the only server-side refinement (`types`); ALL omits it. The per-query cache
     * key includes the filter so a filtered + unfiltered query for the same text don't collide.
     */
    suspend fun search(
        query: String,
        filters: SearchFilters = SearchFilters.DEFAULT,
        limit: Int = SearchApi.DEFAULT_LIMIT,
    ): ApiResult<SearchResults>

    /** Last successful results for [query] under [filters], or null. */
    fun cached(query: String, filters: SearchFilters = SearchFilters.DEFAULT): SearchResults?

    fun clearCache()
}

@Singleton
class SearchRepositoryImpl @Inject constructor(
    private val api: SearchApi,
    private val errorParser: ApiErrorParser,
) : SearchRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    /** Access-ordered LRU, evicting the eldest beyond [CACHE_SIZE]. Guarded by its own monitor. */
    private val lru = object : LinkedHashMap<String, SearchResults>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, SearchResults>): Boolean =
            size > CACHE_SIZE
    }

    /** Cache key combines the query text and the filter wire form so they never collide. */
    private fun key(query: String, filters: SearchFilters): String = "${filters.toTypesParam().orEmpty()}|$query"

    override fun cached(query: String, filters: SearchFilters): SearchResults? =
        synchronized(lru) { lru[key(query, filters)] }

    override fun clearCache() {
        synchronized(lru) { lru.clear() }
    }

    override suspend fun search(
        query: String,
        filters: SearchFilters,
        limit: Int,
    ): ApiResult<SearchResults> = withContext(io) {
        val capped = limit.coerceIn(1, SearchApi.MAX_LIMIT)
        when (val raw = call { api.search(query = query, types = filters.toTypesParam(), limit = capped) }) {
            is ApiResult.Success -> {
                val mapped = SearchMapper.toDomain(raw.data)
                synchronized(lru) { lru[key(query, filters)] = mapped }
                ApiResult.Success(mapped)
            }
            is ApiResult.Failure -> raw
            is ApiResult.NetworkError -> raw
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
        const val CACHE_SIZE = 16
    }
}

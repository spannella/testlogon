package com.testlogon.android.data.discover

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-182 — discover data layer over [DiscoverApi].
 *
 * Fans out to the three per-section endpoints (suggested / trending creators / trending tags)
 * CONCURRENTLY, then assembles the client-side [DiscoverContent]. Partial-failure policy (spec §4.3):
 * if at least one section succeeds, emit Success with whatever loaded; only if ALL fail do we surface
 * the failure (Failure / NetworkError) so the ViewModel can pick error vs offline vs stale.
 *
 * A last-successful result is held in-memory in this @Singleton to back the stale path after a
 * transient failure; [clearCache] is wired to logout (AND-032) to avoid cross-account leakage.
 */
interface DiscoverRepository {

    /** Loads + assembles the discover sections. Returns the cached value on total failure if present. */
    suspend fun getDiscover(): ApiResult<DiscoverContent>

    /** Last successfully-loaded content, or null. Drives the stale banner. */
    fun cached(): DiscoverContent?

    /** Clear the in-memory cache (logout). */
    fun clearCache()
}

@Singleton
class DiscoverRepositoryImpl @Inject constructor(
    private val api: DiscoverApi,
    private val errorParser: ApiErrorParser,
) : DiscoverRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var lastSuccess: DiscoverContent? = null

    override fun cached(): DiscoverContent? = lastSuccess

    override fun clearCache() {
        lastSuccess = null
    }

    override suspend fun getDiscover(): ApiResult<DiscoverContent> = withContext(io) {
        coroutineScope {
            val suggestedDef = async { call { api.getSuggested() } }
            val trendingDef = async { call { api.getTrending() } }
            val tagsDef = async { call { api.getTrendingTags() } }

            val suggested = suggestedDef.await()
            val trending = trendingDef.await()
            val tags = tagsDef.await()

            // Total failure only if every section failed (no partial data to show).
            val anySuccess = suggested is ApiResult.Success ||
                trending is ApiResult.Success ||
                tags is ApiResult.Success
            if (!anySuccess) {
                // Prefer a network-error classification over a server failure for the offline path.
                return@coroutineScope firstFailure(suggested, trending, tags)
            }

            val content = DiscoverContent(
                suggested = (suggested as? ApiResult.Success)?.data?.items?.toCreators().orEmpty(),
                trendingCreators = (trending as? ApiResult.Success)?.data?.items?.toCreators().orEmpty(),
                trendingTags = (tags as? ApiResult.Success)?.data?.tags?.toTags().orEmpty(),
            )
            lastSuccess = content
            ApiResult.Success(content)
        }
    }

    private fun firstFailure(vararg results: ApiResult<*>): ApiResult<Nothing> {
        results.firstOrNull { it is ApiResult.NetworkError }?.let { return it as ApiResult.NetworkError }
        results.firstOrNull { it is ApiResult.Failure }?.let { return it as ApiResult.Failure }
        // Unreachable (caller guarantees at least one failure), but keep the type total.
        return ApiResult.NetworkError(IOException("discover load failed"))
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
